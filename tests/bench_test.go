package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// --- Test data generators ---

// generateDeployment creates a realistic Pulumi deployment JSON with N resources.
func generateDeployment(resourceCount int) []byte {
	resources := make([]map[string]any, resourceCount)
	for i := range resourceCount {
		resources[i] = map[string]any{
			"urn":    fmt.Sprintf("urn:pulumi:dev::test::pkg:module:Resource::res-%d", i),
			"custom": true,
			"type":   "pkg:module:Resource",
			"id":     fmt.Sprintf("id-%d", i),
			"inputs": map[string]any{
				"name":   fmt.Sprintf("resource-%d", i),
				"region": "us-east-1",
				"tags":   map[string]string{"env": "dev", "managed-by": "pulumi"},
			},
			"outputs": map[string]any{
				"id":        fmt.Sprintf("id-%d", i),
				"arn":       fmt.Sprintf("arn:aws:service:us-east-1:123456789:%d", i),
				"name":      fmt.Sprintf("resource-%d", i),
				"status":    "active",
				"createdAt": "2024-01-01T00:00:00Z",
			},
		}
	}
	deployment := map[string]any{
		"version": 3,
		"deployment": map[string]any{
			"manifest": map[string]any{
				"time":    "2024-01-01T00:00:00Z",
				"magic":   "test-magic",
				"version": "1.0.0",
			},
			"resources": resources,
		},
	}
	data, _ := json.Marshal(deployment)
	return data
}

// --- Benchmark helpers ---

// benchBackend creates a backend suitable for benchmarks (no logging/audit overhead).
func benchBackend(b *testing.B) *testBackend {
	b.Helper()

	disableAuditForTest(b)

	dataDir := b.TempDir()
	dbPath := filepath.Join(dataDir, "bench.db")

	store, err := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
	if err != nil {
		b.Fatalf("failed to open database: %v", err)
	}

	masterKey := make([]byte, 32)
	provider, err := engine.NewLocalSecretsProvider(masterKey)
	if err != nil {
		b.Fatalf("secrets provider: %v", err)
	}
	secrets := engine.NewSecretsEngine(provider)

	mgr, err := engine.NewManager(store, secrets, engine.ManagerConfig{})
	if err != nil {
		b.Fatalf("engine: %v", err)
	}

	srv := api.NewServer(mgr, "organization", "bench-user", api.WithSingleTenantToken("test-token"))
	router := srv.Router()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	httpServer := &http.Server{Handler: router, ReadHeaderTimeout: 10 * time.Second} //nolint:gosec
	go func() { _ = httpServer.Serve(listener) }()

	tb := &testBackend{
		URL:     fmt.Sprintf("http://127.0.0.1:%d", port),
		server:  httpServer,
		store:   store,
		dataDir: dataDir,
		dbPath:  dbPath,
	}

	b.Cleanup(func() {
		_ = httpServer.Close()
		mgr.Shutdown()
		_ = store.Close()
	})

	waitForBackend(b, tb.URL)
	return tb
}

func benchHTTPDo(b *testing.B, method, url string, body []byte) *http.Response {
	b.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		b.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "token test-token")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Fatalf("request failed: %v", err)
	}
	return resp
}

// --- HTTP API Benchmarks ---

// BenchmarkHealthCheck measures baseline HTTP overhead.
func BenchmarkHealthCheck(b *testing.B) {
	tb := benchBackend(b)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		resp := benchHTTPDo(b, "GET", tb.URL+"/", nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkCreateStack measures stack creation throughput.
func BenchmarkCreateStack(b *testing.B) {
	tb := benchBackend(b)

	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		body := fmt.Sprintf(`{"stackName":"stack-%d"}`, i)
		resp := benchHTTPDo(b, "POST",
			fmt.Sprintf("%s/api/stacks/organization/project-%d", tb.URL, i), []byte(body))
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			b.Fatalf("create stack: status %d", resp.StatusCode)
		}
	}
}

// BenchmarkCheckpointSave benchmarks the full checkpoint save path (HTTP -> engine -> SQLite).
func BenchmarkCheckpointSave(b *testing.B) {
	for _, resourceCount := range []int{10, 100, 1000, 5000, 10000} {
		b.Run(fmt.Sprintf("resources=%d", resourceCount), func(b *testing.B) {
			tb := benchBackend(b)
			deployment := generateDeployment(resourceCount)
			b.SetBytes(int64(len(deployment)))

			// Create stack.
			resp := benchHTTPDo(b, "POST", tb.URL+"/api/stacks/organization/project", []byte(`{"stackName":"bench"}`))
			resp.Body.Close()

			b.ResetTimer()
			b.ReportAllocs()
			for i := range b.N {
				// Create update.
				resp = benchHTTPDo(b, "POST", tb.URL+"/api/stacks/organization/project/bench/update", []byte(`{"kind":"update"}`))
				var createResult struct{ UpdateID string }
				_ = json.NewDecoder(resp.Body).Decode(&createResult)
				resp.Body.Close()
				updateID := createResult.UpdateID

				// Start update.
				resp = benchHTTPDo(b, "POST", fmt.Sprintf("%s/api/stacks/organization/project/bench/update/%s", tb.URL, updateID), []byte("{}"))
				var startResult struct {
					Version int
					Token   string
				}
				_ = json.NewDecoder(resp.Body).Decode(&startResult)
				resp.Body.Close()

				// Save checkpoint.
				checkpointBody, _ := json.Marshal(map[string]any{"deployment": json.RawMessage(deployment)})
				req, _ := http.NewRequest("PATCH",
					fmt.Sprintf("%s/api/stacks/organization/project/bench/update/%s/checkpoint", tb.URL, updateID),
					bytes.NewReader(checkpointBody))
				req.Header.Set("Authorization", "token test-token")
				req.Header.Set("Content-Type", "application/json")
				resp, _ = http.DefaultClient.Do(req)
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					b.Fatalf("checkpoint save: status %d (iter %d)", resp.StatusCode, i)
				}

				// Complete update.
				resp = benchHTTPDo(b, "POST",
					fmt.Sprintf("%s/api/stacks/organization/project/bench/update/%s/complete", tb.URL, updateID),
					[]byte(`{"status":"succeeded","result":{"create":1}}`))
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		})
	}
}

// BenchmarkStateExport benchmarks state export (read path).
func BenchmarkStateExport(b *testing.B) {
	for _, resourceCount := range []int{10, 100, 1000, 5000, 10000} {
		b.Run(fmt.Sprintf("resources=%d", resourceCount), func(b *testing.B) {
			tb := benchBackend(b)
			deployment := generateDeployment(resourceCount)

			// Create stack and save initial state.
			resp := benchHTTPDo(b, "POST", tb.URL+"/api/stacks/organization/project", []byte(`{"stackName":"bench"}`))
			resp.Body.Close()

			// Import state to seed data.
			importBody, _ := json.Marshal(map[string]any{"deployment": json.RawMessage(deployment)})
			resp = benchHTTPDo(b, "POST", tb.URL+"/api/stacks/organization/project/bench/export", importBody)
			resp.Body.Close()

			b.SetBytes(int64(len(deployment)))
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				resp = benchHTTPDo(b, "GET", tb.URL+"/api/stacks/organization/project/bench/export", nil)
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					b.Fatalf("export: status %d", resp.StatusCode)
				}
			}
		})
	}
}

// BenchmarkSecretsEncrypt benchmarks the secrets encryption path.
func BenchmarkSecretsEncrypt(b *testing.B) {
	tb := benchBackend(b)

	resp := benchHTTPDo(b, "POST", tb.URL+"/api/stacks/organization/project", []byte(`{"stackName":"secrets-bench"}`))
	resp.Body.Close()

	plaintext := strings.Repeat("sensitive-data-", 10)
	body, _ := json.Marshal(map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte(plaintext))})

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		resp = benchHTTPDo(b, "POST",
			tb.URL+"/api/stacks/organization/project/secrets-bench/encrypt",
			body)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			b.Fatalf("encrypt: status %d", resp.StatusCode)
		}
	}
}

// BenchmarkSecretsDecrypt benchmarks the secrets decryption path.
func BenchmarkSecretsDecrypt(b *testing.B) {
	tb := benchBackend(b)

	resp := benchHTTPDo(b, "POST", tb.URL+"/api/stacks/organization/project", []byte(`{"stackName":"secrets-bench"}`))
	resp.Body.Close()

	// First encrypt to get a ciphertext.
	plaintext := strings.Repeat("sensitive-data-", 10)
	encBody, _ := json.Marshal(map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte(plaintext))})
	resp = benchHTTPDo(b, "POST", tb.URL+"/api/stacks/organization/project/secrets-bench/encrypt", encBody)
	var encResult struct{ Ciphertext string }
	_ = json.NewDecoder(resp.Body).Decode(&encResult)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		b.Fatalf("encrypt setup: status %d", resp.StatusCode)
	}

	decBody, _ := json.Marshal(map[string]string{"ciphertext": encResult.Ciphertext})

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		resp = benchHTTPDo(b, "POST",
			tb.URL+"/api/stacks/organization/project/secrets-bench/decrypt",
			decBody)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			b.Fatalf("decrypt: status %d", resp.StatusCode)
		}
	}
}

// BenchmarkListStacks measures stack listing performance with varying counts.
func BenchmarkListStacks(b *testing.B) {
	for _, stackCount := range []int{10, 100} {
		b.Run(fmt.Sprintf("stacks=%d", stackCount), func(b *testing.B) {
			tb := benchBackend(b)

			// Create stacks.
			for i := range stackCount {
				body := fmt.Sprintf(`{"stackName":"stack-%d"}`, i)
				resp := benchHTTPDo(b, "POST", tb.URL+"/api/stacks/organization/project", []byte(body))
				resp.Body.Close()
			}

			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				resp := benchHTTPDo(b, "GET", tb.URL+"/api/user/stacks", nil)
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					b.Fatalf("list stacks: status %d", resp.StatusCode)
				}
			}
		})
	}
}

// --- Engine-level benchmarks (bypass HTTP) ---

// BenchmarkEngineCompression benchmarks gzip compression of deployment data.
func BenchmarkEngineCompression(b *testing.B) {
	for _, resourceCount := range []int{10, 100, 1000, 5000, 10000} {
		b.Run(fmt.Sprintf("resources=%d", resourceCount), func(b *testing.B) {
			disableAuditForTest(b)

			dataDir := b.TempDir()
			dbPath := filepath.Join(dataDir, "bench.db")
			store, _ := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
			masterKey := make([]byte, 32)
			provider, _ := engine.NewLocalSecretsProvider(masterKey)
			secrets := engine.NewSecretsEngine(provider)
			mgr, _ := engine.NewManager(store, secrets, engine.ManagerConfig{})
			b.Cleanup(func() { mgr.Shutdown(); store.Close() })

			deployment := generateDeployment(resourceCount)
			b.SetBytes(int64(len(deployment)))

			ctx := context.Background()
			_ = mgr.CreateStack(ctx, "org", "proj", "bench", nil)

			b.ResetTimer()
			b.ReportAllocs()
			for i := range b.N {
				_ = mgr.ImportState(ctx, "org", "proj", "bench", deployment)
				_ = i
			}
		})
	}
}

// BenchmarkEngineExport benchmarks state export from cache and DB.
func BenchmarkEngineExport(b *testing.B) {
	for _, resourceCount := range []int{10, 100, 1000, 5000, 10000} {
		b.Run(fmt.Sprintf("resources=%d", resourceCount), func(b *testing.B) {
			disableAuditForTest(b)

			dataDir := b.TempDir()
			dbPath := filepath.Join(dataDir, "bench.db")
			store, _ := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
			masterKey := make([]byte, 32)
			provider, _ := engine.NewLocalSecretsProvider(masterKey)
			secrets := engine.NewSecretsEngine(provider)
			mgr, _ := engine.NewManager(store, secrets, engine.ManagerConfig{})
			b.Cleanup(func() { mgr.Shutdown(); store.Close() })

			deployment := generateDeployment(resourceCount)
			ctx := context.Background()
			_ = mgr.CreateStack(ctx, "org", "proj", "bench", nil)
			_ = mgr.ImportState(ctx, "org", "proj", "bench", deployment)

			b.SetBytes(int64(len(deployment)))
			b.ResetTimer()
			b.ReportAllocs()

			b.Run("cached", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_, err := mgr.ExportState(ctx, "org", "proj", "bench", nil)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// BenchmarkSHA256 benchmarks SHA256 hashing at various deployment sizes.
func BenchmarkSHA256(b *testing.B) {
	for _, size := range []int{1024, 10 * 1024, 100 * 1024, 1024 * 1024} {
		b.Run(fmt.Sprintf("size=%dKB", size/1024), func(b *testing.B) {
			data := make([]byte, size)
			_, _ = rand.Read(data)
			b.SetBytes(int64(size))

			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				h := sha256.Sum256(data)
				hex.EncodeToString(h[:])
			}
		})
	}
}

// BenchmarkUpdateLifecycle measures the full update lifecycle (create, start, checkpoint, complete).
func BenchmarkUpdateLifecycle(b *testing.B) {
	disableAuditForTest(b)

	dataDir := b.TempDir()
	dbPath := filepath.Join(dataDir, "bench.db")
	store, _ := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
	masterKey := make([]byte, 32)
	provider, _ := engine.NewLocalSecretsProvider(masterKey)
	secrets := engine.NewSecretsEngine(provider)
	mgr, _ := engine.NewManager(store, secrets, engine.ManagerConfig{})
	b.Cleanup(func() { mgr.Shutdown(); store.Close() })

	deployment := generateDeployment(50)
	ctx := context.Background()
	_ = mgr.CreateStack(ctx, "org", "proj", "bench", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		result, err := mgr.CreateUpdate(ctx, "org", "proj", "bench", "update", nil, nil)
		if err != nil {
			b.Fatal(err)
		}

		startResult, err := mgr.StartUpdate(ctx, result.UpdateID, nil, 0)
		if err != nil {
			b.Fatal(err)
		}
		_ = startResult

		if err := mgr.SaveCheckpoint(ctx, result.UpdateID, deployment); err != nil {
			b.Fatal(err)
		}

		if err := mgr.CompleteUpdate(ctx, result.UpdateID, "succeeded", json.RawMessage(`{"create":1}`)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSecretsEngine benchmarks encrypt/decrypt directly.
func BenchmarkSecretsEngine(b *testing.B) {
	disableAuditForTest(b)

	dataDir := b.TempDir()
	dbPath := filepath.Join(dataDir, "bench.db")
	store, _ := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
	masterKey := make([]byte, 32)
	provider, _ := engine.NewLocalSecretsProvider(masterKey)
	secrets := engine.NewSecretsEngine(provider)
	mgr, _ := engine.NewManager(store, secrets, engine.ManagerConfig{})
	b.Cleanup(func() { mgr.Shutdown(); store.Close() })

	ctx := context.Background()
	_ = mgr.CreateStack(ctx, "org", "proj", "bench", nil)

	plaintext := []byte(strings.Repeat("secret-value-", 10))

	b.Run("encrypt", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := mgr.EncryptValue(ctx, "org", "proj", "bench", plaintext)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	ciphertext, _ := mgr.EncryptValue(ctx, "org", "proj", "bench", plaintext)

	b.Run("decrypt", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := mgr.DecryptValue(ctx, "org", "proj", "bench", ciphertext)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkJournalSave benchmarks journal entry saves.
func BenchmarkJournalSave(b *testing.B) {
	for _, batchSize := range []int{1, 10, 50} {
		b.Run(fmt.Sprintf("batch=%d", batchSize), func(b *testing.B) {
			disableAuditForTest(b)

			dataDir := b.TempDir()
			dbPath := filepath.Join(dataDir, "bench.db")
			store, _ := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
			masterKey := make([]byte, 32)
			provider, _ := engine.NewLocalSecretsProvider(masterKey)
			secrets := engine.NewSecretsEngine(provider)
			mgr, _ := engine.NewManager(store, secrets, engine.ManagerConfig{})
			b.Cleanup(func() { mgr.Shutdown(); store.Close() })

			ctx := context.Background()
			_ = mgr.CreateStack(ctx, "org", "proj", "bench", nil)

			result, _ := mgr.CreateUpdate(ctx, "org", "proj", "bench", "update", nil, nil)
			_, _ = mgr.StartUpdate(ctx, result.UpdateID, nil, 1)

			// Use unique sequence IDs per iteration to avoid PK conflicts.
			seq := 0
			b.ResetTimer()
			b.ReportAllocs()
			for range b.N {
				entries := make([]json.RawMessage, batchSize)
				for i := range batchSize {
					seq++
					entries[i] = json.RawMessage(fmt.Sprintf(`{"sequenceID":%d,"type":"resource","payload":{"urn":"urn:pulumi:dev::test::pkg:mod:Res::r","type":"pkg:mod:Res"}}`, seq))
				}
				if err := mgr.SaveJournalEntries(ctx, result.UpdateID, entries); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEventSave benchmarks engine event saves (buffered path).
func BenchmarkEventSave(b *testing.B) {
	disableAuditForTest(b)

	dataDir := b.TempDir()
	dbPath := filepath.Join(dataDir, "bench.db")
	store, _ := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
	masterKey := make([]byte, 32)
	provider, _ := engine.NewLocalSecretsProvider(masterKey)
	secrets := engine.NewSecretsEngine(provider)
	mgr, _ := engine.NewManager(store, secrets, engine.ManagerConfig{
		EventBufferSize:    10000,
		EventFlushInterval: time.Hour, // Don't auto-flush during benchmark.
	})
	b.Cleanup(func() { mgr.Shutdown(); store.Close() })

	ctx := context.Background()
	_ = mgr.CreateStack(ctx, "org", "proj", "bench", nil)
	result, _ := mgr.CreateUpdate(ctx, "org", "proj", "bench", "update", nil, nil)
	_, _ = mgr.StartUpdate(ctx, result.UpdateID, nil, 0)

	events := make([]json.RawMessage, 10)
	for i := range 10 {
		events[i] = json.RawMessage(fmt.Sprintf(`{"sequence":%d,"event":{"type":"diagnostic","message":"msg %d"}}`, i, i))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if err := mgr.SaveEngineEvents(ctx, result.UpdateID, events); err != nil {
			b.Fatal(err)
		}
	}
}

// --- Concurrent load benchmarks ---

// BenchmarkConcurrentUpdates runs full update lifecycles in parallel across
// separate stacks, stressing SQLite WAL contention and engine lock paths.
// Each iteration uses a unique stack to avoid update lock conflicts.
func BenchmarkConcurrentUpdates(b *testing.B) {
	for _, parallelism := range []int{2, 4, 8, 16} {
		b.Run(fmt.Sprintf("parallel=%d", parallelism), func(b *testing.B) {
			disableAuditForTest(b)

			dataDir := b.TempDir()
			dbPath := filepath.Join(dataDir, "bench.db")
			store, _ := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
			masterKey := make([]byte, 32)
			provider, _ := engine.NewLocalSecretsProvider(masterKey)
			secrets := engine.NewSecretsEngine(provider)
			mgr, _ := engine.NewManager(store, secrets, engine.ManagerConfig{})
			b.Cleanup(func() { mgr.Shutdown(); store.Close() })

			deployment := generateDeployment(1000)
			ctx := context.Background()

			// Pre-create enough stacks for all iterations.
			const maxStacks = 1024
			for i := range maxStacks {
				_ = mgr.CreateStack(ctx, "org", fmt.Sprintf("proj-%d", i), "stack", nil)
			}

			var counter atomic.Int64
			b.SetBytes(int64(len(deployment)))
			b.ResetTimer()
			b.ReportAllocs()
			b.SetParallelism(parallelism)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					idx := counter.Add(1) - 1
					proj := fmt.Sprintf("proj-%d", idx%maxStacks)

					result, err := mgr.CreateUpdate(ctx, "org", proj, "stack", "update", nil, nil)
					if err != nil {
						b.Errorf("CreateUpdate: %v", err)
						return
					}
					if _, err := mgr.StartUpdate(ctx, result.UpdateID, nil, 0); err != nil {
						b.Errorf("StartUpdate: %v", err)
						return
					}
					if err := mgr.SaveCheckpoint(ctx, result.UpdateID, deployment); err != nil {
						b.Errorf("SaveCheckpoint: %v", err)
						return
					}
					if err := mgr.CompleteUpdate(ctx, result.UpdateID, "succeeded", json.RawMessage(`{"create":1}`)); err != nil {
						b.Errorf("CompleteUpdate: %v", err)
						return
					}
				}
			})
		})
	}
}

// BenchmarkConcurrentCheckpoints runs parallel checkpoint saves on separate stacks
// with large deployments (5000 resources), stressing gzip compression pools and
// SQLite write throughput.
func BenchmarkConcurrentCheckpoints(b *testing.B) {
	for _, resourceCount := range []int{1000, 5000, 10000} {
		b.Run(fmt.Sprintf("resources=%d", resourceCount), func(b *testing.B) {
			const maxStacks = 1024
			disableAuditForTest(b)

			dataDir := b.TempDir()
			dbPath := filepath.Join(dataDir, "bench.db")
			store, _ := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
			masterKey := make([]byte, 32)
			provider, _ := engine.NewLocalSecretsProvider(masterKey)
			secrets := engine.NewSecretsEngine(provider)
			mgr, _ := engine.NewManager(store, secrets, engine.ManagerConfig{})
			b.Cleanup(func() { mgr.Shutdown(); store.Close() })

			deployment := generateDeployment(resourceCount)
			ctx := context.Background()

			for i := range maxStacks {
				_ = mgr.CreateStack(ctx, "org", fmt.Sprintf("proj-%d", i), "stack", nil)
			}

			var counter atomic.Int64
			b.SetBytes(int64(len(deployment)))
			b.ResetTimer()
			b.ReportAllocs()
			b.SetParallelism(8)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					idx := counter.Add(1) - 1
					proj := fmt.Sprintf("proj-%d", idx%maxStacks)

					result, err := mgr.CreateUpdate(ctx, "org", proj, "stack", "update", nil, nil)
					if err != nil {
						b.Errorf("CreateUpdate: %v", err)
						return
					}
					if _, err := mgr.StartUpdate(ctx, result.UpdateID, nil, 0); err != nil {
						b.Errorf("StartUpdate: %v", err)
						return
					}
					if err := mgr.SaveCheckpoint(ctx, result.UpdateID, deployment); err != nil {
						b.Errorf("SaveCheckpoint: %v", err)
						return
					}
					if err := mgr.CompleteUpdate(ctx, result.UpdateID, "succeeded", json.RawMessage(`{"create":1}`)); err != nil {
						b.Errorf("CompleteUpdate: %v", err)
						return
					}
				}
			})
		})
	}
}

// BenchmarkConcurrentHTTPCheckpoints is the HTTP-level variant — parallel clients
// saving large checkpoints through the full HTTP stack.
func BenchmarkConcurrentHTTPCheckpoints(b *testing.B) {
	for _, resourceCount := range []int{1000, 5000} {
		b.Run(fmt.Sprintf("resources=%d", resourceCount), func(b *testing.B) {
			const (
				parallelism = 8
				maxStacks   = 512
			)
			tb := benchBackend(b)
			deployment := generateDeployment(resourceCount)

			// Pre-create stacks.
			for i := range maxStacks {
				body := `{"stackName":"stack"}`
				resp := benchHTTPDo(b, "POST", fmt.Sprintf("%s/api/stacks/organization/proj-%d", tb.URL, i), []byte(body))
				resp.Body.Close()
			}

			var counter atomic.Int64
			b.SetBytes(int64(len(deployment)))
			b.ResetTimer()
			b.ReportAllocs()
			b.SetParallelism(parallelism)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					idx := counter.Add(1) - 1
					proj := fmt.Sprintf("proj-%d", idx%maxStacks)

					// Create update.
					resp := benchHTTPDo(b, "POST",
						fmt.Sprintf("%s/api/stacks/organization/%s/stack/update", tb.URL, proj),
						[]byte(`{"kind":"update"}`))
					var createResult struct{ UpdateID string }
					_ = json.NewDecoder(resp.Body).Decode(&createResult)
					resp.Body.Close()
					updateID := createResult.UpdateID

					// Start update.
					resp = benchHTTPDo(b, "POST",
						fmt.Sprintf("%s/api/stacks/organization/%s/stack/update/%s", tb.URL, proj, updateID),
						[]byte("{}"))
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()

					// Save checkpoint.
					checkpointBody, _ := json.Marshal(map[string]any{"deployment": json.RawMessage(deployment)})
					req, _ := http.NewRequest("PATCH",
						fmt.Sprintf("%s/api/stacks/organization/%s/stack/update/%s/checkpoint", tb.URL, proj, updateID),
						bytes.NewReader(checkpointBody))
					req.Header.Set("Authorization", "token test-token")
					req.Header.Set("Content-Type", "application/json")
					resp, _ = http.DefaultClient.Do(req)
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode != 200 {
						b.Errorf("checkpoint save: status %d", resp.StatusCode)
						return
					}

					// Complete update.
					resp = benchHTTPDo(b, "POST",
						fmt.Sprintf("%s/api/stacks/organization/%s/stack/update/%s/complete", tb.URL, proj, updateID),
						[]byte(`{"status":"succeeded","result":{"create":1}}`))
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			})
		})
	}
}

// BenchmarkConcurrentExportsWhileUpdating reads state exports on some stacks
// while other stacks are being updated — mixed read/write workload.
func BenchmarkConcurrentExportsWhileUpdating(b *testing.B) {
	disableAuditForTest(b)

	dataDir := b.TempDir()
	dbPath := filepath.Join(dataDir, "bench.db")
	store, _ := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
	masterKey := make([]byte, 32)
	provider, _ := engine.NewLocalSecretsProvider(masterKey)
	secrets := engine.NewSecretsEngine(provider)
	mgr, _ := engine.NewManager(store, secrets, engine.ManagerConfig{})
	b.Cleanup(func() { mgr.Shutdown(); store.Close() })

	const (
		writerStacks = 512
		readerStacks = 4
	)

	deployment := generateDeployment(2000)
	ctx := context.Background()

	// Create writer stacks (each iteration gets a unique one).
	for i := range writerStacks {
		_ = mgr.CreateStack(ctx, "org", fmt.Sprintf("writer-%d", i), "stack", nil)
	}
	// Create reader stacks and seed with state.
	for i := range readerStacks {
		_ = mgr.CreateStack(ctx, "org", fmt.Sprintf("reader-%d", i), "stack", nil)
		_ = mgr.ImportState(ctx, "org", fmt.Sprintf("reader-%d", i), "stack", deployment)
	}

	var writerCounter atomic.Int64
	var readerCounter atomic.Int64
	b.SetBytes(int64(len(deployment)))
	b.ResetTimer()
	b.ReportAllocs()
	b.SetParallelism(8)
	b.RunParallel(func(pb *testing.PB) {
		// Alternate: odd goroutines write, even goroutines read.
		isWriter := writerCounter.Add(1)%2 == 1
		for pb.Next() {
			if isWriter {
				idx := writerCounter.Add(1) - 1
				proj := fmt.Sprintf("writer-%d", idx%writerStacks)
				result, err := mgr.CreateUpdate(ctx, "org", proj, "stack", "update", nil, nil)
				if err != nil {
					b.Errorf("CreateUpdate: %v", err)
					return
				}
				if _, err := mgr.StartUpdate(ctx, result.UpdateID, nil, 0); err != nil {
					b.Errorf("StartUpdate: %v", err)
					return
				}
				if err := mgr.SaveCheckpoint(ctx, result.UpdateID, deployment); err != nil {
					b.Errorf("SaveCheckpoint: %v", err)
					return
				}
				if err := mgr.CompleteUpdate(ctx, result.UpdateID, "succeeded", json.RawMessage(`{"create":1}`)); err != nil {
					b.Errorf("CompleteUpdate: %v", err)
					return
				}
			} else {
				idx := readerCounter.Add(1) - 1
				proj := fmt.Sprintf("reader-%d", idx%readerStacks)
				if _, err := mgr.ExportState(ctx, "org", proj, "stack", nil); err != nil {
					b.Errorf("ExportState: %v", err)
					return
				}
			}
		}
	})
}

// BenchmarkRenameUnderLoad renames stacks while concurrent updates are running
// on other stacks. Tests SQLite row-level write contention between rename
// (UPDATE stacks SET) and checkpoint saves (INSERT/UPDATE deployments).
func BenchmarkRenameUnderLoad(b *testing.B) {
	disableAuditForTest(b)

	dataDir := b.TempDir()
	dbPath := filepath.Join(dataDir, "bench.db")
	store, _ := storage.NewSQLiteStore(dbPath, storage.SQLiteStoreConfig{})
	masterKey := make([]byte, 32)
	provider, _ := engine.NewLocalSecretsProvider(masterKey)
	secrets := engine.NewSecretsEngine(provider)
	mgr, _ := engine.NewManager(store, secrets, engine.ManagerConfig{})
	b.Cleanup(func() { mgr.Shutdown(); store.Close() })

	const updaterCount = 4
	deployment := generateDeployment(1000)
	ctx := context.Background()

	// Create updater stacks (these run continuous updates).
	for i := range updaterCount {
		_ = mgr.CreateStack(ctx, "org", fmt.Sprintf("updater-%d", i), "stack", nil)
	}

	// Start a background goroutine per updater stack running continuous updates.
	stopUpdaters := make(chan struct{})
	updatersDone := make(chan struct{})
	go func() {
		defer close(updatersDone)
		var wg sync.WaitGroup
		for i := range updaterCount {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				proj := fmt.Sprintf("updater-%d", idx)
				for {
					select {
					case <-stopUpdaters:
						return
					default:
					}
					result, err := mgr.CreateUpdate(ctx, "org", proj, "stack", "update", nil, nil)
					if err != nil {
						continue
					}
					if _, err := mgr.StartUpdate(ctx, result.UpdateID, nil, 0); err != nil {
						continue
					}
					_ = mgr.SaveCheckpoint(ctx, result.UpdateID, deployment)
					_ = mgr.CompleteUpdate(ctx, result.UpdateID, "succeeded", json.RawMessage(`{"create":1}`))
				}
			}(i)
		}
		wg.Wait()
	}()

	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		proj := fmt.Sprintf("rename-%d", i)
		_ = mgr.CreateStack(ctx, "org", proj, "before", nil)
		_ = mgr.ImportState(ctx, "org", proj, "before", deployment)

		err := mgr.RenameStack(ctx, "org", proj, "before", proj, "after")
		if err != nil {
			b.Fatalf("RenameStack: %v", err)
		}

		// Verify state survived rename.
		data, err := mgr.ExportState(ctx, "org", proj, "after", nil)
		if err != nil {
			b.Fatalf("ExportState after rename: %v", err)
		}
		if len(data) == 0 {
			b.Fatal("empty state after rename")
		}

		// Clean up.
		_ = mgr.DeleteStack(ctx, "org", proj, "after", true)
	}

	close(stopUpdaters)
	<-updatersDone
}

// BenchmarkRenameHTTPUnderLoad is the HTTP-level variant — rename requests
// through the full HTTP stack while concurrent checkpoint saves are running.
func BenchmarkRenameHTTPUnderLoad(b *testing.B) {
	tb := benchBackend(b)

	const updaterCount = 4
	deployment := generateDeployment(1000)

	// Create updater stacks.
	for i := range updaterCount {
		resp := benchHTTPDo(b, "POST",
			fmt.Sprintf("%s/api/stacks/organization/updater-%d", tb.URL, i),
			[]byte(`{"stackName":"stack"}`))
		resp.Body.Close()
	}

	// Background updaters.
	stopUpdaters := make(chan struct{})
	updatersDone := make(chan struct{})
	go func() {
		defer close(updatersDone)
		var wg sync.WaitGroup
		for i := range updaterCount {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				proj := fmt.Sprintf("updater-%d", idx)
				for {
					select {
					case <-stopUpdaters:
						return
					default:
					}

					resp := benchHTTPDo(b, "POST",
						fmt.Sprintf("%s/api/stacks/organization/%s/stack/update", tb.URL, proj),
						[]byte(`{"kind":"update"}`))
					var cr struct{ UpdateID string }
					_ = json.NewDecoder(resp.Body).Decode(&cr)
					resp.Body.Close()

					resp = benchHTTPDo(b, "POST",
						fmt.Sprintf("%s/api/stacks/organization/%s/stack/update/%s", tb.URL, proj, cr.UpdateID),
						[]byte("{}"))
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()

					checkpointBody, _ := json.Marshal(map[string]any{"deployment": json.RawMessage(deployment)})
					req, _ := http.NewRequest("PATCH",
						fmt.Sprintf("%s/api/stacks/organization/%s/stack/update/%s/checkpoint", tb.URL, proj, cr.UpdateID),
						bytes.NewReader(checkpointBody))
					req.Header.Set("Authorization", "token test-token")
					req.Header.Set("Content-Type", "application/json")
					resp, _ = http.DefaultClient.Do(req)
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()

					resp = benchHTTPDo(b, "POST",
						fmt.Sprintf("%s/api/stacks/organization/%s/stack/update/%s/complete", tb.URL, proj, cr.UpdateID),
						[]byte(`{"status":"succeeded","result":{"create":1}}`))
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}(i)
		}
		wg.Wait()
	}()

	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		proj := fmt.Sprintf("rename-%d", i)

		// Create stack with state.
		resp := benchHTTPDo(b, "POST",
			fmt.Sprintf("%s/api/stacks/organization/%s", tb.URL, proj),
			[]byte(`{"stackName":"before"}`))
		resp.Body.Close()

		importBody, _ := json.Marshal(map[string]any{"deployment": json.RawMessage(deployment)})
		resp = benchHTTPDo(b, "POST",
			fmt.Sprintf("%s/api/stacks/organization/%s/before/export", tb.URL, proj),
			importBody)
		resp.Body.Close()

		// Rename.
		resp = benchHTTPDo(b, "POST",
			fmt.Sprintf("%s/api/stacks/organization/%s/before/rename", tb.URL, proj),
			[]byte(`{"newName":"after"}`))
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			b.Fatalf("rename: status %d (iter %d)", resp.StatusCode, i)
		}

		// Verify state survived.
		resp = benchHTTPDo(b, "GET",
			fmt.Sprintf("%s/api/stacks/organization/%s/after/export", tb.URL, proj),
			nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			b.Fatalf("export after rename: status %d (iter %d)", resp.StatusCode, i)
		}

		// Clean up.
		resp = benchHTTPDo(b, "DELETE",
			fmt.Sprintf("%s/api/stacks/organization/%s/after", tb.URL, proj),
			[]byte(`{"force":true}`))
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	close(stopUpdaters)
	<-updatersDone
}
