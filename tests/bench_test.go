package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
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

	srv := api.NewServer(mgr, "organization", "bench-user")
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
	for _, resourceCount := range []int{10, 100, 1000} {
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
				resp = benchHTTPDo(b, "POST", fmt.Sprintf("%s/api/stacks/organization/project/bench/update/%s/start", tb.URL, updateID), []byte("{}"))
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
	for _, resourceCount := range []int{10, 100, 1000} {
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
	body, _ := json.Marshal(map[string]string{"plaintext": plaintext})

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
	encBody, _ := json.Marshal(map[string]string{"plaintext": plaintext})
	resp = benchHTTPDo(b, "POST", tb.URL+"/api/stacks/organization/project/secrets-bench/encrypt", encBody)
	var encResult struct{ Ciphertext string }
	_ = json.NewDecoder(resp.Body).Decode(&encResult)
	resp.Body.Close()

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
	for _, resourceCount := range []int{10, 100, 1000} {
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
	for _, resourceCount := range []int{10, 100, 1000} {
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
	for range b.N {
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
	for range b.N {
		if err := mgr.SaveEngineEvents(ctx, result.UpdateID, events); err != nil {
			b.Fatal(err)
		}
	}
}
