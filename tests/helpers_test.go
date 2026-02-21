package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// testBackend holds a running backend server for integration tests.
type testBackend struct {
	URL     string
	server  *http.Server
	store   *storage.SQLiteStore
	dataDir string
}

// startBackend starts a fresh backend server on a random port with default options.
func startBackend(t *testing.T) *testBackend {
	t.Helper()
	return startBackendWithOpts(t)
}

// backendConfig allows customizing engine and storage configuration for tests.
type backendConfig struct {
	serverOpts    []api.ServerOption
	engineConfig  engine.ManagerConfig
	storageConfig storage.SQLiteStoreConfig
}

// startBackendWithConfig starts a backend with custom engine and storage config.
func startBackendWithConfig(t *testing.T, cfg backendConfig) *testBackend {
	t.Helper()

	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "test.db")

	store, err := storage.NewSQLiteStore(dbPath, cfg.storageConfig)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	masterKey := make([]byte, 32)
	provider, err := engine.NewLocalSecretsProvider(masterKey)
	if err != nil {
		t.Fatalf("failed to create secrets provider: %v", err)
	}
	secrets := engine.NewSecretsEngine(provider)

	mgr, err := engine.NewManager(store, secrets, cfg.engineConfig)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	srv := api.NewServer(mgr, "organization", "test-user", cfg.serverOpts...)
	router := srv.Router()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	httpServer := &http.Server{Handler: router, ReadHeaderTimeout: 10 * time.Second} //nolint:gosec // test server
	go func() { _ = httpServer.Serve(listener) }()

	tb := &testBackend{
		URL:     fmt.Sprintf("http://127.0.0.1:%d", port),
		server:  httpServer,
		store:   store,
		dataDir: dataDir,
	}

	// Wait for server to be ready.
	for i := 0; i < 50; i++ {
		resp, err := http.Get(tb.URL + "/")
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Cleanup(func() {
		_ = httpServer.Close()
		_ = store.Close()
	})
	return tb
}

// --- CLI helpers ---

// requireCLI skips the test if the pulumi CLI binary is not available.
func requireCLI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pulumi"); err != nil {
		t.Skip("pulumi CLI not in PATH, skipping CLI integration test")
	}
}

// pulumi runs a pulumi CLI command against the test backend.
func (tb *testBackend) pulumi(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return tb.pulumiEnv(t, dir, nil, args...)
}

// pulumiEnv runs a pulumi CLI command with extra environment variables.
func (tb *testBackend) pulumiEnv(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()

	cmd := exec.Command("pulumi", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PULUMI_ACCESS_TOKEN=test-token",
		"PULUMI_BACKEND_URL="+tb.URL,
		"PULUMI_HOME="+tb.dataDir,
		"PULUMI_SKIP_UPDATE_CHECK=true",
		"NO_COLOR=true",
	)
	cmd.Env = append(cmd.Env, env...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pulumi %s failed: %v\nOutput:\n%s", strings.Join(args, " "), err, string(out))
	}
	return string(out)
}

// pulumiExpectFailure runs a pulumi command and expects it to fail.
func (tb *testBackend) pulumiExpectFailure(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("pulumi", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PULUMI_ACCESS_TOKEN=test-token",
		"PULUMI_BACKEND_URL="+tb.URL,
		"PULUMI_HOME="+tb.dataDir,
		"PULUMI_SKIP_UPDATE_CHECK=true",
		"NO_COLOR=true",
	)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("pulumi %s expected to fail but succeeded\nOutput:\n%s", strings.Join(args, " "), string(out))
	}
	return string(out)
}

// pulumiMayFail runs a pulumi command and returns output + error (doesn't fatal).
func (tb *testBackend) pulumiMayFail(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()

	cmd := exec.Command("pulumi", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PULUMI_ACCESS_TOKEN=test-token",
		"PULUMI_BACKEND_URL="+tb.URL,
		"PULUMI_HOME="+tb.dataDir,
		"PULUMI_SKIP_UPDATE_CHECK=true",
		"NO_COLOR=true",
	)
	cmd.Env = append(cmd.Env, env...)

	out, err := cmd.CombinedOutput()
	return string(out), err
}

// makeYAMLProject creates a minimal Pulumi YAML project in a temp directory.
func makeYAMLProject(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(content), 0o644)
	if err != nil {
		t.Fatalf("failed to write Pulumi.yaml: %v", err)
	}
	return dir
}

// --- HTTP helpers ---

// httpDo is a helper for direct HTTP API calls against the test backend.
func (tb *testBackend) httpDo(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, tb.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "token test-token")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

// httpJSON decodes a JSON response body into v and closes the body.
func httpJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("failed to unmarshal response (%s): %v", string(b), err)
	}
}
