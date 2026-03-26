package compatref

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
)

type PulumiHTTPEndpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Name   string `json:"name"`
}

type PulumiHTTPContractSnapshot struct {
	PulumiGitCommit  string               `json:"pulumiGitCommit,omitempty"`
	PulumiSDKVersion string               `json:"pulumiSdkVersion"`
	SourceFile       string               `json:"sourceFile"`
	Endpoints        []PulumiHTTPEndpoint `json:"endpoints"`
}

var addEndpointPattern = regexp.MustCompile(`addEndpoint\("([^"]+)", "([^"]+)", "([^"]+)"\)`)

func ReferenceSourceAvailable() bool {
	root, err := repoRoot()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(root, "reference", "pulumi", "pkg", "backend", "httpstate", "client", "api_endpoints.go"))
	return err == nil
}

func LoadCurrentPulumiHTTPContract() (*PulumiHTTPContractSnapshot, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}

	sourceFile := filepath.Join(root, "reference", "pulumi", "pkg", "backend", "httpstate", "client", "api_endpoints.go")
	data, err := os.ReadFile(sourceFile)
	if err != nil {
		return nil, fmt.Errorf("read upstream endpoint map: %w", err)
	}

	matches := addEndpointPattern.FindAllStringSubmatch(string(data), -1)
	endpoints := make([]PulumiHTTPEndpoint, 0, len(matches))
	for _, match := range matches {
		endpoints = append(endpoints, PulumiHTTPEndpoint{
			Method: match[1],
			Path:   match[2],
			Name:   match[3],
		})
	}
	slices.SortFunc(endpoints, func(a, b PulumiHTTPEndpoint) int {
		if c := strings.Compare(a.Method, b.Method); c != 0 {
			return c
		}
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})

	return &PulumiHTTPContractSnapshot{
		PulumiGitCommit:  gitCommit(filepath.Join(root, "reference", "pulumi")),
		PulumiSDKVersion: strings.TrimSpace(readFile(filepath.Join(root, "reference", "pulumi", "sdk", ".version"))),
		SourceFile:       "reference/pulumi/pkg/backend/httpstate/client/api_endpoints.go",
		Endpoints:        endpoints,
	}, nil
}

func LoadSnapshot(path string) (*PulumiHTTPContractSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snapshot PulumiHTTPContractSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &snapshot, nil
}

func MarshalSnapshot(snapshot *PulumiHTTPContractSnapshot) ([]byte, error) {
	return json.MarshalIndent(snapshot, "", "  ")
}

func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("resolve caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..")), nil
}

func gitCommit(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
