package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hatemosphere/pulumi-backend/internal/compatref"
)

func main() {
	snapshot, err := compatref.LoadCurrentPulumiHTTPContract()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load contract: %v\n", err)
		os.Exit(1)
	}

	data, err := compatref.MarshalSnapshot(snapshot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal contract: %v\n", err)
		os.Exit(1)
	}

	outPath := filepath.Join("tests", "testdata", "pulumi_http_contract.json")
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, append(data, '\n'), 0o644); err != nil { //nolint:gosec // committed testdata file
		fmt.Fprintf(os.Stderr, "write snapshot: %v\n", err)
		os.Exit(1)
	}
}
