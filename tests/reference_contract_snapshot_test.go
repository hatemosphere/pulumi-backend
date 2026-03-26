package tests

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hatemosphere/pulumi-backend/internal/compatref"
)

func TestPulumiHTTPContractSnapshotUpToDate(t *testing.T) {
	current, err := compatref.LoadCurrentPulumiHTTPContract()
	require.NoError(t, err)

	snapshotPath := filepath.Join("testdata", "pulumi_http_contract.json")
	snapshot, err := compatref.LoadSnapshot(snapshotPath)
	require.NoError(t, err)

	require.Equal(t, current, snapshot,
		"Pulumi HTTP contract snapshot is stale. Regenerate with: go run ./cmd/dump-pulumi-http-contract")
}
