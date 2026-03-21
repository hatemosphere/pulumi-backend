package config

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgsReturnsErrorsInsteadOfExiting(t *testing.T) {
	t.Parallel()

	_, err := ParseArgs([]string{"-not-a-real-flag"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}

func TestParseArgsAutoGeneratesMasterKeyWarning(t *testing.T) {
	t.Parallel()

	var warnings bytes.Buffer
	cfg, err := ParseArgs([]string{"-auth-mode", "single-tenant"}, &warnings)
	require.NoError(t, err)
	require.Len(t, cfg.MasterKey, 64)
	assert.Contains(t, warnings.String(), "WARNING: auto-generated master key")
}

func TestParseArgsSkipsMasterKeyWarningForGCPKMS(t *testing.T) {
	t.Parallel()

	var warnings bytes.Buffer
	cfg, err := ParseArgs([]string{"-secrets-provider", "gcpkms", "-kms-key", "projects/p/locations/l/keyRings/r/cryptoKeys/k"}, &warnings)
	require.NoError(t, err)
	assert.Empty(t, cfg.MasterKey)
	assert.Empty(t, strings.TrimSpace(warnings.String()))
}
