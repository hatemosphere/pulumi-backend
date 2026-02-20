package tests

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
)

// TestGroupsResolutionADC tests the Google groups resolver using Application Default Credentials
// with IAM impersonation for keyless domain-wide delegation.
//
// Requires:
//   - ADC configured (user or SA credentials with iam.serviceAccountTokenCreator on the target SA)
//   - The target SA has domain-wide delegation for admin.directory.group.readonly
//   - GOOGLE_SA_EMAIL env var set to the DWD service account email
//   - GOOGLE_ADMIN_EMAIL env var set to a Workspace super-admin email
//   - GOOGLE_EXPECTED_GROUPS env var set to comma-separated group emails to verify
//
// Run:
//
//	GOOGLE_SA_EMAIL=my-sa@project.iam.gserviceaccount.com \
//	GOOGLE_ADMIN_EMAIL=admin@example.com \
//	GOOGLE_EXPECTED_GROUPS=admins@example.com,devs@example.com \
//	go test -v -run TestGroupsResolutionADC ./tests/
func TestGroupsResolutionADC(t *testing.T) {
	saEmail := os.Getenv("GOOGLE_SA_EMAIL")
	adminEmail := os.Getenv("GOOGLE_ADMIN_EMAIL")
	if saEmail == "" || adminEmail == "" {
		t.Skip("GOOGLE_SA_EMAIL or GOOGLE_ADMIN_EMAIL not set, skipping groups integration test")
	}

	ctx := context.Background()

	// Create resolver with SA email for keyless DWD via IAM impersonation.
	resolver, err := auth.NewGroupsResolver(ctx, "", saEmail, adminEmail, false)
	if err != nil {
		t.Fatalf("NewGroupsResolver (ADC): %v", err)
	}

	// Resolve groups for the admin user.
	groups, err := resolver.ResolveGroups(ctx, adminEmail)
	if err != nil {
		t.Fatalf("ResolveGroups(%s): %v", adminEmail, err)
	}

	t.Logf("Groups for %s: %v", adminEmail, groups)

	if len(groups) == 0 {
		t.Fatal("expected at least one group, got none")
	}

	// Check expected groups if configured.
	expectedStr := os.Getenv("GOOGLE_EXPECTED_GROUPS")
	if expectedStr == "" {
		t.Logf("GOOGLE_EXPECTED_GROUPS not set, skipping group membership check (found %d groups)", len(groups))
		return
	}

	expected := make(map[string]bool)
	for _, g := range strings.Split(expectedStr, ",") {
		g = strings.TrimSpace(g)
		if g != "" {
			expected[g] = false
		}
	}

	for _, g := range groups {
		if _, ok := expected[g]; ok {
			expected[g] = true
		}
	}
	for group, found := range expected {
		if !found {
			t.Errorf("expected group %s not found in results", group)
		}
	}
}
