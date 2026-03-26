package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/clockutil"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

type benchOIDCAuthenticator struct{}

func (benchOIDCAuthenticator) Exchange(ctx context.Context, rawIDToken string) (*auth.OIDCAuthResult, error) {
	panic("not used in benchmark")
}

func (benchOIDCAuthenticator) Revalidate(ctx context.Context, refreshToken string) error {
	return nil
}

func (benchOIDCAuthenticator) AuthCodeURL(redirectURI, state string) (authURL, nonce string) {
	panic("not used in benchmark")
}

func (benchOIDCAuthenticator) ExchangeCode(ctx context.Context, code, redirectURI, expectedNonce string) (*auth.CodeExchangeResult, error) {
	panic("not used in benchmark")
}

func (benchOIDCAuthenticator) Config() auth.OIDCConfig {
	return auth.OIDCConfig{}
}

func BenchmarkListVisibleStacksPage(b *testing.B) {
	resolver, err := auth.NewRBACResolver(&auth.RBACConfig{
		DefaultPermission: "none",
		StackPolicies: []auth.StackPolicy{
			{Group: "devs", StackPattern: "organization/proj-visible-*/*", Permission: "read"},
		},
	})
	require.NoError(b, err)

	srv := newSQLiteTestServerWithOptions(b, WithRBAC(resolver))
	ctx := auth.WithIdentity(context.Background(), &auth.UserIdentity{
		UserName: "dev@example.com",
		Groups:   []string{"devs"},
	})

	for i := range 400 {
		project := fmt.Sprintf("proj-hidden-%03d", i)
		if i%2 == 0 {
			project = fmt.Sprintf("proj-visible-%03d", i)
		}
		require.NoError(b, srv.engine.CreateStack(ctx, "organization", project, "stack", nil))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		stacks, nextToken, err := srv.listVisibleStacksPage(ctx, "organization", "", "", 50)
		if err != nil {
			b.Fatal(err)
		}
		if len(stacks) != 50 {
			b.Fatalf("expected 50 stacks, got %d", len(stacks))
		}
		if nextToken == "" {
			b.Fatal("expected continuation token")
		}
	}
}

func BenchmarkScheduleOIDCFollowUp(b *testing.B) {
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()

	srv := &Server{
		oidcAuth:      benchOIDCAuthenticator{},
		tokenStore:    newSQLiteBenchmarkTokenStore(b),
		backgroundCtx: ctx,
		clock:         clockutil.RealClock{},
		oidcFollowUp:  newOIDCFollowUpScheduler(ctx, clockutil.RealClock{}),
	}

	tok := &storage.Token{
		TokenHash:    "hash",
		UserName:     "dev@example.com",
		RefreshToken: "refresh",
		CreatedAt:    time.Now().Add(-2 * time.Hour),
	}
	expires := time.Now().Add(2 * time.Hour)
	tok.ExpiresAt = &expires

	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		srv.scheduleOIDCFollowUp(fmt.Sprintf("token-bench-%d", i), tok)
	}
}

type sqliteBenchmarkTokenStore struct{}

func newSQLiteBenchmarkTokenStore(tb testing.TB) *sqliteBenchmarkTokenStore {
	tb.Helper()
	return &sqliteBenchmarkTokenStore{}
}

func (*sqliteBenchmarkTokenStore) Close() error                   { return nil }
func (*sqliteBenchmarkTokenStore) Ping(ctx context.Context) error { return nil }
func (*sqliteBenchmarkTokenStore) CreateStack(ctx context.Context, s *storage.Stack) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetStack(ctx context.Context, org, project, stack string) (*storage.Stack, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) DeleteStack(ctx context.Context, org, project, stack string) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) ListStacks(ctx context.Context, org, project string, continuationToken string, pageSize int) ([]storage.Stack, string, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) UpdateStackTags(ctx context.Context, org, project, stack string, tags map[string]string) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) RenameStack(ctx context.Context, org, oldProject, oldName, newProject, newName string) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) ProjectExists(ctx context.Context, org, project string) (bool, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetCurrentState(ctx context.Context, org, project, stack string) (*storage.StackState, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetStateVersion(ctx context.Context, org, project, stack string, version int) (*storage.StackState, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) SaveState(ctx context.Context, state *storage.StackState) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetStateVersionRaw(ctx context.Context, org, project, stack string, version int) ([]byte, bool, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetCurrentStateRaw(ctx context.Context, org, project, stack string) ([]byte, int, bool, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) CreateUpdate(ctx context.Context, u *storage.Update) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetUpdate(ctx context.Context, updateID string) (*storage.Update, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) StartUpdate(ctx context.Context, updateID string, version int, token string, tokenExpiresAt time.Time, journalVersion int) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) CompleteUpdate(ctx context.Context, updateID string, status string, result []byte) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) RenewLease(ctx context.Context, updateID string, newToken string, newExpiry time.Time) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetActiveUpdate(ctx context.Context, org, project, stack string) (*storage.Update, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) CancelUpdate(ctx context.Context, updateID string) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) SaveJournalEntries(ctx context.Context, entries []storage.JournalEntry) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetJournalEntries(ctx context.Context, updateID string) ([]storage.JournalEntry, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetMaxJournalSequence(ctx context.Context, updateID string) (int64, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) SaveEngineEvents(ctx context.Context, events []storage.EngineEvent) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetEngineEvents(ctx context.Context, updateID string, offset, count int) ([]storage.EngineEvent, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) SaveUpdateHistory(ctx context.Context, h *storage.UpdateHistory) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetUpdateHistory(ctx context.Context, org, project, stack string, pageSize, page int) ([]storage.UpdateHistory, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetUpdateHistoryByVersion(ctx context.Context, org, project, stack string, version int) (*storage.UpdateHistory, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) CreateToken(ctx context.Context, t *storage.Token) error {
	return nil
}

func (*sqliteBenchmarkTokenStore) GetToken(ctx context.Context, tokenHash string) (*storage.Token, error) {
	return nil, nil
}
func (*sqliteBenchmarkTokenStore) TouchToken(ctx context.Context, tokenHash string) error { return nil }
func (*sqliteBenchmarkTokenStore) DeleteToken(ctx context.Context, tokenHash string) error {
	return nil
}

func (*sqliteBenchmarkTokenStore) DeleteTokensByUser(ctx context.Context, userName string) (int64, error) {
	return 0, nil
}

func (*sqliteBenchmarkTokenStore) ListTokensByUser(ctx context.Context, userName string) ([]storage.Token, error) {
	return nil, nil
}

func (*sqliteBenchmarkTokenStore) SaveSecretsKey(ctx context.Context, org, project, stack string, encryptedKey []byte) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetSecretsKey(ctx context.Context, org, project, stack string) ([]byte, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) ListSecretsKeys(ctx context.Context) ([]storage.SecretsKeyEntry, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) GetConfig(ctx context.Context, key string) (string, error) {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) SetConfig(ctx context.Context, key, value string) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) DeleteConfig(ctx context.Context, key string) error {
	panic("not used")
}

func (*sqliteBenchmarkTokenStore) Backup(ctx context.Context, destPath string) error {
	panic("not used")
}
