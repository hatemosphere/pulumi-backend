package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hatemosphere/pulumi-backend/internal/auth"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

type fakeClock struct {
	now time.Time
}

func (f fakeClock) Now() time.Time {
	return f.now
}

func TestServerCloseCancelsOIDCFollowUpContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		backgroundCtx: ctx,
		cancel:        cancel,
		clock:         fakeClock{now: time.Now()},
		oidcAuth:      benchOIDCAuthenticator{},
		tokenStore:    newSQLiteBenchmarkTokenStore(t),
		oidcFollowUp:  newOIDCFollowUpScheduler(ctx, fakeClock{now: time.Now()}),
	}

	require.NoError(t, srv.Close())

	select {
	case <-srv.backgroundCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected server background context to be canceled")
	}
}

func TestOIDCFollowUpSchedulerThrottlesPerToken(t *testing.T) {
	now := time.Now()
	sched := newOIDCFollowUpScheduler(context.Background(), fakeClock{now: now})

	require.True(t, sched.trySchedule("token-a"))
	require.False(t, sched.trySchedule("token-a"))
	sched.release()
}

func TestOIDCFollowUpSchedulerAllowsDifferentTokens(t *testing.T) {
	now := time.Now()
	sched := newOIDCFollowUpScheduler(context.Background(), fakeClock{now: now})

	require.True(t, sched.trySchedule("token-a"))
	require.True(t, sched.trySchedule("token-b"))
	sched.release()
	sched.release()
}

func TestShouldRevalidateUsesHalfTTL(t *testing.T) {
	now := time.Now()
	srv := &Server{clock: fakeClock{now: now}}
	createdAt := now.Add(-90 * time.Minute)
	expiresAt := createdAt.Add(2 * time.Hour)
	tok := &storage.Token{
		UserName:  "dev@example.com",
		CreatedAt: createdAt,
		ExpiresAt: &expiresAt,
	}
	require.True(t, srv.shouldRevalidate(tok))

	tok.CreatedAt = now.Add(-30 * time.Minute)
	expiresAt = tok.CreatedAt.Add(2 * time.Hour)
	tok.ExpiresAt = &expiresAt
	require.False(t, srv.shouldRevalidate(tok))
}

func TestShouldRevalidateNoExpiry(t *testing.T) {
	srv := &Server{clock: fakeClock{now: time.Now()}}
	require.False(t, srv.shouldRevalidate(&storage.Token{
		UserName:  "dev@example.com",
		CreatedAt: time.Now().Add(-time.Hour),
	}))
}

var _ auth.OIDCAuthenticator = benchOIDCAuthenticator{}
