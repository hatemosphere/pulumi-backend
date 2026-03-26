package api

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/hatemosphere/pulumi-backend/internal/clockutil"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

const oidcFollowUpInterval = time.Minute

type oidcFollowUpScheduler struct {
	mu      sync.Mutex
	lastRun map[string]time.Time
	slots   chan struct{}
	ctx     context.Context
	clock   clockutil.Clock
}

func newOIDCFollowUpScheduler(ctx context.Context, clock clockutil.Clock) *oidcFollowUpScheduler {
	if ctx == nil {
		ctx = context.Background()
	}
	if clock == nil {
		clock = clockutil.RealClock{}
	}
	return &oidcFollowUpScheduler{
		lastRun: make(map[string]time.Time),
		slots:   make(chan struct{}, 8),
		ctx:     ctx,
		clock:   clock,
	}
}

func (s *Server) scheduleOIDCFollowUp(tokenHash string, tok *storage.Token) {
	if s.oidcFollowUp == nil {
		return
	}
	if !s.oidcFollowUp.trySchedule(tokenHash) {
		return
	}

	go func() {
		defer s.oidcFollowUp.release()

		asyncCtx, cancel := context.WithTimeout(s.oidcFollowUp.ctx, 30*time.Second)
		defer cancel()

		if err := s.tokenStore.TouchToken(asyncCtx, tokenHash); err != nil {
			slog.Warn("failed to touch token", "error", err)
		}

		if tok.RefreshToken != "" && s.oidcAuth != nil && s.shouldRevalidate(tok) {
			if err := s.oidcAuth.Revalidate(asyncCtx, tok.RefreshToken); err != nil {
				slog.Warn("OIDC re-validation failed, revoking token",
					"user", tok.UserName,
					"error", err,
				)
				if delErr := s.tokenStore.DeleteToken(asyncCtx, tokenHash); delErr != nil {
					slog.Error("failed to delete revoked token", "error", delErr)
				}
			}
		}
	}()
}

func (s *oidcFollowUpScheduler) trySchedule(tokenHash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if lastRun, ok := s.lastRun[tokenHash]; ok && s.clock.Now().Sub(lastRun) < oidcFollowUpInterval {
		return false
	}
	select {
	case s.slots <- struct{}{}:
		s.lastRun[tokenHash] = s.clock.Now()
		return true
	default:
		return false
	}
}

func (s *oidcFollowUpScheduler) release() {
	<-s.slots
}
