package backup

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Scheduler runs periodic backups via a background goroutine.
type Scheduler struct {
	backupFn func(ctx context.Context) error
	interval time.Duration
	mu       sync.Mutex // prevent concurrent backup runs (scheduled + on-demand)
	stop     chan struct{}
	done     chan struct{}
}

// NewScheduler creates and starts a periodic backup scheduler.
// The backupFn is called on each tick. If interval is 0, no goroutine is started.
func NewScheduler(backupFn func(ctx context.Context) error, interval time.Duration) *Scheduler {
	s := &Scheduler{
		backupFn: backupFn,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}

	if interval > 0 {
		go s.run()
	} else {
		close(s.done)
	}

	return s
}

func (s *Scheduler) run() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	defer close(s.done)

	for {
		select {
		case <-ticker.C:
			if err := s.RunOnce(context.Background()); err != nil {
				slog.Error("scheduled backup failed", "error", err)
			}
		case <-s.stop:
			return
		}
	}
}

// RunOnce executes a single backup. Safe to call concurrently with the ticker;
// the mutex ensures only one backup runs at a time.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backupFn(ctx)
}

// Shutdown stops the periodic scheduler and waits for it to finish.
func (s *Scheduler) Shutdown() {
	close(s.stop)
	<-s.done
}
