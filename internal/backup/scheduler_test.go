package backup

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduler_RunOnce(t *testing.T) {
	var called atomic.Int32
	fn := func(_ context.Context) error {
		called.Add(1)
		return nil
	}

	sched := NewScheduler(fn, 0) // no periodic scheduling
	defer sched.Shutdown()

	if err := sched.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if called.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", called.Load())
	}
}

func TestScheduler_PeriodicTick(t *testing.T) {
	var called atomic.Int32
	fn := func(_ context.Context) error {
		called.Add(1)
		return nil
	}

	sched := NewScheduler(fn, 50*time.Millisecond)

	// Wait for at least 2 ticks.
	time.Sleep(150 * time.Millisecond)
	sched.Shutdown()

	count := called.Load()
	if count < 2 {
		t.Fatalf("expected at least 2 calls, got %d", count)
	}
}

func TestScheduler_ShutdownStopsTicker(t *testing.T) {
	var called atomic.Int32
	fn := func(_ context.Context) error {
		called.Add(1)
		return nil
	}

	sched := NewScheduler(fn, 50*time.Millisecond)
	time.Sleep(80 * time.Millisecond) // wait for 1 tick
	sched.Shutdown()

	countAtShutdown := called.Load()
	time.Sleep(100 * time.Millisecond) // wait to confirm no more ticks

	if called.Load() != countAtShutdown {
		t.Fatal("scheduler continued after shutdown")
	}
}

func TestScheduler_NoPanicOnZeroInterval(t *testing.T) {
	sched := NewScheduler(func(_ context.Context) error { return nil }, 0)
	sched.Shutdown() // should not panic or block
}
