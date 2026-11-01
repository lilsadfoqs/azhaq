package egress

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

func TestRatePacesRequests(t *testing.T) {
	Reset()
	defer Reset()
	SetRate(50) // a burst of 10, then one every 20 ms
	t0 := time.Now()
	for i := 0; i < 20; i++ {
		if err := Spend(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(t0); d < 150*time.Millisecond {
		t.Errorf("20 requests at 50/s took %s", d)
	}
}

func TestSpendStopsAtTheBudgetAndRefundGivesBack(t *testing.T) {
	Reset()
	defer Reset()
	SetMaxRequests(3)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := Spend(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := Spend(ctx); !errors.Is(err, neterr.ErrBudget) || Take() == nil || !Spent() {
		t.Fatalf("over the budget: %v", err)
	}
	Refund()
	if Take() != nil || Sent() != 3 {
		t.Errorf("a refunded request is not given back: sent %d", Sent())
	}
	Count(5)
	if Sent() != 8 {
		t.Errorf("counted %d after 5 sent outside, want 8", Sent())
	}
}

func TestWatchBudgetSeesARefusal(t *testing.T) {
	Reset()
	defer Reset()
	SetMaxRequests(1)
	ctx, refused, used := WatchBudget(context.Background())
	if err := Spend(ctx); err != nil || used() != 1 || refused() {
		t.Fatalf("first request: %v used %d", err, used())
	}
	if err := Spend(ctx); err == nil || !refused() || used() != 1 {
		t.Fatalf("second request: %v refused %v used %d", err, refused(), used())
	}
}

func TestSessionTickRefusalIsRefunded(t *testing.T) {
	Reset()
	defer Reset()
	SessionTick = func(context.Context) error { return neterr.ErrBudget }
	defer func() { SessionTick = nil }()
	if err := Spend(context.Background()); err == nil || Sent() != 0 {
		t.Fatalf("a request the session check refused stays counted: %v sent %d", err, Sent())
	}
}

func TestSpendIsSafeUnderConcurrency(t *testing.T) {
	Reset()
	defer Reset()
	SetMaxRequests(50)
	var wg sync.WaitGroup
	var ok sync.Map
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if Spend(context.Background()) == nil {
				ok.Store(i, true)
			}
		}()
	}
	wg.Wait()
	n := 0
	ok.Range(func(_, _ any) bool { n++; return true })
	if n != 50 || Sent() != 50 {
		t.Errorf("%d allowed, %d counted, want 50", n, Sent())
	}
}

func TestDepartedLeavesOutWhatWaitsForThePace(t *testing.T) {
	Reset()
	defer Reset()
	SetRate(5) // a burst of 1, then one every 200 ms
	ctx := context.Background()
	if err := Spend(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = Spend(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for Sent() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if Sent() != 2 || Departed() != 1 {
		t.Errorf("the second is counted and waiting: sent %d, departed %d, want 2 and 1", Sent(), Departed())
	}
	<-done
	if Departed() != 2 {
		t.Errorf("departed %d once it went, want 2", Departed())
	}
}

func TestDepartedKeepsAHeldRequestOutUntilItLeaves(t *testing.T) {
	Reset()
	defer Reset()
	if Take() != nil {
		t.Fatal("take")
	}
	Hold(1)
	Refund() // answered from the cache: counted back, never left
	Release(1)
	Release(1) // more than was held: no negative
	if Sent() != 0 || Departed() != 0 {
		t.Errorf("sent %d, departed %d, want 0", Sent(), Departed())
	}
}

func TestTotalCountsOverResets(t *testing.T) {
	Reset()
	defer Reset()
	from := Total()
	Count(3)
	Reset() // a command that resets between its parts
	Count(2)
	if Sent() != 2 || Total()-from != 5 {
		t.Errorf("sent %d, total since %d, want 2 and 5", Sent(), Total()-from)
	}
}

// A sweep leaves the requests reserved for web work, and the web requests use
// the reserve up: what the sweep may spend does not move as they are sent.
func TestSweepLeavesTheReserveForWebRequests(t *testing.T) {
	Reset()
	defer Reset()
	SetMaxRequests(10)
	Reserve(4)
	for i := 0; i < 6; i++ {
		if err := TakeSweep(); err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
	}
	if err := TakeSweep(); !errors.Is(err, neterr.ErrBudget) {
		t.Fatalf("the sweep took what the reserve holds: %v", err)
	}
	for i := 0; i < 4; i++ {
		if err := Spend(context.Background()); err != nil {
			t.Fatalf("web request %d: %v", i, err)
		}
	}
	if Reserved() != 0 || Sent() != 10 || !Spent() {
		t.Errorf("reserved %d, sent %d", Reserved(), Sent())
	}
	if Spend(context.Background()) == nil {
		t.Error("a request past the budget was let through")
	}
}
