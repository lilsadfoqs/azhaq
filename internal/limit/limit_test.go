package limit

import (
	"context"
	"testing"
	"time"
)

func TestPerKeyRate(t *testing.T) {
	l := New(20, 1)
	ctx := context.Background()
	t0 := time.Now()
	for i := 0; i < 5; i++ {
		if err := l.Wait(ctx, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(t0); d < 150*time.Millisecond {
		t.Fatalf("5 requests at 20/s took %s", d)
	}
	t1 := time.Now()
	if err := l.Wait(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t1); d > 20*time.Millisecond {
		t.Fatalf("another key waited %s", d)
	}
}

func TestUnlimitedAndOverride(t *testing.T) {
	l := New(0, 1)
	l.Set("slow", 10)
	ctx := context.Background()
	t0 := time.Now()
	for i := 0; i < 50; i++ {
		_ = l.Wait(ctx, "fast")
	}
	if d := time.Since(t0); d > 50*time.Millisecond {
		t.Fatalf("unlimited key waited %s", d)
	}
	t1 := time.Now()
	for i := 0; i < 3; i++ {
		_ = l.Wait(ctx, "slow")
	}
	if d := time.Since(t1); d < 150*time.Millisecond {
		t.Fatalf("override ignored: %s", d)
	}
}

func TestWaitHonoursContext(t *testing.T) {
	l := New(1, 1)
	_ = l.Wait(context.Background(), "k")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx, "k"); err == nil {
		t.Fatal("want a context error")
	}
}

// A wait the deadline would cut short lasts to the deadline, so the caller
// sees its context end instead of an early refusal while ctx is still live.
func TestWaitUntilDeadlineEndsTheContext(t *testing.T) {
	l := New(1, 1)
	_ = l.Wait(context.Background(), "k")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	err := l.Wait(ctx, "k")
	if err == nil || ctx.Err() == nil {
		t.Fatalf("err %v, ctx.Err %v: the context must have ended", err, ctx.Err())
	}
	if d := time.Since(t0); d < 50*time.Millisecond {
		t.Fatalf("returned after %s, before the deadline", d)
	}
}

// WaitN takes the places of n requests in one wait: the pace is the same as
// n waits of one, past the burst.
func TestWaitNTakesPlacesAtTheRate(t *testing.T) {
	l := New(1000, 100)
	ctx := context.Background()
	t0 := time.Now()
	if err := l.WaitN(ctx, "k", 100); err != nil { // the burst
		t.Fatal(err)
	}
	if d := time.Since(t0); d > 30*time.Millisecond {
		t.Errorf("the burst took %v", d)
	}
	t0 = time.Now()
	for i := 0; i < 5; i++ {
		if err := l.WaitN(ctx, "k", 20); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(t0); d < 80*time.Millisecond || d > 200*time.Millisecond {
		t.Errorf("100 requests past the burst took %v at 1000 a second", d)
	}
	if err := l.WaitN(ctx, "k", 5000); err != nil { // more than the burst: the burst
		t.Errorf("more than the burst: %v", err)
	}
}

// A strict Limiter holds a key to its rate in every second even with a
// burst that would let more through.
func TestStrictHoldsEverySecond(t *testing.T) {
	l := New(10, 10).Strict()
	var ts []time.Time
	for i := 0; i < 15; i++ {
		if err := l.Wait(context.Background(), "k"); err != nil {
			t.Fatal(err)
		}
		ts = append(ts, time.Now())
	}
	if d := ts[10].Sub(ts[0]); d < time.Second {
		t.Errorf("11 sends in %v at 10 a second", d)
	}
}
