package guard

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestCallReturnsThePanicAndWhereItWas(t *testing.T) {
	err := Call(func() error {
		var m map[string]int
		m["x"] = 1
		return nil
	})
	var pe *PanicError
	if !errors.As(err, &pe) || !strings.HasPrefix(err.Error(), Prefix+"assignment to entry in nil map") || !strings.Contains(pe.Stack, "guard_test.go") {
		t.Fatalf("%v", err)
	}
	if strings.Contains(pe.Stack, "runtime.") || strings.Contains(pe.Stack, "\n") {
		t.Errorf("a short stack of the code's own frames: %q", pe.Stack)
	}
	if want := errors.New("plain"); Call(func() error { return want }) != want {
		t.Error("an error returns as it is")
	}
}

func TestRecoverGivesAGoroutinesPanicToTheWatch(t *testing.T) {
	ctx, panicked, stop := Watch(context.Background())
	defer stop()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer Recover(ctx)
		panic("worker bug")
	}()
	wg.Wait()
	err := panicked()
	if err == nil || !strings.Contains(err.Error(), "panic: worker bug") {
		t.Fatalf("%v", err)
	}
	if ctx.Err() == nil {
		t.Error("the collector's other goroutines are told to stop")
	}
}

func TestRecoverWithNoWatchRaisesAgain(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(r.(string), "panic: bug") {
			t.Fatalf("recovered %v", r)
		}
	}()
	func() {
		defer Recover(context.Background())
		panic("bug")
	}()
}

func TestCarryMovesTheWatchToAnotherContext(t *testing.T) {
	ctx, panicked, stop := Watch(context.Background())
	defer stop()
	other := Carry(context.Background(), ctx)
	func() {
		defer Recover(other)
		panic("tab bug")
	}()
	if panicked() == nil {
		t.Fatal("the panic reaches the watch of the context it was carried from")
	}
}
