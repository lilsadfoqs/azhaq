// Package guard turns a panic in collector or worker code into an error
// the run reports, so one bug loses one task and not the run.
package guard

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
)

// PanicError is a recovered panic: its value and the frames of the code
// that raised it.
type PanicError struct {
	Value any
	Stack string // a few frames, one line
}

func (p *PanicError) Error() string {
	return fmt.Sprintf("panic: %v (%s)", p.Value, p.Stack)
}

// Prefix starts the text of every PanicError.
const Prefix = "panic: "

const frames = 4

// capture reads the stack of a panic being recovered: the frames above
// the runtime's own, nearest first.
func capture(v any) *PanicError {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(2, pcs)
	fr := runtime.CallersFrames(pcs[:n])
	var out []string
	for {
		f, more := fr.Next()
		name := f.Function
		if !strings.HasPrefix(name, "runtime.") && !strings.HasSuffix(f.File, "/internal/guard/guard.go") {
			name = strings.TrimPrefix(name, "github.com/trannghiach/azhaq/")
			file := f.File
			if i := strings.LastIndex(file, "/"); i >= 0 {
				file = file[i+1:]
			}
			out = append(out, fmt.Sprintf("%s %s:%d", name, file, f.Line))
			if len(out) == frames {
				break
			}
		}
		if !more {
			break
		}
	}
	return &PanicError{Value: v, Stack: strings.Join(out, " < ")}
}

// Call runs fn and returns what it returned, or the panic it raised.
func Call(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = capture(r)
		}
	}()
	return fn()
}

type sinkKey struct{}

type sink struct {
	mu     sync.Mutex
	err    error
	cancel context.CancelFunc
}

// Watch returns a context for one collector run, a function that gives
// the first panic raised in a goroutine started under it (Recover), and
// a function that releases the context once the run is over. A panic
// cancels the context: the collector's other goroutines wind down
// instead of waiting for the one that died.
func Watch(ctx context.Context) (context.Context, func() error, func()) {
	ctx, cancel := context.WithCancel(ctx)
	s := &sink{cancel: cancel}
	return context.WithValue(ctx, sinkKey{}, s), func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.err
	}, cancel
}

// Recover is deferred first in a goroutine that runs collector code:
// `defer guard.Recover(ctx)`. A panic goes to the run's Watch; with none
// listening it is raised again, as before.
func Recover(ctx context.Context) {
	r := recover()
	if r == nil {
		return
	}
	pe := capture(r)
	s, _ := ctx.Value(sinkKey{}).(*sink)
	if s == nil {
		panic(pe.Error())
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = pe
	}
	s.mu.Unlock()
	s.cancel()
}

// Catch is deferred first in a goroutine that belongs to no run, such as
// a browser's event loop: a panic goes to fn, which says what to do.
func Catch(fn func(error)) {
	if r := recover(); r != nil {
		fn(capture(r))
	}
}

// Carry gives to the panic watch of from, for code that runs under a
// context not derived from it (a browser tab).
func Carry(to, from context.Context) context.Context {
	if s, ok := from.Value(sinkKey{}).(*sink); ok {
		return context.WithValue(to, sinkKey{}, s)
	}
	return to
}
