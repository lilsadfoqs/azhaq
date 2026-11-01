package egress

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

// KillCheck is how often the kill file is looked for while something
// waits for the pace: that wait ends within KillCheck of the file. A send
// does not rely on it, it looks for the file itself.
const KillCheck = 100 * time.Millisecond

// killWatch is one SetKill: the file, and the wake once it is seen.
type killWatch struct {
	path string
	now  chan struct{} // closed once the file is seen: wakes what waits for the pace
	once sync.Once
}

// kill is a Policy's watch for its kill file.
type kill struct {
	killMu   sync.Mutex
	killStop chan struct{}
	killNow  chan struct{}
	watch    atomic.Pointer[killWatch]
	killed   atomic.Pointer[neterr.Killed]
}

// SetKill watches for the file at path: once it exists, Spend and Take
// refuse with neterr.ErrKilled and Spent says so. An empty path watches
// nothing. Every check (Killed, which every send makes at the moment it
// goes out) looks for the file itself; a poll every KillCheck wakes what
// waits for the pace. The func returned stops the watch and forgets a
// file it saw.
func (p *Policy) SetKill(path string) (stop func()) {
	p.killMu.Lock()
	if p.killStop != nil {
		close(p.killStop)
		p.killStop = nil
	}
	p.killed.Store(nil)
	p.watch.Store(nil)
	if path == "" {
		p.killNow = nil
		p.killMu.Unlock()
		return func() {}
	}
	done := make(chan struct{})
	w := &killWatch{path: path, now: make(chan struct{})}
	p.killStop, p.killNow = done, w.now
	p.watch.Store(w)
	p.killMu.Unlock()
	seen := func() bool { return p.look(w) }
	if !seen() {
		go func() {
			t := time.NewTicker(KillCheck)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					if seen() {
						return
					}
				}
			}
		}()
	}
	return func() {
		p.killMu.Lock()
		defer p.killMu.Unlock()
		if p.killStop == done {
			close(done)
			p.killStop, p.killNow = nil, nil
			p.watch.Store(nil)
			p.killed.Store(nil)
		}
	}
}

// look stats the kill file of w and notes it once it is there.
func (p *Policy) look(w *killWatch) bool {
	if _, err := os.Stat(w.path); err != nil {
		return false
	}
	w.once.Do(func() {
		if p.watch.Load() == w {
			p.killed.Store(&neterr.Killed{Path: w.path})
		}
		close(w.now)
	})
	return true
}

// killWake is closed once the kill file is seen; nil without a watch.
func (p *Policy) killWake() <-chan struct{} {
	p.killMu.Lock()
	defer p.killMu.Unlock()
	return p.killNow
}

// Killed is the refusal the kill file gives, or nil. It looks for the file
// at each call: a send that asks is not let go after the file exists, and
// nothing is cached between the poll and the send.
func (p *Policy) Killed() error {
	if k := p.killed.Load(); k != nil {
		return k
	}
	if w := p.watch.Load(); w != nil && p.look(w) {
		if k := p.killed.Load(); k != nil {
			return k
		}
	}
	return nil
}

// SetKill is Current().SetKill.
func SetKill(path string) (stop func()) { return Current().SetKill(path) }

// Killed is Current().Killed.
func Killed() error { return Current().Killed() }
