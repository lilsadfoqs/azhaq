package subcol

import (
	"errors"
	"sync"
)

// errRunning marks a source that had not answered when its rows were read.
var errRunning = errors.New("still running when the run stopped")

// live holds, for each domain, a function that reads the rows of the sources
// of its last Run as they stand: the engine drops what a task emitted when the
// run is stopped under a request budget or by the kill file, and the summary
// of the sources must not depend on that row.
var live sync.Map // domain → func() map[string]any

func setLive(domain string, rows func() map[string]any) { live.Store(domain, rows) }

// Live is the rows of the sources of domain's last Run, as its summary would
// carry them (the "sources" of the payload): each source asked, with its
// requests, and the ones the run's stop caught asking marked "running". It is
// for a command whose summary row was lost; false when no Run started.
func Live(domain string) (map[string]any, bool) {
	v, ok := live.Load(domain)
	if !ok {
		return nil, false
	}
	return v.(func() map[string]any)(), true
}

// ForgetLive drops what Live holds: a command calls it before its run, so a
// domain of an earlier run in the process is not read as this one's.
func ForgetLive() { live.Range(func(k, _ any) bool { live.Delete(k); return true }) }
