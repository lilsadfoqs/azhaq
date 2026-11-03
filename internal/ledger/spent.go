package ledger

import (
	"context"
	"sync"
	"sync/atomic"
)

// What a run spent, by where it went and who sent it. The ledger's own tally
// exists only while a ledger is open; this one is kept either way, so the
// summary can say which stage spent the requests of a run that keeps no
// ledger.

// SpentKey is one line of the account: the class an entry was sent to (see
// ClassTarget), its kind (http, tcp, udp, dns, chrome), the collector that
// sent it, and the stage the command was in (SetStage), "" when it names none.
type SpentKey struct{ Class, Kind, Collector, Stage string }

var (
	last     atomic.Pointer[SpentKey]
	spentBy  sync.Map // SpentKey → *atomic.Int64
	stageNow atomic.Value
)

func spend(class, kind, collector string, n int64) {
	k := SpentKey{class, kind, collector, Stage()}
	if class == ClassTarget {
		last.Store(&k) // the sender of the request that spent the budget is the last
	}
	if v, ok := spentBy.Load(k); ok {
		v.(*atomic.Int64).Add(n)
		return
	}
	v, _ := spentBy.LoadOrStore(k, new(atomic.Int64))
	v.(*atomic.Int64).Add(n)
}

// Account is what the process has sent so far, by SpentKey. Two snapshots
// give a command's own: its difference.
func Account() map[SpentKey]int64 {
	out := map[SpentKey]int64{}
	spentBy.Range(func(k, v any) bool {
		out[k.(SpentKey)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

// LastSender is the stage and collector of the latest request or connect sent
// to a target: when the request budget is spent, the one that spent it. The
// zero key before any.
func LastSender() SpentKey {
	if k := last.Load(); k != nil {
		return *k
	}
	return SpentKey{}
}

// SetStage names the part of a command that is sending from now on (roles
// has several: sign-in, the maps, the replay), and returns the func that
// puts back the stage that was. Stages follow one another: the requests of
// two at once are the later one's.
func SetStage(name string) (restore func()) {
	prev := Stage()
	stageNow.Store(name)
	return func() { stageNow.Store(prev) }
}

// Stage is the stage set with SetStage, "" for none.
func Stage() string {
	s, _ := stageNow.Load().(string)
	return s
}

// SignIn is the collector Chrome's sign-in requests are sent under: the account
// keeps them apart from the work they were made for.
const SignIn = "sign-in"

// CollectorOf is the collector ctx was marked with (WithCollector), or "".
func CollectorOf(ctx context.Context) string { return collectorOf(ctx) }
