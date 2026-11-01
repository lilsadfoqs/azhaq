package egress

import (
	"context"
	"net/http"
	"sync"
)

// SessionWire, when set, sees each answer a target gave before the request
// that got it counts as done (fetch sets it): a signed-in run learns that an
// answer ended its session while no measurement can be in flight.
var SessionWire func(req *http.Request, resp *http.Response)

// wire is held for reading from the moment a request to a target is handed
// to the transport until its answer was seen, and for writing by a
// measurement that goes out without the session (Exclusive).
var wire sync.RWMutex

type exclusiveKey struct{}

// Exclusive waits until no request to a target is in flight, then lets none
// start until release is called. The requests of ctx pass: they are the
// holder's own. A request sent without the session meets no revocation that
// way: the one that would revoke it is not in the air, and is not sent while
// it is.
func Exclusive(ctx context.Context) (exclusive context.Context, release func()) {
	wire.Lock()
	return context.WithValue(ctx, exclusiveKey{}, true), wire.Unlock
}

func isExclusive(ctx context.Context) bool { return ctx.Value(exclusiveKey{}) != nil }

type unwatchedKey struct{}

// Unwatched marks the requests of ctx as the session guard's own: their
// answers are not taken for the run's, so SessionWire does not see them.
func Unwatched(ctx context.Context) context.Context {
	return context.WithValue(ctx, unwatchedKey{}, true)
}

func isUnwatched(ctx context.Context) bool {
	return ctx.Value(unwatchedKey{}) != nil || isExclusive(ctx)
}
