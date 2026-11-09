package engine

import (
	"net"
	"net/url"
	"strings"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/types"
)

// The reserve a port sweep holds for the web mapping of each service it finds
// (egress.ReserveFor) is given back when that mapping ends: when every task
// on the service's origins has finished, whatever it did not spend goes back
// to the sweep. A task the budget stopped, or one cancelled, has not finished,
// so its origin keeps the reserve for the resume.

// webOrigins are the host:port origins a task's work is done under: a URL's
// own, and, for a host or an address, its ports 80 and 443 (what the HTTP
// collector asks of every name). Lower case.
func webOrigins(seed types.Seed) []string {
	switch seed.Type {
	case types.TypeURL:
		u, err := url.Parse(seed.Key())
		if err != nil || u.Hostname() == "" {
			return nil
		}
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		return []string{strings.ToLower(net.JoinHostPort(u.Hostname(), port))}
	case types.TypeHostname, types.TypeIPAddress:
		h := strings.ToLower(seed.Key())
		return []string{net.JoinHostPort(h, "80"), net.JoinHostPort(h, "443")}
	}
	return nil
}

// reserveWatch counts the tasks of each origin the reserve may be given back
// for: recorded and not finished.
type reserveWatch struct {
	live    map[string]int
	seen    map[string]bool // origins a task was recorded on
	touched map[string]bool // origins a task finished on
}

// counts says the task's origins are tracked: the port scan's own task is
// not (it ends with the sweep the reserve is held against).
func (s *scheduler) counts(t task) []string {
	col, ok := s.e.Cat.Get(t.col)
	if !ok || catalog.InfoOf(col).Flag == "ports" {
		return nil
	}
	return webOrigins(t.seed)
}

func (s *scheduler) noteRecorded(t task) {
	for _, o := range s.counts(t) {
		if s.rw.live == nil {
			s.rw.live, s.rw.seen, s.rw.touched = map[string]int{}, map[string]bool{}, map[string]bool{}
		}
		s.rw.live[o]++
		s.rw.seen[o] = true
	}
}

func (s *scheduler) noteFinished(t task) {
	for _, o := range s.counts(t) {
		if s.rw.live[o] > 0 {
			s.rw.live[o]--
			s.rw.touched[o] = true
		}
	}
}

// releaseMapped gives back the reserve of every service whose mapping has
// ended: all the origins its web work runs under have no task left, and some
// task ran on them.
func (s *scheduler) releaseMapped() {
	keys := egress.TakeFresh()
	for o := range s.rw.touched {
		keys = append(keys, egress.ReserveKeys(o)...)
	}
	clear(s.rw.touched)
	for _, k := range keys {
		ran, busy := false, false
		for _, o := range egress.ReserveOrigins(k) {
			ran = ran || s.rw.seen[o]
			busy = busy || s.rw.live[o] > 0
		}
		if ran && !busy {
			egress.ReleaseFor(k)
		}
	}
}
