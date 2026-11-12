package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/collectors/asncol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// stderrProgressEvery is how often a command that is still working says so on
// stderr: a run paced at a request a second is quiet otherwise, and looks
// hung.
var stderrProgressEvery = 10 * time.Second

// progressSnap is what a progress line reports at one moment.
type progressSnap struct {
	At   time.Duration // since the command began
	Sent int64         // requests sent to the targets (never fewer than the line before)
	Done int           // tasks done
	Left int           // tasks known and not done; -1: not counted
	// A port scan's own unit, which moves while one task covers many addresses:
	// the addresses its scans finished, and those of the tasks known that are
	// not (-1: the tasks name more than addresses). Ports: the run has port work.
	Ports              bool
	AddrDone, AddrLeft int
}

// progressCfg says how a command reports progress and what ends it.
type progressCfg struct {
	JSON    bool          // one JSON object a line, as everything else on stderr with -json
	Cap     int64         // requests at most; 0: no cap
	CapBy   string        // the option that set Cap
	Timeout time.Duration // 0: none
	// TimeoutBy is the option that set Timeout; empty: -timeout.
	TimeoutBy string
}

func (c progressCfg) timeoutBy() string {
	if c.TimeoutBy == "" {
		return "-timeout"
	}
	return c.TimeoutBy
}

// rate is the requests a second between two snapshots.
func rateBetween(prev, cur progressSnap) float64 {
	if d := (cur.At - prev.At).Seconds(); d > 0 {
		return float64(cur.Sent-prev.Sent) / d
	}
	return 0
}

func rateText(r float64) string {
	switch {
	case r >= 10:
		return fmt.Sprintf("%.0f/s", r)
	case r >= 1:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", r), ".0") + "/s"
	case r > 0:
		return fmt.Sprintf("%.2g/s", r)
	}
	return "0/s"
}

// aboutDuration is a time to go, rounded for reading: 18 s, 3 min, 1.5 h.
func aboutDuration(d time.Duration) string {
	switch {
	case d < 100*time.Second:
		return fmt.Sprintf("%d s", max(1, int(d.Round(time.Second).Seconds())))
	case d < 100*time.Minute:
		return fmt.Sprintf("%d min", int(d.Round(time.Minute).Minutes()))
	}
	return fmt.Sprintf("%.1f h", d.Hours())
}

// ends is what stops the command first at the pace of the last interval,
// and in how long: the request cap or the timeout. ok is false when
// nothing is known to.
func (c progressCfg) ends(prev, cur progressSnap) (by string, in time.Duration, ok bool) {
	if c.Cap > 0 && cur.Sent < c.Cap {
		if r := rateBetween(prev, cur); r > 0 {
			by, in, ok = fmt.Sprintf("%s %d", c.CapBy, c.Cap), time.Duration(float64(c.Cap-cur.Sent)/r*float64(time.Second)), true
		}
	}
	if c.Timeout > 0 && cur.At < c.Timeout {
		if left := c.Timeout - cur.At; !ok || left < in {
			by, in, ok = c.timeoutBy()+" "+c.Timeout.String(), left, true
		}
	}
	return by, in, ok
}

// line is the progress line for cur, after prev.
func (c progressCfg) line(prev, cur progressSnap) string {
	var b strings.Builder
	fmt.Fprintf(&b, "azhaq: %s, %s sent (%s)", cur.At.Round(time.Second), plural(int(cur.Sent), "request"), rateText(rateBetween(prev, cur)))
	if cur.Left >= 0 {
		fmt.Fprintf(&b, ", %s left", plural(cur.Left, "task"))
	}
	if by, in, ok := c.ends(prev, cur); ok {
		fmt.Fprintf(&b, "; %s ends it in about %s", by, aboutDuration(in))
	}
	if cur.Ports {
		word := "addresses"
		if cur.AddrDone+max(cur.AddrLeft, 0) == 1 {
			word = "address"
		}
		if cur.AddrLeft >= 0 {
			fmt.Fprintf(&b, ", %d of %d %s done", cur.AddrDone, cur.AddrDone+cur.AddrLeft, word)
		} else {
			fmt.Fprintf(&b, ", %d %s done", cur.AddrDone, word)
		}
	}
	b.WriteString(stillWaiting())
	return b.String()
}

// progressObject is a progress line for -json.
type progressObject struct {
	Type       string   `json:"type"`
	Seconds    int      `json:"seconds"`
	Requests   int64    `json:"requests"`
	PerSecond  float64  `json:"requests_per_second"`
	TasksDone  int      `json:"tasks_done"`
	TasksLeft  *int     `json:"tasks_left,omitempty"`
	AddrDone   *int     `json:"addresses_done,omitempty"` // port scans: addresses finished
	AddrLeft   *int     `json:"addresses_left,omitempty"` // and those of the tasks known not yet finished
	EndsBy     string   `json:"ends_by,omitempty"`
	EndsInSecs *int     `json:"ends_in_seconds,omitempty"`
	WaitingFor []string `json:"waiting_for,omitempty"` // subdomain sources not answered yet
}

// object is the same line for -json.
func (c progressCfg) object(prev, cur progressSnap) progressObject {
	o := progressObject{Type: "progress", Seconds: int(cur.At.Seconds()), Requests: cur.Sent,
		PerSecond: float64(int(rateBetween(prev, cur)*100)) / 100, TasksDone: cur.Done}
	if cur.Left >= 0 {
		o.TasksLeft = &cur.Left
	}
	if cur.Ports {
		o.AddrDone = &cur.AddrDone
		if cur.AddrLeft >= 0 {
			o.AddrLeft = &cur.AddrLeft
		}
	}
	if by, in, ok := c.ends(prev, cur); ok {
		secs := int(in.Seconds())
		o.EndsBy, o.EndsInSecs = by, &secs
	}
	for _, w := range subcol.Waiting() {
		o.WaitingFor = append(o.WaitingFor, w.Source)
	}
	return o
}

// paceLine says, as a command starts, how slowly it is paced: a rate at
// which the work known takes minutes, and what the request cap comes to.
// It is empty for a pace nobody waits on.
func (c progressCfg) paceLine(rate float64) string {
	if rate <= 0 {
		return ""
	}
	if c.Cap > 0 {
		if took := time.Duration(float64(c.Cap) / rate * float64(time.Second)); took >= 20*time.Second {
			return fmt.Sprintf("azhaq: -rate %g paces requests to %s: the cap of %d requests (%s) takes at least %s at that pace; progress lines follow every %s", rate, rateText(rate), c.Cap, c.CapBy, aboutDuration(took), stderrProgressEvery)
		}
		return ""
	}
	if rate <= 10 {
		return fmt.Sprintf("azhaq: -rate %g paces requests to %s, so a run that follows many pages takes a while; progress lines follow every %s", rate, rateText(rate), stderrProgressEvery)
	}
	return ""
}

// startProgress writes a line to w every stderrProgressEvery until ctx ends or
// the returned stop is called; a command that is done sooner writes none.
// snap reads where the command stands.
func startProgress(ctx context.Context, cfg progressCfg, w io.Writer, snap func() progressSnap) func() {
	done := make(chan struct{})
	var once sync.Once
	every := stderrProgressEvery // read here, not in the goroutine: a test resets it
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		prev := progressSnap{Left: -1}
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				cur := snap()
				cur.Sent = max(cur.Sent, prev.Sent) // one given back is not taken off what was said
				if cfg.JSON {
					raw, _ := json.Marshal(cfg.object(prev, cur))
					fmt.Fprintf(w, "%s\n", raw)
				} else {
					fmt.Fprintln(w, cfg.line(prev, cur))
				}
				prev = cur
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// portProgress is the port scans' own progress, from the ports tasks of the
// run and the addresses finished since it began: whether there is port work
// at all, the addresses done, and those of the tasks known that are not (-1
// when a task names something whose addresses are not known yet: a name, or a
// range too big for one block, whose blocks are tasks once it runs).
func portProgress(tasks []store.Task, done int) (ports bool, doneN, left int) {
	total, known := 0, true
	for _, t := range tasks {
		if t.Seed.Keys["from"] == asncol.FromPrefix {
			continue // an address of a range being scanned: the range counts it
		}
		ports = true
		switch t.Seed.Type {
		case types.TypePrefix:
			pf, err := netip.ParsePrefix(t.Seed.Key())
			if err != nil || pf.Bits() < blockBits(pf) {
				if !t.Done {
					known = false
				}
				continue
			}
			total += blockSize(pf.Masked())
		default:
			if _, err := netip.ParseAddr(normalize.Hostname(t.Seed.Key())); err == nil {
				total++
			} else if !t.Done {
				known = false
			}
		}
	}
	if !ports && done == 0 {
		return false, 0, -1
	}
	if !known {
		return true, done, -1
	}
	return true, done, max(total-done, 0)
}

// blockBits is the prefix length a range is scanned in blocks of.
func blockBits(pf netip.Prefix) int {
	if pf.Addr().Is6() {
		return 120
	}
	return 24
}
