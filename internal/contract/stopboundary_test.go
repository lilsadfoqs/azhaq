package contract

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A run stopped by its deadline or by the kill file lists what it sent and
// no more: the requests of its summary, the lines of its ledger and what
// reached the other end are one number.

// stopWords is a wordlist longer than any of these runs gets through.
func stopWords(l *Labs) {
	var b strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "w%03d\n", i)
	}
	l.File("words.txt", b.String())
}

// ledgerTargetLines is the non-seal lines to targets of the ledger at name.
func ledgerTargetLines(l *Labs, name string) int {
	return ledgerSent(readLedger(l.T, filepath.Join(l.Dir, name))).N
}

// sameNumber fails unless the summary, the ledger and the wire agree.
func sameNumber(v *Inv, l *Labs, r Result, name string, wire int) {
	lines := ledgerTargetLines(l, name)
	v.Equal("summary requests, against the non-seal lines of the ledger", r.Summary.Requests, int64(lines))
	v.Equal("ledger lines, against the requests the proxy saw", int64(lines), int64(wire))
}

func TestStopBoundaryHTTP(t *testing.T) {
	for _, c := range []struct {
		name  string
		flags []string
		kill  time.Duration // the kill file appears after this long; zero: not at all
		want  int           // the exit code
	}{
		{"a short -timeout while paced", []string{"-rate", "2", "-timeout", "1s"}, 0, 4},
		{"a short -timeout at a higher rate", []string{"-rate", "7", "-timeout", "700ms"}, 0, 4},
		{"the kill file while paced", []string{"-rate", "5"}, 900 * time.Millisecond, 4},
		{"the kill file at a low rate", []string{"-rate", "2"}, 1300 * time.Millisecond, 4},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newLabs(t)
			stopWords(l)
			args := []string{"dirs", "-u", l.Site.URL + "/", "-w", "words.txt", "-proxy", l.Proxy.URL, "-ledger", "l.jsonl", "-kill-file", "k.stop"}
			args = append(args, c.flags...)
			if c.kill > 0 {
				time.AfterFunc(c.kill, func() { _ = os.WriteFile(filepath.Join(l.Dir, "k.stop"), nil, 0o644) })
			}
			r := RunRaw(t, l.Dir, nil, append(args, "-json")...)
			if !r.Has {
				t.Fatalf("no summary (exit %d)\n%s", r.Code, r.Stderr)
			}
			v := newInv(t, "")
			if r.Code != c.want {
				v.Errorf("exit %d, want %d", r.Code, c.want)
			}
			sameNumber(v, l, r, "l.jsonl", l.Proxy.Wire.Total())
			v.Done()
		})
	}
}
