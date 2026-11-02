package contract

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Inv collects what a row breaks. A row that names a known bug (an issue
// that is open) is skipped, not failed, when it breaks something, and says
// so when it no longer does: the marker is then dropped. AZHAQ_CONTRACT_STRICT=1
// fails the known rows too, to list what is still open.
type Inv struct {
	t     *testing.T
	known string
	broke []string
}

func newInv(t *testing.T, known string) *Inv { return &Inv{t: t, known: known} }

func (v *Inv) Errorf(format string, args ...any) {
	v.broke = append(v.broke, fmt.Sprintf(format, args...))
}

// Equal records a mismatch of two counts.
func (v *Inv) Equal(what string, got, want int64) {
	if got != want {
		v.Errorf("%s: %d, want %d", what, got, want)
	}
}

// Done reports what the row broke.
func (v *Inv) Done() {
	v.t.Helper()
	switch {
	case len(v.broke) == 0 && v.known != "":
		v.t.Logf("%s no longer reproduces: drop the known marker of this row", v.known)
	case len(v.broke) == 0:
	case v.known != "" && os.Getenv("AZHAQ_CONTRACT_STRICT") == "":
		v.t.Skipf("known %s: %s", v.known, strings.Join(v.broke, "; "))
	default:
		v.t.Errorf("%s", strings.Join(v.broke, "\n"))
	}
}
