package main

import (
	"os"
	"strings"
	"testing"
)

// The ledger holds what azhaq sends: where -role-cmd and the ledger are
// documented, the docs say what a helper's requests are, and that the ones that
// skip the proxy are not in it.
func TestDocsSayWhichRoleCmdRequestsAreInTheLedger(t *testing.T) {
	for f, wants := range map[string][]string{
		"../../docs/commands/roles.md": {
			"pointing at a loopback proxy that azhaq starts for the command's lifetime",
			"is not azhaq's: it stays outside the ledger and the scope",
			"`-role-cmd-direct` runs the commands with no proxy",
		},
		"../../docs/CONCEPTS.md": {
			"loopback proxy of azhaq's, so its requests are held to the scope, the budget and the pace and are in the ledger",
			"A request it makes without honouring the proxy variables is not azhaq's and is not in the ledger or held to the scope",
			"`-role-cmd-direct` runs the command with no proxy",
		},
		"../../docs/OUTPUT.md": {"the requests of a helper outside azhaq, such as a `-role-cmd` command that ignores the proxy variables or runs with `-role-cmd-direct`, are not"},
	} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range wants {
			if !strings.Contains(string(raw), want) {
				t.Errorf("%s does not say: %s", f, want)
			}
		}
	}
}
