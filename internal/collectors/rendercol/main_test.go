package rendercol

import (
	"os"
	"testing"
)

// The tests that start Chrome run where the system may give it no sandbox
// (a container, AppArmor): AZHAQ_CHROME_NO_SANDBOX=1 is the user's say that
// it may run without one. A test of the refusal clears it.
func TestMain(m *testing.M) {
	os.Setenv("AZHAQ_CHROME_NO_SANDBOX", "1")
	os.Exit(m.Run())
}
