package icontest

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fingerprint"
)

func TestBodyHasTheHash(t *testing.T) {
	for _, h := range []string{"1278323681", "945408572", "-1595726841", "603314", "0"} {
		got, ok := fingerprint.Favicon(Body(h))
		if !ok || got != h {
			t.Errorf("hash %s: icon hashes to %q (image %v)", h, got, ok)
		}
	}
}
