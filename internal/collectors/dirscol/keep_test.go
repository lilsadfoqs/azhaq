package dirscol

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/fuzz"
)

// The matchers judge the first keepBody bytes of a body, whether or not
// KeepDir keeps more of it for the file.
func TestKeepDirDoesNotChangeWhatTheMatchersRead(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/deep":
			w.Write([]byte(strings.Repeat("a", keepBody+10) + "NEEDLE"))
		case "/near":
			w.Write([]byte("NEEDLE"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	for _, keep := range []bool{false, true} {
		set := fuzz.NewSet(nil)
		if err := set.AddMatcher("regexp", "NEEDLE"); err != nil {
			t.Fatal(err)
		}
		o := Options{Words: []string{"deep", "near"}, Set: set, Rate: 1000}
		dir := t.TempDir()
		if keep {
			o.KeepDir = dir
		}
		got, _ := sweepOf(t, New(srv.Client(), o), srv.URL+"/")
		if strings.Join(got, " ") != "/near" {
			t.Errorf("KeepDir %v: hits %v, want /near alone: -mr reads the first MB", keep, got)
		}
		if ents, _ := os.ReadDir(dir); keep && len(ents) != 1 {
			t.Errorf("%d files kept, want the one of /near", len(ents))
		}
	}
}
