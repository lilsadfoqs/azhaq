package jscol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/types"
)

// capRun reads the page of srv and returns the caps its note names.
func capRun(t *testing.T, srv *httptest.Server, maxScripts int) map[string]capPart {
	t.Helper()
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	col := New(srv.Client())
	col.MaxScripts = maxScripts
	got := map[string]capPart{}
	_, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		if o.Kind == "note" {
			var p struct{ Caps []capPart }
			_ = json.Unmarshal(o.Payload, &p)
			for _, c := range p.Caps {
				got[c.What] = c
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Each cap that leaves work unread names it and how much; a larger
// -max-scripts raises every one of them.
func TestCapsNameWhatTheyLeaveAndScaleWithMaxScripts(t *testing.T) {
	const maps, scripts = 12, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/":
			var b strings.Builder
			for i := 0; i < maps+scripts; i++ {
				fmt.Fprintf(&b, `<script src="/s%d.js"></script>`, i)
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<title>x</title>%s", b.String())
		case strings.HasSuffix(p, ".js") && strings.HasPrefix(p, "/s"):
			w.Header().Set("Content-Type", "application/javascript")
			var b strings.Builder
			n := 0
			_, _ = fmt.Sscanf(p, "/s%d.js", &n)
			// Three scripts of 2000 routes pass the cap of 4096, not four times it.
			for i := 0; n < 3 && i < 2000; i++ {
				fmt.Fprintf(&b, `fetch("/api%s/r%d");`, strings.TrimSuffix(p, ".js"), i)
			}
			b.WriteString(`fetch("/api/one");`)
			if n < maps {
				fmt.Fprintf(&b, "\n//# sourceMappingURL=%s.map", strings.TrimPrefix(p, "/"))
			}
			fmt.Fprint(w, b.String())
		case strings.HasSuffix(p, ".map"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"version":3,"sources":["a.ts"],"sourcesContent":["export const a = 1"],"mappings":"AAAA"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got := capRun(t, srv, 0)
	if c := got["source maps"]; c.Limit != maxMaps || c.Left != maps-maxMaps {
		t.Errorf("source maps: %+v, want %d left at %d", c, maps-maxMaps, maxMaps)
	}
	if c := got["routes"]; c.Limit != maxEmit || c.Left == 0 {
		t.Errorf("routes: %+v, want some left at %d", c, maxEmit)
	}
	if c, ok := got["scripts"]; ok {
		t.Errorf("scripts under the cap named as left: %+v", c)
	}
	// Four times the scripts: four times the routes and maps, all read.
	if got := capRun(t, srv, 4*maxScripts); len(got) != 0 {
		t.Errorf("with -max-scripts %d the caps still leave work: %v", 4*maxScripts, got)
	}
}

func TestLimitsScaleUpAndNeverUnderTheDefaults(t *testing.T) {
	d := limitsFor(0)
	if d != (limits{256, 4096, 8, 10, 8, 256}) {
		t.Errorf("defaults %+v", d)
	}
	if l := limitsFor(10); l.scripts != 10 || l.routes != maxEmit || l.maps != maxMaps {
		t.Errorf("a lowered number changes only the scripts: %+v", l)
	}
	if l := limitsFor(512); l != (limits{512, 8192, 16, 20, 16, 512}) {
		t.Errorf("doubled: %+v", l)
	}
}

// Scripts left unread are not hints to resume, and the maps a page's scripts
// do not name, asked for by name up to the origin's limit, are no work left.
func TestUnreadScriptsAreNotHintsAndGuessesAreNotLeft(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			var b strings.Builder
			for i := 0; i < maxScripts+20; i++ {
				fmt.Fprintf(&b, `<script src="/s%d.js"></script>`, i)
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, b.String())
			return
		}
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/one")`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	var caps map[string]capPart = map[string]capPart{}
	meta, err := New(srv.Client()).Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		if o.Kind == "note" {
			var p struct{ Caps []capPart }
			_ = json.Unmarshal(o.Payload, &p)
			for _, c := range p.Caps {
				caps[c.What] = c
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != 1 || caps["scripts"].Left != 20 {
		t.Errorf("caps %v, want only 20 scripts left", caps)
	}
	hinted := 0
	for _, h := range meta.NextHints {
		if strings.HasSuffix(h.Keys["url"], ".js") {
			hinted++
		}
	}
	if hinted != maxScripts {
		t.Errorf("%d scripts hinted, want only the %d read", hinted, maxScripts)
	}
}

// A webpack loader that names more chunks than the limit says how many it
// left; a larger -max-scripts reads the lot.
func TestChunkCapNamesWhatItLeft(t *testing.T) {
	var table []string
	for i := 0; i < 300; i++ {
		table = append(table, fmt.Sprintf(`%d:"h%d"`, i, i))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<script src="/main.js"></script>`)
		case r.URL.Path == "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `n.p="/",n.u=e=>"js/"+e+"."+{%s}[e]+".js",n.x=1;`, strings.Join(table, ","))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if c := capRun(t, srv, 0)["chunk names"]; c.Limit != 256 || c.Left != 44 {
		t.Errorf("chunk names: %+v, want 44 left at 256", c)
	}
	if got := capRun(t, srv, 512); len(got) != 0 {
		t.Errorf("with -max-scripts 512: %v", got)
	}
}
