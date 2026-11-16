package engine

import (
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/httprow"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// The azhaq-http rows the engine writes (a failure and an answer cut short, a
// URL not requested, a scheme settled) fit httprow.Row key for key.
func TestEngineHTTPRowsFitRow(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ws.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e := &Engine{Store: st}
	ent, err := st.UpsertEntity(types.TypeURL, "https://h/", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	e.noteError(ent.ID, "azhaq-http", errors.New("dial tcp: refused"))
	cut := &fetch.CutBody{Status: 200, ContentType: "text/html", Header: http.Header{"X-A": {"b"}}, Body: []byte("<html>part"), Want: 100}
	e.noteError(ent.ID, "azhaq-http", cut)
	e.noteError(ent.ID, "azhaq-http", &fetch.CutBody{Status: 200, Header: http.Header{"X-A": {"b"}}, Body: []byte{0xff, 0xfe}, Want: -1})
	e.noteSkip(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://h/x"}}, "out of scope")
	e.secureHost("h")
	obs, err := st.Observations()
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, o := range obs {
		if o.Collector != "azhaq-http" {
			continue
		}
		kinds[o.Kind] = true
		if _, err := httprow.ParseRowStrict(o.Payload); err != nil {
			t.Errorf("%s row: %v in %s", o.Kind, err, o.Payload)
		}
	}
	for _, k := range []string{"error", "skipped", schemeKind} {
		if !kinds[k] {
			t.Errorf("no %s row written", k)
		}
	}
}
