package detect

import (
	"net/http"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/icontest"
)

// The catalog's favicon hash is all the shared template reads: its hit is an
// icon's. A template that reads a header on the same path is not.
func TestHashOnlyHitsAreIcons(t *testing.T) {
	hits := Match(Response{Path: "/favicon.ico", Status: 200, Body: icontest.Body("1278323681")})
	var gitlab *Hit
	for i, h := range hits {
		if h.Template == "favicon-detect" && h.Product == "gitlab" {
			gitlab = &hits[i]
		}
	}
	if gitlab == nil || !gitlab.Icon {
		t.Fatalf("the catalog icon is not an icon hit: %+v", hits)
	}
	rows := Rows(hits)
	if len(rows) == 0 || rows[0]["icon"] != "1" {
		t.Errorf("rows %v", rows)
	}
	// Evidence of more than an image: a response header a template reads at /favicon.ico.
	hits = Match(Response{Path: "/favicon.ico", Status: 200, Header: http.Header{"X-Bigcommerce-Request-Id": {"1"}}, Body: []byte("x")})
	if len(hits) == 0 {
		t.Fatalf("no template matched the header")
	}
	for _, h := range hits {
		if h.Icon {
			t.Errorf("a header match is an icon hit: %+v", h)
		}
	}
	// Another template naming it by more than an image takes the mark off.
	rows = Rows([]Hit{{Product: "A", Template: "favicon-detect", Icon: true}, {Product: "A", Template: "a-detect"}})
	if len(rows) != 1 || rows[0]["icon"] != "" {
		t.Errorf("rows %v", rows)
	}
}
