package portcol

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/httpcol"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// A port nothing was probed on is asked over plain HTTP first when it is
// above 1024 (one request when it is plain, a 400 and a second over TLS when
// it is not); a probed service names its scheme.
func TestHintSchemeOrder(t *testing.T) {
	for _, tc := range []struct {
		open    portscan.Open
		url, fb string
	}{
		{portscan.Open{Port: 3001}, "http://h:3001/", "https"},
		{portscan.Open{Port: 8080}, "http://h:8080/", "https"},
		{portscan.Open{Port: 3001, Service: "tls"}, "https://h:3001/", "http"},
		{portscan.Open{Port: 3001, Service: "https"}, "https://h:3001/", ""},
		{portscan.Open{Port: 3001, Service: "http"}, "http://h:3001/", ""},
	} {
		hints := hintsOf("h", []portscan.Open{tc.open})
		if len(hints) != 1 || hints[0].Keys["url"] != tc.url || hints[0].Keys[httpcol.FallbackKey] != tc.fb {
			t.Errorf("%+v: %v, want %s then %q", tc.open, hints, tc.url, tc.fb)
		}
	}
}

// Only a port the scan did not name as HTTP is marked: a close on its
// request is an answer there, and a failure for one named http or https.
func TestHintMarksPortsNotNamedHTTP(t *testing.T) {
	for _, tc := range []struct {
		open portscan.Open
		want bool
	}{
		{portscan.Open{Port: 3001}, true},
		{portscan.Open{Port: 3001, Service: "tls"}, true},
		{portscan.Open{Port: 8000, Service: "http?"}, true},
		{portscan.Open{Port: 3001, Service: "http"}, false},
		{portscan.Open{Port: 3001, Service: "https"}, false},
	} {
		hints := hintsOf("h", []portscan.Open{tc.open})
		if len(hints) != 1 || (hints[0].Keys[types.UnnamedPortKey] != "") != tc.want {
			t.Errorf("%+v: %v, marked %v wanted", tc.open, hints, tc.want)
		}
	}
}
