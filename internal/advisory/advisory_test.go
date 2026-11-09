package advisory

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

const fixture = `[
  {"id":"CVE-TEST-0001","summary":"old nginx issue",
   "affected":[{"package":{"name":"nginx","ecosystem":"test"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.20.0"}]}]}],
   "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-0001"}]},
  {"id":"CVE-TEST-0002","summary":"conditional nginx issue","azhaq_precondition":"only when the example module is enabled",
   "azhaq_confirm_path":"/version",
   "affected":[{"package":{"name":"nginx","ecosystem":"test"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.20.0"}]}]}],
   "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-0002"}]},
  {"id":"CVE-TEST-0003","summary":"openssh epoch issue",
   "affected":[{"package":{"name":"OpenSSH","ecosystem":"Debian"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1:9.0"},{"fixed":"1:9.7"}]}]}]}
]`

func loadFixture(t *testing.T) []Advisory {
	t.Helper()
	advs, err := Load([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	return advs
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.18.0", "1.20.0", -1, true},
		{"1.20.0", "1.20.0", 0, true},
		{"v1.2.3", "1.2.3", 0, true},
		{"1.0.0-rc.1", "1.0.0", -1, true},
		{"9.6p1", "9.6", 1, true},
		{"9.6p1", "9.7", -1, true},
		{"1:9.6p1", "1:9.7", -1, true},
		{"2:1.0", "1:9.9", 1, true},
		{"2.4.25-3", "2.4.25-10", -1, true}, // release numbers compare by value, not as text
		{"2.4.25-3ubuntu1", "2.4.25-3", 1, true},
		{"unknown", "1.0.0", 0, false},
		{"14 - 17", "15", 0, false},
		{"", "1.0.0", 0, false},
	}
	for _, c := range cases {
		got, ok := Compare(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("Compare(%q,%q) = %d,%v want %d,%v", c.a, c.b, got, ok, c.want, c.ok)
		}
		if ok {
			rev, _ := Compare(c.b, c.a)
			if rev != -c.want {
				t.Errorf("Compare(%q,%q) = %d, reverse of %d", c.b, c.a, rev, c.want)
			}
		}
	}
}

func TestMatchLabels(t *testing.T) {
	advs := loadFixture(t)
	services := []Service{
		{Host: "h.test", Port: 80, Service: "http", Product: "nginx", Version: "1.18.0"},
		{Host: "h.test", Port: 443, Service: "https", Product: "nginx", Version: "1.24.0"},
		{Host: "h.test", Port: 22, Service: "ssh", Product: "OpenSSH", Version: "1:9.6p1"},
		{Host: "h.test", Port: 22, Service: "ssh", Product: "OpenSSH", Version: "weird"},
	}
	leads := Match(services, advs)
	by := map[string]Lead{}
	for _, l := range leads {
		by[fmt.Sprintf("%s/%d/%s", l.AdvisoryID, l.Port, l.VersionSeen)] = l
	}
	byVer := func(id string, port int, version string) Lead { return by[fmt.Sprintf("%s/%d/%s", id, port, version)] }
	if l := byVer("CVE-TEST-0001", 80, "1.18.0"); l.Label != LabelAffected || l.URL != "https://example.test/CVE-TEST-0001" || l.VersionSeen != "1.18.0" || l.AffectedRange != ">=1.0.0 <1.20.0" {
		t.Errorf("affected lead wrong: %+v", l)
	}
	if l := byVer("CVE-TEST-0002", 80, "1.18.0"); l.Label != LabelConditional || !strings.Contains(l.Precondition, "example module") {
		t.Errorf("conditional lead wrong: %+v", l)
	}
	if l := byVer("CVE-TEST-0001", 443, "1.24.0"); l.Label != LabelNotAffected {
		t.Errorf("not-affected lead wrong: %+v", l)
	}
	if l := byVer("CVE-TEST-0003", 22, "1:9.6p1"); l.Label != LabelAffected {
		t.Errorf("epoch lead wrong: %+v", l)
	}
	// An uncomparable version is conditional and says why, never a guess.
	found := false
	for _, l := range leads {
		if l.AdvisoryID == "CVE-TEST-0003" && l.VersionSeen == "weird" {
			found = true
			if l.Label != LabelConditional || !strings.Contains(l.Precondition, "could not be compared") {
				t.Errorf("uncertain lead wrong: %+v", l)
			}
		}
	}
	if !found {
		t.Error("no lead for the uncomparable version")
	}
}

func TestLoadRejectsUnsafeConfirmPath(t *testing.T) {
	for _, p := range []string{"https://evil.test/x", "//evil.test/x", "/../secret", "/a b", "POST /x"} {
		raw := fmt.Sprintf(`[{"id":"X-1","azhaq_confirm_path":%q,"affected":[{"package":{"name":"nginx"}}]}]`, p)
		if _, err := Load([]byte(raw)); err == nil {
			t.Errorf("confirm path %q accepted", p)
		}
	}
	if _, err := Load([]byte(`[{"id":"X-1","affected":[{"package":{"name":"nginx"}}]}]`)); err != nil {
		t.Errorf("plain record refused: %v", err)
	}
	// JSON lines load too.
	raw := "{\"id\":\"X-1\",\"affected\":[{\"package\":{\"name\":\"nginx\"}}]}\n{\"id\":\"X-2\",\"affected\":[{\"package\":{\"name\":\"nginx\"}}]}"
	if advs, err := Load([]byte(raw)); err != nil || len(advs) != 2 {
		t.Errorf("jsonl: %v %d", err, len(advs))
	}
}

func TestConfirmObservedInferredClaimed(t *testing.T) {
	advs := loadFixture(t)
	var adv Advisory
	for _, a := range advs {
		if a.ID == "CVE-TEST-0002" {
			adv = a
		}
	}
	svc := Service{Host: "h.test", Port: 80, Service: "http", Product: "nginx", Version: "1.18.0"}

	// A stand-in that exposes its version at the documented path:
	// observed for the version, but the advisory's precondition is not
	// what the read shows, so it stays inferred and names the unknown.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/version" {
			t.Errorf("confirmation sent %s %s, want one GET /version", r.Method, r.URL.Path)
		}
		if r.ContentLength != 0 {
			t.Errorf("confirmation sent a body")
		}
		fmt.Fprint(w, `{"product":"nginx","version":"1.18.0"}`)
	}))
	defer srv.Close()
	svc.Origin = srv.URL
	conf, read, err := Confirmer{Client: srv.Client()}.Confirm(context.Background(), adv, svc)
	if err != nil || conf != Inferred || !strings.Contains(read, "GET /version answered 200") || !strings.Contains(read, "example module") {
		t.Errorf("conditional confirm = %q %q %v", conf, read, err)
	}
	if hits.Load() != 1 {
		t.Errorf("confirmation sent %d requests, want 1", hits.Load())
	}

	// Without the precondition the same read settles the range: observed.
	plain := adv
	plain.Precondition, plain.Specific = "", nil
	conf, read, err = Confirmer{Client: srv.Client()}.Confirm(context.Background(), plain, svc)
	if err != nil || conf != Observed || !strings.Contains(read, "inside the advisory's range") {
		t.Errorf("plain confirm = %q %q %v", conf, read, err)
	}

	// A stand-in that exposes no signal: claimed, never observed.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer srv2.Close()
	svc.Origin = srv2.URL
	conf, read, err = Confirmer{Client: srv2.Client()}.Confirm(context.Background(), plain, svc)
	if err != nil || conf != Claimed {
		t.Errorf("silent confirm = %q %q %v, want claimed", conf, read, err)
	}

	// A non-web service is not read at all.
	svc.Origin = ""
	conf, read, err = Confirmer{Client: srv.Client()}.Confirm(context.Background(), plain, svc)
	if err != nil || conf != Claimed || !strings.Contains(read, "not read") {
		t.Errorf("non-web confirm = %q %q %v", conf, read, err)
	}
}

func TestProductVersion(t *testing.T) {
	for line, want := range map[string][2]string{
		"nginx/1.18.0":            {"nginx", "1.18.0"},
		"Apache/2.4.25 (Debian)":  {"Apache", "2.4.25"},
		"OpenSSH 9.6p1":           {"OpenSSH", "9.6p1"},
		"Werkzeug/2.2.3 Python/3": {"Werkzeug", "2.2.3"},
		"":                        {"", ""},
	} {
		p, v := ProductVersion(line)
		if [2]string{p, v} != want {
			t.Errorf("ProductVersion(%q) = %q,%q want %v", line, p, v, want)
		}
	}
}

// The read of a confirmation is bounded as every read of a target answer
// is: a stream that never ends is cut at 64 KiB or 2 s, and the run says so.
func TestConfirmCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	advs := loadFixture(t)
	done := make(chan struct{})
	defer close(done)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for {
			if _, err := w.Write([]byte("data: tick\n")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-done:
				return
			case <-r.Context().Done():
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()
	svc := Service{Host: "h.test", Port: 80, Service: "http", Product: "nginx", Version: "1.18.0", Origin: srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t0 := time.Now()
	_, _, _ = Confirmer{Client: srv.Client()}.Confirm(ctx, advs[0], svc)
	if took := time.Since(t0); took > 5*time.Second {
		t.Errorf("the stream held the read for %s", took)
	}
	said := false
	for _, n := range fetch.Notes() {
		said = said || strings.Contains(n, "stream that never ends")
	}
	if !said {
		t.Errorf("no note says the answer was cut: %q", fetch.Notes())
	}
}
