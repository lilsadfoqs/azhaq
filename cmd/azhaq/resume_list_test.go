package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// A drop-in's target list is a temporary file, gone when azhaq resume
// runs: the workspace's copy stands in for it.
func TestResumeListFromWorkspace(t *testing.T) {
	db := filepath.Join(t.TempDir(), "w.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetMeta("list:r1", "http://a.test/\nhttp://b.test/"); err != nil {
		t.Fatal(err)
	}
	st.Close()
	got, err := listFromWorkspace(db, "r1", []string{"-list=/tmp/azhaq-list-gone", "-dirs", "words.txt"})
	if err != nil || !reflect.DeepEqual(got, []string{"-list=@run", "-dirs", "words.txt"}) || !reflect.DeepEqual(storedList, []string{"http://a.test/", "http://b.test/"}) {
		t.Fatalf("%q %v, list %q", got, err, storedList)
	}
	seeds, _, err := loadList("@run")
	if err != nil || len(seeds) != 2 {
		t.Fatalf("seeds %v %v", seeds, err)
	}
	if _, err := listFromWorkspace(db, "r2", []string{"-list", "-"}); err == nil {
		t.Error("a list neither on disk nor in the workspace resumed")
	}
	if got := keptArgs([]string{"-list", "-"}); !reflect.DeepEqual(got, []string{"-list=-"}) {
		t.Errorf("stdin list kept as %q", got)
	}
	// A list file changed since: the run continues the targets it began with.
	changed := filepath.Join(t.TempDir(), "t.txt")
	if err := os.WriteFile(changed, []byte("http://evil.test/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	storedList = nil
	got, err = listFromWorkspace(db, "r1", []string{"-list", changed})
	if err != nil || !reflect.DeepEqual(got, []string{"-list", "@run"}) || len(storedList) != 2 {
		t.Errorf("changed file: %q %v, list %q", got, err, storedList)
	}
	// Files are kept absolute: azhaq resume may run from elsewhere.
	if got := keptArgs([]string{"-dirs", "words.txt", "-screenshots=shots"}); !filepath.IsAbs(strings.TrimPrefix(got[0], "-dirs=")) || !filepath.IsAbs(strings.TrimPrefix(got[1], "-screenshots=")) {
		t.Errorf("relative files kept as %q", got)
	}
}

func TestStreamFound(t *testing.T) {
	out, _, err := captureBoth(t, func() error {
		see := streamFound(false)
		for _, p := range []string{`{"url":"http://a.test/x"}`, `{"url":"http://a.test/x"}`} {
			see(types.Entity{}, types.Observation{Kind: "url", Payload: []byte(p)})
		}
		see(types.Entity{}, types.Observation{Kind: "application", Payload: []byte(`{"url":"http://a.test/","status":200,"title":"Home"}`)})
		see(types.Entity{}, types.Observation{Kind: "application", Payload: []byte(`{"url":"http://a.test/signup","status":200,"title":"Home","catchall":true}`)})
		see(types.Entity{}, types.Observation{Kind: "dns", Payload: []byte(`{"fqdn":"w.a.test","ips":["192.0.2.1"],"wildcard":true}`)})
		return nil
	})
	want := "found  url     http://a.test/x\nfound  answer  http://a.test/  [200] Home\nfound  answer  http://a.test/signup  [200] Home  (catch-all: the page any unknown path gets)\nfound  address 192.0.2.1\n"
	if err != nil || out != want {
		t.Errorf("%q, want %q", out, want)
	}
}

// A URL found by the crawl and answered later, or answered and then linked,
// is one line, and the address of an IP host is one more: a key prints once.
func TestStreamFoundOncePerKey(t *testing.T) {
	out, _, err := captureBoth(t, func() error {
		see := streamFound(true)
		obs := func(kind, payload string) {
			see(types.Entity{}, types.Observation{Kind: kind, Collector: "c", Payload: []byte(payload)})
		}
		obs("url", `{"url":"http://127.0.0.1:5020/a"}`)
		obs("application", `{"url":"http://127.0.0.1:5020/a","status":200,"title":"A"}`)
		obs("application", `{"url":"http://127.0.0.1:5020/","status":200,"title":"Home"}`)
		obs("url", `{"url":"http://127.0.0.1:5020/"}`)
		obs("url", `{"url":"http://127.0.0.1:5020/#/x","role":"client-route"}`)
		obs("dns", `{"fqdn":"a.test","ips":["192.0.2.1","127.0.0.1"]}`)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var d map[string]any
		if json.Unmarshal([]byte(l), &d) != nil {
			t.Fatalf("not JSON: %q", l)
		}
		keys = append(keys, d["kind"].(string)+" "+d["key"].(string))
	}
	want := []string{"url http://127.0.0.1:5020/a", "address 127.0.0.1", "answer http://127.0.0.1:5020/", "url http://127.0.0.1:5020/#/x", "name a.test", "address 192.0.2.1"}
	if !slices.Equal(keys, want) {
		t.Errorf("lines %q, want %q", keys, want)
	}
}

// What -stream prints and the map holds are the same keys, each once: the
// address row and the front page found twice included.
func TestRunStreamKeysAreTheMapsKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><head><title>Home</title><script src="/app.js"></script></head><body><a href="/">home</a><a href="/a">a</a><a href="/b">b</a></body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/x")`)
		case "/a", "/b":
			fmt.Fprint(w, `<html><title>`+r.URL.Path+`</title></html>`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	for _, depth := range []string{"0", "2"} {
		out, _, err := captureBoth(t, func() error {
			return cmdRun([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-depth", depth, "-max-requests", "40", "-stream", "-json", "-db", filepath.Join(t.TempDir(), "w.db")})
		})
		if err != nil && exitCode(err) != exitPartial {
			t.Fatal(err)
		}
		var streamed, mapped []string
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			var d map[string]any
			if json.Unmarshal([]byte(l), &d) != nil {
				t.Fatalf("not JSON: %q", l)
			}
			key, _ := d["key"].(string)
			switch d["type"] {
			case "found":
				streamed = append(streamed, key)
			case "summary":
			default:
				mapped = append(mapped, key)
			}
		}
		slices.Sort(streamed)
		slices.Sort(mapped)
		if !slices.Equal(streamed, mapped) {
			t.Errorf("-depth %s: streamed %q, map %q", depth, streamed, mapped)
		}
		if !slices.Contains(mapped, "127.0.0.1") {
			t.Errorf("-depth %s: no address row in %q", depth, mapped)
		}
	}
}

// An open port is one line under its row's key, whichever scan reports it:
// the cumulative open list of a later scan does not print the first port
// again, and a range's own row is no port.
func TestStreamFoundPortRows(t *testing.T) {
	out, _, err := captureBoth(t, func() error {
		see := streamFound(true)
		obs := func(payload string) {
			see(types.Entity{}, types.Observation{Kind: "ports", Collector: "azhaq-ports", Payload: []byte(payload)})
		}
		obs(`{"host":"a.test","ip":"192.0.2.1","open":[22],"services":[{"port":22,"service":"ssh"}]}`)
		obs(`{"host":"a.test","ip":"192.0.2.1","open":[22,3001],"services":[{"port":22,"service":"ssh"},{"port":3001}],"udp_services":[{"port":53,"state":"open|filtered"}]}`)
		obs(`{"host":"a.test","ip":"192.0.2.1","open":[],"scanned":2}`)
		obs(`{"range":true,"prefix":"192.0.2.0/24","open":[]}`)
		obs(`{"host":"192.0.2.9","open":[80],"services":[{"port":80}]}`)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var d map[string]any
		if json.Unmarshal([]byte(l), &d) != nil {
			t.Fatalf("not JSON: %q", l)
		}
		if d["kind"] != "port" || d["port"] == nil || d["protocol"] == nil || d["ip"] == nil {
			t.Errorf("line %q lacks kind port, port, protocol or ip", l)
		}
		keys = append(keys, d["key"].(string))
	}
	want := []string{"192.0.2.1:22/tcp", "192.0.2.1:3001/tcp", "192.0.2.1:53/udp", "192.0.2.9:80/tcp"}
	if !slices.Equal(keys, want) {
		t.Errorf("keys %q, want %q", keys, want)
	}
	text, _, _ := captureBoth(t, func() error {
		streamFound(false)(types.Entity{}, types.Observation{Kind: "ports", Payload: []byte(`{"host":"a.test","ip":"192.0.2.1","services":[{"port":22,"service":"ssh"}]}`)})
		return nil
	})
	if text != "found  port    192.0.2.1:22/tcp  a.test  open ssh\n" {
		t.Errorf("text line %q", text)
	}
}

// With ports, what -stream prints and the map holds are the same keys: one
// line for each port row, the open-port list of the scan is not one.
func TestRunStreamPortKeysAreTheMapsKeys(t *testing.T) {
	var ports []string
	for i := 0; i < 2; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
				c.Close()
			}
		}()
		ports = append(ports, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	}
	out, _, err := captureBoth(t, func() error {
		return cmdRun([]string{"-cidr", "127.0.0.1/32", "-ports", strings.Join(ports, ","), "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-depth", "0", "-stream", "-json", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	var streamed, mapped []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var d map[string]any
		if json.Unmarshal([]byte(l), &d) != nil {
			t.Fatalf("not JSON: %q", l)
		}
		key, _ := d["key"].(string)
		switch d["type"] {
		case "found":
			if d["kind"] == "port" {
				streamed = append(streamed, key)
			}
		case "summary":
		default:
			if strings.Contains(key, "/tcp") {
				mapped = append(mapped, key)
			}
		}
	}
	slices.Sort(streamed)
	slices.Sort(mapped)
	var want []string
	for _, p := range ports {
		want = append(want, "127.0.0.1:"+p+"/tcp")
	}
	slices.Sort(want)
	if !slices.Equal(streamed, want) || !slices.Equal(mapped, want) {
		t.Errorf("streamed %q, map %q, want %q", streamed, mapped, want)
	}
}

// A run stored with the options that held GETs back by name goes on
// without them, and the resume says so.
func TestResumeDropsRemovedFlags(t *testing.T) {
	got, gone := dropRemovedFlags([]string{"-url", "https://app.test/", "-all-gets", "-get-words", "exec,import", "-depth=2", "--get-words=x", "-all-gets=true", "-skip", "azhaq-dns"})
	want := []string{"-url", "https://app.test/", "-depth=2", "-skip", "azhaq-dns"}
	if !slices.Equal(got, want) {
		t.Errorf("args %q, want %q", got, want)
	}
	if !slices.Equal(gone, []string{"-all-gets", "-get-words", "-get-words", "-all-gets"}) {
		t.Errorf("gone %q", gone)
	}
}

// -cloud FILE was replaced by -l: a stored run that has it goes on without,
// and the note says what to use.
func TestResumeDropsCloud(t *testing.T) {
	got, gone := dropRemovedFlags([]string{"-url", "https://app.test/", "-cloud", "/tmp/inv.json", "-depth=2", "-cloud=/tmp/b.json"})
	if want := []string{"-url", "https://app.test/", "-depth=2"}; !slices.Equal(got, want) {
		t.Errorf("args %q, want %q", got, want)
	}
	if !slices.Equal(gone, []string{"-cloud", "-cloud"}) || !strings.Contains(removedWhy(gone), "-l FILE") || strings.Contains(removedWhy(gone), "GET") {
		t.Errorf("gone %q: %s", gone, removedWhy(gone))
	}
}

func TestRunCloudIsUsageError(t *testing.T) {
	for _, f := range []func([]string) error{cmdRun, cmdPlan} {
		err := f([]string{"-cloud", "inv.json"})
		if err == nil || exitCode(err) != exitUsage || !strings.Contains(err.Error(), "-cloud") {
			t.Errorf("-cloud: %v", err)
		}
	}
}
