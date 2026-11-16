package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/hunt"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// bannerListener answers each connection with banner and closes.
func bannerListener(t *testing.T, banner string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(banner))
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// keyOf is what a streamed line and a hunt row are told apart by: the listener,
// what was named and how far a read settled it.
func rowKey(tier, key, product, version, label string) string {
	return strings.Join([]string{tier, key, strings.ToLower(product), version, label}, "|")
}

// The lines a run streams for its listeners are the rows `hunt` lists for them
// after it: the same listeners, products, versions and labels, once each, with
// the fields of hunt -json, and before the map.
func TestRunStreamNamesEachListenerAsHuntDoes(t *testing.T) {
	ssh := bannerListener(t, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
	ftp := bannerListener(t, "220 (vsFTPd 3.0.3)\r\n")
	redis := newRedisFixture(t, redisInfoResp())
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		_, _ = w.Write([]byte("<html><title>x</title></html>"))
	}))
	t.Cleanup(web.Close)
	t.Chdir(t.TempDir())
	ports := strings.Join([]string{strconv.Itoa(ssh), strconv.Itoa(ftp), strconv.Itoa(redis.port)}, ",")
	out, stderr, code := cli(t, "run", "-url", web.URL+"/", "-allow", "127.0.0.1", "-ports", ports, "-verify", "-stream", "-json",
		"-no-paths", "-no-favicon", "-no-tech", "-sources", "none", "-db", "w.db", "-ledger", "w.ledger")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	streamed := map[string]map[string]any{}
	lastNamed, firstMap := -1, -1
	for i, l := range strings.Split(out, "\n") {
		var o map[string]any
		if json.Unmarshal([]byte(l), &o) != nil {
			continue
		}
		if o["type"] == "found" && (o["kind"] == "identified" || o["kind"] == "finding") {
			tier := map[string]string{"identified": "identification", "finding": "finding"}[o["kind"].(string)]
			k := rowKey(tier, o["key"].(string), sval(o["product"]), sval(o["version"]), sval(o["label"]))
			if streamed[k] != nil {
				t.Errorf("%s streamed twice", k)
			}
			streamed[k] = o
			lastNamed = i
		} else if o["type"] != "found" && firstMap < 0 {
			firstMap = i
		}
	}
	if lastNamed < 0 || (firstMap >= 0 && lastNamed > firstMap) {
		t.Errorf("the named lines (last at %d) do not come before the map (first row at %d):\n%s", lastNamed, firstMap, out)
	}
	g, err := readGraph("w.db")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]hunt.Row{}
	for _, r := range huntRows(g, "w.db", nil, 7*24*time.Hour) {
		if r.Ident != nil {
			want[rowKey(r.Tier, r.Key, r.Product, r.Version, r.Label)] = r
		}
	}
	// Every row hunt lists was streamed. A listener a read later proved is one
	// finding row at the end, and its identification line stays printed: the
	// only lines hunt does not list.
	var extra, missing []string
	for k := range want {
		if streamed[k] == nil {
			missing = append(missing, k)
		}
	}
	for k := range streamed {
		if _, ok := want[k]; ok {
			continue
		}
		parts := strings.Split(k, "|")
		proved := false
		for k2 := range want {
			if p2 := strings.Split(k2, "|"); p2[0] == "finding" && p2[1] == parts[1] && p2[2] == parts[2] {
				proved = true
			}
		}
		if !proved {
			extra = append(extra, k)
		}
	}
	if len(missing)+len(extra) > 0 {
		t.Fatalf("hunt lists %q and the stream did not; the stream printed %q and hunt does not", missing, extra)
	}
	var gotKeys []string
	for k := range streamed {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(gotKeys)
	// Nothing was stored after the lines that hunt does not have, so a line is
	// the row: its score, reasons, next command and proof are hunt's own.
	for k, o := range streamed {
		w, ok := want[k]
		if !ok {
			continue
		}
		raw, _ := json.Marshal(w)
		var hr map[string]any
		_ = json.Unmarshal(raw, &hr)
		for _, f := range []string{"score", "reasons", "next", "tier", "evidence", "command", "proof", "label", "severity"} {
			a, _ := json.Marshal(o[f])
			b, _ := json.Marshal(hr[f])
			if string(a) != string(b) {
				t.Errorf("%s: field %s is %s in the stream and %s in hunt", k, f, a, b)
			}
		}
	}
	for _, need := range []string{"identification|127.0.0.1:" + strconv.Itoa(ssh) + "|openssh|8.2p1|version-only", "identification|127.0.0.1:" + strconv.Itoa(ftp) + "|vsftpd|3.0.3|version-only",
		"identification|127.0.0.1:" + web.Listener.Addr().String()[len("127.0.0.1:"):] + "|nginx|1.18.0|version-only"} {
		if streamed[need] == nil {
			t.Errorf("no streamed %s in\n%s", need, strings.Join(gotKeys, "\n"))
		}
	}
	nfind := 0
	for k, o := range streamed {
		if strings.HasPrefix(k, "finding|") {
			nfind++
			if o["tier"] != "finding" || o["label"] != "proved" || o["proof"] == nil || o["collector"] != "azhaq-verify" {
				t.Errorf("finding line %v lacks the fields of hunt -json", o)
			}
		}
		for _, f := range []string{"rank", "type"} {
			if _, ok := o[f]; ok && f == "rank" {
				t.Errorf("%s has a %s", k, f)
			}
		}
		if o["type"] != "found" || o["next"] == nil || o["reasons"] == nil || o["score"] == nil {
			t.Errorf("%s: %v lacks the fields of a hunt row", k, o)
		}
	}
	if nfind == 0 {
		t.Errorf("no finding line for the Redis that answered INFO with no credential:\n%s", strings.Join(gotKeys, "\n"))
	}
}

func sval(v any) string { s, _ := v.(string); return s }

// Text lines carry what the issue asks: the listener, the product, the version
// and the label.
func TestRunStreamIdentifiedTextLine(t *testing.T) {
	ssh := bannerListener(t, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
	t.Chdir(t.TempDir())
	out, stderr, code := cli(t, "run", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1", "-ports", strconv.Itoa(ssh), "-stream",
		"-no-paths", "-no-favicon", "-no-tech", "-sources", "none", "-db", "w.db", "-ledger", "w.ledger")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	want := "found  identified 127.0.0.1:" + strconv.Itoa(ssh) + "  OpenSSH 8.2p1 (version-only)"
	if n := strings.Count(out, want); n != 1 {
		t.Errorf("%d lines %q in\n%s", n, want, out)
	}
}

// A listener is printed again only when what is stored of it changed (a
// more specific version, another label), never for the same row stored again;
// each line is printed while the run goes, once the row is committed.
func TestLiveHuntPrintsAListenerOnceAndAgainWhenItChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.BeginRun("r1", 0, 0); err != nil {
		t.Fatal(err)
	}
	ent, err := st.UpsertEntity(types.TypeHostname, "127.0.0.1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	var advisoryOf []any // the advisory_id each line carries
	named := func(kind, key, same, more, collector string, fields map[string]any) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, l := range lines {
			if strings.HasPrefix(l, kind+" "+key+" ") && strings.HasSuffix(l, " "+same) {
				return false
			}
		}
		lines = append(lines, kind+" "+key+" "+more+" "+same)
		advisoryOf = append(advisoryOf, fields["advisory_id"])
		return true
	}
	have := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
	old := liveHuntMinGap
	liveHuntMinGap = 20 * time.Millisecond
	defer func() { liveHuntMinGap = old }()
	live := startLiveHunt(st, path, named)
	defer live.finish()
	wait := func(n int) {
		t.Helper()
		for i := 0; i < 300 && len(have()) < n; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if got := have(); len(got) != n {
			t.Fatalf("%d lines, want %d: %q", len(got), n, got)
		}
	}
	store := func(version string, extra int) {
		row := map[string]any{"host": "127.0.0.1", "ip": "127.0.0.1", "services": []map[string]any{{"port": 6379 + extra, "service": "redis", "product": "Redis", "version": version}}}
		raw, _ := json.Marshal(row)
		o := types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: raw, ObservedAt: time.Now()}
		st.Batch(func() {
			if _, err := st.AddObservation(ent.ID, o); err != nil {
				t.Fatal(err)
			}
			live.note(o)
		})
	}
	store("7", 0)
	wait(1)
	if !live.Stored() {
		t.Error("a row is stored and Stored says no")
	}
	store("7", 0) // another read of the same: the same row again
	store("7.2.0", 0)
	wait(2)
	// A read of an advisory that says more of the same listener: a new label.
	raw, _ := json.Marshal(verify.Result{Kind: verify.KindAdvisoryPrecond, Label: verify.VersionRead, Severity: "info", Host: "127.0.0.1", Port: 6379,
		Target: "127.0.0.1:6379", Product: "Redis", Version: "7.2.0", AdvisoryID: "CVE-2000-1", Request: "GET /", Evidence: "version 7.2.0"})
	o := types.Observation{Collector: "azhaq-verify", Kind: "verify", Payload: raw, ObservedAt: time.Now()}
	st.Batch(func() {
		if _, err := st.AddObservation(ent.ID, o); err != nil {
			t.Fatal(err)
		}
	})
	live.wake()
	wait(3)
	time.Sleep(150 * time.Millisecond)
	got := have()
	mu.Lock()
	if len(advisoryOf) == 3 && (advisoryOf[0] != nil || advisoryOf[2] != "CVE-2000-1") {
		t.Errorf("advisory_id of the lines %v, want none on the first and CVE-2000-1 on the version-read line", advisoryOf)
	}
	mu.Unlock()
	if len(got) != 3 || !strings.Contains(got[0], "Redis 7 (version-only)") || !strings.Contains(got[1], "Redis 7.2.0 (version-only)") || !strings.Contains(got[2], "Redis 7.2.0 (version-read)") {
		t.Errorf("lines %q, want the version 7 line, the version 7.2.0 line and the version-read line, once each", got)
	}
}

// hunt reads a workspace whose run is still going, rows so far, while the run
// writes; the writer is never held up and loses nothing.
func TestHuntReadsAnOpenWorkspaceWithoutBlockingTheWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.BeginRun("r1", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRunArgs([]string{"-host", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	ent, err := st.UpsertEntity(types.TypeHostname, "127.0.0.1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const listeners = 60
	add := func(i int) error {
		raw, _ := json.Marshal(map[string]any{"host": "127.0.0.1", "ip": "127.0.0.1",
			"services": []map[string]any{{"port": 20000 + i, "service": "redis", "product": "Redis", "version": "7.2.0"}}})
		_, err := st.AddObservation(ent.ID, types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: raw, ObservedAt: time.Now()})
		return err
	}
	// The first rows are committed; the next are written in a batch that stays
	// open while hunt reads, as a task's observations are.
	for i := 0; i < 10; i++ {
		if err := add(i); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var reads, most int
	var readErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			g, err := readGraph(path)
			if err != nil {
				readErr = err
				return
			}
			n := 0
			for _, r := range huntRows(g, path, nil, time.Hour) {
				if r.Ident != nil {
					n++
				}
			}
			reads++
			most = max(most, n)
		}
	}()
	var werr error
	start := time.Now()
	st.Batch(func() {
		for i := 10; i < listeners && werr == nil; i++ {
			werr = add(i)
			time.Sleep(5 * time.Millisecond)
		}
	})
	took := time.Since(start)
	close(stop)
	wg.Wait()
	if werr != nil || readErr != nil {
		t.Fatalf("write error %v, read error %v", werr, readErr)
	}
	if reads == 0 || most < 10 {
		t.Errorf("hunt read %d times and listed at most %d listeners, want the 10 committed rows", reads, most)
	}
	if took > 5*time.Second {
		t.Errorf("the writer took %s for %d rows of 5 ms each: hunt held it up", took, listeners-10)
	}
	g, err := readGraph(path)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range huntRows(g, path, nil, time.Hour) {
		if r.Ident != nil {
			n++
		}
	}
	if n != listeners {
		t.Errorf("%d listeners after the writer ended, want %d", n, listeners)
	}
}

// The progress line names `azhaq hunt -db PATH` once the first listener is
// stored, and not before.
func TestProgressLineNamesHuntOnceAListenerIsStored(t *testing.T) {
	cfg := progressCfg{}
	before := cfg.line(progressSnap{Left: -1}, progressSnap{At: 10 * time.Second, Left: -1})
	if strings.Contains(before, "hunt") {
		t.Errorf("%q names hunt with nothing stored", before)
	}
	after := cfg.line(progressSnap{Left: -1}, progressSnap{At: 10 * time.Second, Left: -1, Hunt: "azhaq hunt -db w.db"})
	if !strings.Contains(after, "; azhaq hunt -db w.db for the rows so far") {
		t.Errorf("%q does not name hunt", after)
	}
	obj := cfg.object(progressSnap{Left: -1}, progressSnap{At: 10 * time.Second, Left: -1, Hunt: "azhaq hunt -db w.db"})
	if obj.Hunt != "azhaq hunt -db w.db" {
		t.Errorf("%+v", obj)
	}
}

// A run that is still going names `azhaq hunt -db PATH` in its progress line
// once its first listener is stored, though no -stream was given; and hunt
// on that workspace, while the run goes, lists the listener.
func TestRunProgressNamesHuntWhileTheRunGoes(t *testing.T) {
	ssh := bannerListener(t, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
	release := make(chan struct{})
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		_, _ = w.Write([]byte("<html></html>"))
	}))
	t.Cleanup(web.Close)
	old := stderrProgressEvery
	stderrProgressEvery = 100 * time.Millisecond
	defer func() { stderrProgressEvery = old }()
	t.Chdir(t.TempDir())
	var rows string
	done := make(chan struct{})
	go func() {
		defer close(done)
		// hunt on the workspace the run holds open, as soon as it has the row.
		for i := 0; i < 200; i++ {
			time.Sleep(25 * time.Millisecond)
			if g, err := readGraph("w.db"); err == nil {
				for _, r := range huntRows(g, "w.db", nil, time.Hour) {
					if r.Ident != nil && r.Product == "OpenSSH" {
						rows = r.Key
						time.Sleep(600 * time.Millisecond) // the run goes on: progress lines follow
						close(release)
						return
					}
				}
			}
		}
		close(release)
	}()
	_, stderr, _ := cli(t, "run", "-url", web.URL+"/", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1", "-ports", strconv.Itoa(ssh),
		"-no-paths", "-no-favicon", "-no-tech", "-sources", "none", "-db", "w.db", "-ledger", "w.ledger")
	<-done
	if rows != "127.0.0.1:"+strconv.Itoa(ssh) {
		t.Errorf("hunt on the open workspace listed %q, want the SSH listener", rows)
	}
	if !strings.Contains(stderr, "; azhaq hunt -db w.db for the rows so far") {
		t.Errorf("no progress line names hunt:\n%s", stderr)
	}
}
