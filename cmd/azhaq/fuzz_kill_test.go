package main

import (
	"fmt"
	"github.com/lilsadfoqs/azhaq/store"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fuzzKilled starts fuzz with -db, kills it with SIGKILL once the server has
// seen from its words, and returns what the server saw per path.
func fuzzKilled(t *testing.T, method string, words, after int, srv func(w http.ResponseWriter, r *http.Request)) (db string, seen func() map[string]int, srvURL string) {
	t.Helper()
	var mu sync.Mutex
	counts := map[string]int{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		if srv != nil {
			srv(w, r)
		}
	}))
	t.Cleanup(s.Close)
	var lines []string
	for i := 1; i <= words; i++ {
		lines = append(lines, fmt.Sprintf("w%d", i))
	}
	dir := t.TempDir()
	db = filepath.Join(dir, "f.db")
	args := []string{"fuzz", "-u", s.URL + "/FUZZ", "-w", wlist(t, lines...), "-ac=false", "-mc", "all", "-rate", "25", "-t", "2", "-db", db, "-json"}
	if method != "" {
		args = append(args, "-X", method, "-d", "a=b")
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1", "AZHAQ_DATA_DIR="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	total := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, c := range counts {
			n += c
		}
		return n
	}
	for i := 0; i < 400 && total() < after; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if total() < after || total() >= words {
		_ = cmd.Process.Kill()
		t.Fatalf("the server saw %d requests of %d before the kill, want %d or more and not all", total(), words, after)
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	if raw, _ := os.ReadFile(db + ".ledger.jsonl"); strings.Contains(string(raw), `"kind":"seal"`) {
		t.Fatal("the killed run's ledger is sealed")
	}
	dataDirs.Store(t.Name(), dir)
	ledgerHoldsAKilledRun(t)
	return db, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range counts {
			out[k] = v
		}
		return out
	}, s.URL
}

// A fuzz run with -db that is killed (SIGKILL) leaves its workspace and the
// command that goes on: azhaq resume asks the rest, and what the run had
// answered is not asked again beyond the answers its last checkpoint missed.
func TestFuzzKilledWithSIGKILLResumes(t *testing.T) {
	const words = 60
	db, seen, _ := fuzzKilled(t, "", words, 30, nil)
	if _, err := os.Stat(db); err != nil {
		t.Fatalf("the killed run left no workspace: %v", err)
	}
	_, rep, code := runContract(t, "resume", "-db", db)
	if code != exitOK {
		t.Fatalf("resume: exit %d\n%+v", code, rep)
	}
	after := seen()
	again := 0
	for i := 1; i <= words; i++ {
		k := fmt.Sprintf("GET /w%d", i)
		if after[k] < 1 {
			t.Errorf("%s was never asked", k)
		}
		if after[k] > 1 {
			again++
		}
	}
	// Only the answers since the last checkpoint (a second, 25 requests) are
	// asked again.
	if again > 30 {
		t.Errorf("%d inputs were asked twice: the resume did not skip what was answered", again)
	}
	if !regexp.MustCompile(`\d+ requests? sent before the run was killed had no stored answer and (was|were) asked again`).MatchString(strings.Join(rep.Notes, "\n")) && again > 0 {
		t.Errorf("%d inputs were asked again and the notes do not say so:\n%s", again, strings.Join(rep.Notes, "\n"))
	}
}

// The same with a write: a POST the killed run sent is never sent again, so
// every word has exactly one, and the resume says what it held back.
func TestFuzzKilledWithSIGKILLNeverSendsAWriteTwice(t *testing.T) {
	const words = 60
	db, seen, _ := fuzzKilled(t, "POST", words, 30, nil)
	_, rep, code := runContract(t, "resume", "-db", db)
	if code != exitOK {
		t.Fatalf("resume: exit %d\n%+v", code, rep)
	}
	after := seen()
	for i := 1; i <= words; i++ {
		if k := fmt.Sprintf("POST /w%d", i); after[k] != 1 {
			t.Errorf("%s reached the server %d times, want 1", k, after[k])
		}
	}
	if len(rep.Failed) != 0 || rep.Requests >= words {
		t.Errorf("the resume failed %+v or sent %d requests of the %d inputs", rep.Failed, rep.Requests, words)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "sent before the run was killed, with no answer stored: not sent again") {
		t.Errorf("the notes do not say what was held back:\n%s", strings.Join(rep.Notes, "\n"))
	}
}

// The summary of a fuzz run says what its ledger holds and its seal, as every
// other command's does (it is written after the ledger is sealed).
func TestFuzzSummarySaysWhatTheLedgerHolds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	db := filepath.Join(t.TempDir(), "s.db")
	_, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "a", "b", "c"), "-ac=false", "-db", db)
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !regexp.MustCompile(`ledger: 3 recorded in .*3 to targets .*sealed [0-9a-f]{64}`).MatchString(notes) {
		t.Errorf("the notes do not say what the ledger holds:\n%s", notes)
	}
}

const (
	secretCookie = "SECRETCOOKIE-7c1f"
	secretBearer = "SECRETBEARER-7c1f"
	secretProxy  = "SECRETPROXYPW-7c1f"
)

// everythingKept is the bytes of a workspace and its ledger, free pages
// included: nothing a run kept may hold a secret.
func everythingKept(t *testing.T, db string) string {
	t.Helper()
	var b strings.Builder
	for _, f := range []string{db, db + "-wal", db + ".ledger.jsonl"} {
		raw, _ := os.ReadFile(f)
		b.Write(raw)
	}
	return b.String()
}

// A fuzz run with -db keeps its command for azhaq resume as run does: the
// cookie, a credential header and a proxy's password are not stored, files
// are by their full path, and the resume works when they are given again.
func TestFuzzKeepsItsCommandWithoutSecrets(t *testing.T) {
	var mu sync.Mutex
	var cookies, auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookies = append(cookies, r.Header.Get("Cookie"))
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(404)
	}))
	defer srv.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "w.txt"), []byte("a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir) // the files are given by relative names
	db := filepath.Join(dir, "k.db")
	_, rep, code := runContract(t, "fuzz", "-u", srv.URL+"/FUZZ", "-w", "w.txt", "-ac=false", "-mc", "all", "-t", "1", "-max-requests", "3",
		"-b", "a="+secretCookie, "-H", "Authorization: Bearer "+secretBearer, "-H", "X-Trace: 1",
		"-x", "http://u:"+secretProxy+"@"+strings.TrimPrefix(srv.URL, "http://"), "-db", db)
	_ = rep
	if code != exitLimit {
		t.Fatalf("exit %d, want the budget to stop it", code)
	}
	if got := everythingKept(t, db); strings.Contains(got, secretCookie) || strings.Contains(got, secretBearer) || strings.Contains(got, secretProxy) {
		t.Errorf("a secret is in the workspace or the ledger")
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	stored := st.GetMeta(fuzzResumeKey)
	st.Close()
	for _, want := range []string{filepath.Join(dir, "w.txt"), "-H=X-Trace: 1", srv.URL[len("http://"):]} {
		if !strings.Contains(stored, want) {
			t.Errorf("the stored command lacks %q: %s", want, stored)
		}
	}
	if strings.Contains(stored, `"-db`) || strings.Contains(stored, `"w.txt"`) || strings.Contains(stored, "Authorization") {
		t.Errorf("the stored command holds the database, a relative file or a credential header: %s", stored)
	}

	// Without the secrets the resume says it goes without them.
	t.Chdir(t.TempDir()) // from another directory: the wordlist is found
	mu.Lock()
	cookies, auths = nil, nil
	mu.Unlock()
	_, rep, code = runContract(t, "resume", "-db", db, "-max-requests", "3", "-x", "")
	if code != exitLimit {
		t.Fatalf("resume: exit %d\n%+v", code, rep)
	}
	if n := strings.Join(rep.Notes, "\n"); !strings.Contains(n, "-b") || !strings.Contains(n, "-H Authorization") || !strings.Contains(n, "-x credentials") || !strings.Contains(n, "not stored") {
		t.Errorf("the resume does not say what it lacks:\n%s", n)
	}
	// Given again, they are sent.
	_, rep, code = runContract(t, "resume", "-db", db, "-max-requests", "3", "-b", "a="+secretCookie, "-H", "Authorization: Bearer "+secretBearer,
		"-x", "http://u:"+secretProxy+"@"+strings.TrimPrefix(srv.URL, "http://"))
	if code != exitLimit {
		t.Fatalf("resume with the secrets: exit %d\n%+v", code, rep)
	}
	mu.Lock()
	defer mu.Unlock()
	last := len(cookies) - 1
	if last < 0 || !strings.Contains(cookies[last], secretCookie) || !strings.Contains(auths[last], secretBearer) {
		t.Errorf("the resume did not send the secrets given again: %q %q", cookies, auths)
	}
	if strings.Contains(strings.Join(rep.Notes, "\n"), "not stored") {
		t.Errorf("the resume says it lacks what it was given: %v", rep.Notes)
	}
	if got := everythingKept(t, db); strings.Contains(got, secretCookie) || strings.Contains(got, secretBearer) {
		t.Errorf("a secret given to the resume is in the workspace or the ledger")
	}
}

// The password of a proxy is no more stored than a cookie is, whichever
// command's workspace it is.
func TestKeptArgsDropAProxyPassword(t *testing.T) {
	got := strings.Join(keptArgs([]string{"-url", "http://t/", "-proxy", "http://u:pw-1@p:3128", "-source-proxy=http://u:pw-2@p:1", "-urls-proxy", "http://u:pw-3@p:2", "-port-proxy", "u:pw-4@p:1080"}), " ")
	if strings.Contains(got, "pw-") || !strings.Contains(got, "-proxy=http://p:3128") || !strings.Contains(got, "-port-proxy=p:1080") {
		t.Errorf("kept %q", got)
	}
	if d := strings.Join(keptDNSArgs([]string{"-d", "x", "-proxy", "socks5://u:pw-5@p:1"}), " "); strings.Contains(d, "pw-5") {
		t.Errorf("dns kept %q", d)
	}
}

// probe keeps each answer for resume with the request that asked it: that
// request has no credential header (and no body) in the workspace.
func TestProbeKeepsNoCredentialHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<title>t</title>") }))
	defer srv.Close()
	db := filepath.Join(t.TempDir(), "p.db")
	if _, _, code := runContract(t, "probe", "-u", srv.URL, "-cookie", "a="+secretCookie, "-H", "Authorization: Bearer "+secretBearer, "-H", "X-Trace: 1", "-irr", "-db", db); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if got := everythingKept(t, db); strings.Contains(got, secretCookie) || strings.Contains(got, secretBearer) {
		t.Errorf("a credential header is in the workspace")
	}
}
