package fetch

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A catch-all response is what an origin returns for a path that does not
// exist: an SPA index served for every route, a soft 404 page with status
// 200, an error page that echoes the path, or a redirect every unknown path
// gets. CatchAll compares a response with the origin's answer for a random
// path in the same directory.

// maxProbeDirs caps baseline requests per origin; further directories fall
// back to the nearest one above them that was asked.
const maxProbeDirs = 24

var probeToken = RandomName()

// probeDepth, when above zero, is how many directory levels get a baseline of
// their own: a deeper directory is compared with the nearest one above it.
var probeDepth atomic.Int32

// SetProbeDepth limits the baseline requests to the root and the directories
// n levels down (1: /api/ and /rest/, not /rest/user/); 0 asks every directory.
func SetProbeDepth(n int) { probeDepth.Store(int32(max(n, 0))) }

var (
	probeMu    sync.Mutex
	baselines  = map[string]*baseline{}       // origin + dir
	probeDirs  = map[string]int{}             // origin → directories probed
	namedPaths = map[string]map[string]bool{} // origin → paths a script names, whose answers say what their directory holds
	dirAnswers = map[string]*dirAnswer{}      // origin and directory → what those answered
)

// dirAnswer is what the script-named paths asked in one directory answered:
// the catch-all page (shell), or anything else (real).
type dirAnswer struct {
	shell map[string]bool
	real  map[string]bool
	held  bool // a run before this resume held the directory's other paths
}

// CatchAllStop is how many of a directory's script-named paths answer with
// the origin's catch-all page, before as many answer with anything else, for
// run to stop asking the others of that directory: the number the summary's
// note has always started at.
const CatchAllStop = 3

// NoteNamed registers a URL a script names: what it answers, in its
// directory, is what decides whether that directory's other script-named
// paths are asked. The page's own links, the origin's files and what the
// user gave say nothing of them.
func NoteNamed(raw string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return
	}
	origin := u.Scheme + "://" + u.Host
	probeMu.Lock()
	if namedPaths[origin] == nil {
		namedPaths[origin] = map[string]bool{}
	}
	namedPaths[origin][u.EscapedPath()] = true
	probeMu.Unlock()
}

// answerMemo and heldMemo are where a run keeps what the rule learned, for
// azhaq resume: a capped task's answers are kept, but what it recorded is not.
func answerMemo(origin, path string) string { return "catchall " + origin + path }
func heldMemo(dirKey string) string         { return "catchall held " + dirKey }

// NoteHeld records that the other script-named paths of raw's directory are
// not asked.
func NoteHeld(raw string) {
	if u, err := url.Parse(raw); err == nil && u.Host != "" && Memos != nil {
		Memos.Remember(heldMemo(u.Scheme+"://"+u.Host+trimDir(parentDir(u.EscapedPath()))), []byte("1"))
	}
}

// RestoreNamed gives a resumed run what the run it continues learned of the
// script-named URLs: how each answered, and which directories it stopped
// asking in.
func RestoreNamed(raws []string) {
	if Memos == nil {
		return
	}
	held := map[string]bool{} // directories looked up
	for _, raw := range raws {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		origin, path := u.Scheme+"://"+u.Host, u.EscapedPath()
		NoteNamed(raw)
		if v, ok := Memos.Recall(answerMemo(origin, path)); ok && len(v) > 0 {
			noteAnswerAs(origin, path, v[0] == 's', false)
		}
		key := origin + trimDir(parentDir(path))
		if held[key] {
			continue
		}
		held[key] = true
		if _, ok := Memos.Recall(heldMemo(key)); ok {
			probeMu.Lock()
			d := dirAnswers[key]
			if d == nil {
				d = &dirAnswer{shell: map[string]bool{}, real: map[string]bool{}}
				dirAnswers[key] = d
			}
			d.held = true
			probeMu.Unlock()
		}
	}
}

// noteAnswer records how a script-named path answered, in the directory the
// controls are kept for.
func noteAnswer(origin, path string, shell bool) { noteAnswerAs(origin, path, shell, true) }

func noteAnswerAs(origin, path string, shell, keep bool) {
	probeMu.Lock()
	defer probeMu.Unlock()
	if !namedPaths[origin][path] {
		return
	}
	key := origin + trimDir(parentDir(path))
	d := dirAnswers[key]
	if d == nil {
		d = &dirAnswer{shell: map[string]bool{}, real: map[string]bool{}}
		dirAnswers[key] = d
	}
	if shell {
		d.shell[path] = true
		delete(d.real, path)
	} else if !d.shell[path] {
		d.real[path] = true
	}
	if keep && Memos != nil {
		v := []byte("r")
		if shell {
			v = []byte("s")
		}
		Memos.Remember(answerMemo(origin, path), v)
	}
}

// trimDir is the directory the controls are kept for: with a probe depth
// set, a deeper one is the directory that many levels down.
func trimDir(dir string) string {
	for d := int(probeDepth.Load()); d > 0 && strings.Count(dir, "/") > d+1; {
		dir = parentDir(dir)
	}
	return dir
}

// CatchAllHeld says that asking raw would only draw its origin's catch-all
// page again, by what its own directory answered: stop of the directory's
// script-named paths asked so far gave the page every unknown path gets (an
// answer that matched the directory's control, and a success or a
// redirect: an error page says nothing of the paths that exist), before stop
// of them gave anything else. A directory nothing was asked in is no
// exception to know of, so its first path is asked.
func CatchAllHeld(raw string, stop int) bool {
	st, _ := CatchAllDir(raw, stop)
	return st == DirHeld
}

// DirState is what the answers of a directory's script-named paths say of
// one that was not asked yet.
type DirState int

const (
	// DirNone: nothing to hold the path for (no stop, the root, a bad URL).
	DirNone DirState = iota
	// DirUnknown: no script-named path of the directory was asked.
	DirUnknown
	// DirUndecided: some were, and neither stop of them gave the page nor
	// stop of them anything else.
	DirUndecided
	// DirReal: stop of them gave something else, before as many gave the
	// page: the directory's paths answer for themselves, and are asked.
	DirReal
	// DirHeld: stop of them gave the page before stop gave anything else.
	DirHeld
)

// CatchAllDir says what the directory's answers say of raw, and names the
// directory (origin and path), so that callers can keep one path of it in
// flight until its answers have decided.
func CatchAllDir(raw string, stop int) (DirState, string) {
	if stop <= 0 {
		return DirNone, ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return DirNone, ""
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		return DirNone, ""
	}
	own := u.Scheme + "://" + u.Host + trimDir(parentDir(path))
	probeMu.Lock()
	defer probeMu.Unlock()
	d := dirAnswers[own]
	switch {
	case d == nil:
		return DirUnknown, own
	case d.held:
		return DirHeld, own
	case len(d.real) >= stop:
		return DirReal, own
	case len(d.shell) >= stop:
		return DirHeld, own
	case len(d.shell)+len(d.real) == 0:
		return DirUnknown, own
	}
	return DirUndecided, own
}

type baseline struct {
	once  sync.Once
	ready atomic.Bool // the probe has answered or failed
	ok    bool
	fp    fingerprint
	url   string // the path that cannot exist, as asked
	ctype string
}

func (b *baseline) control() *Control {
	return &Control{URL: b.url, Status: b.fp.status, Type: b.ctype, Size: b.fp.size, Title: b.fp.title}
}

type fingerprint struct {
	status   int
	location string
	hash     string
	raw      string // the hash of the body as it came, before the requested path is taken out
	title    string
	lines    int
	words    int
	size     int
	keys     string // a JSON answer's top-level fields; "" for anything else
}

var titleRE = lazyre.New(`(?is)<title[^>]*>(.*?)</title>`)

// RandomName is a path segment no site has: 10 to 14 lowercase letters
// and digits, starting with a letter. It names nothing that would tell a
// log reader which tool asked.
func RandomName() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const alnum = letters + "0123456789"
	var b [15]byte
	_, _ = rand.Read(b[:])
	n := 10 + int(b[0])%5
	out := make([]byte, n)
	out[0] = letters[int(b[1])%len(letters)]
	for i := 1; i < n; i++ {
		out[i] = alnum[int(b[i+1])%len(alnum)]
	}
	return string(out)
}

// ProbeName is a name like RandomName that is the same for the same salt
// within a run, and a run's resume (it has the run's probe token): a sweep's
// calibration asks for the names the stopped run asked, so its answers are
// the kept ones and both halves of the sweep are judged by one calibration.
func ProbeName(salt string) string {
	sum := sha256.Sum256([]byte(ProbeToken() + "\x00" + salt))
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const alnum = letters + "0123456789"
	n := 10 + int(sum[0])%5
	out := make([]byte, n)
	out[0] = letters[int(sum[1])%len(letters)]
	for i := 1; i < n; i++ {
		out[i] = alnum[int(sum[i+1])%len(alnum)]
	}
	return string(out)
}

// SetProbeToken makes the catch-all checks ask for name: a resumed run
// asks for the same paths as the run it continues, whose answers it kept.
func SetProbeToken(name string) {
	probeMu.Lock()
	defer probeMu.Unlock()
	if name != "" {
		probeToken = name
	}
}

// ProbeToken is the name the catch-all checks ask for.
func ProbeToken() string {
	probeMu.Lock()
	defer probeMu.Unlock()
	return probeToken
}

func resetProbes() {
	probeMu.Lock()
	baselines = map[string]*baseline{}
	probeDirs = map[string]int{}
	namedPaths = map[string]map[string]bool{}
	dirAnswers = map[string]*dirAnswer{}
	probeMu.Unlock()
}

// CatchAll reports whether res is the origin's generic answer rather than a
// page of its own. The site root is never a catch-all, and 404/410 are
// already a "no". An auth challenge (401) or a refusal (403) is the server
// distinguishing a route that exists but is gated, not the page an unknown
// path gets: never a catch-all, so an item route like /api/Feedbacks/1 that
// answers 401 (as every id under it does, unauthenticated) is kept, not
// dismissed as the shell, and its answer does not depend on how many
// directories were probed before it.
func CatchAll(ctx context.Context, c *http.Client, res Result) bool {
	shell, _ := CatchAllControl(ctx, c, res)
	return shell
}

// Control is the request for a path that cannot exist, and the answer an
// origin gave it: what a catch-all row was compared with.
type Control struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Type   string `json:"type,omitempty"` // the Content-Type, without parameters
	Size   int    `json:"size"`           // body bytes
	Title  string `json:"title,omitempty"`
	// Exact says the answer that matched it was the control's own page, byte
	// for byte once the requested path is taken out of both; not by shape
	// (same title, size and lines). It is a property of the answer, not of the
	// control, so it is not part of what is stored for the control.
	Exact bool `json:"-"`
}

// CatchAllControl is CatchAll, and for a catch-all answer also the control
// it matched.
func CatchAllControl(ctx context.Context, c *http.Client, res Result) (bool, *Control) {
	if res.Status == 0 {
		return false, nil
	}
	shell, judged, ctl := catchAllVerdict(ctx, c, res)
	if u, err := url.Parse(res.RequestURL); err == nil && u.Host != "" && judged {
		noteAnswer(u.Scheme+"://"+u.Host, u.EscapedPath(), shell && res.Status < 400)
	}
	if !shell {
		ctl = nil
	}
	return shell, ctl
}

// catchAllVerdict says whether res is the catch-all page, and whether that
// was judged: an answer whose control failed (refused by a budget, no
// answer) is no verdict, and says nothing of its directory.
func catchAllVerdict(ctx context.Context, c *http.Client, res Result) (shell, judged bool, ctl *Control) {
	switch res.Status {
	case http.StatusNotFound, http.StatusGone, http.StatusUnauthorized, http.StatusForbidden:
		return false, true, nil
	}
	u, err := url.Parse(res.RequestURL)
	if err != nil || u.Host == "" {
		return false, false, nil
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		return false, false, nil
	}
	origin := u.Scheme + "://" + u.Host
	dir := parentDir(path)
	fp := fingerprintOf(res, origin, requestTarget(u))
	if root := rootShell(origin, dir, fp); root != nil {
		rc := root.control()
		rc.Exact = true
		return true, true, rc
	}
	b := baselineFor(ctx, c, origin, dir)
	if b == nil || !b.ok {
		return false, false, nil
	}
	ctl = b.control()
	ctl.Exact = b.fp.status == fp.status && (isRedirect(fp.status) && b.fp.location == fp.location || !isRedirect(fp.status) && (b.fp.hash == fp.hash || b.fp.raw == fp.raw))
	return b.fp.matches(fp), true, ctl
}

// rootShell: a page byte for byte the site root's answer for an unknown
// path (the single-page app's shell) is that answer in any directory not
// yet asked, so its own baseline request is saved.
func rootShell(origin, dir string, fp fingerprint) *baseline {
	if dir == "/" {
		return nil
	}
	probeMu.Lock()
	root, asked := baselines[origin+"/"], baselines[origin+dir] != nil
	probeMu.Unlock()
	if root == nil || asked || !root.ready.Load() {
		return nil
	}
	if root.ok && root.fp.status == fp.status && root.fp.hash == fp.hash && fp.size > 0 {
		return root
	}
	return nil
}

// FinalCatchAll is CatchAll for the page a redirect chain ended on: the
// body crawlers parse. /assets/i18n → 301 → /assets/i18n/ can land on an
// SPA index although the redirect itself is real.
func FinalCatchAll(ctx context.Context, c *http.Client, res Result) bool {
	if len(res.Hops) <= 1 {
		return CatchAll(ctx, c, res)
	}
	last := res.Hops[len(res.Hops)-1]
	return CatchAll(ctx, c, Result{RequestURL: last.URL, Status: last.Status, Body: res.Body, Header: http.Header{}})
}

func baselineFor(ctx context.Context, c *http.Client, origin, dir string) *baseline {
	dir = trimDir(dir)
	probeMu.Lock()
	key := origin + dir
	b, ok := baselines[key]
	if !ok {
		if dir != "/" && probeDirs[origin] >= maxProbeDirs {
			// The nearest directory above it that was asked: /rest/memories/
			// answers like /rest/ (an error page), not like the site's root
			// (a single-page app's shell).
			probeMu.Unlock()
			return baselineFor(ctx, c, origin, parentDir(dir))
		}
		b = &baseline{}
		baselines[key] = b
		probeDirs[origin]++
	}
	probeMu.Unlock()
	b.once.Do(func() {
		defer b.ready.Store(true)
		target := origin + dir + ProbeToken()
		res, _, err := Do(ledger.WithPurpose(ctx, ledger.PurposeControls), c, target)
		if err != nil || res.Status == 0 {
			return
		}
		u, _ := url.Parse(target)
		b.fp = fingerprintOf(res, origin, requestTarget(u))
		b.url = target
		if res.Header != nil {
			b.ctype = strings.TrimSpace(strings.SplitN(res.Header.Get("Content-Type"), ";", 2)[0])
		}
		b.ok = true
	})
	return b
}

// parentDir is the directory a path lives in: /a/b → /a/, /a/b/ → /a/.
func parentDir(p string) string {
	p = strings.TrimSuffix(p, "/")
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i+1]
}

func requestTarget(u *url.URL) string {
	if u.RawQuery != "" {
		return u.EscapedPath() + "?" + u.RawQuery
	}
	return u.EscapedPath()
}

func fingerprintOf(res Result, origin, target string) fingerprint {
	return fingerprintBy(res, origin, func(s string) string { return stripEcho(s, origin, target) })
}

// SamePage says whether two answers, of two origins, are the same page
// as a catch-all check compares them, once each answer's links to its own
// origin are taken out: one site served over http and https.
func SamePage(a, b Result) bool {
	if a.Status == 0 || b.Status == 0 {
		return false
	}
	return ownPage(a).matches(ownPage(b))
}

func ownPage(res Result) fingerprint {
	origin := ""
	if u, err := url.Parse(res.RequestURL); err == nil {
		origin = u.Scheme + "://" + u.Host
	}
	escaped := strings.ReplaceAll(origin, "/", `\/`) // in JSON strings
	return fingerprintBy(res, origin, func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, origin, ""), escaped, "")
	})
}

func fingerprintBy(res Result, origin string, strip func(string) string) fingerprint {
	fp := fingerprint{status: res.Status}
	if res.Header != nil {
		fp.location = strip(strings.TrimPrefix(res.Header.Get("Location"), origin))
	}
	body := strip(string(res.Body))
	sum := sha256.Sum256([]byte(body))
	fp.hash = hex.EncodeToString(sum[:8])
	rawSum := sha256.Sum256(res.Body)
	fp.raw = hex.EncodeToString(rawSum[:8])
	if m := titleRE.FindStringSubmatch(body); len(m) == 2 {
		fp.title = strings.Join(strings.Fields(m[1]), " ")
	}
	fp.lines = strings.Count(body, "\n")
	fp.words = len(strings.Fields(body))
	fp.size = len(body)
	fp.keys = jsonShape(body)
	return fp
}

// jsonShape is a JSON object's sorted top-level field names ("[]" for an
// array), or "" when the body is not JSON.
func jsonShape(body string) string {
	t := strings.TrimSpace(body)
	if !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") {
		return ""
	}
	var v any
	if json.Unmarshal([]byte(t), &v) != nil {
		return ""
	}
	m, ok := v.(map[string]any)
	if !ok {
		return "[]"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "{" + strings.Join(keys, ",") + "}"
}

// near: two sizes within a fraction of the larger.
func near(a, b int, frac float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return float64(d) <= frac*float64(max(a, b))
}

// stripEcho removes the requested path from a body or header, in the forms
// error pages usually echo it, so two unknown paths compare equal.
func stripEcho(s, origin, target string) string {
	forms := []string{origin + target, target}
	if dec, err := url.PathUnescape(target); err == nil && dec != target {
		forms = append(forms, origin+dec, dec)
	}
	for _, f := range append([]string(nil), forms...) {
		if esc := html.EscapeString(f); esc != f {
			forms = append(forms, esc)
		}
		if esc := url.QueryEscape(f); esc != f {
			forms = append(forms, esc)
		}
	}
	for _, f := range forms {
		s = strings.ReplaceAll(s, f, "\x00")
	}
	return s
}

func (b fingerprint) matches(o fingerprint) bool {
	if b.status != o.status {
		return false
	}
	if isRedirect(b.status) {
		return b.location == o.location
	}
	if b.hash == o.hash {
		return true
	}
	if b.keys != "" || o.keys != "" {
		// JSON on one line has one "word": an object with data and the
		// same object empty would read alike. Fields and size decide.
		return b.keys == o.keys && near(b.size, o.size, 0.1)
	}
	// Pages with a CSRF token or timestamp differ byte-wise but keep their shape.
	return b.title == o.title && b.lines == o.lines && b.words == o.words && b.words > 0 && near(b.size, o.size, 0.2)
}

// String is the control as a line says it: GET /path → 200 text/html, 3748 bytes, "title".
func (c Control) String() string {
	path := c.URL
	if u, err := url.Parse(c.URL); err == nil && u.Path != "" {
		path = u.EscapedPath()
	}
	s := fmt.Sprintf("GET %s → %d", path, c.Status)
	if c.Type != "" {
		s += " " + c.Type
	}
	s += fmt.Sprintf(", %d bytes", c.Size)
	if c.Title != "" {
		s += fmt.Sprintf(", %q", c.Title)
	}
	return s
}
