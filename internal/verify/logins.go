package verify

// This file is the mechanism behind -verify-logins: for a product the
// catalog (logins_catalog.go) names, one sign-in attempt per published
// default credential pair, each measured against two controls sent first on
// the same request (no credential, and a random wrong one), stopping at the
// first success or at a lockout sign, a 429 or a captcha; and, for a product whose own docs say a
// resource needs a sign-in, one GET of it with no credential compared
// with the same GET carrying a deliberately wrong credential. Unlike the
// checks of verify.go, these are not read-only: a sign-in attempt is a
// write the flag alone authorizes, for these requests only.
//
// No password is ever returned by anything here: Attempt's own Request
// and Excerpt name it only as "the published default", and the answer's
// body is scrubbed of the password where it is a credential before it is kept.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/internal/productname"
	"github.com/lilsadfoqs/azhaq/internal/proof"
)

// Kinds of result -verify-logins adds, named by its two checks.
const (
	// KindDefaultLogin: a sign-in attempt with a published default
	// credential pair was accepted.
	KindDefaultLogin = "default-login"
	// KindUnauthenticatedBypass: a resource the product's own docs say
	// needs a sign-in answered a request with no credential the way it
	// answers a signed-in one.
	KindUnauthenticatedBypass = "unauthenticated-bypass"
)

// LoginMode is how a DefaultLogin's one sign-in attempt is sent.
type LoginMode int

const (
	// ModeBasic: a GET of Path with an Authorization: Basic header of
	// the pair — the resource it asks is the one a correct pair unlocks.
	// The pair never appears in the URL, so the ledger's request line
	// (which keeps the URL, never a header) never carries it.
	ModeBasic LoginMode = iota
	// ModeForm: a POST of Path, application/x-www-form-urlencoded, of
	// UserField and PassField. The ledger keeps only the body's hash.
	ModeForm
	// ModeJSON: a POST of Path, application/json, of Body(User, Pass).
	// The ledger keeps only the body's hash.
	ModeJSON
)

// DefaultLogin is one published default credential pair for one product,
// with the one vendor or advisory page that states it: the catalog's
// entries are this type, and none of them is a guess.
type DefaultLogin struct {
	ID      string
	Product string // matched against the product name the run confirmed, by productname.Same (the vendor prefix is optional)
	Source  string // the vendor doc or advisory page that states this pair
	Ports   []int  // the product's documented default ports (web console, API, wire): default asks them
	User    string
	Pass    string

	Mode LoginMode
	Path string // ModeBasic: the resource the pair unlocks; ModeForm/ModeJSON: the sign-in endpoint

	UserField, PassField string                         // ModeForm
	Body                 func(user, pass string) []byte // ModeJSON

	// CaptchaCheck: GET Path first (a GET, read-only) and give up — no
	// credential is ever sent — when its body shows a captcha. Only a
	// product with a sign-in page to look at sets this.
	CaptchaCheck bool

	// Success says a response (status, body) shows the pair was accepted.
	Success func(status int, body []byte) bool

	// Logout, when the product has one, ends the session a success left.
	// It is best-effort: an error changes nothing about the result, and
	// no session is kept whether or not it succeeds. Its request is
	// counted, paced and ledgered like any other (d).
	Logout func(ctx context.Context, d HTTPDoer, origin, cookie string, body []byte)
}

// UnauthRead is one resource a product's own docs say needs a sign-in,
// checked once with no credential and once with a deliberately wrong one.
type UnauthRead struct {
	ID, Product, Path, Source string
	Ports                     []int // the product's documented default ports: default asks them

	// Shown says a response (status, body) shows the product's protected
	// content: a signal that would not appear on its sign-in page or a
	// bare refusal.
	Shown func(status int, body []byte) bool

	// Window, when set, gives the part of a body the evidence keeps (the
	// matched key and a short window around it) instead of its start: a
	// configuration read holds secrets beside what it shows.
	Window func(body []byte) string
}

// HTTPDoer is what a login or read check needs to send one request: an
// egress client already held to the scope, -deny-path and the kill file,
// and Spend, which counts the request against the run's budget and waits
// for its pace before it is sent, as every request to a target is. Both
// are the caller's: this package asks for nothing on its own authority.
type HTTPDoer struct {
	Client *http.Client
	Spend  func(ctx context.Context) error
}

func (d HTTPDoer) do(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	if d.Spend != nil {
		if err := d.Spend(ctx); err != nil {
			return nil, nil, err
		}
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	fetch.BoundNote(resp, req.Method+" "+req.URL.Path) // a stream that never ends is cut, and the run says so
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp, body, nil
}

// LoginOutcome is what one credential pair's attempt showed.
type LoginOutcome struct {
	Tried       bool // false only when CaptchaCheck stopped it first: no credential was sent
	Success     bool
	Lockout     bool // a 429, or the answer's own lockout sign: stop further pairs on this host
	CaptchaSkip bool // the sign-in page showed a captcha: no credential is sent to this product on this host
	Request     string
	Excerpt     string
	Cookie      string // a Form/JSON success: its session cookie, for Logout
	Body        []byte
	// Controls is the control outcome beside the pair's, as it is kept in the
	// evidence. Note is set, with Success false, when the pair was not proved
	// because the path answers the same without a credential (or with a wrong
	// one): a page that is not gated says nothing about a password.
	Controls string
	Note     string
	// Proof is the attempt and its answer, with the password left out of both
	// and of the command that sends the pair again.
	Proof *proof.Proof
}

// answer is what one request of an attempt got, with the rule's verdict.
type answer struct {
	status   int
	body     []byte
	ok       bool            // the entry's Success rule holds for it
	location string          // a redirect's target path, without its query
	cookies  map[string]bool // the names of the cookies it set
}

func isRedirect(status int) bool { return status >= 300 && status < 400 }

// randomCredential is a user and a password nobody has: sent as the wrong
// credential, never a guess at a real pair.
func randomCredential() (user, pass string) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "azhaq-" + hex.EncodeToString(b[:4]), hex.EncodeToString(b[4:])
}

// request is the sign-in request of lg for one credential; none sends it
// with no credential at all (no header, empty fields).
func (lg DefaultLogin) request(ctx context.Context, origin, user, pass string, none bool) (*http.Request, error) {
	switch lg.Mode {
	case ModeForm:
		if none {
			user, pass = "", ""
		}
		form := url.Values{lg.UserField: {user}, lg.PassField: {pass}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+lg.Path, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		return req, err
	case ModeJSON:
		if none {
			user, pass = "", ""
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+lg.Path, bytes.NewReader(lg.Body(user, pass)))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+lg.Path, nil)
	if err == nil && !none {
		req.SetBasicAuth(user, pass)
	}
	return req, err
}

// ask sends one request of an attempt and reads the answer.
func (lg DefaultLogin) ask(ctx context.Context, d HTTPDoer, origin, user, pass string, none bool) (answer, *http.Response, error) {
	req, err := lg.request(ctx, origin, user, pass, none)
	if err != nil {
		return answer{}, nil, err
	}
	resp, body, err := d.do(ctx, req)
	if err != nil {
		return answer{}, nil, err
	}
	a := answer{status: resp.StatusCode, body: body, ok: lg.Success(resp.StatusCode, body), cookies: map[string]bool{}}
	if isRedirect(a.status) {
		if u, err := url.Parse(resp.Header.Get("Location")); err == nil {
			a.location, _, _ = strings.Cut(u.Path, ";") // a session id rides after the ;
		}
	}
	for _, c := range resp.Cookies() {
		a.cookies[c.Name] = true
	}
	return a, resp, nil
}

func (a answer) lockout() bool {
	return a.status == http.StatusTooManyRequests || isLockout(a.status, a.body)
}

// differs says the pair's answer is measurably not the control's: another
// status class, the marker gone, and, for two redirects (a refused sign-in
// redirects too), another target or a session cookie only the pair got.
func differs(pair, c answer) bool {
	if pair.status/100 != c.status/100 || (pair.ok && !c.ok) {
		return true
	}
	if isRedirect(pair.status) && isRedirect(c.status) {
		if pair.location != c.location {
			return true
		}
		for name := range pair.cookies {
			if !c.cookies[name] {
				return true
			}
		}
	}
	return false
}

// describe is an answer as the evidence shows it: its status, where a
// redirect goes, and whether the marker is in it.
func (a answer) describe() string {
	s := strconv.Itoa(a.status)
	switch {
	case isRedirect(a.status) && a.location != "":
		s += " to " + a.location
	case a.ok:
		s += " + marker"
	case a.status/100 == 2:
		s += ", marker absent"
	}
	return s
}

// Attempt sends two controls on lg's request, one with no credential and one
// with a random wrong one, then lg's one pair through d to origin, and judges
// the answers: the pair is accepted only when its answer passes lg's rule and
// each control fails it or answers measurably differently. A path whose
// answer to no credential is the same is not gated, so no pair is sent to it
// and nothing is proved. The password is read from lg only to build the
// request; nothing this returns carries its bytes.
func (lg DefaultLogin) Attempt(ctx context.Context, d HTTPDoer, origin string) (LoginOutcome, error) {
	if lg.CaptchaCheck {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+lg.Path, nil)
		if err != nil {
			return LoginOutcome{}, err
		}
		_, body, err := d.do(ctx, req)
		if err != nil {
			return LoginOutcome{}, err
		}
		if isCaptcha(body) {
			return LoginOutcome{CaptchaSkip: true, Request: "GET " + lg.Path + " (the sign-in page)", Excerpt: "a captcha field is on the sign-in page: no credential is sent"}, nil
		}
	}
	verb := "GET"
	if lg.Mode != ModeBasic {
		verb = "POST"
	}
	sent := fmt.Sprintf("%s %s with no credential, then with a deliberately wrong credential, then with the published default credential pair for %s (%s)", verb, lg.Path, lg.Product, lg.ID)
	out := LoginOutcome{Tried: true, Request: sent}
	stop := func(a answer) LoginOutcome {
		out.Lockout = true
		out.Excerpt = redact(excerpt(a.body), lg.User, lg.Pass, lg.PassField)
		if a.status == http.StatusTooManyRequests {
			out.Excerpt = "429 Too Many Requests: no further pair is sent to this host"
		}
		return out
	}
	none, _, err := lg.ask(ctx, d, origin, "", "", true)
	if err != nil {
		return LoginOutcome{}, err
	}
	if none.lockout() {
		return stop(none), nil
	}
	notGated := "the page answers the same without a credential; the published pair was not proved"
	if none.ok && !isRedirect(none.status) { // a redirect is told apart by its target, any other answer that passes is a page open to all
		out.Controls = "no credential: " + none.describe()
		out.Note = notGated
		return out, nil
	}
	wu, wp := randomCredential()
	wrong, _, err := lg.ask(ctx, d, origin, wu, wp, false)
	if err != nil {
		return LoginOutcome{}, err
	}
	if wrong.lockout() {
		return stop(wrong), nil
	}
	pair, resp, err := lg.ask(ctx, d, origin, lg.User, lg.Pass, false)
	if err != nil {
		return LoginOutcome{}, err
	}
	out.Controls = fmt.Sprintf("no credential: %s; wrong pair: %s; the published pair (%s): %s", none.describe(), wrong.describe(), lg.User, pair.describe())
	shown := redact(excerpt(pair.body), lg.User, lg.Pass, lg.PassField)
	out.Excerpt = out.Controls + "; answer: " + shown
	out.Proof = &proof.Proof{
		ObservedAt: time.Now().UTC().Format(time.RFC3339), Method: verb, Target: origin + lg.Path,
		Status: pair.status, ContentType: resp.Header.Get("Content-Type"),
		Excerpt:     out.Controls + "; answer: " + redact(proof.Printable(pair.body, proof.MaxExcerpt), lg.User, lg.Pass, lg.PassField),
		ExcerptPart: "response", How: "azhaq-verify-logins", Reproduce: lg.reproduce(origin),
	}
	switch {
	case pair.lockout():
		return stop(pair), nil
	case !pair.ok:
	case none.ok && !differs(pair, none):
		out.Note = notGated
	case wrong.ok && !differs(pair, wrong):
		out.Note = "the page answers the same with a wrong credential; the published pair was not proved"
	default:
		out.Success = true
		out.Cookie = setCookieOf(resp)
		out.Body = pair.body
	}
	if out.Note != "" {
		out.Proof = nil
	}
	return out, nil
}

// passMark stands for the password in a JSON body the reproduce command
// fills from the terminal.
const passMark = "AZHAQ-PASSWORD-READ-FROM-THE-TERMINAL"

// reproduce is the curl commands that send lg's request three times: with no
// credential, with a wrong one, and with the pair. The password is asked for,
// not written: the command is kept in the workspace and reports.
func (lg DefaultLogin) reproduce(origin string) string {
	head := "curl -sS --max-time 10"
	if strings.HasPrefix(origin, "https://") {
		head += " -k"
	}
	target := proof.Quote(origin + lg.Path)
	ctl := func(label, args string) string {
		return head + " -o /dev/null -w " + proof.Quote(label+": %{http_code} %{redirect_url}\n") + args + " " + target
	}
	const wrong = "azhaq-wrong"
	switch lg.Mode {
	case ModeForm:
		f := func(u, p string) string {
			return " --data-urlencode " + proof.Quote(lg.UserField+"="+u) + " --data-urlencode " + proof.Quote(lg.PassField+"="+p)
		}
		return "read -rs PASS; " + ctl("no credential", f("", "")) + "; " + ctl("wrong pair", f(wrong, wrong)) + "; " +
			head + " -i --data-urlencode " + proof.Quote(lg.UserField+"="+lg.User) + ` --data-urlencode "` + lg.PassField + `=$PASS" ` + target
	case ModeJSON:
		j := func(u, p string) string {
			return " -H 'Content-Type: application/json' --data " + proof.Quote(string(lg.Body(u, p)))
		}
		body := strings.ReplaceAll(string(lg.Body(lg.User, passMark)), passMark, `'"$PASS"'`)
		return "read -rs PASS; " + ctl("no credential", j("", "")) + "; " + ctl("wrong pair", j(wrong, wrong)) + "; " +
			head + " -i -H 'Content-Type: application/json' --data '" + body + "' " + target
	default:
		return ctl("no credential", "") + "; " + ctl("wrong pair", " -u "+proof.Quote(wrong+":"+wrong)) + "; " +
			head + " -i -u " + proof.Quote(lg.User) + " " + target // curl asks for the password
	}
}

// AttemptLogins tries pairs, in the order given, against origin through
// d: the loop -verify-logins runs for one product on one host. It stops
// at the first pair whose Attempt reports a success, a lockout sign, a
// captcha, or an error, and never sends the pairs after it. lg is the
// pair that stopped it (its zero value when every pair was tried and
// none of them did); tried is how many pairs were actually asked. A path
// found open to all is not asked again for the next pair: when nothing
// else stops the loop, lg and outcome are the one that found it, with
// outcome.Note.
func AttemptLogins(ctx context.Context, d HTTPDoer, origin string, pairs []DefaultLogin) (lg DefaultLogin, outcome LoginOutcome, tried int, err error) {
	open := map[string]bool{}
	var noted DefaultLogin
	var notedOut LoginOutcome
	for _, p := range pairs {
		if open[p.Path] {
			continue
		}
		tried++
		o, e := p.Attempt(ctx, d, origin)
		if e != nil {
			return p, LoginOutcome{}, tried, e
		}
		if o.CaptchaSkip || o.Lockout || o.Success {
			return p, o, tried, nil
		}
		if o.Note != "" {
			open[p.Path] = true
			if notedOut.Note == "" {
				noted, notedOut = p, o
			}
		}
	}
	return noted, notedOut, tried, nil
}

// wrongCredential is sent instead of a real one for the unauthenticated-
// read comparison: deliberately wrong, never a guess at a real pair.
const wrongCredUser, wrongCredPass = "azhaq-verify", "a-deliberately-wrong-credential"

// Check makes u's two reads of origin: one with no credential, one with
// wrongCredential. finding is true only when the unauthenticated answer
// shows u's protected content (Shown); the wrong-credential answer is
// sent and kept as evidence regardless, so the finding carries the
// contrast that proves the resource is usually gated.
func (u UnauthRead) Check(ctx context.Context, d HTTPDoer, origin string) (finding bool, request, evidence string, err error) {
	reqA, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+u.Path, nil)
	if err != nil {
		return false, "", "", err
	}
	respA, bodyA, err := d.do(ctx, reqA)
	if err != nil {
		return false, "", "", err
	}
	reqB, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+u.Path, nil)
	if err != nil {
		return false, "", "", err
	}
	reqB.SetBasicAuth(wrongCredUser, wrongCredPass)
	respB, bodyB, err := d.do(ctx, reqB)
	if err != nil {
		return false, "", "", err
	}
	request = "GET " + u.Path + " with no credential, then GET " + u.Path + " with a deliberately wrong credential"
	evidence = fmt.Sprintf("unauthenticated: %d %s; with a wrong credential: %d %s",
		respA.StatusCode, u.shown(bodyA), respB.StatusCode, u.shown(bodyB))
	finding = u.Shown(respA.StatusCode, bodyA)
	return finding, request, evidence, nil
}

// shown is the evidence of a body: Window's part of it when it has one, else
// the start of it, with the value of every secret key masked before anything
// is cut, so no cut can leave the front of a value behind.
func (u UnauthRead) shown(body []byte) string {
	s := redactSecrets(string(body))
	if u.Window != nil {
		if w := u.Window([]byte(s)); w != "" {
			s = w
		}
	}
	return excerpt([]byte(s))
}

// secretPair is a JSON member whose key names a secret and its value, or the
// start of a value cut off with the body.
var secretPair = lazyre.New(`(?i)("[^"]*(?:pass|secret|token|key|credential)[^"]*"\s*:\s*)("(?:[^"\\]|\\.)*"|"(?:[^"\\]|\\.)*$|[^,}\]\s]+)`)

// redactSecrets masks the value of every JSON member whose key contains pass,
// secret, token, key or credential.
func redactSecrets(s string) string {
	return secretPair.ReplaceAllString(s, `${1}"[redacted]"`)
}

// captchaMarkers and lockoutMarkers are generic, not product-specific:
// a sign-in page or an answer that carries one of these says so itself.
var captchaMarkers = []string{"captcha", "recaptcha", "hcaptcha"}

var lockoutMarkers = []string{
	"too many attempts", "too many failed", "account locked", "account is locked",
	"temporarily locked", "temporarily disabled", "account disabled",
	"try again later", "locked out",
}

func isCaptcha(body []byte) bool { return bodyHasAny(body, captchaMarkers) }

func isLockout(status int, body []byte) bool {
	return status == http.StatusLocked || bodyHasAny(body, lockoutMarkers)
}

func bodyHasAny(body []byte, markers []string) bool {
	s := strings.ToLower(string(body))
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// setCookieOf is the Set-Cookie headers of resp as one Cookie-header
// value: the session a Form or JSON success left, so Logout can ask to
// end it.
func setCookieOf(resp *http.Response) string {
	var parts []string
	for _, c := range resp.Cookies() {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// maskedPass stands for the password in everything kept.
const maskedPass = "(the published default)"

// redact masks the password where it is a credential in s, a body the server
// echoed: as the Authorization header or the user:pass base64, as a credential
// field (password=…, "password":"…", an input's value, field), and as the
// user:pass of a URL. A path, a title or a name that holds the same word is
// left as it is: with admin:admin, /admin/ must stay /admin/.
func redact(s, user, pass, field string) string {
	if pass == "" {
		return s
	}
	val := "(?:" + regexp.QuoteMeta(pass)
	if e := url.QueryEscape(pass); e != pass {
		val += "|" + regexp.QuoteMeta(e)
	}
	val += ")"
	names := "(?:password|passwd|pwd"
	if field != "" {
		names += "|" + regexp.QuoteMeta(field)
	}
	names += ")"
	end := `($|[^\p{L}\p{N}_])`
	for _, p := range []struct{ re, to string }{
		{`(?i)(\bauthorization["']?\s*[:=]\s*["']?(?:basic|bearer|digest|negotiate)?\s*)[A-Za-z0-9+/=._~-]{4,}`, "${1}" + maskedPass},
		{`(?i)(` + names + `["'][^>]{0,200}?\bvalue\s*=\s*["'])` + val + `(["'])`, "${1}" + maskedPass + "${2}"},
		{`(?i)(\bvalue\s*=\s*["'])` + val + `(["'][^>]{0,200}?\bname\s*=\s*["']` + names + `["'])`, "${1}" + maskedPass + "${2}"},
		{`(?i)(\b` + names + `\b["']?[\s:=]+["']?)` + val + end, "${1}" + maskedPass + "${2}"},
		{`(://[^/\s:@"'<>]*:)` + val + `(@)`, "${1}" + maskedPass + "${2}"},
	} {
		s = regexp.MustCompile(p.re).ReplaceAllString(s, p.to)
	}
	pair := user + ":" + pass
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		s = strings.ReplaceAll(s, enc.EncodeToString([]byte(pair)), maskedPass)
	}
	return s
}

// init gives the scan the ports of every catalog entry, so -p default asks
// them (portscan cannot read this package: it imports portscan).
func init() {
	for _, lg := range defaultLogins {
		portscan.RegisterServicePorts(lg.Product, lg.Ports...)
	}
	for _, u := range unauthReads {
		portscan.RegisterServicePorts(u.Product, u.Ports...)
	}
}

// DefaultLogins is the whole catalog, in the order its checks run.
func DefaultLogins() []DefaultLogin { return append([]DefaultLogin(nil), defaultLogins...) }

// UnauthReads is the whole catalog, in the order its checks run.
func UnauthReads() []UnauthRead { return append([]UnauthRead(nil), unauthReads...) }

// LoginsForProduct is the catalog's pairs for product, in catalog order.
func LoginsForProduct(product string) []DefaultLogin {
	if productname.Key(product) == "" {
		return nil
	}
	var out []DefaultLogin
	for _, lg := range defaultLogins {
		if productname.Same(lg.Product, product) {
			out = append(out, lg)
		}
	}
	return out
}

// ReadsForProduct is the catalog's unauthenticated-read checks for
// product, in catalog order.
func ReadsForProduct(product string) []UnauthRead {
	if productname.Key(product) == "" {
		return nil
	}
	var out []UnauthRead
	for _, u := range unauthReads {
		if productname.Same(u.Product, product) {
			out = append(out, u)
		}
	}
	return out
}
