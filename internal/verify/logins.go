package verify

// This file is the mechanism behind -verify-logins: for a product the
// catalog (logins_catalog.go) names, one sign-in attempt per published
// default credential pair, stopping at the first success or at a lockout
// sign, a 429 or a captcha; and, for a product whose own docs say a
// resource needs a sign-in, one GET of it with no credential compared
// with the same GET carrying a deliberately wrong credential. Unlike the
// checks of verify.go, these are not read-only: a sign-in attempt is a
// write the flag alone authorizes, for these requests only.
//
// No password is ever returned by anything here: Attempt's own Request
// and Excerpt name it only as "the published default", and the answer's
// body is scrubbed of the literal password bytes before it is kept.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
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
	Product string // matched against the product name the run confirmed, by loginProductKey
	Source  string // the vendor doc or advisory page that states this pair
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

	// Shown says a response (status, body) shows the product's protected
	// content: a signal that would not appear on its sign-in page or a
	// bare refusal.
	Shown func(status int, body []byte) bool
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
	// Proof is the attempt and its answer, with the password left out of both
	// and of the command that sends the pair again.
	Proof *proof.Proof
}

// Attempt sends lg's one pair through d to origin, and judges the answer.
// The password is read from lg only to build the request; nothing this
// returns carries its bytes.
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
	var req *http.Request
	var err error
	sent := fmt.Sprintf("%s with the published default credential pair for %s (%s)", lg.Path, lg.Product, lg.ID)
	switch lg.Mode {
	case ModeBasic:
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, origin+lg.Path, nil)
		sent = "GET " + sent
		if err == nil {
			req.SetBasicAuth(lg.User, lg.Pass)
		}
	case ModeForm:
		form := url.Values{lg.UserField: {lg.User}, lg.PassField: {lg.Pass}}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, origin+lg.Path, strings.NewReader(form.Encode()))
		sent = "POST " + sent
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	case ModeJSON:
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, origin+lg.Path, bytes.NewReader(lg.Body(lg.User, lg.Pass)))
		sent = "POST " + sent
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		return LoginOutcome{}, err
	}
	resp, body, err := d.do(ctx, req)
	if err != nil {
		return LoginOutcome{}, err
	}
	out := LoginOutcome{Tried: true, Request: sent, Excerpt: redact(excerpt(body), lg.Pass)}
	out.Proof = &proof.Proof{
		ObservedAt: time.Now().UTC().Format(time.RFC3339), Method: req.Method, Target: origin + lg.Path,
		Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"),
		Excerpt: redact(proof.Printable(body, proof.MaxExcerpt), lg.Pass), ExcerptPart: "response", ExcerptOffset: proof.Offset(0),
		How: "azhaq-verify-logins", Reproduce: lg.reproduce(origin),
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		out.Lockout = true
		out.Excerpt = "429 Too Many Requests: no further pair is sent to this host"
	case isLockout(resp.StatusCode, body):
		out.Lockout = true
	case lg.Success(resp.StatusCode, body):
		out.Success = true
		out.Cookie = setCookieOf(resp)
		out.Body = body
	}
	return out, nil
}

// passMark stands for the password in a JSON body the reproduce command
// fills from the terminal.
const passMark = "AZHAQ-PASSWORD-READ-FROM-THE-TERMINAL"

// reproduce is the curl command that sends lg's pair again. The password is
// asked for, not written: the command is kept in the workspace and reports.
func (lg DefaultLogin) reproduce(origin string) string {
	head := "curl -sS -i --max-time 10"
	if strings.HasPrefix(origin, "https://") {
		head += " -k"
	}
	target := proof.Quote(origin + lg.Path)
	switch lg.Mode {
	case ModeForm:
		return "read -rs PASS; " + head + " --data-urlencode " + proof.Quote(lg.UserField+"="+lg.User) +
			` --data-urlencode "` + lg.PassField + `=$PASS" ` + target
	case ModeJSON:
		body := strings.ReplaceAll(string(lg.Body(lg.User, passMark)), passMark, `'"$PASS"'`)
		return "read -rs PASS; " + head + " -H 'Content-Type: application/json' --data '" + body + "' " + target
	default:
		return head + " -u " + proof.Quote(lg.User) + " " + target // curl asks for the password
	}
}

// AttemptLogins tries pairs, in the order given, against origin through
// d: the loop -verify-logins runs for one product on one host. It stops
// at the first pair whose Attempt reports a success, a lockout sign, a
// captcha, or an error, and never sends the pairs after it. lg is the
// pair that stopped it (its zero value when every pair was tried and
// none of them did); tried is how many pairs were actually asked.
func AttemptLogins(ctx context.Context, d HTTPDoer, origin string, pairs []DefaultLogin) (lg DefaultLogin, outcome LoginOutcome, tried int, err error) {
	for _, p := range pairs {
		tried++
		o, e := p.Attempt(ctx, d, origin)
		if e != nil {
			return p, LoginOutcome{}, tried, e
		}
		if o.CaptchaSkip || o.Lockout || o.Success {
			return p, o, tried, nil
		}
	}
	return DefaultLogin{}, LoginOutcome{}, tried, nil
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
		respA.StatusCode, excerpt(bodyA), respB.StatusCode, excerpt(bodyB))
	finding = u.Shown(respA.StatusCode, bodyA)
	return finding, request, evidence, nil
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

// redact replaces every occurrence of pass in s: nothing kept as evidence
// carries the password, even one a server happened to echo back.
func redact(s, pass string) string {
	if pass == "" {
		return s
	}
	return strings.ReplaceAll(s, pass, "(the published default)")
}

// loginProductKey normalizes a product name for matching: lower case,
// no spaces, hyphens, underscores or dots — the same folding
// internal/advisory uses, kept local so this package asks nothing of it.
func loginProductKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer(" ", "", "-", "", "_", "", ".", "").Replace(s)
}

// DefaultLogins is the whole catalog, in the order its checks run.
func DefaultLogins() []DefaultLogin { return append([]DefaultLogin(nil), defaultLogins...) }

// UnauthReads is the whole catalog, in the order its checks run.
func UnauthReads() []UnauthRead { return append([]UnauthRead(nil), unauthReads...) }

// LoginsForProduct is the catalog's pairs for product, in catalog order.
func LoginsForProduct(product string) []DefaultLogin {
	key := loginProductKey(product)
	if key == "" {
		return nil
	}
	var out []DefaultLogin
	for _, lg := range defaultLogins {
		if loginProductKey(lg.Product) == key {
			out = append(out, lg)
		}
	}
	return out
}

// ReadsForProduct is the catalog's unauthenticated-read checks for
// product, in catalog order.
func ReadsForProduct(product string) []UnauthRead {
	key := loginProductKey(product)
	if key == "" {
		return nil
	}
	var out []UnauthRead
	for _, u := range unauthReads {
		if loginProductKey(u.Product) == key {
			out = append(out, u)
		}
	}
	return out
}
