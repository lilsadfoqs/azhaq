package subcol

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/answer"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

// A source that answers 429 or a 5xx that says busy (500, 502, 503, 504 and
// the like; not 501 or 505) is asked again after the Retry-After it names
// (or a growing pause when it names none), up to maxRetries times, so a
// busy source costs time, not names. The sources are subfinder's: they
// give up at the first refusal, so the wait is made one level down, in the
// transport every source's request goes through. A pause that would end
// past the source's time (-source-timeout) is not taken.
const (
	maxRetries = 3
	// maxRetryWait is the longest pause taken: a source that wants more is
	// not waited for, and says so in its row.
	maxRetryWait = 30 * time.Second
)

var firstPause = 2 * time.Second

type throttleKey struct{}

// throttle is what Run learns about a source's 429 answers, for its row.
type throttle struct {
	requests   atomic.Int32 // requests sent, retries included
	retried    atomic.Int32 // requests sent again after a 429
	mu         sync.Mutex
	waited     time.Duration
	gaveUp     bool          // still 429 after the retries, or asked for too long a wait
	retried5   atomic.Int32  // requests sent again after a 5xx
	gaveUp5    bool          // still a 5xx after the retries, or no time left to wait
	retryAfter time.Duration // the longest Retry-After seen
}

func (t *throttle) note(wait time.Duration, asked time.Duration, gaveUp, serverError bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.waited += wait
	t.retryAfter = max(t.retryAfter, asked)
	if serverError {
		t.gaveUp5 = t.gaveUp5 || gaveUp
		return
	}
	t.gaveUp = t.gaveUp || gaveUp
}

// fields adds the row's keys: how many requests were retried and for how
// long, and whether the source was still refusing at the end.
func (t *throttle) fields(row map[string]any) {
	if n := t.requests.Load(); n > 0 {
		row["requests"] = int(n)
	}
	n, n5 := int(t.retried.Load()), int(t.retried5.Load())
	t.mu.Lock()
	defer t.mu.Unlock()
	if n5 > 0 || t.gaveUp5 {
		if n5 > 0 {
			row["retried_5xx"] = n5
		}
		if t.gaveUp5 {
			row["gave_up_5xx"] = true
		}
	}
	if n > 0 || n5 > 0 {
		row["waited_seconds"] = round(t.waited.Seconds())
	}
	if n == 0 && !t.gaveUp {
		return
	}
	row["rate_limited"] = true
	if n > 0 {
		row["retried_429"] = n
	}
	if t.retryAfter > 0 {
		row["retry_after_seconds"] = round(t.retryAfter.Seconds())
	}
	if t.gaveUp {
		row["gave_up_429"] = true
	}
}

// busy says an answer asks to be tried again: 429, or a server error other
// than the two that say a request can never work (501, 505).
func busy(code int) bool {
	return code == http.StatusTooManyRequests || (code >= 500 && code != http.StatusNotImplemented && code != http.StatusHTTPVersionNotSupported)
}

// retryTransport wraps a RoundTripper to answer 429 as above.
type retryTransport struct {
	next http.RoundTripper
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	th, _ := req.Context().Value(throttleKey{}).(*throttle)
	for attempt := 0; ; attempt++ {
		if th != nil {
			th.requests.Add(1)
		}
		resp, err := t.next.RoundTrip(req)
		if err == nil {
			// Before anything reads the body, a source's own reader included.
			fetch.BoundNote(resp, "source "+req.URL.Host)
		}
		if err != nil || !busy(resp.StatusCode) || (resp.StatusCode != http.StatusTooManyRequests && ownRetries(req.Context())) {
			if err == nil && resp.StatusCode == http.StatusOK {
				screenAnswer(req, resp)
			} else if err == nil && resp.StatusCode >= 400 {
				quoteStatus(req, resp)
			}
			return resp, err
		}
		serverError := resp.StatusCode != http.StatusTooManyRequests
		if th == nil {
			th = &throttle{} // still counted for the decision below
		}
		asked, hinted := retryAfter(resp.Header.Get("Retry-After"))
		wait := asked
		if !hinted {
			wait = firstPause << attempt
		}
		// A body that cannot be sent again, no attempts left, or a wait that
		// is too long or past the source's deadline: hand back the 429.
		replay := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
		tooLong := wait > maxRetryWait
		if dl, ok := req.Context().Deadline(); ok && time.Until(dl) <= wait {
			tooLong = true
		}
		if attempt >= maxRetries || !replay || tooLong || req.Context().Err() != nil {
			th.note(0, asked, true, serverError)
			quoteStatus(req, resp)
			return resp, nil
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(wait):
		}
		if serverError {
			th.retried5.Add(1)
		} else {
			th.retried.Add(1)
		}
		th.note(wait, asked, false, serverError)
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req = req.Clone(req.Context())
			req.Body = body
		}
	}
}

// retryAfter reads a Retry-After header: seconds, or an HTTP date.
func retryAfter(h string) (time.Duration, bool) {
	if h == "" {
		return 0, false
	}
	if s, err := strconv.Atoi(h); err == nil && s >= 0 {
		return time.Duration(s) * time.Second, true
	}
	if at, err := http.ParseTime(h); err == nil {
		return max(time.Until(at), 0), true
	}
	return 0, false
}

func withThrottle(ctx context.Context, t *throttle) context.Context {
	return context.WithValue(ctx, throttleKey{}, t)
}

// quoteStatus keeps the first words of the body of a failed answer for the
// source the request belongs to: subfinder's sources report the status and
// drop the body, which says why ("server busy (64 queries in flight)"). The
// body is still the source's to read, whole.
func quoteStatus(req *http.Request, resp *http.Response) {
	l, _ := req.Context().Value(statusKey{}).(*statusLog)
	if l == nil || resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	prefix, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var rest io.Reader = resp.Body
	if err != nil {
		rest = io.MultiReader(strings.NewReader(""), errReader{err})
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(prefix), rest), resp.Body}
	if w := answer.Words(prefix); w != "" {
		l.add(req.URL.Host, resp.StatusCode, w)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

type statusKey struct{}

// statusLog is the words of the failed answers a source got, by host and status.
type statusLog struct {
	mu    sync.Mutex
	words map[string]string
}

func (l *statusLog) add(host string, code int, words string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.words == nil {
		l.words = map[string]string{}
	}
	l.words[host+" "+strconv.Itoa(code)] = words
}

// statusFromSubfinder is how its sources report a status they did not take.
var statusFromSubfinder = lazyre.New(`unexpected status code (\d{3}) received from (\S+)`)

// withWords says a failed answer in the server's words where the source
// reported only the status: "unexpected status code 503 received from
// https://h/?q=1" becomes "h answered 503: server busy (64 queries in
// flight)". An error whose status has no words, or none, stays as it is.
func withWords(ctx context.Context, err string) string {
	l, _ := ctx.Value(statusKey{}).(*statusLog)
	if l == nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return statusFromSubfinder.ReplaceAllStringFunc(err, func(m string) string {
		sub := statusFromSubfinder.FindStringSubmatch(m)
		u, perr := url.Parse(strings.TrimRight(sub[2], `.,;:)`))
		if perr != nil || u.Host == "" {
			return m
		}
		if w := l.words[u.Host+" "+sub[1]]; w != "" {
			return u.Host + " answered " + sub[1] + ": " + w
		}
		return m
	})
}

type ownRetriesKey struct{}

// withOwnRetries marks requests of a source that asks again a server error
// by itself (crt.sh's JSON API, whose pauses end where the run's wait does):
// the transport leaves its 5xx to the source and still waits out a 429.
func withOwnRetries(ctx context.Context) context.Context {
	return context.WithValue(ctx, ownRetriesKey{}, true)
}

func ownRetries(ctx context.Context) bool {
	own, _ := ctx.Value(ownRetriesKey{}).(bool)
	return own
}

type answerKey struct{}

// answerLog is what Run learns about a source's 200 answers that were
// errors (a quota page, a JSON error): a source that gave no names after
// one has failed, not found nothing.
type answerLog struct {
	mu   sync.Mutex
	what []string
}

func (l *answerLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.what) < 3 {
		l.what = append(l.what, s)
	}
}

func (l *answerLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.what, "; ")
}

// screenAnswer reads the start of a 200 answer and logs it when it is an
// error, for the source the request belongs to. The body is still the
// source's to read, whole.
func screenAnswer(req *http.Request, resp *http.Response) {
	l, _ := req.Context().Value(answerKey{}).(*answerLog)
	if l == nil || resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	body, why := answer.Screen(resp.Body)
	resp.Body = body
	if why != "" {
		l.add(fmt.Sprintf("%s answered 200 with an error, not names: %s", req.URL.Host, why))
	}
}

// answeredWithError is what the source's requests were answered with, when
// an answer was an error page and not data.
func answeredWithError(ctx context.Context) string {
	if l, ok := ctx.Value(answerKey{}).(*answerLog); ok {
		return l.text()
	}
	return ""
}
