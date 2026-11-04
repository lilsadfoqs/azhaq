package notify

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// Each message goes to every entry of every provider, in notify's order,
// whatever order the file lists them in.
func TestMessagesGoToEveryEntryOfEveryProviderInNotifysOrder(t *testing.T) {
	s := newStub(t)
	s.reply = func(n int, r *seen) (int, map[string]string, string) {
		if strings.Contains(r.Path, "workflows") {
			return 202, nil, ""
		}
		return 200, nil, "ok"
	}
	sink := newSMTPSink(t)
	g1, g2, owner := "11111111-2222-4333-8444-555555555555", "66666666-7777-4888-9999-000000000000", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	cfg := fmt.Sprintf(`
gotify:
  - id: g1
    gotify_host: gotify.test
    gotify_token: gtfyaMODERNTOKEN
    gotify_disabletls: true
  - id: g2
    gotify_host: gotify2.test
    gotify_token: gtfyaMODERNTOKEN
    gotify_disabletls: true
custom:
  - id: c1
    custom_webhook_url: http://hook.test/c1
    custom_method: POST
  - id: c2
    custom_webhook_url: http://hook.test/c2
    custom_method: POST
telegram:
  - id: t1
    telegram_api_key: "1:abc"
    telegram_chat_id: "1"
teams:
  - id: tm1
    teams_webhook_url: https://contoso.webhook.office.com/webhookb2/%s@%s/IncomingWebhook/%s/%s
smtp:
  - id: m1
    smtp_server: %s
    from_address: f@x.test
    smtp_cc: [t@x.test]
googlechat:
  - id: gc1
    space: S
    key: K1
    token: T1
pushover:
  - id: p1
    pushover_user_key: UKEY123
    pushover_api_token: ATOKEN456
discord:
  - id: d1
    discord_webhook_url: https://discord.com/api/webhooks/123456789012345678/%s
slack:
  - id: s1
    slack_webhook_url: https://hooks.slack.com/services/T/B/X
`, g1, g2, strings.Repeat("a1", 16), owner, sink.ln.Addr(), strings.Repeat("a", 68))
	ds := run(t, s, cfg, "", nil, nil, "one message")
	var got []string
	for _, d := range ds {
		got = append(got, d.Provider+"/"+d.ID)
	}
	want := "slack/s1 discord/d1 pushover/p1 googlechat/gc1 smtp/m1 teams/tm1 telegram/t1 custom/c1 custom/c2 gotify/g1 gotify/g2"
	if strings.Join(got, " ") != want {
		t.Errorf("deliveries in the order %v, want %s", got, want)
	}
	var hosts []string
	for _, r := range s.got() {
		hosts = append(hosts, r.Host)
	}
	wantHosts := "hooks.slack.com discord.com api.pushover.net chat.googleapis.com contoso.webhook.office.com api.telegram.org hook.test hook.test gotify.test gotify2.test"
	if strings.Join(hosts, " ") != wantHosts {
		t.Errorf("requests to %v, want %s", hosts, wantHosts)
	}
	select {
	case <-sink.mails:
	default:
		t.Error("the smtp entry sent no mail")
	}
}

// starttlsSink is a mail server that offers STARTTLS and says whether it was asked.
func starttlsSink(t *testing.T) (addr string, asked func() bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	was := false
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				fmt.Fprint(c, "220 sink\r\n")
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
					case strings.HasPrefix(cmd, "EHLO"):
						fmt.Fprint(c, "250-sink\r\n250 STARTTLS\r\n")
					case cmd == "STARTTLS":
						mu.Lock()
						was = true
						mu.Unlock()
						return // the handshake that follows finds nothing: the attempt is the point
					case cmd == "QUIT":
						fmt.Fprint(c, "221 bye\r\n")
						return
					default:
						fmt.Fprint(c, "250 ok\r\n")
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), func() bool { mu.Lock(); defer mu.Unlock(); return was }
}

// STARTTLS is used when the server offers it and smtp_disable_starttls is
// not set.
func TestSMTPUsesSTARTTLSWhenTheServerOffersItUnlessDisabled(t *testing.T) {
	for _, c := range []struct {
		disable bool
		tried   bool
	}{{false, true}, {true, false}} {
		addr, asked := starttlsSink(t)
		pc, err := ParseConfig(strings.NewReader(fmt.Sprintf("smtp:\n  - smtp_server: %s\n    from_address: f@x.test\n    smtp_cc: [t@x.test]\n    smtp_disable_starttls: %v\n", addr, c.disable)), "t")
		if err != nil {
			t.Fatal(err)
		}
		set, _ := NewSet(pc, nil, nil, "", &Env{Client: &Client{}})
		d := set.Send(context.Background(), "x")
		if asked() != c.tried {
			t.Errorf("smtp_disable_starttls %v: the server was asked for STARTTLS: %v, want %v (%v)", c.disable, asked(), c.tried, d[0].Err)
		}
		if c.tried && (d[0].Err == nil || !strings.Contains(d[0].Err.Error(), "STARTTLS")) {
			t.Errorf("an offer that was taken and failed is not said: %v", d[0].Err)
		}
	}
	// A server that does not offer it is used in the clear: the sink of the other tests.
	sink := newSMTPSink(t)
	pc, _ := ParseConfig(strings.NewReader(fmt.Sprintf("smtp:\n  - smtp_server: %s\n    from_address: f@x.test\n    smtp_cc: [t@x.test]\n", sink.ln.Addr())), "t")
	set, _ := NewSet(pc, nil, nil, "", &Env{Client: &Client{}})
	if d := set.Send(context.Background(), "x"); d[0].Err != nil {
		t.Errorf("no STARTTLS offered: %v", d[0].Err)
	}
}

// At most three embeds go to a post, 2,000 characters to an embed, and
// more posts take more text.
func TestDiscordPostsHoldAtMostThreeEmbedsOfTwoThousandCharacters(t *testing.T) {
	s := newStub(t)
	id, tok := "123456789012345678", strings.Repeat("a", 68)
	run(t, s, "discord:\n  - discord_webhook_url: https://discord.com/api/webhooks/"+id+"/"+tok+"\n", "", nil, nil, strings.Repeat("word ", 5000)) // 25,000 characters
	posts := s.got()
	if len(posts) < 4 {
		t.Fatalf("%d posts for 25,000 characters: more text must take more posts", len(posts))
	}
	embeds := 0
	for _, r := range posts {
		emb := jsonOf(t, r.Body)["embeds"].([]any)
		if len(emb) > 3 {
			t.Errorf("a post holds %d embeds", len(emb))
		}
		for _, e := range emb {
			embeds++
			if n := len([]rune(e.(map[string]any)["description"].(string))); n > 2000 {
				t.Errorf("an embed of %d characters", n)
			}
		}
	}
	if embeds < 12 {
		t.Errorf("%d embeds hold 25,000 characters?", embeds)
	}
}

// A custom answer of 300 or more is a failure; a 2xx is not.
func TestCustomAnswerOfThreeHundredOrMoreIsAFailure(t *testing.T) {
	for status, fails := range map[int]bool{200: false, 204: false, 299: false, 300: true, 302: true, 400: true, 404: true, 500: true} {
		s := newStub(t)
		s.reply = func(int, *seen) (int, map[string]string, string) { return status, nil, "" }
		pc, _ := ParseConfig(strings.NewReader("custom:\n  - id: c\n    custom_webhook_url: http://hook.test/x\n    custom_method: POST\n"), "t")
		set, _ := NewSet(pc, nil, nil, "", &Env{Client: s.client()})
		if d := set.Send(context.Background(), "x"); (d[0].Err != nil) != fails {
			t.Errorf("an answer of %d: error %v, want a failure: %v", status, d[0].Err, fails)
		}
	}
}

// deadlineTransport notes the deadline and the time of each request and
// answers it with what reply says (a status, or an error for status 0).
type deadlineTransport struct {
	mu        sync.Mutex
	deadlines []time.Duration
	at        []time.Time
	reply     func(n int) (int, http.Header, error)
}

func (d *deadlineTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	d.mu.Lock()
	if dl, ok := r.Context().Deadline(); ok {
		d.deadlines = append(d.deadlines, time.Until(dl))
	}
	d.at = append(d.at, time.Now())
	n := len(d.at)
	d.mu.Unlock()
	status, h, err := d.reply(n)
	if err != nil {
		return nil, err
	}
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d x", status), Header: h, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

func clientOver(d *deadlineTransport) *Client {
	return &Client{HTTP: &http.Client{Transport: d}}
}

// Every request has 30 seconds.
func TestEveryRequestHasThirtySeconds(t *testing.T) {
	d := &deadlineTransport{reply: func(int) (int, http.Header, error) { return 200, nil, nil }}
	if err := clientOver(d).Send(context.Background(), "https://example.test/hook", "hi", nil); err != nil {
		t.Fatal(err)
	}
	if len(d.deadlines) != 1 || d.deadlines[0] < 29*time.Second || d.deadlines[0] > 30*time.Second {
		t.Errorf("the deadline of the request is %v away, want 30s", d.deadlines)
	}
}

// A 429, a 5xx or a failed connection is tried again, up to three times; the
// wait is 1 and 2 seconds; any other 4xx is not tried again.
func TestRetriesAreThreeWithOneAndTwoSecondsBetween(t *testing.T) {
	d := &deadlineTransport{reply: func(int) (int, http.Header, error) { return 429, nil, nil }}
	err := clientOver(d).Send(context.Background(), "https://example.test/hook", "hi", nil)
	if err == nil || len(d.at) != 3 || !strings.Contains(err.Error(), "after 3 tries") {
		t.Fatalf("a 429: %d tries, error %v, want 3 tries", len(d.at), err)
	}
	if g1, g2 := d.at[1].Sub(d.at[0]), d.at[2].Sub(d.at[1]); g1 < 900*time.Millisecond || g1 > 1500*time.Millisecond || g2 < 1900*time.Millisecond || g2 > 2600*time.Millisecond {
		t.Errorf("waited %v then %v, want 1s then 2s", g1, g2)
	}
	for name, reply := range map[string]func(int) (int, http.Header, error){
		"a 503":               func(int) (int, http.Header, error) { return 503, nil, nil },
		"a failed connection": func(int) (int, http.Header, error) { return 0, nil, io.ErrUnexpectedEOF },
	} {
		d := &deadlineTransport{reply: reply}
		c := clientOver(d)
		c.Backoff = time.Millisecond
		if err := c.Send(context.Background(), "https://example.test/hook", "hi", nil); err == nil || len(d.at) != 3 {
			t.Errorf("%s: %d tries, error %v, want 3 tries", name, len(d.at), err)
		}
	}
	for _, status := range []int{400, 401, 403, 404, 410, 422} {
		d := &deadlineTransport{reply: func(int) (int, http.Header, error) { return status, nil, nil }}
		if err := clientOver(d).Send(context.Background(), "https://example.test/hook", "hi", nil); err == nil || len(d.at) != 1 {
			t.Errorf("%d: %d tries, error %v, want 1 try and a failure", status, len(d.at), err)
		}
	}
	d = &deadlineTransport{reply: func(n int) (int, http.Header, error) {
		if n < 3 {
			return 429, http.Header{"Retry-After": {"0.01"}}, nil
		}
		return 200, nil, nil
	}}
	if err := clientOver(d).Send(context.Background(), "https://example.test/hook", "hi", nil); err != nil || len(d.at) != 3 {
		t.Errorf("a 429 twice, then 200: %d tries, %v", len(d.at), err)
	}
}

// A Retry-After of up to a minute is waited out (seconds or a date); a longer one is reported.
func TestRetryAfterIsHonouredUpToAMinute(t *testing.T) {
	for _, c := range []struct {
		after  string
		waited bool
	}{{"59", true}, {"61", false}, {time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat), true}, {time.Now().Add(2 * time.Minute).UTC().Format(http.TimeFormat), false}} {
		d := &deadlineTransport{reply: func(int) (int, http.Header, error) { return 429, http.Header{"Retry-After": {c.after}}, nil }}
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		err := clientOver(d).Send(ctx, "https://example.test/hook", "hi", nil)
		cancel()
		reported := err != nil && strings.Contains(err.Error(), "is longer than the 1m0s waited")
		if reported == c.waited || len(d.at) != 1 {
			t.Errorf("Retry-After %s: %d tries, error %v: want it %s", c.after, len(d.at), err, map[bool]string{true: "waited out", false: "reported, not waited"}[c.waited])
		}
	}
}

// A redirect to another host is not followed (the token would go with it);
// one to the same host is.
func TestRedirectToAnotherHostIsNotFollowed(t *testing.T) {
	var elsewhere, here int
	var mu sync.Mutex
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); elsewhere++; mu.Unlock() }))
	t.Cleanup(other.Close)
	otherPort := strings.Split(other.URL, ":")[2]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, "http://localhost:"+otherPort+"/x", http.StatusTemporaryRedirect)
		case "/same":
			http.Redirect(w, r, "/landed", http.StatusTemporaryRedirect)
		case "/landed":
			mu.Lock()
			here++
			mu.Unlock()
		}
	}))
	t.Cleanup(srv.Close)
	c := &Client{}
	if err := c.Send(context.Background(), srv.URL+"/away", "hi", nil); err == nil {
		t.Error("a redirect to another host was taken as a success")
	}
	if err := c.Send(context.Background(), srv.URL+"/same", "hi", nil); err != nil {
		t.Errorf("a redirect to the same host: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if elsewhere != 0 || here != 1 {
		t.Errorf("the other host got %d requests, the landing page %d: want 0 and 1", elsewhere, here)
	}
}

// connectProxy is an HTTP proxy that tunnels CONNECT to the address it is asked for.
func connectProxy(t *testing.T) (url string, connects func() int) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", 400)
			return
		}
		mu.Lock()
		n++
		mu.Unlock()
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { io.Copy(up, conn); up.Close() }()
		io.Copy(conn, up)
		conn.Close()
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// Certificates are verified, also through -proxy.
func TestCertificatesAreVerifiedAlsoThroughAProxy(t *testing.T) {
	served := 0
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); served++; mu.Unlock() }))
	t.Cleanup(srv.Close)
	proxy, connects := connectProxy(t)
	for name, proxyURL := range map[string]string{"direct": "", "through a proxy": proxy} {
		c, err := NewClient(0, proxyURL)
		if err != nil {
			t.Fatal(err)
		}
		c.Tries = 1
		err = c.Send(context.Background(), srv.URL+"/hook", "hi", nil)
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Errorf("%s: the self-signed certificate was taken: %v", name, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if served != 0 {
		t.Errorf("the server answered %d requests: the handshake must have failed first", served)
	}
	if connects() != 1 {
		t.Errorf("the proxy tunnelled %d connections, want the 1 of the proxied run", connects())
	}
	_ = tls.VersionTLS12
}

// An SMTP delivery is one tcp line in the ledger, to the mail server, for all its recipients.
func TestSMTPDeliveryIsOneTCPLineInTheLedger(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	t.Cleanup(func() { ledger.Use(nil) })
	sink := newSMTPSink(t)
	pc, _ := ParseConfig(strings.NewReader(fmt.Sprintf("smtp:\n  - smtp_server: %s\n    from_address: f@x.test\n    smtp_cc: [a@x.test, b@x.test, c@x.test]\n", sink.ln.Addr())), "t")
	set, _ := NewSet(pc, nil, nil, "", &Env{Client: &Client{}})
	if d := set.Send(context.Background(), "x"); d[0].Err != nil {
		t.Fatal(d[0].Err)
	}
	l.Close()
	var lines []string
	_ = ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind != "seal" {
			lines = append(lines, e.Kind+"/"+e.Class+" "+e.Target)
		}
		return nil
	})
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "tcp/source ") || !strings.Contains(lines[0], sink.ln.Addr().String()) {
		t.Errorf("ledger lines %v, want one tcp line to the mail server", lines)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

// -rl 0 is no pace; any other number is the most requests a second, whatever the provider.
func TestNewClientPaceIsTheRateGiven(t *testing.T) {
	if c, _ := NewClient(0, ""); c.Rate != nil {
		t.Error("a rate of 0 must be no pace")
	}
	if c, _ := NewClient(2, ""); c.Rate == nil || float64(c.Rate.Limit()) != 2 {
		t.Errorf("a rate of 2: %+v", c.Rate)
	}
}
