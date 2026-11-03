package verify

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
)

// listen serves each connection with fn on a free port of 127.0.0.1 and
// records the exact bytes it was sent.
type fixture struct {
	port int
	sent [][]byte
}

func listen(t *testing.T, fn func(req []byte) []byte) *fixture {
	t.Helper()
	f := &fixture{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				req := append([]byte(nil), buf[:n]...)
				f.sent = append(f.sent, req)
				if resp := fn(req); resp != nil {
					_, _ = c.Write(resp)
				}
			}(c)
		}
	}()
	return f
}

func dial(ctx context.Context, host, ip string, port int) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
}

func runOne(t *testing.T, svc advisory.Service, f *fixture) Result {
	t.Helper()
	svc.Host, svc.IP, svc.Port = "127.0.0.1", "127.0.0.1", f.port
	check, ok := ForService(svc)
	if !ok {
		t.Fatalf("no check for %+v", svc)
	}
	r, err := check.Execute(context.Background(), svc, dial)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRedisUnauthenticatedIsProved(t *testing.T) {
	body := "# Server\r\nredis_version:7.2.0\r\nredis_mode:standalone\r\n"
	f := listen(t, func(req []byte) []byte {
		return []byte(fmt.Sprintf("$%d\r\n%s\r\n", len(body), body))
	})
	r := runOne(t, advisory.Service{Service: "redis", Product: "Redis"}, f)
	if r.Label != Proved {
		t.Fatalf("label %q, want proved: %+v", r.Label, r)
	}
	if r.Request != "INFO server" || len(f.sent) != 1 || string(f.sent[0]) != "INFO server\r\n" {
		t.Fatalf("request %q sent %q, want exactly INFO server", r.Request, f.sent)
	}
	if r.Version != "7.2.0" || !strings.Contains(r.Evidence, "redis_version:7.2.0") {
		t.Fatalf("version/evidence: %+v", r)
	}
	if r.Kind != "unauthenticated-read" || r.Severity != "high" {
		t.Fatalf("kind/severity: %+v", r)
	}
}

func TestRedisAuthRequiredIsVersionOnlyNotProved(t *testing.T) {
	f := listen(t, func(req []byte) []byte { return []byte("-NOAUTH Authentication required.\r\n") })
	r := runOne(t, advisory.Service{Service: "redis", Product: "Redis", Version: "7.2.0"}, f)
	if r.Label != VersionOnly {
		t.Fatalf("label %q, want version-only (never proved): %+v", r.Label, r)
	}
	if !strings.Contains(r.Evidence, "NOAUTH") {
		t.Fatalf("evidence: %+v", r)
	}
}

func TestMemcachedUnauthenticatedIsProved(t *testing.T) {
	f := listen(t, func(req []byte) []byte { return []byte("VERSION 1.6.21\r\n") })
	r := runOne(t, advisory.Service{Service: "memcached", Product: "memcached"}, f)
	if r.Label != Proved || r.Version != "1.6.21" || string(f.sent[0]) != "version\r\n" {
		t.Fatalf("%+v sent %q", r, f.sent)
	}
}

// mongoMsg is one OP_MSG carrying the given BSON document bytes.
func mongoMsg(doc []byte) []byte {
	d := append([]byte(nil), doc...)
	binary.LittleEndian.PutUint32(d, uint32(len(d)))
	msg := make([]byte, 16, 21+len(d))
	binary.LittleEndian.PutUint32(msg[4:], 1)
	binary.LittleEndian.PutUint32(msg[12:], 2013)
	msg = append(msg, 0, 0, 0, 0, 0)
	msg = append(msg, d...)
	binary.LittleEndian.PutUint32(msg, uint32(len(msg)))
	return msg
}

func bsonDoc(elems ...[]byte) []byte {
	doc := []byte{0, 0, 0, 0}
	for _, e := range elems {
		doc = append(doc, e...)
	}
	return append(doc, 0)
}

func bsonStr(name, val string) []byte {
	e := []byte{0x02}
	e = append(e, name+"\x00"...)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(val)+1))
	e = append(e, n[:]...)
	e = append(e, val+"\x00"...)
	return e
}

func bsonBool(name string, v bool) []byte {
	b := byte(0)
	if v {
		b = 1
	}
	return append([]byte{0x08}, append([]byte(name+"\x00"), b)...)
}

func bsonDouble(name string, v float64) []byte {
	e := []byte{0x01}
	e = append(e, name+"\x00"...)
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], math.Float64bits(v))
	return append(e, n[:]...)
}

func TestMongoUnauthenticatedIsProved(t *testing.T) {
	doc := bsonDoc(bsonBool("ismaster", true), bsonStr("version", "7.0.5"), bsonDouble("ok", 1))
	f := listen(t, func(req []byte) []byte { return mongoMsg(doc) })
	r := runOne(t, advisory.Service{Service: "mongodb", Product: "MongoDB"}, f)
	if r.Label != Proved || r.Version != "7.0.5" {
		t.Fatalf("%+v, want proved MongoDB 7.0.5", r)
	}
	if r.Request != "isMaster (OP_MSG, $db admin)" {
		t.Fatalf("request %q", r.Request)
	}
	// The request sent is one OP_MSG isMaster and nothing else.
	if len(f.sent) != 1 || binary.LittleEndian.Uint32(f.sent[0][12:]) != 2013 || !strings.Contains(string(f.sent[0]), "isMaster") {
		t.Fatalf("sent %q", f.sent)
	}
}

func TestMongoAuthRequiredIsNotProved(t *testing.T) {
	doc := bsonDoc(bsonStr("errmsg", "Authentication failed"), bsonDouble("ok", 0))
	f := listen(t, func(req []byte) []byte { return mongoMsg(doc) })
	r := runOne(t, advisory.Service{Service: "mongodb", Product: "MongoDB", Version: "7.0.5"}, f)
	if r.Label == Proved {
		t.Fatalf("authenticated MongoDB labelled proved: %+v", r)
	}
	if r.Label != VersionOnly && r.Label != Conditional {
		t.Fatalf("label %q", r.Label)
	}
}

func TestAdvisoryPreconditionAbsentIsConditional(t *testing.T) {
	// Affected by version, the advisory names a precondition, and the
	// confirmation read states the version but not the precondition:
	// conditional, never proved.
	lead := advisory.Lead{
		AdvisoryID: "CVE-TEST-0002", URL: "https://example.test/CVE-TEST-0002",
		Host: "127.0.0.1", Port: 8080, Target: "127.0.0.1:8080",
		Product: "nginx", VersionSeen: "1.18.0", Label: advisory.LabelConditional,
		Precondition: "only when the example module is enabled",
		Confidence:   advisory.Inferred,
		Read:         "GET /version answered 200; it states version 1.18.0, which settles the version but not the precondition",
	}
	r, ok := AdvisoryResult(lead, "GET /version")
	if !ok || r.Label != Conditional || r.AdvisoryID != "CVE-TEST-0002" {
		t.Fatalf("%+v %v, want conditional CVE-TEST-0002", r, ok)
	}
	// Observed with no precondition settles the version in range: proved.
	lead2 := lead
	lead2.Label, lead2.Precondition, lead2.Confidence = advisory.LabelAffected, "", advisory.Observed
	r, ok = AdvisoryResult(lead2, "GET /")
	if !ok || r.Label != Proved {
		t.Fatalf("%+v %v, want proved", r, ok)
	}
	// A range match alone is version-only.
	lead3 := lead2
	lead3.Confidence = advisory.Claimed
	r, _ = AdvisoryResult(lead3, "")
	if r.Label != VersionOnly {
		t.Fatalf("%+v, want version-only", r)
	}
	// Not affected is no result at all.
	lead4 := lead2
	lead4.Label = advisory.LabelNotAffected
	if _, ok := AdvisoryResult(lead4, ""); ok {
		t.Fatal("a not-affected lead produced a result")
	}
}

func TestChecksEnumeratePreconditions(t *testing.T) {
	checks := Checks()
	if len(checks) < 3 {
		t.Fatalf("checks %v", checks)
	}
	for _, c := range checks {
		if c.ID == "" || c.Request == "" || c.Precondition == "" {
			t.Errorf("check %+v does not print its precondition and exact request", c)
		}
	}
}
