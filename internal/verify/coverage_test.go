package verify

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// Every TCP service the scan names has a check or a stated reason it has
// none, and no service has both.
func TestEveryIdentifiedServiceHasACheckOrAReason(t *testing.T) {
	identified := portscan.IdentifiedServices()
	for _, name := range identified {
		_, has := ForService(advisory.Service{Service: name, Proto: "tcp"})
		reason, none := NoCheck[name]
		switch {
		case has && none:
			t.Errorf("%s has a check and a reason for none", name)
		case !has && !none:
			t.Errorf("%s is identified by the scan and has neither a verify check nor an entry of NoCheck with its reason", name)
		case none && strings.TrimSpace(reason) == "":
			t.Errorf("%s is in NoCheck with no reason", name)
		}
	}
	for name := range NoCheck {
		if !slices.Contains(identified, name) {
			t.Errorf("NoCheck lists %s, which the scan does not name", name)
		}
	}
	for _, c := range Checks() {
		if !slices.Contains(identified, c.Service) {
			t.Errorf("%s: %s is not a service the scan names", c.ID, c.Service)
		}
	}
}

// A check is one fixed request: its ID and its service are unique, it prints
// the request and its precondition, and the request it sends has no
// credential in it.
func TestChecksAreFixedAndCarryNoCredential(t *testing.T) {
	ids, svcs := map[string]bool{}, map[string]bool{}
	for _, c := range Checks() {
		if ids[c.ID] || svcs[c.Service] {
			t.Errorf("%s: id or service used twice", c.ID)
		}
		ids[c.ID], svcs[c.Service] = true, true
		if c.Request == "" || c.Precondition == "" {
			t.Errorf("%s prints no request or precondition", c.ID)
		}
		req, parse := c.prepare(advisory.Service{Host: "h.example", Port: 1})
		if len(req) == 0 || parse == nil {
			t.Errorf("%s builds no request", c.ID)
		}
		low := strings.ToLower(string(req))
		for _, bad := range []string{"password", "passwd", "auth ", "login", "user:", "pass:", "authorization", "set ", "put ", "delete", "flushall", "config "} {
			if strings.Contains(low, bad) {
				t.Errorf("%s sends %q, which looks like a credential or a write", c.ID, bad)
			}
		}
	}
}

// Whatever a service answers that is not its protocol's answer is conditional
// and never proved, for every check.
func TestEveryCheckLabelsAForeignAnswerConditional(t *testing.T) {
	for _, c := range Checks() {
		f := listen(t, func([]byte) []byte { return []byte("HTTP/1.1 400 Bad Request\r\n\r\n") })
		svc := advisory.Service{Service: c.Service, Host: "127.0.0.1", IP: "127.0.0.1", Port: f.port}
		r, err := c.Execute(context.Background(), svc, dial)
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		if r.Label != Conditional || r.Precondition == "" {
			t.Errorf("%s: a foreign answer is %q: %+v", c.ID, r.Label, r)
		}
	}
}

// Each check sends its request once, on one connection, as the scan's
// identification sends it to a port that waits.
func TestProbeChecksSendWhatTheScanSends(t *testing.T) {
	for _, c := range Checks() {
		if c.ID == "redis-info" || c.ID == "mongodb-isMaster" || c.ID == "memcached-version" {
			continue
		}
		f := listen(t, func([]byte) []byte { return nil })
		svc := advisory.Service{Service: c.Service, Host: "127.0.0.1", IP: "127.0.0.1", Port: f.port}
		_, _ = c.Execute(context.Background(), svc, dial)
		pr, ok := portscan.ProbeFor(c.Service, "127.0.0.1", f.port)
		if !ok {
			t.Errorf("%s: the scan has no request for %s", c.ID, c.Service)
			continue
		}
		sent := f.requests()
		if len(sent) != 1 {
			t.Errorf("%s: %d requests sent", c.ID, len(sent))
			continue
		}
		if c.Service == "dns" || c.Service == "smb" { // a random id or nonce
			if len(sent[0]) != len(pr.Request) {
				t.Errorf("%s: sent %d bytes, want %d", c.ID, len(sent[0]), len(pr.Request))
			}
			continue
		}
		if string(sent[0]) != string(pr.Request) {
			t.Errorf("%s: sent %q, the scan sends %q", c.ID, sent[0], pr.Request)
		}
	}
}

func hexFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "portscan", "testdata", name+".hex"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// What a service answers is labelled by what it says: proved for an answer
// that came with no credential, declined (no label) for one that asks for it
// and states no version; a read ranks info: it showed a version or a banner.
func TestProbeChecksLabelTheAnswers(t *testing.T) {
	const declined = ""
	for _, tt := range []struct {
		service  string
		answer   []byte
		label    string
		severity string
		version  string
	}{
		{"zookeeper", []byte("Zookeeper version: 3.9.2-abc, built on 2024\nLatency min/avg/max: 0/0/0\n"), Proved, "info", ""},
		{"postgresql", hexFixture(t, "postgres"), Proved, "info", "14 - 17"},
		{"smb", hexFixture(t, "smb"), Proved, "info", ""},
		{"ldap", hexFixture(t, "ldap"), Proved, "info", ""},
		{"amqp", hexFixture(t, "amqp"), Proved, "info", "3.13.7"},
		{"mqtt", []byte{0x20, 2, 0, 0}, Proved, "info", ""},
		{"mqtt", []byte{0x20, 2, 0, 5}, declined, "", ""},
		{"stomp", []byte("CONNECTED\nversion:1.2\nserver:ActiveMQ/5.18.3\n\n\x00"), Proved, "info", "5.18.3"},
		{"stomp", []byte("ERROR\nmessage:Authentication failed\n\n\x00"), declined, "", ""},
		{"socks5", []byte{5, 0}, Proved, "info", ""},
		{"socks5", []byte{5, 0xff}, declined, "", ""},
		{"jdwp", []byte("JDWP-Handshake"), Proved, "info", ""},
		{"rtsp", []byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"), Proved, "info", ""},
		{"rtsp", []byte("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n"), declined, "", ""},
		{"sip", []byte("SIP/2.0 200 OK\r\nServer: Asterisk PBX 20.5.0\r\n\r\n"), Proved, "info", ""},
		{"sip", []byte("SIP/2.0 401 Unauthorized\r\n\r\n"), declined, "", ""},
	} {
		f := listen(t, func([]byte) []byte { return tt.answer })
		svc := advisory.Service{Service: tt.service, Host: "127.0.0.1", IP: "127.0.0.1", Port: f.port}
		c, ok := ForService(svc)
		if !ok {
			t.Fatalf("no check for %s", tt.service)
		}
		r, err := c.Execute(context.Background(), svc, dial)
		if err != nil {
			t.Errorf("%s: %v", tt.service, err)
			continue
		}
		if r.Label != tt.label || r.Severity != tt.severity || (tt.version != "" && !strings.HasPrefix(r.Version, tt.version)) {
			t.Errorf("%s: %+v, want %s %s %s", tt.service, r, tt.label, tt.severity, tt.version)
		}
		if r.Declined != (tt.label == declined) {
			t.Errorf("%s: declined %v for label %q", tt.service, r.Declined, tt.label)
		}
		if r.Request != c.Request || r.Evidence == "" {
			t.Errorf("%s: a result carries the request and the evidence: %+v", tt.service, r)
		}
	}
}

// A service seen over UDP has no TCP check.
func TestUDPServiceHasNoCheck(t *testing.T) {
	if _, ok := ForService(advisory.Service{Service: "memcached", Proto: "udp"}); ok {
		t.Error("a UDP service got a TCP check")
	}
}

// A default scan asks the usual ports of every service a check reads.
func TestDefaultPortsHoldThePortsOfEveryCheckedService(t *testing.T) {
	def := portscan.DefaultPorts()
	for _, c := range Checks() {
		ports := portscan.ProtocolPorts(c.Service)
		if len(ports) == 0 {
			t.Errorf("%s: the scan has no usual port for %s", c.ID, c.Service)
		}
		for _, q := range ports {
			if !slices.Contains(def, q) {
				t.Errorf("the default set lacks %d, a port of %s, which -verify checks", q, c.Service)
			}
		}
	}
}

// The docs list every service with no check, with the reason the code gives.
func TestDocsListTheServicesWithNoCheck(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "CONCEPTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for name, reason := range NoCheck {
		if !strings.Contains(doc, "| `"+name+"` | "+reason+" |") {
			t.Errorf("docs/CONCEPTS.md does not list %s with its reason: %s", name, reason)
		}
	}
}
