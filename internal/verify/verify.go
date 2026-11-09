// Package verify turns what a service already exposes into labelled
// results. Behind -verify, each enumerated check sends only what a
// client with no credentials would send to read information the
// service already gives anyone: a protocol info or hello command, or
// the one benign read an advisory names. Never a payload, never a
// write or state-changing command, never a credential or a guessed
// password, never a request that tries to trigger a flaw.
//
// Every result is labelled exactly one of proved, version-only or
// conditional, and carries the exact request sent and an excerpt of
// the response as its evidence:
//
//   - proved: the read answered with no credential, or an advisory's
//     version and named precondition were both settled by the read.
//     Proved names that read, not exploitability, which is never tested.
//   - version-only: only the product and version identification stands
//     (the service asked for authentication, or no confirmation read
//     settled more); no unauthenticated read is claimed.
//   - conditional: the result depends on a precondition the read did
//     not show, which the result names.
package verify

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// Labels of a verification result.
const (
	Proved      = "proved"
	VersionOnly = "version-only"
	Conditional = "conditional"
)

// Kinds of result.
const (
	KindUnauthenticatedRead = "unauthenticated-read"
	KindAdvisoryPrecond     = "advisory-precondition"
)

// Result is one labelled verification result, stored as one
// observation and printed as one row.
type Result struct {
	Kind         string `json:"kind"`
	Label        string `json:"label"` // proved, version-only or conditional
	Severity     string `json:"severity"`
	Host         string `json:"host"`
	Port         int    `json:"port,omitempty"`
	Target       string `json:"target"`
	URL          string `json:"url,omitempty"`
	Service      string `json:"service,omitempty"`
	Product      string `json:"product,omitempty"`
	Version      string `json:"version,omitempty"`
	AdvisoryID   string `json:"advisory_id,omitempty"`
	AdvisoryURL  string `json:"advisory_url,omitempty"`
	Precondition string `json:"precondition,omitempty"`
	Request      string `json:"request"`
	Evidence     string `json:"evidence"`
	Command      string `json:"command,omitempty"`
}

// Line is the result as one line of text output.
func (r Result) Line() string {
	s := fmt.Sprintf("verify: %s %s on %s", r.Label, r.Kind, r.Target)
	if r.Product != "" {
		s += " (" + r.Product
		if r.Version != "" {
			s += " " + r.Version
		}
		s += ")"
	}
	if r.AdvisoryID != "" {
		s += " — " + r.AdvisoryID
	}
	if r.Precondition != "" {
		s += "; precondition: " + r.Precondition
	}
	s += "; request: " + r.Request + "; evidence: " + r.Evidence
	return s
}

// Check is one enumerated verification: the exact request it sends
// and the precondition it prints in plan and in the docs. Only the
// checks listed by Checks exist; there is no way to name another
// request.
type Check struct {
	ID           string `json:"id"`
	Service      string `json:"service"`
	Request      string `json:"request"` // as printed: the exact bytes, escapes shown
	Precondition string `json:"precondition"`

	// High: the read shows the state of a data store, so a proved result
	// ranks high; any other proved read is info.
	High bool `json:"high,omitempty"`

	// prepare is the request for svc and the reader of its answer.
	prepare func(svc advisory.Service) (req []byte, parse func(resp []byte, r *Result))
}

// Checks lists every verification, in the order they run.
func Checks() []Check { return append([]Check(nil), checks...) }

// fixed is a prepare for a check whose request does not depend on the
// service.
func fixed(req func() []byte, parse func(resp []byte, svc advisory.Service, r *Result)) func(advisory.Service) ([]byte, func([]byte, *Result)) {
	return func(svc advisory.Service) ([]byte, func([]byte, *Result)) {
		return req(), func(resp []byte, r *Result) { parse(resp, svc, r) }
	}
}

var checks = []Check{
	{
		ID: "redis-info", Service: "redis", Request: "INFO server", High: true,
		Precondition: "the service answers INFO server, a read of what it already exposes, with no credential sent",
		prepare:      fixed(func() []byte { return []byte("INFO server\r\n") }, parseRedis),
	},
	{
		ID: "mongodb-isMaster", Service: "mongodb", Request: "isMaster (OP_MSG, $db admin)", High: true,
		Precondition: "the service answers isMaster, its hello, with no credential sent",
		prepare:      fixed(func() []byte { return mongoCommand("isMaster") }, parseMongo),
	},
	{
		ID: "memcached-version", Service: "memcached", Request: "version", High: true,
		Precondition: "the service answers version, a read of what it already exposes, with no credential sent",
		prepare:      fixed(func() []byte { return []byte("version\r\n") }, parseMemcached),
	},
	probeCheck("zookeeper-srvr", "zookeeper", "srvr (the four-letter command)", "its own state command srvr", true, nil),
	probeCheck("postgresql-startup", "postgresql", "a StartupMessage of protocol version 1.0 with no user", "a startup message of a protocol version that does not exist, whose error names the versions it speaks", false, nil),
	probeCheck("kafka-apiversions", "kafka", "ApiVersions v0", "ApiVersions, the first request of every client", false, nil),
	probeCheck("mssql-prelogin", "mssql", "a TDS PRELOGIN", "a TDS prelogin, the first packet of every client, whose answer holds the version", false, nil),
	probeCheck("cassandra-options", "cassandra", "an OPTIONS frame (CQL native protocol v4)", "OPTIONS, which lists what the server supports", false, nil),
	probeCheck("oracle-tns-ping", "oracle-tns", "a TNS Connect with (COMMAND=ping)", "the listener ping tnsping sends, whose answer holds the version", false, nil),
	probeCheck("ldap-rootdse", "ldap", "an anonymous search of the root DSE, no bind", "an anonymous search of the root DSE, which RFC 4512 has every server answer", false, nil),
	probeCheck("dns-version-bind", "dns", "version.bind CHAOS TXT, length-prefixed over TCP", "a CHAOS TXT query for version.bind", false, nil),
	probeCheck("rtsp-options", "rtsp", "OPTIONS * RTSP/1.0", "OPTIONS, which lists the methods it supports", false, refusedStatus),
	probeCheck("sip-options", "sip", "an OPTIONS request over TCP", "OPTIONS, which a SIP server answers with what it supports", false, refusedStatus),
	probeCheck("socks5-methods", "socks5", "the method selection: version 5, one method, no authentication", "the method selection, which names the method it accepts", false, refusedSocks),
	probeCheck("smb-negotiate", "smb", "an SMB2 NEGOTIATE, no session", "a NEGOTIATE, which lists the dialect and the signing it requires", false, nil),
	probeCheck("netbios-ssn-request", "netbios-ssn", "a NetBIOS session request to *SMBSERVER", "a session request, which the service answers positively or not", false, nil),
	probeCheck("rdp-x224", "rdp", "an X.224 connection request with a negotiation request", "the X.224 connection request, which names the protocol it selects", false, nil),
	probeCheck("x11-setup", "x11", "a connection setup with no authorization", "a connection setup, which an X server answers with its vendor and release, or with a refusal", false, refusedX11),
	probeCheck("jdwp-handshake", "jdwp", "JDWP-Handshake", "the handshake, which a debug port answers with itself", false, nil),
	probeCheck("java-rmi-header", "java-rmi", "the stream header JRMI, version 2, StreamProtocol", "the stream header, which a registry acknowledges", false, nil),
	probeCheck("elasticsearch-transport-ping", "elasticsearch-transport", "the keep-alive ping (ES and a length of -1)", "the keep-alive ping, which a node of 7.x or later returns", false, nil),
	probeCheck("afp-getstatus", "afp", "a DSI GetStatus, no login", "DSIGetStatus, which an AFP server answers before any login", false, nil),
	probeCheck("minecraft-status", "minecraft", "a handshake and a status request (Server List Ping)", "the status request every game client sends to list a server", false, nil),
	probeCheck("mqtt-connect", "mqtt", "a CONNECT without user name or password", "a CONNECT, which the broker accepts or refuses in its CONNACK", false, refusedMQTT),
	probeCheck("amqp-header", "amqp", "the protocol header AMQP 0-9-1", "the protocol header, which a broker answers with its Connection.Start", false, nil),
	probeCheck("stomp-connect", "stomp", "a CONNECT frame without credentials", "a CONNECT, which the broker accepts or refuses", false, refusedSTOMP),
	probeCheck("xmpp-stream", "xmpp", "the opening of a stream", "the opening of a stream, which a server answers with its own", false, nil),
}

// probeCheck is a check whose request and reader are the identification's
// own for the protocol (portscan.ProbeFor): it sends nothing the scan does
// not already send to a port that waits. refused says an answer is the
// service asking for a credential, which stands as version-only.
func probeCheck(id, service, request, what string, high bool, refused func(resp []byte) bool) Check {
	return Check{
		ID: id, Service: service, Request: request, High: high,
		Precondition: "the service answers " + what + " with no credential sent",
		prepare: func(svc advisory.Service) ([]byte, func([]byte, *Result)) {
			host := firstNonEmpty(svc.Host, svc.IP)
			pr, ok := portscan.ProbeFor(service, host, svc.Port)
			if !ok {
				return nil, nil
			}
			return pr.Request, func(resp []byte, r *Result) {
				a, ok := pr.Read(resp)
				switch {
				case !ok:
					r.Label = Conditional
					r.Precondition = "the answer is not a " + service + " answer the check can read"
				case refused != nil && refused(resp):
					r.Label = VersionOnly
				default:
					r.Label = Proved
					if svc.Product == "" && a.Product != "" {
						r.Product = a.Product
					}
					if a.Version != "" {
						r.Version = a.Version
					}
				}
			}
		},
	}
}

// refusedStatus: an RTSP or SIP status line that asks for a credential.
func refusedStatus(resp []byte) bool {
	f := strings.Fields(string(resp))
	return len(f) > 1 && (f[1] == "401" || f[1] == "403" || f[1] == "407")
}

func refusedSocks(resp []byte) bool { return len(resp) == 2 && resp[1] == 0xff }

func refusedMQTT(resp []byte) bool { return len(resp) >= 4 && resp[3] != 0 }

func refusedSTOMP(resp []byte) bool { return bytes.HasPrefix(resp, []byte("ERROR")) }

// refusedX11: a setup the server refused (0) or wants authorization for (2).
func refusedX11(resp []byte) bool { return len(resp) > 0 && resp[0] != 1 }

// byService maps the name a scan gives a service to its check.
var byService = func() map[string]int {
	m := map[string]int{}
	for i, c := range checks {
		m[c.Service] = i
	}
	m["mongo"] = m["mongodb"]
	return m
}()

// ForService is the check for a confirmed TCP service, by the service or
// product the scan named. A service seen over UDP has none: the scan's own
// datagram is its read.
func ForService(svc advisory.Service) (Check, bool) {
	if svc.Proto == "udp" {
		return Check{}, false
	}
	name := strings.ToLower(strings.TrimSuffix(firstNonEmpty(svc.Service, svc.Product), "?"))
	if i, ok := byService[name]; ok {
		return checks[i], true
	}
	return Check{}, false
}

// NoCheck lists every TCP service a scan names that has no check, with the
// reason it has none. Every service the scan names is in Checks or here
// (a test holds that), so no service is left out unsaid.
var NoCheck = map[string]string{
	"ssh":         "states its software and version in its first line, which the scan reads: there is no further no-credential read",
	"ftp":         "states its software in its greeting, which the scan reads; SYST and FEAT are asked only by -detect all, where the greeting names no product",
	"smtp":        "states its software in its greeting, which the scan reads; its commands after it (EHLO, HELP) add a capability list, not a version",
	"ftp-or-smtp": "only a 220 greeting that names neither: there is nothing to read that the greeting did not say",
	"pop3":        "states its software in its greeting, which the scan reads",
	"imap":        "states its software in its greeting, which the scan reads",
	"mysql":       "states its server version in its first packet, which the scan reads; any request after it is a login",
	"telnet":      "opens with its option negotiation, which the scan reads; the next thing it wants is a login",
	"vnc":         "states its protocol version in its first line, which the scan reads; the next message is a security handshake",
	"irc":         "opens with its notice, which the scan reads; its version is read after a registration with a nick",
	"nntp":        "states its software in its greeting, which the scan reads",
	"sieve":       "sends its capability list, with its implementation, on connect, which the scan reads",
	"icy":         "states its server in its first line, which the scan reads",
	"nping-echo":  "opens with its binary handshake, which the scan reads; the next message is a client handshake that starts an echo session",
	"kerberos":    "the only request without a credential is an AS-REQ that names an account, which asks the KDC about a principal; it states no version",
	"finger":      "its only request lists a user or the logged-in users, data of the host rather than a version or info of the service",
	"gopher":      "its only request lists the menu it serves, its content rather than a version or info of the service",
	"http":        "the scan's own HEAD and GET already read its Server header and page; a version or info path belongs to a product, not to the protocol",
	"https":       "the scan's own HEAD and GET already read its Server header and page; a version or info path belongs to a product, not to the protocol",
	"tls":         "a handshake is the whole of what a client with no credentials says, and the scan reads its version, suite and certificate",
	"tcpwrapped":  "closes the connection without a word: it answers nothing to read",
}

// DialFunc opens one connection to a service. The caller holds it to
// the scope, the request budget, the pace and the ledger (in the CLI
// it is egress, with the collector azhaq-verify); this package dials
// nothing on its own authority.
type DialFunc func(ctx context.Context, host, ip string, port int) (net.Conn, error)

// Execute makes the check's one read of svc and labels the answer.
// An error is a read that got no answer at all (a refusal, a timeout):
// the caller counts it as a degraded result, as a confirmation read
// that fails is counted.
func (c Check) Execute(ctx context.Context, svc advisory.Service, dial DialFunc) (Result, error) {
	host := firstNonEmpty(svc.Host, svc.IP)
	r := Result{
		Kind: KindUnauthenticatedRead, Host: host, Port: svc.Port,
		Target: svc.Target(), Service: strings.TrimSuffix(svc.Service, "?"),
		Product: firstNonEmpty(svc.Product, c.Service), Version: svc.Version, Request: c.Request,
		Precondition: c.Precondition,
	}
	if dial == nil {
		return r, fmt.Errorf("verification of %s has no dialer: ask egress for one", r.Target)
	}
	req, parse := c.prepare(svc)
	if req == nil {
		return r, fmt.Errorf("check %s has no request for %s", c.ID, r.Target)
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dial(dctx, host, svc.IP, svc.Port)
	if err != nil {
		return r, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if l, ok := conn.(interface{ Label(proto string) }); ok {
		l.Label(c.Service) // the ledger's probe line names the protocol
	}
	if _, err := conn.Write(req); err != nil {
		return r, err
	}
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for buf.Len() < 64<<10 {
		n, err := conn.Read(tmp)
		buf.Write(tmp[:n])
		if err != nil || n == 0 {
			break
		}
		// One answer is enough: stop at the first pause after bytes.
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	}
	if buf.Len() == 0 {
		return r, fmt.Errorf("no answer from %s", r.Target)
	}
	r.Evidence = excerpt(buf.Bytes())
	if r.Evidence == "" { // a binary answer: its first bytes
		r.Evidence = "(binary) " + hex.EncodeToString(buf.Bytes()[:min(buf.Len(), 24)])
	}
	parse(buf.Bytes(), &r)
	r.Severity = severityOf(r)
	if r.Label == Proved && !c.High {
		r.Severity = "info" // it answered, but its state is not a data store's
	}
	return r, nil
}

func parseRedis(resp []byte, svc advisory.Service, r *Result) {
	s := string(resp)
	switch {
	case strings.HasPrefix(s, "-NOAUTH") || strings.HasPrefix(s, "-DENIED") || strings.Contains(s, "Authentication required"):
		// The service asks for a credential azhaq does not have and
		// does not guess: only the identification stands.
		r.Label = VersionOnly
		if v := redisVersion(s); v != "" {
			r.Version = v
		}
	case strings.HasPrefix(s, "$") || strings.HasPrefix(s, "+"):
		if v := redisVersion(s); v != "" || strings.Contains(s, "# Server") || strings.Contains(s, "redis_version:") {
			r.Label = Proved
			if v := redisVersion(s); v != "" {
				r.Version = v
			}
			return
		}
		r.Label = Conditional
		r.Precondition = "the answer names no version or server section the check can read"
	default:
		r.Label = Conditional
		r.Precondition = "the answer is not a Redis INFO answer the check can read"
	}
}

var redisVersionRe = lazyre.New(`(?m)^redis_version:(\S+)`)

func redisVersion(s string) string {
	if m := redisVersionRe.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func parseMongo(resp []byte, svc advisory.Service, r *Result) {
	s := string(resp)
	switch {
	case strings.Contains(s, "Authentication failed") || strings.Contains(s, "authentication failed") ||
		strings.Contains(s, "Unauthorized") || strings.Contains(s, "unauthorized"):
		r.Label = VersionOnly
	case len(resp) > 21 && binary.LittleEndian.Uint32(resp[12:]) == 2013 &&
		(strings.Contains(s, "ismaster") || strings.Contains(s, "isWritablePrimary") || strings.Contains(s, "maxWireVersion")):
		r.Label = Proved
		if v := bsonString(resp[21:], "version"); v != "" {
			r.Version = v
		}
	default:
		r.Label = Conditional
		r.Precondition = "the answer is not a MongoDB hello the check can read"
	}
}

func parseMemcached(resp []byte, svc advisory.Service, r *Result) {
	s := strings.TrimSpace(string(resp))
	switch {
	case strings.HasPrefix(s, "VERSION "):
		r.Label = Proved
		if f := strings.Fields(s); len(f) > 1 {
			r.Version = f[1]
		}
	case strings.Contains(s, "Authentication") || strings.Contains(s, "authentication"):
		r.Label = VersionOnly
	default:
		r.Label = Conditional
		r.Precondition = "the answer is not a memcached VERSION answer the check can read"
	}
}

// AdvisoryResult labels one advisory lead as a verification result.
// request is the exact request the confirmation read sent ("GET
// /version"), or "" when none was sent. A lead the version places
// outside the range is no result.
func AdvisoryResult(lead advisory.Lead, request string) (Result, bool) {
	if lead.Label == advisory.LabelNotAffected {
		return Result{}, false
	}
	host := lead.Host
	r := Result{
		Kind: KindAdvisoryPrecond, Host: host, Port: lead.Port, Target: lead.Target,
		Service: lead.Service, Product: lead.Product, Version: lead.VersionSeen,
		AdvisoryID: lead.AdvisoryID, AdvisoryURL: lead.URL,
		Precondition: lead.Precondition, Request: request,
	}
	if lead.Origin != "" {
		r.URL = lead.Origin
	}
	switch {
	case lead.Label == advisory.LabelConditional || lead.Confidence == advisory.Inferred:
		r.Label = Conditional
		if r.Precondition == "" {
			r.Precondition = "the confirmation read narrows the match but leaves a precondition open"
		}
	case lead.Confidence == advisory.Observed:
		r.Label = Proved
	case request == "" && lead.Confidence == "":
		r.Label = VersionOnly
		r.Request = "not sent: a version-range match only (give -advisories-confirm with -verify for the one benign read)"
	default:
		// Claimed, or a read that settled nothing: the version stands alone.
		r.Label = VersionOnly
		if r.Request == "" {
			r.Request = "not sent: a version-range match only"
		}
	}
	ev := lead.Read
	if ev == "" {
		ev = "version " + lead.VersionSeen + " is in range " + lead.AffectedRange + " of " + lead.AdvisoryID
	}
	r.Evidence = excerpt([]byte(ev))
	r.Severity = severityOf(r)
	return r, true
}

// severityOf is the stated ranking of a result, by its kind and
// label, printed wherever the result is: it ranks how directly the
// read itself shows the fact, and is not a CVSS score (azhaq holds
// no data to rate one).
func severityOf(r Result) string {
	switch {
	case r.Kind == KindUnauthenticatedRead && r.Label == Proved:
		return "high" // a data store answered a read with no credential
	case r.Kind == KindAdvisoryPrecond && r.Label == Proved:
		return "medium" // version and precondition settled by a read; exploitability never tested
	case r.Label == Conditional:
		return "low"
	default:
		return "info"
	}
}

// SeverityOf is severityOf for the callers that rebuild a result
// from a stored lead.
func SeverityOf(r Result) string { return severityOf(r) }

// excerpt is the first printable lines of an answer, at most 200
// bytes, whitespace folded: the evidence a result carries.
func excerpt(b []byte) string {
	var out []rune
	for _, c := range string(b) {
		if c == '\r' || c == '\n' || c == '\t' {
			c = ' '
		}
		if c < 0x20 || c == 0x7f {
			continue // a binary protocol's framing is not evidence text
		}
		out = append(out, c)
		if len(out) >= 200 {
			break
		}
	}
	return strings.Join(strings.Fields(string(out)), " ")
}

// mongoCommand is an OP_MSG carrying {name: 1, $db: "admin"}, the
// hello a MongoDB client sends before authentication (the same bytes
// the port scan's identification sends).
func mongoCommand(name string) []byte {
	var doc bytes.Buffer
	doc.Write([]byte{0, 0, 0, 0, 0x10})
	doc.WriteString(name + "\x00")
	doc.Write([]byte{1, 0, 0, 0, 0x02})
	doc.WriteString("$db\x00")
	doc.Write([]byte{6, 0, 0, 0})
	doc.WriteString("admin\x00")
	doc.WriteByte(0)
	d := doc.Bytes()
	binary.LittleEndian.PutUint32(d, uint32(len(d)))
	msg := make([]byte, 16, 21+len(d))
	binary.LittleEndian.PutUint32(msg[0:], uint32(21+len(d)))
	binary.LittleEndian.PutUint32(msg[4:], 1)
	binary.LittleEndian.PutUint32(msg[12:], 2013)
	msg = append(msg, 0, 0, 0, 0, 0) // flag bits, section kind 0
	return append(msg, d...)
}

// bsonString finds a string element of a top-level BSON document.
func bsonString(doc []byte, key string) string {
	if len(doc) < 5 {
		return ""
	}
	for el := doc[4:]; len(el) > 1; {
		typ := el[0]
		end := bytes.IndexByte(el[1:], 0)
		if end < 0 {
			return ""
		}
		name, val := string(el[1:1+end]), el[2+end:]
		var size int
		switch typ {
		case 0x01, 0x09, 0x11, 0x12:
			size = 8
		case 0x02:
			if len(val) < 4 {
				return ""
			}
			n := int(binary.LittleEndian.Uint32(val))
			if n < 1 || len(val) < 4+n {
				return ""
			}
			if name == key {
				return string(val[4 : 4+n-1])
			}
			size = 4 + n
		case 0x03, 0x04:
			if len(val) < 4 {
				return ""
			}
			size = int(binary.LittleEndian.Uint32(val))
		case 0x05:
			if len(val) < 4 {
				return ""
			}
			size = 5 + int(binary.LittleEndian.Uint32(val))
		case 0x07:
			size = 12
		case 0x08:
			size = 1
		case 0x0a:
		case 0x10:
			size = 4
		case 0x13:
			size = 16
		default:
			return ""
		}
		if size < 0 || len(val) < size {
			return ""
		}
		el = val[size:]
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
