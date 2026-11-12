package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strings"
)

// MaxSent is the longest probe whose bytes a line carries (in hex, so twice
// that in the file). Every request azhaq's own probes send is far shorter; a
// longer write keeps its hash only.
const MaxSent = 1024

// Probe records bytes about to be written to a connection that a port
// identification opened (addr is its ip:port, host the name it was found
// under). An HTTP request is listed by its method and path, with the scheme
// of its connection in proto (http, https); any other bytes by proto, the
// protocol they speak, the start of their sha256 in body and the bytes
// themselves in sent. It is a no-op without a ledger. A probe is not a
// request or a connection of its own: the connection it went on has a tcp
// line, and the summary counts that.
func Probe(ctx context.Context, class, host, addr string, secure bool, proto string, b []byte) {
	l := Active()
	if l == nil || len(b) == 0 {
		return
	}
	e := tcpEntry(l, ctx, class, host, addr)
	e.Kind = KindProbe
	if method, path, hostHdr, ok := httpRequestLine(b); ok {
		scheme := "http"
		if secure {
			scheme = "https"
		}
		e.Proto, e.Method, e.Target = scheme, method, scheme+"://"+addr+path
		if hostHdr != addr {
			e.VHost = hostHdr
		}
	} else {
		e.Proto = proto
		if e.Proto == "" {
			e.Proto = "raw"
		}
	}
	sum := sha256.Sum256(b)
	e.Body = hex.EncodeToString(sum[:])[:16]
	if len(b) <= MaxSent {
		e.Sent = hex.EncodeToString(b)
	}
	l.Record(e)
}

// httpRequestLine reads the request line and Host header of an HTTP request
// at the start of b.
func httpRequestLine(b []byte) (method, path, host string, ok bool) {
	head := b
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		head = b[:i]
	}
	lines := strings.Split(string(head), "\r\n")
	f := strings.Fields(lines[0])
	if len(f) != 3 || !strings.HasPrefix(f[2], "HTTP/") || f[0] == "" || strings.Trim(f[0], "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return "", "", "", false
	}
	for _, l := range lines[1:] {
		if k, v, found := strings.Cut(l, ":"); found && strings.EqualFold(strings.TrimSpace(k), "host") {
			host = strings.TrimSpace(v)
			break
		}
	}
	return f[0], f[1], host, true
}

// Labeler is a connection that takes the name of the protocol its next
// writes speak, for the probe lines.
type Labeler interface{ Label(proto string) }

// WrapProbes returns c with each write to it recorded as a probe line (see
// Probe); secure says c is inside TLS. The caller makes the connection's
// own tcp line. A connection that reports its TLS state keeps doing so.
func WrapProbes(ctx context.Context, class, host, addr string, secure bool, c net.Conn) net.Conn {
	if c == nil {
		return nil
	}
	t := &probeConn{Conn: c, ctx: ctx, class: class, host: host, addr: addr, secure: secure}
	if st, ok := c.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return &probeTLSConn{probeConn: t, state: st.ConnectionState}
	}
	return t
}

type probeConn struct {
	net.Conn
	ctx               context.Context
	class, host, addr string
	secure            bool
	proto             string
}

func (c *probeConn) Label(proto string) { c.proto = proto }

func (c *probeConn) Write(b []byte) (int, error) {
	Probe(c.ctx, c.class, c.host, c.addr, c.secure, c.proto, b)
	return c.Conn.Write(b)
}

type probeTLSConn struct {
	*probeConn
	state func() tls.ConnectionState
}

func (c *probeTLSConn) ConnectionState() tls.ConnectionState { return c.state() }
