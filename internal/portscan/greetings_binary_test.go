package portscan

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// openWireFrame builds a WireFormatInfo as the OpenWire format describes
// it: size, type 1, magic, version, a present flag, then the properties.
func openWireFrame(wire int32, props ...[2]string) []byte {
	m := binary.BigEndian.AppendUint32(nil, uint32(len(props)))
	for _, p := range props {
		m = binary.BigEndian.AppendUint16(m, uint16(len(p[0])))
		m = append(m, p[0]...)
		m = append(m, 9)
		m = binary.BigEndian.AppendUint16(m, uint16(len(p[1])))
		m = append(m, p[1]...)
	}
	body := append([]byte{1}, "ActiveMQ"...)
	body = binary.BigEndian.AppendUint32(body, uint32(wire))
	body = append(body, 1)
	body = binary.BigEndian.AppendUint32(body, uint32(len(m)))
	body = append(body, m...)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}

func zmtpGreetingBytes(minor byte, mech string) []byte {
	b := []byte{0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0x7f, 3, minor}
	b = append(b, mech...)
	return append(b, make([]byte, 20-len(mech))...)
}

func TestBinaryGreetings(t *testing.T) {
	tests := []struct {
		name                      string
		raw                       []byte
		service, product, version string
		extra                     string
	}{
		{"openwire with version", openWireFrame(12, [2]string{"ProviderName", "ActiveMQ"}, [2]string{"ProviderVersion", "5.15.9"}),
			"openwire", "ActiveMQ", "5.15.9", "OpenWire version 12"},
		{"openwire snapshot", openWireFrame(12, [2]string{"ProviderVersion", "6.1.0-SNAPSHOT"}),
			"openwire", "ActiveMQ", "6.1.0", "OpenWire version 12"},
		{"openwire without version", openWireFrame(10, [2]string{"CacheEnabled", "true"}),
			"openwire", "ActiveMQ", "", "OpenWire version 10"},
		{"openwire minimal", []byte("\x00\x00\x00\x12\x01ActiveMQ\x00\x00\x00\x0c\x01\x00\x00\x00\x00"),
			"openwire", "ActiveMQ", "", "OpenWire version 12"},
		{"openwire version cut off", openWireFrame(12, [2]string{"ProviderVersion", "5.18.3"})[:44],
			"openwire", "ActiveMQ", "", "OpenWire version 12"},
		{"zeromq null", zmtpGreetingBytes(0, "NULL"), "zeromq", "ZeroMQ", "", "ZMTP 3.0; mechanism NULL"},
		{"zeromq curve", zmtpGreetingBytes(1, "CURVE"), "zeromq", "ZeroMQ", "", "ZMTP 3.1; mechanism CURVE"},
		{"zeromq first 11 octets", zmtpGreetingBytes(0, "")[:11], "zeromq", "ZeroMQ", "", "ZMTP 3"},
		{"ceph msgr2", append([]byte("ceph v2\n\x10\x00"), make([]byte, 16)...), "ceph-msgr2", "Ceph", "", ""},
		// Not matches: a wrong magic, a wrong type, a short or foreign frame.
		{"openwire wrong magic", []byte("\x00\x00\x00\x12\x01ActiveXX\x00\x00\x00\x0c\x01\x00\x00\x00\x00"), "", "", "", ""},
		{"openwire wrong type", []byte("\x00\x00\x00\x12\x02ActiveMQ\x00\x00\x00\x0c\x01\x00\x00\x00\x00"), "", "", "", ""},
		{"openwire bare magic", []byte("\x00\x00\x00\x12\x01ActiveMQ"), "", "", "", ""},
		{"zeromq zmtp 2", []byte{0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0x7f, 1, 0}, "", "", "", ""},
		{"ceph v1 banner", []byte("ceph v027\n\x00\x00"), "", "", "", ""},
		{"unknown binary", []byte{0x00, 0x01, 0x80, 0x90, 0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00}, "", "", "", ""},
	}
	for _, tt := range tests {
		o := Open{Banner: bannerOf(tt.raw)}
		(&Scanner{}).greeted(&o, tt.raw)
		if o.Service != tt.service || o.Product != tt.product || o.Version != tt.version || o.Extra != tt.extra {
			t.Errorf("%s: got %q %q %q %q, want %q %q %q %q", tt.name, o.Service, o.Product, o.Version, o.Extra,
				tt.service, tt.product, tt.version, tt.extra)
		}
		if tt.service == "" && printable(tt.raw) == "(binary)" && !strings.HasPrefix(o.Banner, "(binary) ") {
			t.Errorf("%s: an unmatched greeting lost its hex: %q", tt.name, o.Banner)
		}
	}
}

// MySQL and SSH keep their own readers ahead of the table.
func TestBinaryGreetingsKeepMySQLAndSSH(t *testing.T) {
	o := Open{Banner: bannerOf([]byte("SSH-2.0-OpenSSH_9.6p1\r\n"))}
	(&Scanner{}).greeted(&o, []byte("SSH-2.0-OpenSSH_9.6p1\r\n"))
	if o.Service != "ssh" || o.Product != "OpenSSH" {
		t.Errorf("ssh: %+v", o)
	}
	if g, _, _, ok := binaryGreeted([]byte("SSH-2.0-OpenSSH_9.6p1\r\n")); ok {
		t.Errorf("ssh read as %s", g.service)
	}
}

// A port that sends a binary greeting on connect is named from it with
// -detect all, and nothing is asked of it.
func TestScanNamesBinaryGreeting(t *testing.T) {
	asked := make(chan int, 1)
	mq := listen(t, func(c net.Conn) {
		c.Write(openWireFrame(12, [2]string{"ProviderName", "ActiveMQ"}, [2]string{"ProviderVersion", "5.15.9"}))
		_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, _ := c.Read(make([]byte, 64))
		asked <- n
	})
	s := &Scanner{Detect: DetectAll, Banner: 150 * time.Millisecond, Timeout: time.Second}
	r, err := s.ScanEach(context.Background(), "localhost", "127.0.0.1", []int{mq})
	if err != nil || len(r.Open) != 1 {
		t.Fatalf("scan: %v %+v", err, r)
	}
	o := r.Open[0]
	if o.Service != "openwire" || o.Product != "ActiveMQ" || o.Version != "5.15.9" {
		t.Errorf("named %q %q %q, banner %q", o.Service, o.Product, o.Version, o.Banner)
	}
	if n := <-asked; n != 0 {
		t.Errorf("the greeting was answered with %d bytes", n)
	}

	odd := listen(t, func(c net.Conn) { c.Write([]byte{0x00, 0x01, 0x80, 0x90, 0xfe, 0xed, 0xfa, 0xce}) })
	if o := scanAll(t, odd); o.Product != "" || !strings.HasPrefix(o.Banner, "(binary) 000180") {
		t.Errorf("unknown greeting: %+v", o)
	}
}

func scanAll(t *testing.T, port int) Open {
	t.Helper()
	s := &Scanner{Detect: DetectAll, Banner: 150 * time.Millisecond, Timeout: time.Second}
	r, err := s.ScanEach(context.Background(), "localhost", "127.0.0.1", []int{port})
	if err != nil || len(r.Open) != 1 {
		t.Fatalf("scan: %v %+v", err, r)
	}
	return r.Open[0]
}
