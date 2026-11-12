package portscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// binaryGreeting names a service from the first bytes a server sends in a
// binary protocol, by a magic its public specification fixes. match returns
// the version when the frame states one, and what it says beside that. Only
// server-first protocols belong here; a client-first one needs a probe. A
// protocol that already has a strict passive reader (telnet, VNC) is read
// there and not repeated.
type binaryGreeting struct {
	service, product string
	match            func(raw []byte) (version, extra string, ok bool)
}

var binaryGreetings = []binaryGreeting{
	{"openwire", "ActiveMQ", openWireGreeting},
	{"zeromq", "ZeroMQ", zmtpGreeting},
	{"ceph-msgr2", "Ceph", cephGreeting},
}

// binaryGreeted is the first entry whose magic the bytes carry.
func binaryGreeted(raw []byte) (g binaryGreeting, version, extra string, ok bool) {
	for _, g = range binaryGreetings {
		if version, extra, ok = g.match(raw); ok {
			return g, version, extra, true
		}
	}
	return binaryGreeting{}, "", "", false
}

// openWireGreeting reads the WireFormatInfo command an ActiveMQ broker sends
// on connect: size (int32), type 1, the magic "ActiveMQ", the wire format
// version (int32), then the marshalled properties. Source: OpenWire format
// specification, https://activemq.apache.org/components/classic/documentation/openwire-version-2-specification
// and WireFormatInfoMarshaller / MarshallingSupport in the ActiveMQ sources
// (a property is a UTF key, a type byte, the value; type 9 is a UTF string).
func openWireGreeting(raw []byte) (version, extra string, ok bool) {
	if len(raw) < 17 || raw[4] != 1 || string(raw[5:13]) != "ActiveMQ" {
		return "", "", false
	}
	if n := binary.BigEndian.Uint32(raw); n < 13 || n > 1<<20 {
		return "", "", false
	}
	extra = fmt.Sprintf("OpenWire version %d", int32(binary.BigEndian.Uint32(raw[13:])))
	// Loose and tight encodings differ before the properties; the
	// property bytes do not, so the key is looked up whole.
	key := []byte("\x00\x0fProviderVersion\x09")
	i := bytes.Index(raw[17:], key)
	if i < 0 {
		return "", extra, true
	}
	p := raw[17+i+len(key):]
	if len(p) < 2 {
		return "", extra, true
	}
	n := int(binary.BigEndian.Uint16(p))
	if n == 0 || len(p) < 2+n {
		return "", extra, true
	}
	return leadVer.FindString(string(p[2 : 2+n])), extra, true
}

// zmtpGreeting reads the greeting of ZMTP 3.x: 0xFF, eight padding octets,
// 0x7F, the major version 3, the minor, then a 20-octet mechanism name. A
// peer that must talk to older ones sends only the first 11 octets at
// first. Source: ZMTP 3.0, https://rfc.zeromq.org/spec/23/. The greeting
// does not state the library's version.
func zmtpGreeting(raw []byte) (version, extra string, ok bool) {
	if len(raw) < 11 || raw[0] != 0xff || raw[9] != 0x7f || raw[10] != 3 {
		return "", "", false
	}
	extra = "ZMTP 3"
	if len(raw) >= 12 {
		extra += fmt.Sprintf(".%d", raw[11])
	}
	if len(raw) >= 32 {
		m := bytes.TrimRight(raw[12:32], "\x00")
		if len(m) > 0 && isUpperASCII(m) {
			extra += "; mechanism " + string(m)
		}
	}
	return "", extra, true
}

func isUpperASCII(b []byte) bool {
	for _, c := range b {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

// cephGreeting reads the banner both ends of a Ceph messenger v2 connection
// send on connect: "ceph v2\n", a little-endian 16-bit length, then the
// feature words. Source: Ceph msgr2 protocol, https://docs.ceph.com/en/latest/dev/msgr2/
func cephGreeting(raw []byte) (version, extra string, ok bool) {
	return "", "", bytes.HasPrefix(raw, []byte("ceph v2\n"))
}
