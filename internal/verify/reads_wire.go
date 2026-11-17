package verify

// Two checks that read one more thing than the protocol's opening, in the
// same connection and the same write: a JDWP debug port's VM version and a
// Java RMI registry's bound names. Both are what nmap's jdwp-version and
// rmi-dumpregistry scripts ask, and both are reads: neither command changes
// the target.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/proof"
)

// withRead sends tail after the identification's own request and, when that
// answer is a proved handshake, reads what follows with more. head is the
// part of the answer that is the handshake's own, which the identification's
// reader takes whole. When more finds nothing, the result stays the handshake.
func withRead(c Check, tail []byte, head func(resp []byte) []byte, more func(resp []byte, r *Result) bool) Check {
	inner := c.prepare
	c.Kind = KindUnauthenticatedRead
	c.prepare = func(svc advisory.Service) ([]byte, func([]byte, *Result)) {
		req, parse := inner(svc)
		if req == nil {
			return nil, nil
		}
		return append(append([]byte(nil), req...), tail...), func(resp []byte, r *Result) {
			parse(head(resp), r)
			if r.Label != Proved {
				return
			}
			if !more(resp, r) {
				r.Kind = KindUnauthenticatedHandshake
			}
		}
	}
	return c
}

// shown replaces the excerpt of the proof with what the check read, in words,
// so the proof carries the strings of the answer and not the bytes between.
func shown(r *Result, s string) {
	r.Evidence = excerpt([]byte(s))
	if r.Proof != nil {
		r.Proof.Excerpt = proof.Printable([]byte(s), proof.MaxExcerpt)
	}
}

// jdwpVersionRequest is a JDWP command packet: length 11, id 1, flags 0,
// command set 1 (VirtualMachine), command 1 (Version), no data. The bytes
// nmap's jdwp-version sends after the handshake.
var jdwpVersionRequest = []byte{0, 0, 0, 11, 0, 0, 0, 1, 0, 1, 1}

const jdwpHandshake = "JDWP-Handshake"

// jdwpHead is the handshake's echo: the first 14 bytes.
func jdwpHead(resp []byte) []byte { return resp[:min(len(resp), len(jdwpHandshake))] }

// rmiHead is the ProtocolAck: 0x4e, a host string and a port.
func rmiHead(resp []byte) []byte {
	if len(resp) >= 3 && resp[0] == 0x4e {
		if n := 3 + int(binary.BigEndian.Uint16(resp[1:])) + 4; n <= len(resp) {
			return resp[:n]
		}
	}
	return resp
}

// readJDWPVersion reads the reply to VirtualMachine.Version that follows the
// handshake's echo: a reply packet (flags 0x80, error code 0) with the VM
// description, the JDWP version, the VM version and the VM name.
func readJDWPVersion(resp []byte, r *Result) bool {
	if !bytes.HasPrefix(resp, []byte(jdwpHandshake)) {
		return false
	}
	p := resp[len(jdwpHandshake):]
	if len(p) < 11 {
		return false
	}
	n := int(binary.BigEndian.Uint32(p))
	if n < 11 || n > len(p) || binary.BigEndian.Uint32(p[4:]) != 1 || p[8] != 0x80 || binary.BigEndian.Uint16(p[9:]) != 0 {
		return false
	}
	d := &wire{b: p[11:n]}
	desc := d.str(4096)
	major, minor := d.u32(), d.u32()
	version := d.str(256)
	name := d.str(256)
	if d.bad || version == "" {
		return false
	}
	r.Label = Proved
	// The description is long: it goes last, where the evidence may cut it.
	shown(r, fmt.Sprintf("VirtualMachine.Version: JDWP %d.%d; VM version %q; VM name %q; description %q",
		major, minor, version, name, strings.Join(strings.Fields(desc), " ")))
	return true
}

// rmiListCall is the registry's list() over the stream protocol, after the
// protocol header: the client's endpoint (the host and port the server may
// call back, as nmap writes it), then a Call message of one serialized
// block: the registry's ObjID (number 0, an all-zero UID), operation 1
// (list), the RegistryImpl_Stub interface hash. list() takes no argument.
var rmiListCall = func() []byte {
	var b bytes.Buffer
	b.Write([]byte{0, 9})
	b.WriteString("127.0.0.1")
	b.Write([]byte{0, 0, 0, 0})
	b.WriteByte(0x50)                             // Call
	b.Write([]byte{0xac, 0xed, 0, 5, 0x77, 0x22}) // stream header, block data of 34 bytes
	b.Write(make([]byte, 8+4+8+2))                // ObjID: object number 0, UID of zeros
	b.Write([]byte{0, 0, 0, 1})                   // operation 1: list
	b.Write([]byte{0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6, 0x3b, 0xdf})
	return b.Bytes()
}()

// maxRMINames bounds the names one answer is read for.
const maxRMINames = 1024

// readRMINames reads the names out of the reply to list(): the ProtocolAck,
// a Return message (0x51) whose serialized stream is a normal return and a
// String[] (Java Object Serialization, chapter 6). Only the lengths and the
// strings of that one shape are read; anything else is not an answer the
// check reads, and no object is ever built from the bytes.
func readRMINames(resp []byte, r *Result) bool {
	d := &wire{b: resp}
	if d.u8() != 0x4e {
		return false
	}
	d.skip(int(d.u16()) + 4) // the host and port the registry sees
	if d.u8() != 0x51 || d.u32() != 0xaced0005 || d.u8() != 0x77 {
		return false
	}
	blk := d.take(int(d.u8()))
	if d.bad || len(blk) == 0 || blk[0] != 1 { // 1: a normal return
		return false
	}
	if d.u8() != 0x75 || d.u8() != 0x72 || d.utf(64) != "[Ljava.lang.String;" {
		return false
	}
	if d.u64() != 0xadd256e7e91d7b47 || d.u8() != 0x02 || d.u16() != 0 || d.u8() != 0x78 || d.u8() != 0x70 {
		return false
	}
	size := int(d.u32())
	if d.bad || size < 0 || size > maxRMINames {
		return false
	}
	var names []string
	for i := 0; i < size; i++ {
		if d.u8() != 0x74 { // TC_STRING
			break
		}
		s := d.utf(1024)
		if d.bad {
			break
		}
		names = append(names, s)
	}
	if len(names) == 0 && size > 0 {
		return false
	}
	r.Label = Proved
	list := "none"
	if len(names) > 0 {
		list = strings.Join(names, ", ")
	}
	cut := ""
	if len(names) < size {
		cut = fmt.Sprintf(" (the answer ended after %d of %d)", len(names), size)
	}
	shown(r, fmt.Sprintf("list() returned %d bound names%s: %s", len(names), cut, list))
	return true
}

// wire reads big-endian fields from a byte slice and goes bad, never past
// its end, at the first read that does not fit.
type wire struct {
	b   []byte
	bad bool
}

func (w *wire) take(n int) []byte {
	if w.bad || n < 0 || n > len(w.b) {
		w.bad = true
		return nil
	}
	out := w.b[:n]
	w.b = w.b[n:]
	return out
}

func (w *wire) skip(n int) { w.take(n) }

func (w *wire) u8() byte {
	if b := w.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (w *wire) u16() uint16 {
	if b := w.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (w *wire) u32() uint32 {
	if b := w.take(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (w *wire) u64() uint64 {
	if b := w.take(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

// str is a JDWP string: a four-byte length, then UTF-8, at most max bytes.
func (w *wire) str(max int) string {
	n := int(w.u32())
	if n > max {
		w.bad = true
		return ""
	}
	return w.text(w.take(n))
}

// utf is a serialization string: a two-byte length, then the text, at most
// max bytes.
func (w *wire) utf(max int) string {
	n := int(w.u16())
	if n > max {
		w.bad = true
		return ""
	}
	return w.text(w.take(n))
}

// text is b as a string; bytes that are not valid text make the read bad.
func (w *wire) text(b []byte) string {
	if b != nil && !utf8.Valid(b) {
		w.bad = true
		return ""
	}
	return string(b)
}
