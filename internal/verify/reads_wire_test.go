package verify

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
)

// jdwpString and jdwpInt are JDWP's wire types: a four-byte length then
// UTF-8, and a big-endian int.
func jdwpString(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

// jdwpReply is a reply packet (flags 0x80) of the given id and error code:
// length, id, flags, error code, then data. Layout: JDWP specification,
// "Packet layout" and VirtualMachine.Version (command set 1, command 1).
func jdwpReply(id uint32, flags byte, errCode uint16, data []byte) []byte {
	p := binary.BigEndian.AppendUint32(nil, uint32(11+len(data)))
	p = binary.BigEndian.AppendUint32(p, id)
	p = append(p, flags)
	p = binary.BigEndian.AppendUint16(p, errCode)
	return append(p, data...)
}

// versionData is the data of a VirtualMachine.Version reply: description,
// JDWP major and minor, VM version, VM name (the order nmap's jdwp-version
// matches).
func versionData(desc string, major, minor uint32, vmVersion, vmName string) []byte {
	d := jdwpString(desc)
	d = binary.BigEndian.AppendUint32(d, major)
	d = binary.BigEndian.AppendUint32(d, minor)
	d = append(d, jdwpString(vmVersion)...)
	return append(d, jdwpString(vmName)...)
}

const jdwpDesc = "Java Debug Wire Protocol (Reference Implementation) version 17.0\nJVM Debug Interface version 15.0\nJVM version 17.0.9 (OpenJDK 64-Bit Server VM, mixed mode, sharing)"

func goodJDWPAnswer() []byte {
	return append([]byte("JDWP-Handshake"), jdwpReply(1, 0x80, 0, versionData(jdwpDesc, 17, 0, "17.0.9", "OpenJDK 64-Bit Server VM"))...)
}

// A fake debug port: it answers the handshake with itself, and a
// VirtualMachine.Version command with its reply. What it was sent proves
// that nothing else was.
func TestJDWPVersionIsReadAfterTheHandshake(t *testing.T) {
	f := listen(t, func(req []byte) []byte {
		if !bytes.Equal(req, []byte("JDWP-Handshake\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x01\x01")) {
			return nil
		}
		return goodJDWPAnswer()
	})
	r := runOne(t, advisory.Service{Service: "jdwp", Product: "Java Debug Wire Protocol"}, f)
	if r.Label != Proved || r.Kind != KindUnauthenticatedRead || r.Severity != "info" {
		t.Fatalf("%+v, want a proved unauthenticated-read ranked info", r)
	}
	for _, want := range []string{"17.0.9", "OpenJDK 64-Bit Server VM", "JDWP 17.0", "VirtualMachine.Version"} {
		if !strings.Contains(r.Evidence, want) || !strings.Contains(r.Proof.Excerpt, want) {
			t.Errorf("evidence %q / proof %q lack %q", r.Evidence, r.Proof.Excerpt, want)
		}
	}
	if sent := f.requests(); len(sent) != 1 || !strings.HasPrefix(string(sent[0]), "JDWP-Handshake") || len(sent[0]) != 14+11 {
		t.Fatalf("sent %q, want the handshake and the one 11-byte command on one connection", sent)
	}
	if !strings.Contains(r.Request, "VirtualMachine.Version") || !strings.Contains(r.Proof.Method, "VirtualMachine.Version") {
		t.Errorf("request %q does not name the command", r.Request)
	}
	cmd := r.Proof.Reproduce
	if !strings.HasPrefix(cmd, "printf '%b' ") || !strings.Contains(cmd, `JDWP-Handshake\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x01\x01`) || !strings.Contains(cmd, "| nc -w 3 127.0.0.1 ") {
		t.Errorf("reproduce %q", cmd)
	}
}

// Nothing that is not a VirtualMachine.Version reply proves a version: a
// handshake alone, an error, another id, an echo of the command, a cut or an
// empty answer stay the handshake the port did answer.
func TestJDWPAnswerThatIsNotAVersionReplyProvesNoVersion(t *testing.T) {
	hs := []byte("JDWP-Handshake")
	good := versionData(jdwpDesc, 17, 0, "17.0.9", "OpenJDK 64-Bit Server VM")
	for name, answer := range map[string][]byte{
		"handshake only":                 hs,
		"an error reply":                 append(append([]byte(nil), hs...), jdwpReply(1, 0x80, 99, nil)...),
		"another id":                     append(append([]byte(nil), hs...), jdwpReply(2, 0x80, 0, good)...),
		"a command, not a reply":         append(append([]byte(nil), hs...), jdwpReply(1, 0, 0, good)...),
		"cut inside a string":            append(append([]byte(nil), hs...), jdwpReply(1, 0x80, 0, good[:30])...),
		"no VM version":                  append(append([]byte(nil), hs...), jdwpReply(1, 0x80, 0, versionData("d", 1, 8, "", "n"))...),
		"a string longer than its bytes": append(append([]byte(nil), hs...), jdwpReply(1, 0x80, 0, binary.BigEndian.AppendUint32(nil, 1<<30))...),
		"bytes that are not text":        append(append([]byte(nil), hs...), jdwpReply(1, 0x80, 0, versionData("\xff\xfe", 1, 8, "x", "n"))...),
	} {
		f := listen(t, func([]byte) []byte { return answer })
		r := runOne(t, advisory.Service{Service: "jdwp"}, f)
		if r.Label != Proved || r.Kind != KindUnauthenticatedHandshake {
			t.Errorf("%s: %+v, want the proved handshake", name, r)
		}
		if strings.Contains(r.Evidence, "VirtualMachine.Version:") || strings.Contains(r.Proof.Excerpt, "VirtualMachine.Version:") {
			t.Errorf("%s: evidence claims a version: %q", name, r.Evidence)
		}
	}
	// What is not a handshake at all is conditional, whatever follows.
	f := listen(t, func([]byte) []byte { return goodJDWPAnswer()[1:] })
	if r := runOne(t, advisory.Service{Service: "jdwp"}, f); r.Label != Conditional {
		t.Errorf("a cut handshake: %+v, want conditional", r)
	}
}

// hx is the bytes of a hex literal; a malformed literal is the test's bug.
func hx(s string) []byte {
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		panic(err)
	}
	return b
}

// The registry's list() call, as nmap's rmi-dumpregistry writes it (nselib
// rmi.lua: writeMethodCall, Registry:list): the stream header, the client's
// endpoint ("127.0.0.1", port 0), then 0x50 (Call), the serialization header
// aced0005, a block of 0x22 bytes holding the ObjID (number 0, a UID of
// zeros), operation 1 and the hash of RegistryImpl_Stub, 44154dc9d4e63bdf.
const rmiListRequestHex = `4a524d49 0002 4b
	0009 3132372e302e302e31 00000000
	50 aced 0005 77 22
	0000000000000000 00000000 0000000000000000 0000
	00000001 44154dc9d4e63bdf`

// rmiAck is a registry's ProtocolAck: 0x4e, the host it sees the asker as
// and its port (Java RMI specification, section 10.2.2).
func rmiAck(host string, port uint32) []byte {
	b := append([]byte{0x4e}, binary.BigEndian.AppendUint16(nil, uint16(len(host)))...)
	b = append(b, host...)
	return binary.BigEndian.AppendUint32(b, port)
}

// rmiNames is a Return message with a normal return of String[] names: the
// stream a registry's list() writes. The layout is the Java Object
// Serialization specification, section 6.4.2 (TC_ARRAY, TC_CLASSDESC of
// [Ljava.lang.String; with its serialVersionUID, no fields, TC_STRINGs),
// behind the return header of the RMI specification (0x51, aced0005, a
// block of 0x0f bytes: 0x01 for a normal return and the return's UID), as in
// the example in nmap's nselib/rmi.lua (readReturnData). No JVM ran here:
// the bytes are written from those documents.
func rmiNames(names ...string) []byte {
	b := hx(`51 aced0005 77 0f 01 25149521 0000012b169a625a 800b
		75 72 0013 5b4c6a6176612e6c616e672e537472696e673b add256e7e91d7b47 02 0000 78 70`)
	b = binary.BigEndian.AppendUint32(b, uint32(len(names)))
	for _, n := range names {
		b = append(b, 0x74)
		b = binary.BigEndian.AppendUint16(b, uint16(len(n)))
		b = append(b, n...)
	}
	return b
}

func registryAnswer(names ...string) []byte {
	return append(rmiAck("127.0.0.1", 40123), rmiNames(names...)...)
}

// A fake registry that gives its two bound names to the one list() call, and
// nothing to any other bytes. What it was sent is exactly that call.
func TestRMIRegistryNamesAreReadFromList(t *testing.T) {
	want := hx(rmiListRequestHex)
	f := listen(t, func(req []byte) []byte {
		if !bytes.Equal(req, want) {
			return nil
		}
		return registryAnswer("jmxrmi", "CustomService")
	})
	r := runOne(t, advisory.Service{Service: "java-rmi", Product: "Java RMI"}, f)
	if r.Label != Proved || r.Kind != KindUnauthenticatedRead || r.Severity != "info" {
		t.Fatalf("%+v, want a proved unauthenticated-read ranked info", r)
	}
	for _, s := range []string{r.Evidence, r.Proof.Excerpt} {
		if !strings.Contains(s, "2 bound names") || !strings.Contains(s, "jmxrmi, CustomService") {
			t.Errorf("the names are not in %q", s)
		}
	}
	if sent := f.requests(); len(sent) != 1 || !bytes.Equal(sent[0], want) {
		t.Fatalf("sent %x, want exactly the header, the endpoint and one list() call", sent)
	}
	if !strings.Contains(r.Request, "list()") || !strings.Contains(r.Proof.Method, "list()") {
		t.Errorf("request %q does not name list()", r.Request)
	}
	cmd := r.Proof.Reproduce
	if !strings.HasPrefix(cmd, "printf '%b' ") || !strings.Contains(cmd, `\x00\x00\x00\x01D\x15M\xc9\xd4\xe6;\xdf`) || !strings.Contains(cmd, "| nc -w 3 127.0.0.1 ") {
		t.Errorf("reproduce %q", cmd)
	}
	// An empty registry answered the call too: it lists no names.
	f = listen(t, func([]byte) []byte { return registryAnswer() })
	if r := runOne(t, advisory.Service{Service: "java-rmi"}, f); r.Label != Proved || r.Kind != KindUnauthenticatedRead || !strings.Contains(r.Evidence, "0 bound names: none") {
		t.Errorf("an empty registry: %+v", r)
	}
}

// What is not a list of names proves no name: a thrown exception, another
// class, a count the bytes do not hold, a name that is not text, a stream cut
// anywhere. The acknowledgement stays the handshake it was, and no cut of the
// answer makes the reader read past its end.
func TestRMIAnswerThatIsNotAListOfNamesProvesNoName(t *testing.T) {
	ok := registryAnswer("jmxrmi", "CustomService")
	ack := rmiAck("127.0.0.1", 40123)
	exception := bytes.Replace(ok, []byte{0x77, 0x0f, 0x01}, []byte{0x77, 0x0f, 0x02}, 1)
	otherClass := bytes.Replace(ok, []byte("[Ljava.lang.String;"), []byte("[Ljava.lang.Object;"), 1)
	otherUID := bytes.Replace(ok, hx("add256e7e91d7b47"), hx("add256e7e91d7b48"), 1)
	hugeCount := bytes.Replace(ok, hx("78 70 00000002"), hx("78 70 7fffffff"), 1)
	notText := bytes.Replace(ok, []byte("jmxrmi"), []byte("jmx\xff\xfe\xfd"), 1)
	notString := bytes.Replace(ok, hx("74 0006"), hx("73 0006"), 1)
	for name, answer := range map[string][]byte{
		"the acknowledgement alone":       ack,
		"an exception":                    exception,
		"another class":                   otherClass,
		"another serialVersionUID":        otherUID,
		"a count past the bound":          hugeCount,
		"a name that is not text":         notText,
		"an element that is not a string": notString,
		"a call, not a return":            append(append([]byte(nil), ack...), 0x50),
	} {
		f := listen(t, func([]byte) []byte { return answer })
		r := runOne(t, advisory.Service{Service: "java-rmi"}, f)
		if r.Label != Proved || r.Kind != KindUnauthenticatedHandshake {
			t.Errorf("%s: %+v, want the proved handshake", name, r)
		}
		if strings.Contains(r.Evidence, "bound names") {
			t.Errorf("%s: evidence names bound names: %q", name, r.Evidence)
		}
	}
	// Every cut of a good answer: no panic, and no names beyond those whole.
	for n := 0; n < len(ok); n++ {
		var r Result
		got := readRMINames(ok[:n], &r)
		if got && !strings.Contains(r.Evidence, "bound names") {
			t.Fatalf("cut at %d: read with no names: %+v", n, r)
		}
		if got && strings.Contains(r.Evidence, "CustomService") {
			t.Fatalf("cut at %d: a name that was not whole: %q", n, r.Evidence)
		}
	}
}
