package fetch

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestSharedBodiesAreOneCopy(t *testing.T) {
	Reset()
	page := bytes.Repeat([]byte("<p>app</p>"), 500)
	a := shared(append([]byte(nil), page...))
	b := shared(append([]byte(nil), page...))
	if &a[0] != &b[0] {
		t.Error("equal bodies are two copies")
	}
	if len(a) != len(page) || !bytes.Equal(a, page) {
		t.Error("the shared body differs from what was read")
	}
	if cap(a) != len(a) {
		t.Errorf("capacity %d, length %d: an append could reach the shared copy", cap(a), len(a))
	}
	other := append([]byte(nil), page...)
	other[7] = 'X'
	if c := shared(other); &c[0] == &a[0] || c[7] != 'X' {
		t.Error("a body that differs by one byte was shared")
	}
	small := []byte("tiny")
	if s := shared(small); &s[0] != &small[0] {
		t.Error("a body under the minimum is looked up")
	}
	Reset()
	if c := shared(append([]byte(nil), page...)); &c[0] == &a[0] {
		t.Error("Reset keeps the table")
	}
}

type failAfter struct {
	r io.Reader
}

func (f failAfter) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func TestReadAllPooledIsReadAll(t *testing.T) {
	for _, n := range []int{0, 1, 511, 512, 513, 70000, 3 << 20} {
		src := strings.Repeat("x", n)
		got, err := readAllPooled(strings.NewReader(src))
		if err != nil || string(got) != src || got == nil {
			t.Errorf("%d bytes: got %d bytes, err %v, nil %v", n, len(got), err, got == nil)
		}
	}
	got, err := readAllPooled(failAfter{strings.NewReader("partial")})
	if err != io.ErrUnexpectedEOF || string(got) != "partial" {
		t.Errorf("a failed read: %q, %v", got, err)
	}
	a, _ := readAllPooled(strings.NewReader("first"))
	b, _ := readAllPooled(strings.NewReader("second"))
	if string(a) != "first" || string(b) != "second" {
		t.Errorf("a read reached the next one's buffer: %q %q", a, b)
	}
}
