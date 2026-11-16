package store

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestGzRoundTripsAndRepeats(t *testing.T) {
	page := bytes.Repeat([]byte("<div>the application page</div>"), 400)
	first := gz(page)
	got, err := gunzip(first)
	if err != nil || !bytes.Equal(got, page) {
		t.Fatalf("round trip: %v", err)
	}
	if again := gz(append([]byte(nil), page...)); !bytes.Equal(again, first) {
		t.Error("the same body packs two ways")
	}
	for i := 0; i < 6; i++ { // more bodies than the memory holds, from a reused writer
		b := append(append([]byte(nil), page...), byte(i))
		if got, err := gunzip(gz(b)); err != nil || !bytes.Equal(got, b) {
			t.Fatalf("body %d: %v", i, err)
		}
	}
	if got, err := gunzip(gz(nil)); err != nil || len(got) != 0 {
		t.Errorf("empty body: %q %v", got, err)
	}
	// What a pooled writer packs is what a new one would.
	var plain bytes.Buffer
	if z := gzipFresh(&plain, page); !bytes.Equal(z, gz(page)) {
		t.Error("a pooled writer's output differs from a fresh writer's")
	}
}

func gzipFresh(buf *bytes.Buffer, b []byte) []byte {
	w, _ := gzip.NewWriterLevel(buf, gzip.BestSpeed)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}
