package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

// A probe line holds the bytes sent, so a probe can be sent again from the
// ledger, and the chain and the seal still verify with the new field.
func TestProbeLineHoldsTheBytesSent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	Use(l)
	defer Use(nil)
	mongo := []byte{0x3a, 0x00, 0x00, 0x00, 0x15, 0xd1, 0x07, 0x00, 'i', 's', 'M', 'a', 's', 't', 'e', 'r'}
	head := []byte("HEAD / HTTP/1.0\r\nHost: 127.0.0.1:80\r\n\r\n")
	long := bytes.Repeat([]byte{'x'}, MaxSent+1)
	Probe(context.Background(), ClassTarget, "", "127.0.0.1:27017", false, "mongodb", mongo)
	Probe(context.Background(), ClassTarget, "", "127.0.0.1:80", false, "", head)
	Probe(context.Background(), ClassTarget, "", "127.0.0.1:9", false, "raw", long)
	l.Close()

	var got []Entry
	if err := Read(path, func(e Entry) error {
		if e.Kind == KindProbe {
			got = append(got, e)
		}
		return nil
	}); err != nil || len(got) != 3 {
		t.Fatalf("read: %d probe lines, %v", len(got), err)
	}
	for i, want := range [][]byte{mongo, head} {
		b, err := hex.DecodeString(got[i].Sent)
		if err != nil || !bytes.Equal(b, want) {
			t.Errorf("line %d sent %q, want %x", i, got[i].Sent, want)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:])[:16] != got[i].Body {
			t.Errorf("line %d: body %s is not the hash of its sent bytes", i, got[i].Body)
		}
	}
	if got[2].Sent != "" || got[2].Body == "" {
		t.Errorf("a write over %d bytes keeps its hash only: sent %d chars, body %q", MaxSent, len(got[2].Sent), got[2].Body)
	}
	c, err := Verify(path)
	if err != nil || c.Entries < 3 || c.Seals != 1 || c.Unsealed != 0 {
		t.Fatalf("verify: %+v %v", c, err)
	}
}
