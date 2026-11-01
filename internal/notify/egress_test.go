package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A notification is sent to a third party, not a target: the target scope
// does not hold it, and the ledger lists it as a source's.
func TestNotificationIsInTheLedgerAsASource(t *testing.T) {
	egress.Reset()
	defer egress.Reset()
	egress.SetScope(func(string) bool { return false })
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	c, err := NewClient(0, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.http().Post(srv.URL, "text/plain", strings.NewReader("hi"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	l.Close()
	var got []string
	_ = ledger.Read(path, func(e ledger.Entry) error { got = append(got, e.Kind+"/"+e.Class+"/"+e.Method); return nil })
	if len(got) != 1 || got[0] != "http/source/POST" {
		t.Fatalf("ledger %v", got)
	}
}

// A webhook that cannot be reached is named by its host, in the error and
// in the ledger, and by nothing else of its URL: not the user, path or query.
func TestUnreachableWebhookIsNamedByItsHostOnly(t *testing.T) {
	egress.Reset()
	defer egress.Reset()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
	c := &Client{Tries: 2, Backoff: time.Millisecond}
	sendErr := c.Send(context.Background(), "http://user:pw-9f3a1c@unreachable.invalid/hooks/tok-9f3a1c?key=k-9f3a1c#frag-9f3a1c", "hi", nil)
	l.Close()
	raw, _ := os.ReadFile(path)
	if sendErr == nil || !strings.Contains(sendErr.Error(), "unreachable.invalid") || !strings.Contains(string(raw), `"host":"unreachable.invalid"`) {
		t.Fatalf("error %v\nledger %s", sendErr, raw)
	}
	for _, secret := range []string{"9f3a1c", "hooks/", "user"} {
		if strings.Contains(sendErr.Error(), secret) || strings.Contains(string(raw), secret) {
			t.Errorf("%q is in the error or the ledger:\n%v\n%s", secret, sendErr, raw)
		}
	}
}
