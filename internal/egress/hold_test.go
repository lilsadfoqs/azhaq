package egress

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

func pathWord(raw string) string {
	u, _ := url.Parse(raw)
	for _, w := range []string{"logout", "delete", "reset"} {
		if strings.Contains(u.Path, w) {
			return w
		}
	}
	return ""
}

// A GET whose own name declares a state change never reaches the server
// while the run holds them back, and the policy tells who was refused; a
// request the user asked for, a write and any other GET go through.
func TestHeldGETNeverReachesTheServer(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := counting(t)
	var heard []string
	SetOnDenied(func(raw, rule string) { heard = append(heard, raw+" "+DenyReason(rule)) })
	SetStateWords(pathWord, func(raw string) bool { return strings.HasSuffix(raw, "/given/logout") }, true)
	c := TargetClient(TargetOptions{})

	if err := get(c, srv.URL+"/logout"); !errors.Is(err, neterr.ErrDenied) {
		t.Fatalf("a held GET: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("a held GET reached the server")
	}
	if len(heard) != 1 || !strings.Contains(heard[0], neterr.SendFlag) || !IsHeldReason(strings.SplitN(heard[0], " ", 2)[1]) {
		t.Errorf("who was told: %v", heard)
	}
	for _, ok := range []string{"/home", "/given/logout"} {
		if err := get(c, srv.URL+ok); err != nil {
			t.Errorf("GET %s: %v", ok, err)
		}
	}
	// A request made with the asked context is the user's own wordlist's.
	req, _ := http.NewRequestWithContext(WithAsked(context.Background()), "GET", srv.URL+"/reset", nil)
	if resp, err := c.Do(req); err != nil {
		t.Errorf("an asked GET: %v", err)
	} else {
		resp.Body.Close()
	}
	// Only GET and HEAD are held: a write is the user's flag's to send.
	post, _ := http.NewRequest("POST", srv.URL+"/delete", strings.NewReader("x"))
	if resp, err := c.Do(post); err != nil {
		t.Errorf("a POST: %v", err)
	} else {
		resp.Body.Close()
	}
	if n := hits.Load(); n != 4 {
		t.Errorf("the server saw %d requests, want 4", n)
	}
	// Without the hold the policy only remembers.
	SetStateWords(pathWord, nil, false)
	if err := get(c, srv.URL+"/logout"); err != nil {
		t.Errorf("a GET with no hold: %v", err)
	}
	if !WasSent(srv.URL + "/logout") {
		t.Errorf("a sent state-changing GET is not remembered as sent")
	}
	if WasSent(srv.URL + "/home") {
		t.Errorf("a GET that declares nothing is watched")
	}
}

// An API description's operationId makes the GET held though its path is
// plain.
func TestDeclaredOperationIsHeld(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := counting(t)
	SetStateWords(pathWord, nil, true)
	DeclareStateChange(srv.URL+"/books/v1", "delete")
	if err := get(TargetClient(TargetOptions{}), srv.URL+"/books/v1"); !errors.Is(err, neterr.ErrDenied) {
		t.Fatalf("a declared GET: %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("a declared GET reached the server")
	}
}
