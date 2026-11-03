package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// bookApp is a VAmPI-shaped book store: the owner is taken from the
// session, POST /books/v1 answers 201 with no usable body unless mode
// says so, and GET /books/v1 lists the books.
type bookApp struct {
	mu      sync.Mutex
	books   map[string]bookRec
	next    int
	mode    string // "location", "generated", "hidden"
	anyRead bool
}

type bookRec struct {
	Title, Owner, Note string
}

func newBookApp(mode string, anyRead bool) (*httptest.Server, *bookApp) {
	app := &bookApp{books: map[string]bookRec{}, mode: mode, anyRead: anyRead}
	srv := httptest.NewServer(http.HandlerFunc(app.handle))
	return srv, app
}

func (a *bookApp) handle(w http.ResponseWriter, r *http.Request) {
	caller := r.Header.Get("A")
	if caller == "" {
		w.WriteHeader(401)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/books/v1":
		var in struct {
			Title string `json:"book_title"`
			Note  string `json:"note"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &in)
		title := in.Title
		if a.mode == "generated" || a.mode == "location" {
			a.next++
			title = fmt.Sprintf("gen-%d", a.next)
		}
		if a.mode == "hidden" {
			w.WriteHeader(201)
			fmt.Fprint(w, `{}`)
			return
		}
		a.books[title] = bookRec{Title: title, Owner: caller, Note: in.Note}
		if a.mode == "location" {
			w.Header().Set("Location", "/books/v1/"+title)
		}
		w.WriteHeader(201)
		fmt.Fprint(w, `{}`)
	case r.Method == http.MethodGet && r.URL.Path == "/books/v1":
		var items []string
		for _, t := range sortedKeys(mapKeys(a.books)) {
			b := a.books[t]
			items = append(items, fmt.Sprintf(`{"book_title":%q,"owner":%q,"note":%q}`, b.Title, b.Owner, b.Note))
		}
		fmt.Fprintf(w, `{"books":[%s]}`, strings.Join(items, ","))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/books/v1/"):
		title := strings.TrimPrefix(r.URL.Path, "/books/v1/")
		b, ok := a.books[title]
		if !ok {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"no such book"}`)
			return
		}
		if !a.anyRead && b.Owner != caller {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":"not yours"}`)
			return
		}
		fmt.Fprintf(w, `{"book_title":%q,"owner":%q,"note":%q}`, b.Title, b.Owner, b.Note)
	default:
		w.WriteHeader(404)
	}
}

func bookRoles() []role {
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	return []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
}

func bookPost(srv *httptest.Server, body string) writeReq {
	return writeReq{owner: "alice", method: "POST", url: srv.URL + "/books/v1", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(body), status: 201, from: "alice.har"}
}

// A create whose answer only gives a Location is located from it, read
// back as its sender, and reported as the sender's own new object: not a
// cross-role result.
func TestCreatedObjectFromLocation(t *testing.T) {
	srv, _ := newBookApp("location", false)
	defer srv.Close()
	rows, _, err := replayWrites(bookRoles(), []writeReq{bookPost(srv, `{"book_title":"ignored","note":"n"}`)}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	r := rows[0]
	if r.Verdict != verdictWriteAccepted || r.CreatedOwner["bob"] != "bob" || r.WriteVerification != verifyProved ||
		!strings.Contains(r.OwnerBy, "Location") || !strings.Contains(r.OwnerBy, "readable back at /books/v1/gen-") {
		t.Errorf("location create: verdict %q created %v verification %q owner_by %q", r.Verdict, r.CreatedOwner, r.WriteVerification, r.OwnerBy)
	}
}

// A create whose answer gives nothing at all is located by reading the
// collection as the creator before and after.
func TestCreatedObjectFromCollectionDiff(t *testing.T) {
	srv, _ := newBookApp("generated", false)
	defer srv.Close()
	rows, _, err := replayWrites(bookRoles(), []writeReq{bookPost(srv, `{"note":"n"}`)}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	r := rows[0]
	if r.Verdict != verdictWriteAccepted || r.CreatedOwner["bob"] != "bob" ||
		!strings.Contains(r.OwnerBy, "before and after") {
		t.Errorf("collection create: verdict %q created %v owner_by %q", r.Verdict, r.CreatedOwner, r.OwnerBy)
	}
}

// A sender-owned new object that every signed-in role reads is a
// cross-role read of the created object, with the creator as its owner.
func TestCreatedObjectReadByOthers(t *testing.T) {
	srv, _ := newBookApp("", true)
	defer srv.Close()
	roles := bookRoles()
	rows, _, err := replayWrites(roles, []writeReq{bookPost(srv, `{"book_title":"bob-book","note":"n"}`)}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 1 || rows[0].made == nil {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	objs := createdRows(roles, rows, map[string]instance{})
	if len(objs) != 1 {
		t.Fatalf("created rows %+v", objs)
	}
	o := objs[0]
	if o.Verdict != verdictCross || o.Owner != "bob" || !slices.Contains(o.Readers, "alice") || o.From == "" || o.value != "bob-book" {
		t.Errorf("created object row: verdict %q owner %q readers %v from %q value %q", o.Verdict, o.Owner, o.Readers, o.From, o.value)
	}
	if post := rows[0]; post.Verdict != verdictWriteAccepted {
		t.Errorf("the create itself stays accepted, not a finding: %q", post.Verdict)
	}
}

// A replay that reuses the identifier of another role's book and
// displaces it is a cross-role create, told apart from a fresh create.
func TestCreatedObjectDisplacesAnotherRoles(t *testing.T) {
	srv, app := newBookApp("", true)
	defer srv.Close()
	app.books["shared"] = bookRec{Title: "shared", Owner: "alice", Note: "alice's"}
	rows, _, err := replayWrites(bookRoles(), []writeReq{bookPost(srv, `{"book_title":"shared","note":"taken"}`)}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	r := rows[0]
	if r.Verdict != verdictWriteCreate || r.WriteVerification != verifyProved ||
		!strings.Contains(r.OwnerBy, "belonged to alice before") || !strings.Contains(r.OwnerBy, "displaced") {
		t.Errorf("overwrite create: verdict %q verification %q owner_by %q", r.Verdict, r.WriteVerification, r.OwnerBy)
	}
	if app.books["shared"].Owner != "bob" {
		t.Errorf("fixture: the book should now be bob's: %+v", app.books["shared"])
	}
}

// A create whose object no Location, answer or collection listing can
// locate says so and claims no negative.
func TestCreatedObjectNotLocatable(t *testing.T) {
	srv, _ := newBookApp("hidden", true)
	defer srv.Close()
	rows, _, err := replayWrites(bookRoles(), []writeReq{bookPost(srv, `{"book_title":"ghost","note":"n"}`)}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	r := rows[0]
	if r.Verdict != verdictWriteUnverifiable || r.WriteVerification != verifyUnlocated ||
		!strings.Contains(r.Evidence, "unverifiable") || !strings.Contains(r.OwnerBy, "check by hand") {
		t.Errorf("unlocatable create: verdict %q verification %q evidence %q owner_by %q", r.Verdict, r.WriteVerification, r.Evidence, r.OwnerBy)
	}
	if strings.Contains(r.label(), "nothing shows") {
		t.Errorf("an unlocated create claims a negative in its label: %q", r.label())
	}
}
