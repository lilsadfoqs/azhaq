package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
)

// Write verdicts. A proved cross write is listed above every read; a write
// that was answered but changed nothing of the owner's ranks below the
// proved reads.
const (
	verdictWriteAnyone = "anyone writes another role's object"
	verdictWriteCross  = "writes another role's object"
	verdictWriteCreate = "creates in another role's collection"
	// A POST another role sent was accepted. Nothing shows the server ignores
	// who may create: the object may be its sender's own.
	verdictWriteAccepted = "create accepted: nothing shows it crosses roles"
	// A create was accepted but the object it made could not be located
	// (no Location, no identifier in the answer, no new item in the
	// collection), so nobody read it back: this claims no negative.
	verdictWriteUnverifiable = "create accepted: the created object could not be located to check who reads it"
	verdictWriteNoChange     = "answered 2xx but changed nothing of the owner's"
	verdictWriteOwner        = "only its owner writes it"
	verdictWriteVoid         = "the owner's own write was refused"
	verdictWriteRefused      = "the other roles were refused"
	// Every other role's write ended in a server error: neither refused nor
	// let through, so nothing is said about who may write.
	verdictWriteFailed = "the other roles' writes failed with a server error (5xx): neither refused nor accepted"
	// Some other roles were refused and some got a 5xx, none was let: only
	// the refused are known to be kept out.
	verdictWriteMixed = "the other roles' writes were refused or failed with a server error (5xx): neither accepted"
	verdictWriteDry   = "would be sent (-dry-writes)"
	// A write another role sent was answered 2xx, and nothing the owner's
	// object shows can tell whether it took.
	verdictWriteUnread = "writes another role's object: accepted; the change cannot be read back to confirm"
)

// The words a write row reports for a verification step.
const (
	verifyProved    = "proved"
	verifyAccepted  = "accepted-not-verified"
	verifyRefuted   = "refuted"
	verifyUnlocated = "unverifiable"
)

func init() {
	verdictOrder[verdictWriteAnyone] = -2
	verdictOrder[verdictWriteCross] = -1
	verdictOrder[verdictWriteUnread] = 0
	verdictOrder[verdictWriteDry] = -3
	verdictOrder[verdictWriteNoChange] = 15
	verdictOrder[verdictWriteCreate] = 16
	verdictOrder[verdictWriteAccepted] = 16
	verdictOrder[verdictWriteUnverifiable] = 17
	verdictOrder[verdictWriteOwner] = 20
	verdictOrder[verdictWriteVoid] = 21
	verdictOrder[verdictWriteRefused] = 20
	verdictOrder[verdictWriteFailed] = 19
	verdictOrder[verdictWriteMixed] = 19
}

// serverFailed counts the other roles that were asked and got a 5xx, and
// those that got anything else (a refusal: a role that was let never gets
// here).
func serverFailed(row *roleRow) (failed, other int) {
	for name, a := range row.Answers {
		switch {
		case name == row.Owner || a.Status == 0:
		case a.Status >= 500:
			failed++
		default:
			other++
		}
	}
	return
}

// serverVerdict is the verdict of a write nobody else was let to send, when
// a 5xx is among the answers: failed when every other role got one, mixed
// when some were refused. "" when there is no 5xx.
func serverVerdict(row *roleRow) string {
	switch failed, other := serverFailed(row); {
	case failed > 0 && other == 0:
		return verdictWriteFailed
	case failed > 0:
		return verdictWriteMixed
	}
	return ""
}

// writeOp is a write a route takes, as a role's run found it: PUT
// /api/Users/{id} from an API description, a script's call.
type writeOp struct {
	method   string
	bodyType string
}

// writeReq is one write to ask with the other roles' sessions: one its
// owner sent (recorded in the owner's HAR), or a route's write filled with
// the owner's object.
type writeReq struct {
	owner  string
	method string
	url    string
	header http.Header // the request's own headers: never a session's
	body   []byte
	from   string // what it is: "alice.har", or "PUT /api/Users/{id} with an empty body"
	status int    // what the owner got, recorded in its HAR; 0 for a map write
	empty  bool   // a map write: an empty object, sent first as its owner
}

// writeMethods reads -replay-writes: the methods to replay, of POST, PUT,
// PATCH and DELETE.
func writeMethods(spec string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, m := range strings.Split(spec, ",") {
		m = strings.ToUpper(strings.TrimSpace(m))
		switch m {
		case "":
		case "POST", "PUT", "PATCH", "DELETE":
			out[m] = true
		default:
			return nil, usagef("-replay-writes %q: want a list of post, put, patch, delete", spec)
		}
	}
	if len(out) == 0 {
		return nil, usagef("-replay-writes: name the methods, such as post,put,patch (add delete to delete objects)")
	}
	return out, nil
}

// keptHeaders are the headers of a recorded request a replay sends: what
// the body is and how the app is asked, never a session (cookies, tokens,
// a CSRF token bound to the owner's session).
var keptHeaders = map[string]bool{"Content-Type": true, "Accept": true, "X-Requested-With": true}

// harWrites reads the writes a role sent, from a HAR its browser or proxy
// saved: the methods asked for, on the run's own hosts, one each.
func harWrites(owner, path string, methods map[string]bool, own map[string]bool) ([]writeReq, error) {
	es, err := readHAR(path)
	if err != nil {
		return nil, err
	}
	return writesFrom(owner, filepathBase(path), es, methods, own), nil
}

// writesFrom are the writes of a history's requests that a replay sends.
func writesFrom(owner, from string, entries []histEntry, methods map[string]bool, own map[string]bool) []writeReq {
	var out []writeReq
	seen := map[string]bool{}
	for _, e := range entries {
		u, err := url.Parse(e.url)
		if !methods[e.method] || err != nil || !own[normalize.Hostname(u.Hostname())] {
			continue
		}
		w := writeReq{owner: owner, method: e.method, url: e.url, header: http.Header{}, from: from, status: e.status}
		for k, vs := range e.header {
			if kept := http.CanonicalHeaderKey(k); keptHeaders[kept] && len(vs) > 0 {
				w.header.Set(kept, vs[0])
			}
		}
		if len(e.body) > 0 || e.mime != "" {
			w.body = e.body
			if w.header.Get("Content-Type") == "" && e.mime != "" {
				w.header.Set("Content-Type", e.mime)
			}
		}
		if key := e.method + " " + w.url + "\x00" + string(w.body); !seen[key] {
			seen[key] = true
			out = append(out, w)
		}
	}
	return out
}

func filepathBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// mapWrites are the writes the routes the runs found take, filled with
// each role's own objects: PATCH with an empty object, which asks for the
// write and changes nothing; PUT with an empty object, which changes
// nothing on a server that updates the fields sent and may clear the
// object on one that replaces it, so the owner's own goes first and its
// object is read again before anyone else is asked; DELETE with no body.
func mapWrites(made map[string]instance, writes map[string][]writeOp, methods map[string]bool) []writeReq {
	var urls []string
	for u, in := range made {
		if in.owner != "" && len(writes[in.template]) > 0 {
			urls = append(urls, u)
		}
	}
	sort.Strings(urls)
	var out []writeReq
	for _, u := range urls {
		in := made[u]
		for _, op := range writes[in.template] {
			m := strings.ToUpper(op.method)
			if !methods[m] {
				continue
			}
			w := writeReq{owner: in.owner, method: m, url: u, header: http.Header{}, from: m + " " + routePath(in.template)}
			switch m {
			case "PUT", "PATCH":
				if op.bodyType != "" && !strings.Contains(op.bodyType, "json") {
					continue // a form's write wants its fields: the HAR has them
				}
				w.body, w.empty = []byte("{}"), true
				w.header.Set("Content-Type", "application/json")
				w.from += " with an empty body"
			case "DELETE":
			default:
				continue // a POST to an object makes something new: the HAR has the real ones
			}
			out = append(out, w)
		}
	}
	return out
}

func routePath(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		return u.Path
	}
	return raw
}

// replayWrites sends each write with the other roles' sessions and proves
// a cross-role write before it claims one: the owner's object is read as
// the owner before and after the write, and "X writes Y's object" is kept
// only when that object changed the way the write asks (or was deleted). A
// 2xx that left the owner's object unchanged is answered-but-changed-
// nothing, not a finding. A POST to a collection is a create, never a
// cross write. A map write (empty body) is sent first with its owner's
// session: the owner must be let, and its own object must not change. A
// DELETE goes to the others alone, the anonymous role first, and stops at
// the first proven. canary, with a PUT or PATCH that is not a map write,
// changes one short field of the body to a value unique to each role it
// is sent with, so replaying the owner's exact body (idempotent: nothing
// to read back) can still be proved. Every request counts against budget.
func replayWrites(roles []role, reqs []writeReq, answers map[string]map[string]answer, own map[string]bool, rate float64, budget int, canary bool, allow ...string) ([]roleRow, int, error) {
	return replayWritesAs(nil, roles, reqs, answers, own, rate, budget, canary, allow...)
}

// replayWritesAs is replayWrites with who each role is, which tells whose
// object a create made.
func replayWritesAs(who map[string]identity, roles []role, reqs []writeReq, answers map[string]map[string]answer, own map[string]bool, rate float64, budget int, canary bool, allow ...string) ([]roleRow, int, error) {
	return replayWritesVerify(who, roles, reqs, answers, own, rate, budget, canary, nil, allow...)
}

// replayWritesVerify is replayWritesAs with the user's verification
// steps for writes the read-back cannot prove.
func replayWritesVerify(who map[string]identity, roles []role, reqs []writeReq, answers map[string]map[string]answer, own map[string]bool, rate float64, budget int, canary bool, verify []verifyWrite, allow ...string) ([]roleRow, int, error) {
	return replayWritesPaused(who, roles, reqs, answers, own, rate, budget, canary, verify, nil, allow...)
}

// replayWritesPaused is replayWritesVerify with the roles paused on
// session loss in the read replay: they are not asked to send writes.
func replayWritesPaused(who map[string]identity, roles []role, reqs []writeReq, answers map[string]map[string]answer, own map[string]bool, rate float64, budget int, canary bool, verify []verifyWrite, paused map[string]bool, allow ...string) ([]roleRow, int, error) {
	ctx := context.Background()
	fetch.Reset()
	defer fetch.Reset()
	egress.SetRate(rate)
	egress.SetTargetProxy(rolesProxy)
	egress.SetScope(func(h string) bool { return own[normalize.Hostname(h)] })
	holdDeny()
	client := *fetch.Client(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	sent := 0
	latest := map[string]answer{} // the owner's objects as last read: an earlier write may have changed what the run read
	var cur *roleRow              // the write's row: a request that gets no answer is noted on it
	send := func(r role, w writeReq) (answer, error) {
		if sent >= budget {
			return answer{}, fmt.Errorf("%w: some writes were not replayed", errReplayMax)
		}
		sent++
		a, err := sendWrite(ctx, &client, r, w)
		var na *noAnswerError
		if errors.As(err, &na) {
			if noAnswer(na.err) && cur != nil {
				cur.Failed = append(cur.Failed, fmt.Sprintf("%s's %s: %s", r.name, w.method, failWhy(na.err)))
			}
			return na.a, nil // no answer, or a cut one: the row says so
		}
		return a, err
	}
	// read gets the owner's object again, to see whether a write changed
	// it; a budget spent or a failed read leaves the write unproven.
	short := false // a read was left out for the budget
	read := func(r role, u string) (answer, bool) {
		if sent >= budget {
			short = true
			return answer{}, false
		}
		sent++
		endStage := ledger.SetStage(stageVerify)
		a, err := readAs(ctx, &client, r, u)
		endStage()
		if err == nil {
			latest[r.name+"\x00"+u] = a
		} else if noAnswer(err) && cur != nil {
			cur.Failed = append(cur.Failed, fmt.Sprintf("read back at %s as %s: %s", pathOf(u), r.name, failWhy(err)))
		}
		return a, err == nil
	}
	byName := map[string]role{}
	for _, r := range roles {
		byName[r.name] = r
	}
	var rows []roleRow
	var stop error
	live := map[string]bool{} // owner and URL → the owner could not read it
	for _, w := range reqs {
		owner, ok := byName[w.owner]
		if !ok {
			continue
		}
		row := roleRow{URL: w.url, Method: w.method, Status: map[string]int{}, Answers: map[string]answer{}, FoundBy: []string{w.owner},
			Owner: w.owner, OwnerBy: w.from, reqBody: w.body, reqType: w.header.Get("Content-Type")}
		cur = &row
		if w.status != 0 {
			row.Answers[w.owner] = answer{Status: w.status}
		}
		// A POST to a collection makes a new object: never another role's
		// object written.
		if w.method == http.MethodPost {
			if err := replayCollectionPaused(&row, roles, w, answers, read, send, who, paused); err != nil {
				stop = err
				rows = append(rows, finishWriteRow(row))
				break
			}
			rows = append(rows, finishWriteRow(row))
			continue
		}
		vu := verifyURL(w, answers)
		ownerLet := w.status >= 200 && w.status < 300
		// The owner's object before any write: the one the owner's run
		// already read when its body is at hand, else read fresh, so its
		// values are there to compare against.
		var before answer
		haveBefore := false
		if vu != "" {
			before, haveBefore = resolveBefore(owner, vu, answers, latest, read)
		} else {
			// The history did not read the owner's object: ask for the write's
			// own URL, then its parents, as the owner.
			vu, before, haveBefore = liveVerify(w, owner, live, read)
		}
		if !w.empty && w.method != http.MethodDelete && (vu == "" || !fieldsVisible(w, before)) {
			// verifyURL only looks at the write's own path and its ancestors,
			// which do not always carry the field the write sets (VAmPI's own
			// GET of a user omits its email); another endpoint the map
			// already knows may still show it (a debug or admin listing of
			// everyone's fields).
			if alt := knownReadBack(w, answers); alt != "" && alt != vu {
				if altBefore, ok := resolveBefore(owner, alt, answers, latest, read); ok {
					vu, before, haveBefore = alt, altBefore, true
				}
			}
		}
		if w.empty {
			a, err := send(owner, w)
			if err != nil {
				stop = err
				break
			}
			row.Answers[w.owner] = a
			ownerLet = reads(a)
			if ownerLet && haveBefore {
				if after, ok := read(owner, vu); ok {
					if changed(before, after) {
						row.Verdict = verdictWriteVoid
						row.OwnerBy += "; the empty write changed the owner's object: no other role was asked"
						rows = append(rows, finishWriteRow(row))
						continue
					}
					before = after
				}
			}
		}
		var canaryField string
		var canaryable bool
		if canary && !w.empty && w.method != http.MethodDelete {
			_, canaryField, canaryable = withCanary(w.body, "azhaqcanaryprobe", allow...)
		}
		already := haveBefore && !w.empty && w.method != http.MethodDelete && !canaryable && alreadySet(before, w.body)
		var let, proven []string
		anon := map[string]bool{}
		for _, r := range otherRoles(roles, w.owner) {
			if paused[r.name] {
				row.OwnerBy += fmt.Sprintf("; %s was not asked: its session was lost and its remaining work was paused", r.name)
				continue
			}
			wr := w
			if canaryable {
				wr.body, _, _ = withCanary(w.body, canaryToken(), allow...)
			}
			a, err := send(r, wr)
			if err != nil {
				stop = err
				break
			}
			row.Answers[r.name] = a
			if !reads(a) {
				continue
			}
			let = append(let, r.name)
			if r.anonymous() {
				anon[r.name] = true
			}
			if vu == "" {
				continue // the owner's object cannot be read: let, but unproven
			}
			after, ok := read(owner, vu)
			if !ok {
				continue
			}
			if provesCross(wr, before, after) {
				proven = append(proven, r.name)
				proof := writeProof(wr, r.name, after)
				if vu != w.url {
					proof += " (read back at " + pathOf(vu) + ")"
				}
				if canaryable {
					proof += fmt.Sprintf(" (canary: %s changed to a value only this replay sent)", canaryField)
				}
				row.OwnerBy += "; " + proof
				if w.method == http.MethodDelete {
					break // the object is gone
				}
			}
			before = after
		}
		if stop != nil {
			break
		}
		// A map DELETE is never asked of its owner: it would delete it.
		ownerAsked := w.status != 0 || w.empty
		why := unreadable(w, vu, before)
		if len(let) > 0 && len(proven) == 0 && len(verify) > 0 {
			refuted := false
			for _, name := range let {
				sender := byName[name]
				switch verifyOutcome(verify, w, sender, w.owner, read, send) {
				case verifyProved:
					proven = append(proven, name)
					if sender.anonymous() {
						anon[name] = true
					}
					row.OwnerBy += fmt.Sprintf("; %s's write is proved by the verification step the user gave", name)
				case verifyRefuted:
					refuted = true
				}
			}
			switch {
			case len(proven) > 0:
				row.WriteVerification = verifyProved
			case refuted:
				row.WriteVerification = verifyRefuted
				row.OwnerBy += "; the verification step the user gave refuted it: the write did not take as the owner's"
			default:
				row.WriteVerification = verifyAccepted
			}
		}
		row.Verdict = writeVerdict(&row, let, proven, anon, ownerLet, ownerAsked, vu != "", why, already)
		switch {
		case len(proven) > 0 && row.WriteVerification == "":
			row.WriteVerification = verifyProved
		case row.Verdict == verdictWriteUnread && row.WriteVerification == "":
			row.WriteVerification = verifyAccepted
		}
		rows = append(rows, finishWriteRow(row))
	}
	if short && stop == nil {
		stop = fmt.Errorf("%w: some objects were not read back", errReplayMax)
	}
	return rows, sent, stop
}

// replayCollection replays a POST, which creates a new object in a
// collection. It is sent with the other roles, and a role that is let can
// create there, but a create is never another role's object written. When
// the map already knows the member URL the created object would answer at
// (createdURL), the first role let read it back, as itself, to confirm
// the create is more than a 2xx.
//
// What a let create is called rests on whose object it made: the owner
// fields of the answer to the create, and of the read-back, are matched with
// who each role is. A create is "creates in another role's collection" only
// when something shows it crosses roles: the anonymous role was let, or the
// object belongs to the role whose request was replayed. Else it is "create
// accepted": the object may well be its sender's own, which is what a
// collection every signed-in user may post to does.
func replayCollectionPaused(row *roleRow, roles []role, w writeReq, answers map[string]map[string]answer, read func(role, string) (answer, bool), send func(role, writeReq) (answer, error), who map[string]identity, paused map[string]bool) error {
	var let, shown, unlocated []string
	ownerRole, hasOwner := role{}, false
	for _, r := range roles {
		if r.name == w.owner {
			ownerRole, hasOwner = r, true
		}
	}
	for _, r := range otherRoles(roles, w.owner) {
		if paused[r.name] {
			row.OwnerBy += fmt.Sprintf("; %s was not asked: its session was lost and its remaining work was paused", r.name)
			continue
		}
		// The object's pre-state, before this create: the collection as
		// the sender reads it, and the member the write's own identifier
		// names, as its recorded owner reads it.
		collBefore, collBeforeOK := read(r, w.url)
		type preState struct {
			exists bool
			ans    answer
			owner  string
			item   *listObject
		}
		pre := map[string]preState{}
		for _, c := range bodyCandidates(w) {
			if !hasOwner {
				break
			}
			if got, ok := read(ownerRole, c.url); ok {
				o, _, _ := createdOwner(got, w.owner, roles, who)
				exists := reads(got)
				if exists {
					// A route that answers a made-up identifier alike
					// proves nothing about the identifier before.
					if fake := madeUp(c.value); fake != "" {
						if ctrl, ok := read(ownerRole, memberURLFor(w.url, fake)); ok && reads(ctrl) && (ctrl.Hash == got.Hash || !fieldsDiffer(ctrl, got)) {
							exists = false
						}
					}
				}
				pre[c.url] = preState{exists: exists, ans: got, owner: o}
			}
		}
		a, err := send(r, w)
		if err != nil {
			return err
		}
		row.Answers[r.name] = a
		if !reads(a) {
			continue
		}
		let = append(let, r.name)
		// Locate the created object without guessing a mapped URL: the
		// answer's Location, a link or identifier in its body, the
		// write's own identifier, then the collection as the creator
		// reads it before and after.
		var obj *createdObject
		var postAns answer
		tried := map[string]bool{}
		try := func(c candidate) bool {
			if c.url == "" || tried[c.url] {
				return false
			}
			tried[c.url] = true
			got, ok := read(r, c.url)
			if !ok || !reads(got) {
				return false
			}
			obj = &createdObject{url: c.url, field: c.field, value: c.value, creator: r.name, answers: map[string]answer{r.name: got}}
			postAns = got
			row.OwnerBy += fmt.Sprintf("; %s's create is readable back at %s (%s)", r.name, pathOf(c.url), c.how)
			return true
		}
		for _, c := range responseCandidates(w, a) {
			if try(c) {
				break
			}
		}
		if obj == nil {
			if collAfter, ok := read(r, w.url); ok {
				for _, c := range collectionCandidates(w, collBefore, collAfter) {
					if try(c) {
						break
					}
				}
			}
		}
		if obj == nil {
			unlocated = append(unlocated, r.name)
			why := "no Location and no identifier in the create answer or the write reads back, and the collection read as " + r.name + " before and after shows no new or changed object"
			if !collBeforeOK {
				why = "no Location and no identifier in the create answer or the write reads back, and the collection could not be read as " + r.name + " before the create"
			}
			row.OwnerBy += fmt.Sprintf("; unverifiable: %s's created object could not be located: %s; check by hand: read %s as %s, find the object it made, then read that object as each other role", r.name, why, pathOf(w.url), r.name)
			row.Evidence = "unverifiable: " + why
			continue
		}
		made := postAns
		// Did the identifier already belong to another role?
		var preInfo preState
		hasPre := false
		if p, ok := pre[obj.url]; ok {
			preInfo, hasPre = p, true
		} else if item := findItem(collBefore, obj.value); item != nil {
			cp := *item
			preInfo = preState{exists: true, item: &cp, owner: ownerOfItem(cp, roles, who)}
			hasPre = true
		}
		postOwner, postBy, postStrong := createdOwner(made, r.name, roles, who)
		if postOwner == "" {
			if o, by, strong := createdOwner(a, r.name, roles, who); o != "" {
				postOwner, postBy, postStrong = o, by, strong
			}
		}
		changedPre := false
		if hasPre && preInfo.exists {
			switch {
			case preInfo.ans.Hash != "" && postAns.Hash != "" && preInfo.ans.Hash != postAns.Hash:
				changedPre = true
			case preInfo.item != nil && postAns.self != nil && itemDiffers(*preInfo.item, *postAns.self):
				changedPre = true
			case preInfo.owner != "" && postOwner != "" && preInfo.owner != postOwner:
				changedPre = true
			}
		}
		if hasPre && preInfo.exists && preInfo.owner != "" && preInfo.owner != r.name && changedPre && postOwner != preInfo.owner {
			shown = append(shown, r.name)
			effective := postOwner
			if effective == "" {
				effective = r.name
			}
			obj.preOwner, obj.displaced = preInfo.owner, true
			row.WriteVerification = verifyProved
			row.OwnerBy += fmt.Sprintf("; the identifier %s belonged to %s before %s's create and is changed after it (now %s): a create that displaced another role's object", obj.value, preInfo.owner, r.name, effective)
			setCreated(row, r.name, effective)
			if !r.anonymous() {
				readByOthers(row, roles, obj, read)
			}
			continue
		}
		if r.anonymous() {
			shown = append(shown, r.name)
			row.OwnerBy += fmt.Sprintf("; %s, a role with no session, was let to create", r.name)
			continue
		}
		owner, by, strong := postOwner, postBy, postStrong
		switch {
		case owner == "":
			row.OwnerBy += fmt.Sprintf("; the object %s's create made at %s does not say whose it is", r.name, pathOf(obj.url))
			obj.ownerUnknown = true
			if row.WriteVerification == "" {
				row.WriteVerification = verifyAccepted
			}
			readByOthers(row, roles, obj, read)
		case owner == r.name:
			row.OwnerBy += fmt.Sprintf("; the object %s's create made belongs to %s (%s)", r.name, r.name, by)
			row.WriteVerification = verifyProved
			setCreated(row, r.name, owner)
			readByOthers(row, roles, obj, read)
		case owner == w.owner && strong:
			shown = append(shown, r.name)
			row.OwnerBy += fmt.Sprintf("; the object %s's create made belongs to %s, whose request was replayed (%s)", r.name, owner, by)
			setCreated(row, r.name, owner)
		default:
			row.OwnerBy += fmt.Sprintf("; the object %s's create made may belong to %s (%s)", r.name, owner, by)
			obj.ownerUnknown = owner != r.name
			if owner == r.name {
				readByOthers(row, roles, obj, read)
			}
		}
		_ = answers
	}
	row.Readers = let
	switch {
	case len(shown) > 0:
		row.Verdict = verdictWriteCreate
	case len(let) > 0 && len(unlocated) == len(let):
		row.Verdict = verdictWriteUnverifiable
		row.WriteVerification = verifyUnlocated
	case len(let) > 0:
		row.Verdict = verdictWriteAccepted
		if len(unlocated) > 0 {
			row.WriteVerification = verifyUnlocated
		}
	default:
		if row.Verdict = serverVerdict(row); row.Verdict == "" {
			row.Verdict = verdictWriteRefused
		}
	}
	return nil
}

type candidate struct {
	url, field, value, how string
}

func memberURLFor(collection, value string) string {
	pu, err := url.Parse(collection)
	if err != nil || value == "" {
		return ""
	}
	pu.Path = strings.TrimRight(pu.Path, "/") + "/" + value
	pu.RawPath = ""
	pu.RawQuery, pu.Fragment = "", ""
	return pu.String()
}

func bodyCandidates(w writeReq) []candidate {
	var out []candidate
	seen := map[string]bool{}
	for _, p := range bodyPairs(w.body) {
		u := memberURLFor(w.url, p[1])
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, candidate{url: u, field: p[0], value: p[1], how: "the write's " + p[0]})
		}
	}
	return out
}

func resolveAgainst(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := b.Parse(ref)
	if err != nil {
		return ""
	}
	r.RawQuery, r.Fragment = "", ""
	return r.String()
}

func idFieldRank(n string) int {
	switch {
	case n == "id" || strings.HasSuffix(n, "id"):
		return 0
	case strings.Contains(n, "title") || n == "name" || strings.Contains(n, "slug") || n == "key":
		return 1
	}
	return 2
}

func responseCandidates(w writeReq, a answer) []candidate {
	var out []candidate
	seen := map[string]bool{}
	add := func(c candidate) {
		if c.url != "" && !seen[c.url] {
			seen[c.url] = true
			out = append(out, c)
		}
	}
	if a.Location != "" {
		if u := resolveAgainst(w.url, a.Location); u != "" {
			v := u
			if pu, err := url.Parse(u); err == nil {
				seg := pu.Path[strings.LastIndex(pu.Path, "/")+1:]
				if un, err := url.PathUnescape(seg); err == nil {
					v = un
				}
			}
			add(candidate{url: u, value: v, how: "the create answer's Location"})
		}
	}
	if a.self != nil {
		var fields []string
		for n := range a.self.fields {
			fields = append(fields, n)
		}
		sort.Slice(fields, func(i, j int) bool {
			ri, rj := idFieldRank(fields[i]), idFieldRank(fields[j])
			if ri != rj {
				return ri < rj
			}
			return fields[i] < fields[j]
		})
		// A link the answer itself gives comes before a guessed member.
		for _, n := range fields {
			v := a.self.fields[n]
			switch norm(n) {
			case "url", "self", "href", "link", "location", "uri":
				if strings.HasPrefix(v, "http") || strings.HasPrefix(v, "/") {
					add(candidate{url: resolveAgainst(w.url, v), value: v, how: "the create answer's " + n})
				}
			}
		}
		bodyFields := map[string]bool{}
		for _, p := range bodyPairs(w.body) {
			bodyFields[norm(p[0])] = true
		}
		sort.Slice(fields, func(i, j int) bool {
			bi, bj := bodyFields[fields[i]], bodyFields[fields[j]]
			if bi != bj {
				return bi
			}
			ri, rj := idFieldRank(fields[i]), idFieldRank(fields[j])
			if ri != rj {
				return ri < rj
			}
			return fields[i] < fields[j]
		})
		for _, n := range fields {
			v := a.self.fields[n]
			if v == "" || len(v) > 64 || strings.ContainsAny(v, "/?#") {
				continue
			}
			if idFieldRank(n) < 2 || bodyFields[n] {
				add(candidate{url: memberURLFor(w.url, v), field: a.self.spelled(n), value: v, how: "the create answer's " + a.self.spelled(n)})
			}
		}
	}
	for _, c := range bodyCandidates(w) {
		c.how = "the write's " + c.field
		add(c)
	}
	return out
}

func orderedValFields(w writeReq, a answer) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range bodyPairs(w.body) {
		if n := norm(p[0]); !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	var rest []string
	for n := range a.vals {
		if !seen[n] {
			rest = append(rest, n)
		}
	}
	sort.Slice(rest, func(i, j int) bool {
		ri, rj := idFieldRank(rest[i]), idFieldRank(rest[j])
		if ri != rj {
			return ri < rj
		}
		return rest[i] < rest[j]
	})
	return append(out, rest...)
}

func collectionCandidates(w writeReq, before, after answer) []candidate {
	var out []candidate
	seen := map[string]bool{}
	add := func(field, value, how string) {
		u := memberURLFor(w.url, value)
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, candidate{url: u, field: field, value: value, how: how})
		}
	}
	for _, f := range orderedValFields(w, after) {
		bv := map[string]bool{}
		for _, v := range before.vals[f] {
			bv[v] = true
		}
		for _, v := range after.vals[f] {
			if !bv[v] {
				add(f, v, "the collection as the creator read it before and after")
			}
		}
	}
	for i := range after.items {
		for _, f := range orderedValFields(w, after) {
			v := after.items[i].fields[f]
			if v == "" {
				continue
			}
			for j := range before.items {
				if before.items[j].fields[f] == v && itemDiffers(before.items[j], after.items[i]) {
					add(f, v, "an object changed in the collection as the creator read it before and after")
				}
			}
		}
	}
	return out
}

func findItem(a answer, value string) *listObject {
	if value == "" {
		return nil
	}
	for i := range a.items {
		for _, v := range a.items[i].fields {
			if v == value {
				return &a.items[i]
			}
		}
	}
	return nil
}

func itemDiffers(a, b listObject) bool {
	for n, v := range a.fields {
		if b.fields[n] != v && !timeLike.MatchString(v) {
			return true
		}
	}
	for n, v := range b.fields {
		if a.fields[n] != v && !timeLike.MatchString(v) {
			return true
		}
	}
	return false
}

func ownerOfItem(item listObject, roles []role, who map[string]identity) string {
	o := item
	owner, _, _ := createdOwner(answer{self: &o}, "", roles, who)
	return owner
}

// readByOthers has every role but the creator read the object its create
// made, once, as itself: what the create's row cannot say alone is whether
// the object is the creator's only. The object is kept on the row when a
// role read it, for createdRows to judge.
func readByOthers(row *roleRow, roles []role, c *createdObject, read func(role, string) (answer, bool)) {
	readers := false
	for _, o := range roles {
		if o.name == c.creator {
			continue
		}
		a, ok := read(o, c.url)
		if !ok {
			break // the budget is spent or the request failed: the row says which
		}
		c.answers[o.name] = a
		readers = readers || reads(a)
	}
	if readers {
		if row.made == nil {
			row.made = c // else only its sender reads it: the create stays accepted
		}
		row.mades = append(row.mades, c)
	}
}

// createdObject is an object a replayed create made, that a role besides its
// creator read.
type createdObject struct {
	url, field, value string
	creator           string
	answers           map[string]answer // each role's read of it
	ownerUnknown      bool              // the read-back does not say whose it is
	preOwner          string            // the role the identifier belonged to before the create, when it did
	displaced         bool              // it belonged to preOwner before and changed after
}

// createdRows are the rows for the objects the replayed creates made and
// other roles read: each a read of the creator's own object. made learns
// whose each object is and how it is known.
func createdRows(roles []role, wrows []roleRow, made map[string]instance) []roleRow {
	var out []roleRow
	for _, w := range wrows {
		cs := w.mades
		if len(cs) == 0 && w.made != nil {
			cs = []*createdObject{w.made}
		}
		for _, c := range cs {
			out = append(out, createdRow(roles, w, c, made))
		}
	}
	return out
}

func createdRow(roles []role, w roleRow, c *createdObject, made map[string]instance) roleRow {
	in := made[c.url]
	if in.template == "" {
		if i := strings.LastIndex(c.url, "/"+url.PathEscape(c.value)); i >= 0 && c.field != "" {
			in.template = c.url[:i] + "/{" + c.field + "}"
		}
	}
	by := fmt.Sprintf("created by %s's replayed POST %s", c.creator, pathOf(w.URL))
	if c.displaced && c.preOwner != "" {
		by += fmt.Sprintf("; the identifier belonged to %s before the create", c.preOwner)
	}
	in.value, in.owner, in.by, in.sure, in.told, in.given = c.value, c.creator, by, proved, toldConfirms, false
	if c.ownerUnknown {
		in.sure, in.told = hinted, toldNone
	}
	in.holders = []string{c.creator}
	made[c.url] = in
	row := roleRow{URL: c.url, Status: map[string]int{}, Answers: map[string]answer{}, FoundBy: []string{c.creator},
		From: in.template, Owner: c.creator, OwnerBy: by, value: c.value}
	for _, r := range roles {
		if a, ok := c.answers[r.name]; ok {
			row.Answers[r.name] = a
			row.Status[r.name] = a.Status
		}
	}
	row.Verdict = verdict(roles, &row)
	return row
}

// withRows is rows with extra's added: a row for a URL the read replay
// listed before the object existed is replaced.
func withRows(rows, extra []roleRow) []roleRow {
	at := map[string]int{}
	for i, r := range rows {
		if r.Method == "" {
			at[r.URL] = i
		}
	}
	for _, r := range extra {
		if i, ok := at[r.URL]; ok {
			rows[i] = r
		} else {
			rows = append(rows, r)
		}
	}
	return rows
}

func setCreated(row *roleRow, sender, owner string) {
	if row.CreatedOwner == nil {
		row.CreatedOwner = map[string]string{}
	}
	row.CreatedOwner[sender] = owner
}

// createdOwner is whose object an answer about a created object says it
// is: the role that who names by an owner field of it, else a role whose
// name the owner field spells (not strong: the session does not say). by
// says what told.
func createdOwner(a answer, sender string, roles []role, who map[string]identity) (owner, by string, strong bool) {
	if a.self == nil {
		return "", "", false
	}
	if o, why, known, _ := whose(a.self, roles, who, "", ""); known && o != "" {
		return o, why, true // the session says so: not a name that matches a role's
	}
	for _, n := range sortedKeys(mapKeys(a.self.fields)) {
		if !ownerField(n) {
			continue
		}
		for _, r := range roles {
			if !r.anonymous() && strings.EqualFold(a.self.fields[n], r.name) {
				return r.name, fmt.Sprintf("its %s field says %s, the name of the role: its session does not say", a.self.spelled(n), a.self.fields[n]), false
			}
		}
	}
	return "", "", false
}

// provesCross: the owner's object changed the way the write asks. A DELETE
// is proven when the object is gone; a PUT or PATCH with a body when one
// of its values is now in the object and was not before; an empty PUT or
// PATCH when any value the object held changed (timestamps aside).
func provesCross(w writeReq, before, after answer) bool {
	if w.method == http.MethodDelete {
		return !reads(after)
	}
	if w.empty {
		return changed(before, after)
	}
	return wroteInto(before, after, w.body)
}

// writeProof says, for owner_by, what the owner's object showed after the
// cross write.
func writeProof(w writeReq, reader string, after answer) string {
	if w.method == http.MethodDelete {
		return "after " + reader + "'s DELETE the owner's object is gone (" + answerCell(after) + ")"
	}
	return "after " + reader + "'s " + w.method + " the owner's object changed to match it"
}

// otherRoles are the roles a write of owner's is asked with: the
// anonymous ones first, as a DELETE stops at the first let.
func otherRoles(roles []role, owner string) []role {
	var anon, signed []role
	for _, r := range roles {
		switch {
		case r.name == owner:
		case r.anonymous():
			anon = append(anon, r)
		default:
			signed = append(signed, r)
		}
	}
	return append(anon, signed...)
}

// changed: after differs from before in a value the object held, timestamps
// aside.
func changed(before, after answer) bool {
	if before.Hash == "" || after.Hash == "" || after.Hash == before.Hash {
		return false
	}
	for v := range before.held {
		if !after.held[v] && !timeLike.MatchString(v) {
			return true
		}
	}
	for v := range after.held {
		if !before.held[v] && !timeLike.MatchString(v) {
			return true
		}
	}
	return false
}

// wroteInto: the owner's object now holds a value the write's body sets
// and did not hold before: in the field of that name when the object has
// one (quantity 2, though a ProductId of 2 was there already), else
// anywhere. An empty body names nothing, so any change counts.
func wroteInto(before, after answer, body []byte) bool {
	pairs := bodyPairs(body)
	if len(pairs) == 0 {
		return changed(before, after)
	}
	for _, p := range pairs {
		n := norm(p[0])
		if b, a := before.vals[n], after.vals[n]; len(b) > 0 && len(a) > 0 {
			if slices.Contains(a, p[1]) && !slices.Contains(b, p[1]) {
				return true
			}
			continue
		}
		if after.held[p[1]] && !before.held[p[1]] {
			return true
		}
	}
	return false
}

// alreadySet: the object holds every value the write's body sets, so the
// write cannot be seen to change it.
func alreadySet(obj answer, body []byte) bool {
	pairs := bodyPairs(body)
	for _, p := range pairs {
		if v := obj.vals[norm(p[0])]; len(v) > 0 {
			if !slices.Contains(v, p[1]) {
				return false
			}
		} else if !obj.held[p[1]] {
			return false
		}
	}
	return len(pairs) > 0
}

// bodyPairs are the fields and scalar values a JSON write body sets,
// timestamps aside.
func bodyPairs(body []byte) [][2]string {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	var out [][2]string
	for k, x := range m {
		if s, ok := scalarString(x); ok && len(s) <= 64 && !timeLike.MatchString(s) {
			out = append(out, [2]string{k, s})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// verifyURL is the owner's readable object a write is checked against: the
// write's own URL when the owner reads it (PUT, PATCH, DELETE on an
// object), else a readable ancestor (/users/v1/alice for a write to
// /users/v1/alice/email). "" when none is found.
func verifyURL(w writeReq, answers map[string]map[string]answer) string {
	ownerReads := func(u string) (string, bool) {
		if a, ok := answers[w.owner][u]; ok && reads(a) {
			return u, true
		}
		if n, err := normalize.URL(u); err == nil {
			if a, ok := answers[w.owner][n]; ok && reads(a) {
				return n, true
			}
		}
		return "", false
	}
	if u, ok := ownerReads(w.url); ok {
		return u
	}
	pu, err := url.Parse(w.url)
	if err != nil {
		return ""
	}
	path := strings.TrimRight(pu.Path, "/")
	for strings.Count(path, "/") > 1 {
		path = path[:strings.LastIndex(path, "/")]
		cand := *pu
		cand.Path, cand.RawQuery, cand.Fragment = path, "", ""
		if u, ok := ownerReads(cand.String()); ok {
			return u
		}
	}
	return ""
}

// resolveBefore is the owner's object at u: the one its run already read
// when its body is at hand, else read fresh; ok is false when neither
// gives an answer that reads.
func resolveBefore(owner role, u string, answers map[string]map[string]answer, latest map[string]answer, read func(role, string) (answer, bool)) (answer, bool) {
	if b, ok := latest[owner.name+"\x00"+u]; ok {
		return b, reads(b)
	}
	if b := answers[owner.name][u]; len(b.held) > 0 && reads(b) {
		return b, true
	}
	return read(owner, u)
}

// objectIDs are u's path segments that could name an object: not the
// version or framework segments (v1, api, rest) every route under it
// shares.
func objectIDs(u string) []string {
	pu, err := url.Parse(u)
	if err != nil {
		return nil
	}
	var out []string
	for _, seg := range strings.Split(strings.Trim(pu.Path, "/"), "/") {
		if seg != "" && !versionSeg.MatchString(norm(seg)) {
			out = append(out, seg)
		}
	}
	return out
}

// knownReadBack is a GET URL the map already has an answer for, other
// than the write's own path or an ancestor of it (verifyURL tries those
// first), whose body already holds one of the write's object's path
// segments or a field the write sets: an endpoint such as
// /users/v1/_debug, which the read run found exposes every object's
// fields, read again as the owner can confirm a write verifyURL's
// narrower search would call unreadable. "" when none of the map's known
// GETs qualifies.
func knownReadBack(w writeReq, answers map[string]map[string]answer) string {
	ids := objectIDs(w.url)
	fields := setFields(w)
	if len(ids) == 0 && len(fields) == 0 {
		return ""
	}
	best, score := "", 0
	seen := map[string]bool{}
	for _, byURL := range answers {
		for u, a := range byURL {
			if u == w.url || seen[u] || !reads(a) {
				continue
			}
			seen[u] = true
			s := 0
			for _, id := range ids {
				if a.held[id] {
					s += 2
				}
			}
			for _, f := range fields {
				if len(a.vals[norm(f)]) > 0 {
					s++
				}
			}
			if s > score || s == score && s > 0 && (best == "" || u < best) {
				best, score = u, s
			}
		}
	}
	return best
}

// createdURL guesses the object a POST to a collection created, and
// returns it only when the map already has an answer for that exact URL
// (some role's run already reached it): the collection's path with one
// more segment, one of the scalar values the write's body sets, in the
// order the body names them.
func createdURL(w writeReq, answers map[string]map[string]answer) string {
	u, _, _ := createdMember(w, answers)
	return u
}

// createdMember is createdURL with the body field and the value that made
// the last segment.
func createdMember(w writeReq, answers map[string]map[string]answer) (u, field, value string) {
	pu, err := url.Parse(w.url)
	if err != nil {
		return "", "", ""
	}
	base := strings.TrimRight(pu.Path, "/")
	for _, p := range bodyPairs(w.body) {
		cand := *pu
		cand.Path, cand.RawQuery, cand.Fragment = base+"/"+p[1], "", ""
		out := cand.String()
		for _, byURL := range answers {
			if _, ok := byURL[out]; ok {
				return out, p[0], p[1]
			}
		}
	}
	return "", "", ""
}

// canaryToken is a value unlikely to already be anywhere in a target: a
// fresh one for each role a write is replayed with, so a read-back can
// tell which role's write landed.
func canaryToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "azhaq-" + hex.EncodeToString(b[:])
}

// fieldLeft is a field of a write body the canary leaves alone, and why.
type fieldLeft struct{ name, why string }

// canaryField picks the field of a JSON object body a canary sets, and
// lists the string fields it leaves alone with the rule that did. A field
// the caller named in allow is taken first, whatever the rules say: that
// is the caller's risk. Otherwise it is the first of the fields by name
// that is not an identifier, an owner or reference field (changing whose
// the object is is not what this proves), a credential, or a timestamp.
func canaryField(m map[string]any, allow []string) (field string, left []fieldLeft) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	named := map[string]bool{}
	for _, a := range allow {
		named[norm(a)] = true
	}
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" && named[norm(k)] {
			return k, nil
		}
	}
	for _, k := range keys {
		s, isStr := m[k].(string)
		if !isStr || s == "" {
			continue
		}
		n := norm(k)
		switch {
		case ownerField(n):
			left = append(left, fieldLeft{k, "it says whose the object is"})
		case refField(n):
			left = append(left, fieldLeft{k, "it refers to another object"})
		case sensitiveField(k) != "":
			left = append(left, fieldLeft{k, "it holds a credential"})
		case timeLike.MatchString(s):
			left = append(left, fieldLeft{k, "it is a timestamp"})
		default:
			if field == "" {
				field = k
			}
		}
	}
	return field, left
}

// withCanary changes one short string field of a JSON write body to
// token (see canaryField). ok is false, and body is given back unchanged,
// when the body is not a JSON object or no field qualifies: the write is
// then sent as recorded, proving nothing new.
func withCanary(body []byte, token string, allow ...string) (out []byte, field string, ok bool) {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body, "", false
	}
	field, _ = canaryField(m, allow)
	if field == "" {
		return body, "", false
	}
	m[field] = token
	if raw, err := json.Marshal(m); err == nil {
		return raw, field, true
	}
	return body, "", false
}

// canaryNotes says, before anything is sent, which field the canary of
// each PUT or PATCH write will set and which it leaves alone and why; when
// no field qualifies, that the write goes as recorded with no canary.
func canaryNotes(reqs []writeReq, allow []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, w := range reqs {
		if w.empty || w.method == http.MethodDelete || w.method == http.MethodPost {
			continue
		}
		id := w.method + " " + pathOf(w.url)
		if seen[id] {
			continue
		}
		seen[id] = true
		var m map[string]any
		if json.Unmarshal(w.body, &m) != nil || m == nil {
			out = append(out, fmt.Sprintf("canary: %s has no JSON object body, so no field can carry a canary: it is replayed as recorded", id))
			continue
		}
		field, left := canaryField(m, allow)
		var parts []string
		for _, l := range left {
			parts = append(parts, fmt.Sprintf("%s (%s)", l.name, l.why))
		}
		switch {
		case field != "" && len(parts) > 0:
			out = append(out, fmt.Sprintf("canary: %s sets %s; left alone: %s", id, field, strings.Join(parts, ", ")))
		case field != "":
			out = append(out, fmt.Sprintf("canary: %s sets %s", id, field))
		case len(parts) > 0:
			out = append(out, fmt.Sprintf("canary: %s has no field a canary may set, so it is replayed as recorded, with no canary; left alone: %s; -replay-writes-field NAME takes one when you accept changing it", id, strings.Join(parts, ", ")))
		default:
			out = append(out, fmt.Sprintf("canary: %s has no non-empty string field, so it is replayed as recorded, with no canary", id))
		}
	}
	return out
}

// readAs reads u as role r, past the cache, inside the scope and pace,
// without following a redirect; the body is kept as evidence.
func readAs(ctx context.Context, client *http.Client, r role, u string) (answer, error) {
	pu, err := url.Parse(u)
	if err != nil || !egress.Allows(pu.Hostname()) {
		return answer{}, fmt.Errorf("%s is outside the scope", u)
	}
	if err := egress.Spend(ctx); err != nil {
		return answer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return answer{}, err
	}
	fetch.Extra = r.session.Clone()
	fetch.ApplyHeaders(req)
	fetch.Extra = nil
	resp, err := client.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer resp.Body.Close()
	body, cut, err := fetch.ReadAnswer(resp, 1<<20) // a stream that never ends is cut
	if err != nil {
		return answer{}, fmt.Errorf("the answer was cut: %w", err)
	}
	a, _ := readAnswer(resp.StatusCode, body, resp.Header.Get("Content-Type"))
	a.Truncated = cut
	if loc := resp.Header.Get("Location"); loc != "" {
		a.Location = bareLocation(loc)
	}
	keepBody(a.Hash, resp.Header.Get("Content-Type"), body)
	return a, nil
}

var timeLike = lazyre.New(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|^\d{10,13}$`)

// sendWrite sends w as r: its method, body and own headers, r's session,
// inside the scope and the run's budget and pace, without following a
// redirect.
func sendWrite(ctx context.Context, client *http.Client, r role, w writeReq) (answer, error) {
	u, err := url.Parse(w.url)
	if err != nil || !egress.Allows(u.Hostname()) {
		return answer{}, fmt.Errorf("%s is outside the scope", w.url)
	}
	if err := egress.Spend(ctx); err != nil {
		return answer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, w.method, w.url, bytes.NewReader(w.body))
	if err != nil {
		return answer{}, err
	}
	for k, vs := range w.header {
		req.Header[k] = vs
	}
	fetch.Extra = r.session.Clone()
	fetch.ApplyHeaders(req)
	fetch.Extra = nil
	resp, err := client.Do(req)
	if err != nil {
		return answer{}, &noAnswerError{err: err}
	}
	defer resp.Body.Close()
	body, cut, rerr := fetch.ReadAnswer(resp, 1<<20) // a stream that never ends is cut
	a, _ := readAnswer(resp.StatusCode, body, resp.Header.Get("Content-Type"))
	a.Truncated = cut
	if loc := resp.Header.Get("Location"); loc != "" {
		a.Location = bareLocation(loc)
	}
	if ok2xx(a.Status) && len(body) <= 300 && deniedText.Match(body) {
		a.Refusal = true // a short 2xx answer that says no ("Only Admins may delete users!")
	}
	keepBody(a.Hash, resp.Header.Get("Content-Type"), body)
	if rerr != nil {
		// The status came; the body was cut: the write was sent, so its
		// status stands, noted as the failure it is.
		return a, &noAnswerError{err: fmt.Errorf("the answer was cut: %w", rerr), a: a}
	}
	return a, nil
}

// noAnswerError is a write the target did not answer, or answered with a
// body that was cut (a, then, is the status and what came): replayWrites
// notes it on the row and goes on.
type noAnswerError struct {
	err error
	a   answer
}

func (e *noAnswerError) Error() string { return e.err.Error() }
func (e *noAnswerError) Unwrap() error { return e.err }

// writeNotes says in the summary how many requests of the write replay got
// no answer, and why. failed is true when one did: the run exits 3.
func writeNotes(rows []roleRow) (notes []string, failed bool) {
	n := 0
	var reasons []string
	for _, row := range rows {
		n += len(row.Failed)
		reasons = append(reasons, row.Failed...)
	}
	if n == 0 {
		return nil, false
	}
	return []string{fmt.Sprintf("write replay: %s got no answer, so the rows say what the others showed: %s", plural(n, "request"), distinctReasons(reasons))}, true
}

// deniedText: what a server says when it refuses a write and still answers 2xx.
var deniedText = lazyre.New(`(?i)\bonly\s+(admin|administrator|owner|moderator)s?\b|not\s+(authori[sz]ed|permitted|allowed)|permission\s+denied|access\s+denied|\bforbidden\b|\bunauthori[sz]ed\b|insufficient\s+(privileges|permissions)`)

// writeVerdict reads the replay's result. A cross write is claimed only
// when it was proven (the owner's object changed), and anyone-writes when
// the anonymous role proved it. A role answered 2xx whose write changed
// nothing of the owner's is listed apart, below the proved reads, not as a
// finding.
func writeVerdict(row *roleRow, let, proven []string, anon map[string]bool, ownerLet, ownerAsked, canVerify bool, why string, already bool) string {
	var provenAnon, provenSigned []string
	for _, n := range proven {
		if anon[n] {
			provenAnon = append(provenAnon, n)
		} else {
			provenSigned = append(provenSigned, n)
		}
	}
	switch {
	case len(provenAnon) > 0:
		row.Readers = append(provenAnon, provenSigned...)
		return verdictWriteAnyone
	case len(provenSigned) > 0:
		row.Readers = provenSigned
		return verdictWriteCross
	case len(let) > 0 && why != "":
		// Accepted, and no GET shows the change: neither proved nor
		// disproved, so listed as what it is.
		row.Readers = let
		row.Evidence = fmt.Sprintf("%s's write was accepted (%d); %s", let[0], row.Answers[let[0]].Status, why)
		return verdictWriteUnread
	case len(let) > 0:
		row.Readers = let
		if already {
			row.OwnerBy += "; the owner's object already held what the write sets: no change could show"
		} else if canVerify {
			row.OwnerBy += "; the owner's object was unchanged after the write"
		} else {
			row.OwnerBy += "; the owner's object could not be read to verify the write"
		}
		return verdictWriteNoChange
	case serverVerdict(row) != "":
		return serverVerdict(row)
	case ownerLet:
		return verdictWriteOwner
	case !ownerAsked:
		return verdictWriteRefused
	}
	return verdictWriteVoid
}

// unreadable says why a write's change cannot be read back, or "" when it
// can: no GET of the owner's object answers, or the object it shows has none
// of the fields the write sets (a password is never in the user's answer).
// An empty write sets nothing to read back.
func unreadable(w writeReq, vu string, before answer) string {
	if w.empty {
		return ""
	}
	if vu == "" {
		return "no GET of the owner's object can be read, to see it change"
	}
	if fieldsVisible(w, before) {
		return ""
	}
	return fmt.Sprintf("%s shows no %s, the field the write sets", pathOf(vu), strings.Join(setFields(w), "/"))
}

// fieldsVisible: before, the object a write's read-back is checked
// against, carries at least one of the fields the write sets -- or
// nothing can be told either way (a DELETE sets none, the write is not
// JSON or a form, or before is not JSON), in which case the read-back is
// not ruled out on these grounds alone.
func fieldsVisible(w writeReq, before answer) bool {
	if w.method == http.MethodDelete {
		return true
	}
	fields := setFields(w)
	if len(fields) == 0 || len(before.Keys) == 0 {
		return true
	}
	have := map[string]bool{}
	for _, k := range before.Keys {
		k = strings.TrimSuffix(k, "[]")
		have[norm(k[strings.LastIndexAny(k, ".")+1:])] = true
	}
	for _, f := range fields {
		if have[norm(f)] {
			return true
		}
	}
	return false
}

// setFields are the names of the fields a write's body sets: a JSON object's
// or a form's.
func setFields(w writeReq) []string {
	var out []string
	var m map[string]any
	if json.Unmarshal(w.body, &m) == nil {
		for k := range m {
			out = append(out, k)
		}
	} else if q, err := url.ParseQuery(string(w.body)); err == nil && !strings.Contains(w.header.Get("Content-Type"), "json") {
		for k := range q {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// liveVerify finds the owner's object a write can be checked against when
// no answer of the history holds it: the write's own URL, then its parents
// down to two segments, each read as the owner (at most once each).
func liveVerify(w writeReq, owner role, live map[string]bool, read func(role, string) (answer, bool)) (string, answer, bool) {
	if w.method == http.MethodPost {
		return "", answer{}, false
	}
	pu, err := url.Parse(w.url)
	if err != nil {
		return "", answer{}, false
	}
	path := strings.TrimRight(pu.Path, "/")
	for first := true; ; first = false {
		last := path[strings.LastIndex(path, "/")+1:]
		if first || !versionSeg.MatchString(norm(last)) { // /users/v1 is the collection, not an object
			cand := *pu
			cand.Path, cand.RawPath, cand.RawQuery, cand.Fragment = path, "", "", ""
			u := cand.String()
			key := owner.name + "\x00" + u
			if !live[key] { // a failed read is not tried again; a good one is read afresh
				if got, ok := read(owner, u); ok && reads(got) {
					return u, got, true
				}
				live[key] = true
			}
		}
		if strings.Count(path, "/") < 3 {
			return "", answer{}, false // a parent one segment deep is a collection
		}
		path = path[:strings.LastIndex(path, "/")]
	}
}

func finishWriteRow(row roleRow) roleRow {
	for n, a := range row.Answers {
		row.Status[n] = a.Status
	}
	if len(row.Failed) > 0 {
		row.Evidence = strings.TrimPrefix(row.Evidence+"; no answer: "+strings.Join(row.Failed, ", "), "; ")
	}
	return row
}

// writeRoutes are the writes a run's routes take, by route: the methods
// besides GET its API descriptions and scripts name, with how the body is
// sent.
func (s runSeen) addWrites(raw string, methods []string, ops []struct {
	Method   string `json:"method"`
	BodyType string `json:"body_type"`
}) {
	u, err := normalize.URL(raw)
	if err != nil || !strings.Contains(raw, "{") {
		return
	}
	key := webextract.RouteKey(u)
	have := s.writes[key]
	add := func(m, bt string) {
		m = strings.ToUpper(m)
		if m == "GET" || m == "HEAD" || m == "OPTIONS" || slices.ContainsFunc(have, func(o writeOp) bool { return o.method == m }) {
			return
		}
		have = append(have, writeOp{method: m, bodyType: bt})
	}
	for _, op := range ops {
		add(op.Method, op.BodyType)
	}
	for _, m := range methods {
		add(m, "")
	}
	if len(have) > 0 {
		s.writes[key] = have
	}
}
