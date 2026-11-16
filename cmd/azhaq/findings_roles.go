package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/hunt"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/store"
)

// readRolesFiles reads the JSONL files `azhaq roles -json` printed, for hunt,
// `report -findings` and `export -format findings`: one input, one reading.
func readRolesFiles(files []string) ([]hunt.RoleRow, error) {
	var rows []hunt.RoleRow
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		rs, err := hunt.ReadRoles(fh)
		seen := fileTime(fh)
		fh.Close()
		if err != nil {
			return nil, fmt.Errorf("-roles %s: %v", f, err)
		}
		// Rows an older roles printed carry no directory: the file's own,
		// else the newest one the roles default names.
		dir := rolesDirFor(f)
		for i := range rs {
			if rs[i].Dir == "" {
				rs[i].Dir = dir
			}
			rs[i].Seen = seen
		}
		rows = append(rows, rs...)
	}
	return rows, nil
}

func fileTime(f *os.File) (t time.Time) {
	if st, err := f.Stat(); err == nil {
		t = st.ModTime()
	}
	return t
}

// roleFindings are the findings the roles verdicts show: one record for each
// route and method that a proved verdict names (hunt.RoleRow.Proved), from the
// row of the strongest verdict, with how many rows of the route there are.
func roleFindings(rows []hunt.RoleRow, command string) []findingRecord {
	type route struct {
		best hunt.RoleRow
		n    int
	}
	byRoute := map[string]*route{}
	var keys []string
	for _, r := range rows {
		if !r.Proved() {
			continue
		}
		k := strings.ToUpper(r.Method) + "\x00" + hunt.GroupKey(r.Route(), false)
		g := byRoute[k]
		if g == nil {
			g = &route{best: r}
			byRoute[k] = g
			keys = append(keys, k)
		}
		g.n++
		if r.Weight() > g.best.Weight() || r.Weight() == g.best.Weight() && r.URL < g.best.URL {
			g.best = r
		}
	}
	sort.Strings(keys)
	ev := map[string]*store.Evidence{} // the roles runs' evidence, opened once
	defer func() {
		for _, e := range ev {
			if e != nil {
				e.Close()
			}
		}
	}()
	var out []findingRecord
	for _, k := range keys {
		out = append(out, roleRecord(byRoute[k].best, byRoute[k].n, command, ev))
	}
	return out
}

// roleRecord is the finding for a proved verdict. The proof is the answer the
// reader got (kept in the roles run's evidence, its session as a placeholder in
// the curl line) when the run's directory is there; else the verdict's own line
// and the command that shows the row.
func roleRecord(r hunt.RoleRow, n int, command string, ev map[string]*store.Evidence) findingRecord {
	method := strings.ToUpper(r.Method)
	if method == "" {
		method = http.MethodGet
	}
	evidence := r.Verdict
	switch {
	case r.Evidence != "":
		evidence += ": " + r.Evidence
	case len(r.Sensitive) > 0:
		evidence += ": " + strings.Join(r.Sensitive, ", ")
	}
	if r.Confidence != "" {
		evidence += " (" + r.Confidence + ")"
	}
	if n > 1 {
		evidence += fmt.Sprintf("; %d rows of this route say so, this is the strongest", n)
	}
	show := "azhaq roles show -dir " + hunt.Quote(r.Dir) + " " + hunt.Quote(r.URL)
	if r.Method != "" {
		show += " -method " + method
	}
	p := &proof.Proof{ObservedAt: stamp(r.Seen), Method: method, Target: r.URL, ExcerptPart: "verdict", Excerpt: evidence, How: "azhaq-roles"}
	rec := findingRecord{Tier: proof.TierFinding, Kind: crossRoleKind, Label: "proved", Severity: "high", URL: r.URL, Command: command,
		Request: method + " " + r.URL, Evidence: evidence, Collector: "azhaq-roles", Proof: p, rank: r.Weight()}
	if strings.Contains(r.Verdict, "cannot be read back") {
		rec.Severity = "medium"
	}
	rec.Host, rec.Port = hostPort(r.URL)
	if r.Dir == "" {
		p.Reproduce = "azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url " + proof.Quote(originOf(r.URL)+"/")
		return rec
	}
	rec.next = show
	p.Reproduce = show
	e, ok := ev[r.Dir]
	if !ok {
		e, _ = store.OpenEvidenceExisting(filepath.Join(r.Dir, evidenceFile))
		ev[r.Dir] = e
	}
	if e == nil {
		return rec
	}
	if at, ok := e.SavedAt(); ok {
		p.ObservedAt = stamp(at)
	}
	m := ""
	if r.Method != "" {
		m = method
	}
	rows, err := e.Rows(r.URL, m)
	if err != nil {
		return rec
	}
	for _, er := range rows {
		a := readerAnswer(r, er)
		if a == nil {
			continue
		}
		p.Status, p.ContentType = a.Status, a.ContentType
		if a.Curl != "" {
			p.Reproduce = a.Curl
		}
		if text := proof.Printable(a.Body, proof.MaxExcerpt); text != "" {
			p.Excerpt, p.ExcerptPart = text, "body"
		}
		break
	}
	return rec
}

// readerAnswer is the answer of a role that read (or wrote) what the verdict
// says: a named reader's, else any role's but the owner's, that got a 2xx.
func readerAnswer(r hunt.RoleRow, er store.EvidenceRow) *store.EvidenceAnswer {
	named := map[string]bool{}
	for _, x := range r.Readers {
		named[x] = true
	}
	for pass := 0; pass < 2; pass++ {
		for i := range er.Answers {
			a := &er.Answers[i]
			if a.Kind != "answer" || a.Status < 200 || a.Status >= 300 {
				continue
			}
			if pass == 0 && named[a.Role] || pass == 1 && a.Role != r.Owner {
				return a
			}
		}
	}
	return nil
}
