package hunt

import (
	"encoding/json"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/types"
)

func answerObs(url string, status int, ct, title, hash, body string) types.StoredObservation {
	p, _ := json.Marshal(map[string]any{"url": url, "status": status, "content_type": ct, "title": title, "body_hash": hash,
		"head": []byte(body), "head_kept": true})
	return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: p, ObservedAt: now}}
}

// A path that names a file ranks as a finding only when its answer holds the file's own bytes;
// a served page that is not the file is a lead with its check; an answer equal to the host's
// index is no row.
func TestPathAnswersDecideTheTier(t *testing.T) {
	const o = "http://t.test"
	rows := []engine.MapEntry{
		urlRow(o+"/", "page", "visited", 200, nil),
		urlRow(o+"/.env", "page", "visited", 200, nil),
		urlRow(o+"/backup.zip", "page", "visited", 200, nil),
		urlRow(o+"/config", "page", "visited", 200, nil),
		urlRow(o+"/admin", "page", "visited", 200, nil),
	}
	obs := []types.StoredObservation{
		answerObs(o+"/", 200, "text/html", "Acme", "idx", "<html><title>Acme</title></html>"),
		answerObs(o+"/.env", 200, "text/plain", "", "e", "DB_PASSWORD=x\n"),
		answerObs(o+"/backup.zip", 200, "text/html", "Acme downloads", "z", "<html><title>Acme downloads</title></html>"),
		answerObs(o+"/config", 200, "text/html", "Acme", "idx", "<html><title>Acme</title></html>"),
		answerObs(o+"/admin", 200, "text/html", "Acme", "idx", "<html><title>Acme</title></html>"),
	}
	got := Build(Input{DB: "w.db", Rows: rows, Obs: obs, Now: now, Since: 7 * 24 * 3600e9})
	env, zip := find(got, o+"/.env"), find(got, o+"/backup.zip")
	if env == nil || env.Tier != "finding" || env.Proof == nil || !env.Proof.Complete() || env.Check != "" {
		t.Fatalf("/.env: %+v", env)
	}
	if zip == nil || zip.Tier != "lead" || zip.Check == "" || !has(zip, "exposed-file") {
		t.Errorf("/backup.zip: %+v", zip)
	}
	for _, p := range []string{"/config", "/admin"} {
		if r := find(got, o+p); r != nil {
			t.Errorf("%s is a row: its answer is the host's index: %+v", p, r)
		}
	}
	// Findings before leads, whatever the score.
	for i, r := range got {
		if r.Tier == "lead" {
			for _, later := range got[i:] {
				if later.Tier == "finding" {
					t.Errorf("a finding after a lead: %+v", got)
				}
			}
		}
	}
}

// A secret whose own format names it is a finding; one found by the name it was assigned to is a lead.
func TestSecretsAreFindingsOnlyByTheirFormat(t *testing.T) {
	got := Build(Input{Now: now, Since: 7 * 24 * 3600e9, Secrets: []Secret{
		{Kind: "github-token", Severity: "high", Where: "http://t.test/a.js", Rule: "known key format", Known: true},
		{Kind: "generic-secret", Severity: "medium", Where: "http://t.test/b.js", Rule: "name says secret, value looks random"},
	}})
	a, b := find(got, "http://t.test/a.js"), find(got, "http://t.test/b.js")
	if a == nil || a.Tier != "finding" || b == nil || b.Tier != "lead" || b.Check == "" {
		t.Errorf("a %+v, b %+v", a, b)
	}
}

// A served file whose bytes were never judged (no answer kept) is a lead, not a finding.
func TestAServedFileWithNoAnswerKeptIsALead(t *testing.T) {
	got := build(urlRow("http://t.test/.env", "page", "visited", 200, nil))
	if r := find(got, "http://t.test/.env"); r == nil || r.Tier != "lead" || r.Check == "" || !has(r, "exposed-file") {
		t.Errorf("%+v", r)
	}
}
