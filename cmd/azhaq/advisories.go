package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// The flags of -advisories, shared by run and ports (ports passes them
// to the run it makes). Matching is off unless -advisories says so, and
// confirmation is off unless -advisories-confirm says so.
type advisoryFlags struct {
	on, confirm bool
	source      string
}

func (a *advisoryFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&a.on, "advisories", false, "match the products and versions this run already confirmed against the advisory records of -advisory-source, as labelled leads (affected, not affected or conditional, each with its advisory id and URL): a pure lookup over what the run already holds, nothing more is sent to a target")
	fs.BoolVar(&a.confirm, "advisories-confirm", false, "with -advisories: for each affected or conditional lead, also make the one benign read the advisory names (a GET of its documented version or info path, or of / to read the version it states): no payload, no login, no state change, never a request that could trigger the issue; each read is in the ledger and counts against -max-requests, and each lead is labelled observed, inferred or claimed (with -advisories; reads only within the run's scope: the targets given, -allow or -scope)")
	fs.StringVar(&a.source, "advisory-source", "", "the advisory records to match against, OSV JSON (a record, a list, {\"vulns\": [...]}, or JSON lines): a file the user downloaded (works offline), or an http(s) URL asked once as a third-party source; azhaq vendors no snapshot and fetches none it was not given")
}

// check is the usage half of the flags, before anything is sent: a
// confirmation needs the match, the match needs a source it can read,
// and a confirmation needs a scope (the caller's targets stand for one,
// as they do for the other active techniques).
func (a advisoryFlags) check() error {
	switch {
	case a.confirm && !a.on:
		return usagef("-advisories-confirm confirms the matches of -advisories: give both")
	case a.on && a.source == "":
		return usagef("-advisories matches against records the user names: give -advisory-source FILE (OSV JSON, works offline) or -advisory-source https://… (asked once as a source)")
	case a.on && !isURL(a.source):
		if _, err := os.Stat(a.source); err != nil {
			return usagef("-advisory-source %s: %v", a.source, err)
		}
	}
	return nil
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// loadAdvisories reads the records of source: a local file, offline, or
// one GET of a URL through the source client (held to the kill file,
// recorded in the ledger as a source, verified TLS). An error is a
// failed source, which the caller reports as a degraded result (exit 3),
// never as no matches.
func loadAdvisories(ctx context.Context, source string) ([]advisory.Advisory, error) {
	var raw []byte
	if isURL(source) {
		client := egress.SourceClient(egress.SourceOptions{Timeout: 30 * time.Second})
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("advisory source %s: %w", source, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("advisory source %s answered %d", source, resp.StatusCode)
		}
		raw, err = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return nil, fmt.Errorf("advisory source %s: %w", source, err)
		}
	} else {
		var err error
		raw, err = os.ReadFile(source)
		if err != nil {
			return nil, fmt.Errorf("advisory source: %w", err)
		}
	}
	advs, err := advisory.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("advisory source %s: %w", source, err)
	}
	return advs, nil
}

// advisoryStage is the whole of -advisories after the run: Part 1
// matches what the run's observations already confirmed (it sends
// nothing to any target), and Part 2, only with -advisories-confirm,
// makes each affected or conditional lead's one benign read through the
// egress chokepoint (scope, pace, budget, ledger), with the collector
// name azhaq-advisories on its ledger lines. The leads are stored as
// observations of their host, so the summary's counts are derivable
// from the workspace: one stored lead per line printed.
//
// failures are what did not get its answer (the source, a confirmation
// read): the caller lists them in the summary, which makes the exit
// code 3, a degraded result with the leads it has standing.
func advisoryStage(ctx context.Context, st *store.Store, obs []types.StoredObservation, fl advisoryFlags) (leads []advisory.Lead, failures []engine.Failure, note string) {
	advs, err := loadAdvisories(ctx, fl.source)
	if err != nil {
		return nil, []engine.Failure{{Collector: "azhaq-advisories", Error: err.Error(), Count: 1}}, ""
	}
	byID := map[string]advisory.Advisory{}
	for _, a := range advs {
		byID[a.ID] = a
	}
	services := advisory.Services(obs)
	leads = advisory.Match(services, advs)
	var deferNote []string
	if fl.confirm {
		confirmer := advisory.Confirmer{
			Client: egress.TargetClient(egress.TargetOptions{Timeout: 15 * time.Second}),
			Spend:  func(ctx context.Context) error { return egress.Spend(ctx) },
		}
		svcByTarget := map[string]advisory.Service{}
		for _, s := range services {
			svcByTarget[s.Target()+"\x00"+s.Product] = s
		}
		cctx := ledger.WithCollector(ctx, "azhaq-advisories")
		failed, refused, stopped, denied := 0, 0, 0, 0
		for i, lead := range leads {
			leads[i].Confidence = advisory.Claimed
			leads[i].Read = "nothing read: a range match only"
			if lead.Label == advisory.LabelNotAffected {
				continue
			}
			svc := svcByTarget[lead.Target+"\x00"+lead.Product]
			conf, read, err := confirmer.Confirm(cctx, byID[lead.AdvisoryID], svc)
			switch {
			case err == nil:
				leads[i].Confidence, leads[i].Read = conf, read
			case isDenied(err):
				// A -deny-path rule of the user's keeps the read out:
				// a note, not a failure, and the lead stays claimed.
				denied++
				leads[i].Read = "not read: " + err.Error() + " (a -deny-path rule of yours keeps its path out)"
			case isScopeRefusal(err):
				// A scope that refuses a target is a note, not a failure:
				// the scope is the user's, and the lead stays claimed.
				refused++
				leads[i].Read = "not read: outside the scope (-allow, -scope)"
			case isStop(err):
				stopped++
				leads[i].Read = "not read: " + err.Error()
			default:
				failed++
				leads[i].Read = "the confirmation read failed: " + err.Error()
			}
		}
		if failed > 0 {
			failures = append(failures, engine.Failure{Collector: "azhaq-advisories", Error: "a confirmation read got no answer", Count: failed, Retryable: true})
		}
		if denied > 0 {
			deferNote = append(deferNote, fmt.Sprintf("advisories-confirm: %d confirmation reads were not sent: a -deny-path rule keeps their paths out", denied))
		}
		if refused > 0 {
			deferNote = append(deferNote, fmt.Sprintf("advisories-confirm: %d confirmation reads were not sent: their targets are outside the scope", refused))
		}
		if stopped > 0 {
			deferNote = append(deferNote, fmt.Sprintf("advisories-confirm: %d confirmation reads were not sent: the run's limit stopped them", stopped))
		}
	}
	// Stored, one observation per lead, on its host's entity: the lines
	// below and in -json are these rows, and azhaq show lists them.
	now := time.Now().UTC()
	for _, lead := range leads {
		raw, _ := json.Marshal(lead)
		host := lead.Host
		typ := types.TypeHostname
		if host == "" {
			continue
		}
		ent, err := st.UpsertEntity(typ, host, now)
		if err != nil {
			continue
		}
		_, _ = st.AddObservation(ent.ID, types.Observation{
			Collector: "azhaq-advisories", Source: lead.URL, Kind: "advisory",
			Payload: raw, Confidence: 0.9, ObservedAt: now,
		})
	}
	var affected, notAffected, conditional, observed, inferred, claimed int
	for _, l := range leads {
		switch l.Label {
		case advisory.LabelAffected:
			affected++
		case advisory.LabelNotAffected:
			notAffected++
		case advisory.LabelConditional:
			conditional++
		}
		switch l.Confidence {
		case advisory.Observed:
			observed++
		case advisory.Inferred:
			inferred++
		case advisory.Claimed:
			claimed++
		}
	}
	note = fmt.Sprintf("advisories: %d leads (%d affected, %d not affected, %d conditional) from %d confirmed product versions against %d advisory records of %s; each lead is a stored advisory row and a line of the output, never a proven finding",
		len(leads), affected, notAffected, conditional, len(services), len(advs), fl.source)
	if fl.confirm {
		note += fmt.Sprintf("; confirmation: %d observed, %d inferred, %d claimed (range match only)", observed, inferred, claimed)
	}
	for _, n := range deferNote {
		note += "; " + n
	}
	return leads, failures, note
}

// isDenied says err is a -deny-path rule of the user's keeping a
// request out: the rule's doing, not a failure.
func isDenied(err error) bool {
	var d *neterr.Denied
	return errors.As(err, &d)
}

// isScopeRefusal says err is the egress chokepoint refusing a target the
// scope leaves out (by host, or by the port its -allow entry names).
func isScopeRefusal(err error) bool {
	return errors.Is(err, neterr.ErrOutOfScope) || errors.Is(err, neterr.ErrOutOfPort)
}

// isStop says err is a limit, not an answer: the request budget spent or
// the kill file. The read was not sent; the lead stays claimed.
func isStop(err error) bool {
	return errors.Is(err, neterr.ErrBudget) || errors.Is(err, neterr.ErrKilled)
}

// advisoryLeadsOf reads the leads a run stored, as ports prints them
// after the run that made them: the rows of the workspace, in the order
// they were matched.
func advisoryLeadsOf(obs []types.StoredObservation) []advisory.Lead {
	var out []advisory.Lead
	for _, o := range obs {
		if o.Collector != "azhaq-advisories" || o.Kind != "advisory" {
			continue
		}
		var lead advisory.Lead
		if json.Unmarshal(o.Payload, &lead) == nil {
			out = append(out, lead)
		}
	}
	return out
}

// leadRow is a lead as a -json line: the lead's fields and its type.
func leadRow(l advisory.Lead) map[string]any {
	raw, _ := json.Marshal(l)
	var row map[string]any
	_ = json.Unmarshal(raw, &row)
	row["type"] = "advisory"
	return row
}
