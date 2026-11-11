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
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// The flags of -advisories, shared by run and ports (ports passes them
// to the run it makes). Matching is on unless -advisories=false says
// otherwise, against the index azhaq carries and the user's -advisory-source;
// confirmation is off unless -advisories-confirm says so.
type advisoryFlags struct {
	on, confirm bool
	source      string
	builtin     bool // match the index azhaq carries (set by register; a literal without it matches the user's records only)
}

func (a *advisoryFlags) register(fs *flag.FlagSet) {
	a.builtin = true
	fs.BoolVar(&a.on, "advisories", true, "match the products and versions this run already confirmed against the advisory index azhaq carries (built from the CISA KEV catalogue and the NVD records of the products it fingerprints; `azhaq version` names its date) and the records of -advisory-source, as labelled leads (affected, not affected or conditional, each with its advisory id, URL and the version range): a pure lookup over what the run already holds, nothing more is sent to a target; -advisories=false turns it off")
	fs.BoolVar(&a.confirm, "advisories-confirm", false, "with -advisories: for each affected or conditional lead, also make the one benign read the advisory names (a GET of its documented version or info path, or of / to read the version it states): no payload, no login, no state change, never a request that could trigger the issue; each read is in the ledger and counts against -max-requests, and each lead is labelled observed, inferred or claimed (with -advisories; reads only within the run's scope: the targets given, -allow or -scope)")
	fs.StringVar(&a.source, "advisory-source", "", "your own advisory records to match as well as the built-in index, OSV JSON (a record, a list, {\"vulns\": [...]}, or JSON lines): a file (works offline), or an http(s) URL asked once as a third-party source; azhaq fetches none it was not given")
}

// check is the usage half of the flags, before anything is sent: a
// confirmation needs the match, a source needs the match, the source
// must be one it can read, and a confirmation needs a scope (the
// caller's targets stand for one, as they do for the other active
// techniques).
func (a advisoryFlags) check() error {
	switch {
	case a.confirm && !a.on:
		return usagef("-advisories-confirm confirms the matches of -advisories, which is off: drop -advisories=false")
	case a.source != "" && !a.on:
		return usagef("-advisory-source adds records to the matching of -advisories, which is off: drop -advisories=false")
	case a.source != "" && !isURL(a.source):
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
		fetch.BoundNote(resp, "advisory source "+req.URL.Host) // a stream that never ends is cut, and the run says so
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
	var advs []advisory.Advisory
	if fl.source != "" {
		var err error
		if advs, err = loadAdvisories(ctx, fl.source); err != nil {
			failures = append(failures, engine.Failure{Collector: "azhaq-advisories", Error: err.Error(), Count: 1})
			if !fl.builtin {
				return nil, failures, ""
			}
		}
	}
	byID := map[string]advisory.Advisory{}
	for _, a := range advs {
		byID[a.ID] = a
	}
	services := advisory.Services(obs)
	// The built-in index is read only when there is a service to look up:
	// a run that confirmed no product and version has nothing to match.
	var ix *advisory.Index
	if fl.builtin && len(services) > 0 {
		var err error
		if ix, err = advisory.Builtin(); err != nil {
			failures = append(failures, engine.Failure{Collector: "azhaq-advisories", Error: "the built-in advisory index: " + err.Error(), Count: 1})
		}
	}
	all, quiet, err := advisory.MatchAll(services, advs, ix)
	if err != nil {
		failures = append(failures, engine.Failure{Collector: "azhaq-advisories", Error: "the built-in advisory index: " + err.Error(), Count: 1})
	}
	if fl.source == "" && ix == nil && len(failures) == 0 && len(services) == 0 {
		return nil, nil, ""
	}
	// One lead a service: the advisories of a product and version are one
	// line, with the count by label and the list in the lead's fields.
	leads = advisory.Group(all)
	var deferNote []string
	var reads int
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
		// One read for each origin and path, whatever the number of advisories
		// that name it: each is judged against the answer. A read that was
		// refused or failed is counted once, and its answer stands for them all.
		type readKey struct{ origin, path string }
		type readResult struct {
			sig  advisory.Signal
			err  error
			text string // what a lead that was not read says
		}
		cache := map[readKey]readResult{}
		for i := range leads {
			lead := &leads[i]
			svc := svcByTarget[lead.Target+"\x00"+lead.Product]
			for j := range lead.Advisories {
				ref := &lead.Advisories[j]
				read, conf := "nothing read: a range match only", advisory.Claimed
				if ref.Label != advisory.LabelNotAffected {
					adv := byID[ref.ID]
					if ref.Index && ix != nil {
						adv, _ = ix.Advisory(lead.Product, ref.ID)
					}
					if c, why, no := advisory.NoRead(svc); no {
						conf, read = c, why
					} else {
						path := adv.ReadPath()
						k := readKey{svc.Origin, path}
						res, seen := cache[k]
						if !seen {
							res.sig, res.err = confirmer.Read(cctx, svc, path)
							reads++
							switch {
							case res.err == nil:
							case isDenied(res.err):
								// A -deny-path rule of the user's keeps the read out:
								// a note, not a failure, and the lead stays claimed.
								denied++
								res.text = "not read: " + res.err.Error() + " (a -deny-path rule of yours keeps its path out)"
							case isScopeRefusal(res.err):
								// A scope that refuses a target is a note, not a failure:
								// the scope is the user's, and the lead stays claimed.
								refused++
								res.text = "not read: outside the scope (-allow, -scope)"
							case isStop(res.err):
								stopped++
								res.text = "not read: " + res.err.Error()
							default:
								failed++
								res.text = "the confirmation read failed: " + res.err.Error()
							}
							cache[k] = res
						}
						if res.err == nil {
							conf, read = res.sig.Judge(adv, svc)
							ref.ConfirmReq = "GET " + path
						} else {
							read = res.text
						}
					}
				}
				ref.Confidence = conf
				if j == 0 {
					lead.Confidence, lead.Read = conf, read
				} else if read != lead.Read {
					ref.Read = read // only where it says something the lead's does not
				}
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
	// Stored, one observation per service lead, on its host's entity: the
	// lines below and in -json are these rows, and azhaq show lists them.
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
	var matches, affected, notAffected, conditional, kev, observed, inferred, claimed int
	for _, l := range leads {
		matches += len(l.Advisories)
		affected += l.Counts[advisory.LabelAffected]
		notAffected += l.Counts[advisory.LabelNotAffected]
		conditional += l.Counts[advisory.LabelConditional]
		kev += l.KEVCount
		for _, r := range l.Advisories {
			switch r.Confidence {
			case advisory.Observed:
				observed++
			case advisory.Inferred:
				inferred++
			case advisory.Claimed:
				claimed++
			}
		}
	}
	against := ""
	if ix != nil {
		m := ix.Meta()
		against = fmt.Sprintf("the %s", m.Label())
	}
	if fl.source != "" {
		if against != "" {
			against += " and "
		}
		against += fmt.Sprintf("%d advisory records of %s", len(advs), fl.source)
	}
	note = fmt.Sprintf("advisories: %d leads, one for each of %d confirmed product versions, holding %d advisories (%d affected, %d not affected, %d conditional; %d of those that apply on the CISA KEV catalogue) against %s; each lead is a stored advisory row and a line of the output, never a proven finding",
		len(leads), len(services), matches, affected, notAffected, conditional, kev, against)
	if quiet > 0 {
		note += fmt.Sprintf("; %d more not-affected records of the index matched a product seen and are not listed (the version is outside their ranges and none is on the CISA KEV catalogue)", quiet)
	}
	if fl.confirm {
		note += fmt.Sprintf("; confirmation: %d reads for %d advisories: %d observed, %d inferred, %d claimed (range match only)", reads, matches, observed, inferred, claimed)
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
	return advisoryLeadsIn(obs, false)
}

// advisoryLeadsExpanded is the stored leads with each advisory a lead of
// its own: the findings list them all.
func advisoryLeadsExpanded(obs []types.StoredObservation) []advisory.Lead {
	return advisoryLeadsIn(obs, true)
}

func advisoryLeadsIn(obs []types.StoredObservation, expand bool) []advisory.Lead {
	var out []advisory.Lead
	for _, o := range obs {
		if o.Collector != "azhaq-advisories" || o.Kind != "advisory" {
			continue
		}
		var lead advisory.Lead
		if json.Unmarshal(o.Payload, &lead) == nil {
			if expand {
				out = append(out, lead.Expand()...)
			} else {
				out = append(out, lead)
			}
		}
	}
	return out
}

// advisoryPlan is what a plan says of the matching: the index in use with
// its date and size, any records of the user's added, and that the match
// is a lookup over what the run confirms. Off, it says so.
func advisoryPlan(fl advisoryFlags) string {
	if !fl.on {
		return "off (-advisories=false): no product and version is matched against advisories"
	}
	var parts []string
	if fl.builtin {
		if m, err := advisory.BuiltinMeta(); err == nil {
			parts = append(parts, m.Label())
		} else {
			parts = append(parts, "advisory index unreadable: "+err.Error())
		}
	}
	if fl.source != "" {
		parts = append(parts, "your records of "+fl.source)
	}
	return strings.Join(parts, " and ") + "; each product and version the run confirms is matched as a lookup that sends nothing"
}
