package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// verifyFlags is -verify, shared by run and ports (ports passes it to
// the run it makes). Off unless given: a plain run sends no
// verification read beyond naming a service.
type verifyFlags struct {
	on bool
}

func (v *verifyFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&v.on, "verify", false, "with the services this run confirmed: make each enumerated safe read-only verification (Redis INFO server, MongoDB isMaster, memcached version, each sent with no credential, and, with -advisories, each advisory lead labelled from its confirmation read) and label the results proved, version-only or conditional, each with the exact request sent and an excerpt of the answer; every read goes through the scope, -deny-path (for the advisory GET), -max-requests, the pace, the kill file and the ledger; no payload, no credential, no write and no request that tries to trigger an issue")
}

// verifyStage is the whole of -verify after a run. The data-store
// checks send one read each, through egress (scope, budget, pace,
// kill file, ledger, collector azhaq-verify); the advisory results
// send nothing more: they label the leads -advisories already made
// (and, with -advisories-confirm, already read for) as proved,
// version-only or conditional. Each result is stored as one
// observation of its host, so the summary's counts are derivable
// from the workspace: one stored result per line printed.
//
// A read the scope refuses, a -deny-path rule keeps out or a limit
// stops is a note, not a failure: those are the user's own settings.
// A read that gets no answer is a failure (exit 3), as a confirmation
// read that fails is.
func verifyStage(ctx context.Context, st *store.Store, obs []types.StoredObservation, leads []advisory.Lead, command string) (results []verify.Result, failures []engine.Failure, note string) {
	cctx := ledger.WithCollector(ctx, "azhaq-verify")
	dialer := egress.NewPortDialer(5*time.Second, nil, "", "")
	failed, refused, stopped := 0, 0, 0
	for _, svc := range advisory.ServicesAnyVersion(obs) {
		check, ok := verify.ForService(svc)
		if !ok {
			continue
		}
		host := svc.Host
		if host == "" {
			host = svc.IP
		}
		if err := egress.Current().CheckAddr(host, strconv.Itoa(svc.Port)); err != nil {
			refused++
			continue
		}
		if err := egress.Take(); err != nil {
			stopped++
			continue
		}
		if err := egress.Pace(ctx); err != nil {
			egress.Refund()
			stopped++
			continue
		}
		dial := func(ctx context.Context, host, ip string, port int) (net.Conn, error) {
			addrHost := ip
			if addrHost == "" {
				addrHost = host
			}
			return dialer.TCPDirect(ctx, host, net.JoinHostPort(addrHost, strconv.Itoa(port)))
		}
		r, err := check.Execute(cctx, svc, dial)
		if err != nil {
			failed++
			continue
		}
		r.Command = command
		results = append(results, r)
	}
	for _, lead := range leads {
		// The request is only carried when a confirmation read was
		// actually sent (a confidence was recorded); a lead that was
		// never read must not claim one.
		request := ""
		if lead.Confidence != "" {
			request = lead.ConfirmReq
		}
		if r, ok := verify.AdvisoryResult(lead, request); ok {
			r.Command = command
			results = append(results, r)
		}
	}
	now := time.Now().UTC()
	for _, r := range results {
		raw, _ := json.Marshal(r)
		if r.Host == "" {
			continue
		}
		ent, err := st.UpsertEntity(types.TypeHostname, r.Host, now)
		if err != nil {
			continue
		}
		src := r.Kind
		if r.AdvisoryID != "" {
			src = r.AdvisoryID
		}
		_, _ = st.AddObservation(ent.ID, types.Observation{
			Collector: "azhaq-verify", Source: src, Kind: "verify",
			Payload: raw, Confidence: 0.9, ObservedAt: now,
		})
	}
	if failed > 0 {
		failures = append(failures, engine.Failure{Collector: "azhaq-verify", Error: "a verification read got no answer", Count: failed, Retryable: true})
	}
	var proved, versionOnly, conditional int
	for _, r := range results {
		switch r.Label {
		case verify.Proved:
			proved++
		case verify.VersionOnly:
			versionOnly++
		case verify.Conditional:
			conditional++
		}
	}
	note = fmt.Sprintf("verify: %d results (%d proved, %d version-only, %d conditional) from the enumerated read-only checks; each result is a stored verify row and a line of the output, carries the exact request sent and an excerpt of the answer, and proved names that read only, never exploitability",
		len(results), proved, versionOnly, conditional)
	if refused > 0 {
		note += fmt.Sprintf("; %d verification reads were not sent: their targets are outside the scope", refused)
	}
	if stopped > 0 {
		note += fmt.Sprintf("; %d verification reads were not sent: the run's limit stopped them", stopped)
	}
	return results, failures, note
}

// verifyResultsOf reads the results a run stored, as ports prints
// them after the run that made them.
func verifyResultsOf(obs []types.StoredObservation) []verify.Result {
	var out []verify.Result
	for _, o := range obs {
		if o.Collector != "azhaq-verify" || o.Kind != "verify" {
			continue
		}
		var r verify.Result
		if json.Unmarshal(o.Payload, &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

// verifyRow is a result as a -json line: its fields and its type.
func verifyRow(r verify.Result) map[string]any {
	raw, _ := json.Marshal(r)
	var row map[string]any
	_ = json.Unmarshal(raw, &row)
	row["type"] = "verify"
	return row
}
