package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// verifyLoginsFlags is -verify-logins, shared by run and ports (ports
// passes it to the run it makes), off unless given.
type verifyLoginsFlags struct {
	on bool
}

func (v *verifyLoginsFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&v.on, "verify-logins", false, "with the services this run confirmed: for a product internal/verify's logins catalog names, one sign-in attempt per published default credential pair (each sourced to a vendor doc or an advisory), stopping at the first success and, for that host, at a lockout sign, a 429 or a captcha on the sign-in page; and, for a product whose own docs say a resource needs a sign-in, one GET of it with no credential compared with the same GET carrying a deliberately wrong credential, a finding only when the unauthenticated GET shows the protected content; `azhaq plan` lists every check the catalog has before anything is sent. Off by default. The sign-in attempts are the writes this flag asks for and no others; a password is never printed, only \"the published default\"; no session is kept after a check, and a logout is sent where the product has one. Every request goes through the scope, -deny-path, -max-requests, the pace and the kill file, and is a ledger line of the collector azhaq-verify-logins")
}

// loginsStage is the whole of -verify-logins after a run: for each web
// service the run confirmed, the catalog's sign-in attempts for its
// product (stopping at the first success, a lockout, a 429 or a
// captcha) and its unauthenticated-read checks. Every request goes
// through egress (scope, -deny-path, the budget, the pace, the kill
// file, the ledger), with the collector azhaq-verify-logins. A success
// is stored as one azhaq-verify observation, exactly as -verify's own
// results are, so it is one row of `azhaq show`, one line of findings
// and one entry of the summary's verify.
func loginsStage(ctx context.Context, st *store.Store, obs []types.StoredObservation, command string) (results []verify.Result, failures []engine.Failure, note string) {
	cctx := ledger.WithCollector(ctx, "azhaq-verify-logins")
	client := egress.TargetClient(egress.TargetOptions{Timeout: 15 * time.Second})
	doer := verify.HTTPDoer{Client: client, Spend: func(ctx context.Context) error { return egress.Spend(ctx) }}

	var loginsPlanned, loginsSucceeded, captchaSkipped, lockoutStopped int
	var readsPlanned, readsFound int
	var refused, denied, stopped, failed int

	note1 := func(err error) {
		switch {
		case isDenied(err):
			denied++
		case isScopeRefusal(err):
			refused++
		case isStop(err):
			stopped++
		default:
			failed++
		}
	}

	done := map[string]bool{} // origin + product already asked this run
	for _, svc := range loginWebServices(obs) {
		key := svc.Origin + "\x00" + loginsKey(svc.Product)
		if done[key] {
			continue
		}
		done[key] = true

		if pairs := verify.LoginsForProduct(svc.Product); len(pairs) > 0 {
			loginsPlanned++
			lg, outcome, _, err := verify.AttemptLogins(cctx, doer, svc.Origin, pairs)
			switch {
			case err != nil:
				note1(err)
			case outcome.CaptchaSkip:
				captchaSkipped++
			case outcome.Lockout:
				lockoutStopped++
			case outcome.Success:
				loginsSucceeded++
				if lg.Logout != nil {
					lg.Logout(egress.WithAsked(cctx), doer, svc.Origin, outcome.Cookie, outcome.Body)
				}
				r := verify.Result{
					Kind: verify.KindDefaultLogin, Label: verify.Proved,
					Host: svcHost(svc), Port: svc.Port, Target: svc.Target(),
					Service: svc.Service, Product: svc.Product, Version: svc.Version,
					URL: svc.Origin + lg.Path, Request: outcome.Request, Evidence: outcome.Excerpt,
					Command: command,
				}
				r.Severity = verify.SeverityOf(r)
				results = append(results, r)
			}
		}

		for _, u := range verify.ReadsForProduct(svc.Product) {
			readsPlanned++
			ok, request, evidence, err := u.Check(cctx, doer, svc.Origin)
			if err != nil {
				note1(err)
				continue
			}
			if !ok {
				continue
			}
			readsFound++
			r := verify.Result{
				Kind: verify.KindUnauthenticatedBypass, Label: verify.Proved,
				Host: svcHost(svc), Port: svc.Port, Target: svc.Target(),
				Service: svc.Service, Product: svc.Product, Version: svc.Version,
				URL: svc.Origin + u.Path, Request: request, Evidence: evidence,
				Command: command,
			}
			r.Severity = verify.SeverityOf(r)
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
		_, _ = st.AddObservation(ent.ID, types.Observation{
			Collector: "azhaq-verify", Source: r.Kind, Kind: "verify",
			Payload: raw, Confidence: 0.9, ObservedAt: now,
		})
	}
	if failed > 0 {
		failures = append(failures, engine.Failure{Collector: "azhaq-verify-logins", Error: "a sign-in attempt or an unauthenticated read got no answer", Count: failed, Retryable: true})
	}
	note = fmt.Sprintf("verify-logins: %d product(s) asked for a published default login (%d succeeded, %d stopped for a captcha, %d stopped for a lockout sign or a 429), %d unauthenticated-read check(s) asked (%d found the protected content with no credential)",
		loginsPlanned, loginsSucceeded, captchaSkipped, lockoutStopped, readsPlanned, readsFound)
	if denied > 0 {
		note += fmt.Sprintf("; %d requests were not sent: a -deny-path rule keeps their paths out", denied)
	}
	if refused > 0 {
		note += fmt.Sprintf("; %d requests were not sent: their targets are outside the scope", refused)
	}
	if stopped > 0 {
		note += fmt.Sprintf("; %d requests were not sent: the run's limit stopped them", stopped)
	}
	return results, failures, note
}

func svcHost(svc advisory.Service) string {
	if svc.Host != "" {
		return svc.Host
	}
	return svc.IP
}

func loginsKey(product string) string { return strings.ToLower(strings.TrimSpace(product)) }

// loginWebServices is the web services the run confirmed, for -verify-
// logins to match its catalog against: advisory.ServicesAnyVersion's own
// list (a port scan's web product, or a page's Server header and the
// technologies it names with a version), plus the technologies a page
// names with no version — a product -verify-logins may still have a
// catalog entry for, since its check does not need one.
func loginWebServices(obs []types.StoredObservation) []advisory.Service {
	out := advisory.ServicesAnyVersion(obs)
	seen := map[string]bool{}
	for _, s := range out {
		if s.Origin != "" {
			seen[s.Origin+"\x00"+loginsKey(s.Product)] = true
		}
	}
	add := func(s advisory.Service) {
		if s.Origin == "" || s.Product == "" {
			return
		}
		key := s.Origin + "\x00" + loginsKey(s.Product)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, s)
	}
	for _, o := range obs {
		if o.Collector != "azhaq-http" {
			continue
		}
		var row struct {
			URL  string   `json:"url"`
			Tech []string `json:"tech"`
		}
		if json.Unmarshal(o.Payload, &row) != nil || len(row.Tech) == 0 {
			continue
		}
		u, err := url.Parse(row.URL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		port := 0
		if p, err := strconv.Atoi(u.Port()); err == nil {
			port = p
		} else if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
		origin := u.Scheme + "://" + u.Host
		for _, t := range row.Tech {
			name, _, _ := strings.Cut(t, ":") // "Name" or "Name:version": the bare name either way
			if name == "" {
				continue
			}
			add(advisory.Service{Host: u.Hostname(), Port: port, Proto: "tcp", Service: u.Scheme, Product: name, Origin: origin})
		}
	}
	return out
}
