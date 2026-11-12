package main

import (
	"encoding/json"
	"net"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/takeover"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/types"
)

// danglingKind is the kind of the finding for a CNAME that points at a name
// that answered NXDOMAIN: what was measured, with no claim about who may take
// the name (that is the takeover lead's, when the target is on a provider list).
const danglingKind = "dangling-dns"

// danglingRecords are the dangling-dns findings of a workspace: each name
// whose DNS answer showed a CNAME chain ending at a name that answered
// NXDOMAIN, one per name, from the latest answer.
func danglingRecords(obs []types.StoredObservation, command string) []findingRecord {
	type seen struct {
		dg takeover.Dangling
		at string
	}
	byHost := map[string]seen{}
	for _, o := range obs {
		if o.Collector != "azhaq-dns" {
			continue
		}
		var p struct {
			FQDN     string             `json:"fqdn"`
			Dangling *takeover.Dangling `json:"dangling"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Dangling == nil || p.Dangling.Target == "" {
			continue
		}
		host := normalize.Hostname(p.FQDN)
		if host == "" {
			continue
		}
		byHost[host] = seen{*p.Dangling, stamp(o.ObservedAt)}
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	out := make([]findingRecord, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, danglingRecord(h, byHost[h].dg, byHost[h].at, command))
	}
	return out
}

// danglingRecord is the finding for one name: the chain, the answer and the
// resolver that gave it, and the dig command that asks again.
func danglingRecord(host string, dg takeover.Dangling, at, command string) findingRecord {
	chain := host + " -> " + strings.Join(dg.Chain, " -> ")
	gave := ""
	if dg.Server != "" {
		gave = " from " + dg.Server
	}
	evidence := "observed: " + host + " is a CNAME to " + dg.Chain[0] + " (chain " + chain + "); " + dg.Target + " answered " + dg.Rcode + gave +
		". Whether anyone can create that name was not tested"
	excerpt := chain + "; status: " + dg.Rcode + " at " + dg.Target
	if dg.Server != "" {
		excerpt += " (server " + dg.Server + ")"
	}
	p := &proof.Proof{ObservedAt: at, Method: "dns A", Target: host, Excerpt: excerpt, ExcerptPart: "dns",
		How: "azhaq-dns", Reproduce: digCommand(host, dg.Server)}
	return findingRecord{Tier: proof.TierFinding, Kind: danglingKind, Label: verify.Proved, Severity: "low", Host: host,
		Request: "dns A " + host, Evidence: evidence, Command: command, Collector: "azhaq-dns", Proof: p}
}

// digCommand asks the resolver that gave the answer for the name's A record
// and prints the status and the chain, as azhaq read them.
func digCommand(host, server string) string {
	args := []string{"dig"}
	if server != "" {
		h, port, err := net.SplitHostPort(server)
		if err != nil {
			h, port = strings.Trim(server, "[]"), ""
		}
		args = append(args, "@"+h)
		if port != "" && port != "53" {
			args = append(args, "-p", port)
		}
	}
	return strings.Join(append(args, "+noall", "+comments", "+answer", "A", proof.Quote(host)), " ")
}
