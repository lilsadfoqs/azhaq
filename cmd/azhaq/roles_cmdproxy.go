package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/scope"
)

// rolesCmd is how roles runs the commands of -role-cmd: through a loopback
// proxy of azhaq's (egress.CmdProxy) so their requests are held to the scope
// and the budget and listed in the ledger, or with none under
// -role-cmd-direct. cmdRoles sets it; runs counts what each command sent.
var rolesCmd struct {
	direct bool
	scope  egress.CmdScope
	runs   map[string]*cmdRunStats
	order  []string
}

// cmdRunStats is what one role's command did over the command's life.
type cmdRunStats struct {
	runs     int
	requests int64
	refused  int
	direct   bool
}

func (s *cmdRunStats) add(requests int64, refused bool) {
	s.runs++
	s.requests += requests
	if refused {
		s.refused++
	}
}

func resetRolesCmd(direct bool, sc egress.CmdScope) {
	rolesCmd.direct, rolesCmd.scope = direct, sc
	rolesCmd.runs, rolesCmd.order = map[string]*cmdRunStats{}, nil
}

func cmdStatsOf(name string) *cmdRunStats {
	if rolesCmd.runs == nil {
		rolesCmd.runs = map[string]*cmdRunStats{}
	}
	s := rolesCmd.runs[name]
	if s == nil {
		s = &cmdRunStats{direct: rolesCmd.direct}
		rolesCmd.runs[name] = s
		rolesCmd.order = append(rolesCmd.order, name)
	}
	return s
}

// cmdProxyScope is what a command's requests are held to: the scope the
// run holds. With no -allow, -deny or -scope that is the -url targets' hosts
// held to their ports and no more (a sign-in may go to an identity provider
// the user named nowhere); with a rule, the rule, as roles holds the headers
// of its roles to it.
func cmdProxyScope(runArgs []string, rules scope.Rules) egress.CmdScope {
	var s egress.CmdScope
	if hasFlag(runArgs, "allow", "deny", "scope") {
		if !rules.Empty() {
			s.Allow, s.AllowAddr = rules.Allows, rules.AllowsAddr
		}
	} else {
		var urls, bare []string
		for _, v := range runFlagValues(runArgs, "url") {
			switch u, err := url.Parse(v); {
			case err == nil && u.Scheme != "" && u.Host != "":
				urls = append(urls, v)
			case err == nil && strings.Contains(v, ":") && !strings.Contains(v, "/"):
				urls = append(urls, "http://"+v)
			default:
				bare = append(bare, v)
			}
		}
		s.TargetPorts = scope.TargetPorts(urls, bare)
	}
	if len(rules.DenyPath) > 0 {
		s.DenyPath = rules.DeniedPath
	}
	return s
}

// roleCmdNotes are the lines the summary says of the commands that ran:
// which went through the proxy, how many requests each sent, and what the
// proxy does not see.
func roleCmdNotes() []string {
	var out []string
	for _, name := range rolesCmd.order {
		s := rolesCmd.runs[name]
		if s.direct {
			out = append(out, fmt.Sprintf("role %s: its -role-cmd ran with -role-cmd-direct, with no proxy: its own requests are not in the ledger and not held to the scope, the budget or the pace", name))
			continue
		}
		line := fmt.Sprintf("role %s: its -role-cmd ran through azhaq's loopback proxy (HTTP_PROXY, HTTPS_PROXY): %s in %s, held to the scope, the budget and the pace and listed in the ledger", name,
			nOf(int(s.requests), "request", "requests"), nOf(s.runs, "run", "runs"))
		if s.refused > 0 {
			line += fmt.Sprintf("; %s refused", nOf(s.refused, "run had a request", "runs had a request"))
		}
		out = append(out, line+"; a request it makes without honouring the proxy variables is outside the ledger")
	}
	return out
}

// roleCmdPlan says what the roles' commands would be run through: plan runs
// none, so it cannot say how many requests they send.
func roleCmdPlan(roles []role, direct bool) []string {
	var out []string
	for _, r := range roles {
		switch {
		case r.cmd == "":
		case direct:
			out = append(out, fmt.Sprintf("role %s: its -role-cmd would run with -role-cmd-direct, with no proxy: its own requests are not counted, held to the scope or listed in the ledger", r.name))
		default:
			out = append(out, fmt.Sprintf("role %s: its -role-cmd would run through azhaq's loopback proxy (HTTP_PROXY, HTTPS_PROXY): its requests are held to the scope, the budget and the pace and listed in the ledger, and counted in requests; how many it sends is the command's own, not known before it runs", r.name))
		}
	}
	return out
}
