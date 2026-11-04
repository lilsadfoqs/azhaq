package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// A next pass is a wider pass than the one a finished command made, which it
// leaves to the user: the rest of the port range, the lookup of names the
// sources only listed, the writes a history holds. It is a labelled line in the
// summary's next, a command to copy with what it would send, counted as plan
// counts it. Nothing is run for it.

// allTCPPorts is every TCP port.
const allTCPPorts = 65535

// nextPass adds a next-pass line to the summary: the command, and why it is
// worth asking and what it costs.
func (r *report) nextPass(command, why string) {
	line := command + "   (next pass, not run: " + why + ")"
	if !slices.Contains(r.Next, line) {
		r.Next = append(r.Next, line)
	}
}

// moreOf is n with its unit, for a cost line: 64535 connects.
func moreOf(a amount) string { return a.String() }

// portsPass says, after a TCP scan that did not ask every port, what the rest
// of the range would ask and how many connects that is. asked is the ports
// each address was asked, addresses how many were scanned, open how many open
// ports the scan found. "" when every port was asked.
func portsPass(asked, addresses, open int) (why string, cost amount) {
	if asked <= 0 || asked >= allTCPPorts || addresses <= 0 {
		return "", amount{}
	}
	rest := allTCPPorts - asked
	cost = amount{Connects: int64(rest) * int64(addresses)}
	found := "no open port was found"
	if open > 0 {
		found = plural(open, "open port") + " found"
	}
	return fmt.Sprintf("the other %d of the %d TCP ports were not asked on %s: %s; %s in the %d asked",
		rest, allTCPPorts, nOf(addresses, "address", "addresses"), moreOf(cost), found, asked), cost
}

// portsPassCommand is the command that asks the whole port range of the
// targets of args, a ports command line: the same flags with -p full. "" when
// the targets are not on the command line (stdin).
func portsPassCommand(args []string, db string) string {
	rest := args
	for _, f := range []string{"p", "tp", "pf"} {
		rest = withoutFlag(rest, f)
	}
	rest = append(slices.Clone(rest), "-p", "full")
	if db != "" && !hasFlag(rest, "db") {
		rest = append(rest, "-db", db)
	}
	return "azhaq ports " + shellJoin(rest)
}

// portsRangeAsked is how many TCP ports each address is asked by a ports spec
// (as -ports and -p take it), 0 when it asks none.
func portsRangeAsked(spec string) int {
	ports, err := portscan.Ports(spec)
	if err != nil {
		return 0
	}
	return len(ports)
}

// livePass says, after a subs run that looked nothing up, what -live would
// ask: about two DNS queries (A and AAAA) for each name listed.
func livePass(names int) (why string, cost amount) {
	if names <= 0 {
		return "", amount{}
	}
	cost = amount{DNS: 2 * int64(names)}
	return fmt.Sprintf("%s listed by the sources were not looked up, so some may not exist; -live asks about %s", plural(names, "name"), moreOf(cost)), cost
}

// livePassCommand is the subs command line with -live.
func livePassCommand(args []string) string {
	return "azhaq subs " + shellJoin(append(slices.Clone(args), "-live"))
}

// hostsOf joins hosts for a ports command's -host.
func hostsOf(hosts []string) string { return strings.Join(hosts, ",") }

// writesPass says, after a roles run that replayed no write, what replaying
// the writes the histories hold would send: at least each write once with
// every other role's session. The reads of the owner's object around it are
// not counted: how many a write gets depends on the answers. "" when they
// hold none.
func writesPass(in rolesCostIn, own map[string]bool) (why string, cost amount) {
	in.methods = map[string]bool{"POST": true, "PUT": true, "PATCH": true}
	writes := 0
	for _, h := range in.hist {
		writes += len(historyWrites(h, in.sc, in.methods, own))
	}
	if writes == 0 || len(in.roles) < 2 {
		return "", amount{}
	}
	est := estimateRoles(in)
	for _, st := range est.Stages {
		if st.Stage == stageWrites {
			cost.add(*st.Estimate)
		}
	}
	return fmt.Sprintf("%s in the histories were not replayed with the other roles' sessions: at least %s more (one for each write and other role, a floor: the reads that check them come on top), and each changes data on the target", plural(writes, "write"), moreOf(cost)), cost
}

// writesPassCommand is the roles command line with -replay-writes, before
// the run options.
func writesPassCommand(args []string) string {
	i := slices.Index(args, "--")
	if i < 0 {
		i = len(args)
	}
	out := append(slices.Clone(args[:i]), "-replay-writes", "post,put,patch")
	return "azhaq roles " + shellJoin(append(out, args[i:]...))
}
