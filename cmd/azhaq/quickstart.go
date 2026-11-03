package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/normalize"
)

// The guided first map: azhaq TARGET, or azhaq quickstart TARGET. It is the
// scoped default `azhaq run` of one target, said first: the plan, with what it
// will send, then the map, then the commands that go deeper in the workspace.
// It is not another mode: what it sends is what `azhaq run` with the same
// flags sends, and its map is that run's.

// guidedTarget says whether arg is a target for the guided run, and as which
// run flag: a URL with a scheme (-url), an address (-cidr) or a name with a dot
// (-domain). A word that is a file in the current directory, or has no dot, is
// not: it is an unknown command.
func guidedTarget(arg string) (kind, value string, ok bool) {
	if arg == "" || strings.HasPrefix(arg, "-") {
		return "", "", false
	}
	if strings.Contains(arg, "://") {
		u, err := url.Parse(arg)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return "", "", false
		}
		return "-url", arg, true
	}
	if ip := net.ParseIP(arg); ip != nil {
		if ip.To4() != nil {
			return "-cidr", arg + "/32", true
		}
		return "-cidr", arg + "/128", true
	}
	if strings.ContainsAny(arg, "/:@ ") || !strings.Contains(arg, ".") || strings.HasSuffix(arg, ".") {
		return "", "", false
	}
	host := normalize.Hostname(arg)
	if host == "" {
		return "", "", false
	}
	if _, err := os.Stat(arg); err == nil {
		return "", "", false
	}
	return "-domain", host, true
}

// cmdQuickstart is azhaq quickstart TARGET [run flags].
func cmdQuickstart(args []string) error {
	if len(args) > 0 && args[0] == "quickstart" {
		args = args[1:]
	}
	fs := newFlags("quickstart")
	var names []string
	runFlags().VisitAll(func(f *flag.Flag) {
		if !strings.HasPrefix(f.Usage, "internal:") {
			names = append(names, f.Name)
		}
	})
	given := inherit(fs, names...)
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usagef("give the one target to map: azhaq quickstart example.com, or azhaq quickstart https://app.example.com/")
	}
	arg := fs.Arg(0)
	kind, value, ok := guidedTarget(arg)
	if !ok {
		return usagef("%q is not a target for a first map: give a name such as example.com, an address, or a URL with its scheme such as https://app.example.com/ (a host with a port needs the URL form)", arg)
	}
	flags := given()
	runArgs := append([]string{kind, value}, flags...)
	if !hasFlag(flags, "quiet", "json") {
		var plan runPlan
		if err := mapTarget(runArgs, newReport("plan"), &runOut{embedded: true, plan: true, planInto: &plan}); err != nil {
			return err
		}
		w := os.Stderr
		fmt.Fprintf(w, "azhaq: a first map of %s. The plan comes first; nothing is sent until it is printed.\n", value)
		printPlanText(w, plan)
		fmt.Fprintf(w, "azhaq: mapping now, as `azhaq run %s` does: the scope is the target given (-allow widens it), no wordlist, port scan or login (each is a flag of run, and the lines at the end say what they would cost)\n", shellJoin(runArgs))
	}
	rep := newReport("run")
	out := runOut{estimated: true}
	if err := mapTarget(runArgs, rep, &out); err != nil {
		return err
	}
	deeper(rep, runArgs)
	return rep.finish(out.json, false)
}

// deeper adds to the summary the commands that go on from the map: read the
// workspace, and the wider passes, each with what it would send.
func deeper(rep *report, runArgs []string) {
	if rep.DB == "" {
		return
	}
	db := rep.DB
	rep.Next = append(rep.Next,
		"azhaq hunt -db "+db+"   (go deeper: the routes, hosts and files of this map ranked, each with its evidence)",
		"azhaq query -db "+db+" -type URL   (go deeper: ask the workspace a precise question; azhaq show -db "+db+" URL lists everything known about one row)",
	)
	if !hasFlag(runArgs, "ports") {
		rep.Next = append(rep.Next, passLine(runArgs, db, "-ports", "top-1000", "the 1000 most common TCP ports of each address"))
	}
	if !hasFlag(runArgs, "dirs") {
		rep.Next = append(rep.Next, passLine(runArgs, db, "-dirs", "@common", "each word of the built-in wordlist under each web service"))
	}
	rep.Next = slices.DeleteFunc(rep.Next, func(s string) bool { return s == "" })
}

// passLine is a deeper pass of the first map: run with the flag added, and
// what it adds to the estimate, counted as plan counts it.
func passLine(runArgs []string, db, flagName, value, what string) string {
	with := append(slices.Clone(runArgs), flagName, value)
	var base, wide runPlan
	if mapTarget(runArgs, newReport("plan"), &runOut{embedded: true, plan: true, planInto: &base}) != nil ||
		mapTarget(with, newReport("plan"), &runOut{embedded: true, plan: true, planInto: &wide}) != nil {
		return ""
	}
	var more amount
	more.Requests = wide.Estimate.Total.Requests - base.Estimate.Total.Requests
	more.Connects = wide.Estimate.Total.Connects - base.Estimate.Total.Connects
	if more.Requests <= 0 && more.Connects <= 0 {
		return ""
	}
	cmd := "azhaq run " + shellJoin(append(with, "-db", db))
	return cmd + "   (next pass, not run: " + what + "; adds " + more.String() + ", before what the answers lead to)"
}
