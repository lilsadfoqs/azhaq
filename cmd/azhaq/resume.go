package main

import (
	"encoding/json"
	"fmt"
	"github.com/lilsadfoqs/azhaq/internal/collectors/httpcol"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/collectors/dirscol"
	"github.com/lilsadfoqs/azhaq/internal/scopefile"
	"github.com/lilsadfoqs/azhaq/store"
)

// cmdResume continues the latest run of a database that has tasks left:
// one interrupted, or stopped by -max-requests, a daily budget or
// -max-items. The run's options are read back from the database; session
// values are not stored and are given again after -db:
//
//	azhaq resume -db app.db [-cookie session=… | -login-pass …] [-max-items 4096]
//
// What the resume is told to leave out (-skip, -passive) applies to the
// tasks the run kept as well as to new ones.
func cmdResume(args []string) error {
	db := ""
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-db" || a == "--db":
			if i+1 < len(args) {
				db = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-db=") || strings.HasPrefix(a, "--db="):
			db = a[strings.Index(a, "=")+1:]
		default:
			rest = append(rest, a)
		}
	}
	retry := hasFlag(rest, "retry-failed")
	rest = dropBoolFlag(rest, "retry-failed")
	retryRun, _ := flagValue(rest, "retry-run")
	rest = dropFlag(rest, "retry-run")
	if retryRun != "" && !retry {
		return usagef("-retry-run picks the run -retry-failed asks again: add -retry-failed")
	}
	if db == "" {
		return usagef("give -db FILE, the database of the run to continue (run options to add, such as -cookie or -login-pass, may follow)")
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		return err
	}
	// A stopped fuzz run keeps the command that goes on from where it was.
	if raw := st.GetMeta(fuzzResumeKey); raw != "" {
		var args []string
		if json.Unmarshal([]byte(raw), &args) == nil && len(args) > 0 {
			fuzzSkip = nil
			if raw := st.GetMeta(fuzzAskedKey); raw != "" {
				var a fuzzAsked
				if json.Unmarshal([]byte(raw), &a) == nil && len(a.Spans) > 0 {
					fuzzSkip = &a
				}
			}
			fuzzDropped, fuzzStored = storedDropped(st), slices.Clone(args)
			st.Close()
			fuzzResuming = true
			// The stored command has no -db (and no secret): the workspace is this one.
			return cmdFuzz(append(append(args, "-db", db), fuzzSpelling(rest)...))
		}
	}
	var retryable int
	var retryHint string
	retriedID := ""
	if retry {
		n, run, err := retryFailed(st, db, retryRun)
		if err != nil {
			st.Close()
			return err
		}
		retriedID = run
		if !wantsJSON(rest) {
			fmt.Fprintf(os.Stderr, "azhaq: -retry-failed: %d failed targets of run %s will be asked again\n", n, run)
		}
	} else {
		retryable, retryHint = retryableIn(st, db)
	}
	var id string
	var runArgs []string
	var left int
	var ok bool
	if retriedID != "" {
		// The run whose targets were reopened, whichever run is the newest.
		id = retriedID
		runArgs, left, ok, err = st.ResumableRun(id)
	} else {
		id, runArgs, left, ok, err = st.Resumable()
	}
	deeper := false
	if err == nil && !ok {
		id, runArgs, left, deeper = pastDepth(st, rest)
		ok = deeper
	}
	command := ""
	if ok {
		command = st.GetMeta("command:" + id)
		if command == "subs" {
			keepSubsAnswers(st, id) // the sources that answered are not asked again
		}
	}
	st.Close()
	if err != nil {
		return err
	}
	if !ok && retryable > 0 {
		return fmt.Errorf("no task left in %s, but %d failed targets are retryable: %s (azhaq query -db %s -failed lists them)", db, retryable, retryHint, db)
	}
	if !ok {
		return fmt.Errorf("nothing to resume in %s: every run finished", db)
	}
	if !wantsJSON(rest) {
		if deeper {
			fmt.Fprintf(os.Stderr, "azhaq: resuming run %s of %s with a larger -depth, %d seeds found past its own to ask\n", id, db, left)
		} else {
			fmt.Fprintf(os.Stderr, "azhaq: resuming run %s of %s, %d tasks known and not done\n", id, db, left)
			if retryable > 0 {
				fmt.Fprintf(os.Stderr, "azhaq: %d failed targets are retryable: %s\n", retryable, retryHint)
			}
		}
	}
	runArgs, gone := dropRemovedFlags(runArgs)
	if len(gone) > 0 && !wantsJSON(rest) {
		fmt.Fprintf(os.Stderr, "azhaq: the run was started with %s, which azhaq no longer has: %s; ignored\n", strings.Join(gone, ", "), removedWhy(gone))
	}
	// A flag that takes one value, given to resume, replaces the stored one.
	for _, name := range []string{"list", "in", "org"} {
		if hasFlag(rest, name) {
			runArgs = dropFlag(runArgs, name)
		}
	}
	if !hasFlag(rest, "list") {
		if runArgs, err = listFromWorkspace(db, id, runArgs); err != nil {
			return err
		}
	}
	rest = runSpelling(command, rest)
	switch command {
	case "ports":
		return resumePorts(db, id, runArgs, rest)
	case "dirs":
		return resumeDirs(db, id, runArgs, rest)
	}
	if command != "" && command != "run" && !hasFlag(rest, "quiet") {
		// The drop-in hushed its run to print its own rows: here the rows
		// are the map's.
		runArgs = slices.DeleteFunc(slices.Clone(runArgs), func(a string) bool { return a == "-quiet" })
	}
	runArgs, rest = mergeSkip(runArgs, rest)
	// Later options win: what is given now overrides what was stored.
	all := append(append(append([]string(nil), runArgs...), rest...), "-db", db, "-resume-run", id)
	if command == "" {
		command = "run"
	}
	return cmdRunAs(command, all)
}

// retried are the failed targets a -retry-failed resume asked again: the
// run's summary says how many still fail; retriedRun is the run they were
// asked again in.
var (
	retried    []engine.FailedTarget
	retriedRun string
)

// retryFailed makes a run of the workspace (the one named, else the newest)
// ask again the failed targets a later try may fix, and gives how many there
// are and the run.
func retryFailed(st *store.Store, db, want string) (int, string, error) {
	runs, err := st.Runs()
	if err != nil {
		return 0, "", err
	}
	if len(runs) == 0 {
		return 0, "", fmt.Errorf("nothing to retry in %s: it holds no run", db)
	}
	run, err := pickRun(runs, want)
	if err != nil {
		return 0, "", err
	}
	st.UseRun(run.ID)
	if c := st.GetMeta("command:" + st.RunID()); c == "ports" || c == "dirs" {
		return 0, "", usagef("-retry-failed does not apply to a %s run: azhaq resume alone continues its unfinished sweep", c)
	}
	ents, err := st.Entities()
	if err != nil {
		return 0, "", err
	}
	obs, err := st.Observations()
	if err != nil {
		return 0, "", err
	}
	r, err := engine.RetryFailed(st, ents, obs)
	if err != nil {
		return 0, "", err
	}
	if r.Targets == 0 {
		msg := fmt.Sprintf("nothing to retry in run %s of %s: no failed target is retryable (azhaq query -db %s -failed -run %s lists the failures and says which are)", run.ID, db, db, run.ID)
		if want == "" {
			if n := otherRunsNote(db, earlierFailures(st, runs, run.ID), true); n != "" {
				msg += "; " + n
			}
		}
		return 0, "", fmt.Errorf("%s", msg)
	}
	retried, retriedRun = r.Asked, run.ID
	return r.Targets, run.ID, nil
}

// retryableIn counts the failed targets of the newest run of the workspace
// that a later try may fix, with the command that asks them again; when the
// newest has none, the count and command are those of the newest earlier run
// that has some.
func retryableIn(st *store.Store, db string) (int, string) {
	runs, err := st.Runs()
	if err != nil || len(runs) == 0 {
		return 0, ""
	}
	newest := runs[len(runs)-1].ID
	st.UseRun(newest)
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	if n := engine.RetryableTargets(ents, obs); n > 0 {
		return n, "azhaq resume -db " + db + " -retry-failed asks them again"
	}
	for _, r := range earlierFailures(st, runs, newest) {
		if r.Retryable > 0 {
			return r.Retryable, fmt.Sprintf("in run %s: azhaq resume -db %s -retry-failed -retry-run %s asks them again", r.Run, db, r.Run)
		}
	}
	return 0, ""
}

// mergeSkip makes the -skip given to a resume add to the one the run was
// started with: a collector it skipped stays skipped.
func mergeSkip(stored, given []string) ([]string, []string) {
	now, ok := flagValue(given, "skip")
	was, had := flagValue(stored, "skip")
	if !ok || !had || was == "" {
		return stored, given
	}
	return dropFlag(stored, "skip"), append(dropFlag(given, "skip"), "-skip="+was+","+now)
}

// pastDepth finds the run to continue when none has tasks left: the latest
// one, when a -depth larger than its own is given and it found seeds past
// its own, which the larger -depth asks.
func pastDepth(st *store.Store, rest []string) (id string, args []string, left int, ok bool) {
	v, given := flagValue(rest, "depth")
	n, err := strconv.Atoi(v)
	runs, _ := st.Runs()
	if !given || err != nil || len(runs) == 0 {
		return "", nil, 0, false
	}
	id = runs[len(runs)-1].ID
	st.UseRun(id)
	stats, _ := st.Stats()
	seeds, _ := st.LoadLeftover()
	if max(n, 1) <= max(stats.Depth, 1) || len(seeds) == 0 {
		return "", nil, 0, false
	}
	return id, st.RunArgs(), len(seeds), true
}

// dropBoolFlag is args without a flag that takes no value, whatever follows it.
func dropBoolFlag(args []string, name string) []string {
	return slices.DeleteFunc(slices.Clone(args), func(a string) bool {
		k, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		return strings.HasPrefix(a, "-") && k == name
	})
}

// dropFlag is args without the flag name, as -name=value or -name value.
func dropFlag(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		k, _, inline := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if strings.HasPrefix(args[i], "-") && k == name {
			if !inline && i+1 < len(args) {
				i++
			}
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// listFromWorkspace points the stored run's -list at the copy the
// workspace keeps: the file may be gone (stdin, the temporary list a
// command such as dirs or probe wrote and removed) or changed since, and
// a resumed run continues the targets it started with. A -list given to
// azhaq resume replaces it.
func listFromWorkspace(db, id string, args []string) ([]string, error) {
	out := append([]string(nil), args...)
	for i := 0; i < len(out); i++ {
		name, val, inline := strings.Cut(strings.TrimLeft(out[i], "-"), "=")
		if name != "list" || !strings.HasPrefix(out[i], "-") {
			continue
		}
		at := i
		if !inline {
			if i+1 >= len(out) {
				break
			}
			at, val = i+1, out[i+1]
		}
		st, err := store.OpenExisting(db)
		if err != nil {
			return nil, err
		}
		kept := st.GetMeta("list:" + id)
		st.Close()
		if kept == "" {
			if _, err := os.Stat(val); val != "-" && err == nil {
				continue // a run from before workspaces kept their lists
			}
			return nil, fmt.Errorf("the run's target list %s is gone and %s keeps no copy of it: give it again with -list FILE", val, db)
		}
		if now, err := loadLines(val); err == nil && val != "-" && strings.Join(now, "\n") != kept {
			fmt.Fprintf(os.Stderr, "azhaq: %s changed since the run started; resuming the targets the run started with (give -list to use the file as it is now)\n", val)
		}
		storedList = strings.Split(kept, "\n")
		if inline {
			out[i] = "-list=@run"
		} else {
			out[at] = "@run"
		}
	}
	return out, nil
}

// removedFlags are options of earlier versions: -all-gets and -get-words
// held back GETs by their names, which azhaq no longer does; -cloud read
// seeds from an inventory file, which -l does. A stored run that has them
// goes on without.
var removedFlags = map[string]bool{"all-gets": false, "get-words": true, "cloud": true} // true: takes a value

// removedWhy says what replaces the removed flags that were found.
func removedWhy(gone []string) string {
	var why []string
	for _, g := range gone {
		w := "every GET found in scope is requested, whatever its name says"
		if g == "-cloud" {
			w = "-l FILE takes its domains, hosts and URLs, one per line"
		}
		if !slices.Contains(why, w) {
			why = append(why, w)
		}
	}
	return strings.Join(why, "; ")
}

// dropRemovedFlags is args without the removed flags, and their names.
func dropRemovedFlags(args []string) (out, gone []string) {
	for i := 0; i < len(args); i++ {
		name, _, inline := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		takes, removed := removedFlags[name]
		if !strings.HasPrefix(args[i], "-") || !removed {
			out = append(out, args[i])
			continue
		}
		gone = append(gone, "-"+name)
		if takes && !inline && i+1 < len(args) {
			i++
		}
	}
	return out, gone
}

// keptArgs are the run options stored for azhaq resume: everything but the
// database and the values that carry a session or a secret (cookies, a
// password, the worker token, headers whose name sounds like a
// credential). A -scope file is kept by its full path, so a resume or an
// export started in another directory reads the same file.
func keptArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
			continue
		}
		takesValue := !inline && i+1 < len(args)
		switch name {
		case "db", "resume-run", "cookie", "login-pass", "worker-token", "retry-failed", "retry-run":
			if takesValue {
				i++
			}
			continue
		case "proxy", "source-proxy", "chrome-proxy", "urls-proxy", "port-proxy":
			// A proxy's password is a secret: the proxy is kept without it.
			if !inline && takesValue {
				val = args[i+1]
				i++
			}
			out = append(out, "-"+name+"="+withoutUserinfo(val))
			continue
		case "header", "H":
			if !inline && takesValue {
				val = args[i+1]
				i++
			}
			if secretHeader(val) {
				continue
			}
			out = append(out, "-header="+val)
			continue
		case "list", "in", "facts", "paths", "providers", "resolvers", "dns-brute", "dirs", "params", "params-targets", "screenshots", "urls", "ledger", "kill-file":
			// Files and directories, made absolute: azhaq resume may run
			// from another directory.
			if !inline && takesValue {
				val = args[i+1]
				i++
			}
			if val != "-" && val != "" && !(name == "ledger" && val == "off") && (name != "resolvers" || isFile(val)) && !(name == "params" && builtinNames(val)) && !(name == "dirs" && val == dirscol.Builtin) {
				if abs, err := filepath.Abs(val); err == nil {
					val = abs
				}
			}
			out = append(out, "-"+name+"="+val)
			continue
		case "probe-opts":
			// probe's options hold a raw request whose credential headers are
			// kept as little as -header's are.
			if !inline && takesValue {
				val = args[i+1]
				i++
			}
			out = append(out, "-probe-opts="+redactProbeOpts(val))
			continue
		case "scope":
			if !inline && takesValue {
				val = args[i+1]
				i++
			}
			if _, platform := scopefile.Platforms[val]; !platform && val != "" {
				if abs, err := filepath.Abs(val); err == nil {
					val = abs
				}
			}
			out = append(out, "-scope="+val)
			continue
		}
		out = append(out, a)
	}
	return out
}

func secretHeader(h string) bool {
	k, _, _ := strings.Cut(h, ":")
	return fetch.SecretHeader(k)
}

// redactProbeOpts drops the credential headers of the raw request in
// probe's options, as keptArgs drops them from -header.
func redactProbeOpts(raw string) string {
	var spec httpcol.Spec
	if json.Unmarshal([]byte(raw), &spec) != nil || spec.Raw == nil {
		return raw
	}
	for k := range spec.Raw.Header {
		if secretHeader(k + ":") {
			delete(spec.Raw.Header, k)
		}
	}
	out, err := json.Marshal(&spec)
	if err != nil {
		return raw
	}
	return string(out)
}

// localFlags are the flags a command names differently from run, whose
// stored run holds them under run's name: ports -rate is run's -port-rate.
var localFlags = map[string]map[string]string{
	"ports": {"rate": "port-rate", "min-rate": "port-min-rate", "workers": "port-workers", "c": "port-workers",
		"connect-timeout": "port-timeout", "retries": "port-retries", "max-retries": "port-retries"},
	"dirs":   {"rate": "dirs-rate", "t": "dirs-threads"},
	"params": {"rate": "params-rate"},
}

// fuzzSpelling gives run's flags a resume was given as fuzz spells them: run's
// -timeout is a duration for the whole run, fuzz's -maxtime in seconds
// (fuzz's own -timeout is one request's).
func fuzzSpelling(args []string) []string {
	out := slices.Clone(args)
	for i, a := range out {
		name, val, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "timeout" {
			continue
		}
		at := i + 1
		if inline {
			out[i], at = "-maxtime", -1
		} else if i+1 < len(out) {
			out[i], val = "-maxtime", out[i+1]
		}
		if d, err := time.ParseDuration(val); err == nil {
			v := strconv.FormatFloat(d.Seconds(), 'f', -1, 64)
			if at < 0 {
				out[i] = "-maxtime=" + v
			} else {
				out[at] = v
			}
		}
	}
	return out
}

// runSpelling gives the flags a resume was given under the names the
// stored run holds them by, so that -rate 1000 replaces a ports run's
// -port-rate instead of setting run's own -rate beside it.
func runSpelling(command string, args []string) []string {
	names := localFlags[command]
	if len(names) == 0 {
		return args
	}
	out := make([]string, len(args))
	copy(out, args)
	for i, a := range out {
		dashes := len(a) - len(strings.TrimLeft(a, "-"))
		if dashes == 0 || dashes > 2 {
			continue
		}
		name, val, inline := strings.Cut(a[dashes:], "=")
		if to, ok := names[name]; ok {
			out[i] = "-" + to
			if inline {
				out[i] += "=" + val
			}
		}
	}
	return out
}
