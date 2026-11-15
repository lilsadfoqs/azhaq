package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// signInCost is what one Chrome sign-in sends at least: the sign-in page,
// the form's POST and the page it ends on. The page's scripts, styles and
// images come on top, and are not known before it is loaded.
const signInCost = 3

// rolesCostIn is what the estimate of a roles command is made from.
type rolesCostIn struct {
	roles    []role
	logins   int  // roles that sign in with Chrome
	crawl    bool // the run options are given: each role maps the target
	hist     []*history
	sc       histScope
	replay   bool
	max      int // -replay-max
	methods  map[string]bool
	budget   int64         // -max-requests of the run options, the command's budget
	verify   []verifyWrite // -replay-writes-verify steps
	canary   bool          // -replay-writes-canary
	mapsPlan *runPlan      // what one role's run would send, from plan; nil outside plan
}

// estimateRoles is what roles would send, by stage, from the roles, the
// histories and the run options: each stage as far as they say, and what it
// leaves out named.
func estimateRoles(in rolesCostIn) costEstimate {
	e := newEstimator()
	e.cap = in.budget
	n := len(in.roles)
	if in.logins > 0 {
		e.put(signInStage, "", amount{Requests: int64(in.logins * signInCost)}, "the sign-in page's scripts, styles and images; a sign-in again each time a session ends")
	}
	if in.crawl && in.mapsPlan != nil {
		for _, st := range in.mapsPlan.Estimate.Stages {
			if st.Stage == signInStage {
				continue
			}
			for _, c := range st.Collectors {
				if c.Estimate == nil {
					continue
				}
				var each amount
				for i := 0; i < n; i++ {
					each.add(*c.Estimate)
				}
				e.putBound(stageRoleMaps, c.Collector, each, st.NotCounted, c.ceil.times(int64(n)))
			}
		}
	}
	own := hostSet(in.sc.hostnames())
	reached := map[string]int{} // URL → roles whose history reached it
	var reads int64
	for _, h := range in.hist {
		urls, _ := h.gets(in.sc, own)
		reads += int64(len(urls))
		for _, u := range urls {
			reached[u]++
		}
	}
	if reads > 0 {
		open := ""
		if in.crawl {
			open = "the pages the role's run reached are not read again"
		}
		e.putBound(stageHistory, "", amount{Requests: reads}, open, ceiling{target: reads}) // each page is asked at most once
	}
	if in.replay {
		var need int64
		for _, k := range reached {
			need += int64(max(n-k, 0))
		}
		open := "the objects the answers name, asked of every role; a check of each session every -canary-every requests"
		if in.crawl {
			open = "each URL a role's run reaches, asked of the roles whose run did not"
		}
		// -replay-max is shared: the history reads take what they need of
		// it first, the replay gets what is left.
		if left := int64(in.max) - min(reads, int64(in.max)); in.max > 0 && need > left {
			need, open = left, "capped by -replay-max, which the history reads share; "+open
		}
		e.put(stageReplay, "", amount{Requests: need}, open)
		e.put(stageControls, "", amount{}, "one request with a made-up identifier for each cross read the replay finds; for a role signed in with Chrome and with no check, a request with and one without the session for each page the sign-in loaded, until one tells the session apart")
	}
	if in.methods != nil {
		var writes, floor, most int64
		var reasons []string
		for _, h := range in.hist {
			for _, w := range historyWrites(h, in.sc, in.methods, own) {
				writes++
				others := int64(len(otherRoles(in.roles, w.owner)))
				f, m, open := verifyReads(w, others, int64(n-1), in.verify, in.canary, slices.ContainsFunc(in.roles, func(r role) bool { return r.name == w.owner }))
				floor += f
				most += m
				if open != "" && !slices.Contains(reasons, open) {
					reasons = append(reasons, open)
				}
			}
		}
		others := int64(max(n-1, 0))
		e.put(stageWrites, "", amount{Requests: writes * others}, "the PUT, PATCH and DELETE the roles' routes take on each role's objects")
		cl := ceiling{target: most, tOpen: reasons}
		if in.crawl {
			// What each role's run found: its PUT, PATCH and DELETE on the
			// role's objects are read back too, and are not known before.
			cl.tOpen = mergeReasons(cl.tOpen, []string{crawlWrites})
		}
		open := strings.Join(cl.tOpen, "; ")
		e.putBound(stageVerify, "", amount{Requests: floor}, open, cl)
	}
	out := e.result()
	out.Basis = rolesBasis
	return out
}

// crawlWrites is why the verification of a run with role maps has no
// ceiling of its own: the writes its maps find are read back too.
const crawlWrites = "the reads that check the PUT, PATCH and DELETE the role maps find on each role's objects"

// createLocates is why a create's verification has no ceiling of its own:
// where its object is looked for depends on the answers.
const createLocates = "the places a create's answer and the collection name for its object are read until one answers"

// verifyReads are the reads of the verification stage that one write can
// send: floor is what it sends at least (its owner's object once, each
// other role's check after it), most the most it sends from what is known
// before the run, and open says what the answers decide on top of it.
// others are the roles the write is sent with, n1 the other roles of the
// create's creator, steps the user's -replay-writes-verify steps.
func verifyReads(w writeReq, others, n1 int64, steps []verifyWrite, canary, ownerThere bool) (floor, most int64, open string) {
	if !ownerThere {
		return 0, 0, "" // the replay skips a write whose owner is not a role
	}
	if w.method == http.MethodPost {
		// Each role that sends it reads the collection before and after,
		// the member each identifier of the body names as its recorded
		// owner and again with a made-up identifier, and then every other
		// role reads the object it made.
		k := int64(len(bodyCandidates(w)))
		return others, others * (2 + 2*k + n1), createLocates
	}
	var reads int64
	for _, v := range steps {
		if v.kind == "read" {
			reads++
		}
	}
	// The owner's object before (the write's own URL, then each parent
	// the replay tries, or the one the history read), a read-back the map
	// knows, one more after an empty write, then each sender's read after
	// its write and each step's read as the sender, and with a canary the
	// sender's own object after a write the owner's did not show.
	before := max(int64(liveVerifyReads(w)), 1)
	most = before + 1 + others*(1+reads)
	if w.empty {
		most++
	}
	if canary && !w.empty && w.method != http.MethodDelete {
		most += others
	}
	return 1 + others, most, ""
}

// liveVerifyReads is how many URLs liveVerify tries for a write: its own and
// each parent down to two segments, but a version segment.
func liveVerifyReads(w writeReq) int {
	pu, err := url.Parse(w.url)
	if err != nil {
		return 0
	}
	path := strings.TrimRight(pu.Path, "/")
	n := 0
	for first := true; ; first = false {
		if last := path[strings.LastIndex(path, "/")+1:]; first || !versionSeg.MatchString(norm(last)) {
			n++
		}
		if strings.Count(path, "/") < 3 {
			return n
		}
		path = path[:strings.LastIndex(path, "/")]
	}
}

// planRoles prints what roles would send, by stage, and sends nothing.
func planRoles(in rolesCostIn, asJSON bool, budget int64) error {
	est := estimateRoles(in)
	names := make([]string, 0, len(in.roles))
	for _, r := range in.roles {
		names = append(names, r.name)
	}
	if asJSON {
		out := map[string]any{"type": "plan", "command": "roles", "roles": names, "sign_ins": in.logins, "estimate": est}
		if b := budgetStage(est, budget); b != "" {
			out["budget"] = b
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	fmt.Printf("roles (%d): %s; %s\n", len(names), strings.Join(names, " "), nOf(in.logins, "sign-in with Chrome", "sign-ins with Chrome"))
	printEstimate(os.Stdout, "estimate: ", est)
	if b := budgetStage(est, budget); b != "" {
		fmt.Println(b)
	}
	return nil
}

// budgetStage says in which stage the estimate passes the budget of the
// whole command (-max-requests), "" when it does not or none is given.
func budgetStage(est costEstimate, budget int64) string {
	if budget <= 0 {
		return ""
	}
	var sum int64
	for _, st := range est.Stages {
		sum += st.Estimate.Requests + st.Estimate.Connects + st.Estimate.Datagrams
		if sum > budget {
			return fmt.Sprintf("-max-requests %d, the budget of the whole command, would be reached in the %s stage (%d requests and connects estimated by then, before what the answers lead to)", budget, st.Stage, sum)
		}
	}
	return ""
}

// addRunEstimate adds to the estimate of roles the estimate each role's run
// made for itself: their stages are the run's, and here are the collectors
// of the role maps stage; a sign-in stays a stage of its own.
func addRunEstimate(e *costEstimate, sub *report) {
	if sub == nil || sub.Cost == nil || sub.Cost.Estimate == nil {
		return
	}
	for _, st := range sub.Cost.Stages {
		if st.Estimate == nil || st.Stage == signInStage {
			continue // the sign-ins of roles are counted once, from its own roles
		}
		stage := stageRoleMaps
		if st.Stage == signInStage {
			stage = signInStage
		}
		merge(e, stage, st)
	}
	e.seal()
}

// merge adds the estimate of one stage of a run to stage of e.
func merge(e *costEstimate, stage string, st costStage) {
	var dst *costStage
	for i := range e.Stages {
		if e.Stages[i].Stage == stage {
			dst = &e.Stages[i]
		}
	}
	if dst == nil {
		e.Stages = append(e.Stages, costStage{Stage: stage, Estimate: &amount{}})
		dst = &e.Stages[len(e.Stages)-1]
	}
	dst.Estimate.add(*st.Estimate)
	dst.ceil.add(st.ceil)
	e.Total.add(*st.Estimate)
	if st.AtLeast {
		dst.AtLeast, e.AtLeast = true, true
		if st.NotCounted != "" && !strings.Contains(dst.NotCounted, st.NotCounted) {
			if dst.NotCounted != "" {
				dst.NotCounted += "; "
			}
			dst.NotCounted += st.NotCounted
		}
	}
	for _, c := range st.Collectors {
		if c.Estimate == nil {
			continue
		}
		done := false
		for i := range dst.Collectors {
			if dst.Collectors[i].Collector == c.Collector {
				dst.Collectors[i].Estimate.add(*c.Estimate)
				done = true
			}
		}
		if !done {
			a := *c.Estimate
			dst.Collectors = append(dst.Collectors, costCollector{Collector: c.Collector, Estimate: &a, ceil: c.ceil})
		}
	}
}

// failedWithBudget adds to err, a run of a role that failed, what the budget
// of the command was spent on when it was refused: the stage it was reached
// in, and what each stage had sent by then. Any other error is returned as it is.
func failedWithBudget(rep *report, err error) error {
	if err == nil || !errors.Is(err, neterr.ErrBudget) {
		return err
	}
	stage := stageRoleMaps
	if strings.Contains(err.Error(), "signing in") {
		stage = signInStage
	}
	c := accountCost(rep.estimate, rep.spentFrom, rolesStages)
	rep.Cost = c
	return fmt.Errorf("%w: the budget was reached in the %s stage%s", err, stage, strings.Replace(spentBy(c), ", ", "; ", 1))
}
