package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
)

// A summary says nothing its rows do not say. Each command that emits rows
// counts them as they go out (tally), apart from the numbers it publishes
// (Results, Counts, Stored, Folded, LeftOut, Requests); before the summary is
// printed audit recomputes what it can from the rows and the ledger, and a
// number that differs is an internal error: exit 1, its own message, and a
// summary that is not complete. A run that disagrees with itself is never
// reported as done.

// tally is what a command counted as it emitted rows.
type tally struct {
	n    int            // rows emitted
	held int            // the stored rows they stand for (a templated row holds many)
	by   map[string]int // the stored rows they stand for, by the count each belongs to
}

// add counts one emitted row of class that stands for held stored rows; a row
// that stands for more than one has no class of its own.
func (t *tally) add(class string, held int) {
	if held > 1 {
		class = ""
	}
	if t.by == nil {
		t.by = map[string]int{}
	}
	t.n++
	t.held += held
	t.by[class] += held
}

// addGroup counts one emitted line that stands for several stored rows, each
// of which belongs to the count classOf names: the line is one row emitted, and
// its members are held by it, class by class.
func (t *tally) addGroup(members []engine.MapEntry, classOf func(engine.MapEntry) string) {
	if t.by == nil {
		t.by = map[string]int{}
	}
	t.n++
	t.held += len(members)
	for _, m := range members {
		t.by[classOf(m)]++
	}
}

// emitted is the tally of the command's rows, made on first use.
func (r *report) emitted() *tally {
	if r.rows == nil {
		r.rows = &tally{}
	}
	return r.rows
}

// disagree records a number the summary publishes that its rows or the
// ledger do not give.
func (r *report) disagree(format string, a ...any) {
	r.problems = append(r.problems, fmt.Sprintf(format, a...))
}

// expect records a disagreement unless published is what the rows give.
func (r *report) expect(what string, published, fromRows int) {
	if published != fromRows {
		r.disagree("%s: the summary says %d, the rows say %d", what, published, fromRows)
	}
}

// audit checks the identities the docs promise: the counts of a run add up to
// its stored rows, and every count the rows it printed give is the one the
// summary published. It runs once, before the summary is made final.
func (r *report) audit() {
	if r.audited {
		return
	}
	r.audited = true
	if r.Folded != nil {
		sum := 0
		for _, n := range r.Counts {
			sum += n
		}
		r.expect("the counts added together, against the stored rows", sum, r.Stored)
		r.expect("results + folded + left_out, against the stored rows", r.Results+*r.Folded+r.LeftOut, r.Stored)
	}
	if t := r.rows; t != nil {
		r.expect("results, against the rows emitted", r.Results, t.n)
		if r.Folded != nil {
			r.expect("the stored rows less left_out, against the stored rows the rows emitted stand for", r.Stored-r.LeftOut, t.held)
			r.expect("folded, against the stored rows the rows emitted hold beyond themselves", *r.Folded, t.held-t.n)
		}
		// A row that stands for several stored rows (a template, dead names) has
		// the class of its first: the counts by class are checked when none does.
		if t.by[""] == 0 {
			keys := map[string]bool{}
			for k := range t.by {
				keys[k] = true
			}
			for k := range r.Counts {
				keys[k] = true
			}
			names := make([]string, 0, len(keys))
			for k := range keys {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				r.expect("count "+k+", against the rows emitted", r.Counts[k]-r.leftOutBy[k], t.by[k])
			}
		}
	}
	for _, c := range r.sums {
		r.expect(c.what, c.published, c.fromRows)
	}
}

// sum is an identity a command states for its own counts.
type sum struct {
	what                string
	published, fromRows int
}

// holds states that published is what fromRows adds up to.
func (r *report) holds(what string, published, fromRows int) {
	r.sums = append(r.sums, sum{what, published, fromRows})
}

// internalError is the message of a summary that disagrees with its rows.
func (r *report) internalError() string {
	return "internal error: the summary disagrees with the rows and the ledger it summarises (" + strings.Join(r.problems, "; ") + "): this is a bug in azhaq, not a result to rely on"
}
