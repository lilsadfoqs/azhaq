package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/runs"
)

// cmdRuns lists the kept runs, newest first, and removes the ones named.
func cmdRuns(args []string) error {
	fs := newFlags("runs")
	asJSON := fs.Bool("json", false, "one JSON object per run: its run.json")
	homeFlag := fs.String("home", "", "the run home to read (default $AZHAQ_HOME, else .azhaq in the current directory)")
	var rm stringsFlag
	fs.Var(&rm, "rm", "remove this run's folder (repeatable): its workspace and files go with it")
	older := fs.String("older", "", "remove the runs that started more than this long ago (30d, 12h)")
	limit := fs.Int("limit", 0, "list at most this many runs (0: all)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usagef("runs takes flags only")
	}
	home, err := runHome(*homeFlag)
	if err != nil {
		return err
	}
	if len(rm) > 0 || *older != "" {
		var ids []string
		ids = append(ids, rm...)
		if *older != "" {
			d, err := parseAge(*older)
			if err != nil {
				return usagef("-older %s: %v", *older, err)
			}
			old, err := runs.Older(home, time.Now().Add(-d))
			if err != nil {
				return err
			}
			for _, r := range old {
				ids = append(ids, r.ID)
			}
		}
		for _, id := range ids {
			if err := runs.Remove(home, id); err != nil {
				return fmt.Errorf("remove %s: %w", id, err)
			}
			fmt.Fprintf(os.Stderr, "azhaq: removed %s\n", id)
		}
		fmt.Fprintf(os.Stderr, "azhaq: %d runs removed from %s\n", len(ids), runs.Dir(home))
		return nil
	}
	list, err := runs.List(home)
	if err != nil {
		return err
	}
	if *limit > 0 && len(list) > *limit {
		list = list[:*limit]
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, r := range list {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	}
	if len(list) == 0 {
		fmt.Fprintf(os.Stderr, "azhaq: %s\n", noRunsText(home))
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tWHEN\tSTATUS\tTIME\tREQUESTS\tGOT")
	for _, r := range list {
		s := runSummaryOf(r)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Started.Local().Format("2006-01-02 15:04"),
			runStatus(r), runTime(r), s.requestsText(), s.gotText())
	}
	tw.Flush()
	fmt.Fprintf(os.Stderr, "azhaq: %d runs in %s (azhaq ui shows them)\n", len(list), runs.Dir(home))
	return nil
}

// runHome is -home, else the run home; an error when keeping is off and
// no home was named.
func runHome(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	home, ok := runs.Home()
	if !ok {
		return "", usagef("runs are not kept (AZHAQ_HOME=%s): give -home DIR", os.Getenv("AZHAQ_HOME"))
	}
	return home, nil
}

// noRunsText says the home holds no runs, and where another one is named.
func noRunsText(home string) string {
	return fmt.Sprintf("no runs kept in %s yet (this folder's home is ./.azhaq; -home DIR reads another folder's, AZHAQ_HOME sets the home)", runs.Dir(home))
}

// parseAge is a duration that also takes days: 30d, 36h, 90m.
func parseAge(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		d, err := strconv.Atoi(n)
		if err != nil || d < 0 {
			return 0, fmt.Errorf("want a number of days, like 30d")
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// runSummary is the part of a command's summary the run list reads.
type runSummary struct {
	present  bool
	Requests int64          `json:"requests"`
	DNS      int64          `json:"dns_queries"`
	Results  int            `json:"results"`
	Counts   map[string]int `json:"counts"`
	Failures int            `json:"failures"`
	Exit     int            `json:"exit"`
}

func runSummaryOf(r runs.Record) runSummary {
	var s runSummary
	if len(r.Summary) > 0 && json.Unmarshal(r.Summary, &s) == nil {
		s.present = true
	}
	return s
}

func (s runSummary) requestsText() string {
	if !s.present {
		return "not recorded"
	}
	return strconv.FormatInt(s.Requests, 10)
}

// gotText is the summary's own counts, the largest first.
func (s runSummary) gotText() string {
	if !s.present {
		return "not recorded"
	}
	if len(s.Counts) == 0 {
		return fmt.Sprintf("%d results", s.Results)
	}
	keys := make([]string, 0, len(s.Counts))
	for k := range s.Counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if s.Counts[keys[i]] != s.Counts[keys[j]] {
			return s.Counts[keys[i]] > s.Counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var parts []string
	for i, k := range keys {
		if i == 4 {
			parts = append(parts, "…")
			break
		}
		name := k
		if s.Counts[k] == 1 {
			name = countName(k)
		}
		parts = append(parts, fmt.Sprintf("%d %s", s.Counts[k], name))
	}
	return strings.Join(parts, ", ")
}

func runStatus(r runs.Record) string {
	if r.Status != runs.StatusDone || r.Exit == nil {
		if runs.Alive(r) {
			return "running"
		}
		return "did not finish"
	}
	if *r.Exit == exitOK {
		return "ok"
	}
	return fmt.Sprintf("exit %d", *r.Exit)
}

func runTime(r runs.Record) string {
	if r.Ended == nil {
		return "-"
	}
	return (time.Duration(r.Seconds*1000) * time.Millisecond).Round(time.Second).String()
}
