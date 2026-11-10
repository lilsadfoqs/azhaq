package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A small one-shot job is its start-up and its exit more than its requests:
// dirs on six words, or a scan of a thousand ports of this machine. The
// comparisons above take whole lists and ranges, where the first request
// comes late and the sum hides it, so a small job has rows of its own, with
// a bar that does not bend for the size of the job.
const (
	smallTime = 1.25 // times the reference's time
	smallMem  = 2.0  // times the reference's peak private memory
)

// smallRow is one small case against its reference tool.
type smallRow struct {
	Case      string  `json:"case"`
	Azhaq     int     `json:"azhaq"`
	Ref       int     `json:"reference"`
	AzhaqSecs float64 `json:"azhaq_seconds"`
	RefSecs   float64 `json:"reference_seconds"`
	memPair
	// The peak private memory (RssAnon) in MB: what the job itself holds.
	// The resident peaks of memPair also count the binary's file pages,
	// shared and dropped by the system as needed, so they grow with the
	// size of the binary, not with the job.
	AzhaqAnon float64 `json:"azhaq_anon_mb,omitempty"`
	RefAnon   float64 `json:"reference_anon_mb,omitempty"`
}

// setMem takes both peaks of each tool from the runs that were timed.
func (r *smallRow) setMem(az, ref runMeasure) {
	r.set(az, ref)
	r.AzhaqAnon, r.RefAnon = az.AnonMB, ref.AnonMB
}

// barSmall holds a small job to its bar: at least the reference's results, at
// most smallTime of its time and smallMem of its private memory; the resident
// peaks are printed beside it. A peak that was not measured is a failed
// check, not a pass.
func barSmall(name string, r smallRow, evidence, cmds, note string) {
	if why, gone := refGone[vsTool(cmds)]; gone {
		for _, what := range []string{"results ≥ the reference's", "time", "memory"} {
			addCheck(name+": "+what, false, "the reference did not run: %s | %s", why, cmds)
		}
		return
	}
	if note != "" {
		note = "; " + note
	}
	failed := strings.Contains(note, "[azhaq: ")
	addCheck(name+": results ≥ the reference's, confirmed by "+evidence, r.Azhaq >= r.Ref,
		"azhaq %d, reference %d%s | %s", r.Azhaq, r.Ref, note, cmds)
	addCheck(fmt.Sprintf("%s: time ≤ %.2f× the reference's", name, smallTime), r.AzhaqSecs <= r.RefSecs*smallTime && !failed,
		"azhaq %.2fs, reference %.2fs (%.2f×, the median of 3)%s | %s", r.AzhaqSecs, r.RefSecs, safeRatio(r.AzhaqSecs, r.RefSecs), failedNote(failed), cmds)
	measured := r.AzhaqAnon > 0 && r.RefAnon > 0
	addCheck(fmt.Sprintf("%s: private memory ≤ %.0f× the reference's", name, smallMem), measured && r.AzhaqAnon <= r.RefAnon*smallMem,
		"private (RssAnon) azhaq %.1f MB, reference %.1f MB (%.2f×); resident with the binary's shared file pages (VmHWM) azhaq %.0f MB, reference %.0f MB (%.2f×); the median of 3 | %s",
		r.AzhaqAnon, r.RefAnon, safeRatio(r.AzhaqAnon, r.RefAnon), r.AzhaqRSS, r.RefRSS, safeRatio(r.AzhaqRSS, r.RefRSS), cmds)
}

func safeRatio(a, b float64) float64 {
	if b <= 0 {
		return 0
	}
	return a / b
}

// benchDirsSmall sweeps six words on one app with azhaq and with ffuf -ac:
// three paths the app serves and three it does not.
func benchDirsSmall(app string) *smallRow {
	list := filepath.Join(work, "dirs-six.txt")
	must(os.WriteFile(list, []byte(strings.Join(append(append([]string{}, realPaths[:3]...), "azhaqnothere1", "azhaqnothere2", "azhaqnothere3"), "\n")+"\n"), 0o644))
	row := &smallRow{Case: "dirs, 6 words, " + app}
	aa := []string{"dirs", "-u", app, "-w", list, "-silent"}
	fa := []string{"-u", app + "FUZZ", "-w", list, "-ac", "-s"}
	var aOut, fOut []byte
	var am, fm runMeasure
	beforeEach = func() { freshApp(app) }
	legWithApp(app, func() { aOut, am, fOut, fm = timedPair(app, 10*time.Minute, work, azhaq, ref("ffuf"), aa, fa) })
	beforeEach = nil
	az, ff := map[string]bool{}, map[string]bool{}
	for _, l := range lines(aOut) {
		az[firstField(l)] = true
	}
	for _, l := range lines(fOut) {
		ff[app+l] = true
	}
	row.Azhaq, row.Ref = len(az), len(ff)
	row.AzhaqSecs, row.RefSecs = am.Seconds, fm.Seconds
	row.setMem(am, fm)
	barSmall("dirs 6 words", *row, "the paths ffuf lists", cmdLine(azhaq, aa...)+" vs "+cmdLine("ffuf", fa...), azFail(am))
	return row
}

// benchPortsSmall scans the first thousand ports of 127.0.0.1 with azhaq and
// with nmap, twice: connecting only (azhaq -detect none, nmap -sT), and
// naming what answers (azhaq's default, nmap -sT -sV).
func benchPortsSmall() []smallRow {
	nmap := nmapBin()
	if nmap == "" {
		addCheck("ports 1000: nmap is installed", false, "nmap is not in PATH, -nmap or AZHAQ_NMAP: the small comparison is skipped")
		return nil
	}
	var rows []smallRow
	for _, c := range []struct {
		name, evidence string
		az, nm         []string
	}{
		{"ports 1-1000 on 127.0.0.1, connect only", "nmap's own connect scan",
			[]string{"ports", "-host", "127.0.0.1", "-p", "1-1000", "-detect", "none", "-silent"},
			[]string{"-sT", "-Pn", "-n", "-p", "1-1000", "-oG", "-", "127.0.0.1"}},
		{"ports 1-1000 on 127.0.0.1, services named", "nmap -sV's open ports",
			[]string{"ports", "-host", "127.0.0.1", "-p", "1-1000", "-silent"},
			[]string{"-sT", "-sV", "-Pn", "-n", "-p", "1-1000", "-oG", "-", "127.0.0.1"}},
	} {
		aOut, am, nOut, nm := timedPair("127.0.0.1", 10*time.Minute, work, azhaq, nmap, c.az, c.nm)
		az, nb := portSet(aOut), nmapOpen(nOut)
		r := smallRow{Case: c.name, Azhaq: len(az), Ref: len(nb), AzhaqSecs: am.Seconds, RefSecs: nm.Seconds}
		r.setMem(am, nm)
		barSmall(strings.Replace(c.name, " on 127.0.0.1", "", 1), r, c.evidence, cmdLine(azhaq, c.az...)+" vs "+cmdLine("nmap", c.nm...), azFail(am))
		rows = append(rows, r)
	}
	return rows
}
