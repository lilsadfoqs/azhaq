package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// portsCPU is what a full-range connect scan costs against nmap -sT's at the
// same rate on 127.0.0.1: the CPU seconds (user and system, of the process
// and no more) and the wall time, the median of runs taken in turn so that a
// machine that gets busier costs both tools the same.
type portsCPU struct {
	Target      string  `json:"target"`
	Ports       string  `json:"ports"`
	Rate        string  `json:"rate"`
	Runs        int     `json:"runs"`
	AzhaqCPU    float64 `json:"azhaq_cpu_seconds"`
	NmapCPU     float64 `json:"nmap_cpu_seconds"`
	AzhaqWall   float64 `json:"azhaq_seconds"`
	NmapWall    float64 `json:"nmap_seconds"`
	AzhaqRSS    float64 `json:"azhaq_rss_mb"`
	NmapRSS     float64 `json:"nmap_rss_mb"`
	AzhaqOpen   int     `json:"azhaq_open"`
	NmapOpen    int     `json:"nmap_open"`
	NmapMissing bool    `json:"nmap_missing,omitempty"`
}

// cpuBound is how far above the reference's CPU and wall time a full-range
// connect scan may be.
const cpuBound = 1.25

// cpuRuns is how many pairs of runs the row takes.
const cpuRuns = 5

// cpuCmd runs a command and says the CPU seconds it used (its own and its
// children's, user and system) and the wall time, with its standard output.
func cpuCmd(dir, name string, args ...string) (out []byte, cpu, wall float64, err error) {
	out, cpu, wall, _, err = cpuRSSCmd(dir, name, args...)
	return
}

// cpuRSSCmd is cpuCmd that also says the most memory the process held (its
// peak resident set, in MB).
func cpuRSSCmd(dir, name string, args ...string) (out []byte, cpu, wall, rss float64, err error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	t0 := time.Now()
	err = cmd.Run()
	wall = time.Since(t0).Seconds()
	if cmd.ProcessState != nil {
		cpu = (cmd.ProcessState.UserTime() + cmd.ProcessState.SystemTime()).Seconds()
		if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			rss = float64(ru.Maxrss) / 1024 // kilobytes on Linux
		}
	}
	return stdout.Bytes(), cpu, wall, rss, err
}

// benchPortsCPU takes the row: azhaq ports with its ledger and database on,
// against nmap -sT, both on every port of 127.0.0.1 at 10,000 connects a
// second.
func benchPortsCPU() *portsCPU {
	row := &portsCPU{Target: "127.0.0.1", Ports: "1-65535", Rate: "10000", Runs: cpuRuns}
	nmap := nmapBin()
	if nmap == "" {
		row.NmapMissing = true
		addCheck("ports: nmap is installed for the CPU comparison", false, "nmap is not in PATH, -nmap or -refbin; the comparison is skipped")
		return row
	}
	dir, err := os.MkdirTemp(work, "portscpu")
	if err != nil {
		addCheck("ports 127.0.0.1 1-65535: CPU ≤ 1.25× nmap -sT's", false, "%v", err)
		return row
	}
	defer os.RemoveAll(dir)
	// One pass each, no second look at a port that did not answer: the row
	// measures the connect path, and a listener that is wedged on this machine
	// would cost one tool its retry wait and not the other.
	azArgs := []string{"ports", "-host", row.Target, "-p", row.Ports, "-rate", row.Rate, "-retries", "0", "-detect", "none", "-silent", "-db", filepath.Join(dir, "cpu.db")}
	nmArgs := []string{"-sT", "-Pn", "-n", "-p", row.Ports, "--max-rate", row.Rate, "--max-retries", "0", "-oG", "-", row.Target}
	var azCPU, nmCPU, azWall, nmWall, azRSS, nmRSS []float64
	var az, nm map[string]bool
	before := listening()
	for i := 0; i < cpuRuns; i++ {
		for _, f := range []string{"cpu.db", "cpu.db.ledger.jsonl", "cpu.db.stop"} {
			_ = os.Remove(filepath.Join(dir, f))
		}
		out, c, w, r, err := cpuRSSCmd(dir, azhaq, azArgs...)
		if err != nil {
			addCheck("ports 127.0.0.1 1-65535: CPU ≤ 1.25× nmap -sT's", false, "azhaq failed: %v", err)
			return row
		}
		azCPU, azWall, azRSS, az = append(azCPU, c), append(azWall, w), append(azRSS, r), portSet(out)
		out, c, w, r, err = cpuRSSCmd(dir, nmap, nmArgs...)
		if err != nil {
			addCheck("ports 127.0.0.1 1-65535: CPU ≤ 1.25× nmap -sT's", false, "nmap failed: %v", err)
			return row
		}
		nmCPU, nmWall, nmRSS, nm = append(nmCPU, c), append(nmWall, w), append(nmRSS, r), nmapOpen(out)
	}
	row.AzhaqCPU, row.NmapCPU = median(azCPU), median(nmCPU)
	row.AzhaqWall, row.NmapWall = median(azWall), median(nmWall)
	row.AzhaqRSS, row.NmapRSS = median(azRSS), median(nmRSS)
	row.AzhaqOpen, row.NmapOpen = len(az), len(nm)
	cmds := cmdLine(azhaq, azArgs...) + " vs " + cmdLine("nmap", nmArgs...)
	// A socket that listens for a moment is in one list and not the other: what
	// counts is the sockets that listened throughout (`ss` before and after) and
	// one tool found and the other did not.
	after := listening()
	var missed, extra []string
	stable := func(k string) bool {
		_, p, ok := strings.Cut(k, ":")
		return ok && listensOn(before, p) && listensOn(after, p)
	}
	for k := range nm {
		if !az[k] && stable(k) {
			missed = append(missed, k)
		}
	}
	for k := range az {
		if !nm[k] && stable(k) {
			extra = append(extra, k)
		}
	}
	sort.Strings(missed)
	sort.Strings(extra)
	detail := fmt.Sprintf("azhaq %.2f CPU s, %.1f s and %.0f MB, nmap %.2f CPU s, %.1f s and %.0f MB (median of %d runs in turn); open: azhaq %d, nmap %d; listening throughout and azhaq missed %v, nmap missed %v | %s",
		row.AzhaqCPU, row.AzhaqWall, row.AzhaqRSS, row.NmapCPU, row.NmapWall, row.NmapRSS, cpuRuns, row.AzhaqOpen, row.NmapOpen, clipList(missed, 5), clipList(extra, 5), cmds)
	addCheck("ports 127.0.0.1 1-65535: open ports ≥ nmap -sT's", len(missed) == 0, "%s", detail)
	addCheck(fmt.Sprintf("ports 127.0.0.1 1-65535: CPU ≤ %.2f× nmap -sT's", cpuBound), row.AzhaqCPU <= cpuBound*row.NmapCPU, "%.2f×: %s", cpuRatio(row.AzhaqCPU, row.NmapCPU), detail)
	addCheck(fmt.Sprintf("ports 127.0.0.1 1-65535: time ≤ %.2f× nmap -sT's", cpuBound), row.AzhaqWall <= cpuBound*row.NmapWall, "%.2f×: %s", cpuRatio(row.AzhaqWall, row.NmapWall), detail)
	return row
}

func cpuRatio(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// nmapOpen reads the open ports of `nmap -oG -` output as host:port.
func nmapOpen(out []byte) map[string]bool {
	set := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		host, ports, ok := strings.Cut(l, "\tPorts: ")
		if !ok || !strings.HasPrefix(host, "Host: ") {
			continue
		}
		ip := strings.Fields(host)[1]
		ports, _, _ = strings.Cut(ports, "\t")
		for _, p := range strings.Split(ports, ",") {
			f := strings.Split(strings.TrimSpace(p), "/")
			if len(f) > 1 && f[1] == "open" {
				set[ip+":"+f[0]] = true
			}
		}
	}
	return set
}
