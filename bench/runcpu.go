package main

import (
	"os"
	"path/filepath"
)

// runCPU is what mapping one app with `azhaq run` costs against katana's
// deepest crawl of it (-jc -jsl, depth 3): the CPU seconds of the process, the
// median of runs taken in turn so that a machine that gets busier costs both
// the same. The app is a single-page one whose scripts are megabytes, where
// reading them is most of the work.
type runCPU struct {
	Target     string  `json:"target"`
	Runs       int     `json:"runs"`
	AzhaqCPU   float64 `json:"azhaq_cpu_seconds"`
	KatanaCPU  float64 `json:"katana_cpu_seconds"`
	AzhaqWall  float64 `json:"azhaq_seconds"`
	KatanaWall float64 `json:"katana_seconds"`
}

// benchRunCPU takes the row on app: azhaq run against katana -jc -jsl.
func benchRunCPU(app string) *runCPU {
	row := &runCPU{Target: app, Runs: cpuRuns}
	const name = "juice-shop run: CPU ≤ katana -jc -jsl's"
	dir, err := os.MkdirTemp(work, "runcpu")
	if err != nil {
		addCheck(name, false, "%v", err)
		return row
	}
	defer os.RemoveAll(dir)
	azArgs := append([]string{"run", "-url", app, "-db", filepath.Join(dir, "cpu.db"), "-quiet"}, azPace(app)...)
	kaArgs := append([]string{"-u", app, "-d", "3", "-jc", "-jsl", "-silent", "-nc", "-timeout", "10", "-c", "10"}, katanaPace(app)...)
	var azCPU, kaCPU, azWall, kaWall []float64
	for i := 0; i < cpuRuns; i++ {
		for _, f := range []string{"cpu.db", "cpu.db.ledger.jsonl", "cpu.db.stop"} {
			_ = os.Remove(filepath.Join(dir, f))
		}
		freshApp(app)
		_, c, w, err := cpuCmd(dir, azhaq, azArgs...)
		if err != nil {
			addCheck(name, false, "azhaq failed: %v", err)
			return row
		}
		azCPU, azWall = append(azCPU, c), append(azWall, w)
		freshApp(app)
		_, c, w, err = cpuCmd(dir, ref("katana"), kaArgs...)
		if err != nil {
			addCheck(name, false, "katana failed: %v", err)
			return row
		}
		kaCPU, kaWall = append(kaCPU, c), append(kaWall, w)
	}
	row.AzhaqCPU, row.KatanaCPU = median(azCPU), median(kaCPU)
	row.AzhaqWall, row.KatanaWall = median(azWall), median(kaWall)
	addCheck(name, row.AzhaqCPU <= row.KatanaCPU,
		"azhaq %.2f CPU s in %.1f s, katana %.2f CPU s in %.1f s (%.2f×, the median of %d runs in turn) | %s vs %s",
		row.AzhaqCPU, row.AzhaqWall, row.KatanaCPU, row.KatanaWall, cpuRatio(row.AzhaqCPU, row.KatanaCPU), cpuRuns,
		cmdLine(azhaq, azArgs...), cmdLine("katana", kaArgs...))
	return row
}
