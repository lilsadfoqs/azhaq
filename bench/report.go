package main

import (
	"fmt"
	"os"
	"text/tabwriter"
)

func printReport() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() {
		n := 0
		for _, r := range rec.Runs {
			if r.Cached {
				n++
			}
		}
		if n > 0 {
			fmt.Printf("\n%d reference runs replayed from today's (their times are that run's); -fresh runs them again\n", n)
		}
	}()
	printSet(w, "default flags", &rec.profileSet)
	if rec.Polite != nil {
		printSet(w, fmt.Sprintf("polite (HTTP %s/s, DNS %s/s, ports %s/s)", politeHTTP, politeDNS, politePort), rec.Polite)
	}
	if d := rec.Dropin; d != nil {
		fmt.Fprintf(w, "\ndrop-in and exports\tresult\n")
		fmt.Fprintf(w, "azhaq crawl, Juice Shop routes its pages and scripts name\t%d/%d (+%d of %d only the full map reaches)\n", d.CrawlKnown, d.CrawlOf, d.CrawlMapFound, d.CrawlMapOnly)
		fmt.Fprintf(w, "azhaq probe -json on stdin\t%d of 2, httpx fields %v\n", d.ProbeRows, d.ProbeFields)
		fmt.Fprintf(w, "OpenAPI export, VAmPI / crAPI paths\t%d/12, %d/40\n", d.OpenAPIVampi, d.OpenAPICrapi)
		fmt.Fprintf(w, "targets, HTML report\t%d, %d bytes\n", d.Targets, d.HTMLBytes)
	}
	if s := rec.Scale; s != nil {
		fmt.Fprintf(w, "\nscale (juice-shop, %d URLs in one run)\tURLs as one run\tdetail\n", s.URLs)
		fmt.Fprintf(w, "-max-requests %d, resumed\t%v\t%d processes, at most %d requests received from one, %d in all (one run %d)\n", s.Budget, s.BudgetSame, s.Processes, s.MostReceived, s.AllReceived, s.OneReceived)
		fmt.Fprintf(w, "kill -9, resumed\t%v\tkilled after %.1fs\n", s.KilledSame, s.KilledAfter)
		fmt.Fprintf(w, "two workers\t%v\t%d tasks on the workers, %.1fs (one process %.1fs)\n", s.WorkersSame, s.WorkerTasks, s.Seconds, s.OneSeconds)
	}
	if cl := rec.Claims; cl != nil {
		fmt.Fprintf(w, "\nclaims (%.0fs)\tpace\tsummary\tledger\tcounter\tpass\n", cl.Seconds)
		for _, r := range cl.Rows {
			fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%v\n", r.Case, r.Pace, r.Summary, r.Ledger, r.Counter, r.Pass)
		}
	}
	if t := rec.Tenants; t != nil {
		fmt.Fprintln(w, "\nroles (multi-tenant fixture)\trows as expected\twrong\textra\tsigned-in logouts\ttime")
		fmt.Fprintf(w, "anon → member → owner\t%d/%d\t%d\t%d\t%d\t%.1fs\n", t.Matched, t.Expected, len(t.Wrong), len(t.Extra), t.Logouts, t.Seconds)
	}
	w.Flush()
	for _, ps := range []*profileSet{&rec.profileSet, rec.Polite} {
		if ps != nil && ps.Probe != nil && len(ps.Probe.Disagree) > 0 {
			fmt.Printf("\nprobe differences (azhaq/httpx), %s\n", ps.Probe.Profile)
			for _, d := range ps.Probe.Disagree {
				fmt.Printf("  %s\n", d)
			}
		}
	}
	fmt.Println("\nchecks")
	pass := 0
	for _, c := range rec.Checks {
		mark := "PASS"
		if !c.Pass {
			mark = "FAIL"
		} else {
			pass++
		}
		fmt.Printf("  %s  %s  (%s)\n", mark, c.Name, c.Detail)
	}
	fmt.Printf("\n%d of %d checks pass\n", pass, len(rec.Checks))
	for _, r := range rec.Runs {
		if r.Error != "" {
			fmt.Printf("  note: %s on %s (%s): %s\n", r.Tool, r.Target, r.Profile, r.Error)
		}
	}
}

// printSet prints the comparison rows of one profile.
func printSet(w *tabwriter.Writer, title string, ps *profileSet) {
	if len(ps.Apps) > 0 {
		fmt.Fprintf(w, "\n== %s ==\napps\tazhaq routes\tknown\tshell\ttime\tRSS\tkatana routes\tknown\tshell\ttime\tRSS\n", title)
		for _, a := range ps.Apps {
			if a.Crawl != nil && a.CrawlKatana != nil {
				fmt.Fprintf(w, "%s (crawl)\t%d\t%s\t%d\t%.1fs\t%.0fMB\t%d\t%s\t%d\t%.1fs\t%.0fMB\n", a.Name,
					a.Crawl.Routes, known(*a.Crawl), a.Crawl.Shell, a.Crawl.Seconds, a.Crawl.RSSMB,
					a.CrawlKatana.Routes, known(*a.CrawlKatana), a.CrawlKatana.Shell, a.CrawlKatana.Seconds, a.CrawlKatana.RSSMB)
			}
			if a.Azhaq.TruthOf > 0 {
				fmt.Fprintf(w, "%s (run)\t%d\t%s\t%d\t%.1fs\t%.0fMB\t%d\t%s\t%d\t%.1fs\t%.0fMB\n", a.Name,
					a.Azhaq.Routes, known(a.Azhaq), a.Azhaq.Shell, a.Azhaq.Seconds, a.Azhaq.RSSMB,
					a.Katana.Routes, known(a.Katana), a.Katana.Shell, a.Katana.Seconds, a.Katana.RSSMB)
			}
		}
		for _, a := range ps.Apps {
			if b := a.Browser; b != nil {
				fmt.Fprintf(w, "\nwith a browser (%s)\troutes\tknown\tshell\ttime\tRSS\n", a.Name)
				fmt.Fprintf(w, "azhaq -browser\t%d\t%s\t%d\t%.1fs\t%.0fMB\n", b.Azhaq.Routes, known(b.Azhaq), b.Azhaq.Shell, b.Azhaq.Seconds, b.Azhaq.RSSMB)
				stopped := ""
				if b.KatanaStopped {
					stopped = " (stopped)"
				}
				fmt.Fprintf(w, "katana -headless\t%d\t%s\t%d\t%.1fs%s\t%.0fMB\n", b.Katana.Routes, known(b.Katana), b.Katana.Shell, b.Katana.Seconds, stopped, b.Katana.RSSMB)
			}
			if r := a.Roles; r != nil {
				fmt.Fprintf(w, "\nroles (%s)\tendpoints that differ\texpected 401 → 200\ttime\n", a.Name)
				fmt.Fprintf(w, "anon → user (token)\t%d\t%d/%d\t%.1fs\n", r.Rows, len(r.Found), len(r.Expected), r.Seconds)
				fmt.Fprintf(w, "anon → user (-role-login)\t%d\t%d/%d\t%.1fs\n", r.ChromeRows, len(r.ChromeFound), len(r.Expected), r.ChromeSecs)
			}
			if f := a.Ffuf; f != nil {
				fmt.Fprintf(w, "\nwordlist (%d words)\tazhaq hits\tshell\tffuf -ac hits\tshell\tshared\tffuf time\n", f.Words)
				fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%.1fs\n", a.Name, f.AzhaqHits, f.AzhaqShell, f.FfufHits, f.FfufShell, f.Shared, f.Seconds)
			}
		}
	}
	if len(ps.Domains) > 0 {
		fmt.Fprintf(w, "\n%s: subs -live\tazhaq live (confirmed)\tazhaq s\tsubfinder | dnsx live (confirmed)\ttime s\tboth\tgaps\n", title)
		for _, d := range ps.Domains {
			fmt.Fprintf(w, "%s\t%d\t%.0f%s\t%d\t%.0f%s\t%d\t%d\n", d.Domain, d.AzhaqLive, d.AzhaqSeconds, mem(d.AzhaqRSS), d.SubfinderLive, d.RefSeconds, mem(d.RefRSS), d.SharedLive, len(d.Gaps))
		}
		fmt.Fprintln(w, "sources\tsubdomain sources")
		for _, d := range ps.Domains {
			fmt.Fprintf(w, "%s\t%s\n", d.Domain, d.CT)
		}
	}
	if u := ps.URLs; u != nil {
		fmt.Fprintf(w, "\n%s: urls (%s)\tazhaq\tgau\tgau's in azhaq\tazhaq s\tgau s\n", title, u.Domain)
		fmt.Fprintf(w, "URLs\t%d\t%d\t%d\t%.0f%s\t%.0f%s\n", u.Azhaq, u.Gau, u.Shared, u.AzhaqSecs, mem(u.AzhaqRSS), u.GauSecs, mem(u.RefRSS))
	}
	if b := ps.Brute; b != nil {
		fmt.Fprintf(w, "\n%s: DNS brute force (%s)\tazhaq\tdnsx\tshared\tazhaq time\tdnsx time\n", title, b.Domain)
		fmt.Fprintf(w, "%d words\t%d\t%d\t%d\t%.1fs%s\t%.1fs%s\n", b.Words, b.AzhaqFound, b.DnsxFound, b.Shared, b.AzhaqSeconds, mem(b.AzhaqRSS), b.DnsxSeconds, mem(b.RefRSS))
		if b.WildcardWords > 0 {
			fmt.Fprintf(w, "wildcard zone, %d words, %d real\t%d found, %d fake\t%d unfiltered\t\t\t\n", b.WildcardWords, b.WildcardReal, b.WildcardAzhaq, b.WildcardFake, b.WildcardNoWild)
		}
	}
	if d := ps.DNS; d != nil {
		fmt.Fprintf(w, "\n%s: dns record types\tazhaq\tdnsx\tazhaq time\tdnsx time\tqueries azhaq/dnsx\n", title)
		fmt.Fprintf(w, "%d names\t%d\t%d\t%.1fs%s\t%.1fs%s\t%d / %d\n", d.Names, d.AzhaqOK, d.DnsxOK, d.AzhaqSecs, mem(d.AzhaqRSS), d.DnsxSecs, mem(d.RefRSS), d.AzhaqQ, d.DnsxQ)
	}
	if p := ps.Probe; p != nil {
		fmt.Fprintf(w, "\n%s: probe (%d hosts)\tanswered (confirmed)\tshared\tstatus\ttitle\ttech\tall\tfavicon\tcdn\ttime\n", title, p.Hosts)
		fmt.Fprintf(w, "azhaq\t%d (%d)\t%d\t%d\t%d\t%d\t%d\t%d/%d\t%d/%d\t%.1fs%s\n", p.AzhaqAnswered, p.AzhaqOK, p.Shared, p.Status, p.Title, p.Tech, p.All, p.FaviconAgree, p.FaviconBoth, p.CDNAgree, p.CDNHttpx, p.AzhaqSeconds, mem(p.AzhaqRSS))
		fmt.Fprintf(w, "httpx\t%d (%d)\t\t\t\t\t\t\t\t%.1fs%s\n", p.HttpxAnswered, p.HttpxOK, p.HttpxSeconds, mem(p.RefRSS))
	}
	if d := ps.Dirs; d != nil {
		fmt.Fprintf(w, "\n%s: paths (%d words, %d apps)\tazhaq\tffuf -ac\tshared\tfalse positives\ttime\n", title, d.Words, len(d.Apps))
		fmt.Fprintf(w, "hits\t%d\t%d\t%d\t%d / %d\t%.1fs%s / %.1fs%s\n", d.AzhaqHits, d.FfufHits, d.Shared, d.AzhaqFalse, d.FfufFalse, d.AzhaqSecs, mem(d.AzhaqRSS), d.FfufSecs, mem(d.RefRSS))
	}
	if f := ps.Fuzz; f != nil {
		fmt.Fprintf(w, "\n%s: fuzz (%d words)\tazhaq hits (confirmed)\tffuf hits (confirmed)\tshared\tazhaq s\tffuf s\tJSON report equal\n", title, f.Words)
		for _, l := range f.Legs {
			eq := "-"
			if l.ReportEqual != nil {
				eq = fmt.Sprint(*l.ReportEqual)
			}
			fmt.Fprintf(w, "%s %s\t%d (%d)\t%d (%d)\t%d\t%.1f%s\t%.1f%s\t%s\n", l.App, l.Variant, l.AzhaqHits, l.AzhaqOK, l.FfufHits, l.FfufOK, l.Shared, l.AzhaqSecs, mem(l.AzhaqRSS), l.FfufSecs, mem(l.RefRSS), eq)
		}
	}
	if p := ps.Params; p != nil {
		fmt.Fprintf(w, "\n%s: parameters (%d pages, %d names)\tazhaq\tarjun\tshared\ttime\n", title, len(p.Pages), p.Words)
		fmt.Fprintf(w, "found\t%d\t%d\t%d\t%.1fs%s / %.1fs%s\n", len(p.Azhaq), len(p.Arjun), p.Shared, p.AzhaqSecs, mem(p.AzhaqRSS), p.ArjunSecs, mem(p.RefRSS))
		fmt.Fprintf(w, "planted truth (%d)\t%d right, %d wrong\t%d right, %d wrong\t\t\n", p.PlantedTruth, p.AzhaqPlanted, p.AzhaqWrong, p.ArjunPlanted, p.ArjunWrong)
	}
	if p := ps.Ports; p != nil {
		fmt.Fprintf(w, "\n%s: ports (connect)\tazhaq\tnaabu\tconfirmed azhaq / naabu\tazhaq time\tnaabu time\n", title)
		for _, l := range p.Legs {
			fmt.Fprintf(w, "%s %s\t%d\t%d\t%d / %d\t%.1fs%s\t%.1fs%s\n", l.Target, l.Ports, l.Azhaq, l.Naabu, l.AzhaqOK, l.NaabuOK, l.AzhaqSecs, mem(l.AzhaqRSS), l.NaabuSecs, mem(l.RefRSS))
		}
	}
	if c := ps.Ports; c != nil && c.CPU != nil && !c.CPU.NmapMissing {
		c := c.CPU
		fmt.Fprintf(w, "\n%s: ports, CPU (%s %s, -rate %s)\tazhaq\tnmap -sT\n", title, c.Target, c.Ports, c.Rate)
		fmt.Fprintf(w, "CPU seconds\t%.2f\t%.2f\n", c.AzhaqCPU, c.NmapCPU)
		fmt.Fprintf(w, "time\t%.1fs\t%.1fs\n", c.AzhaqWall, c.NmapWall)
		fmt.Fprintf(w, "open ports\t%d\t%d\n", c.AzhaqOpen, c.NmapOpen)
	}
	if s := ps.Services; s != nil {
		fmt.Fprintf(w, "\n%s: services (%d lab ports)\tazhaq\tnmap -sV\tazhaq time\tnmap time\n", title, s.Ports)
		fmt.Fprintf(w, "named right\t%d\t%d\t%.1fs%s\t%.1fs%s\n", s.AzhaqNamed, s.NmapNamed, s.AzhaqSecs, mem(s.AzhaqRSS), s.NmapSecs, mem(s.RefRSS))
		fmt.Fprintf(w, "with product and version\t%d\t%d\t\t\n", s.AzhaqVer, s.NmapVer)
	}
	if s := ps.Shots; s != nil {
		fmt.Fprintf(w, "\n%s: screenshots (%d targets)\tazhaq\tgowitness\tazhaq time\tgowitness time\n", title, s.Targets)
		fmt.Fprintf(w, "not blank\t%d\t%d\t%.1fs%s\t%.1fs%s\n", s.AzhaqOK, s.GowitnessOK, s.AzhaqSeconds, mem(s.AzhaqRSS), s.GowitnessSecs, mem(s.RefRSS))
	}
	if n := ps.Notify; n != nil {
		fmt.Fprintf(w, "\n%s: notify (%d messages, 2 providers)\tazhaq\tnotify\tazhaq time\tnotify time\n", title, n.Messages)
		fmt.Fprintf(w, "received at the stub\t%d\t%d\t%.1fs%s\t%.1fs%s\n", n.AzhaqOK, n.NotifyOK, n.AzhaqSecs, mem(n.AzhaqRSS), n.NotifySecs, mem(n.RefRSS))
	}
	w.Flush()
}

// mem is a peak for a report cell, " 80MB", or nothing when it was not measured.
func mem(v float64) string {
	if v <= 0 {
		return ""
	}
	return fmt.Sprintf(" %.0fMB", v)
}

func known(s toolScore) string {
	if s.TruthOf == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d", s.Truth, s.TruthOf)
}
