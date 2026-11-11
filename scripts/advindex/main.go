// Command advindex builds the advisory index azhaq carries
// (internal/advisory/index/index.json.gz) from public records. Run it by
// hand, with network access, when the index should be refreshed:
//
//	go run ./scripts/advindex
//
// It downloads the CISA KEV catalogue and the NVD CVE feeds (2.0, one
// file a year) into a cache folder, keeps the records of every KEV CVE
// and of the products internal/advisory/cpemap.tsv maps, and writes the
// index. It sends nothing but the downloads, and a record it cannot read
// stops it. See docs/CONCEPTS.md, "Known-issue matching".
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	awesomesearchqueries "github.com/projectdiscovery/awesome-search-queries"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/advisory/build"
	"github.com/lilsadfoqs/azhaq/internal/wappalyzer"
)

const (
	kevCISA   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevMirror = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
	nvdBase   = "https://nvd.nist.gov/feeds/json/cve/2.0/"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "advindex:", err)
		os.Exit(1)
	}
}

func run() error {
	cacheDefault, _ := os.UserCacheDir()
	cache := flag.String("cache", filepath.Join(cacheDefault, "azhaq-advindex"), "folder the downloads are kept in, and read from on a later run")
	out := flag.String("out", "internal/advisory/index/index.json.gz", "the index file to write")
	mapFile := flag.String("map", "internal/advisory/cpemap.tsv", "the product map")
	kevURL := flag.String("kev-url", kevCISA, "the KEV catalogue; when it cannot be read the CISA mirror on GitHub is used and said")
	from := flag.Int("from-year", 2002, "the first NVD feed year")
	to := flag.Int("to-year", time.Now().UTC().Year(), "the last NVD feed year")
	refresh := flag.Bool("refresh", false, "download again what the cache holds")
	minCVSS := flag.Float64("min-cvss", 0, "keep a record below this CVSS score only when it is on KEV (0: keep all); for a size budget")
	draft := flag.String("draft-map", "", "write FILE with a map line for each product the catalogues name with a CPE and the map lacks, and stop")
	unmapped := flag.String("unmapped", "", "write FILE with the catalogue products the map has no line for")
	built := flag.String("built", time.Now().UTC().Format("2006-01-02"), "the day to record as the build day")
	flag.Parse()

	mf, err := os.Open(*mapFile)
	if err != nil {
		return err
	}
	lines, err := build.ParseMap(mf)
	mf.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", *mapFile, err)
	}
	cat, err := catalogues()
	if err != nil {
		return err
	}
	if *draft != "" {
		return writeDraft(*draft, cat, lines)
	}

	if err := os.MkdirAll(*cache, 0o755); err != nil {
		return err
	}
	kev, usedKEV, err := fetchKEV(*cache, *kevURL, *refresh)
	if err != nil {
		return err
	}
	var feeds []build.Feed
	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			c.Close()
		}
	}()
	for y := *from; y <= *to; y++ {
		name := fmt.Sprintf("nvdcve-2.0-%d.json.gz", y)
		path, err := cached(*cache, name, nvdBase+name, *refresh)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return fmt.Errorf("%s: %w", path, err)
		}
		closers = append(closers, f, zr)
		feeds = append(feeds, build.Feed{Name: name, R: zr})
	}
	fmt.Fprintf(os.Stderr, "building from %d NVD feeds and the KEV catalogue (%s)\n", len(feeds), usedKEV)
	res, err := build.Build(build.Options{KEV: kev, KEVURL: usedKEV, NVDURL: nvdBase, Feeds: feeds, Map: lines, Built: *built, MinCVSS: *minCVSS})
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := advisory.WriteIndex(&buf, res.Meta, res.Products); err != nil {
		return err
	}
	if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		return err
	}
	report(res, buf.Len(), *out)
	return unmappedFile(*unmapped, cat, lines)
}

func report(res *build.Result, size int, out string) {
	m, r := res.Meta, res.Report
	fmt.Printf("wrote %s: %d bytes, %d records, %d (product, record) pairs, %d products\n", out, size, m.Records, m.Entries, m.Products)
	for _, s := range m.Sources {
		fmt.Printf("source: %s, %s (%d records) %s\n", s.Name, s.Date, s.N, s.URL)
	}
	if m.Scope != "" {
		fmt.Printf("scope: %s (%d records dropped)\n", m.Scope, r.DroppedByScope)
	}
	fmt.Printf("feed records read %d; rejected %d; no CPE configuration yet %d; CPE matches with no version (-) %d; CPE matches naming no one product %d\n", r.FeedCVEs, r.Rejected, r.NoConfig, r.NotApplicable, r.NoProduct)
	fmt.Printf("KEV CVEs in no feed: %d %v\n", len(r.KEVMissing), r.KEVMissing)
	fmt.Printf("KEV CVEs with no application or OS product to index: %d\n", len(r.KEVNoProduct))
	fmt.Printf("CVEs NVD marks exploited that the KEV file lacks: %d\n", len(r.KEVMismatch))
	fmt.Printf("map lines with no NVD record: %d\n", len(r.NoRecords))
	fmt.Printf("names two catalogue products answer to, reaching none: %d\n", len(r.AmbiguousNames))
	fmt.Printf("KEV products no map line names, indexed under their own CPE name: %d\n", len(r.AutoProducts))
	if len(r.NoRecords) > 0 {
		var l []string
		for _, n := range r.NoRecords {
			l = append(l, n.Name+"="+n.CPE)
		}
		sort.Strings(l)
		fmt.Printf("no NVD record for: %s\n", strings.Join(l, ", "))
	}
}

// product is one product a detection catalogue names.
type product struct {
	Name, CPE, Source string // CPE is vendor:product, "" when the catalogue gives none
}

// catalogues are the products azhaq's own detection catalogues name: the
// wappalyzer fingerprints (a CPE where they carry one) and the cpedetect
// queries (a vendor and a product).
func catalogues() ([]product, error) {
	var out []product
	var w struct {
		Apps map[string]struct {
			CPE string `json:"cpe"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(wappalyzer.GetRawFingerprints()), &w); err != nil {
		return nil, fmt.Errorf("the wappalyzer catalogue: %w", err)
	}
	for name, a := range w.Apps {
		p := product{Name: name, Source: build.SourceWappalyzer}
		if a.CPE != "" {
			f, err := build.SplitCPE(a.CPE)
			if err != nil {
				return nil, fmt.Errorf("the wappalyzer catalogue, %s: %w", name, err)
			}
			if f[3] != "" && f[4] != "" {
				p.CPE = f[3] + ":" + f[4]
			}
		}
		out = append(out, p)
	}
	raw, err := awesomesearchqueries.GetQueries()
	if err != nil {
		return nil, err
	}
	var qs []struct {
		Name   string          `json:"name"`
		Vendor json.RawMessage `json:"vendor"`
	}
	if err := json.Unmarshal(raw, &qs); err != nil {
		return nil, fmt.Errorf("the cpedetect catalogue: %w", err)
	}
	for _, q := range qs {
		var v string
		var vs []string
		if json.Unmarshal(q.Vendor, &v) != nil {
			if json.Unmarshal(q.Vendor, &vs) == nil && len(vs) > 0 {
				v = vs[0]
			}
		}
		p := product{Name: q.Name, Source: build.SourceCPEDetect}
		if v != "" && q.Name != "" {
			p.CPE = strings.ToLower(strings.ReplaceAll(v, " ", "_")) + ":" + strings.ToLower(strings.ReplaceAll(q.Name, " ", "_"))
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func mapped(lines []build.MapLine) map[string]bool {
	m := map[string]bool{}
	for _, l := range lines {
		m[l.Source+"\x00"+l.Name+"\x00"+l.CPE] = true
	}
	return m
}

// writeDraft writes a map line for each catalogue product that carries a
// CPE and has none yet, for a person to review and add to the map.
func writeDraft(path string, cat []product, lines []build.MapLine) error {
	have := mapped(lines)
	var b strings.Builder
	n := 0
	seen := map[string]bool{}
	for _, p := range cat {
		if p.CPE == "" || strings.ContainsAny(p.Name, "\t\n") || have[p.Source+"\x00"+p.Name+"\x00"+p.CPE] {
			continue
		}
		k := p.Name + "\x00" + p.CPE + "\x00" + p.Source
		if seen[k] {
			continue
		}
		seen[k] = true
		fmt.Fprintf(&b, "%s\t%s\t%s\n", p.Name, p.CPE, p.Source)
		n++
	}
	fmt.Fprintf(os.Stderr, "%d draft lines\n", n)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// unmappedFile lists the catalogue products the map has no line for.
func unmappedFile(path string, cat []product, lines []build.MapLine) error {
	named := map[string]bool{}
	for _, l := range lines {
		named[l.Source+"\x00"+l.Name] = true
	}
	var b strings.Builder
	n, total := 0, len(cat)
	for _, p := range cat {
		if !named[p.Source+"\x00"+p.Name] {
			fmt.Fprintf(&b, "%s\t%s\t%s\n", p.Source, p.Name, p.CPE)
			n++
		}
	}
	fmt.Printf("catalogue products %d; with a line in the map %d; with none %d\n", total, total-n, n)
	if path == "" {
		return nil
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

var client = &http.Client{Timeout: 10 * time.Minute}

func download(url, to string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "azhaq-advindex (public data download)")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", url, resp.StatusCode)
	}
	f, err := os.Create(to + ".part")
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(to+".part", to)
}

func cached(dir, name, url string, refresh bool) (string, error) {
	path := filepath.Join(dir, name)
	if st, err := os.Stat(path); err == nil && st.Size() > 0 && !refresh {
		return path, nil
	}
	fmt.Fprintf(os.Stderr, "downloading %s\n", url)
	if err := download(url, path); err != nil {
		return "", err
	}
	return path, nil
}

// fetchKEV reads the KEV catalogue: the URL asked for, else the CISA
// mirror on GitHub, and says which.
func fetchKEV(dir, url string, refresh bool) ([]byte, string, error) {
	tries := []string{url}
	if url == kevCISA {
		tries = append(tries, kevMirror)
	}
	var errs []string
	for i, u := range tries {
		path, err := cached(dir, fmt.Sprintf("kev-%d.json", i), u, refresh)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, "", err
		}
		if _, _, err := build.ParseKEV(raw); err != nil {
			errs = append(errs, u+": "+err.Error())
			continue
		}
		if i > 0 {
			fmt.Fprintf(os.Stderr, "the CISA site did not give the catalogue (%s); using the CISA mirror %s\n", strings.Join(errs, "; "), u)
		}
		return raw, u, nil
	}
	return nil, "", fmt.Errorf("the KEV catalogue could not be read: %s", strings.Join(errs, "; "))
}
