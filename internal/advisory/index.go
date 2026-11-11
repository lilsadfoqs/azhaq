package advisory

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// The index is what azhaq carries so that a run can name the known
// issues of a product and version with no file from the user. It is
// built by hand, with network access, from public records (the CISA KEV
// catalogue and the NVD records with their CPE configurations) by
// `go run ./scripts/advindex`, and embedded here. Matching it is a
// lookup: it sends nothing.
//
// File format: gzip of JSON lines. The first line is IndexMeta; each
// next line is one product (its CPE vendor:product) with its records.

//go:embed index/index.json.gz
var embeddedIndex []byte

// IndexGenerator names the format and the generator that wrote an index.
const IndexGenerator = "advindex/1"

// IndexSource is one public source an index was built from.
type IndexSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Date string `json:"date"` // the day the source says it was made (YYYY-MM-DD)
	N    int    `json:"records,omitempty"`
}

// IndexMeta is the first line of an index: what it was built from, when,
// and how the product names azhaq reports find its products.
type IndexMeta struct {
	Generator string              `json:"generator"`
	Built     string              `json:"built"` // the day it was built (YYYY-MM-DD)
	Sources   []IndexSource       `json:"sources"`
	Records   int                 `json:"records"`  // distinct advisory ids
	Entries   int                 `json:"entries"`  // (product, advisory) pairs
	Products  int                 `json:"products"` // CPE vendor:product keys
	Scope     string              `json:"scope,omitempty"`
	Names     map[string][]string `json:"names"` // ProductKey of a name azhaq reports → CPE keys
}

// Label is the index as the plan and `azhaq version` name it.
func (m IndexMeta) Label() string {
	return fmt.Sprintf("advisory index %s (%d records)", m.Built, m.Records)
}

// IndexVuln is one advisory of one product. Ranges are "[1.0|2.0)" (a
// round bracket leaves the bound out, an empty bound is open); Versions
// are listed exactly.
type IndexVuln struct {
	ID       string   `json:"i"`
	CVSS     float64  `json:"s,omitempty"`
	KEV      bool     `json:"k,omitempty"`
	Plat     []string `json:"p,omitempty"` // with CondPlatform: what the record says it runs on or with (vendor:product), the first few
	Cond     int      `json:"c,omitempty"` // CondPlatform and CondEdition: what the version alone cannot settle
	Ranges   []string `json:"r,omitempty"`
	Versions []string `json:"v,omitempty"`
}

// IndexProduct is one product line of an index.
type IndexProduct struct {
	CPE   string      `json:"cpe"`
	Vulns []IndexVuln `json:"vulns"`
}

// WriteIndex writes meta and products as an index file: deterministic,
// products and records in order.
func WriteIndex(w io.Writer, meta IndexMeta, products []IndexProduct) error {
	zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(zw)
	if err := enc.Encode(meta); err != nil {
		return err
	}
	sort.Slice(products, func(i, j int) bool { return products[i].CPE < products[j].CPE })
	for _, p := range products {
		sort.Slice(p.Vulns, func(i, j int) bool { return p.Vulns[i].ID < p.Vulns[j].ID })
		if err := enc.Encode(p); err != nil {
			return err
		}
	}
	return zw.Close()
}

// Index is a read index: its meta and, for each product, its records,
// decoded the first time a service names that product.
type Index struct {
	meta IndexMeta
	raw  map[string][]byte

	mu    sync.Mutex
	vulns map[string][]IndexVuln
}

// Meta is what the index was built from.
func (ix *Index) Meta() IndexMeta { return ix.meta }

func readLines(raw []byte, each func(line []byte) error) error {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer zr.Close()
	br := bufio.NewReaderSize(zr, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			if e := each(line); e != nil {
				return e
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// ReadIndex reads an index file. A line that is not a record of the
// format is an error: an index azhaq cannot read exactly is not guessed at.
func ReadIndex(raw []byte) (*Index, error) {
	ix := &Index{raw: map[string][]byte{}, vulns: map[string][]IndexVuln{}}
	first := true
	err := readLines(raw, func(line []byte) error {
		if first {
			first = false
			if err := json.Unmarshal(line, &ix.meta); err != nil {
				return fmt.Errorf("the index header: %w", err)
			}
			if ix.meta.Generator != IndexGenerator {
				return fmt.Errorf("the index was made by %q, azhaq reads %q", ix.meta.Generator, IndexGenerator)
			}
			return nil
		}
		var head struct {
			CPE string `json:"cpe"`
		}
		if err := json.Unmarshal(line, &head); err != nil || head.CPE == "" {
			return fmt.Errorf("an index line is not a product record")
		}
		ix.raw[head.CPE] = append([]byte(nil), line...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if first {
		return nil, fmt.Errorf("the index is empty")
	}
	return ix, nil
}

// ReadIndexMeta reads the header of an index only, which is cheap.
func ReadIndexMeta(raw []byte) (IndexMeta, error) {
	var meta IndexMeta
	got := false
	stop := fmt.Errorf("stop")
	err := readLines(raw, func(line []byte) error {
		got = true
		if err := json.Unmarshal(line, &meta); err != nil {
			return fmt.Errorf("the index header: %w", err)
		}
		return stop
	})
	if err != nil && err != stop {
		return IndexMeta{}, err
	}
	if !got {
		return IndexMeta{}, fmt.Errorf("the index is empty")
	}
	return meta, nil
}

var (
	builtinOnce sync.Once
	builtin     *Index
	builtinErr  error

	overrideMu sync.Mutex
	override   *Index
)

// NewIndex is an index made of meta and products already in memory (what
// ReadIndex makes of a file), for tests and for a build.
func NewIndex(meta IndexMeta, products []IndexProduct) *Index {
	ix := &Index{meta: meta, raw: map[string][]byte{}, vulns: map[string][]IndexVuln{}}
	if ix.meta.Names == nil {
		ix.meta.Names = map[string][]string{}
	}
	for _, p := range products {
		ix.vulns[p.CPE] = p.Vulns
	}
	return ix
}

// SetBuiltin makes ix the built-in index until the returned function is
// called, for a test that needs its own records; the embedded index is
// what every other caller gets.
func SetBuiltin(ix *Index) (restore func()) {
	overrideMu.Lock()
	prev := override
	override = ix
	overrideMu.Unlock()
	return func() {
		overrideMu.Lock()
		override = prev
		overrideMu.Unlock()
	}
}

func overridden() *Index {
	overrideMu.Lock()
	defer overrideMu.Unlock()
	return override
}

// Builtin is the index embedded in the binary, read the first time it is
// asked for.
func Builtin() (*Index, error) {
	if ix := overridden(); ix != nil {
		return ix, nil
	}
	builtinOnce.Do(func() { builtin, builtinErr = ReadIndex(embeddedIndex) })
	return builtin, builtinErr
}

// BuiltinMeta is the header of the embedded index: its date and counts,
// with no need to read its records.
func BuiltinMeta() (IndexMeta, error) {
	if ix := overridden(); ix != nil {
		return ix.meta, nil
	}
	return ReadIndexMeta(embeddedIndex)
}

func (ix *Index) productVulns(cpe string) []IndexVuln {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if v, ok := ix.vulns[cpe]; ok {
		return v
	}
	var p IndexProduct
	if line, ok := ix.raw[cpe]; ok {
		_ = json.Unmarshal(line, &p) // the line was read as a record once; a bad one has no records
	}
	ix.vulns[cpe] = p.Vulns
	return p.Vulns
}

// CPEs are the products an index holds under a name azhaq reports.
func (ix *Index) CPEs(product string) []string {
	return ix.meta.Names[ProductKey(product)]
}

// NVDURL is the NVD page of a CVE.
func NVDURL(id string) string { return "https://nvd.nist.gov/vuln/detail/" + id }

// What a record's configuration leaves open, as bits of IndexVuln.Cond.
const (
	CondPlatform = 1 // it also names a platform or component the product runs with
	CondEdition  = 2 // its ranges are for a named edition or target, or for several
)

const (
	condPlatformText = "the advisory's configuration also names a platform or component the product runs with (see the advisory): azhaq does not see it"
	condEditionText  = "the advisory gives its ranges for a named edition or target of the product, or for several (a long-term release line and the weekly one): the version seen does not say which the service is"
)

func condText(c int, plat []string) string {
	var t []string
	if c&CondPlatform != 0 {
		if len(plat) > 0 {
			t = append(t, "the advisory's configuration also names what the product runs on or with ("+strings.Join(plat, ", ")+"): azhaq does not see whether the service does")
		} else {
			t = append(t, condPlatformText)
		}
	}
	if c&CondEdition != 0 {
		t = append(t, condEditionText)
	}
	return strings.Join(t, "; ")
}

// advisoryOf is an index record as an advisory of its product: the
// ranges and versions the record lists, as the OSV shape Match reads.
func advisoryOf(cpe string, v IndexVuln) (Advisory, Affected, error) {
	adv := Advisory{ID: v.ID, References: []Reference{{Type: "WEB", URL: NVDURL(v.ID)}}}
	if v.Cond != 0 {
		adv.Precondition = condText(v.Cond, v.Plat)
	}
	aff := Affected{Package: Package{Name: cpe, Ecosystem: "cpe"}, Versions: v.Versions}
	for _, r := range v.Ranges {
		rng, err := ParseIndexRange(r)
		if err != nil {
			return adv, aff, fmt.Errorf("%s of %s: %w", v.ID, cpe, err)
		}
		aff.Ranges = append(aff.Ranges, rng)
	}
	return adv, aff, nil
}

// MatchIndex is every lead of the services against the index: one per
// service and record that names its product, labelled by where the
// version seen sits in the record's range, exactly as Match labels a
// user's records. It sends nothing. A service's product is found by
// ProductKey in the names the index holds.
func MatchIndex(services []Service, ix *Index) ([]Lead, error) {
	var out []Lead
	label := "azhaq " + ix.meta.Label()
	for _, svc := range services {
		if svc.Product == "" || svc.Version == "" {
			continue
		}
		// One lead for each advisory: a record under two names NVD has used
		// for the product (proftpd:proftpd and proftpd_project:proftpd) is one
		// lead, the one that says most.
		at := map[string]int{}
		for _, cpe := range ix.CPEs(svc.Product) {
			for _, v := range ix.productVulns(cpe) {
				adv, aff, err := advisoryOf(cpe, v)
				if err != nil {
					return nil, err
				}
				lead := leadFor(svc, adv, aff)
				lead.KEV, lead.CVSS, lead.Source = v.KEV, v.CVSS, label
				if i, dup := at[v.ID]; dup {
					if labelRank(lead.Label) < labelRank(out[i].Label) {
						out[i] = lead
					}
					continue
				}
				at[v.ID] = len(out)
				out = append(out, lead)
			}
		}
	}
	sortLeads(out)
	return out, nil
}

// Advisory is the index record id as the advisory of the product a
// service named, for a confirmation read that needs its range.
func (ix *Index) Advisory(product, id string) (Advisory, bool) {
	for _, cpe := range ix.CPEs(product) {
		for _, v := range ix.productVulns(cpe) {
			if v.ID == id {
				adv, aff, err := advisoryOf(product, v)
				if err != nil {
					return Advisory{}, false
				}
				adv.Affected = []Affected{aff}
				return adv, true
			}
		}
	}
	return Advisory{}, false
}

// MatchAll is every lead of the services against the user's records and,
// when ix is not nil, the index: the leads a reader is shown, and how many
// not-affected leads of the index were only counted (see Notable). The
// user's records keep every label, as they always did.
func MatchAll(services []Service, user []Advisory, ix *Index) (leads []Lead, quiet int, err error) {
	leads = Match(services, user)
	if ix != nil {
		il, err := MatchIndex(services, ix)
		if err != nil {
			return nil, 0, err
		}
		for _, l := range il {
			if Notable(l) {
				leads = append(leads, l)
			} else {
				quiet++
			}
		}
	}
	sortLeads(leads)
	return leads, quiet, nil
}

// Notable says a lead of the index is worth a line of its own: an
// affected or conditional one, or a not-affected one for an advisory CISA
// lists as exploited (so that a patched version of a well-known flaw says
// so). The other not-affected leads are only counted.
func Notable(l Lead) bool { return l.Label != LabelNotAffected || l.KEV }

// FormatIndexRange is the text of a range of the index.
func FormatIndexRange(start string, startIncl bool, end string, endIncl bool) string {
	open, closeB := "(", ")"
	if startIncl {
		open = "["
	}
	if endIncl {
		closeB = "]"
	}
	return open + start + "|" + end + closeB
}

// ParseIndexRange reads a range of the index back into an OSV range.
func ParseIndexRange(s string) (Range, error) {
	if len(s) < 3 || (s[0] != '[' && s[0] != '(') || (s[len(s)-1] != ']' && s[len(s)-1] != ')') {
		return Range{}, fmt.Errorf("range %q is not [a|b) or its forms", s)
	}
	lo, hi, ok := strings.Cut(s[1:len(s)-1], "|")
	if !ok {
		return Range{}, fmt.Errorf("range %q has no |", s)
	}
	var ev []Event
	switch {
	case lo == "":
		ev = append(ev, Event{Introduced: "0"})
	case s[0] == '[':
		ev = append(ev, Event{Introduced: lo})
	default:
		ev = append(ev, Event{IntroducedAfter: lo})
	}
	switch {
	case hi == "":
	case s[len(s)-1] == ']':
		ev = append(ev, Event{LastAffected: hi})
	default:
		ev = append(ev, Event{Fixed: hi})
	}
	return Range{Type: "ECOSYSTEM", Events: ev}, nil
}
