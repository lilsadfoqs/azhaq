package brutecol

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v3"

	"github.com/lilsadfoqs/azhaq/internal/dnsr"
	"github.com/lilsadfoqs/azhaq/types"
)

// live names in example.org; *.wild.example.org is a wildcard.
var live = map[string]bool{"www.example.org": true, "api.example.org": true, "api2.example.org": true, "dev-api.example.org": true, "www-dev.example.org": true}

func pool(t *testing.T) *dnsr.Pool {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		name := strings.TrimSuffix(q.Name, ".")
		switch {
		case (live[name] || strings.HasSuffix(name, ".wild.example.org")) && q.Qtype == dns.TypeA:
			rr, _ := dns.NewRR(q.Name + " 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
		case live[name] || strings.HasSuffix(name, ".wild.example.org"):
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return dnsr.New(dnsr.Options{Resolvers: []string{pc.LocalAddr().String()}, PerSecond: -1})
}

func names(t *testing.T, o types.Observation) []string {
	t.Helper()
	var p struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(o.Payload, &p); err != nil {
		t.Fatal(err)
	}
	sort.Strings(p.Names)
	return p.Names
}

func TestBrute(t *testing.T) {
	p := pool(t)
	b := &Brute{Pool: p, Wild: dnsr.NewWildcards(p), Words: []string{"www", "api", "nope", "Bad Word", "x.wild", "# comment"}}
	var got types.Observation
	meta, err := b.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}},
		func(o types.Observation) error { got = o; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Join(names(t, got), ","); n != "api.example.org,www.example.org" {
		t.Fatalf("found %s (wildcard names must be dropped)", n)
	}
	if len(meta.NextHints) != 2 {
		t.Fatalf("hints %+v", meta.NextHints)
	}
}

func TestPermute(t *testing.T) {
	p := pool(t)
	perm := &Permute{Pool: p, Wild: dnsr.NewWildcards(p), Words: []string{"dev", "test"}}
	var got types.Observation
	_, err := perm.Run(context.Background(), types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "api.example.org"}},
		func(o types.Observation) error { got = o; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Join(names(t, got), ","); n != "api2.example.org,dev-api.example.org" {
		t.Fatalf("found %s", n)
	}
	// Each candidate is tried once per run.
	var again types.Observation
	_, _ = perm.Run(context.Background(), types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "api.example.org"}},
		func(o types.Observation) error { again = o; return nil })
	if again.Payload != nil {
		t.Fatalf("second run retried candidates: %s", again.Payload)
	}
}

// A name a source gave is varied even when another name's variations
// asked for it too (www is a word): only the names a variation found, which
// come back marked, are not.
func TestPermuteVariesASourceNameThatWasAlsoAGuess(t *testing.T) {
	p := pool(t)
	perm := &Permute{Pool: p, Wild: dnsr.NewWildcards(p)}
	run := func(seed types.Seed) (types.Observation, types.RunMeta) {
		var got types.Observation
		meta, err := perm.Run(context.Background(), seed, func(o types.Observation) error { got = o; return nil })
		if err != nil {
			t.Fatal(err)
		}
		return got, meta
	}
	host := func(n string) types.Seed {
		return types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": n}}
	}
	_, meta := run(host("api.example.org")) // asks www.example.org among its variations
	var marked types.Seed
	for _, h := range meta.NextHints {
		if h.Keys["fqdn"] == "www.example.org" {
			marked = h
		}
	}
	if marked.Keys[types.ViaKey] != types.ViaPermute {
		t.Fatalf("a found name is not marked: %+v", meta.NextHints)
	}
	got, _ := run(host("www.example.org")) // the seed the source gave
	if n := strings.Join(names(t, got), ","); !strings.Contains(n, "www-dev.example.org") {
		t.Fatalf("variations of www.example.org found %q", n)
	}
	if again, _ := run(marked); again.Payload != nil {
		t.Fatalf("a found name was varied: %s", again.Payload)
	}
}

func TestVariants(t *testing.T) {
	v := strings.Join(variants("web-01.example.org", []string{"dev"}), " ")
	for _, want := range []string{"web-02.example.org", "web-00.example.org", "dev-web-01.example.org", "dev.example.org", "dev.web-01.example.org"} {
		if !strings.Contains(v, want) {
			t.Errorf("missing %s in %s", want, v)
		}
	}
}

// The sample a hint shows is two of the names Permute asks: a number next to
// the first label, and an environment word joined to it.
func TestPermuteSampleIsWhatPermuteAsks(t *testing.T) {
	got := PermuteSample("api.example.org")
	want := []string{"api1.example.org", "api-dev.example.org"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sample %v, want %v", got, want)
	}
	asked := map[string]bool{}
	for _, n := range variants("api.example.org", PermuteWords) {
		asked[n] = true
	}
	for _, n := range got {
		if !asked[n] {
			t.Errorf("%s is not one Permute asks for", n)
		}
	}
	if s := PermuteSample("example"); len(s) != 0 {
		t.Errorf("a name with no dot: %v", s)
	}
}

// Every kind of variation is asked for a name, and a limit on the names asked
// still takes all of them: the kinds come early, not after the joined words.
func TestVariantsHaveEveryKind(t *testing.T) {
	kinds := map[string]string{
		"number":       "api1.example.org",
		"long number":  "api2024.example.org",
		"region":       "us-east-1.api.example.org",
		"in place":     "dev.example.org",
		"joined":       "api-dev.example.org",
		"prefixed":     "dev-api.example.org",
		"run together": "apidev.example.org",
		"one below":    "dev.api.example.org",
		"after label":  "api.dev.example.org",
	}
	all := variants("api.example.org", PermuteWords)
	for _, limit := range []int{len(all), 120, 60} {
		have := map[string]bool{}
		for _, n := range all[:limit] {
			have[n] = true
		}
		for kind, name := range kinds {
			if !have[name] {
				t.Errorf("first %d variations lack the %s kind (%s)", limit, kind, name)
			}
		}
	}
	// One below is what the help promises: dev.api.example.org, not only api-dev.
	p := pool(t)
	perm := &Permute{Pool: p, Wild: dnsr.NewWildcards(p)}
	if perm.PerHost != 0 {
		t.Errorf("a default limit per name: %d", perm.PerHost)
	}
}

// What alterx's default patterns make of a name, azhaq makes too: the same
// words, numbers and regions, in the same places. The patterns are read from
// alterx's module in the module cache.
func TestVariantsCoverAlterxDefaults(t *testing.T) {
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Skip(err)
	}
	files, _ := filepath.Glob(filepath.Join(strings.TrimSpace(string(out)), "github.com/projectdiscovery/alterx@*", "permutations.yaml"))
	if len(files) == 0 {
		t.Skip("alterx is not in the module cache; its default patterns have 6 per word, 1 per number and 1 per region")
	}
	raw, err := os.ReadFile(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Patterns []string            `yaml:"patterns"`
		Payloads map[string][]string `yaml:"payloads"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"api.example.org", "web-01.example.org", "a.b.example.org"} {
		i := strings.IndexByte(host, '.')
		sub, suffix := host[:i], host[i+1:]
		want := map[string]bool{}
		for _, pat := range cfg.Patterns {
			for _, kind := range []string{"word", "number", "region"} {
				tag := "{{" + kind + "}}"
				if !strings.Contains(pat, tag) {
					continue
				}
				for _, v := range cfg.Payloads[kind] {
					n := strings.NewReplacer(tag, v, "{{sub}}", sub, "{{suffix}}", suffix).Replace(pat)
					if n != host {
						want[n] = true
					}
				}
			}
		}
		have := map[string]bool{}
		for _, n := range variants(host, PermuteWords) {
			have[n] = true
		}
		var missing []string
		for n := range want {
			if !have[n] {
				missing = append(missing, n)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s: %d of alterx's %d names are not asked, such as %v", host, len(missing), len(want), missing[:min(5, len(missing))])
		}
		if len(have) < len(want) {
			t.Errorf("%s: %d variations, alterx's defaults make %d", host, len(have), len(want))
		}
	}
}

// -max-names caps what guessing asks, the words and the variations together:
// the words take the budget first, and a variation past it is held back, once.
func TestBudgetCapsWhatGuessingAsks(t *testing.T) {
	p := pool(t)
	bud := NewBudget(3)
	run := func(c interface {
		Run(context.Context, types.Seed, func(types.Observation) error) (types.RunMeta, error)
	}, seed types.Seed) (tried int) {
		_, err := c.Run(context.Background(), seed, func(o types.Observation) error {
			var pl struct {
				Tried int `json:"tried"`
			}
			if err := json.Unmarshal(o.Payload, &pl); err != nil {
				t.Fatal(err)
			}
			tried = pl.Tried
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return tried
	}
	b := &Brute{Pool: p, Wild: dnsr.NewWildcards(p), Budget: bud, Words: []string{"www", "api", "nope", "nope2", "nope3"}}
	if n := run(b, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}); n != 3 {
		t.Errorf("the words asked %d names, want the 3 of the budget", n)
	}
	if bud.Held() != 2 {
		t.Errorf("held %d, want the 2 words past the budget", bud.Held())
	}
	pm := &Permute{Pool: p, Wild: dnsr.NewWildcards(p), Budget: bud}
	if n := run(pm, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "api.example.org"}}); n != 0 {
		t.Errorf("-permute asked %d names after the budget was spent", n)
	}
	want := 2 // the words past the budget, and the variations that no word asked
	for _, v := range variants("api.example.org", PermuteWords) {
		if v != "www.example.org" && v != "api.example.org" {
			want++
		}
	}
	if got := bud.Held(); got != want {
		t.Errorf("held %d, want %d: 2 words and the variations of api.example.org", got, want)
	}
	// The same variations of a second name are held back once.
	run(pm, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "api.example.org"}})
	if got := bud.Held(); got != want {
		t.Errorf("held %d after the same name again, want %d", got, want)
	}
	var none *Budget
	if none.Held() != 0 || func() bool { got, _ := none.take([]string{"a", "b"}); return len(got) != 2 }() {
		t.Error("a nil budget caps nothing")
	}
}
