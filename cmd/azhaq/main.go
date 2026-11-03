package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"io"
	"log"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/collectors"
	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/internal/collectors/apicol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/asncol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/brutecol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/dirscol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/gqlcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/httpcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/paramcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/pathscol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/rendercol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/urlcol"
	"github.com/lilsadfoqs/azhaq/internal/connector"
	"github.com/lilsadfoqs/azhaq/internal/crawlscope"
	"github.com/lilsadfoqs/azhaq/internal/dnsr"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/fuzz"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/internal/timing"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

const lastDBFile = ".azhaq-last"

// version is set at release time (-ldflags "-X main.version=0.4.0"); a
// go install of a tagged version reports the module version instead.
var version = "dev"

func init() {
	// The standard library logs a host's stray bytes on an idle connection
	// ("Unsolicited response received"): noise on a quiet command's stderr.
	log.SetOutput(io.Discard)
	if version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(bi.Main.Version, "v") {
			version = strings.TrimPrefix(bi.Main.Version, "v")
		}
	}
	fetch.ToolAgent = "azhaq/" + version + " (+https://github.com/lilsadfoqs/azhaq)"
}

func main() {
	err := run(os.Args[1:])
	reportError(os.Args[1:], err)
	os.Exit(exitCode(err))
}

// reportError says on stderr why run failed, unless a summary already did.
func reportError(args []string, err error) {
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		var ee exitErr
		switch {
		case errors.As(err, &ee):
			if ee.msg != "" {
				fmt.Fprintf(os.Stderr, "azhaq: %s\n", ee.msg)
			}
		case wantsJSON(args):
			// The caller reads stderr as JSON: the error is a summary too.
			cmd := ""
			if len(args) > 0 {
				cmd = args[0]
			}
			raw, _ := json.Marshal(map[string]any{"type": "summary", "command": cmd, "version": version, "complete": false, "exit": exitCode(err), "error": err.Error()})
			fmt.Fprintf(os.Stderr, "%s\n", raw)
		default:
			fmt.Fprintf(os.Stderr, "azhaq: %v\n", err)
			var ue usageErr
			if errors.As(err, &ue) && len(args) > 0 {
				if _, ok := lookup(args[0]); ok {
					fmt.Fprintf(os.Stderr, "azhaq: azhaq help %s shows its flags and examples\n", args[0])
				}
			}
		}
	}
}

// wantsJSON says whether a command line asks for JSON output.
func wantsJSON(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		switch strings.TrimLeft(a, "-") {
		case "json", "jsonl", "json=true", "jsonl=true":
			return strings.HasPrefix(a, "-")
		}
	}
	return false
}

func run(args []string) error {
	if len(args) == 0 {
		printOverview(os.Stderr, false)
		return usagef("need a command")
	}
	switch args[0] {
	case "-h", "-help", "--help":
		return cmdHelp(args[1:])
	case "-v", "-V", "-version", "--version":
		return cmdVersion(args[1:])
	}
	c, ok := lookup(args[0])
	if !ok {
		if near := suggest(args[0]); len(near) > 0 {
			return usagef("unknown command %q; did you mean %s? (azhaq help lists every command)", args[0], strings.Join(near, " or "))
		}
		return usagef("unknown command %q (azhaq help lists every command)", args[0])
	}
	return c.run(args[1:])
}

func cmdRun(args []string) error { return cmdRunAs("run", args) }

// cmdRunAs is run for the resume of a run another command started: the
// summary names that command, and the rows are the map's, as run prints
// them.
func cmdRunAs(command string, args []string) error {
	rep := newReport("run")
	var out runOut
	if err := mapTarget(args, rep, &out); err != nil {
		return err
	}
	if command != "run" {
		rep.Command = command
		rep.Notes = append(rep.Notes, fmt.Sprintf("a resumed %s run prints the rows of the map, as run does, not %s's own rows: azhaq query -db %s lists what the run found", command, command, rep.DB))
	}
	return rep.finish(out.json, false)
}

// resumeHint is the command that continues a stopped run. The sign-in is
// not stored (no password on disk): resume signs in again, so the hint
// carries the credential flags. A cut task runs again whole, so the same
// -timeout would cut it again.
func resumeHint(db string, cut, signedIn bool, user string) string {
	hint := "azhaq resume -db " + db
	if cut {
		hint += " -timeout 0"
	}
	if signedIn {
		hint += " -login-user " + user + " -login-pass PASS"
	}
	return hint
}

// runOut is how a run prints its map: text, JSON lines, or not at all.
// embedded: a command built on run owns stdout.
// runOut is how a run prints; scratch says its database is temporary,
// so nothing is kept for azhaq resume.
type runOut struct {
	json, quiet, embedded, plan, scratch bool
	axfr                                 bool // plan: also the zone transfers of dns -axfr
	// progress is how a drop-in wants the lines of a long run: "json" for
	// its -json, which hushes the run itself; empty, as run's own flags say.
	progress string
}

// observer, when set, sees every observation of the next run as it is
// stored: the drop-in commands print their results as they come.
var observer func(types.Entity, types.Observation)

// urlSink and urlscanKey are what the urls command hands the archive
// collector in this process: a function that gets each URL as it
// arrives, and a urlscan.io key from a config file.
var (
	urlSink    func(url, source string)
	urlscanKey string
)

// mapTarget runs the engine as azhaq run does and fills rep; run and the
// commands built on it print rep.
func mapTarget(args []string, rep *report, out *runOut) (runErr error) {
	fs := newFlags("run")
	var urls stringsFlag
	fs.Var(&urls, "url", "seed URL (repeatable)")
	org := onceString(fs, "org", "seed Organization name")
	in := onceString(fs, "in", "JSONL seeds")
	list := onceString(fs, "list", "targets, one per line: URL, host, host:port or IP (- for stdin)")
	var asns, cidrs stringsFlag
	fs.Var(&asns, "asn", "seed an autonomous system: its announced prefixes (repeatable)")
	fs.Var(&cidrs, "cidr", "seed an address range such as 192.0.2.0/24 (repeatable)")
	render := fs.Bool("browser", false, "also load pages in Chrome: the requests their scripts send and the links of the rendered page (needs Chrome)")
	browserWrites := fs.Bool("browser-writes", false, "let pages in Chrome send their writes (POST, PUT, DELETE…, beacons, forms posted on load) as a user's browser would: they change data on the target; by default Chrome sends only GET, HEAD and OPTIONS outside signing in, and maps the writes it does not send")
	interact := fs.Bool("interact", false, "with -browser: click the buttons, links and menus of each page (up to -interact-clicks) to find what only a click brings; a click is made whatever its label says, and the writes it would send are refused by their method and mapped, not sent")
	interactClicks := fs.Int("interact-clicks", 12, "clicks -interact makes on each page")
	shots := fs.String("screenshots", "", "save a screenshot of each web service's front page in this directory (needs Chrome)")
	tabs := fs.Int("tabs", 6, "Chrome tabs open at once for screenshots and -browser (gowitness -t)")
	shotSize := fs.String("shot-size", "1440x900", "screenshot size in pixels, WIDTHxHEIGHT")
	shotFull := fs.Bool("shot-fullpage", false, "screenshot the whole page, not only the first screen (up to 16384 pixels tall)")
	shotWait := fs.Duration("shot-wait", 1500*time.Millisecond, "wait after a page's load event for scripts that draw after it, before the screenshot: a value is waited out whatever the page does (0: none); by default a page with no script, frame or refresh is taken once painted, and one with a script after 1.5 s")
	shotTimeout := fs.Duration("shot-timeout", 30*time.Second, "time a page gets: with -rate, how long it may go without a request let go or an answer, not in all")
	shotFormat := fs.String("shot-format", "png", "screenshot format: png or jpeg")
	shotQuality := fs.Int("shot-quality", 80, "jpeg quality, 1 to 100")
	shotJS := fs.String("shot-js", "", "a file of JavaScript to run on each page before its screenshot (it runs on the target's page)")
	shotCodes := fs.String("shot-codes", "", "take only pages that answer with these statuses, comma-separated (default: any); the others are listed as skipped")
	shotHTML := fs.Bool("shot-html", false, "keep each page's rendered HTML beside its screenshot")
	chromePath := fs.String("chrome", "", "the Chrome or Chromium to run (default $AZHAQ_CHROME, else the first found)")
	chromeProxy := fs.String("chrome-proxy", "", "send Chrome's own connections through this http or socks5 proxy (default: -proxy, else the environment's); a plain http:// request reaches an http proxy as a proxy request, a page over TLS as a CONNECT tunnel")
	chromeProfile := fs.String("chrome-profile", "", "a Chrome user data directory to use and keep: sessions it holds go with the pages (default: a temporary one)")
	chromeSandbox := fs.Bool("chrome-require-sandbox", false, "never run Chrome without its sandbox (the default since v0.15.0, so this changes nothing: kept for scripts that pass it; it cannot go with -chrome-no-sandbox)")
	chromeNoSandbox := fs.Bool("chrome-no-sandbox", false, "let Chrome run without its sandbox where the system gives it none (no user namespaces, AppArmor, a container): it is started once more without, and the summary says so. The pages it loads are the targets' and untrusted: use a throwaway environment. By default Chrome does not start then")
	unsafePorts := fs.Bool("unsafe-ports", true, "let Chrome open the ports it refuses by default (6000, 6666, 10080 and others); -unsafe-ports=false keeps its refusal")
	webScheme := fs.String("web-scheme", "", "try a name or an address over this scheme only, http or https (default: https, then http)")
	urlsTimeout := fs.Duration("urls-timeout", 3*time.Minute, "time each archive source gets per domain (the Wayback Machine's answer for a large domain takes several minutes)")
	login := fs.String("login", "", "sign in on this page with Chrome before the run; its cookies and token go with every request (needs -login-user and -login-pass)")
	loginUser := fs.String("login-user", "", "user name or email for -login")
	loginPass := fs.String("login-pass", "", "password for -login (default $AZHAQ_LOGIN_PASS)")
	maxIPs := fs.Int("max-ips", 4096, "addresses expanded from -asn and -cidr prefixes, for the whole run")
	sweep := fs.Bool("sweep", false, "cover the whole scope: the IPv4 ranges and addresses -allow and -scope hold are targets too, not only the ones named (without it a note says how much of a range the targets leave); -deny, -deny-path, -rate, -max-requests and the kill file hold as for any target, and a range is expanded up to -max-ips unless -ports scans it")
	scopeSpec := fs.String("scope", "", "a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack")
	program := fs.String("program", "", "the program to take from a -scope list (handle, name or URL)")
	probe := fs.Bool("probe", false, "resolve and fetch each target once, print one line per web service and per path -dirs found: no crawl, scripts, path checks, TLS, subdomain or archive sources, and depth 1; a flag that asks for a collector (-dirs, -params, -ports, -ports-udp, -screenshots, -browser, -dns-brute, -permute, -graphql) still runs it, and a flag for what -probe turns off (-fill-forms, -submit-forms, -path-climb, -known-files) is a usage error")
	noTakeover := fs.Bool("no-takeover", false, "do not check CNAMEs for a takeover: no question is asked about the domain of a CNAME target, in scope or not")
	noTech := fs.Bool("no-tech", false, "skip technology fingerprints (saves about 30 MB of memory)")
	noFavicon := fs.Bool("no-favicon", false, "do not hash the favicon of front pages (one or two requests less per web service)")
	urlsOut := fs.String("urls", "", "write every archived URL of the run's domains to this file, one per line")
	urlsFrom := fs.Bool("urls-source", false, "with -urls: each line is the URL, a tab, and the archive that gave it")
	urlsSubs := fs.Bool("urls-subs", true, "ask the archives for the subdomains of each domain too (false: only the name itself, as gau does without --subs)")
	urlsSources := fs.String("urls-sources", "", "ask only these archives, comma-separated: wayback, commoncrawl, otx, urlscan, arquivo (default: all)")
	urlsMC := fs.String("urls-mc", "", "keep only URLs the archive recorded with these HTTP status codes, comma-separated (200,301); OTX and urlscan.io record a status for most URLs, and a URL with none is not kept")
	urlsFC := fs.String("urls-fc", "", "leave out URLs the archive recorded with these HTTP status codes, comma-separated; a URL whose status the archive did not record is kept")
	urlsMT := fs.String("urls-mt", "", "keep only URLs the archive recorded with these MIME types, comma-separated (text/html); OTX, which keeps no type, is asked all the same and its URLs kept, with a note")
	urlsFT := fs.String("urls-ft", "", "leave out URLs the archive recorded with these MIME types, comma-separated; OTX, which keeps no type, is asked all the same and its URLs kept, with a note")
	urlsFrom2 := fs.String("urls-from", "", "only captures from this time on: YYYY, YYYYMM, YYYYMMDD or YYYYMMDDhhmmss; OTX, which dates no capture, is asked all the same and its URLs kept, with a note")
	urlsTo := fs.String("urls-to", "", "only captures up to this time, in the same form")
	urlsBlacklist := fs.String("urls-blacklist", "", "leave out URLs whose path ends in these extensions, comma-separated (png,jpg,svg)")
	urlsFP := fs.Bool("urls-fp", false, "keep one URL for each host and path, dropping the variants that differ by parameters")
	urlsRetries := fs.Int("urls-retries", 0, "times an archive request is asked again after a 429, 503 or network error, after its Retry-After (seconds or a date, however long) or 2, 5, 10, 20, then 30 s; 0 makes the first refusal final (default: a 429 or 503 is asked again until the archive's time, -urls-timeout, or the run's is spent, a network error 3 times; a wait longer than the time left ends the request at once, with the reason)")
	urlsPages := fs.Int("urls-pages", 50, "pages read from each archive for a domain (0: no cap); an archive that stops at the cap says so in the summary")
	urlsPause := fs.Duration("urls-pause", 0, "pause between the requests of one archive (default: 1 s for the Wayback Machine and Common Crawl, 0.5 s for OTX, 2 s for urlscan.io; 0 for none)")
	urlsProxy := fs.String("urls-proxy", "", "send the archive requests through this proxy: http://HOST:PORT, https:// or socks5://")
	urlsMax := fs.Int("urls-max", 500000, "URLs kept for each domain (0: no cap); the summary counts the ones past it")
	var urlsArchive stringsFlag
	fs.Var(&urlsArchive, "urls-archive", "ask NAME's archive at this address instead of its own, as NAME=URL (a mirror or a test server; repeatable)")
	urlsRaw := fs.Bool("urls-raw", false, "print the archived URLs exactly as the archives gave them: no normalising, junk filter or deduplication")
	webPorts := fs.String("web-ports", "", "ports to probe on each hostname or address of the list, comma-separated (default: 443, falling back to 80; a target given with no port and nothing there is a note, not a failure)")
	factsPath := fs.String("facts", "", "JSONL connector facts to ingest before native collectors")
	execCmd := fs.String("exec", "", "connector command (seeds on stdin, facts on stdout)")
	dbPath := fs.String("db", "", "the workspace, a SQLite file (default: a new azhaq-TIME-PID.db in the current directory, or $AZHAQ_DB; query, show and export read it afterwards)")
	demo := fs.Bool("demo", false, "run against the built-in fixture server (no internet)")
	pathsFile := fs.String("paths", "", "extra path wordlist (one path per line)")
	quiet := fs.Bool("quiet", false, "print no map and no progress lines (a line every 10 s while the run works), only the summary (on stderr)")
	jsonOut := fs.Bool("json", false, "print the map as JSON lines, and the summary as one JSON object on stderr")
	storeResp := fs.Bool("sr", false, "also write each answer a target gave, headers and body as read, to the -srd directory as DIR/HOST/SHA1.txt with an index.txt (katana's -sr); query -fields response_file says where a row's is")
	storeRespDir := fs.String("srd", "azhaq_response", "directory for -sr")
	omitBody := fs.Bool("ob", false, "with -sr: write the status line and headers only")
	stream := fs.Bool("stream", false, "also print each name, address, URL and open port as it is found, once per map row (found lines, before the ranked map)")
	verbose := fs.Bool("v", false, "print a line for every finished task, not only failures")
	timeout := fs.Duration("timeout", 0, "stop after this long and keep what was found; azhaq resume continues (0: no limit)")
	showObs := fs.Bool("obs", false, "also print the observation log")
	fs.Bool("fail-on-errors", false, "accepted, and the default: every failure exits 3, a fan-out one and a source that failed while others answered included; no flag turns a failure into exit 0")
	failCapped := fs.Bool("fail-on-capped", false, "exit 4 also when the run hit -depth with hints left")
	passive := fs.Bool("passive", false, "skip HTTP/crawl/JS/paths/TLS (no handshake to the target)")
	depth := fs.Int("depth", 4, "max fan-out waves (0 = seed wave only, not unlimited)")
	maxItems := fs.Int("max-items", 0, "most collector tasks (a name, a URL, an address each, per collector) this run starts (default: no cap, katana's and httpx's); the work left is for azhaq resume, which starts as many more")
	catchAfter := fs.Int("catchall-after", fetch.CatchAllStop, "stop asking the paths scripts name in a directory once this many of them have answered with the page every unknown path gets, before as many have answered anything else; they stay in the map as skipped (0: ask them all)")
	noCatchAll := fs.Bool("no-catchall", false, "leave out URLs that answer with the page every unknown path gets (client-side routes of a single-page app) from the rows printed")
	perTmpl := fs.Int("per-template", 0, "URLs of one template (/product?id={n}) to request; the rest are listed (default: all)")
	maxRequests := fs.Int64("max-requests", 0, "requests to targets this run may send (0: no cap); the work left over is for azhaq resume")
	rateFlag := fs.Float64("rate", 0, "requests per second to targets, over all hosts (0: no pace)")
	ledgerFlag := fs.String("ledger", "", ledgerHelp)
	killFile := fs.String("kill-file", "", killFileHelp)
	sealTo := fs.String("seal-to", "", sealToHelp)
	resumeRun := fs.String("resume-run", "", "internal: continue this run of -db (azhaq resume sets it)")
	retryRun := fs.String("retry-run", "", "with -retry-failed: the run to ask again, by the run_id of its summary (default: the newest run of the workspace)")
	retryFailed := fs.Bool("retry-failed", false, "with azhaq resume: ask again the failed targets the summary marks retryable (a timeout, a closed connection, a 429 or 5xx); only those run again")
	probeOpts := fs.String("probe-opts", "", "internal: azhaq probe's httpx options, as JSON")
	serve := fs.String("serve", "", "let azhaq worker processes take this run's work, at this address (127.0.0.1:7777)")
	workerToken := fs.String("worker-token", os.Getenv("AZHAQ_WORKER_TOKEN"), "the token workers give (default $AZHAQ_WORKER_TOKEN, else a new one)")
	workerOf := fs.String("worker-of", "", "internal: run as a worker of the run at this address (azhaq worker sets it)")
	daily := fs.Int64("daily-requests", 0, "requests a day to the program's targets (-program, else this run's targets), counted over the runs in -db")
	maxNames := fs.Int("max-names", 0, "most hostnames this run resolves (default 200000, as many as subs keeps for a domain); the names left are for azhaq resume. A value you give also caps the names -dns-brute and -permute ask, together: the guesses past it are not asked, the run exits 4 and says how many (a larger -max-names asks them)")
	parallel := fs.Int("parallel", 0, "work items in flight (default 16)")
	delay := fs.Duration("delay", 0, "pause before each uncached fetch")
	noFollow := fs.Bool("no-follow", false, "do not follow redirects: each URL is asked once and its redirect recorded with the Location (httpx's default)")
	hostParallel := fs.Int("host-parallel", 0, "requests in flight per host (default 10, as katana)")
	retryFlag := fs.Int("retry", 0, "ask again this many times when a host that answered before gives no answer (a timeout, a reset)")
	backoff := fs.Bool("backoff", false, "when a host answers 429 or 503, wait (1 s doubling to 30 s, or its Retry-After) and ask again, up to 3 times; the summary says which hosts did")
	cookieJar := fs.Bool("cookie-jar", false, "carry the cookies targets set (Set-Cookie) on the requests that follow, as a browser does; -cookie and -header values go first")
	hostRate := fs.Float64("host-rate", 0, "requests per second to each host, besides -rate over all (0: none)")
	maxHostReq := fs.Int64("max-host-requests", 0, "requests one host may be sent (0: no cap); the rest of its work is left for azhaq resume")
	reqTimeout := fs.Duration("request-timeout", 0, "time one request gets, headers and body (default: 10 s for headers, 30 s in all; not -timeout, the run's bound)")
	maxResp := fs.Int("max-response-size", 0, "bytes read of a page or document (default 2097152; scripts and JSON get 16 MiB)")
	noMapGuess := fs.Bool("no-map-guess", false, "do not ask for main.js.map next to a script that names no source map (a map a script or a header names is still read)")
	fillForms := fs.Bool("fill-forms", false, "ask the action of each GET form with neutral values in its fields (a search box gets a word): one GET request per form, even one that deletes or logs out (-deny-path keeps its action out); a form that posts is not sent unless -submit-forms; crawl does this by default (-no-form-fill turns it off)")
	pathClimb := fs.Bool("path-climb", false, "also list and ask the parent directories of each link a page names (/a/b/c: /a/b/ and /a/)")
	submitForms := fs.Bool("submit-forms", false, "also submit POST forms with neutral values (crawl): CHANGES DATA on the target, each submission counts as a request and is in the ledger, the summary says how many; held to -allow, -deny and the crawl's scope")
	sourcesList := fs.String("sources", "", "subdomain sources to run, comma-separated (default: the default set; none: no source, and no archive, RDAP, search engine or RIPEstat lookup either: only the resolvers and the targets are asked)")
	excludeSources := fs.String("exclude-sources", "", "subdomain sources never to run, comma-separated")
	allSources := fs.Bool("all-sources", false, "also run slower subdomain sources outside the default set")
	noHistory := fs.Bool("no-history", false, "do not read or write the name history (names earlier runs found, kept under $AZHAQ_DATA_DIR, else ~/.local/share/azhaq; with -live each is checked by DNS in the run)")
	sourceTimeout := fs.Duration("source-timeout", subcol.DefaultSourceTimeout, "give each subdomain source this long, 30s as subfinder does; a slower one (crt.sh) is abandoned, listed as failed, and the names the others gave are kept; -source-timeout 60s or more waits for crt.sh on a large domain (not -timeout, the run's bound)")
	sourceRate := fs.Float64("source-rate", 0, "requests per second to each subdomain source, as subfinder -rl (0: each source's own pace); a source's lower own pace stays")
	sourceRates := fs.String("source-rates", "", "pace single subdomain sources, as subfinder -rls: name=N/unit, comma-separated, unit s, m or h (hackertarget=10/m,crtsh=1/s)")
	maxResults := fs.Int("max-results", 0, "most names one paging subdomain source gives (0: no cap), as subfinder -mr")
	maxTime := fs.Duration("max-time", 0, "how long the run may take: subs stops after this long, in any phase (the sources, subdomain.center's guesses, the DNS checks of -live, -w and -permute), exits 4 and leaves the rest for azhaq resume; run and plan only wait this long for the sources of a domain, then go on with what they gave (0: -source-timeout and a short grace bound the wait; -timeout bounds a run), as subfinder -max-time")
	maxBody := fs.Int64("max-body", 0, "largest response body read from a subdomain source, in bytes (default 33554432), as subfinder -rsr")
	sourceProxy := fs.String("source-proxy", "", "send every subdomain source request through this proxy URL, as subfinder -proxy (else HTTP_PROXY and HTTPS_PROXY)")
	providersFile := fs.String("providers", "", "API keys per source, YAML (default ~/.config/azhaq/providers.yaml, else subfinder's provider-config.yaml)")
	resolversFile := fs.String("resolvers", "", "DNS resolvers: a file with one per line, or a comma list; each is ADDR, ADDR:PORT or udp:, tcp:, dot:, doh:URL[:get] and then the address (default: public resolvers). Named resolvers answer every name, special-use ones (.test, .local, localhost) included; the system resolver is never asked")
	dnsRate := fs.Float64("dns-rate", 0, "DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx)")
	bruteFile := fs.String("dns-brute", "", "resolve WORD.domain for each word in this file (active; the targets given are the scope unless -allow)")
	permute := fs.Bool("permute", false, "resolve variations of found names (active; the targets given are the scope unless -allow)")
	portsSpec := fs.String("ports", "", "scan TCP ports: top-100, top-1000, full or a list of ports, ranges and these names, such as 22,80,8000-8100 or top-100,8888 (active; the targets given are the scope unless -allow)")
	portsUDP := fs.String("ports-udp", "", "ask UDP ports (active): top (about 25 common ones), full or a list of ports, ranges and these names, such as 53,123,161,1-1024 or top,5354; a reply is open, an ICMP unreachable closed, neither open|filtered (-ports none: UDP only)")
	portRate := fs.Float64("port-rate", 0, "port connection attempts per second, a ceiling (0: 1500, as naabu's connect scan, and 127.0.0.1 unpaced)")
	portMinRate := fs.Float64("port-min-rate", 0, "port connection attempts per second at least, as nmap's --min-rate: raises -port-rate to this when lower, and sets no ceiling")
	portTimeout := fs.Duration("port-timeout", 0, "wait this long for one port to accept or refuse a connect (0: 1.5s)")
	portRetries := fs.Int("port-retries", -1, "more passes over the ports that neither accepted nor refused: n passes over all of them, 0 none (default: one, when few did not answer)")
	portWorkers := fs.Int("port-workers", 0, "port connects in flight at once, over all hosts (0: as many as the rate allows, up to 20000)")
	portOrder := fs.String("port-order", "random", "the order a host's ports are asked in: random (the likeliest ports first, each tier shuffled) or asc")
	portSeed := fs.Int64("port-seed", 0, "make the random port order repeat (0: a new one each run)")
	portThreshold := fs.Int("port-threshold", 0, "stop asking a host after this many open ports: it answers every port (0: no limit)")
	portUnnamed := fs.Int("port-unnamed", 0, "after this many open ports of an address that no protocol probe could name, ask its other silent ports their banner only (0: 6; -1: no limit; each probe is a connect)")
	portDetect := fs.String("port-detect", "all", "what is asked of an open port: all (its banner, then HTTP and TLS, then one request of each protocol that waits to be asked, each on its own connection, several at once while the scan has workers free: at most 25 connects after the first), banner (what it says on the one connection; nothing is sent, so a bare 220 stays ftp-or-smtp) or none (connect and close). UDP ports: all and banner ask every request a port's protocol has (4 datagrams to a silent port); none asks one")
	portCDNFull := fs.Bool("port-cdn-full", false, "accepted: CDN and WAF addresses are scanned in full by default")
	portExcludeCDN := fs.Bool("port-exclude-cdn", false, "ask a CDN or WAF address only ports 80, 443, 8080 and 8443 (naabu -ec asks 80 and 443; this adds 8080 and 8443)")
	portDiscover := fs.String("port-discover", "", "ask first whether an address is up, by a connect to 80 and 443: first (scan the ones that answer) or only (list them, scan nothing)")
	portIP := fs.String("port-ip", "", "the address families of a name to scan: 4 or 6 (default both)")
	portAllIPs := fs.Bool("port-all-ips", false, "scan every address of a name, not the first two of each family")
	portSource := fs.String("port-source-ip", "", "connect from this local address")
	portProxy := fs.String("port-proxy", "", "connect to TCP ports through this SOCKS5 proxy (host:port); a port is then asked its banner only, and UDP is not sent")
	portProxyAuth := fs.String("port-proxy-auth", "", "user:password for -port-proxy")
	portPayload := fs.String("port-payload", "", "send this to each open TCP port before reading what it says (\\r and \\n are CR and LF)")
	var portsOn stringsFlag
	fs.Var(&portsOn, "ports-on", "scan only these ports on a host: HOST=22,80 (repeatable)")
	dirsFile := fs.String("dirs", "", "guess paths on each web service from this wordlist, or @common for the built-in one (active; the targets given are the scope unless -allow)")
	dirsExt := fs.String("dirs-ext", "", "also try each word with these extensions, comma-separated (php,bak)")
	dirsDepth := fs.Int("dirs-depth", 1, "directory levels to sweep; 2 also sweeps directories found")
	dirsThreads := fs.Int("dirs-threads", 40, "path guesses in flight per service (as ffuf)")
	dirsRate := fs.Float64("dirs-rate", 0, "path guesses per second per host (0: no limit but -dirs-threads, as ffuf)")
	paramsFile := fs.String("params", "", "find query parameters pages read, from this wordlist or small, medium or large for a built-in one (active; the targets given are the scope unless -allow)")
	paramsPerHost := fs.Int("params-per-host", 20, "pages searched for parameters per host")
	paramsRate := fs.Float64("params-rate", 0, "parameter requests per second per host (0: no limit, as arjun)")
	paramsThreads := fs.Int("params-threads", 5, "parameter requests in flight per page (as arjun -t); 1 with -params-delay and -params-stable")
	paramsChunk := fs.Int("params-chunk", 0, "names per parameter request at most (0: 500, and about 7.6 KB in a query; fewer where the server refuses a long query)")
	paramsMethod := fs.String("params-method", "GET", "how names are sent: GET (query), POST (form body), JSON or XML. A body sends requests that may change data on the target: -params-writes must say it is wanted")
	paramsWrites := fs.Bool("params-writes", false, "let -params-method POST, JSON or XML send bodies (they may change data on the target); needs -allow or -scope, or a single target")
	paramsInclude := fs.String("params-include", "", "sent with every parameter request: a query for GET; for a body a form, a JSON object or XML, or a template with $arjun$ where the names go")
	paramsDelay := fs.Duration("params-delay", 0, "wait before each parameter request, one at a time (arjun -d)")
	paramsStable := fs.Bool("params-stable", false, "one parameter request at a time, 3 to 9 s apart, and 30 s after a refused connection (arjun --stable)")
	paramsTimeout := fs.Duration("params-timeout", 15*time.Second, "wait for each parameter request; one that times out is asked again with 5 s more, up to 20 s (arjun -T)")
	paramsTargets := fs.String("params-targets", "", "file of JSON: pages that are asked otherwise ({\"URL\":{\"method\":\"POST\",\"include\":\"a=1\",\"header\":[\"Name: value\"]}}), as params -i writes it")
	dirsCal := fs.Bool("dirs-ac", true, "calibrate on paths that cannot exist, as ffuf's -ac does, so a catch-all answer is not listed even with a filter of your own; -dirs-ac=false sends no guesses and lists what the filters leave")
	dirsMatch := map[string]*string{}
	for _, m := range dirsMatchers {
		dirsMatch[m.flag] = fs.String("dirs-"+m.flag, "", m.help)
	}
	var advFlags advisoryFlags
	advFlags.register(fs)
	graphql := fs.Bool("graphql", false, "read the schema of GraphQL endpoints with an introspection query (active; the targets given are the scope unless -allow)")
	graphqlWordlist := fs.String("graphql-wordlist", "", "extra probe words (one per line), tried and recombined with the built-in ones when a GraphQL endpoint's introspection is off and its schema has to be recovered from validation errors")
	skip := fs.String("skip", "", "collectors not to run, comma-separated: azhaq-ports or ports, subs for the subdomain collector (azhaq plan lists them); a name that is none is an error; azhaq resume leaves out the tasks the run kept for them")
	noPaths := fs.Bool("no-paths", false, "do not ask each web service for the 51 built-in paths (robots.txt, sitemaps, API descriptions, .git/HEAD, backup, admin, …): some programs count that as scanning")
	knownFiles := fs.String("known-files", "", "ask each web service only for its robots.txt and sitemaps and read every entry (all, robotstxt or sitemapxml); replaces the 51 built-in paths")
	proxyFlag := fs.String("proxy", "", "send requests to targets through this proxy (http://, https:// or socks5://); Chrome too (default: $HTTP_PROXY, $HTTPS_PROXY, except for loopback targets, which stay direct)")
	crawlScope := fs.String("crawl-scope", "", "the hosts a crawl follows links to: rdn (the start host's registrable domain and its subdomains), fqdn (the host only), dn (hosts that name its domain keyword) or a regex on the host (default: rdn for a name, the origin itself for an address)")
	crawlAny := fs.Bool("crawl-any-host", false, "follow links to any host, within -allow and -deny (katana's -ns)")
	var cookies, headers, allow, deny, denyPath, domains, crawlIn, crawlOut stringsFlag
	fs.Var(&crawlIn, "crawl-in", "follow only URLs that match this regex (repeatable)")
	fs.Var(&crawlOut, "crawl-out", "never follow URLs that match this regex (repeatable)")
	fs.Var(&domains, "domain", "seed Domain, for subdomain discovery (repeatable)")
	fs.Var(&cookies, "cookie", "Cookie name=value (repeatable; sent as one Cookie header)")
	fs.Var(&headers, "header", "extra request header K: V (repeatable)")
	fs.Var(&headers, "H", "same as -header")
	fs.Var(&allow, "allow", "a domain, host or address range the run may touch; HOST:PORT allows that host on that port only; with any -allow, nothing else is requested (repeatable)")
	fs.Var(&deny, "deny", "a domain, host or address range the run must not touch, even when given as a target (repeatable)")
	fs.Var(&denyPath, "deny-path", "a regular expression on a URL's path and query: a URL it matches is never requested, by any collector or Chrome, and is listed as not requested (repeatable; azhaq decides nothing by itself)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *retryFailed || *retryRun != "" {
		return usagef("-retry-failed and -retry-run continue a run: give them to azhaq resume -db FILE")
	}
	if err := advFlags.check(); err != nil {
		return err
	}
	if advFlags.on && out.plan {
		return usagef("-advisories matches what a run confirmed: a plan sends nothing and confirms nothing to match, so run without plan")
	}
	if err := scope.CompilePaths(denyPath); err != nil {
		return usagef("%v", err)
	}
	out.json, out.quiet = *jsonOut, *quiet
	rep.hintsOff, rep.hintsVrb = *jsonOut, *verbose
	// Port lists are checked before anything is sent (a sign-in comes first).
	if _, err := portscan.Ports(*portsSpec); *portsSpec != "" && err != nil {
		return usagef("-ports: %v", err)
	}
	if _, err := portscan.UDPPorts(*portsUDP); *portsUDP != "" && err != nil {
		return usagef("-ports-udp: %v", err)
	}
	portCfg, err := portConfig(portFlags{minRate: *portMinRate, timeout: *portTimeout, retries: *portRetries, workers: *portWorkers,
		order: *portOrder, seed: *portSeed, threshold: *portThreshold, unnamed: *portUnnamed, detect: *portDetect, cdnFull: *portCDNFull, excludeCDN: *portExcludeCDN, discover: *portDiscover,
		ip: *portIP, allIPs: *portAllIPs, source: *portSource, payload: *portPayload, on: portsOn, proxy: *portProxy, proxyAuth: *portProxyAuth})
	if err != nil {
		return err
	}

	fetch.Reset()
	fetch.Delay = *delay
	fetch.NoFollow = *noFollow
	crawlscope.Reset()
	if *storeResp && !out.plan {
		answers, err := newAnswerStore(*storeRespDir, *omitBody, *resumeRun != "")
		if err != nil {
			return err
		}
		answerTap = answers.tap
		answerDir, _ = filepath.Abs(*storeRespDir)
		defer func() {
			answerTap, answerDir = nil, ""
			if err := answers.close(); err != nil {
				rep.Notes = append(rep.Notes, fmt.Sprintf("answers written to %s: %v", *storeRespDir, err))
				return
			}
			rep.Notes = append(rep.Notes, fmt.Sprintf("%d answers written to %s", answers.n, *storeRespDir))
		}()
	}
	fetch.Tap = answerTap
	fetch.Retry, fetch.Backoff = *retryFlag, *backoff
	fetch.UseJar(*cookieJar)
	fetch.SetHostRate(*hostRate)
	fetch.MaxPerHost = *maxHostReq
	fetch.RequestTimeout = *reqTimeout
	if *maxResp > 0 {
		fetch.MaxBody = *maxResp
	}
	if k := strings.ToLower(*knownFiles); !slices.Contains([]string{"", "all", "robotstxt", "robots", "sitemapxml", "sitemap"}, k) {
		return usagef("-known-files is all, robotstxt or sitemapxml, got %q", *knownFiles)
	}
	if *proxyFlag != "" {
		pu, err := parseProxy(*proxyFlag)
		if err != nil {
			return err
		}
		egress.SetTargetProxy(pu)
	}
	var spec *httpcol.Spec
	if *probeOpts != "" {
		spec = new(httpcol.Spec)
		if err := json.Unmarshal([]byte(*probeOpts), spec); err != nil {
			return usagef("-probe-opts: %v", err)
		}
		if err := spec.Apply(); err != nil {
			return usageErr{err}
		}
		probeSeeding = true
		defer func() { probeSeeding = false }()
	}
	if *hostParallel > 0 {
		fetch.HostParallel = *hostParallel
	}
	if err := applyExtra(cookies, append(headers, workerHeaders...)); err != nil {
		return err
	}

	var client *http.Client
	var seeds []types.Seed
	var listLines []string // kept in the workspace, for azhaq resume
	if *demo {
		if len(urls) > 0 || *org != "" || *in != "" {
			fmt.Fprintln(os.Stderr, "azhaq: -demo ignores -url/-org/-in")
		}
		srv := demoServer()
		defer srv.Close()
		client = srv.Client()
		seeds = []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}}
	} else {
		var err error
		seeds, err = loadSeeds(urls, *org, *in)
		if err != nil {
			return err
		}
		if *list != "" {
			more, lines, err := loadList(*list)
			if err != nil {
				return err
			}
			seeds = append(seeds, more...)
			listLines = lines
		}
		for _, a := range asns {
			n, ok := asncol.NormalizeASN(a)
			if !ok {
				return usagef("-asn wants a number such as AS64500, got %q", a)
			}
			seeds = append(seeds, types.Seed{Type: types.TypeASN, Keys: map[string]string{"asn": n}})
		}
		for _, c := range cidrs {
			pf, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil {
				return usagef("-cidr: %v", err)
			}
			seeds = append(seeds, types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": pf.Masked().String()}})
		}
		for _, d := range domains {
			h := normalize.Hostname(d)
			if h == "" || strings.ContainsAny(h, "/: ") {
				return usagef("-domain wants a bare domain such as example.com, got %q", d)
			}
			seeds = append(seeds, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": h}})
		}
		if *scopeSpec != "" {
			sc, err := loadScope(*scopeSpec, *program)
			if err != nil {
				return err
			}
			more, err := scopeSeeds(sc)
			if err != nil {
				return err
			}
			if len(seeds) == 0 {
				seeds = append(seeds, more...)
			} else {
				// Targets were given: the program's scope filters them,
				// it adds none of its own.
				rep.Notes = append(rep.Notes, fmt.Sprintf("-scope %s filters the %d targets given; without targets it maps the program's own (%d)", sc.Program, len(seeds), len(more)))
			}
			allow = append(allow, sc.Allow...)
			deny = append(deny, sc.Deny...)
			if !*quiet && !*jsonOut {
				fmt.Fprintf(os.Stderr, "scope %s: %d rules in, %d out, %d domains, %d targets, %d entries skipped\n",
					sc.Program, len(sc.Allow), len(sc.Deny), len(sc.Domains), len(sc.Targets), len(sc.Skipped))
			}
			for _, e := range sc.Skipped {
				rep.Skipped = append(rep.Skipped, engine.Skip{Target: e, Reason: "a scope entry a run cannot use"})
			}
		}
		if *sweep {
			more, v6, err := sweepSeeds(allow, seeds)
			if err != nil {
				return err
			}
			for _, pf := range v6 {
				rep.Notes = append(rep.Notes, fmt.Sprintf("-sweep leaves the IPv6 range %s alone: name it as a target to scan it", pf))
			}
			seeds = append(seeds, more...)
		} else if lead := sweepLead(allow, deny, namedAddrs(seeds)); lead != "" {
			rep.Notes = append(rep.Notes, lead)
		}
		if len(seeds) == 0 && *factsPath == "" && *execCmd == "" && *workerOf == "" {
			return usagef("need a target: -url, -domain, -list, -scope, -asn, -cidr, -org, -in, -facts, -exec or -demo")
		}
		if *execCmd != "" && len(seeds) == 0 {
			return usagef("-exec needs a seed (-url, -org or -in)")
		}
	}

	// Everything that can make this a usage error is checked before a
	// database is created.
	scopeNamed := len(allow) > 0
	active := *bruteFile != "" || *permute || *graphql || *portsSpec != "" || *portsUDP != "" || *dirsFile != "" || *paramsFile != "" || advFlags.confirm
	if *paramsFile != "" {
		switch m := strings.ToUpper(*paramsMethod); m {
		case "GET":
		case "POST", "JSON", "XML":
			if !*paramsWrites {
				return usagef("-params-method %s sends bodies that may change data on the target: add -params-writes to say that is wanted", m)
			}
			if !scopeNamed && len(seeds) != 1 {
				return usagef("-params-method %s needs the targets named: give -allow or -scope, or run on one target", m)
			}
		default:
			return usagef("-params-method %q: use GET, POST, JSON or XML", *paramsMethod)
		}
	}
	if active && len(allow) == 0 {
		noRule := len(deny) == 0 && *scopeSpec == ""
		allow = seedScope(seeds) // the targets given are the scope, as in the drop-ins
		if noRule {
			// With no rule, what the command line names is the authorization:
			// a host a -header names joins the targets.
			allow = append(allow, headerHosts(fetch.Extra)...)
		}
	}
	rules := scope.Rules{Allow: append([]string(nil), allow...), Deny: append([]string(nil), deny...), DenyPath: append([]string(nil), denyPath...)}.Compile()
	if err := hostHeadersInScope(fetch.Extra, rules); err != nil {
		return err
	}
	// What a request file, a page list or a probe line brings is held to it too.
	if *paramsFile != "" && *paramsTargets != "" {
		if err := paramsTargetsInScope(*paramsTargets, rules); err != nil {
			return err
		}
	}
	if err := probeSpecInScope(spec, rules); err != nil {
		return err
	}
	if !rules.Empty() {
		// What the scope excludes is never touched, even when it was given
		// as a target: it is listed in the summary instead.
		kept := seeds[:0]
		var outside []string // the targets no address of can pass, as given
		viaPort := false     // some are outside only for their port
		reachable := 0
		for _, s := range seeds {
			switch {
			case !rules.AllowsSeed(s):
				reason := "outside the scope"
				if u, err := url.Parse(s.Key()); err == nil && s.Type == types.TypeURL && rules.OnlyOtherPort(u.Hostname(), scope.URLPort(u)) {
					reason, viaPort = neterr.OutOfPortReason, true
				}
				rep.Skipped = append(rep.Skipped, engine.Skip{Target: s.Key(), Reason: reason})
				outside = append(outside, s.Key())
			case seedOutsideRange(rules, s):
				// Kept: its addresses are each refused and counted in the summary.
				kept = append(kept, s)
				outside = append(outside, s.Key())
			default:
				kept = append(kept, s)
				reachable++
			}
		}
		seeds = kept
		if reachable == 0 && *factsPath == "" && *execCmd == "" && *workerOf == "" && !*demo {
			if viaPort {
				return outsideScope(outside, " (an -allow entry lists a host with a port: name the target with it, such as -url http://HOST:PORT/)")
			}
			return outsideScope(outside)
		}
	}
	if fi, err := os.Stat(*shots); *shots != "" && err == nil && !fi.IsDir() {
		return usagef("the screenshot directory %s is a file: -dir (shots) or -screenshots (run) names a directory", *shots)
	}
	if active && len(allow) == 0 {
		return usagef("-dns-brute, -permute, -graphql, -ports, -dirs, -params and -advisories-confirm need a target that names a host, domain or address (an ASN or organisation does not), or -allow / -scope")
	}
	if advFlags.confirm && rules.Empty() {
		return usagef("-advisories-confirm sends its reads only inside a scope: give -allow, -scope or a target that names a host or address")
	}
	ports, err := parsePorts(*webPorts)
	if err != nil {
		return usageErr{err}
	}
	seeds = bareAddressPorts(seeds, ports)

	// A URL the user gave with a path is swept from that path (-dirs).
	for _, sd := range seeds {
		if sd.Type == types.TypeURL && sd.Keys != nil {
			sd.Keys[types.StartKey] = "1"
		}
	}
	input := store.SeedsKey(normalizeSeeds(seeds))
	var path string
	var remember bool
	if out.plan {
		// A plan writes nothing: its database is a scratch one.
		dir, err := os.MkdirTemp("", "azhaq-plan-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		path = filepath.Join(dir, "plan.db")
	} else {
		path, remember = resolveDB(*dbPath)
		if remember {
			// A run refused for its options leaves no database behind.
			defer func() {
				var u usageErr
				if errors.As(runErr, &u) {
					for _, f := range []string{path, path + "-wal", path + "-shm"} {
						_ = os.Remove(f)
					}
				}
			}()
		}
	}
	prevDB := ""
	if remember {
		prevDB = previousRun(input)
		if err := os.WriteFile(lastDBFile, []byte(path+"\n"), 0o644); err != nil {
			return err
		}
	}

	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	if input != "" && !*demo {
		if err := st.SaveInput(input); err != nil {
			return err
		}
	}
	budgets := engine.DefaultBudgets()
	budgets.FailOnCapped = *failCapped
	budgets.Passive = *passive
	budgets.Scope = rules
	if *depth == 0 {
		budgets.MaxDepth = 1
	} else {
		budgets.MaxDepth = *depth
	}
	if *maxItems > 0 {
		budgets.MaxItems = *maxItems
	}
	budgets.PerTemplate = *perTmpl
	budgets.CatchAllStop = max(*catchAfter, 0)
	if *maxNames > 0 {
		budgets.MaxNames = *maxNames
	}
	if *parallel > 0 {
		budgets.Parallel = *parallel
	}
	budgets.Skip = map[string]bool{}
	if *noPaths {
		budgets.Skip["azhaq-paths"] = true
	}
	skipped, err := resolveSkip(splitList(*skip))
	if err != nil {
		return usagef("-skip: %v", err)
	}
	for _, name := range skipped {
		budgets.Skip[name] = true
	}
	budgets.Active = map[string]bool{}
	if *bruteFile != "" {
		budgets.Active["dns-brute"] = true
	}
	if *permute {
		budgets.Active["permute"] = true
	}
	if *graphql {
		budgets.Active["graphql"] = true
	}
	if *portsSpec != "" || *portsUDP != "" {
		budgets.Active["ports"] = true
	}
	if *dirsFile != "" {
		budgets.Active["dirs"] = true
	}
	if *paramsFile != "" {
		budgets.Active["params"] = true
	}
	if !budgets.Scope.Empty() {
		egress.SetScope(budgets.Scope.Allows)
		egress.SetScopeAddr(budgets.Scope.AllowsAddr)
	}
	if len(budgets.Scope.DenyPath) > 0 {
		egress.SetDenyPath(budgets.Scope.DeniedPath)
	}
	if *crawlScope != "" || *crawlAny || len(crawlIn) > 0 || len(crawlOut) > 0 {
		var roots []string
		for _, sd := range seeds {
			if sd.Type == types.TypeURL {
				roots = append(roots, sd.Key())
			}
		}
		if err := crawlscope.Set(crawlscope.Config{Field: *crawlScope, Any: *crawlAny, In: crawlIn, Out: crawlOut, Roots: roots}); err != nil {
			return usagef("%v", err)
		}
	}
	doneBefore := 0
	if *resumeRun != "" {
		st.UseRun(*resumeRun)
		budgets.Resume = true
		doneBefore = st.TasksDone()
	} else {
		if err := st.BeginRun(newRunID(), *depth, budgets.MaxItems); err != nil {
			return err
		}
		if err := st.SetRunArgs(keptArgs(args)); err != nil {
			return err
		}
		if signedIn(*login, cookies, headers) {
			// The sign-in itself is not kept; hunt reads that the run had one.
			_ = st.SetMeta(signedInKey(st.RunID()), "1")
		}
		if rep.Command != "run" {
			// The command that started the run: azhaq resume prints as it does.
			_ = st.SetMeta("command:"+st.RunID(), rep.Command)
		}
		if listLines != nil {
			if err := st.SetMeta("list:"+st.RunID(), strings.Join(listLines, "\n")); err != nil {
				return err
			}
		}
		if !rules.Empty() {
			// The scope as resolved now: a program's scope changes, and the
			// export of this run describes this run's.
			raw, _ := json.Marshal(rules)
			_ = st.SetMeta("scope:"+st.RunID(), string(raw))
		}
	}
	if answerDir != "" {
		// Where query finds the stored answer of a row.
		_ = st.SetMeta(responsesKey(st.RunID()), answerDir)
	}
	// The catch-all checks of a resumed run ask for the same names as
	// before, so their kept answers serve.
	if *resumeRun != "" {
		fetch.SetProbeToken(st.GetMeta("probe:" + *resumeRun))
		markDescribed(st) // the description guesses already answered stay answered
	} else {
		_ = st.SetMeta("probe:"+st.RunID(), fetch.ProbeToken())
		_ = st.DropResponses(st.RunID())
	}
	egress.SetRate(*rateFlag)
	egress.SetMaxRequests(*maxRequests)
	if *daily > 0 {
		key := *program
		if key == "" {
			key = input
		}
		day := time.Now().UTC().Format(time.DateOnly)
		left := *daily - st.Spent(key, day)
		if left <= 0 {
			return fmt.Errorf("-daily-requests: the %d requests of %s are spent (resets at 00:00 UTC)", *daily, day)
		}
		if egress.MaxRequests() == 0 || left < egress.MaxRequests() {
			egress.SetMaxRequests(left)
		}
		defer func() { _ = st.AddSpent(key, day, egress.Sent()) }()
	}
	cat := catalog.New()
	if *webScheme != "" && *webScheme != "http" && *webScheme != "https" {
		return usagef("-web-scheme is http or https, got %q", *webScheme)
	}
	opts := collectors.Options{Client: client, HTTP: spec, WebPorts: ports, WebScheme: *webScheme, NoTech: *noTech, NoTakeover: *noTakeover, NoFavicon: *noFavicon, Probe: *probe, PortRate: *portRate, MaxIPs: *maxIPs, Shots: *shots, Render: *render, KnownFiles: *knownFiles, FillForms: *fillForms, NoMapGuess: *noMapGuess, SubmitForms: *submitForms, PathClimb: *pathClimb}
	opts.ShotHTML = *shotHTML
	if *browserWrites && *shots == "" && !*render {
		return usagef("-browser-writes lets the pages Chrome loads send writes: give it with -browser or -screenshots")
	}
	if *interact && !*render {
		return usagef("-interact clicks the pages Chrome loads: give it with -browser")
	}
	if !out.plan {
		led, err := startLedger(*ledgerFlag, *killFile, path, out.scratch, rules, *sealTo)
		if err != nil {
			return err
		}
		defer led.close(rep)
		if *resumeRun != "" {
			led.holdWrites(st, *resumeRun)
		}
	}
	if (*shots != "" || *render) && out.plan {
		opts.Browser = &browser.Browser{} // never started: the collectors that need Chrome are listed
	}
	if *chromeSandbox && *chromeNoSandbox {
		return usagef("-chrome-require-sandbox and -chrome-no-sandbox contradict each other: drop one")
	}
	browser.RequireSandbox, browser.AllowNoSandbox = *chromeSandbox, *chromeNoSandbox // for the sign-in's Chrome too
	if (*shots != "" || *render) && !out.plan {
		if *chromePath != "" {
			if st, err := os.Stat(*chromePath); err != nil || st.IsDir() {
				return usagef("-chrome %s: not a file", *chromePath)
			}
		} else if _, err := browser.Find(); err != nil {
			return fmt.Errorf("-screenshots and -browser: %w", err)
		}
		hdr := map[string]any{}
		for k, vs := range fetch.Extra {
			if len(vs) > 0 && !strings.EqualFold(k, "User-Agent") {
				hdr[k] = strings.Join(vs, ", ")
			}
		}
		waitGiven := false
		fs.Visit(func(f *flag.Flag) { waitGiven = waitGiven || f.Name == "shot-wait" })
		bb, err := shotBrowser(shotOptions{size: *shotSize, full: *shotFull, wait: *shotWait, waitGiven: waitGiven, timeout: *shotTimeout, format: *shotFormat,
			quality: *shotQuality, js: *shotJS, codes: *shotCodes, chrome: *chromePath, proxy: *chromeProxy, profile: *chromeProfile, ports: *unsafePorts})
		if err != nil {
			return err
		}
		bb.Tabs, bb.UserAgent, bb.Header, bb.Writes = *tabs, browserAgent(), hdr, *browserWrites
		opts.Browser = bb
		if *interact {
			opts.Browser.Interact = *interactClicks
		}
		defer opts.Browser.Close()
		if err := opts.Browser.Start(); err != nil {
			return chromeStartErr(fmt.Errorf("-screenshots and -browser: %w", err))
		}
	}
	var loginHome string
	var loginRenew func(context.Context) error
	if *login != "" && out.plan {
		rep.Notes = append(rep.Notes, fmt.Sprintf("the run signs in at %s as %s with Chrome first", *login, *loginUser))
	} else if *login != "" {
		base := fetch.CurrentExtra().Clone()
		if base == nil {
			base = http.Header{} // not nil: signIn reads nil as "the headers now sent"
		}
		home, err := signIn(opts.Browser, *login, *loginUser, *loginPass, rep, base)
		if err != nil {
			return err
		}
		loginHome = home
		loginRenew = func(context.Context) error {
			// The requests going on meanwhile keep the old session until the
			// new one is set: a stripped one would answer them as a visitor.
			_, err := signIn(opts.Browser, *login, *loginUser, *loginPass, rep, base)
			return err
		}
		// The page the login ended on is the signed-in app.
		if home != *login && hasHost(seeds, home) {
			seeds = append(seeds, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": home}})
		}
	}
	if *portsSpec != "" {
		if opts.Ports, err = portscan.Ports(*portsSpec); err != nil {
			return fmt.Errorf("-ports: %w", err)
		}
	}
	if *portsUDP != "" {
		if opts.UDPPorts, err = portscan.UDPPorts(*portsUDP); err != nil {
			return fmt.Errorf("-ports-udp: %w", err)
		}
	}
	opts.PortConfig = portCfg
	opts.PortConfig.WebCost = webServiceCost(budgets.Skip, opts.Paths, *noFavicon, *knownFiles)
	if len(opts.Ports) > 0 || len(opts.UDPPorts) > 0 {
		if obs, err := st.Observations(); err == nil {
			opts.PortConfig.Prior = portcol.Priors(obs) // scans a limit stopped: resume asks the rest
			if *resumeRun != "" {
				opts.PortConfig.Swept = portcol.Swept(obs, runStart(st, *resumeRun)) // and not the addresses it finished
			}
		}
	}
	if *paramsFile != "" {
		words, ok := paramcol.Builtin(*paramsFile)
		if !ok {
			var err error
			if words, err = loadLines(*paramsFile); err != nil {
				return err
			}
		}
		method := strings.ToUpper(*paramsMethod)
		var targets map[string]paramcol.Target
		if *paramsTargets != "" {
			raw, err := os.ReadFile(*paramsTargets)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &targets); err != nil {
				return fmt.Errorf("-params-targets %s: %w", *paramsTargets, err)
			}
			for u, t := range targets {
				if m := strings.ToUpper(t.Method); m != "" && m != "GET" && !*paramsWrites {
					return usagef("-params-targets %s: %s asks with %s, which may change data: add -params-writes", *paramsTargets, u, m)
				}
			}
		}
		opts.Params = paramcol.Options{Words: words, PerHost: *paramsPerHost, Rate: *paramsRate,
			Threads: *paramsThreads, Chunk: *paramsChunk, Method: method, Writes: *paramsWrites, Include: *paramsInclude,
			Delay: *paramsDelay, Stable: *paramsStable, Timeout: *paramsTimeout, Targets: targets}
	}
	if *dirsFile != "" {
		var words []string
		if *dirsFile == dirscol.Builtin {
			words = dirscol.DefaultWords()
		} else {
			var err error
			if words, err = loadWordlist(*dirsFile); err != nil {
				return err
			}
		}
		opts.Dirs = dirscol.Options{Words: words, Extensions: splitList(*dirsExt), Depth: *dirsDepth, Threads: *dirsThreads, Rate: *dirsRate}
		given := map[string]string{}
		for k, v := range dirsMatch {
			given[k] = *v
		}
		if opts.Dirs.Set, err = dirsSet(given, "-dirs-"); err != nil {
			return err
		}
		opts.Dirs.NoCalibration = !*dirsCal
	}
	if *pathsFile != "" {
		if opts.Paths, err = loadPathList(*pathsFile); err != nil {
			return err
		}
	}
	if *graphqlWordlist != "" {
		if opts.GraphQLWordlist, err = loadLines(*graphqlWordlist); err != nil {
			return err
		}
	}
	resolvers, err := dnsr.ParseResolvers(*resolversFile)
	if err != nil {
		return usagef("-resolvers: %v", err)
	}
	// 3 s an attempt, as dnsx waits: a slow zone answers in time for both.
	opts.DNS = dnsr.New(dnsr.Options{Resolvers: resolvers, PerSecond: *dnsRate, Timeout: 3 * time.Second})
	probePool = opts.DNS
	// HTTP connects to the addresses azhaq-dns found: one answer per name.
	egress.SetResolver(func(ctx context.Context, host string) []string { return opts.DNS.ResolveBoth(ctx, host).IPs() })
	egress.SetResolverOnly(len(resolvers) > 0) // named resolvers answer every name: a failure is not retried on the system's
	if *bruteFile != "" {
		if opts.BruteWords, err = loadLines(*bruteFile); err != nil {
			return err
		}
	}
	// A -max-names the user gave also caps the names guessing asks; the default
	// cap is for the names looked up, and never cuts a wordlist.
	guessBudget = brutecol.NewBudget(*maxNames)
	opts.GuessBudget = guessBudget
	providerPaths := subcol.ProviderPaths()
	if *providersFile != "" {
		providerPaths = []string{*providersFile}
	}
	keys, _, err := subcol.LoadProviders(providerPaths...)
	if err != nil {
		return fmt.Errorf("provider keys: %w", err)
	}
	if unknown := subcol.Unknown(splitList(*sourcesList)); len(unknown) > 0 && *sourcesList != "none" { // none: no passive source
		msg := "no source named " + strings.Join(unknown, ", ") + " (azhaq subs -ls lists them)"
		if len(unknown) == len(splitList(*sourcesList)) {
			return usagef("-sources: %s", msg)
		}
		rep.Notes = append(rep.Notes, msg)
	}
	if *sourcesList == "none" {
		var conflict error
		asks := map[string]string{"urls-sources": "an archive", "urls-archive": "an archive", "asn": "RIPEstat"}
		fs.Visit(func(f *flag.Flag) {
			if what, ok := asks[f.Name]; ok && conflict == nil {
				conflict = usagef("-sources none asks no third party, and -%s asks %s: give one of them", f.Name, what)
			}
		})
		if conflict != nil {
			return conflict
		}
	}
	rates, err := parseSourceRates(*sourceRates)
	if err != nil {
		return usagef("-source-rates: %v", err)
	}
	if *sourceRate < 0 || *maxResults < 0 || *maxBody < 0 || *maxTime < 0 {
		return usagef("-source-rate, -max-results, -max-time and -max-body are not negative")
	}
	opts.Subdomains = subcol.Options{Keys: keys, Only: splitList(*sourcesList), Exclude: splitList(*excludeSources), All: *allSources, NoHistory: *noHistory, SourceTimeout: *sourceTimeout,
		SourceRate: *sourceRate, SourceRates: rates, MaxResults: *maxResults, MaxTime: *maxTime, MaxBody: *maxBody, MaxNames: *maxNames, NoCheck: subsMode.NoCheck, GuessSamples: subsMode.GuessSamples, Recursive: subsMode.Recursive, Proxy: *sourceProxy}
	urlKeys := maps.Clone(keys)
	if urlKeys == nil {
		urlKeys = map[string][]string{}
	}
	if urlscanKey != "" {
		urlKeys["urlscan"] = []string{urlscanKey}
	}
	opts.URLs = urlcol.Options{Keys: urlKeys, Out: *urlsOut, OutFrom: *urlsFrom, Timeout: *urlsTimeout,
		Apex: !*urlsSubs, Only: splitList(*urlsSources), FirstPath: *urlsFP, Blacklist: splitList(*urlsBlacklist), Proxy: *urlsProxy,
		MaxPages: *urlsPages, MaxURLs: *urlsMax, Raw: *urlsRaw, OnURL: urlSink}
	if *urlsPages == 0 {
		opts.URLs.MaxPages = math.MaxInt32
	}
	if *urlsMax == 0 {
		opts.URLs.MaxURLs = math.MaxInt32
	}
	if *urlsRetries < 0 {
		return usagef("-urls-retries %d: give 0 or more", *urlsRetries)
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "urls-pause":
			opts.URLs.Pause = urlsPause
		case "urls-retries":
			opts.URLs.Retries = urlsRetries // given: a count; not given: until the time is spent
		}
	})
	opts.URLs.Filters = urlcol.Filters{MatchStatus: splitList(*urlsMC), DropStatus: splitList(*urlsFC), MatchMime: splitList(*urlsMT), DropMime: splitList(*urlsFT), From: *urlsFrom2, To: *urlsTo}
	if err := opts.URLs.Filters.Validate(); err != nil {
		return usagef("-urls-*: %v", err)
	}
	if err := urlcol.CheckSources(opts.URLs.Only); err != nil {
		return usagef("-urls-sources: %v", err)
	}
	if *urlsProxy != "" {
		if _, err := urlcol.ParseProxy(*urlsProxy); err != nil {
			return usagef("-urls-proxy: %v", err)
		}
	}
	if !out.scratch {
		opts.URLs.Archive, opts.URLs.RunID = urlcol.ArchivePath(path), st.RunID()
	}
	if opts.URLs.Bases, err = archiveBases(urlsArchive); err != nil {
		return usagef("-urls-archive: %v", err)
	}
	if *urlsOut != "" && *resumeRun == "" {
		if err := os.WriteFile(*urlsOut, nil, 0o644); err != nil { // start empty; each domain appends
			return err
		}
	}
	collectors.Register(cat, opts)
	if extraCollectors != nil {
		extraCollectors(cat)
	}
	if *sourcesList == "none" {
		// No passive source means no third party at all: the archives, RDAP, search
		// engines and RIPEstat are as much a source as crt.sh. Only the resolvers
		// and the targets are asked.
		for _, n := range cat.Names() {
			if engine.IsThirdParty(n) {
				budgets.Skip[n] = true
			}
		}
	}
	if *probe {
		budgets.MaxDepth = 1 // the listed targets only: no CNAME or redirect targets
		if spec != nil && (spec.TLSProbe || spec.CSPProbe) {
			budgets.MaxDepth = 4 // and the names their certificates or policies give
		}
		// What the command line asks for by name runs: a flag is never dropped.
		asked := map[string]bool{
			"azhaq-dirs": *dirsFile != "", "azhaq-params": *paramsFile != "", "azhaq-ports": *portsSpec != "" || *portsUDP != "",
			"azhaq-shots": *shots != "", "azhaq-render": *render, "azhaq-dns-brute": *bruteFile != "", "azhaq-permute": *permute,
			"azhaq-graphql": *graphql, "azhaq-graphql-schema": *graphql,
		}
		for _, n := range cat.Names() {
			if n != "azhaq-dns" && n != "azhaq-http" && !asked[n] {
				budgets.Skip[n] = true
			}
		}
		// A flag only a collector -probe leaves out reads has nothing to act on.
		off := map[string]string{"fill-forms": "the crawl", "submit-forms": "the crawl", "path-climb": "the crawl", "known-files": "the path checks"}
		var conflict error
		fs.Visit(func(f *flag.Flag) {
			if what, ok := off[f.Name]; ok && conflict == nil && f.Value.String() != "" && f.Value.String() != "false" {
				conflict = usagef("-probe turns off %s, and -%s is for it: give one of them", what, f.Name)
			}
		})
		if conflict != nil {
			return conflict
		}
	}
	// The GETs among the targets whose own name declares a state change
	// are named before anything is sent: in a plan's list, and in a run's
	// first lines and summary. Nothing is withheld by naming them.
	preState := stateChangesOfSeeds(seeds, rules)
	if !out.plan && len(preState) > 0 {
		rep.StateChanging = append(rep.StateChanging, preState...)
		for _, e := range preState {
			rep.Notes = append(rep.Notes, e.line())
			if !*quiet && !*jsonOut && !out.embedded {
				fmt.Fprintf(os.Stderr, "azhaq %s: %s\n", rep.Command, e.line())
			}
		}
	}
	if out.plan {
		paths := append(append([]string{}, pathscol.DefaultWordlist...), opts.Paths...)
		send := sendLimits{noThirdParty: *sourcesList == "none", max: *maxRequests, by: "-max-requests", noFavicon: *noFavicon, chrome: *shots != "" || *render, shots: *shots, render: *render, chromeWrites: *browserWrites,
			interact: *interact, dirs: *dirsFile != "", params: *paramsFile != "", login: *login, loginUser: *loginUser, graphql: *graphql, submitForms: *submitForms,
			portsOn: len(portsOn) > 0, portDetect: portCfg.Detect, portPayload: len(portCfg.Payload) > 0, portDiscover: portCfg.Discover}
		if m := strings.ToUpper(*paramsMethod); *paramsFile != "" && m != "GET" {
			send.paramsBody = m
		}
		send.tcpPorts, send.udpPorts = len(opts.Ports), len(opts.UDPPorts)
		send.axfr, send.resolvers = out.axfr, resolvers
		if *daily > 0 && (send.max == 0 || *daily < send.max) {
			// A plan reads no database: what today's runs spent is not
			// taken off.
			send.max, send.by = *daily, "-daily-requests; what today's runs spent is not counted"
		}
		plan := buildPlan(cat, seeds, budgets, paths, limitsOf(budgets, *maxRequests, *rateFlag, *timeout, *daily), send, rep)
		rep.Results, rep.what = len(plan.Targets), "targets"
		return printPlan(plan, *jsonOut)
	}
	if *workerOf != "" {
		return runWorker(cat, *workerOf, *workerToken, budgets.Parallel)
	}
	if *stream && observer == nil {
		observer = streamFound(*jsonOut)
		defer func() { observer = nil }()
	}
	eng := &engine.Engine{Cat: cat, Store: st, Observe: observer, Client: client}
	if *serve != "" {
		if *workerToken == "" {
			*workerToken = newToken()
		}
		cfg, err := forWorkers(fs, args, allow, deny)
		if err != nil {
			return err
		}
		cfg.DenyPath, cfg.SignIn = budgets.Scope.DenyPath, *login
		eng.Workers = engine.NewWorkers()
		stopServe, err := serveWorkers(*serve, *workerToken, eng.Workers, cfg, func(rep fetch.SessionReport) {
			// Made now, though the work is lent: the run's own requests would not.
			fetch.AbsorbReport(&rep, 0, true)
			_ = fetch.CheckDue(context.Background())
		})
		if err != nil {
			return fmt.Errorf("-serve: %w", err)
		}
		defer stopServe()
		fmt.Fprintf(os.Stderr, "azhaq: workers can join with: AZHAQ_WORKER_TOKEN=%s azhaq worker -server http://%s\n", *workerToken, *serve)
	}

	log := timing.New()

	ctx, stop := stopContext()
	defer stop()
	// The run's wall-clock bound: -timeout, or for subs -max-time when that is
	// shorter, which then bounds every phase and not only the wait on the sources.
	bound, boundBy := *timeout, "-timeout"
	if subsMode.MaxTimeBoundsRun && *maxTime > 0 && (bound == 0 || *maxTime < bound) {
		bound, boundBy = *maxTime, "-max-time"
	}
	if bound > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, bound)
		defer cancel()
	}
	ctx = timing.With(ctx, log)
	// Under -json, stderr holds JSON only: failures and limits are in the
	// summary, not printed as they happen.
	hushed := (*quiet || *jsonOut) && !*verbose
	switch {
	case hushed:
		ctx = engine.WithQuiet(ctx)
	case *verbose:
		ctx = engine.WithVerbose(ctx)
	default:
		ctx = engine.WithProgress(ctx)
	}
	// A command that is still working says so every few seconds (not with
	// -quiet, which the commands built on run give; -silent is that): with
	// -json as JSON lines, as everything on stderr is.
	stopTicker := func() {}
	if mode := progressMode(*quiet, *verbose, *jsonOut, out.progress); mode != "" {
		cfg := progressCfg{JSON: mode == "json", Cap: egress.MaxRequests(), CapBy: "-max-requests", Timeout: bound, TimeoutBy: boundBy}
		if *daily > 0 && egress.MaxRequests() != *maxRequests {
			cfg.CapBy = "-daily-requests"
		}
		if !cfg.JSON {
			if l := cfg.paceLine(*rateFlag); l != "" {
				fmt.Fprintln(os.Stderr, l)
			}
		}
		t0 := time.Now()
		stopTicker = startProgress(ctx, cfg, os.Stderr, func() progressSnap {
			return progressSnap{At: time.Since(t0), Sent: egress.Departed(), Done: st.TasksDone(), Left: st.TasksLeft()}
		})
	}
	defer stopTicker()

	t0 := time.Now()
	if *factsPath != "" {
		facts, err := connector.ReadFile(*factsPath)
		if err != nil {
			return err
		}
		done := timing.Start(ctx, "ingest", *factsPath)
		hints, err := eng.Ingest(ctx, facts)
		done()
		if err != nil {
			return err
		}
		seeds = append(seeds, hints...)
	}
	if *execCmd != "" {
		argv, err := splitCmd(*execCmd)
		if err != nil {
			return err
		}
		done := timing.Start(ctx, "connector", argv[0])
		facts, err := connector.Exec(ctx, argv, engine.ExpandSeeds(seeds))
		done()
		if err != nil {
			fmt.Fprintf(os.Stderr, "azhaq: connector %s: %v\n", argv[0], err)
			if recErr := eng.NoteExternalError(seeds, "connector", fmt.Errorf("%s: %w", argv[0], err)); recErr != nil {
				return recErr
			}
		} else if !*quiet && !*jsonOut {
			fmt.Fprintf(os.Stderr, "  . connector %s (%s)\n", argv[0], connector.Protocol)
		}
		if len(facts) > 0 {
			hints, err := eng.Ingest(ctx, facts)
			if err != nil {
				return err
			}
			seeds = append(seeds, hints...)
		}
	}
	if err := st.SaveSeeds(engine.ExpandSeeds(seeds)); err != nil {
		return err
	}
	stopKeep := func() {}
	if !out.scratch {
		stopKeep = engine.KeepResponses(st, *resumeRun != "")
	}
	if !out.plan {
		watchSession(ctx, seeds, loginHome, *login, loginRenew, rep)
	}
	localErr := eng.RunLocal(ctx, seeds, budgets)
	stopKeep()
	if localErr != nil && !errors.Is(localErr, context.Canceled) && !errors.Is(localErr, context.DeadlineExceeded) {
		return localErr
	}
	stopTicker()
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	// -advisories: Part 1 matches what the run already confirmed and
	// sends nothing more; Part 2's reads, with -advisories-confirm, go
	// through egress here, while the run's ledger and budget are still
	// the run's, and count in rep.Requests below.
	var advLeads []advisory.Lead
	var advFailures []engine.Failure
	advNote := ""
	if advFlags.on {
		advLeads, advFailures, advNote = advisoryStage(ctx, st, obs, advFlags)
		obs, _ = st.Observations()
	}
	edges, _ := st.Edges()
	leftover, _ := st.LoadLeftover()
	scope := engine.ScopeSeeds(seeds, ents, edges)
	_ = st.SaveSeeds(scope)
	stats, err := st.Stats()
	if err != nil {
		return err
	}
	rows := engine.BuildMap(ents, scope, obs, leftover, stats.Capped)
	if *verbose {
		fmt.Fprint(os.Stderr, log.Report(time.Since(t0)))
	}
	shown := rows
	if *noCatchAll {
		shown = withoutCatchAll(rows, engine.CatchAllHeldIDs(obs))
	}
	switch {
	case *quiet || out.embedded:
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		for _, r := range engine.GroupTemplates(shown) {
			if err := enc.Encode(mapRowJSON(r)); err != nil {
				return err
			}
		}
		for _, lead := range advLeads {
			if err := enc.Encode(leadRow(lead)); err != nil {
				return err
			}
		}
	case *probe:
		for _, r := range engine.ProbeRows(obs) {
			fmt.Println(r.Line())
		}
		for _, r := range rows {
			if r.Entity.Type == types.TypePort {
				fmt.Println(r.Line())
			}
		}
		for _, lead := range advLeads {
			fmt.Println(lead.Line())
		}
	default:
		printMap(shown)
		for _, lead := range advLeads {
			fmt.Printf("  %s\n", lead.Line())
		}
		if *showObs {
			fmt.Println("observations")
			for _, o := range obs {
				fmt.Printf("  %s %s %s\n", o.Collector, o.Kind, compact(o.Payload))
			}
		}
	}
	rep.noCatchAll = *noCatchAll
	fillReport(rep, path, seeds, ents, obs, rows)
	if !out.plan {
		// The ones found on the way: an API description's GET whose own
		// description declares a state change, and a found URL whose name
		// does. They were sent in this run; the rule named keeps them out
		// of the next one.
		var likes []mapRowLike
		for _, r := range rows {
			if r.Entity.Type == types.TypeURL {
				likes = append(likes, mapRowLike{key: r.Entity.Key, skipped: r.Coverage == "skipped"})
			}
		}
		found := mergeStateChanges(stateChangesOfOps(obs), stateChangesOfRows(likes))
		for _, e := range found {
			if rules.DeniedPath(e.URL) != "" {
				continue // kept out by the user's rule: listed as skipped, not as sent
			}
			known := false
			for _, p := range rep.StateChanging {
				known = known || p.Method == e.Method && p.URL == e.URL
			}
			if known {
				continue
			}
			rep.StateChanging = append(rep.StateChanging, e)
			rep.Notes = append(rep.Notes, e.line()+"; found on the way, so this run sent it: the rule keeps it out of a later run")
		}
		if len(found) > 0 {
			rep.StateChanging = mergeStateChanges(rep.StateChanging)
		}
	}
	if advFlags.on {
		rep.Advisories = advLeads
		rep.Failed = append(rep.Failed, advFailures...)
		if advNote != "" {
			rep.Notes = append(rep.Notes, advNote)
		}
	}
	if n := opts.DNS.TakeoverNote("-no-takeover"); n != "" {
		rep.Notes = append(rep.Notes, n)
	}
	// The URLs are those the map holds as coverage capped: the number is
	// what `query -coverage capped` lists, each URL once.
	capped := 0
	for _, r := range rows {
		if r.Entity.Type == types.TypeURL && r.Coverage == "capped" {
			capped++
		}
	}
	if c := eng.Caps(); capped+c.DepthNames > 0 {
		var what []string
		if capped > 0 {
			what = append(what, fmt.Sprintf("%d URLs", capped))
		}
		if c.DepthNames > 0 {
			what = append(what, fmt.Sprintf("%d names", c.DepthNames))
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("-depth %d: %s found past it were not asked (their rows are coverage capped); azhaq resume -depth %d asks them", budgets.MaxDepth, strings.Join(what, " and "), budgets.MaxDepth+1))
	}
	if *permute {
		if n := unvaried(leftover); n > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("-permute did not vary %d names found past -depth %d: they were not resolved in this run (-depth %d reaches them)", n, budgets.MaxDepth, budgets.MaxDepth+1))
		}
	}
	if err := fetch.SessionLost(); err != nil {
		// Said once, as a failure of its own: exit 3, never a quiet anonymous run.
		if !slices.ContainsFunc(rep.Failed, func(f engine.Failure) bool { return strings.HasPrefix(f.Error, "the session ended") }) {
			rep.Failed = append(rep.Failed, engine.Failure{Collector: "azhaq-session", Error: err.Error(), Count: 1})
		}
	}
	if *render {
		if n, pages := browserOnly(obs); pages > 0 && n == 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("-browser: Chrome rendered %d pages and found no URL the static pass had not; a run without it maps the same with fewer requests", pages))
		}
	}
	if opts.Browser != nil {
		chromeRefused(rep, opts.Browser)
	}
	schema, _ := cat.Get(gqlcol.SchemaName)
	if hint := engine.GraphQLHint(obs, func(raw string) bool {
		return schema != nil && budgets.Allows(schema, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": raw}})
	}); hint != "" {
		rep.Next = append(rep.Next, hint)
	}
	if *login == "" && len(cookies) == 0 && len(headers) == 0 {
		if hint := engine.LoginHint(rows); hint != "" {
			rep.Next = append(rep.Next, hint)
		}
	}
	if !out.embedded && rep.Command == "run" {
		runHints(rep, rows, obs, *interact, signedIn(*login, cookies, headers))
	}
	rep.RunID = stats.RunID
	if runs, err := st.Runs(); err == nil && len(runs) > 0 && runs[len(runs)-1].ID != stats.RunID {
		// A resumed earlier run: query -failed reads the newest unless told.
		for i, n := range rep.Next {
			rep.Next[i] = strings.Replace(n, " -failed   (", " -failed -run "+stats.RunID+"   (", 1)
		}
	}
	if opts.Browser != nil {
		// What Chrome still held waiting for the pace is given back first:
		// never sent, it is not counted.
		opts.Browser.Close()
	}
	rep.Requests = egress.Sent()
	_ = st.AddRunRequests(rep.Requests)
	// Work the -timeout cut short (a source still asking) is not done:
	// resume runs it again.
	cut := 0
	for _, f := range rep.Failed {
		if f.Error == types.CutShort {
			n, _ := st.Reopen(f.Collector, f.Targets)
			cut += n
		}
	}
	if left := st.TasksLeft(); left > 0 {
		// Tasks left counts what is known so far: the pages a resume reads
		// lead to more, so it can grow between resumes.
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded) || cut > 0:
			rep.Stopped = fmt.Sprintf("%s %s reached with %d tasks known and not done", boundBy, bound, left)
		case ctx.Err() != nil:
			rep.Stopped = fmt.Sprintf("interrupted with %d tasks known and not done", left)
		case egress.Killed() != nil:
			rep.Stopped = killStopped(left)
		case egress.Spent():
			rep.Stopped = fmt.Sprintf("the request budget of %d is spent, %d tasks known and not done (the cap holds for each run: azhaq resume sends up to %d more, or as many as its -max-requests says, 0 for no cap)", egress.MaxRequests(), left, egress.MaxRequests())
		case len(fetch.OriginsDown()) > 0:
			rep.Stopped = fmt.Sprintf("%s stopped answering after %d timeouts, %d tasks known and not done", strings.Join(fetch.OriginsDown(), ", "), fetch.OriginTrips, left)
		default:
			caps := eng.Caps()
			switch {
			case caps.NamesLeft > 0 && caps.ItemsLeft == 0:
				rep.Stopped = fmt.Sprintf("-max-names %d reached, %d names not looked up, %d tasks known and not done (-max-names raises it)", budgets.MaxNames, caps.NamesLeft, left)
			case budgets.MaxItems > 0:
				rep.Stopped = fmt.Sprintf("-max-items %d reached, %d tasks known and not done (-max-items raises it)", budgets.MaxItems, left)
			default:
				rep.Stopped = fmt.Sprintf("%d tasks known and not done", left)
			}
		}
		rep.Resume = resumeHint(path, cut > 0, *login != "", *loginUser)
		if *resumeRun != "" && st.TasksDone() == doneBefore && egress.Spent() && egress.Killed() == nil {
			rep.Notes = append(rep.Notes, noTaskFinished(rep.Command, egress.MaxRequests()))
		}
	} else {
		// Nothing left to resume: the kept answers have served.
		_ = st.DropResponses("")
		if *resumeRun != "" {
			_ = st.SetMeta(unsentKey(*resumeRun), "")
		}
		if *failCapped && stats.Capped {
			rep.Stopped = fmt.Sprintf("-depth %d reached with hints left", stats.Depth)
		}
	}
	if n := guessBudget.Held(); n > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("-max-names %d held back %d guesses: the -w words and -permute variations beyond it were not asked (a larger -max-names asks them)", *maxNames, n))
		if rep.Stopped == "" {
			rep.Stopped = fmt.Sprintf("-max-names %d reached, %d guesses not asked (-max-names raises it)", *maxNames, n)
		}
	}
	if remember && !*demo && input != "" {
		_ = recordRun(input, path)
	}
	if !*quiet && !*jsonOut && !out.embedded && !*demo && prevDB != "" && prevDB != path {
		if err := printDiff(prevDB, path, diffOpts{}); err != nil {
			fmt.Fprintf(os.Stderr, "azhaq: diff vs %s: %v\n", prevDB, err)
		}
	}
	if !*quiet && !*jsonOut && !out.embedded && !*demo && !remember {
		// -db names a workspace: compare with its previous run, if any.
		if err := printRunDiff(path, diffOpts{}); err != nil {
			fmt.Fprintf(os.Stderr, "azhaq: diff vs the previous run in %s: %v\n", path, err)
		}
	}
	return nil
}

// noTaskFinished is the note of a resume that ended with the budget spent and
// no task done: what a task left costs, in the command's own terms.
func noTaskFinished(command string, budget int64) string {
	switch command {
	case "ports":
		return fmt.Sprintf("no task finished: each one left needs more than %d connections (one per port to connect, for each of its addresses); raise -max-requests", budget)
	case "run", "dirs":
		return fmt.Sprintf("no task finished: each one left needs more than %d requests (a path sweep needs one per word); raise -max-requests", budget)
	}
	return fmt.Sprintf("no task finished: each one left needs more than %d requests; raise -max-requests", budget)
}

// webServiceCost is the requests mapping one web service takes at least: the
// number plan gives as about N per web service (its page, the favicon, the
// built-in path checks). A budget keeps that much for each service a port
// sweep finds open and names web, so that the sweep cannot spend it all.
func webServiceCost(skip map[string]bool, extraPaths []string, noFavicon bool, knownFiles string) int {
	if skip["azhaq-http"] {
		return 0
	}
	n := 1
	if !noFavicon {
		n++
	}
	switch {
	case skip["azhaq-paths"]:
	case knownFiles != "":
		n += len(pathscol.KnownFiles(knownFiles))
	default:
		n += len(pathscol.DefaultWordlist) + len(extraPaths)
	}
	return n
}

// runStart is when the run began, the zero time for one the workspace does not know.
func runStart(st *store.Store, id string) time.Time {
	runs, _ := st.Runs()
	for _, r := range runs {
		if r.ID == id {
			return r.Started
		}
	}
	return time.Time{}
}

// unvaried counts the names a run found past -depth that -permute did not
// vary: those a guessing technique resolved are varied whatever -depth says.
func unvaried(left []types.Seed) int {
	n := 0
	for _, s := range left {
		if s.Type == types.TypeHostname && s.Keys[types.LiveKey] == "" && s.Keys[types.ViaKey] != types.ViaPermute &&
			normalize.RegistrableDomain(s.Key()) != s.Key() {
			n++
		}
	}
	return n
}

const runIndexFile = ".azhaq-index"

// previousRun is the last database written in this directory for the same
// seeds. Diffing against a run of another target would be noise.
func previousRun(input string) string {
	idx := readRunIndex()
	path := idx[input]
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

func readRunIndex() map[string]string {
	idx := map[string]string{}
	raw, err := os.ReadFile(runIndexFile)
	if err != nil {
		return idx
	}
	_ = json.Unmarshal(raw, &idx)
	return idx
}

func recordRun(input, path string) error {
	idx := readRunIndex()
	idx[input] = path
	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(runIndexFile, append(raw, '\n'), 0o644)
}

func normalizeSeeds(seeds []types.Seed) []types.Seed {
	out := make([]types.Seed, 0, len(seeds))
	for _, s := range seeds {
		out = append(out, normalize.Seed(s))
	}
	return out
}

func printMap(rows []engine.MapEntry) {
	for _, row := range engine.GroupTemplates(rows) {
		fmt.Printf("  %s\n", row.Line())
		for _, d := range row.Details() {
			fmt.Printf("      %s\n", d)
		}
		if w := engine.Watch(row); len(w) > 0 {
			fmt.Printf("      watch: %s\n", strings.Join(w, ", "))
		}
	}
}

// cmdIngest adds what other tools found to a database: their JSON
// output, Azhaq's own export, connector facts or plain lists.
func cmdIngest(args []string) error {
	fs := newFlags("ingest")
	in := fs.String("in", "", "a file of results (- for stdin): subfinder, dnsx, httpx, katana, naabu, nuclei or gau JSON lines, an ffuf JSON report or -json lines, azhaq export, connector facts, or lines of URLs, hostnames and addresses; files may also be given as arguments, several at once")
	dbPath := fs.String("db", "", "the database to add to (default: a new file)")
	asJSON := fs.Bool("json", false, "the summary as JSON")
	if err := parse(fs, args); err != nil {
		return err
	}
	files := fs.Args()
	if *in != "" {
		files = append([]string{*in}, files...)
	}
	if len(files) == 0 {
		return usagef("give a FILE to ingest (azhaq ingest FILE…; - for stdin)")
	}
	var facts []connector.Fact
	formats := map[string]int{}
	var skipped []string
	for _, f := range files {
		var raw []byte
		var err error
		if f == "-" {
			raw, err = io.ReadAll(os.Stdin)
		} else {
			raw, err = os.ReadFile(f)
		}
		if err != nil {
			return err
		}
		got, fm, sk, err := connector.ReadLines(raw)
		if err != nil {
			return usagef("%s: %v", f, err)
		}
		facts = append(facts, got...)
		for k, n := range fm {
			formats[k] += n
		}
		for _, x := range sk {
			if len(files) > 1 {
				x = f + " " + x
			}
			if len(skipped) < 5 {
				skipped = append(skipped, x)
			}
		}
	}
	path, remember := resolveDB(*dbPath)
	if remember {
		if err := os.WriteFile(lastDBFile, []byte(path+"\n"), 0o644); err != nil {
			return err
		}
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	// Into the newest run of a workspace, so query, show and export see
	// it with what that run found; a new database gets a run of its own.
	runs, err := st.Runs()
	if err != nil {
		return err
	}
	fresh := len(runs) == 0
	if fresh {
		if err := st.BeginRun(newRunID(), 0, 0); err != nil {
			return err
		}
		_ = st.SetRunArgs(append([]string{"ingest"}, files...))
	} else {
		st.UseRun(runs[len(runs)-1].ID)
	}
	eng := &engine.Engine{Store: st}
	ctx, stop := stopContext()
	defer stop()
	hints, err := eng.Ingest(ctx, facts)
	if err != nil {
		return err
	}
	if fresh {
		_ = st.SaveSeeds(hints)
	}
	rep := newReport("ingest")
	rep.what = "facts"
	rep.Results, rep.Counts, rep.DB = len(facts), formats, path
	if n := formats["skipped"]; n > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%s not read and skipped: %s", plural(n, "line"), strings.Join(skipped, "; ")))
	}
	rep.Next = []string{"azhaq query -db " + path, "azhaq export -db " + path + " -format names | azhaq dns -db " + path + "   (resolve the names taken in without addresses)"}
	return rep.finish(*asJSON, false)
}

func cmdBench(args []string) error {
	fs := newFlags("bench")
	if err := parse(fs, args); err != nil {
		return err
	}
	fetch.Reset()
	srv := demoServer()
	defer srv.Close()

	dir, err := os.MkdirTemp("", "azhaq-bench-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	st, err := store.Open(filepath.Join(dir, "bench.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	cat := catalog.New()
	collectors.RegisterAll(cat, srv.Client())
	eng := &engine.Engine{Cat: cat, Store: st}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}}

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t0 := time.Now()
	if err := eng.RunLocal(context.Background(), seeds, engine.DefaultBudgets()); err != nil {
		return err
	}
	wall := time.Since(t0)
	runtime.GC()
	runtime.ReadMemStats(&ms)

	sum, err := st.Summary()
	if err != nil {
		return err
	}
	const maxWall = 5 * time.Second
	const maxHeap = 256 << 20
	fmt.Printf("bench ok\n")
	fmt.Printf("  wall  %s\n", wall.Round(time.Millisecond))
	fmt.Printf("  heap  %.1fMB\n", float64(ms.HeapAlloc)/(1<<20))
	fmt.Printf("  %s\n", sum)
	if wall > maxWall {
		return fmt.Errorf("bench: wall %s over %s", wall.Round(time.Millisecond), maxWall)
	}
	if ms.HeapAlloc > maxHeap {
		return fmt.Errorf("bench: heap %dMB over %dMB", ms.HeapAlloc>>20, maxHeap>>20)
	}
	return nil
}

func cmdDiff(args []string) error {
	fs := newFlags("diff")
	a := fs.String("a", "", "old sqlite")
	b := fs.String("b", "", "new sqlite (default: last run)")
	ws := fs.String("db", "", "workspace: compare the last two runs recorded in this database")
	asJSON := fs.Bool("json", false, "JSON lines instead of a text report, the summary last")
	jsonl := fs.Bool("jsonl", false, "same as -json")
	quiet := fs.Bool("quiet", false, "entities and counts only (skip observation lines)")
	if err := parse(fs, args); err != nil {
		return err
	}
	*jsonl = *jsonl || *asJSON
	if *ws != "" {
		st, err := store.OpenExisting(*ws)
		if err != nil {
			return err
		}
		runs, _ := st.Runs()
		st.Close()
		if len(runs) < 2 {
			// Nothing to compare yet: said, not silent.
			if *jsonl {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"kind": "summary", "runs": len(runs), "added": 0, "removed": 0, "not_seen_again": 0, "observations": 0, "note": "one run so far: a diff needs two"})
			}
			fmt.Printf("%s holds %d run so far: a diff needs two (run the same target into it again)\n", *ws, len(runs))
			return nil
		}
		return printRunDiff(*ws, diffOpts{JSONL: *jsonl, Quiet: *quiet})
	}
	if *a == "" {
		return usagef("need -a OLD.db, or -db WORKSPACE.db")
	}
	newPath := *b
	if newPath == "" {
		newPath = readLastDB()
		if newPath == "" {
			return fmt.Errorf("need -b (no %s)", lastDBFile)
		}
	}
	return printDiff(*a, newPath, diffOpts{JSONL: *jsonl, Quiet: *quiet})
}

func readLastDB() string {
	raw, err := os.ReadFile(lastDBFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

type diffOpts struct {
	JSONL bool
	Quiet bool
}

func printDiff(oldPath, newPath string, opts diffOpts) error {
	old, err := store.OpenExisting(oldPath)
	if err != nil {
		return err
	}
	defer old.Close()
	neu, err := store.OpenExisting(newPath)
	if err != nil {
		return err
	}
	defer neu.Close()
	return printDiffStores(old, neu, oldPath, opts)
}

// printRunDiff compares the last two runs recorded in one database (a
// workspace). It prints nothing when there is only one run.
func printRunDiff(path string, opts diffOpts) error {
	old, err := store.OpenExisting(path)
	if err != nil {
		return err
	}
	defer old.Close()
	runs, err := old.Runs()
	if err != nil || len(runs) < 2 {
		return err
	}
	neu, err := store.OpenExisting(path)
	if err != nil {
		return err
	}
	defer neu.Close()
	prev, last := runs[len(runs)-2], runs[len(runs)-1]
	old.UseRun(prev.ID)
	neu.UseRun(last.ID)
	return printDiffStores(old, neu, fmt.Sprintf("the run of %s in %s", prev.Started.Format("2006-01-02 15:04"), path), opts)
}

func printDiffStores(old, neu *store.Store, oldLabel string, opts diffOpts) error {
	d, err := store.Compare(old, neu)
	if err != nil {
		return err
	}
	oldIn, newIn := old.Input(), neu.Input()
	differ := oldIn != "" && newIn != "" && oldIn != newIn
	// A name or URL the old run only heard of (from a source, an archive,
	// a link) and never checked is not "removed" when the new run does not
	// hear of it again: sources answer differently from one day to the
	// next, and fail. Removed is what answered before.
	oldFacts := factsByEntity(old)
	var removed, unseen []types.Entity
	for _, e := range d.Removed {
		if f := oldFacts[e.ID]; len(f.ips) > 0 || f.status != 0 || f.ports != nil || e.Type != types.TypeHostname && e.Type != types.TypeURL {
			removed = append(removed, e)
		} else {
			unseen = append(unseen, e)
		}
	}
	failed := failedSources(neu)
	if opts.JSONL {
		enc := json.NewEncoder(os.Stdout)
		for _, e := range d.Added {
			if err := enc.Encode(map[string]any{"kind": "added", "type": e.Type, "key": e.Key}); err != nil {
				return err
			}
		}
		for _, e := range removed {
			if err := enc.Encode(map[string]any{"kind": "removed", "type": e.Type, "key": e.Key}); err != nil {
				return err
			}
		}
		for _, e := range unseen {
			if err := enc.Encode(map[string]any{"kind": "not_seen_again", "type": e.Type, "key": e.Key}); err != nil {
				return err
			}
		}
		if !opts.Quiet {
			for _, o := range d.NewObs {
				if err := enc.Encode(map[string]any{"kind": "observation", "collector": o.Collector, "obs_kind": o.Kind, "payload": o.Payload}); err != nil {
					return err
				}
			}
		}
		sum := map[string]any{
			"kind":           "summary",
			"added":          len(d.Added),
			"removed":        len(removed),
			"not_seen_again": len(unseen),
			"observations":   len(d.NewObs),
		}
		if len(failed) > 0 {
			sum["failed_sources"] = failed
		}
		if differ {
			sum["seeds_differ"] = true
		}
		return enc.Encode(sum)
	}
	fmt.Printf("diff vs %s\n", oldLabel)
	if differ {
		fmt.Printf("  ! the runs had different seeds; this compares two targets, not two scans of one\n")
		fmt.Printf("    old: %s\n    new: %s\n", strings.ReplaceAll(oldIn, "\n", ", "), strings.ReplaceAll(newIn, "\n", ", "))
	}
	if len(d.Added) == 0 && len(d.Removed) == 0 && len(d.NewObs) == 0 {
		fmt.Println("  (no new entities or observations)")
		fmt.Println("added=0 removed=0 observations=0")
		return nil
	}
	for _, e := range d.Added {
		fmt.Printf("  + %s %s\n", e.Type, e.Key)
	}
	for _, e := range removed {
		fmt.Printf("  - %s %s\n", e.Type, e.Key)
	}
	if !opts.Quiet {
		for _, o := range d.NewObs {
			fmt.Printf("  + %s %s %s\n", o.Collector, o.Kind, compact(o.Payload))
		}
	}
	if len(unseen) > 0 {
		line := fmt.Sprintf("  ? %d names and URLs the last run heard of and never checked were not heard of again", len(unseen))
		if len(failed) > 0 {
			line += " (sources that failed this run: " + strings.Join(failed, ", ") + ")"
		}
		fmt.Println(line + "; -json lists them")
	}
	fmt.Printf("added=%d removed=%d not_seen_again=%d observations=%d\n", len(d.Added), len(removed), len(unseen), len(d.NewObs))
	return nil
}

// failedSources names the third-party sources that failed in a run.
func failedSources(st *store.Store) []string {
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	seen := map[string]bool{}
	var out []string
	for _, f := range engine.Failures(ents, obs) {
		if f.Source != "" && !seen[f.Source] {
			seen[f.Source] = true
			out = append(out, f.Source)
		}
	}
	sort.Strings(out)
	return out
}

func newRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("local-%d-%d", time.Now().UnixNano(), os.Getpid())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func cmdExport(args []string) error {
	fs := newFlags("export")
	dbPath := fs.String("db", "", "sqlite path (default: last run)")
	format := fs.String("format", "jsonl", "jsonl (everything), urls, hosts (names that resolve), names (every name), targets (web services, for nuclei -l), openapi, graphql (introspection JSON), sdl (GraphQL schema), burp (the run's scope), html, graphml, secrets")
	origin := fs.String("origin", "", "openapi: the origin to describe (default: the one with most API routes); graphql, sdl: the endpoints of an origin, or one endpoint's URL")
	safe := fs.Bool("safe", false, "openapi: leave out the routes the run did not request, such as those -deny-path kept out (otherwise they carry x-azhaq-skipped: true)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *format != "jsonl" {
		path := *dbPath
		if path == "" {
			path = readLastDB()
		}
		if path == "" {
			return fmt.Errorf("need -db (no %s from a previous run)", lastDBFile)
		}
		cw := &countWriter{w: os.Stdout}
		if err := exportTo(path, *format, *origin, *safe, cw); err != nil {
			return err
		}
		if cw.n == 0 {
			fmt.Fprintf(os.Stderr, "azhaq export: nothing to write: %s\n", emptyExport(*format))
		}
		return nil
	}
	path := *dbPath
	if path == "" {
		b, err := os.ReadFile(lastDBFile)
		if err != nil {
			return fmt.Errorf("need -db (no %s from a previous run)", lastDBFile)
		}
		path = strings.TrimSpace(string(b))
	}
	st, err := store.OpenExisting(path)
	if err != nil {
		return err
	}
	defer st.Close()
	enc := json.NewEncoder(os.Stdout)
	ents, err := st.Entities()
	if err != nil {
		return err
	}
	seeds, _ := st.LoadSeeds()
	obs, err := st.Observations()
	if err != nil {
		return err
	}
	edges, err := st.Edges()
	if err != nil {
		return err
	}
	leftover, _ := st.LoadLeftover()
	scope := engine.ScopeSeeds(seeds, ents, edges)
	stats, _ := st.Stats()
	for _, row := range engine.BuildMap(ents, scope, obs, leftover, stats.Capped) {
		out := map[string]any{"kind": "entity", "entity": row.Entity, "scope": row.Scope}
		if row.Coverage != "" {
			out["coverage"] = row.Coverage
		}
		if row.Role != "" {
			out["role"] = row.Role
		}
		if row.Proof != "" {
			out["proof"] = row.Proof
		}
		if row.Evidence != "" {
			out["evidence"], out["evidence_from"] = row.Evidence, row.EvidenceFrom
		}
		if row.Template != "" {
			out["template"] = row.Template
		}
		if len(row.Methods) > 0 {
			out["methods"] = row.Methods
		}
		if len(row.Params) > 0 {
			out["params"] = row.Params
		}
		if len(row.Forms) > 0 {
			out["forms"] = row.Forms
		}
		if err := enc.Encode(out); err != nil {
			return err
		}
	}
	for _, o := range obs {
		if err := enc.Encode(map[string]any{"kind": "observation", "observation": o}); err != nil {
			return err
		}
	}
	for _, e := range edges {
		if err := enc.Encode(map[string]any{"kind": "edge", "edge": e}); err != nil {
			return err
		}
	}
	return nil
}

// extraCollectors lets a test add a collector to a run's catalog.
var extraCollectors func(*catalog.Catalog)

func demoServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><title>Azhaq fixture</title>
<a href="/login">login</a>
<a href="https://evil.example/out">out</a>
<script src="/app.js"></script>
`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>Login</title><form action="/auth"></form>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/status"); const x = "https://evil.example/js";`))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>Auth</title>`))
	})
	return httptest.NewServer(mux)
}

func loadSeeds(urls []string, org, path string) ([]types.Seed, error) {
	var seeds []types.Seed
	for _, url := range urls {
		u, err := parseCLIURL(url)
		if err != nil {
			return nil, err
		}
		seeds = append(seeds, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u, types.GivenKey: "1"}})
	}
	if org != "" {
		seeds = append(seeds, types.Seed{Type: types.TypeOrganization, Keys: map[string]string{"name": org}})
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			s, err := parseSeedLine([]byte(line))
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
			}
			seeds = append(seeds, s)
		}
	}
	return seeds, nil
}

// loadList reads targets the way httpx does: a URL is fetched as given, a
// bare host is probed over HTTPS then HTTP, and host:port or an IP address
// becomes a URL that falls back to plain HTTP.
// loadList reads a -list file, or stdin for "-"; a list azhaq resume
// can no longer read (stdin, a temporary file gone) it takes from the
// workspace, which keeps it as "@run".
func loadList(path string) ([]types.Seed, []string, error) {
	var lines []string
	var err error
	switch {
	case path == "-":
		lines, err = readLines(os.Stdin)
	case strings.HasPrefix(path, "@"):
		lines = storedList
	default:
		lines, err = loadLines(path)
	}
	if err != nil {
		return nil, nil, err
	}
	var seeds []types.Seed
	for i, line := range lines {
		s, err := listSeed(line)
		if err != nil {
			return nil, nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		seeds = append(seeds, s)
	}
	return seeds, lines, nil
}

// storedList is the target list azhaq resume took from the workspace.
var storedList []string

// probeSeeding says the list is probe's: a host:port is asked over plain
// HTTP first where httpx does.
var probeSeeding bool

// probePool is the run's resolver pool, for the resolvers a probe row names.
var probePool *dnsr.Pool

// guessBudget is the run's cap on the names its guessing asks (-max-names given); nil: none.
var guessBudget *brutecol.Budget

func listSeed(line string) (types.Seed, error) {
	if !strings.Contains(line, "://") {
		if pf, err := netip.ParsePrefix(line); err == nil {
			return types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": pf.Masked().String()}}, nil
		}
		if n, ok := asncol.NormalizeASN(line); ok && strings.HasPrefix(strings.ToUpper(line), "AS") {
			return types.Seed{Type: types.TypeASN, Keys: map[string]string{"asn": n}}, nil
		}
	}
	if strings.Contains(line, "://") {
		u, err := parseCLIURL(line)
		if err != nil {
			return types.Seed{}, err
		}
		return types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": u, types.GivenKey: "1"}}, nil
	}
	if strings.ContainsAny(line, " /?#@") {
		return types.Seed{}, fmt.Errorf("want a URL, host, host:port or IP, got %q", line)
	}
	host, port, err := net.SplitHostPort(line)
	if err != nil {
		host, port = strings.Trim(line, "[]"), ""
	}
	if ip := net.ParseIP(host); ip == nil && port == "" {
		keys := map[string]string{"fqdn": normalize.Hostname(host)}
		if !probeSeeding {
			keys[types.BareKey] = "1"
		}
		return types.Seed{Type: types.TypeHostname, Keys: keys}, nil
	}
	hp := host
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		hp = "[" + host + "]"
	}
	if port == "80" {
		if probeSeeding {
			return types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://" + hp + "/", httpcol.FallbackKey: "https"}}, nil
		}
		return types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://" + hp + "/"}}, nil
	}
	if port != "" {
		hp = net.JoinHostPort(host, port)
	}
	if n, err := strconv.Atoi(port); probeSeeding && err == nil && port != "443" && httpcol.HTTPFirst(n) {
		// As httpx: plain HTTP first on 8080 and the ports above 1024.
		return types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://" + hp + "/", httpcol.FallbackKey: "https"}}, nil
	}
	keys := map[string]string{"url": "https://" + hp + "/", httpcol.FallbackKey: "http"}
	if port == "" && !probeSeeding {
		keys[types.BareKey] = "1" // a bare address: 443 then 80 is a guess
	}
	return types.Seed{Type: types.TypeURL, Keys: keys}, nil
}

// bareAddressPorts gives a bare address of the list (no port) one seed per
// -web-ports port, as if each were written host:port, so the ports asked are
// the ones given, not 443 and 80.
func bareAddressPorts(seeds []types.Seed, ports []int) []types.Seed {
	if len(ports) == 0 {
		return seeds
	}
	var out []types.Seed
	for _, s := range seeds {
		if s.Type != types.TypeURL || s.Keys[types.BareKey] == "" {
			out = append(out, s)
			continue
		}
		u, err := url.Parse(s.Keys["url"])
		if err != nil {
			out = append(out, s)
			continue
		}
		for _, p := range ports {
			if n, err := listSeed(net.JoinHostPort(u.Hostname(), strconv.Itoa(p))); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

func parsePorts(raw string) ([]int, error) {
	var out []int
	for _, p := range splitList(raw) {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("-web-ports: bad port %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}

type stringsFlag []string

// onceFlag is a flag that takes one value: given again with another, it is
// a usage error, not the last one silently kept.
type onceFlag struct {
	val string
	set bool
}

func (o *onceFlag) String() string {
	if o == nil {
		return ""
	}
	return o.val
}

func (o *onceFlag) Set(v string) error {
	if o.set && v != o.val {
		return fmt.Errorf("given twice (%q, then %q) and takes one value: combine them in one", o.val, v)
	}
	o.val, o.set = v, true
	return nil
}

// onceString registers a flag like fs.String that refuses a second value.
func onceString(fs *flag.FlagSet, name, usage string) *string {
	o := &onceFlag{}
	fs.Var(o, name, usage)
	return &o.val
}

func (s *stringsFlag) String() string { return strings.Join(*s, ", ") }

func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func resolveDB(flag string) (path string, remember bool) {
	if flag != "" {
		return flag, false
	}
	if v := os.Getenv("AZHAQ_DB"); v != "" {
		return v, false
	}
	return uniqueDB(), true
}

func uniqueDB() string {
	stamp := time.Now().Format("20060102-150405")
	pid := os.Getpid()
	for i := 0; i < 64; i++ {
		path := fmt.Sprintf("azhaq-%s-%d.db", stamp, pid)
		if i > 0 {
			path = fmt.Sprintf("azhaq-%s-%d-%d.db", stamp, pid, i)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			f.Close()
			return path
		}
		if !os.IsExist(err) {
			break
		}
	}
	return fmt.Sprintf("azhaq-%s-%d-%d.db", stamp, pid, time.Now().UnixNano())
}

func parseCLIURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }); i >= 0 {
		return "", fmt.Errorf("URL contains whitespace or a control character: %q", raw)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("need an http(s) URL, got %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	return raw, nil
}

func parseSeedLine(raw []byte) (types.Seed, error) {
	var probe struct {
		Collector string          `json:"collector"`
		ID        string          `json:"id"`
		Type      types.SeedType  `json:"type"`
		Seed      json.RawMessage `json:"seed"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return types.Seed{}, err
	}
	if probe.Collector != "" && probe.ID != "" {
		return types.Seed{}, fmt.Errorf("plan work item, not a seed (pass the original seeds to -in)")
	}
	var s types.Seed
	if err := json.Unmarshal(raw, &s); err != nil {
		return types.Seed{}, err
	}
	if s.Type == "" || s.Key() == "" {
		return types.Seed{}, fmt.Errorf("not a seed")
	}
	if !types.Known(s.Type) {
		return types.Seed{}, fmt.Errorf("unknown seed type %q", s.Type)
	}
	if s.Type == types.TypeURL {
		u, err := parseCLIURL(s.Keys["url"])
		if err != nil {
			return types.Seed{}, err
		}
		s.Keys["url"] = u
	}
	return s, nil
}

// loadLines reads one entry per line, skipping blanks and # comments.
func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLines(f)
}

// loadWordlist is loadLines for a wordlist: an empty line stays, as in
// ffuf, where the empty word asks for the base URL itself.
func loadWordlist(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		if t := strings.TrimSpace(line); line == "" || (t != "" && !strings.HasPrefix(t, "#")) {
			out = append(out, t)
		}
	}
	return out, nil
}

// readLines returns non-empty lines that are not # comments.
func readLines(r io.Reader) ([]string, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

// skipAliases are the names of commands that are not their collector's:
// -skip subs reads as the subdomain collector.
var skipAliases = map[string]string{"subs": "azhaq-subdomains", "subdomains": "azhaq-subdomains", "brute": "azhaq-dns-brute"}

// resolveSkip turns the names of -skip into collector names: a collector's
// own, or without its azhaq- prefix (ports, urls, dirs), or a command's
// alias (subs). A name that is none of them is an error: a skip that skips
// nothing would pass for one that did.
func resolveSkip(names []string) ([]string, error) {
	have := allCollectors()
	var out []string
	for _, n := range names {
		switch {
		case slices.Contains(have, n):
			out = append(out, n)
		case slices.Contains(have, "azhaq-"+n):
			out = append(out, "azhaq-"+n)
		case skipAliases[n] != "" && slices.Contains(have, skipAliases[n]):
			out = append(out, skipAliases[n])
		default:
			return nil, fmt.Errorf("no collector is named %q (they are %s; the azhaq- prefix may be left off, and subs is the subdomain collector)", n, strings.Join(have, ", "))
		}
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func loadPathList(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.TrimPrefix(line, "/"))
	}
	return out, nil
}

// hasHost says whether a URL seed is on the host of raw.
func hasHost(seeds []types.Seed, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for _, sd := range seeds {
		if su, err := url.Parse(sd.Keys["url"]); err == nil && sd.Type == types.TypeURL && su.Host == u.Host {
			return true
		}
	}
	return false
}

// signIn signs in on loginURL with Chrome (b, or a browser of its own) and
// adds the session to every request; it returns the page the login ended
// on. What Chrome was refused on the way is listed in rep.
func signIn(b *browser.Browser, loginURL, user, pass string, rep *report, base http.Header) (string, error) {
	if pass == "" {
		pass = os.Getenv("AZHAQ_LOGIN_PASS")
	}
	if user == "" || pass == "" {
		return "", fmt.Errorf("-login needs -login-user and -login-pass (or AZHAQ_LOGIN_PASS)")
	}
	if b == nil {
		b = &browser.Browser{UserAgent: browserAgent()}
		defer b.Close()
		defer chromeRefused(rep, b)
	}
	ctx, stop := stopContext()
	defer stop()
	s, err := b.Login(ctx, loginURL, user, pass)
	for _, u := range s.Blocked {
		rep.Skipped = append(rep.Skipped, engine.Skip{Target: u, Reason: browser.Reason()})
	}
	if err != nil {
		return "", chromeStartErr(fmt.Errorf("-login %s: %w", loginURL, err))
	}
	if len(s.Cookies) == 0 && s.Bearer == "" {
		return "", fmt.Errorf("-login %s: signed in, but the site set no cookie and stored no token", loginURL)
	}
	// Built apart and set whole: requests in flight read fetch.Extra, and keep
	// the old session until the new one is ready. base is the headers the new
	// session is added to; nil: the ones now sent.
	if base == nil {
		base = fetch.CurrentExtra()
	}
	extra := base.Clone()
	if extra == nil {
		extra = make(http.Header)
	}
	defer func() { fetch.SetExtra(extra) }()
	if len(s.Cookies) > 0 {
		c := strings.Join(s.Cookies, "; ")
		if old := extra.Get("Cookie"); old != "" {
			c = old + "; " + c
		}
		extra.Set("Cookie", c)
	}
	what := fmt.Sprintf("%d cookies", len(s.Cookies))
	if s.Bearer != "" && extra.Get("Authorization") == "" {
		extra.Set("Authorization", "Bearer "+s.Bearer)
		if b.Header == nil {
			b.Header = map[string]any{}
		}
		b.Header["Authorization"] = "Bearer " + s.Bearer // the browser keeps the cookies itself
		what += ", a token from " + s.From
	}
	fmt.Fprintf(os.Stderr, "azhaq: signed in as %s (%s); now on %s\n", user, what, s.URL)
	return s.URL, nil
}

// chromeStartErr is err, as a usage error when Chrome did not start because
// the system gave it no sandbox: the command line is what to change
// (-chrome-no-sandbox), and nothing was sent yet.
func chromeStartErr(err error) error {
	if errors.Is(err, browser.ErrNoSandbox) {
		return usageErr{err}
	}
	return err
}

// chromeRefused lists in rep what Chrome was refused that no page claimed
// (a service worker's requests, WebSockets, a beacon as a tab closed, a
// download the sign-in began), and how many requests there were when
// more URLs were refused than are listed.
func chromeRefused(rep *report, b *browser.Browser) {
	for _, u := range b.Leftover() {
		rep.Skipped = append(rep.Skipped, engine.Skip{Target: u, Reason: browser.Reason()})
	}
	for _, u := range b.LeftoverDownloads() {
		rep.Skipped = append(rep.Skipped, engine.Skip{Target: u, Reason: browser.DownloadReason})
	}
	for _, w := range b.LeftoverWrites() {
		if s := (engine.Skip{Target: w, Reason: browser.WriteReason}); !slices.Contains(rep.Skipped, s) {
			rep.Skipped = append(rep.Skipped, s)
		}
	}
	if why := b.Unsandboxed(); why != "" {
		rep.Notes = append(rep.Notes, "Chrome ran without its sandbox ("+why+"), as -chrome-no-sandbox or AZHAQ_CHROME_NO_SANDBOX=1 allowed: the pages it loaded are the targets' and untrusted")
	}
	if n, hosts := b.GuardDenied(); n > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("Chrome's own services reached for %d connections outside the scope (%s); all were refused, none was sent", n, listOfHosts(hosts, 3)))
	}
	if n, listed, more := b.Refused(); more {
		rep.Notes = append(rep.Notes, fmt.Sprintf("Chrome was refused %d requests %s; the first %d URLs are listed", n, strings.TrimSuffix(browser.Reason(), " (Chrome)"), listed))
	}
}

// listOfHosts is up to n hosts, then how many more.
func listOfHosts(hosts []string, n int) string {
	if len(hosts) <= n {
		return strings.Join(hosts, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(hosts[:n], ", "), len(hosts)-n)
}

// browserAgent is the User-Agent Chrome sends: the run's, not Chrome's
// headless one, which bot managers refuse.
func browserAgent() string {
	if ua := fetch.CurrentExtra().Get("User-Agent"); ua != "" {
		return ua
	}
	return fetch.UserAgent
}

// hostHeadersInScope refuses a -header that names a host the scope leaves
// out: it would reach that host through an address the scope allows. With no
// -allow, -deny or -scope the host a header names joins the targets instead
// (see headerHosts): what the user typed is what they authorized.
func hostHeadersInScope(h http.Header, rules scope.Rules) error {
	return hostHeadersFrom("-header", h, rules)
}

// headerHosts are the hosts the host-naming headers of h name, without
// duplicates.
func headerHosts(h http.Header) []string {
	var out []string
	for k, vs := range h {
		if !scope.NamesHost(k) {
			continue
		}
		for _, v := range vs {
			for _, host := range scope.HeaderHosts(v) {
				if !slices.Contains(out, host) {
					out = append(out, host)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// flagHeaderHosts are the hosts the -header flags among run flags name.
func flagHeaderHosts(runFlags []string) []string {
	h := http.Header{}
	for _, raw := range append(runFlagValues(runFlags, "header"), runFlagValues(runFlags, "H")...) {
		if k, v, ok := strings.Cut(raw, ":"); ok {
			h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return headerHosts(h)
}

// hostHeadersFrom is hostHeadersInScope for headers that came from what
// (a role, a request file): the same refusal, before anything is sent.
func hostHeadersFrom(what string, h http.Header, rules scope.Rules) error {
	if rules.Empty() {
		return nil
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			if h := rules.HeaderOutside(k, v); h != "" {
				if rules.Allows(h) {
					return usagef("%s %s: %s names a port the scope leaves out for %s: -allow lists it with another port only (HOST:PORT allows that port; HOST alone, every port); leave the port out or allow it", what, k, v, h)
				}
				return usagef("%s %s: %s names a host outside the scope: a front end that routes by it serves that host; leave the header out, or name the host in the scope (-allow)", what, k, v)
			}
		}
	}
	return nil
}

// paramsTargetsInScope holds the headers of the pages a -params-targets file
// (params -i writes it) names to the scope: a request that is imported
// carries its own X-Forwarded-Host and the like.
func paramsTargetsInScope(path string, rules scope.Rules) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil // the run reads it again and says
	}
	var targets map[string]paramcol.Target
	if json.Unmarshal(raw, &targets) != nil {
		return nil
	}
	urls := make([]string, 0, len(targets))
	for u := range targets {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	for _, u := range urls {
		h := http.Header{}
		for _, l := range targets[u].Header {
			if k, v, ok := strings.Cut(l, ":"); ok {
				h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
			}
		}
		if err := hostHeadersFrom("-i "+u+" header", h, rules); err != nil {
			return err
		}
	}
	return nil
}

// probeSpecInScope holds what a probe sends besides -header to the scope: the
// headers of the request file (-rr) and the virtual hosts of -vi lines.
func probeSpecInScope(spec *httpcol.Spec, rules scope.Rules) error {
	if spec == nil {
		return nil
	}
	if spec.Raw != nil {
		if err := hostHeadersFrom("-rr header", spec.Raw.Header, rules); err != nil {
			return err
		}
	}
	hosts := make([]string, 0, len(spec.PerHost))
	for h := range spec.PerHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		for _, vh := range spec.PerHost[h].VHosts {
			if err := hostHeadersFrom("-vi", http.Header{"Host": {vh}}, rules); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyExtra(cookies, headers []string) error {
	if len(cookies) == 0 && len(headers) == 0 {
		return nil
	}
	h := make(http.Header)
	var cookieParts []string
	for _, c := range cookies {
		c = strings.TrimSpace(c)
		if c == "" || !strings.Contains(c, "=") {
			return fmt.Errorf("cookie must be name=value")
		}
		cookieParts = append(cookieParts, c)
	}
	if len(cookieParts) > 0 {
		h.Set("Cookie", strings.Join(cookieParts, "; "))
	}
	for _, raw := range headers {
		k, v, ok := strings.Cut(raw, ":")
		if !ok || strings.TrimSpace(k) == "" {
			return fmt.Errorf("header must be K: V")
		}
		h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	fetch.Extra = h
	return nil
}

func splitCmd(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty -exec")
	}
	var parts []string
	var cur strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unclosed quote in -exec")
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty -exec")
	}
	return parts, nil
}

func compact(raw json.RawMessage) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return string(raw)
	}
	parts := make([]string, 0, 4)
	for _, k := range []string{"status", "catchall", "title", "url", "via", "methods", "path", "fqdn", "ips", "params", "role", "count", "not_after", "error", "skipped", "registrar", "registrant", "name", "id", "method", "action", "fields", "auth", "final_url", "extracted", "warning", "note"} {
		if v, ok := m[k]; ok && v != nil && fmt.Sprint(v) != "" {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, " ")
}

// seedScope is the scope the targets themselves name. An ASN or an
// organisation names none.
func seedScope(seeds []types.Seed) []string {
	var out []string
	for _, s := range seeds {
		s = normalize.Seed(s)
		switch s.Type {
		case types.TypeURL:
			out = append(out, normalize.HostFromURL(s.Key()))
		case types.TypeHostname, types.TypeDomain, types.TypeIPAddress, types.TypePrefix:
			out = append(out, s.Key())
		}
	}
	return out
}

// browserOnly counts the URLs only Chrome's rendering saw, and the pages
// it rendered.
func browserOnly(obs []types.StoredObservation) (only, pages int) {
	byChrome, byOthers, rendered := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, o := range obs {
		if o.Kind != "url" {
			continue
		}
		var p struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
			continue
		}
		if o.Collector == rendercol.Name {
			byChrome[p.URL] = true
			rendered[o.Source] = true
		} else {
			byOthers[p.URL] = true
		}
	}
	for u := range byChrome {
		if !byOthers[u] {
			only++
		}
	}
	return only, len(rendered)
}

// markDescribed tells fetch which origins the workspace's run already read
// an API description from, so a resumed run does not guess its locations
// again (the mark lives in the process that found it).
func markDescribed(st *store.Store) {
	obs, err := st.Observations()
	if err != nil {
		return
	}
	for _, o := range obs {
		if o.Collector != apicol.Name || (o.Kind != "api" && o.Kind != "api-ui") {
			continue
		}
		if u, err := url.Parse(o.Source); err == nil && u.Host != "" {
			fetch.MarkDescribed(u.Scheme + "://" + u.Host)
		}
	}
}

// dirsMatchers are the matcher and filter flags of a path sweep, as ffuf
// names them (run's carry the prefix -dirs-): the Set kind each is, and
// whether it filters.
var dirsMatchers = []struct {
	flag, kind, help string
	filter           bool
}{
	{"mc", "status", "report only these statuses (comma-separated, ranges, or all; default ffuf's: 200-299,301,302,307,401,403,405,500)", false},
	{"ms", "size", "report only these response sizes (values and ranges, 100-200)", false},
	{"mw", "word", "report only these word counts", false},
	{"ml", "line", "report only these line counts", false},
	{"mr", "regexp", "report only answers whose headers or body match this regular expression", false},
	{"fc", "status", "hide these statuses", true},
	{"fs", "size", "hide these response sizes", true},
	{"fw", "word", "hide these word counts", true},
	{"fl", "line", "hide these line counts", true},
	{"fr", "regexp", "hide answers whose headers or body match this regular expression", true},
}

// dirsSet is the matchers and filters the flags given (by name, without
// the dash) make, as ffuf does: the default -mc applies when no matcher
// is given. prefix says what to put before a flag's name in an error.
func dirsSet(given map[string]string, prefix string) (*fuzz.Set, error) {
	matcher := false
	for _, m := range dirsMatchers {
		if !m.filter && given[m.flag] != "" {
			matcher = true
		}
	}
	set := fuzz.NewSet(nil)
	if !matcher {
		given = maps.Clone(given)
		given["mc"] = dirscol.DefaultStatus
	}
	for _, m := range dirsMatchers {
		v := given[m.flag]
		if v == "" {
			continue
		}
		add := set.AddMatcher
		if m.filter {
			add = set.AddFilter
		}
		if err := add(m.kind, v); err != nil {
			return nil, usagef("%s", strings.Replace(err.Error(), "-"+m.flag, prefix+m.flag, 1))
		}
	}
	return set, nil
}

// shotOptions are the flags that shape Chrome's pictures.
type shotOptions struct {
	size, format, js, codes, chrome, proxy, profile string
	full, ports                                     bool
	wait, timeout                                   time.Duration
	waitGiven                                       bool // -shot-wait was given: a fixed wait, not until the page has drawn
	quality                                         int
}

// shotBrowser is a Browser set from the screenshot flags; a bad value is
// a usage error, before anything is sent.
func shotBrowser(o shotOptions) (*browser.Browser, error) {
	b := &browser.Browser{FullPage: o.full, Quality: o.quality, ChromePath: o.chrome, Proxy: o.proxy, ProfileDir: o.profile, AllowPorts: o.ports}
	w, h, ok := strings.Cut(strings.ToLower(o.size), "x")
	wi, e1 := strconv.Atoi(w)
	hi, e2 := strconv.Atoi(h)
	if !ok || e1 != nil || e2 != nil || wi < 100 || hi < 100 || wi > 8192 || hi > 8192 {
		return nil, usagef("-shot-size wants WIDTHxHEIGHT between 100x100 and 8192x8192, such as 1440x900, got %q", o.size)
	}
	b.Width, b.Height = wi, hi
	switch strings.ToLower(o.format) {
	case "png", "":
		b.Format = "png"
	case "jpeg", "jpg":
		b.Format = "jpeg"
	default:
		return nil, usagef("-shot-format is png or jpeg, got %q", o.format)
	}
	if o.quality < 1 || o.quality > 100 {
		return nil, usagef("-shot-quality is 1 to 100, got %d", o.quality)
	}
	if o.timeout <= 0 {
		return nil, usagef("-shot-timeout must be more than 0")
	}
	b.Timeout = o.timeout
	switch {
	case !o.waitGiven:
		b.Wait = 0 // until the page has drawn, at most the default wait
	case o.wait <= 0:
		b.Wait = -1
	default:
		b.Wait = o.wait
	}
	if o.js != "" {
		raw, err := os.ReadFile(o.js)
		if err != nil {
			return nil, usagef("-shot-js: %v", err)
		}
		b.Script = string(raw)
	}
	for _, c := range splitList(o.codes) {
		n, err := strconv.Atoi(c)
		if err != nil || n < 100 || n > 599 {
			return nil, usagef("-shot-codes wants HTTP statuses such as 200,301, got %q", c)
		}
		b.Codes = append(b.Codes, n)
	}
	return b, nil
}

// parseProxy reads -proxy.
func parseProxy(s string) (*url.URL, error) {
	pu, err := url.Parse(s)
	if err != nil || pu.Host == "" || !slices.Contains([]string{"http", "https", "socks5", "socks5h"}, pu.Scheme) {
		return nil, usagef("-proxy wants http://host:port, https://host:port or socks5://host:port, got %q", s)
	}
	return pu, nil
}
