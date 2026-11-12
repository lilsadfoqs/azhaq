package advisory

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/lilsadfoqs/azhaq/internal/fingerprint"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// The sources of a page application's name, as a row says them.
const (
	SourceTitle     = "page title"
	SourceGenerator = "generator"
	SourcePowered   = "header X-Powered-By"
	SourceServer    = "header Server"
	SourceTech      = "technology"
)

// pageApps are the applications the root page of each name:port names about
// itself, one service for each name:port and product: from its <title> (the
// title rules the port scan reads a page with), its generator meta tag, an
// X-Powered-By or Server header, or the technologies wappalyzer found in it.
// A version is only what one of them stated; Source says which.
//
// Only application-level products are kept: wappalyzer's categories tell a
// CMS, a wiki, a CI server, a database manager, a framework app from a
// library, a font, a CDN or an analytics script. A product the data holds
// under categories of servers only (web servers, reverse proxies, caches) is
// kept with Plain set, for the caller to leave out where the listener already
// names it. A product the data does not hold, named by a title, a generator or
// X-Powered-By, is the page's own word for itself and is kept.
func pageApps(obs []types.StoredObservation) []pageApp {
	var out []pageApp
	at := map[string]int{}
	for _, o := range obs {
		if o.Collector != "azhaq-http" {
			continue
		}
		var row struct {
			URL       string            `json:"url"`
			Title     string            `json:"title"`
			Generator string            `json:"generator"`
			Server    string            `json:"server"`
			Headers   map[string]string `json:"headers"`
			Tech      []string          `json:"tech"`
		}
		if json.Unmarshal(o.Payload, &row) != nil {
			continue
		}
		u, err := url.Parse(row.URL)
		if err != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			continue // the root page of a name only
		}
		port := 80
		if p, err := strconv.Atoi(u.Port()); err == nil {
			port = p
		} else if u.Scheme == "https" {
			port = 443
		}
		var cands []pageApp
		add := func(product, version, source, said string) {
			product = strings.TrimSpace(product)
			if product == "" {
				return
			}
			class := classify(product, source)
			if class == skip {
				return
			}
			cands = append(cands, pageApp{Service: Service{Host: u.Hostname(), Port: port, Proto: "tcp", Service: u.Scheme, Product: product, Version: version,
				Origin: u.Scheme + "://" + u.Host, Banner: said, Source: source, ObservedAt: o.ObservedAt, From: row.URL}, Plain: class == plain})
		}
		if p, v := portscan.TitleProduct(row.Title); p != "" {
			add(p, v, SourceTitle, "<title>"+row.Title+"</title>")
		}
		if p, v := portscan.GeneratorProduct(row.Generator); p != "" {
			add(p, v, SourceGenerator, `<meta name="generator" content="`+row.Generator+`">`)
		}
		if pw := row.Headers["x-powered-by"]; pw != "" {
			if p, v := portscan.HeaderProduct(pw); p != "" {
				add(p, v, SourcePowered, "X-Powered-By: "+pw)
			}
		}
		if row.Server != "" {
			if p, v := portscan.HeaderProduct(row.Server); p != "" {
				add(p, v, SourceServer, "Server: "+row.Server)
			}
		}
		for _, t := range row.Tech {
			name, version, _ := strings.Cut(t, ":")
			if version != "" && (version[0] < '0' || version[0] > '9') {
				version = ""
			}
			add(name, version, SourceTech, "technology: "+t)
		}
		for _, c := range cands {
			k := strings.ToLower(c.Host) + "|" + strconv.Itoa(c.Port) + "|" + ProductKey(c.Product)
			i, ok := at[k]
			switch {
			case !ok:
				at[k] = len(out)
				out = append(out, c)
			case moreSpecific(c.Version, out[i].Version):
				out[i] = c // one row: the version a source stated beats none
			}
		}
	}
	return out
}

// pageApp is a page application and whether it is a plain server.
type pageApp struct {
	Service
	Plain bool // a web server, proxy or cache: the listener's own row says it
}

type appClass int

const (
	skip  appClass = iota // a library, a font, a CDN, analytics…: not an application
	plain                 // a web server, a reverse proxy, a cache
	app                   // an application
)

// Wappalyzer's categories of applications, and of servers. Everything else
// (JavaScript libraries and frameworks, UI frameworks, fonts, CDNs, analytics,
// tag managers, advertising, widgets…) is not an application a name serves.
var (
	appCategories = setOf("CMS", "Message boards", "Database managers", "Documentation", "Ecommerce", "Photo galleries", "Wikis",
		"Hosting panels", "Blogs", "Issue trackers", "LMS", "Webmail", "Media servers", "Network devices", "Webcams", "CI",
		"Control systems", "Remote access", "Network storage", "DMS", "Email", "Search engines", "Databases", "Development",
		"Digital asset management", "Feed readers", "Web frameworks", "Accounting", "CRM", "Static site generator")
	plainCategories = setOf("Web servers", "Reverse proxies", "Load balancers", "Caching", "Web server extensions")
)

func setOf(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

var (
	catMu    sync.Mutex
	catCache = map[string][]string{}
)

func categoriesOf(product string) []string {
	k := strings.ToLower(product)
	catMu.Lock()
	defer catMu.Unlock()
	if c, ok := catCache[k]; ok {
		return c
	}
	c := fingerprint.Categories(product)
	catCache[k] = c
	return c
}

// classify says what a product a page named by source is. A title and a
// generator are the page's own word for what it is: an application unless the
// data says it is a server. X-Powered-By names the framework app, and so a
// language runtime too. A Server header names the web server, unless the data
// says the product is an application. A technology is an application only by
// its categories.
func classify(product, source string) appClass {
	cats := categoriesOf(product)
	var isApp, isLang bool
	allPlain := len(cats) > 0
	for _, c := range cats {
		isApp = isApp || appCategories[c]
		isLang = isLang || c == "Programming languages"
		allPlain = allPlain && plainCategories[c]
	}
	switch {
	case isApp:
		return app
	case allPlain:
		return plain
	}
	switch source {
	case SourceTitle, SourceGenerator:
		return app
	case SourcePowered:
		if isLang || len(cats) == 0 {
			return app
		}
	case SourceServer:
		if len(cats) == 0 {
			return plain
		}
	}
	return skip
}
