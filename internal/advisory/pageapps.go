package advisory

import (
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/lilsadfoqs/azhaq/internal/fingerprint"
	"github.com/lilsadfoqs/azhaq/internal/httprow"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// The sources of a page application's name, as a row says them.
const (
	SourceTitle     = "page title"
	SourceGenerator = "generator"
	SourcePowered   = "header X-Powered-By"
	SourceServer    = "header Server"
	SourceRealm     = "header WWW-Authenticate realm"
	SourceTech      = "technology"
	SourceDetect    = "detection template"
	// SourceDetectOne is a template written for one product; it is shown as SourceDetect.
	SourceDetectOne = "detection template for the product"
)

// detectedSource is how a detection is classed: a template written for one
// product names an application (or a server); one that names many names
// libraries, fonts and CDNs too, which the fingerprints' categories tell apart.
func detectedSource(d httprow.Detected) string {
	if d.Many != "" {
		return SourceDetect
	}
	return SourceDetectOne
}

// detectedRow reads a row the paths sweep wrote for an answer that matched
// detection templates: the page it was asked of, the path, and the products.
func detectedRow(o types.StoredObservation) (page string, found []httprow.Detected, ok bool) {
	if o.Collector != "azhaq-paths" || o.Kind != "detected" {
		return "", nil, false
	}
	var row struct {
		URL      string             `json:"url"`
		Path     string             `json:"path"`
		Detected []httprow.Detected `json:"detected"`
	}
	if json.Unmarshal(o.Payload, &row) != nil || row.URL == "" {
		return "", nil, false
	}
	u, err := url.Parse(row.URL)
	if err != nil {
		return "", nil, false
	}
	return u.Scheme + "://" + u.Host + row.Path, row.Detected, true
}

// pageApps are the applications the root page of each name:port names about
// itself, one service for each name:port and product: from its <title> (the
// title rules the port scan reads a page with), its generator meta tag, an
// X-Powered-By or Server header, a WWW-Authenticate realm, or the technologies
// wappalyzer found in it.
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
	apps, _ := pageAppsAndIcons(obs)
	return apps
}

// pageAppsAndIcons is pageApps, and the products the hash of an icon alone
// named, which are no application of the name: IconLeads says which of them
// stay leads.
func pageAppsAndIcons(obs []types.StoredObservation) ([]pageApp, []iconCand) {
	var out []pageApp
	var icons []iconCand
	at := map[string]int{}
	for _, o := range obs {
		var row httprow.Row
		from := ""
		if page, found, ok := detectedRow(o); ok {
			// A path the sweep asked to name the product: the origin's root stands for it.
			u, _ := url.Parse(page)
			row.URL, row.Detected, from = u.Scheme+"://"+u.Host+"/", found, page
		} else if o.Collector != "azhaq-http" {
			continue
		} else if r, err := httprow.ParseRow(o.Payload); err != nil {
			continue
		} else {
			row = r
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
		add := func(product, version, source, said string, viaProxy bool) {
			if viaProxy {
				// Named by a header alone through a -proxy that could not be
				// asked for its own answer: the name stays, the version is not taken.
				version, said = "", said+" (read through -proxy, which could not be asked for its own answer)"
			}
			product = strings.TrimSpace(product)
			if product == "" {
				return
			}
			class := classify(product, source)
			if class == skip {
				return
			}
			at := row.URL
			if from != "" {
				at = from
			}
			if source == SourceDetectOne {
				source = SourceDetect
			}
			cands = append(cands, pageApp{Service: Service{Host: u.Hostname(), Port: port, Proto: "tcp", Service: u.Scheme, Product: product, Version: version,
				Origin: u.Scheme + "://" + u.Host, Banner: said, Source: source, ObservedAt: o.ObservedAt, From: at}, Plain: class == plain})
		}
		if p, v := portscan.TitleProduct(row.Title); p != "" {
			add(p, v, SourceTitle, "<title>"+row.Title+"</title>", false)
		}
		if p, v := portscan.GeneratorProduct(row.Generator); p != "" {
			add(p, v, SourceGenerator, `<meta name="generator" content="`+row.Generator+`">`, false)
		}
		if pw := row.Headers["x-powered-by"]; pw != "" {
			if p, v := portscan.HeaderProduct(pw); p != "" {
				add(p, v, SourcePowered, "X-Powered-By: "+pw, slices.Contains(row.ViaProxy, "X-Powered-By"))
			}
		}
		if row.Server != "" {
			if p, v := portscan.HeaderProduct(row.Server); p != "" {
				add(p, v, SourceServer, "Server: "+row.Server, slices.Contains(row.ViaProxy, "Server"))
			}
		}
		if row.Realm != "" {
			if p := portscan.RealmProduct(row.Realm); p != "" {
				add(p, "", SourceRealm, `WWW-Authenticate realm="`+row.Realm+`"`, false)
			}
		}
		for _, t := range row.Tech {
			name, version, _ := strings.Cut(t, ":")
			if version != "" && (version[0] < '0' || version[0] > '9') {
				version = ""
			}
			add(name, version, SourceTech, "technology: "+t, slices.Contains(row.ViaProxy, "tech:"+t))
		}
		ic := iconCand{Host: u.Hostname(), Port: port, Origin: u.Scheme + "://" + u.Host, From: row.URL, Hash: row.Favicon, IconURL: row.FaviconURL, ObservedAt: o.ObservedAt}
		for _, d := range row.Detected {
			if d.IconOnly() {
				if p := strings.TrimSpace(d.Product); p != "" {
					ic.Products = append(ic.Products, iconProduct{Product: p, Ask: d.Ask})
				}
				continue
			}
			if foreignVersion(row.Server, d.Product, d.Version) {
				d.Version = ""
			}
			add(d.Product, d.Version, detectedSource(d), d.Said(), d.ViaProxy != "")
		}
		if len(ic.Products) > 0 {
			icons = append(icons, ic)
		}
		for _, c := range cands {
			k := strings.ToLower(c.Host) + "|" + strconv.Itoa(c.Port) + "|" + identity(c.Product)
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
	return out, icons
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
// generator are the page's own word for what it is, and so is a realm: an application unless the
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
	case SourceTitle, SourceGenerator, SourceRealm:
		return app
	case SourcePowered:
		if isLang || len(cats) == 0 {
			return app
		}
	case SourceServer:
		if len(cats) == 0 {
			return plain
		}
	case SourceDetect:
		if len(cats) == 0 {
			return app // a template names it; the fingerprints do not class it
		}
	case SourceDetectOne:
		return app // a template written to name this product: an application, unless a server (above)
	}
	return skip
}
