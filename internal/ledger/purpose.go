package ledger

import (
	"context"
	"net/url"
	"strings"
)

// What a request to a target was for, so that a summary can say where the
// requests of a run went. A request a collector marks (WithPurpose) is that;
// the rest of a collector's page work is told apart by what the URL names.
const (
	PurposePages        = "pages"              // a page or a route asked as one
	PurposeScripts      = "scripts"            // a script, a stylesheet or a source map
	PurposeAssets       = "assets"             // an image, a font or a media file
	PurposeControls     = "controls"           // a request for a path that cannot exist: what an answer is compared with
	PurposeDescriptions = "description checks" // a guess where an API description or a GraphQL endpoint is
	PurposePathChecks   = "path checks"        // the built-in paths: robots.txt, sitemaps, .git/HEAD, admin pages
	PurposeSweep        = "wordlist sweep"     // a path of a wordlist
	PurposeParams       = "parameter probes"
	PurposeBrowser      = "browser" // a request Chrome sent
	PurposeConnections  = "connections"
	PurposeWorkers      = "sent by workers" // by another process of the run: it does not say what they were for
	PurposeOther        = "other"
)

type purposeKey struct{}

// WithPurpose marks ctx with what the requests made with it are for.
func WithPurpose(ctx context.Context, p string) context.Context {
	return context.WithValue(ctx, purposeKey{}, p)
}

// PurposeOf is what ctx says its requests are for (see WithPurpose), or "".
func PurposeOf(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	p, _ := ctx.Value(purposeKey{}).(string)
	return p
}

// purposeFor is what a request to a target of kind (http, chrome, tcp, udp)
// sent by collector was for. A mark on ctx wins; without one, only a
// collector that fetches what a crawl reads is told apart by the URL, and
// the others are what their own work is, or other.
func purposeFor(ctx context.Context, kind, collector string, u *url.URL) string {
	if p := PurposeOf(ctx); p != "" {
		return p
	}
	switch kind {
	case "tcp", "udp":
		return PurposeConnections
	case "chrome":
		return PurposeBrowser
	}
	switch strings.TrimPrefix(collector, "azhaq-") {
	case "http", "crawl", "js":
		return purposeOfURL(u)
	case "dirs":
		return PurposeSweep
	case "params":
		return PurposeParams
	}
	return PurposeOther
}

var scriptExt = []string{".js", ".mjs", ".cjs", ".css", ".map"}

var assetExt = []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
	".mp4", ".webm", ".avif", ".apng", ".bmp", ".heic", ".otf", ".mp3", ".ogg", ".wav"}

// purposeOfURL tells a script, an asset and a page apart by the file name
// the path ends with.
func purposeOfURL(u *url.URL) string {
	if u == nil {
		return PurposePages
	}
	p := strings.ToLower(u.Path)
	for _, e := range scriptExt {
		if strings.HasSuffix(p, e) {
			return PurposeScripts
		}
	}
	for _, e := range assetExt {
		if strings.HasSuffix(p, e) {
			return PurposeAssets
		}
	}
	return PurposePages
}

// Remote counts n requests to targets that another process of the run (a
// worker) sent: this process has no lines for them, and the summary says
// they were not its own.
func Remote(n int) {
	if n > 0 {
		spend(ClassTarget, "http", "", PurposeWorkers, int64(n))
	}
}
