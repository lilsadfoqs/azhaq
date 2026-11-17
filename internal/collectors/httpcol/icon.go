package httpcol

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/detect"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/statechange"
)

// maxIconAsks is how many of the products one icon names are asked about: an
// icon shared by more is no name for any of them.
const maxIconAsks = 4

// confirmIcons asks, once for each product the page's icon names, the read a
// template written for that product asks (the same path, purpose and cache as
// the sweep's product checks, so the sweep does not send it again). An answer
// a template of the product matches makes it an identification, with the
// version the template read; any other answer leaves it an icon lead, and the
// row says what was asked and what came back.
func (c *Collector) confirmIcons(ctx context.Context, page string, rows []map[string]string) {
	u, err := url.Parse(page)
	if err != nil || u.Host == "" {
		return
	}
	origin := u.Scheme + "://" + u.Host
	asked := 0
	for _, r := range rows {
		if r["icon"] == "" {
			continue
		}
		path := confirmPath(r["product"])
		switch {
		case ctx.Err() != nil:
			return
		case c.NoProductReads:
			r["ask"] = "not asked: the product checks are off (-no-paths)"
		case path == "":
			r["ask"] = "not asked: no published template names a read for it"
		case asked == maxIconAsks:
			r["ask"] = fmt.Sprintf("not asked: the icon names more than %d products", maxIconAsks)
		default:
			asked++
			c.askIcon(ctx, origin, path, r)
		}
	}
}

// confirmPath is the first read of a template written for product that a
// run may send: not a state change, nothing to name it by but the answer.
func confirmPath(product string) string {
	for _, p := range detect.ConfirmPaths(product) {
		if word, _ := statechange.OfTarget(p); word == "" && !strings.HasPrefix(strings.ToLower(p), "/?") {
			return p
		}
	}
	return ""
}

// askIcon sends the one read and writes what came of it into the row.
func (c *Collector) askIcon(ctx context.Context, origin, path string, row map[string]string) {
	target := origin + path
	res, _, err := fetch.Do(ledger.WithPurpose(ctx, ledger.PurposeProductChecks), c.Client, target)
	if err != nil {
		if ctx.Err() == nil {
			row["ask"] = "GET " + path + ": not answered (" + clip(strings.TrimPrefix(err.Error(), "not requested: "), 80) + ")"
		}
		return
	}
	status, header := res.Status, res.Header
	if n := len(res.Hops); n > 1 {
		status = res.Hops[n-1].Status
	}
	if res.FinalHeader != nil {
		header = res.FinalHeader
	}
	if header == nil {
		header = http.Header{}
	}
	body := res.Body[:min(len(res.Body), maxTechBody)]
	for _, h := range detect.Match(detect.Response{Path: path, Status: status, Header: header, Body: body}) {
		if h.Icon || !detect.Related(h.Product, row["product"]) {
			continue
		}
		delete(row, "icon")
		row["ask"] = fmt.Sprintf("GET %s answered %d and the template %s matched", path, status, h.Template)
		if h.Version != "" {
			row["version"] = h.Version
		}
		return
	}
	row["ask"] = fmt.Sprintf("GET %s answered %d and no template of the product matched", path, status)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
