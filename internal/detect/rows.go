package detect

import "strings"

// Rows are hits as a stored row holds them: product, version, and the
// template (and its matcher) that named them, once per product and version.
func Rows(hits []Hit) []map[string]string {
	var out []map[string]string
	seen := map[string]bool{}
	for _, h := range hits {
		k := strings.ToLower(h.Product) + "\x00" + h.Version
		if h.Product == "" || seen[k] {
			continue
		}
		seen[k] = true
		row := map[string]string{"product": h.Product, "template": h.Template}
		if h.Version != "" {
			row["version"] = h.Version
		}
		if h.Matcher != "" {
			row["matcher"] = h.Matcher
		}
		if h.Many {
			row["many"] = "1" // one of many products the template names
		}
		out = append(out, row)
	}
	return out
}

// MergeRows adds rows to have, keeping one per product and version.
func MergeRows(have, add []map[string]string) []map[string]string {
	seen := map[string]bool{}
	for _, r := range have {
		seen[strings.ToLower(r["product"])+"\x00"+r["version"]] = true
	}
	for _, r := range add {
		if k := strings.ToLower(r["product"]) + "\x00" + r["version"]; !seen[k] {
			seen[k] = true
			have = append(have, r)
		}
	}
	return have
}
