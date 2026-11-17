package detect

import "strings"

// Rows are hits as a stored row holds them: product, version, and the
// template (and its matcher) that named them, once per product and version.
func Rows(hits []Hit) []map[string]string {
	var out []map[string]string
	seen := map[string]map[string]string{}
	for _, h := range hits {
		k := strings.ToLower(h.Product) + "\x00" + h.Version
		if h.Product == "" {
			continue
		}
		if have := seen[k]; have != nil {
			if !h.Icon {
				delete(have, "icon") // another template names it by more than an image
			}
			continue
		}
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
		if h.Icon {
			row["icon"] = "1" // named by the hash of an image alone: a lead, not an identification
		}
		seen[k] = row
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
