package detect

import (
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/productname"
)

// iconFile says a path names an image: asking it names nothing but an icon.
func iconFile(p string) bool {
	p, _, _ = strings.Cut(strings.ToLower(p), "?")
	for _, ext := range []string{".ico", ".png", ".svg", ".gif", ".jpg", ".jpeg", ".webp"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// confirmPaths indexes the paths other than the root that a template written
// for one product asks, by the product's keys, in template order: the reads
// that name the product by something other than an icon.
func confirmPaths(units []*cunit) (out map[string][]string, order []string) {
	out = map[string][]string{}
	for _, cu := range units {
		u := cu.spec
		if cu.icon || u.Multi || u.Product == "" {
			continue
		}
		for _, p := range u.Paths {
			if p = requestPath(p); p == "/" || iconFile(p) {
				continue
			}
			for _, k := range productname.Keys(u.Product) {
				if _, ok := out[k]; !ok {
					order = append(order, k)
				}
				if !contains(out[k], p) {
					out[k] = append(out[k], p)
				}
			}
		}
	}
	return out, order
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// minRelated is the shortest product key another product's key may start
// with and still be about it: "springboot" for "springbootactuators".
const minRelated = 6

// Related says a template's product is the icon's product, or is written for
// a part of it (Spring Boot's actuators): the keys are one, or one starts with
// the other and is at least minRelated long.
func Related(a, b string) bool {
	for _, y := range productname.Keys(b) {
		if relatedKey(a, y) {
			return true
		}
	}
	return false
}

// ConfirmPaths are the paths, in template order, that a detection template
// written for a product related to this one asks to name it (not the root and
// not an image): a read of one that matches names the product by its own
// answer. None when no template is for it.
func ConfirmPaths(product string) []string {
	Load()
	var out []string
	for _, k := range engine.confirmKeys {
		if !relatedKey(product, k) {
			continue
		}
		for _, p := range engine.confirm[k] {
			if !contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

func relatedKey(product, key string) bool {
	for _, x := range productname.Keys(product) {
		if x == key || len(x) >= minRelated && strings.HasPrefix(key, x) || len(key) >= minRelated && strings.HasPrefix(x, key) {
			return true
		}
	}
	return false
}
