package detect

import "strings"

// A hit whose only evidence is an icon's hash names a product by one image:
// a template build or a framework's default icon is shared by many sites.
// Icon marks it, for a reader to hold as a lead until a read of the product
// itself says the same.

// hashVal says a DSL value tests a hash of the body and nothing else of it.
func hashVal(v string) bool {
	if !strings.Contains(v, "mmh3(") && !strings.Contains(v, "md5(") {
		return false
	}
	for _, other := range []string{"contains", "regex", "header", "server", "title"} {
		if strings.Contains(v, other) {
			return false
		}
	}
	return true
}

// statusVal says a DSL value tests the status code and nothing else.
func statusVal(v string) bool {
	return strings.Contains(v, "status_code") && !strings.Contains(v, "body") && !hashVal(v)
}

// iconUnit says every way a unit can match is a hash of the body (with the
// status code, in an and-unit): its hit is the icon's, not the product's.
func iconUnit(u *Unit) bool {
	hashed := false
	for _, m := range u.Matchers {
		kind := ""
		switch {
		case m.Type == "status":
			kind = "status"
		case m.Type == "dsl" && len(m.Vals) > 0:
			kind = "hash"
			for _, v := range m.Vals {
				if hashVal(v) {
					continue
				}
				if statusVal(v) {
					kind = "status"
					continue
				}
				return false
			}
			if kind == "status" {
				for _, v := range m.Vals {
					if hashVal(v) {
						kind = "hash"
					}
				}
			}
		default:
			return false
		}
		if kind == "hash" {
			hashed = true
		} else if !u.And {
			return false // an or-unit with a status matcher matches on the status alone
		}
	}
	return hashed
}
