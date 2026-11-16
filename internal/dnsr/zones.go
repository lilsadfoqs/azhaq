package dnsr

import (
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/normalize"
)

// HeldZone says name is in a zone no public resolver can answer: its
// top-level domain is not in the root zone (.internal, .lan, .corp, ...) or
// it is under home.arpa (normalize.Undelegated). Asking the default
// resolvers only tells them the name. Reverse names are LocalReverse's; an
// address and an empty name are not held.
func HeldZone(name string) bool {
	h := normalize.Hostname(name)
	if strings.HasSuffix(h, ".in-addr.arpa") || strings.HasSuffix(h, ".ip6.arpa") {
		return false
	}
	return normalize.Undelegated(h)
}
