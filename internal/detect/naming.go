package detect

import "strings"

// noiseWords end a template title without being part of the product name.
// Longer phrases come first so "- Detect" goes before "Detect".
var noiseWords = []string{
	"- detect", "detection", "detect", "panel", "login", "page", "exposure",
	"exposed", "version", "fingerprint", "dashboard",
}

// Product turns a template title into a product name: trailing noise words
// are removed repeatedly (case-insensitive, whole words), along with stray
// dashes and spaces. A title that is only noise is returned unchanged.
func Product(title string) string {
	name := strings.TrimSpace(title)
	for {
		before := name
		name = strings.TrimRight(name, " -\t")
		lower := strings.ToLower(name)
		for _, w := range noiseWords {
			if !strings.HasSuffix(lower, w) {
				continue
			}
			cut := len(name) - len(w)
			if cut > 0 && !isBreak(name[cut-1]) {
				continue
			}
			name = name[:cut]
			break
		}
		name = strings.TrimRight(name, " -\t")
		if name == before {
			break
		}
	}
	// A title can lead with the noise too: "Detect Springboot Actuators".
	for _, lead := range []string{"detect ", "detection of ", "exposed "} {
		if len(name) > len(lead) && strings.EqualFold(name[:len(lead)], lead) {
			name = strings.TrimSpace(name[len(lead):])
		}
	}
	if name == "" {
		return strings.TrimSpace(title)
	}
	return name
}

func isBreak(c byte) bool { return c == ' ' || c == '-' || c == '\t' }

// Humanise makes a matcher name readable: "-" and "_" become spaces.
func Humanise(name string) string {
	return strings.TrimSpace(strings.NewReplacer("-", " ", "_", " ").Replace(name))
}

// MatcherNamed reports whether a template names its products through matcher
// names: an or-template with at least this many distinct matcher names is a
// shared detector (tech-detect, favicon-detect, a CMS plugin list) whose
// title is generic.
const MatcherNamed = 5
