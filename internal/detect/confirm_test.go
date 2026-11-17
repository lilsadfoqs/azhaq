package detect

import (
	"slices"
	"testing"
)

// The reads that name a product by its own answer: the paths of the templates
// written for it, never the root or an image.
func TestConfirmPathsAreTheProductsOwn(t *testing.T) {
	for _, name := range []string{"gitlab", "GitLab", "Gitlab"} {
		if got := ConfirmPaths(name); !slices.Contains(got, "/users/sign_in") {
			t.Errorf("%s: %v", name, got)
		}
	}
	for _, p := range ConfirmPaths("gitlab") {
		if p == "/" || iconFile(p) {
			t.Errorf("path %q is no read of the product", p)
		}
	}
	if got := ConfirmPaths("no such product"); got != nil {
		t.Errorf("paths of an unknown product: %v", got)
	}
}

// A product the icon names that templates are written for in parts (Spring
// Boot's actuators) is read by those: a related key, never a short prefix.
func TestConfirmPathsOfARelatedProduct(t *testing.T) {
	if got := ConfirmPaths("spring boot"); !slices.Contains(got, "/actuator") {
		t.Errorf("spring boot: %v", got)
	}
	if !Related("Springboot Actuators", "spring boot") || Related("Jira", "jiraservicedesk") || Related("Gitlab", "GitHub") {
		t.Errorf("related names are wrong")
	}
}
