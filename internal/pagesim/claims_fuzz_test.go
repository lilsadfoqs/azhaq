package pagesim

import (
	"fmt"
	"strings"
	"testing"
)

func pageWith(title string, words ...string) Page {
	return Of([]byte("<html><title>" + title + "</title><body>" + strings.Join(words, " ") + "</body></html>"))
}

func wordsN(prefix string, n int) []string {
	var w []string
	for i := 0; i < n; i++ {
		w = append(w, fmt.Sprintf("%sword%c", prefix, 'a'+i))
	}
	return w
}

// The page needs a title all answers share or at least 3 shared words.
func TestLearnNeedsATitleOrThreeSharedWords(t *testing.T) {
	two := []Page{Of([]byte("<p>alpha beta one</p>")), Of([]byte("<p>alpha beta two</p>"))}
	if _, ok := Learn(two); ok {
		t.Error("2 shared words and no title made a shape")
	}
	three := []Page{Of([]byte("<p>alpha beta gamma one</p>")), Of([]byte("<p>alpha beta gamma two</p>"))}
	if _, ok := Learn(three); !ok {
		t.Error("3 shared words did not make a shape")
	}
	titled := []Page{pageWith("Same", "alpha"), pageWith("Same", "beta")}
	if _, ok := Learn(titled); !ok {
		t.Error("a shared title did not make a shape")
	}
	if _, ok := Learn([]Page{pageWith("One", "alpha"), pageWith("Two", "beta")}); ok {
		t.Error("two titles and no shared word made a shape")
	}
}

// A page is held back when it has the same title, only those tags and at
// least 80% of the words all the answers show.
func TestShapeLikeNeedsTheTitleTheTagsAndEightyPercentOfTheWords(t *testing.T) {
	shared := wordsN("", 9) // with the word of the title, 10 words every page shows
	s, ok := Learn([]Page{pageWith("Console", append(wordsN("x", 4), shared...)...), pageWith("Console", append(wordsN("y", 4), shared...)...)})
	if !ok || len(s.Stable) != 10 {
		t.Fatalf("learned %v, %d stable words", ok, len(s.Stable))
	}
	for _, c := range []struct {
		name string
		page Page
		like bool
	}{
		{"all of the words", pageWith("Console", append(wordsN("z", 4), shared...)...), true},
		{"8 of 10 words (80%)", pageWith("Console", append(wordsN("z", 4), shared[:7]...)...), true},
		{"7 of 10 words", pageWith("Console", append(wordsN("z", 4), shared[:6]...)...), false},
		{"another title", pageWith("Admin", shared...), false},
		{"a tag the answers lack", Of([]byte("<html><title>Console</title><body><form>" + strings.Join(shared, " ") + "</form></body></html>")), false},
	} {
		if got := s.Like(c.page); got != c.like {
			t.Errorf("%s: like %v, want %v", c.name, got, c.like)
		}
	}
}
