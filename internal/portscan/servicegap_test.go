package portscan

import (
	"slices"
	"strings"
	"testing"
)

// The service ports a named set leaves out are what default asks and the set
// does not, read from default itself, so the two cannot drift.
func TestServiceGapIsWhatDefaultAddsToTheSet(t *testing.T) {
	for _, spec := range []string{"top-100", "top-1000"} {
		set, _ := Ports(spec)
		var want []int
		for _, p := range DefaultPorts() {
			if !slices.Contains(set, p) && slices.Contains(CatalogPorts(), p) {
				want = append(want, p)
			}
		}
		if got := ServiceGap(set, nil); !slices.Equal(got, want) || len(got) == 0 {
			t.Errorf("%s: gap %v, want %v", spec, got, want)
		}
	}
	all, _ := Ports("full")
	if got := ServiceGap(all, nil); len(got) != 0 {
		t.Errorf("every port asked leaves out %v", got)
	}
	top, _ := Ports("top-1000")
	if got := ServiceGap(top, []int{6379}); slices.Contains(got, 6379) {
		t.Error("a port the user kept out (-ep) is named as left out")
	}
}

func TestNarrowNameIsANamedSetNarrowerThanDefault(t *testing.T) {
	for spec, want := range map[string]bool{
		"top-1000": true, "TOP-100": true, "top100,8888": true, "top-100, 22": true,
		"22,80": false, "default": false, "top-1000,default": false, "full": false, "top-100,-": false, "none": false, "": false,
	} {
		if got := NarrowName(spec); got != want {
			t.Errorf("NarrowName(%q) = %v, want %v", spec, got, want)
		}
	}
}

func TestGapListNamesTheFirstFew(t *testing.T) {
	got := GapList([]int{6379, 9092, 31337})
	if got != "6379 redis, 9092 kafka, 31337" {
		t.Errorf("list %q", got)
	}
	many := make([]int, 20)
	for i := range many {
		many[i] = 6379 + i
	}
	if got := GapList(many); !strings.HasSuffix(got, ", and 12 more") || strings.Count(got, ",") != shownGap {
		t.Errorf("long list %q", got)
	}
	if got := QuietNote("-p", 1000, 1, 1, []int{6379}); got != "no port answered among the 1000 asked; -p default adds 1 service port (6379 redis)" {
		t.Errorf("quiet note %q", got)
	}
}
