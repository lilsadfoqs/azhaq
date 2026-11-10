package main

import "testing"

// The bench counts on neither side a hit of ffuf's that azhaq holds back by
// default, and only such a hit.
func TestHeldBackIsAzhaqsStateChangeRule(t *testing.T) {
	for u, want := range map[string]bool{
		"http://127.0.0.1:5102/createdb": true,
		"http://127.0.0.1:3101/logout":   true,
		"http://127.0.0.1:3101/ftp":      false,
		"http://127.0.0.1:3101/api":      false,
	} {
		if got := heldBack(u); got != want {
			t.Errorf("heldBack(%q) = %v, want %v", u, got, want)
		}
	}
}
