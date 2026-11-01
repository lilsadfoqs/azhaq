package main

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

// The expressions that compile on first use are all valid: one that is not
// would panic in the middle of a run, not at start.
func TestLazyRegexpsCompile(t *testing.T) {
	if err := lazyre.CompileAll(); err != nil {
		t.Fatal(err)
	}
}
