package browser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A new profile is seeded with quiet preferences; one that exists is not
// touched.
func TestSeedProfile(t *testing.T) {
	dir := t.TempDir()
	if err := seedProfile(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "Default", "Preferences"))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("the seeded preferences are not JSON: %v", err)
	}
	kept := t.TempDir()
	if err := os.MkdirAll(filepath.Join(kept, "Default"), 0o700); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(kept, "Default", "Preferences")
	if err := os.WriteFile(own, []byte(`{"mine":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := seedProfile(kept); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(own); string(got) != `{"mine":1}` {
		t.Errorf("a user's profile was changed: %s", got)
	}
}
