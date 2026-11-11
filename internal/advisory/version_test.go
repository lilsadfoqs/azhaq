package advisory

import "testing"

// The forms a banner and an advisory's boundary write a version in.
func TestCompareUsualForms(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.4.49", "2.4.50", -1},
		{"2.4.49", "2.4.5", 1}, // by value, not as text
		{"2.4.49", "2.4.49", 0},
		{"9.0.30", "9.0.31", -1},
		{"9.0.30", "9.0.4", 1},
		{"5.17.3", "5.17.6", -1},
		{"5.17.10", "5.17.6", 1},
		{"5.17.3", "5.18.0", -1},
		{"1.10.0-rc1", "1.10.0", -1},
		{"1.10.0-rc1", "1.9.9", 1},
		{"1.10.0-rc1", "1.10.0-rc2", -1},
		{"1.10.0-rc.1", "1.10.0-rc.10", -1},
		{"1.10.0-rc1", "1.10.0-beta2", 1},
		{"1.10.0-alpha", "1.10.0-beta", -1},
		{"2.0.0-SNAPSHOT", "2.0.0", -1},
		{"8.0.0.Final", "8.0.0", 0},
		{"8.0.0.Final", "8.0.1", -1},
		{"8.0.1.Final", "8.0.0", 1},
		{"3.2.1.RELEASE", "3.2.1", 0},
		{"3.2.1.GA", "3.2.0", 1},
		{"1.0.0-final", "1.0.0", 0},
		{"9.0.0.M1", "9.0.0", -1},
		{"9.0.0.M2", "9.0.0.M10", -1},
		{"9.0.0.M9", "9.0.0.RC1", -1},
		{"9.0.0.RC1", "9.0.0", -1},
		{"9.0.0-M1", "9.0.0.M1", 0},
		{"2.0.0.Beta1", "2.0.0.Beta2", -1},
		{"2.0.0.Beta2", "2.0.0", -1},
		{"8.2p1", "8.2-p1", 0},
		{"8.2p1", "8.2", 1},
		{"9.6p1", "9.8p1", -1},
		{"1:2.4.25-3ubuntu1", "1:2.4.25-3", 1},
		{"v1.18.0", "1.18.0", 0},
		{"2023.11.3", "2023.11.4", -1},
		{"2.426.2", "2.442", -1},
		{"12.2.1.3.0", "12.2.1.4.0", -1},
	}
	for _, c := range cases {
		got, ok := Compare(c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("Compare(%q,%q) = %d,%v want %d", c.a, c.b, got, ok, c.want)
		}
		if rev, _ := Compare(c.b, c.a); rev != -c.want {
			t.Errorf("Compare(%q,%q) = %d, reverse of %d", c.b, c.a, rev, c.want)
		}
	}
}

// A comparison that would be a guess is not made.
func TestCompareRefusesAGuess(t *testing.T) {
	for _, v := range []string{"", "unknown", "latest", "14 - 17", "1.0 2.0"} {
		if _, ok := Compare(v, "1.0.0"); ok {
			t.Errorf("Compare(%q) made", v)
		}
	}
}

// A range closed by its last affected version excludes a version before
// its start (the old walk said it was in).
func TestLastAffectedRangeKeepsAVersionBeforeItsStartOut(t *testing.T) {
	aff := Affected{Package: Package{Name: "p"}, Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "1.0"}, {LastAffected: "2.0"}}}}}
	for _, c := range []struct {
		v    string
		want state
	}{{"0.5", stateOut}, {"1.0", stateIn}, {"1.5", stateIn}, {"2.0", stateIn}, {"2.0.1", stateOut}} {
		if got, _, _ := evalAffected(aff, c.v); got != c.want {
			t.Errorf("version %s: %v, want %v", c.v, got, c.want)
		}
	}
}

// A listed version is the same release however it is written.
func TestListedVersionsAreComparedAsVersions(t *testing.T) {
	aff := Affected{Package: Package{Name: "p"}, Versions: []string{"8.2-p1", "9.0.0-milestone1"}}
	for _, v := range []string{"8.2p1", "8.2-p1", "9.0.0.M1"} {
		if got, _, _ := evalAffected(aff, v); got != stateIn {
			t.Errorf("%s not found in the listed versions", v)
		}
	}
	if got, _, _ := evalAffected(aff, "8.2p2"); got != stateOut {
		t.Error("8.2p2 is not a listed version")
	}
}
