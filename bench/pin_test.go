package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The Juice Shop the README starts, the labs CI starts and the bench measures
// are one image: the truth of the known routes is per build.
func TestJuiceShopImageIsPinnedTheSameEverywhere(t *testing.T) {
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	m := regexp.MustCompile(`image: (bkimminich/juice-shop:(v[\d.]+)@sha256:[0-9a-f]{64})`).FindStringSubmatch(read("compose.yaml"))
	if m == nil {
		t.Fatal("compose.yaml pins no juice-shop release and digest")
	}
	full, tag := m[1], m[2]
	if !strings.Contains(read("../.github/ci/labs.sh"), "docker run -d --name azq-juice") || !strings.Contains(read("../.github/ci/labs.sh"), " "+full+"\n") {
		t.Errorf(".github/ci/labs.sh does not start %s", full)
	}
	readme := read("../README.md")
	if !strings.Contains(readme, "docker run --rm -p 3000:3000 bkimminich/juice-shop:"+tag+"`") {
		t.Errorf("the README's quick start does not start bkimminich/juice-shop:%s", tag)
	}
	if !strings.Contains(readme, "Known routes of juice-shop "+tag+",") {
		t.Errorf("the README's table does not name the Juice Shop build %s", tag)
	}
	if !strings.Contains(readme, "go run ./bench -only apps -profile default") {
		t.Error("the README does not give the command that reproduces the table row")
	}
}
