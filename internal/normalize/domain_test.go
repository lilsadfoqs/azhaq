package normalize

import (
	"strings"
	"testing"
)

func TestRegistrableDomain(t *testing.T) {
	if g := RegistrableDomain("www.example.com"); g != "example.com" {
		t.Fatalf("got %q", g)
	}
	if g := RegistrableDomain("127.0.0.1"); g != "" {
		t.Fatalf("ip -> %q", g)
	}
}

func TestSpecialUse(t *testing.T) {
	if !SpecialUse("example.test") || !SpecialUse("foo.localhost") || !SpecialUse("x.invalid") {
		t.Fatal("reserved TLD")
	}
	if SpecialUse("example.com") || SpecialUse("127.0.0.1") || SpecialUse("") {
		t.Fatal("public or IP")
	}
}

func TestAppspotTenantsAreNotSameSite(t *testing.T) {
	if RegistrableDomain("public-firing-range.appspot.com") != "public-firing-range.appspot.com" {
		t.Fatalf("tenant %q", RegistrableDomain("public-firing-range.appspot.com"))
	}
	if SameSite("public-firing-range.appspot.com", "other.appspot.com") {
		t.Fatal("PaaS siblings must not share a site")
	}
	if RegistrableDomain("appspot.com") != "" {
		t.Fatal("platform suffix is not a tenant")
	}
}

func TestSameSite(t *testing.T) {
	if !SameSite("challs.test.brunnerne.xyz", "php.challs.brunnerne.xyz") {
		t.Fatal("same eTLD+1")
	}
	if SameSite("challs.test.brunnerne.xyz", "dead.traefik.default") {
		t.Fatal("default cert SAN is not same site")
	}
	if SameSite("challs.test.brunnerne.xyz", "other.test") {
		t.Fatal("other site")
	}
}

// The embedded root-zone list is a dated copy of IANA's: a refresh with
// scripts/tldgen changes this pin on purpose.
func TestRootListIsPinned(t *testing.T) {
	if v := RootListVersion(); !strings.HasPrefix(v, "Version 2026111600, Last Updated Mon Nov 16 07:07:02 2026 UTC") {
		t.Fatalf("list header %q", v)
	}
	if n := len(rootTLDs); n < 1400 {
		t.Fatalf("%d TLDs", n)
	}
}

func TestDelegated(t *testing.T) {
	for host, want := range map[string]bool{
		"example.com": true, "a.b.COM.": true, "x.web": true, "x.dev": true, "pool.ntp.org": true,
		"example.рф": true, "example.xn--p1ai": true, "x.arpa": true, "1.0.0.127.in-addr.arpa": true,
		"nas.lan": false, "a.internal": false, "corp": false, "x.home.arpa.corp": false,
		"x.local": false, "x.test": false, "x.localhost": false, "x.example": false, "x.invalid": false,
		"127.0.0.1": false, "": false, ".": false,
	} {
		if got := Delegated(host); got != want {
			t.Errorf("Delegated(%q) = %v, want %v", host, got, want)
		}
	}
}
