package scope

import (
	"reflect"
	"testing"
)

func TestTargetPorts(t *testing.T) {
	for _, c := range []struct {
		name       string
		urls, bare []string
		want       map[string]map[string]bool
	}{
		{"a port", []string{"http://127.0.0.1:3001/"}, nil, map[string]map[string]bool{"127.0.0.1": {"3001": true}}},
		{"http default", []string{"http://h.test/"}, nil, map[string]map[string]bool{"h.test": {"80": true, "443": true}}},
		{"https default", []string{"https://h.test/x"}, nil, map[string]map[string]bool{"h.test": {"80": true, "443": true}}},
		{"default written out", []string{"http://h.test:80/"}, nil, map[string]map[string]bool{"h.test": {"80": true, "443": true}}},
		{"https on 8443", []string{"https://h.test:8443/"}, nil, map[string]map[string]bool{"h.test": {"8443": true}}},
		{"two ports of a host", []string{"http://h.test:81/", "http://h.test:82/"}, nil, map[string]map[string]bool{"h.test": {"81": true, "82": true}}},
		{"a port and the default", []string{"http://h.test:81/", "https://h.test/"}, nil, map[string]map[string]bool{"h.test": {"81": true, "80": true, "443": true}}},
		{"an address of IPv6", []string{"http://[::1]:3000/"}, nil, map[string]map[string]bool{"::1": {"3000": true}}},
		{"a bare name", []string{"http://h.test:81/"}, []string{"h.test"}, map[string]map[string]bool{}},
		{"a bare domain covers its names", []string{"http://a.h.test:81/"}, []string{"h.test"}, map[string]map[string]bool{}},
		{"a bare range covers its addresses", []string{"http://10.0.0.5:81/"}, []string{"10.0.0.0/24"}, map[string]map[string]bool{}},
		{"another bare name", []string{"http://h.test:81/"}, []string{"g.test"}, map[string]map[string]bool{"h.test": {"81": true}}},
	} {
		if got := TargetPorts(c.urls, c.bare); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
