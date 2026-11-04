package targets

import (
	"slices"
	"strings"
	"testing"
)

const scanWithAFilteredPort = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="8080"><state state="filtered"/><service name="http-proxy"/></port>
<port protocol="tcp" portid="9000"><state state="closed"/><service name="cslistener"/></port>
<port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
</ports></host></nmaprun>`

// Only the open TCP ports of the file are taken; -open-only=false also takes
// the ports nmap did not find open. A port nmap named a web service keeps its
// scheme, any other is a bare host:port to try over https, then http.
func TestNmapTakesOpenTCPPortsAndOpenOnlyFalseAddsTheRest(t *testing.T) {
	got, guessed, err := NmapXMLGuessed(strings.NewReader(scanWithAFilteredPort), Options{OpenOnly: true})
	if err != nil || !slices.Equal(got, []string{"192.0.2.5:22"}) || !guessed["192.0.2.5:22"] {
		t.Errorf("open ports: %v %v %v", got, guessed, err)
	}
	got, guessed, _ = NmapXMLGuessed(strings.NewReader(scanWithAFilteredPort), Options{OpenOnly: false})
	want := []string{"192.0.2.5:22", "http://192.0.2.5:8080/", "192.0.2.5:9000"}
	if !slices.Equal(got, want) || guessed["http://192.0.2.5:8080/"] || !guessed["192.0.2.5:9000"] {
		t.Errorf("-open-only=false: %v, guessed %v, want %v with only the ports nmap did not name http guessed", got, guessed, want)
	}
	// A bare host:port is tried over https, then http.
	if got := Expand([]string{"192.0.2.5:9000"}, nil, false, false); len(got) != 1 || got[0] != "192.0.2.5:9000" {
		t.Errorf("a bare host:port is left for both schemes: %v", got)
	}
}
