package portscan

import (
	"bytes"
	"context"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A port of 9100 to 9107 (raw printing: a byte sent there prints) is
// connected to once and asked nothing, where a silent port elsewhere is
// asked the ladder.
func TestRawPrintingPortsAreNeverAsked(t *testing.T) {
	for p, want := range map[int]bool{9099: false, 9100: true, 9104: true, 9107: true, 9108: false} {
		if got := rawData(p); got != want {
			t.Errorf("rawData(%d) = %v", p, got)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:9100")
	if err != nil {
		t.Skipf("port 9100 is taken: %v", err)
	}
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() { time.Sleep(300 * time.Millisecond); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	s := &Scanner{Workers: 1, Banner: 20 * time.Millisecond, Timeout: 50 * time.Millisecond}
	r, err := s.ScanEach(t.Context(), "", "127.0.0.1", []int{9100})
	if err != nil || len(r.Open) != 1 {
		t.Fatalf("%v %+v", err, r)
	}
	time.Sleep(400 * time.Millisecond)
	if n := accepted.Load(); n != 1 {
		t.Errorf("port 9100 was connected to %d times: the scan's connect only was wanted", n)
	}
}

// The silent ports are asked again once when at most 64 or a tenth of the
// scan did not answer, never when more; -retries N makes N more passes, and
// a negative value (-retries 0 on the command line) none.
func TestAgainRule(t *testing.T) {
	for _, c := range []struct {
		retries, try, silent, ports int
		want                        bool
	}{
		{0, 0, 1, 1, true}, {0, 0, 64, 65535, true}, {0, 0, 65, 100, false}, {0, 0, 100, 1000, true}, {0, 0, 101, 1000, false},
		{0, 1, 1, 100, false},
		{-1, 0, 1, 100, false},
		{3, 0, 5000, 5000, true}, {3, 2, 5000, 5000, true}, {3, 3, 5000, 5000, false},
	} {
		s := &Scanner{Retries: c.retries}
		if got := s.again(c.try, c.silent, c.ports); got != c.want {
			t.Errorf("Retries %d, pass %d, %d silent of %d: again = %v, want %v", c.retries, c.try, c.silent, c.ports, got, c.want)
		}
	}
}

// The connects go out in batches of rate/500 up to 32 from a rate of 1,000,
// one at a time below it.
func TestBatchFollowsTheRate(t *testing.T) {
	for rate, want := range map[float64]int{1: 1, 500: 1, 999: 1, 1000: 2, 10000: 20, 16000: 32, 1e6: 32} {
		if got := (&Scanner{Rate: rate}).batch(); got != want {
			t.Errorf("batch at rate %v = %d, want %d", rate, got, want)
		}
	}
}

// The wait before the pass over the silent ports is a connect timeout, at
// most 3 s.
func TestSettleWaitsOneConnectTimeoutAtMostThreeSeconds(t *testing.T) {
	for timeout, want := range map[time.Duration]time.Duration{100 * time.Millisecond: 100 * time.Millisecond, 10 * time.Second: 3 * time.Second} {
		t0 := time.Now()
		if err := (&Scanner{Timeout: timeout}).settle(context.Background()); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(t0); d < want-20*time.Millisecond || d > want+400*time.Millisecond {
			t.Errorf("a connect timeout of %v waited %v, want %v", timeout, d, want)
		}
	}
}

// Every request the ladder can send is one the page calls harmless: text
// requests name no login, credential or write, the MQTT CONNECT carries no
// user name or password, and the LDAP request is an anonymous search.
func TestEveryRequestOfTheLadderIsHarmless(t *testing.T) {
	deny := regexp.MustCompile(`(?i)\b(USER|PASS|AUTH|LOGIN|PASSWORD|SELECT|INSERT|UPDATE|DELETE|DROP|PUT|POST|SET|APPEND|STORE|QUIT_|EVAL|FLUSHALL|CONFIG|SLAVEOF|SHUTDOWN)\b`)
	n := 0
	for _, p := range protocols {
		if p.request == nil {
			continue
		}
		n++
		req := p.request(target{host: "h.test", port: 1})
		if len(req) == 0 {
			t.Errorf("%s: an empty request", p.name)
		}
		text := string(bytes.Map(func(r rune) rune {
			if r < 32 && r != '\r' && r != '\n' || r > 126 {
				return ' '
			}
			return r
		}, req))
		// finger's query names a user that does not exist, on purpose.
		if m := deny.FindString(strings.ReplaceAll(text, "azhaq-no-such-user", "")); m != "" {
			t.Errorf("%s: the request %q has %q in it", p.name, text, m)
		}
	}
	if n < 20 {
		t.Fatalf("only %d protocols have a request", n)
	}
	mq := mqttConnect()
	if flags := mq[2+2+4+1]; flags&0xc0 != 0 { // after the length, the name "MQTT" and the level
		t.Errorf("MQTT CONNECT flags %08b: a user name or password is sent", flags)
	}
}

// A port that greeted is asked nothing by default, but for the SYST and
// EHLO that -detect all sends to a greeting that names no product; a port
// that said nothing is asked.
func TestAGreetingIsNotAnsweredWithARequestExceptSYSTAndEHLO(t *testing.T) {
	received := func(greeting string, detect Detect) string {
		var mu sync.Mutex
		var got bytes.Buffer
		port := listen(t, func(c net.Conn) {
			c.Write([]byte(greeting))
			c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 256)
			for {
				n, err := c.Read(buf)
				mu.Lock()
				got.Write(buf[:n])
				mu.Unlock()
				if err != nil {
					return
				}
				c.Write([]byte("500 no\r\n"))
			}
		})
		s := &Scanner{Detect: detect, Banner: 150 * time.Millisecond, Timeout: time.Second}
		if _, err := s.ScanEach(t.Context(), "", "127.0.0.1", []int{port}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(700 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		return got.String()
	}
	if got := received("SSH-2.0-OpenSSH_9.6\r\n", DetectAll); got != "" {
		t.Errorf("an SSH greeting was answered with %q", got)
	}
	if got := received("220 hello\r\n", DetectAll); !strings.Contains(got, "EHLO") || !strings.Contains(got, "SYST") {
		t.Errorf("-detect all sent %q to a bare 220 greeting, want EHLO and SYST", got)
	}
	if got := received("220 hello\r\n", DetectBanner); got != "" {
		t.Errorf("-detect banner sent %q", got)
	}
}

// The wait for a greeting that came late is six seconds by default: twice
// the connect and banner wait.
func TestLateGreetingWaitIsSixSecondsByDefault(t *testing.T) {
	s := &Scanner{}
	s.init()
	if got := s.lateGreeting(); got != 6*time.Second {
		t.Errorf("late greeting wait %v, want 6s", got)
	}
	s = &Scanner{Timeout: time.Second, Banner: 500 * time.Millisecond}
	if got := s.lateGreeting(); got != 3*time.Second {
		t.Errorf("late greeting wait %v with a 1 s connect and 0.5 s banner wait, want twice their sum", got)
	}
}

// A port with a protocol of its own, in the page's list, is asked its request
// and then one more: two datagrams when it stays silent; any other port,
// among the 25 common ones too, is asked a DNS query, an SNMP get,
// memcached's version and an empty datagram: four. With -detect none each
// port has one.
func TestUDPPortsAreAskedTheRequestsThePageGives(t *testing.T) {
	own := []int{53, 123, 161, 1900, 5353, 137, 500, 4500, 3478, 11211, 47808, 5683, 69, 111, 1434, 5060, 5351, 10001, 623}
	s := &Scanner{}
	for _, p := range own {
		if n := s.payloads(p); n != 2 {
			t.Errorf("port %d has %d requests, want 2", p, n)
		}
	}
	for _, p := range []int{67, 514, 520, 1194, 27015, 51820, 5354, 5555, 8053, 10161} {
		if n := s.payloads(p); n != 4 {
			t.Errorf("port %d has %d requests, want 4: a DNS query, an SNMP get, memcached's version, an empty datagram", p, n)
		}
	}
	none := &Scanner{Detect: DetectNone}
	for _, p := range append(own, 5555) {
		if n := none.payloads(p); n != 1 {
			t.Errorf("-detect none: port %d has %d requests, want 1", p, n)
		}
	}
	if r, _ := none.udpReqFor(161, 0); len(r.payload) == 0 {
		t.Error("-detect none asks 161 nothing")
	}
}

// UDP scans of a range run on as many addresses at once as the rate keeps
// busy: 23 at the default rate and timeout.
func TestUDPHostsAtOnceFollowTheRateAndTheTimeout(t *testing.T) {
	if got := (&Scanner{}).UDPHosts(); got != 23 {
		t.Errorf("%d addresses at once at the default rate, want 23", got)
	}
	if got := (&Scanner{Rate: 1000, Timeout: time.Second}).UDPHosts(); got != 10 {
		t.Errorf("%d addresses at once at 1,000 a second and a 1 s timeout, want 10", got)
	}
	if got := (&Scanner{Rate: 1, Timeout: time.Second}).UDPHosts(); got != 1 {
		t.Errorf("%d at the lowest rate, want 1", got)
	}
}

// A host that refuses with ICMP and is silent on up to 80 ports is asked
// those again one at a time, on a non-loopback address only.
func TestUDPSilentPortsArePacedOnlyOffTheLoopbackAndUpToEighty(t *testing.T) {
	if icmpPaceMax != 80 {
		t.Errorf("silent ports asked at the ICMP pace: up to %d, want 80", icmpPaceMax)
	}
	if !isLoopback("127.0.0.1") || isLoopback("192.0.2.1") {
		t.Error("isLoopback is wrong")
	}
	quiet, _ := udpListener(t, nil)
	closed := closedUDPPort(t)
	s := &Scanner{Timeout: 100 * time.Millisecond, Detect: DetectNone}
	t0 := time.Now()
	r, err := s.ScanUDP(context.Background(), "", "127.0.0.1", []int{quiet, closed})
	if err != nil || r.Closed != 1 || len(r.OpenFiltered) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if d := time.Since(t0); d > icmpGap {
		t.Errorf("a loopback address was asked at the ICMP pace: %v", d)
	}
}

// After N open ports of one address that no request could name, the other
// silent ports are not asked the whole list; N is -unnamed, six when it is not
// given (TestLadderLimit), and -1 means no limit.
func TestUnnamedLimitFollowsUnnamed(t *testing.T) {
	var ports []int
	for i := 0; i < 4; i++ {
		ports = append(ports, listen(t, func(c net.Conn) { time.Sleep(600 * time.Millisecond) }))
	}
	for unnamed, want := range map[int]int{1: 3, 2: 2, -1: 0} {
		s := &Scanner{Workers: 1, Banner: 20 * time.Millisecond, Timeout: 20 * time.Millisecond, Unnamed: unnamed}
		r, err := s.ScanEach(context.Background(), "", "127.0.0.1", ports)
		if err != nil || len(r.Open) != len(ports) || r.Unprobed != want {
			t.Errorf("-unnamed %d: %d open, %d left unprobed (%v), want %d", unnamed, len(r.Open), r.Unprobed, err, want)
		}
	}
}

// Every datagram a UDP scan can send is a read: an SNMP GET (never a SET), a
// TFTP read request (never a write), and no text request names a write or a
// login.
func TestEveryUDPDatagramIsARead(t *testing.T) {
	deny := regexp.MustCompile(`(?i)\b(SET|PUT|POST|DELETE|WRITE|LOGIN|USER|PASS|AUTH|REGISTER|SUBSCRIBE|NOTIFY)\b`)
	seen := map[string]bool{}
	for port := 1; port <= 65535; port++ {
		for pass := 0; pass < 5; pass++ {
			req, ok := udpAsk(port, pass)
			if !ok || len(req.payload) == 0 || seen[string(req.payload)] {
				continue
			}
			seen[string(req.payload)] = true
			p := req.payload
			switch {
			case p[0] == 0x30 && bytes.Contains(p, []byte("public")): // SNMPv1/v2c: the PDU is a GetRequest (0xa0)
				if pdu := p[7+int(p[6])]; pdu != 0xa0 { // after the version and the community string
					t.Errorf("port %d: the SNMP PDU is %#x, a GetRequest is 0xa0: % x", port, pdu, p)
				}
			case port == 69:
				if p[0] != 0 || p[1] != 1 {
					t.Errorf("port 69: opcode % x, want a read request (1)", p[:2])
				}
			case bytes.IndexFunc(p, func(r rune) bool { return r < 9 || r > 126 }) < 0:
				if m := deny.FindString(string(p)); m != "" {
					t.Errorf("port %d: the request %q has %q in it", port, p, m)
				}
			}
		}
	}
	if len(seen) < 15 {
		t.Fatalf("only %d distinct requests were looked at", len(seen))
	}
}
