package main

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// A UDP probe is a datagram, a TCP connect a connection: the ledger note, the
// cost and the summary's requests name each as what it is, and the parts add
// up to the requests (#219).
func TestPortsCountUDPAsDatagramsAndTCPAsConnections(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	gone, _ := net.ListenPacket("udp", "127.0.0.1:0")
	gonePort := gone.LocalAddr().(*net.UDPAddr).Port
	gone.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	pu := fmt.Sprintf("%d,%d", pc.LocalAddr().(*net.UDPAddr).Port, gonePort)
	tcp := fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
	for _, c := range []struct {
		name            string
		p               string
		conns, datagram float64
		note            string
	}{
		{"udp only", "none", 0, 2, "(0 requests, 0 connections, 2 UDP datagrams)"},
		{"tcp and udp", tcp, 1, 2, "(0 requests, 1 connection, 2 UDP datagrams)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", c.p, "-pu", pu, "-detect", "none", "-connect-timeout", "200ms",
				"-db", filepath.Join(t.TempDir(), "d.db"), "-json")
			sum := sumMap(t, errOut)
			notes := fmt.Sprint(sum["notes"])
			stage := stagesOf(t, sum)["ports"]
			conns, dgrams := stageAmount(stage, "actual", "connects"), stageAmount(stage, "actual", "datagrams")
			if code != exitOK || conns != c.conns || dgrams != c.datagram {
				t.Errorf("exit %d: the run made %v connects and %v datagrams, want %v and %v (%v)", code, conns, dgrams, c.conns, c.datagram, stage["actual"])
			}
			if !strings.Contains(notes, c.note) {
				t.Errorf("the ledger note lacks %q: %s", c.note, notes)
			}
			if got := sum["requests"]; got != conns+dgrams {
				t.Errorf("requests %v, connects %v and datagrams %v do not add up", got, conns, dgrams)
			}
			if e := stageAmount(stage, "estimate", "connects") + stageAmount(stage, "estimate", "datagrams"); e != conns+dgrams {
				t.Errorf("the estimate says %v, the run sent %v", e, conns+dgrams)
			}
			if est := stageAmount(stage, "estimate", "datagrams"); est != c.datagram {
				t.Errorf("the estimate says %v datagrams, the run sent %v", est, c.datagram)
			}
		})
	}
}
