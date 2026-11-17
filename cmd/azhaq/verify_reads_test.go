package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

func namedServiceObs(port int, service string) []types.StoredObservation {
	raw, _ := json.Marshal(map[string]any{
		"host": "127.0.0.1", "ip": "127.0.0.1",
		"services": []map[string]any{{"port": port, "service": service}},
	})
	return []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: raw}}}
}

// A JDWP version and an RMI registry's names are each one read: one
// connection, one request counted against -max-requests, one probe line of
// the ledger that holds the bytes sent, one stored row.
func TestVerifyStageJDWPVersionAndRMINamesAreCountedAndLedgered(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	desc := "Java Debug Wire Protocol (Reference Implementation) version 17.0"
	data := []byte{0, 0, 0, byte(len(desc))}
	data = append(data, desc...)
	data = append(data, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 6)
	data = append(data, "17.0.9"...)
	data = append(data, 0, 0, 0, 3)
	data = append(data, "VM1"...)
	reply := append([]byte{0, 0, 0, byte(11 + len(data)), 0, 0, 0, 1, 0x80, 0, 0}, data...)
	jdwp := newRedisFixture(t, "JDWP-Handshake"+string(reply))

	ack := "4e 0009 3132372e302e302e31 00009c40"
	ret := "51 aced0005 770f01 25149521 0000012b169a625a 800b 7572 0013 5b4c6a6176612e6c616e672e537472696e673b add256e7e91d7b47 02 0000 7870 00000002 74 0006 6a6d78726d69 74 0003 616263"
	rmiBytes, err := hex.DecodeString(strings.Join(strings.Fields(ack+ret), ""))
	if err != nil {
		t.Fatal(err)
	}
	rmi := newRedisFixture(t, string(rmiBytes))

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ledPath := filepath.Join(dir, "ledger.jsonl")
	led, err := ledger.Open(ledPath)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(led)
	defer ledger.Use(nil)
	obs := append(namedServiceObs(jdwp.port, "jdwp"), namedServiceObs(rmi.port, "java-rmi")...)
	results, failures, note := verifyStage(context.Background(), st, obs, nil, "azhaq ports -verify")
	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	if len(failures) > 0 || len(results) != 2 {
		t.Fatalf("results %+v failures %v", results, failures)
	}
	byPort := map[int]verify.Result{}
	for _, r := range results {
		byPort[r.Port] = r
	}
	if r := byPort[jdwp.port]; r.Label != verify.Proved || r.Kind != verify.KindUnauthenticatedRead || !strings.Contains(r.Evidence, `VM version "17.0.9"`) {
		t.Errorf("jdwp: %+v", r)
	}
	if r := byPort[rmi.port]; r.Label != verify.Proved || r.Kind != verify.KindUnauthenticatedRead || !strings.Contains(r.Evidence, "2 bound names: jmxrmi, abc") {
		t.Errorf("rmi: %+v", r)
	}
	if len(jdwp.requests()) != 1 || len(rmi.requests()) != 1 {
		t.Errorf("connections: jdwp %d, rmi %d, want one each", len(jdwp.requests()), len(rmi.requests()))
	}
	if !strings.Contains(note, "2 results (2 proved,") {
		t.Errorf("note %q", note)
	}
	var tcp, probe int
	var sent string
	if err := ledger.Read(ledPath, func(e ledger.Entry) error {
		if e.Collector != "azhaq-verify" {
			return nil
		}
		switch e.Kind {
		case "tcp":
			tcp++
		case "probe":
			probe++
			if strings.Contains(e.Proto, "jdwp") {
				sent = e.Sent
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if tcp != 2 || probe != 2 || sent != hex.EncodeToString([]byte("JDWP-Handshake\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x01\x01")) {
		t.Errorf("ledger: %d tcp, %d probe lines, jdwp sent %q; want 2, 2 and the handshake and the command", tcp, probe, sent)
	}
	stored, _ := st.Observations()
	if got := verifyResultsOf(stored); len(got) != 2 {
		t.Errorf("stored %d results, want 2", len(got))
	}

	// The budget counts each as one request: one request of it, one read.
	egress.Reset()
	egress.Current().SetMaxRequests(1)
	results, failures, note = verifyStage(context.Background(), st, obs, nil, "azhaq ports -verify")
	if len(failures) > 0 || len(results) != 1 || !strings.Contains(note, "the run's limit stopped them") {
		t.Errorf("one request of budget: results %d failures %v note %q", len(results), failures, note)
	}
}
