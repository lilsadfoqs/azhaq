package portscan

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// Row is the payload of a "ports" observation: what the azhaq-ports collector
// writes, and what the readers (map, watch, ports, findings, advisories) decode.
// Every key the writer can emit is a field here, so a reader sees which fields
// a row has and a new key fails the contract tests until it is added.
//
// Which fields a row has depends on its kind:
//
//   - Address row (a name's, an address's): Host, IP, Scanned, Open, and when
//     they apply Up, Services, Filtered, FilteredPorts, Threshold, CDN, Note,
//     Unprobed, PortsOutsideScope, Unrouted and the UDP fields. A name's rows
//     have Host as the name and IP as the address; an address given alone has
//     Host equal to IP.
//   - Address of a range: an address row under the range's entity, with Host
//     equal to IP and Prefix set. A silent-only row (UDPSilentOnly) has only
//     Host, IP, Prefix, UDPScanned and UDPOpenFiltered.
//   - Name with no address to scan: Host, Scanned 0, Open [] and one of
//     Unresolved or Unrouted. It has no IP.
//   - Range row: Range true and Prefix, with Addresses, Scanned, Open [] and the
//     block's counts (WithOpen, Down, OutsideScope and the rest). A range a limit
//     stopped has Stopped, Swept and AddressesOf, and Checkpoint when it is the
//     one kept while the block goes. It has no Host or IP.
//   - Partial row (a scan a limit stopped, or a checkpoint kept while it goes):
//     an address row with Partial and Asked, Checkpoint for the latter, and
//     Pass and PortsLeft when the default scan has two passes.
//   - Imported scan (another collector's "ports" rows, as naabu or nmap give
//     them): Host, IP, Services or UDPServices, Via, and Names. Open may then
//     list the ports as strings.
type Row struct {
	Host string `json:"host,omitempty"`
	IP   string `json:"ip,omitempty"`

	// The names an imported scan knew the address by, and the tool that listed its ports.
	Names       []string `json:"names,omitempty"`
	Via         string   `json:"via,omitempty"`
	HostScripts []Script `json:"host_scripts,omitempty"` // an nmap scan's output for the host

	Scanned int         `json:"scanned,omitempty"`
	Open    PortNumbers `json:"open,omitempty"`
	// Up is nil when no discovery ran: absent is not down.
	Up            *bool    `json:"up,omitempty"`
	Services      []Open   `json:"services,omitempty"`
	Filtered      int      `json:"filtered,omitempty"`
	FilteredPorts []int    `json:"filtered_ports,omitempty"`
	Threshold     bool     `json:"threshold,omitempty"`
	CDN           string   `json:"cdn,omitempty"`
	Note          string   `json:"note,omitempty"`
	Unprobed      int      `json:"unprobed,omitempty"`
	Unresolved    string   `json:"unresolved,omitempty"`
	Unrouted      []string `json:"ipv6_not_scanned,omitempty"`
	// PortsOutsideScope counts ports left out because -allow names the host with another port only.
	PortsOutsideScope int `json:"ports_outside_scope,omitempty"`

	// A scan a limit stopped (Partial), and the checkpoint kept while it goes.
	Partial    bool   `json:"partial,omitempty"`
	Asked      string `json:"asked_ports,omitempty"` // Compact list of the ports asked
	Checkpoint bool   `json:"checkpoint,omitempty"`
	Pass       int    `json:"pass,omitempty"`
	PortsLeft  int    `json:"ports_left,omitempty"`
	Prefix     string `json:"prefix,omitempty"`

	UDPScanned      int       `json:"udp_scanned,omitempty"`
	UDPOpen         []int     `json:"udp_open,omitempty"`
	UDPOpenFiltered []int     `json:"udp_open_filtered,omitempty"`
	UDPClosed       int       `json:"udp_closed,omitempty"`
	UDPClosedPorts  []int     `json:"udp_closed_ports,omitempty"`
	UDPLimited      int       `json:"udp_limited,omitempty"`
	UDPServices     []UDPPort `json:"udp_services,omitempty"`
	UDPUnlisted     int       `json:"udp_unlisted,omitempty"`
	// What a stopped UDP scan settled: the refused ports (Compact), the requests
	// each undecided port was asked (requests: Compact ports), and how many ports
	// were asked some requests or none.
	UDPRefused    string            `json:"udp_refused,omitempty"`
	UDPAsked      map[string]string `json:"udp_asked,omitempty"`
	UDPUnfinished int               `json:"udp_unfinished,omitempty"`
	UDPUnasked    int               `json:"udp_unasked,omitempty"`
	UDPOneRequest bool              `json:"udp_one_request,omitempty"`
	UDPSilentOnly bool              `json:"udp_silent_only,omitempty"`

	// A range's row.
	Range                      bool   `json:"range,omitempty"`
	Stopped                    bool   `json:"stopped,omitempty"`
	Swept                      string `json:"swept,omitempty"` // Compact places of the addresses a stopped block finished
	Addresses                  int    `json:"addresses,omitempty"`
	AddressesOf                int    `json:"addresses_of,omitempty"`
	WithOpen                   int    `json:"with_open,omitempty"`
	Down                       int    `json:"down,omitempty"`
	OutsideScope               int    `json:"outside_scope,omitempty"`
	FilteredAddresses          int    `json:"filtered_addresses,omitempty"`
	CDNAddresses               int    `json:"cdn_addresses,omitempty"`
	UDPSilentPorts             int    `json:"udp_silent_ports,omitempty"`
	UDPSilentAddresses         int    `json:"udp_silent_addresses,omitempty"`
	UDPClosedN                 int    `json:"udp_closed_n,omitempty"`
	UDPClosedA                 int    `json:"udp_closed_a,omitempty"`
	PortsOutsideScopeAddresses int    `json:"ports_outside_scope_addresses,omitempty"`
}

// PortNumbers is a list of port numbers. Rows imported from naabu list them as
// strings ("open":["80"]), which it reads as well.
type PortNumbers []int

func (p *PortNumbers) UnmarshalJSON(b []byte) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		*p = nil
		return nil
	}
	var nums []int
	err := json.Unmarshal(b, &nums)
	if err == nil {
		*p = nums
		return nil
	}
	var strs []string
	if json.Unmarshal(b, &strs) != nil {
		return err
	}
	nums = make([]int, 0, len(strs))
	for _, s := range strs {
		n, aerr := strconv.Atoi(s)
		if aerr != nil {
			return err
		}
		nums = append(nums, n)
	}
	*p = nums
	return nil
}

// ParseRow reads a ports row as json.Unmarshal does: keys it does not know
// are ignored, and a field of the wrong type is an error with the rest read.
func ParseRow(raw json.RawMessage) (Row, error) {
	var r Row
	err := json.Unmarshal(raw, &r)
	return r, err
}

// ParseRowStrict is ParseRow that fails on a key Row does not have: the
// contract test of what the writer emits.
func ParseRowStrict(raw json.RawMessage) (Row, error) {
	var r Row
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, err
	}
	return r, nil
}
