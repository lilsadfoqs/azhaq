package portcol

import "github.com/lilsadfoqs/azhaq/internal/portscan"

// gapOf is the service ports of -p default that a scan of asked leaves out,
// less the ports never asked (-port-skip, -ep).
func (c *Collector) gapOf(asked []int) []int {
	skip := make([]int, 0, len(c.NoPorts))
	for p := range c.NoPorts {
		skip = append(skip, p)
	}
	return portscan.ServiceGap(asked, skip)
}

// quietNote notes, on an address's row that shows no open port, what the
// ports asked left out of default: a narrow list may have missed the
// service. Nothing is asked for it.
func (c *Collector) quietNote(row map[string]any, asked []int) {
	if _, ok := row["note"]; ok || row["partial"] != nil {
		return
	}
	if row["services"] != nil || row["udp_services"] != nil {
		return
	}
	if n, _ := row["scanned"].(int); n > 0 {
		if gap := c.gapOf(asked); len(gap) > 0 {
			row["note"] = portscan.QuietNote(c.flag(), n, 1, 1, gap)
		}
	}
}

// flag is the option the notes name the ports by.
func (c *Collector) flag() string {
	if c.PortsFlag == "" {
		return "-ports"
	}
	return c.PortsFlag
}
