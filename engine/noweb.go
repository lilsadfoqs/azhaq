package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/types"
)

// KindNoWeb is the observation of a target given with no port whose guessed
// web ports (443, then 80) refused the connection: the host is up and has
// no web service there, which is an answer, not a failure.
const KindNoWeb = "noweb"

// KindNotHTTP is the observation of a port that answered something other
// than HTTP; the HTTP collector records it.
const KindNotHTTP = "nothttp"

func hasKind(obs []types.StoredObservation, kind string) bool {
	for _, o := range obs {
		if o.Kind == kind {
			return true
		}
	}
	return false
}

// NoWebNote says which targets had no web service on the ports guessed.
func NoWebNote(obs []types.StoredObservation) string {
	seen := map[string]bool{}
	var hosts []string
	ports := ""
	for _, o := range obs {
		if o.Kind != KindNoWeb {
			continue
		}
		var p struct {
			Host  string `json:"host"`
			Ports string `json:"ports"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Host == "" || seen[p.Host] {
			continue
		}
		seen[p.Host] = true
		hosts = append(hosts, p.Host)
		ports = p.Ports
	}
	if len(hosts) == 0 {
		return ""
	}
	sort.Strings(hosts)
	list := strings.Join(hosts, ", ")
	if len(hosts) > 5 {
		list = fmt.Sprintf("%s and %d more", strings.Join(hosts[:5], ", "), len(hosts)-5)
	}
	return fmt.Sprintf("no web service on %s (connection refused): %s; -web-ports asks other ports, -ports finds them", ports, list)
}

// NotHTTPNote says which ports answered something other than HTTP (an FTP
// or SSH banner): open, and not a web service.
func NotHTTPNote(obs []types.StoredObservation) string {
	seen := map[string]bool{}
	var at []string
	for _, o := range obs {
		if o.Kind != KindNotHTTP {
			continue
		}
		var p struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Host == "" {
			continue
		}
		hp := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
		if !seen[hp] {
			seen[hp] = true
			at = append(at, hp)
		}
	}
	if len(at) == 0 {
		return ""
	}
	sort.Strings(at)
	list := strings.Join(at, ", ")
	if len(at) > 5 {
		list = fmt.Sprintf("%s and %d more", strings.Join(at[:5], ", "), len(at)-5)
	}
	return "open, but not a web service (answered something other than HTTP): " + list
}
