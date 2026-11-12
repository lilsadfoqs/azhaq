package fetch

import (
	"maps"
	"slices"
	"strings"
	"time"
)

// ExcerptBytes is how much of an answer's body a stored row keeps.
const ExcerptBytes = 1024

// Evidence is what a stored row keeps of the answer it stands on: the
// response headers and the start of the body. The JSON names are the keys
// of the observation payload.
type Evidence struct {
	Headers    map[string][]string `json:"response_headers,omitempty"`
	Excerpt    []byte              `json:"body_excerpt,omitempty"` // raw bytes
	BodyLength int                 `json:"body_length"`
	Cut        bool                `json:"body_cut,omitempty"` // the body is longer than Excerpt
	BodyURL    string              `json:"body_url,omitempty"` // after a redirect: the URL the body is of
	AskedAt    time.Time           `json:"asked_at,omitzero"`
}

// EvidenceKeys are the payload keys Evidence adds.
var EvidenceKeys = []string{"response_headers", "body_excerpt", "body_length", "body_cut", "body_url", "asked_at"}

// EvidenceOf is res as a row keeps it. Only the response's headers go in,
// never the request's; a Set-Cookie value is a session, so its name and
// attributes stay and its value does not. fullLength is the body's size
// when the read stopped short of it (0: the read body's).
func EvidenceOf(res Result, fullLength int) Evidence {
	ev := Evidence{BodyLength: max(len(res.Body), fullLength), AskedAt: res.At.UTC()}
	if len(res.Header) > 0 {
		ev.Headers = make(map[string][]string, len(res.Header))
		for k, vs := range res.Header {
			if strings.EqualFold(k, "Set-Cookie") {
				vs = redactCookies(vs)
			}
			ev.Headers[k] = vs
		}
	}
	// A copy: the excerpt must not keep the whole body reachable.
	ev.Excerpt = slices.Clone(res.Body[:min(len(res.Body), ExcerptBytes)])
	ev.Cut = ev.BodyLength > len(ev.Excerpt)
	if len(res.Hops) > 1 && res.URL != "" && res.URL != res.RequestURL {
		ev.BodyURL = res.URL
	}
	return ev
}

func redactCookies(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		name, rest, _ := strings.Cut(l, "=")
		_, attrs, _ := strings.Cut(rest, ";")
		out[i] = name + "=[kept out]"
		if attrs != "" {
			out[i] += ";" + attrs
		}
	}
	return out
}

// HeaderLines is the headers as lines, sorted by name.
func (e Evidence) HeaderLines() []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(e.Headers)) {
		for _, v := range e.Headers[k] {
			out = append(out, k+": "+v)
		}
	}
	return out
}

// AddEvidence puts res's evidence in a row's payload, under its own keys.
func AddEvidence(row map[string]any, res Result, fullLength int) {
	ev := EvidenceOf(res, fullLength)
	if len(ev.Headers) > 0 {
		row["response_headers"] = ev.Headers
	}
	row["body_excerpt"] = ev.Excerpt
	row["body_length"] = ev.BodyLength
	if ev.Cut {
		row["body_cut"] = true
	}
	if ev.BodyURL != "" {
		row["body_url"] = ev.BodyURL
	}
	if !ev.AskedAt.IsZero() {
		row["asked_at"] = ev.AskedAt
	}
}
