// Package httprow is the payload of the rows azhaq-http writes, and the one
// type its readers decode them into.
package httprow

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/cpedetect"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/takeover"
)

// Row is the payload of an azhaq-http observation, and what the readers (map,
// watch, probe, findings, advisories, exports) decode. Every key the writers
// can emit is a field here, so a reader sees which fields a row has and a new
// key fails the contract tests until it is added. The collector's own writers
// are internal/collectors/httpcol and the engine's notes (an error that cut
// an answer short, a URL it did not request, a scheme it settled).
//
// Which fields a row has depends on its kind:
//
//   - "application" (an answer): URL, Status, FinalURL, ContentType, Server,
//     Title, Location, BodyHash, Length, Words, Lines, MS and the fetch.Evidence
//     fields; when they apply Generator, Realm, Head and HeadKept, Login,
//     Takeover, FinalStatus, StackTrace and the trace excerpt, ErrorText and
//     ErrorSample, Tech, Detected, IP, Cookies, Headers (the X- headers),
//     Truncated, the JSON* fields, Hops, Auth, and Catchall with Control for
//     an answer a catch-all gave, PrefixCatchall, and the Favicon fields. Evidence fields are
//     kept for rows written since they were added.
//   - "application" of azhaq probe (httpcol.Spec set): also Method, ElapsedNS,
//     Hash, BodyPreview, Extracts, CPE, WordPress, Knowledgebase, WebSocket,
//     SNI, TLS, CSP, BodyFQDN, BodyDomains, JarmHash, HTTP2, Pipeline and VHost.
//   - "application" taken in from httpx, katana or ffuf (another collector's
//     row of the same shape): the answer's fields it has, with Via, and CDN
//     and CDNType for httpx.
//   - "error" (a request that failed): Error and URL; the engine's note adds
//     Collector, and for an answer cut short Status, Cut, Received, Length,
//     ContentType, Headers, and Body or BodyBase64.
//   - "nothttp": URL, Host and Port. "noweb": Host and Ports. "dropped":
//     AnsweredAt. "skipped": Skipped. "scheme": HTTP and HTTPS.
type Row struct {
	URL         string `json:"url,omitempty"`
	Status      int    `json:"status,omitempty"`
	FinalURL    string `json:"final_url,omitempty"`
	FinalStatus int    `json:"final_status,omitempty"` // the last hop's, when there is more than one
	ContentType string `json:"content_type,omitempty"`
	Server      string `json:"server,omitempty"`
	Title       string `json:"title,omitempty"`
	Location    string `json:"location,omitempty"`
	BodyHash    string `json:"body_hash,omitempty"`
	Generator   string `json:"generator,omitempty"`
	Realm       string `json:"realm,omitempty"` // of the first WWW-Authenticate challenge
	Auth        string `json:"auth,omitempty"`  // "cookie": the run sent a session

	Head        []byte `json:"head,omitempty"` // the start of the body of a path that names a file or a panel
	HeadKept    bool   `json:"head_kept,omitempty"`
	Login       bool   `json:"login,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
	Length      int    `json:"length,omitempty"`
	Words       int    `json:"words,omitempty"`
	Lines       int    `json:"lines,omitempty"`
	MS          int64  `json:"ms,omitempty"`
	IP          string `json:"ip,omitempty"`
	Via         string `json:"via,omitempty"`
	CDN         string `json:"cdn,omitempty"`
	CDNType     string `json:"cdn_type,omitempty"`
	ErrorText   string `json:"error_text,omitempty"` // what a 5xx body gives away
	ErrorSample string `json:"error_sample,omitempty"`

	Takeover     *takeover.Finding   `json:"takeover,omitempty"`
	StackTrace   *Trace              `json:"stack_trace,omitempty"`
	TraceExcerpt string              `json:"trace_excerpt,omitempty"`
	TraceOffset  *int                `json:"trace_offset,omitempty"`
	Tech         []string            `json:"tech,omitempty"` // "Name" or "Name:version"
	Detected     []Detected          `json:"detected,omitempty"`
	Cookies      []Cookie            `json:"cookies,omitempty"`
	Headers      map[string]string   `json:"headers,omitempty"` // the X- headers of an answer; of a cut one, all
	JSONKeys     []string            `json:"json_keys,omitempty"`
	JSONIDs      map[string][]string `json:"json_ids,omitempty"`
	JSONItems    *int                `json:"json_items,omitempty"` // nil: not a listing
	Hops         []fetch.Hop         `json:"hops,omitempty"`
	Catchall     bool                `json:"catchall,omitempty"`
	Control      *fetch.Control      `json:"control,omitempty"` // the request a catch-all answer was compared with
	ControlExact bool                `json:"control_exact,omitempty"`
	// PrefixCatchall: the answer is also the answer of a name asked under its
	// own path (fetch.PrefixControl); the row is listed, labelled.
	PrefixCatchall *fetch.Control `json:"prefix_catchall,omitempty"`
	Favicon        string         `json:"favicon,omitempty"`
	FaviconURL     string         `json:"favicon_url,omitempty"`
	FaviconMD5     string         `json:"favicon_md5,omitempty"`
	FaviconPath    string         `json:"favicon_path,omitempty"`

	// ViaProxy lists what only a header of the answer named ("Server",
	// "X-Powered-By", "tech:Name:version"), when the -proxy the answer came
	// through could not be asked for its own answer: the proxy may have added
	// it. A version so marked is matched to no advisory.
	ViaProxy []string `json:"via_proxy,omitempty"`

	// The response headers and the start of the body, as fetch.Evidence keeps
	// them (TestEvidenceKeysAreFields holds the names to its own).
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	BodyExcerpt     []byte              `json:"body_excerpt,omitempty"`
	BodyLength      int                 `json:"body_length,omitempty"`
	BodyCut         bool                `json:"body_cut,omitempty"`
	BodyURL         string              `json:"body_url,omitempty"` // after a redirect: the URL the body is of
	AskedAt         time.Time           `json:"asked_at,omitzero"`

	// azhaq probe.
	Method        string                   `json:"method,omitempty"`
	ElapsedNS     int64                    `json:"elapsed_ns,omitempty"`
	Hash          map[string]string        `json:"hash,omitempty"`
	BodyPreview   string                   `json:"body_preview,omitempty"`
	Extracts      map[string][]string      `json:"extracts,omitempty"`
	CPE           []cpedetect.CPEInfo      `json:"cpe,omitempty"`
	WordPress     *cpedetect.WordPressInfo `json:"wordpress,omitempty"`
	Knowledgebase *Knowledgebase           `json:"knowledgebase,omitempty"`
	WebSocket     bool                     `json:"websocket,omitempty"`
	SNI           string                   `json:"sni,omitempty"`
	TLS           *TLS                     `json:"tls,omitempty"`
	CSP           *CSP                     `json:"csp,omitempty"`
	BodyFQDN      []string                 `json:"body_fqdn,omitempty"`
	BodyDomains   []string                 `json:"body_domains,omitempty"`
	JarmHash      string                   `json:"jarm_hash,omitempty"`
	HTTP2         bool                     `json:"http2,omitempty"`
	Pipeline      bool                     `json:"pipeline,omitempty"`
	VHost         bool                     `json:"vhost,omitempty"`

	// A failed request's note: the engine adds Collector, an answer cut short
	// its status, bytes and headers.
	Error      string `json:"error,omitempty"`
	Collector  string `json:"collector,omitempty"`
	Cut        bool   `json:"cut,omitempty"`
	Received   int    `json:"received,omitempty"`
	Body       string `json:"body,omitempty"`
	BodyBase64 []byte `json:"body_base64,omitempty"`

	// The rows of the other kinds.
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	Ports      string `json:"ports,omitempty"`
	AnsweredAt string `json:"answered_at,omitempty"`
	Skipped    string `json:"skipped,omitempty"`
	HTTP       string `json:"http,omitempty"`
	HTTPS      string `json:"https,omitempty"`
}

// Trace is a runtime's stack trace found in the body of an answer.
type Trace struct {
	Runtime   string `json:"runtime"`   // java, python, node, php, dotnet or ruby
	Exception string `json:"exception"` // the line that names the exception
	Frames    int    `json:"frames"`    // the frame lines of the runs of three or more
}

// Detected is a product a detection template named on an answer.
type Detected struct {
	Product  string `json:"product"`
	Template string `json:"template"`
	Version  string `json:"version,omitempty"`
	Matcher  string `json:"matcher,omitempty"`
	Many     string `json:"many,omitempty"` // "1": one of many products the template names
	// ViaProxy is "1" when only a header named it, through a -proxy that could
	// not be asked for its own answer (see Row.ViaProxy).
	ViaProxy string `json:"via_proxy,omitempty"`
}

// MarkViaProxy sets via_proxy on the detected rows only the identity headers
// of header produced, when the run's -proxy could not be asked for its own
// answer. again runs the same detection over other headers.
func MarkViaProxy(rows []map[string]string, header http.Header, again func(http.Header) []map[string]string) {
	if len(rows) == 0 || !egress.ProxyUnasked() {
		return
	}
	key := func(r map[string]string) string { return r["product"] + "\x00" + r["version"] + "\x00" + r["template"] }
	rest := map[string]bool{}
	for _, r := range again(egress.WithoutIdentity(header)) {
		rest[key(r)] = true
	}
	for _, r := range rows {
		if !rest[key(r)] {
			r["via_proxy"] = "1"
		}
	}
}

// Cookie is a Set-Cookie of an answer: its name and attributes, never its value.
type Cookie struct {
	Name     string `json:"name"`
	HTTPOnly bool   `json:"httponly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	SameSite string `json:"samesite,omitempty"`
}

// Fields of TLS, CSP and Knowledgebase are declared in the order a map of them
// is written, so that a row passed on as it is reads the same.

// TLS is httpx's tls object for the handshake of an answer.
type TLS struct {
	Cipher          string          `json:"cipher"`
	Emails          []string        `json:"emails,omitempty"`
	Expired         bool            `json:"expired,omitempty"`
	FingerprintHash FingerprintHash `json:"fingerprint_hash"`
	Host            string          `json:"host"`
	IssuerCN        string          `json:"issuer_cn"`
	IssuerDN        string          `json:"issuer_dn"`
	IssuerOrg       []string        `json:"issuer_org,omitempty"`
	Mismatched      bool            `json:"mismatched,omitempty"`
	NotAfter        string          `json:"not_after"`
	NotBefore       string          `json:"not_before"`
	Port            string          `json:"port"`
	ProbeStatus     bool            `json:"probe_status"`
	SelfSigned      bool            `json:"self_signed,omitempty"`
	Serial          string          `json:"serial"`
	SNI             string          `json:"sni,omitempty"`
	SubjectAN       []string        `json:"subject_an,omitempty"`
	SubjectCN       string          `json:"subject_cn"`
	SubjectDN       string          `json:"subject_dn"`
	SubjectOrg      []string        `json:"subject_org,omitempty"`
	TLSConnection   string          `json:"tls_connection"`
	TLSVersion      string          `json:"tls_version"`
	Wildcard        bool            `json:"wildcard_certificate,omitempty"`
}

// FingerprintHash is the digests of a certificate.
type FingerprintHash struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// CSP is the hosts a Content-Security-Policy names.
type CSP struct {
	Domains []string `json:"domains"`
	FQDN    []string `json:"fqdn"`
}

// Knowledgebase is -kb's page type and forms.
type Knowledgebase struct {
	Forms    any    `json:"Forms,omitempty"`
	PageType string `json:"PageType,omitempty"`
	PHash    int    `json:"pHash"`
}

// ParseRow reads an azhaq-http row as json.Unmarshal does: keys it does not
// know are ignored, and a field of the wrong type is an error with the rest
// read.
func ParseRow(raw json.RawMessage) (Row, error) {
	var r Row
	err := json.Unmarshal(raw, &r)
	return r, err
}

// ParseRowStrict is ParseRow that fails on a key Row does not have: the
// contract test of what the writers emit.
func ParseRowStrict(raw json.RawMessage) (Row, error) {
	var r Row
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, err
	}
	return r, nil
}
