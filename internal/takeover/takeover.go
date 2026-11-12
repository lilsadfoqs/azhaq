// Package takeover tells a name another party may take over: one whose
// CNAME points at a service account or a domain that no longer exists,
// or whose front page is that service's "nothing here" page. The
// services and their pages are the ones the public takeover lists
// (can-i-take-over-xyz) describe as claimable; each finding says what it
// rests on, for a person to confirm before reporting.
package takeover

import (
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"golang.org/x/net/publicsuffix"
)

// Finding is one name another party may take over.
type Finding struct {
	Service  string `json:"service"`          // the service, or "domain" for a CNAME target whose domain does not exist
	Target   string `json:"target,omitempty"` // the CNAME target
	Evidence string `json:"evidence"`         // what the finding rests on
	Strength string `json:"strength"`         // "strong": the service says nothing is there; "dangling": the target does not resolve
	// List names what a "dangling" finding rests on: the public list's entry
	// for the service and when azhaq read it. The name not resolving is the
	// whole evidence.
	List string `json:"list,omitempty"`
	// Status says how far the finding is shown: "verified" when the service
	// itself answered, from the name's own front page, with its documented
	// "nothing here" page; "candidate" when what was seen (a name that did
	// not resolve, a domain with no DNS) does not show the name is free.
	Status string `json:"status"`
}

// The two statuses of a Finding.
const (
	Candidate = "candidate"
	Verified  = "verified"
)

// Settled is f with its Status filled in when it is empty, as a finding
// stored by an earlier version has it: only a service's own page beside a
// CNAME to that service was ever a verified one.
func (f Finding) Settled() Finding {
	if f.Status == "" {
		f.Status = Candidate
		if f.Strength == "strong" && f.Service != "domain" {
			f.Status = Verified
		}
	}
	return f
}

// ListRead is when the public takeover list's entries for the dangling
// services were read; the list changes as providers change.
const ListRead = "2026-10-28"

// service is a hosting service whose names can be claimed by anyone.
type service struct {
	name     string
	suffixes []string       // CNAME targets on the service
	dangling bool           // a target that does not resolve can be claimed
	page     *lazyre.Regexp // what its front page says when nothing is there
	// alone: the page's words are the service's own and nowhere else, so
	// they say something even with no CNAME known; a page that other sites
	// can show counts only beside a CNAME to the service.
	alone bool
}

// services are the ones the public takeover lists call claimable. Azure's
// are the names that serve the web; a disabled Traffic Manager profile or
// a deleted database answers NXDOMAIN while its owner still holds it, or
// serves nobody's pages.
var services = []service{
	{"AWS S3", nil, false, lazyre.New(`<Code>NoSuchBucket</Code>`), true},
	{"GitHub Pages", []string{".github.io"}, false, lazyre.New(`There isn't a GitHub Pages site here\.`), true},
	{"Heroku", []string{".herokuapp.com", ".herokudns.com", ".herokussl.com"}, false, lazyre.New(`herokucdn\.com/error-pages/no-such-app\.html`), true},
	{"Azure", []string{".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".blob.core.windows.net",
		".azure-api.net", ".azurehdinsight.net", ".azureedge.net", ".azurecontainer.io"}, true, nil, false},
	{"AWS Elastic Beanstalk", []string{".elasticbeanstalk.com"}, true, nil, false},
	{"Bitbucket", []string{".bitbucket.io"}, false, lazyre.New(`Repository not found`), false},
	{"Ghost", []string{".ghost.io"}, false, lazyre.New(`Failed to resolve DNS path for this host`), true},
	{"Pantheon", []string{".pantheonsite.io"}, false, lazyre.New(`The gods are wise, but do not know of the site which you seek\.`), true},
	{"Surge.sh", []string{".surge.sh"}, false, lazyre.New(`project not found`), false},
	{"WordPress.com", []string{".wordpress.com"}, false, lazyre.New(`Do you want to register <em>[^<]*\.wordpress\.com</em>`), true},
	{"Help Scout", []string{".helpscoutdocs.com"}, false, lazyre.New(`No settings were found for this company:`), true},
	{"ReadMe", []string{".readme.io"}, false, lazyre.New(`Project doesnt exist\.\.\. yet!`), true},
	{"Ngrok", []string{".ngrok.io", ".ngrok.app"}, false, lazyre.New(`ERR_NGROK_3200`), true},
	{"Fly.io", []string{".fly.dev"}, true, nil, false},
}

// listEntry is the public list's entry behind each suffix of a dangling
// service.
var listEntry = map[string]string{
	".azurewebsites.net": "Azure App Service", ".cloudapp.net": "Azure Cloud Services", ".cloudapp.azure.com": "Azure virtual machine public IP name",
	".blob.core.windows.net": "Azure Blob Storage", ".azure-api.net": "Azure API Management", ".azurehdinsight.net": "Azure HDInsight",
	".azureedge.net": "Azure CDN", ".azurecontainer.io": "Azure Container Instances",
	".elasticbeanstalk.com": "AWS Elastic Beanstalk", ".fly.dev": "Fly.io",
}

// entryOf is the list entry a dangling target rests on.
func entryOf(target string) string {
	t := strings.ToLower(strings.TrimSuffix(target, "."))
	for suf, e := range listEntry {
		if strings.HasSuffix(t, suf) {
			return e
		}
	}
	return ""
}

func (s service) on(target string) bool {
	t := strings.ToLower(strings.TrimSuffix(target, "."))
	if s.name == "AWS S3" {
		// bucket.s3.amazonaws.com, bucket.s3.eu-west-1.amazonaws.com,
		// bucket.s3-website-us-east-1.amazonaws.com, …
		return strings.HasSuffix(t, ".amazonaws.com") && (strings.Contains(t, ".s3.") || strings.Contains(t, ".s3-"))
	}
	for _, suf := range s.suffixes {
		if strings.HasSuffix(t, suf) {
			return true
		}
	}
	return false
}

// Dangling is what a name's DNS answer measured of a CNAME that points at a
// name that does not exist: the chain, the code of its end, and the resolver
// that gave it. It says nothing of who may create the name; a takeover is
// the claim that does, and a Finding makes it.
type Dangling struct {
	Chain  []string `json:"chain"`            // the CNAME targets, first hop first
	Target string   `json:"target"`           // the last one: the name that answered NXDOMAIN
	Rcode  string   `json:"rcode"`            // NXDOMAIN
	Server string   `json:"server,omitempty"` // the resolver that gave the answer
}

// Measure is the Dangling of a name whose chain ends at a name that answered
// NXDOMAIN (gone), whoever holds the target's service or domain. A target that
// is the owner's own name is not one, as for ByCNAME.
func Measure(host string, chain []string, gone bool, server string) (Dangling, bool) {
	if len(chain) == 0 || !gone {
		return Dangling{}, false
	}
	target := chain[len(chain)-1]
	if normalize.SameSite(host, target) {
		return Dangling{}, false
	}
	return Dangling{Chain: append([]string(nil), chain...), Target: target, Rcode: "NXDOMAIN", Server: server}, true
}

// ByCNAME judges a name by its CNAME chain: targetGone says the last
// target does not resolve (NXDOMAIN), registered whether that target's
// registrable domain still exists. A target on a service where anyone may
// create that name, or under a domain nobody holds, can be taken.
func ByCNAME(host string, chain []string, targetGone, registered bool) (Finding, bool) {
	if len(chain) == 0 || !targetGone {
		return Finding{}, false
	}
	target := chain[len(chain)-1]
	if normalize.SameSite(host, target) {
		return Finding{}, false // the target is the owner's own name
	}
	for _, s := range services {
		if s.on(target) && s.dangling {
			e := entryOf(target)
			return Finding{Service: s.name, Target: target, Strength: "dangling", Status: Candidate, List: "can-i-take-over-xyz, entry " + e + ", read " + ListRead,
				Evidence: "observed: CNAME to " + target + "; " + target + " answered NXDOMAIN; " + target + " is on " + s.name + " (the public list's entry). " +
					"Candidate, unverified: NXDOMAIN does not show the name is free, and no check with " + s.name + " was made"}, true
		}
	}
	if !registered {
		return Finding{Service: "domain", Target: target, Strength: "strong", Status: Candidate,
			Evidence: "observed: CNAME to " + target + "; " + target + " answered NXDOMAIN; the SOA of " + Domain(target) + " answered NXDOMAIN. " +
				"Candidate, unverified: " + Domain(target) + " may be free to register; no registry was asked"}, true
	}
	return Finding{}, false
}

// ByPage judges a name by its front page: a service's own page for a name
// nobody claimed. Beside a CNAME to that service it is strong; with no
// CNAME known, only a page no other site shows counts, as "page" (the
// DNS answer then says more); beside a CNAME elsewhere it says nothing.
func ByPage(chain []string, body []byte) (Finding, bool) {
	if len(body) == 0 {
		return Finding{}, false
	}
	target := ""
	if len(chain) > 0 {
		target = chain[len(chain)-1]
	}
	for _, s := range services {
		if s.page == nil || !s.page.Match(body) {
			continue
		}
		evidence := s.name + "'s page for a name nobody claimed: " + quote(s.page.Find(body))
		switch {
		case target != "" && s.on(target):
			return Finding{Service: s.name, Target: target, Strength: "strong", Status: Verified, Evidence: "CNAME to " + target + "; " + evidence + " (verified: the service's own documented answer)"}, true
		case target == "" && s.alone:
			return Finding{Service: s.name, Strength: "page", Status: Candidate, Evidence: evidence + " (candidate: no CNAME known, so the name is not shown to be on the service; check where it points)"}, true
		}
		return Finding{}, false
	}
	return Finding{}, false
}

// Service names the takeover-prone service a CNAME target is on, or "".
func Service(target string) string {
	for _, s := range services {
		if s.on(target) {
			return s.name
		}
	}
	return ""
}

func quote(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return `"` + s + `"`
}

// Domain is the name one registers to hold host: the ICANN public suffix
// and one label. Unlike a registrable domain by the whole public suffix
// list, a cloud's shared suffix (us-west-2.elb.amazonaws.com) is no
// registry: its names cannot be registered, only created by the cloud.
func Domain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	labels := strings.Split(host, ".")
	for i := 1; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		if ps, icann := publicsuffix.PublicSuffix(suffix); icann && ps == suffix {
			return strings.Join(labels[i-1:], ".")
		}
	}
	return ""
}
