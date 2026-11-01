// Package cdnranges is the part of projectdiscovery/cdncheck v1.3.2 (MIT,
// see LICENSE.md) that azhaq uses: whether an address is in a known CDN,
// WAF or cloud range, and whether a name ends in a known CDN or WAF suffix.
//
// Changes from upstream: sources_data.json is read on first use, not in
// init (that cost every command 15 MB and 38 ms), and by kind: a caller that
// asks only about CDNs and WAFs (CheckEdge) never builds the 116,000 cloud
// ranges, and one that asks about names never builds the address tables.
// The text is walked in place (scan.go) rather than unmarshalled, so the
// ranges are not copied into the heap. The DNS client and the
// wappalyzer lookup are left out, and an address in the ranges of two
// providers of one kind (upstream: whichever its map gives first) always
// gets the one with the most specific range, then the first by name.
// Names are split with golang.org/x/net/publicsuffix, not weppos's list
// (another 0.9 MB allocated at start). Matching is otherwise unchanged;
// upstream_test.go compares the two.
//
// To update, from this directory:
//
//	go generate
package cdnranges

//go:generate sh -c "cp $(go list -m -f '{{.Dir}}' github.com/projectdiscovery/cdncheck@vX.Y.Z)/sources_data.json sources_data.json"
