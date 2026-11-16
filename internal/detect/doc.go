// Package detect names web products from an HTTP response with nuclei's
// MIT-licensed detection templates, compiled into embedded data (see
// SOURCE.md and LICENSE.md). It needs neither nuclei nor the network.
//
// Match runs a response against every template request for its path. A
// literal index (Aho-Corasick over the literals each matcher requires)
// keeps the thousands of regexes and words from running on every body.
// A Server or X-Powered-By token a template extracts from must name the
// template's own product (internal/productname.Names); else its version is
// dropped, and the hit with it when the headers were its only evidence.
// scripts/detectgen builds templates.json.gz.
package detect
