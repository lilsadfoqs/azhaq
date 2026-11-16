// Command tldgen refreshes the root-zone TLD list azhaq carries
// (internal/normalize/tlds-alpha-by-domain.txt) from IANA. Run it by hand,
// with network access, when the list should be refreshed:
//
//	go run ./scripts/tldgen
//
// It downloads https://data.iana.org/TLD/tlds-alpha-by-domain.txt (public
// domain), checks it reads as a list of TLDs, and writes it unchanged. It
// sends nothing but the download. See docs/commands/dns.md, "Types".
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const source = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

func main() {
	url := flag.String("url", source, "the list to download")
	out := flag.String("out", "internal/normalize/tlds-alpha-by-domain.txt", "the file to write")
	flag.Parse()
	if err := run(*url, *out); err != nil {
		fmt.Fprintln(os.Stderr, "tldgen:", err)
		os.Exit(1)
	}
}

func run(url, out string) error {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	n, err := check(string(body))
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	if err := os.WriteFile(out, body, 0o644); err != nil {
		return err
	}
	fmt.Printf("%s: %d TLDs, %s\n", out, n, strings.TrimSpace(strings.SplitN(string(body), "\n", 2)[0]))
	return nil
}

var (
	header = regexp.MustCompile(`^# Version \d{10}, Last Updated .+ UTC$`)
	label  = regexp.MustCompile(`^[A-Z0-9-]{2,63}$`)
)

// check says text is IANA's list: a version header, then one upper-case
// TLD a line, in order, with the TLDs every list has. It returns the count.
func check(text string) (int, error) {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) == 0 || !header.MatchString(lines[0]) {
		return 0, errors.New("no version header on the first line")
	}
	seen := map[string]bool{}
	prev := ""
	for i, l := range lines[1:] {
		if !label.MatchString(l) {
			return 0, fmt.Errorf("line %d: %q is not a TLD", i+2, l)
		}
		if l <= prev {
			return 0, fmt.Errorf("line %d: %q is out of order", i+2, l)
		}
		prev = l
		seen[l] = true
	}
	for _, must := range []string{"COM", "NET", "ORG", "ARPA", "DE", "JP", "XN--P1AI"} {
		if !seen[must] {
			return 0, fmt.Errorf("%s is missing: not the root zone's list", must)
		}
	}
	if len(seen) < 1000 {
		return 0, fmt.Errorf("%d TLDs: too few", len(seen))
	}
	return len(seen), nil
}
