package brutecol

import (
	_ "embed"
	"strings"
)

//go:embed words/subdomains-top1million-5000.txt
var builtinWords string

// DefaultWords are the words `run` guesses names from unless -dns-brute names
// a file or says none: SecLists' subdomains-top1million-5000 (MIT), see
// words/NOTICE.
func DefaultWords() []string {
	return strings.Fields(builtinWords)
}
