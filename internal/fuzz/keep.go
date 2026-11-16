package fuzz

import (
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
)

// KeepExchange writes the request and the answer of a match as one file in
// dir (-od), named by the md5 of its text as ffuf names it, and returns the
// name. fuzz and dirs both keep their matches with it.
func KeepExchange(dir, rawRequest, rawResponse string) (string, error) {
	text := fmt.Sprintf("%s\n---- ↑ Request ---- Response ↓ ----\n\n%s", rawRequest, rawResponse)
	name := fmt.Sprintf("%x", md5.Sum([]byte(text)))
	if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o640); err != nil {
		return "", err
	}
	return name, nil
}
