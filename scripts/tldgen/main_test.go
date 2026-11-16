package main

import (
	"os"
	"strings"
	"testing"
)

func TestCheckAcceptsTheEmbeddedList(t *testing.T) {
	b, err := os.ReadFile("../../internal/normalize/tlds-alpha-by-domain.txt")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := check(string(b)); err != nil || n < 1400 {
		t.Fatalf("%d, %v", n, err)
	}
}

func TestCheckRefusesWhatIsNotTheList(t *testing.T) {
	good, _ := os.ReadFile("../../internal/normalize/tlds-alpha-by-domain.txt")
	body := string(good)
	for name, text := range map[string]string{
		"html":      "<html>Not Found</html>",
		"no header": strings.SplitN(body, "\n", 2)[1],
		"unsorted":  strings.Replace(body, "\nAAA\nAARP\n", "\nAARP\nAAA\n", 1),
		"no com":    strings.Replace(body, "\nCOM\n", "\n", 1),
		"lower":     strings.Replace(body, "\nAAA\n", "\naaa\n", 1),
		"short":     "# Version 2026111600, Last Updated Mon Nov 16 07:07:02 2026 UTC\nCOM\nNET\nORG\nARPA\nDE\nJP\nXN--P1AI\n",
	} {
		if _, err := check(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
