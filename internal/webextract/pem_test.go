package webextract

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// begin is a PEM begin line, built so the test file holds no marker of its own.
func begin(label string) string { return "-----BEG" + "IN " + label + "-----" }

func privateKeys(t *testing.T, s []Secret) (keys, marks []Secret) {
	t.Helper()
	for _, x := range s {
		switch x.Kind {
		case "private-key":
			keys = append(keys, x)
		case "private-key-marker":
			marks = append(marks, x)
		}
	}
	return
}

// A key is a finding when its whole block is there: begin line, a base64 body
// that decodes to the structure the format has, and the end line of its type.
func TestPEMBlockIsAPrivateKeyAFindingTier(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := x509.MarshalECPrivateKey(ecKey)
	ed, _ := x509.MarshalPKCS8PrivateKey(edKey)
	blocks := map[string]string{
		"rsa":    string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})),
		"ec":     string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ec})),
		"pkcs8":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ed})),
		"legacy": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF"}, Bytes: make([]byte, 64)})),
	}
	if n := len(blocks["rsa"]); n < 1600 {
		t.Fatalf("the RSA block is %d bytes, want a real one", n)
	}
	for name, b := range blocks {
		b = strings.TrimSpace(b)
		for form, js := range map[string]string{
			"raw lines":   "var k = `" + b + "`;",
			"js escapes":  `var k = "` + strings.ReplaceAll(b, "\n", `\n`) + `";`,
			"crlf":        `var k = "` + strings.ReplaceAll(b, "\n", `\r\n`) + `";`,
			"split lines": `var k = "` + strings.ReplaceAll(b, "\n", `\n" + "`) + `";`,
		} {
			keys, marks := privateKeys(t, Secrets("function f(){}\n"+js))
			if len(keys) != 1 || keys[0].Severity != "high" || keys[0].Rule != RuleFormat || len(marks) != 0 {
				t.Errorf("%s (%s): keys %+v, marks %+v", name, form, keys, marks)
			}
		}
	}
	// The redaction is what it was: the context shows the value's ends only.
	js := "var k=`" + strings.TrimSpace(blocks["pkcs8"]) + "`;"
	keys, _ := privateKeys(t, Secrets(js))
	if len(keys) != 1 || strings.Contains(keys[0].Context, "MC4C") || !strings.HasSuffix(keys[0].Context, "-----B…----") {
		t.Errorf("context %q", keys[0].Context)
	}
}

// A begin line alone, or with text that is not a key after it, is a mention
// at info level, never a key and never a finding.
func TestPEMBeginLineAloneIsOnlyAMention(t *testing.T) {
	line := begin("RSA PRIVATE KEY")
	end := "-----END RSA PRIVATE KEY-----"
	for name, js := range map[string]string{
		"help text":     `var help={keyField:"Paste the private key here. Begins with ` + line + `"};`,
		"concatenation": `var k = "` + line + `\n" + key + "\n` + end + `";`,
		"placeholder":   `var k = "` + line + `\nMIIEowIBAAKCAQEAazhaqnotarealkey\n` + end + `";`,
		"no end line":   `var k = "` + line + `\nMIIEowIBAAKCAQEAazhaqnotarealkeyMIIEowIBAAKCAQEAazhaqnotarealkey\n";`,
		"other end":     `var k = "` + line + `\nMIIEowIBAAKCAQEAazhaqnotarealkeyMIIEowIBAAKCAQEAazhaqnotarealkey\n-----END PRIVATE KEY-----";`,
		"not der":       `var k = "` + line + `\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n` + end + `";`,
		"pattern":       `var re=/` + line + `[\s\S]+?` + end + `/;`,
	} {
		keys, marks := privateKeys(t, Secrets(js))
		if len(keys) != 0 {
			t.Errorf("%s: a key: %+v", name, keys)
		}
		if len(marks) != 1 || marks[0].Severity != "info" || marks[0].Rule != RuleMarker || marks[0].Value != line {
			t.Errorf("%s: marks %+v", name, marks)
		}
	}
	// A real key after a bare mention of its marker is still found, where it is.
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(edKey)
	b := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	js := "// starts with " + begin("PRIVATE KEY") + "\nvar k=`" + b + "`;"
	keys, marks := privateKeys(t, Secrets(js))
	if len(keys) != 1 || len(marks) != 1 || keys[0].Offset != strings.LastIndex(js, begin("PRIVATE KEY")) {
		t.Errorf("keys %+v, marks %+v", keys, marks)
	}
}
