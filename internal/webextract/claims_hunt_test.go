package webextract

import "testing"

// A generic secret needs a string of 8 characters or more with an entropy of
// 3.2 bits a character or more; placeholders and values that are mostly
// punctuation are left out, and a random value of the same shape is listed.
func TestGenericSecretNeedsLengthEntropyAndNoPlaceholderOrPunctuation(t *testing.T) {
	listed := func(js string) []string {
		var out []string
		for _, s := range Secrets(js) {
			out = append(out, s.Value)
		}
		return out
	}
	for name, js := range map[string]string{
		"placeholder":       `var c={apiToken:"YOUR_API_KEY"};`,
		"change me":         `var c={password:"changeme"};`,
		"template":          `var c={apiKey:"{{apiKey}}"};`,
		"7 characters":      `var c={apiToken:"Zx81Qp9"};`,
		"9 distinct, short": `var c={apiToken:"Zx81QpLm2"};`,
		"low entropy":       `var c={apiToken:"abababababababab"};`,
		"much punctuation":  `var c={apiToken:"Zx81!#%&*(Lm2Vt9"};`,
		"punctuation heavy": `var c={secret:"<=>?!#$%^&*()Zx8"};`,
	} {
		if got := listed(js); len(got) != 0 {
			t.Errorf("%s: listed %v", name, got)
		}
	}
	for name, js := range map[string]string{
		"10 characters, random": `var c={apiToken:"Zx81QpLm2V"};`,
		"long, random":          `var c={apiToken:"Zx81QpLm2Vt9Rr4Nc7Ks"};`,
		"a little punctuation":  `var c={apiToken:"Zx81QpLm2Vt9Rr+Nc7Ks"};`,
	} {
		if got := listed(js); len(got) != 1 {
			t.Errorf("%s: listed %v, want the value", name, got)
		}
	}
}
