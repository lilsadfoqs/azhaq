package webextract

import (
	"net/url"
	"testing"
)

// A reference a browser loads as a picture, font, sound or video is media
// whatever the file is called; a link, a form or a longdesc is not.
func TestPageRefMedia(t *testing.T) {
	base, _ := url.Parse("https://h/")
	body := []byte(`<a href="/l"><img src="/i.jfif" longdesc="/d"><img srcset="/s1 1x, /s2 2x"><video poster="/p"><source src="/v"></video>
<audio src="/a"></audio><input type="image" src="/b" formaction="/f"><link rel="stylesheet" href="/c.css"><form action="/go"></form>`)
	media := map[string]bool{}
	for _, r := range LinkRefs(body, base) {
		media[r.URL[len("https://h"):]] = r.Media()
	}
	for p, want := range map[string]bool{"/i.jfif": true, "/s1": true, "/s2": true, "/p": true, "/v": true, "/a": true, "/b": true,
		"/l": false, "/d": false, "/f": false, "/c.css": false, "/go": false} {
		if got, ok := media[p]; !ok || got != want {
			t.Errorf("%s: media %v (found %v), want %v", p, got, ok, want)
		}
	}
	if !MediaRef("style", "url") || MediaRef("style", "import") {
		t.Error("a stylesheet's url() is media, its @import is not")
	}
}
