package browser

import (
	"bytes"
	"context"
	"image"
	"image/jpeg"
	"image/png"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
)

// A picture of another size than -shot-size asked for is a failure with the
// sizes in it, whatever its format; one of the size asked for is not.
func TestPictureOfAnotherSizeIsAFailure(t *testing.T) {
	enc := map[string]func(*bytes.Buffer, image.Image) error{
		"png":  func(b *bytes.Buffer, im image.Image) error { return png.Encode(b, im) },
		"jpeg": func(b *bytes.Buffer, im image.Image) error { return jpeg.Encode(b, im, nil) },
	}
	for name, f := range enc {
		pic := func(w, h int) []byte {
			var b bytes.Buffer
			if err := f(&b, image.NewRGBA(image.Rect(0, 0, w, h))); err != nil {
				t.Fatal(err)
			}
			return b.Bytes()
		}
		if err := sizeError(pic(800, 600), 800, 600); err != nil {
			t.Errorf("%s: the size asked for: %v", name, err)
		}
		for _, got := range [][2]int{{799, 600}, {800, 599}, {400, 300}} {
			err := sizeError(pic(got[0], got[1]), 800, 600)
			want := "the picture came out " + strconv.Itoa(got[0]) + "x" + strconv.Itoa(got[1]) + ", not the 800x600 -shot-size asked for"
			if err == nil || err.Error() != want {
				t.Errorf("%s %v: error %v, want %q", name, got, err, want)
			}
		}
	}
}

// -shot-wait 0 (a negative Wait here) takes the page at once, before a timer
// draws it; -shot-wait 3s-style waits are waited out whatever the page is.
func TestShotWaitZeroTakesThePageAtOnce(t *testing.T) {
	srv := pageServer(t, `<!doctype html><title>late</title><p>shell</p>
<script>setTimeout(() => { const h = document.createElement('h1'); h.textContent = 'drawn late'; document.body.appendChild(h) }, 900)</script>`)
	b := startChrome(t)
	b.Wait = -1
	t0 := time.Now()
	p, err := b.Load(context.Background(), srv.URL, true)
	if err != nil || len(p.Image) == 0 {
		t.Fatalf("no picture: %v", err)
	}
	if strings.Contains(p.HTML, "<h1>drawn late</h1>") || time.Since(t0) > 800*time.Millisecond {
		t.Errorf("a page taken at once was taken after %v, with the timer's work: %s", time.Since(t0), p.HTML)
	}
	b.Wait = 1200 * time.Millisecond
	plain := pageServer(t, `<!doctype html><title>plain</title><h1>no script</h1>`)
	t0 = time.Now()
	if _, err := b.Load(context.Background(), plain.URL, true); err != nil || time.Since(t0) < 1200*time.Millisecond {
		t.Errorf("a page with no script, with a wait given: took %v, err %v, want the whole wait", time.Since(t0), err)
	}
}

// A page's unloaded count is its images, styles, scripts, fonts and media that
// did not come back or failed, out of the ones it asked for; other requests,
// and those azhaq refused, are not in it.
func TestUnloadedCountsImagesStylesScriptsFontsAndMedia(t *testing.T) {
	l := newPageLog("main", nil)
	for _, rt := range []network.ResourceType{network.ResourceTypeImage, network.ResourceTypeStylesheet, network.ResourceTypeScript, network.ResourceTypeFont, network.ResourceTypeMedia} {
		l.all = append(l.all,
			&NetEntry{rt: rt, done: true},                      // came
			&NetEntry{rt: rt},                                  // never came back
			&NetEntry{rt: rt, done: true, Error: "net::ERR_X"}, // failed
			&NetEntry{rt: rt, blocked: true},                   // refused by the scope: not a failure of the page
		)
	}
	l.all = append(l.all, &NetEntry{rt: network.ResourceTypeXHR}, &NetEntry{rt: network.ResourceTypeFetch}, &NetEntry{rt: network.ResourceTypeDocument})
	_, unloaded, total := l.snapshot()
	if unloaded != 10 || total != 15 {
		t.Errorf("%d unloaded of %d, want 10 of 15: each of the 5 kinds has one that did not come, one that failed and one that came", unloaded, total)
	}
	if l.unloaded() != 10 {
		t.Errorf("unloaded() %d, want 10", l.unloaded())
	}
}

// Without -shot-wait a page is taken early only when nothing can still change
// it: a script, frame, object, embed or refresh each keep the page's wait
// (1.5 s after its load event).
func TestPageThatCouldStillChangeKeepsTheWait(t *testing.T) {
	b := startChrome(t)
	for name, html := range map[string]string{
		"frame":   `<!doctype html><title>t</title><h1>frame</h1><iframe src="about:blank"></iframe>`,
		"object":  `<!doctype html><title>t</title><h1>object</h1><object data="about:blank"></object>`,
		"embed":   `<!doctype html><title>t</title><h1>embed</h1><embed src="about:blank">`,
		"refresh": `<!doctype html><title>t</title><meta http-equiv="refresh" content="3600"><h1>refresh</h1>`,
	} {
		srv := pageServer(t, html)
		t0 := time.Now()
		if _, err := b.Load(context.Background(), srv.URL, true); err != nil {
			t.Fatal(name, err)
		}
		if took := time.Since(t0); took < 1400*time.Millisecond {
			t.Errorf("a page with a %s was taken after %s, not given the 1.5 s", name, took)
		}
	}
}
