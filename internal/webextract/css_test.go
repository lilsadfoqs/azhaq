package webextract

import (
	"net/url"
	"reflect"
	"testing"
)

func TestStylesheets(t *testing.T) {
	base, _ := url.Parse("http://h/app/")
	page := `<link rel="icon" href="/favicon.ico"><link rel=stylesheet href=a.css><link REL="Alternate Stylesheet" href="/b.css">` +
		`<link rel="preload" as="style" href="/c.css"><link rel=stylesheet href=a.css><link rel=stylesheet href="https://cdn.test/x.css">`
	got := Stylesheets([]byte(page), base)
	want := []string{"http://h/app/a.css", "http://h/b.css", "https://cdn.test/x.css"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stylesheets %v, want %v", got, want)
	}
}

func TestCSSRefs(t *testing.T) {
	base, _ := url.Parse("http://h/css/main.css")
	got := CSSRefs(`@import 'more.css'; @import url("/lib/x.css"); @import url(y.css) screen;
body{background:url(../img/bg.png)} @font-face{src:url('/f/a.woff2') format("woff2"),url( "/f/a.woff" )}
/* a{background:url(/gone.png)} */ i{background:url(data:image/png;base64,AAAA)} b{background:url(../img/bg.png)}`, base)
	want := []CSSRef{
		{"http://h/css/more.css", true}, {"http://h/lib/x.css", true}, {"http://h/css/y.css", true},
		{"http://h/img/bg.png", false}, {"http://h/f/a.woff2", false}, {"http://h/f/a.woff", false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("refs %v\nwant %v", got, want)
	}
}
