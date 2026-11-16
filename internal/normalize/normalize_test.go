package normalize

import "testing"

func TestURL(t *testing.T) {
	got, err := URL("HTTPS://Example.COM:443/a#frag")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/a" {
		t.Fatalf("got %q", got)
	}
	// The start of a URL a script builds at run time: no port is no URL.
	if got, err := URL("http://127.0.0.1:/"); err == nil {
		t.Errorf("an empty port: %q", got)
	}
}

// The servlet session id a server writes into its links is not part of
// the page's URL; other path parameters and the query are (#479).
func TestURLDropsTheServletSessionID(t *testing.T) {
	for in, want := range map[string]string{
		"http://h:8161/admin/index.jsp;jsessionid=node01abc.node0": "http://h:8161/admin/index.jsp",
		"http://h/a;JSESSIONID=X1/b.jsp":                           "http://h/a/b.jsp",
		"http://h/login;jsessionid=":                               "http://h/login",
		"http://h/a;v=1;jsessionid=x;w=2?jsessionid=q&p=1":         "http://h/a;v=1;w=2?jsessionid=q&p=1",
		"http://h/a;jsessionidx=1":                                 "http://h/a;jsessionidx=1",
		"http://h/%7Bid%7D;jsessionid=abc":                         "http://h/{id}",
		"http://h/caf%C3%A9;jsessionid=abc":                        "http://h/caf%C3%A9",
	} {
		got, err := URL(in)
		if err != nil || got != want {
			t.Errorf("URL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestHostname(t *testing.T) {
	if Hostname("Ex.COM.") != "ex.com" {
		t.Fatal(Hostname("Ex.COM."))
	}
}

func TestTenant(t *testing.T) {
	for host, want := range map[string]bool{
		"bucket.s3.us-west-2.amazonaws.com": true,
		"acme.github.io":                    true,
		"app.herokuapp.com":                 true,
		"www.hackerone.com":                 false,
		"api.example.co.uk":                 false,
		"juice.lab.test":                    false,
		"127.0.0.1":                         false,
	} {
		if got := Tenant(host); got != want {
			t.Errorf("Tenant(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestUndelegated(t *testing.T) {
	for host, want := range map[string]bool{
		"azqlab.lan":             true,
		"www.corp.lan":           true,
		"app.corp.internal":      true,
		"printer.home.arpa":      true,
		"home.arpa":              true,
		"x.test":                 true, // special-use names are undelegated too
		"acme.github.io":         false,
		"www.example.com":        false,
		"api.example.co.uk":      false,
		"x.web":                  false,
		"1.0.0.127.in-addr.arpa": false,
		"example.arpa":           false,
		"127.0.0.1":              false,
		"":                       false,
	} {
		if got := Undelegated(host); got != want {
			t.Errorf("Undelegated(%q) = %v, want %v", host, got, want)
		}
	}
}

// A hash route is the view's address; any other fragment is not.
func TestClientURL(t *testing.T) {
	for in, want := range map[string]string{
		"HTTP://Shop.test:80/#/administration": "http://shop.test/#/administration",
		"https://shop.test/app#!/admin":        "https://shop.test/app#!/admin",
		"https://shop.test/docs#install":       "https://shop.test/docs",
		"https://shop.test/admin":              "https://shop.test/admin",
	} {
		if got, err := ClientURL(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
}
