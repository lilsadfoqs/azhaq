package portscan

// The readers of a page's own words, for a caller that holds a stored answer
// (its title, its generator meta, its headers) and not the connection: the
// same rules the port scan names a web service by, so `ports` and `run` name
// one page alike.

// TitleProduct names the application a page's <title> names, by the title
// rules the port scan reads a page with, and the version the title itself
// states (Apache Tomcat/9.0.1).
func TitleProduct(title string) (product, version string) { return titleProduct(title, nil) }

// GeneratorProduct reads the content of a generator meta tag: the product and
// the version its last word states.
func GeneratorProduct(content string) (product, version string) { return generatorContent(content) }

// HeaderProduct reads the product and version a Server or X-Powered-By value
// names, as the port scan does.
func HeaderProduct(value string) (product, version string) { return serverProduct(value) }
