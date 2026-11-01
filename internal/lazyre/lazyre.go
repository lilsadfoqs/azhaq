// Package lazyre holds regular expressions that compile on first use. A
// package-level regexp.MustCompile builds its program when the program
// starts, whichever command runs; a command that never matches it should
// not pay for it in memory or start-up time.
package lazyre

import (
	"regexp"
	"sync"
)

var (
	mu  sync.Mutex
	all []*Regexp
)

// Regexp is a regexp.Regexp built when it is first used.
type Regexp struct {
	src  string
	once sync.Once
	re   *regexp.Regexp
}

// New is regexp.MustCompile, deferred: an invalid expression panics at its
// first use, and CompileAll finds it before then (a test calls it).
func New(src string) *Regexp {
	r := &Regexp{src: src}
	mu.Lock()
	all = append(all, r)
	mu.Unlock()
	return r
}

// CompileAll compiles every expression made so far and returns the first
// error, or nil.
func CompileAll() error {
	mu.Lock()
	list := append([]*Regexp(nil), all...)
	mu.Unlock()
	for _, r := range list {
		if _, err := regexp.Compile(r.src); err != nil {
			return err
		}
	}
	return nil
}

func (r *Regexp) get() *regexp.Regexp {
	r.once.Do(func() { r.re = regexp.MustCompile(r.src) })
	return r.re
}

func (r *Regexp) String() string { return r.src }

func (r *Regexp) MatchString(s string) bool { return r.get().MatchString(s) }
func (r *Regexp) Match(b []byte) bool       { return r.get().Match(b) }
func (r *Regexp) SubexpIndex(name string) int {
	return r.get().SubexpIndex(name)
}
func (r *Regexp) SubexpNames() []string { return r.get().SubexpNames() }
func (r *Regexp) NumSubexp() int        { return r.get().NumSubexp() }

func (r *Regexp) Find(b []byte) []byte                 { return r.get().Find(b) }
func (r *Regexp) FindIndex(b []byte) []int             { return r.get().FindIndex(b) }
func (r *Regexp) FindSubmatch(b []byte) [][]byte       { return r.get().FindSubmatch(b) }
func (r *Regexp) FindSubmatchIndex(b []byte) []int     { return r.get().FindSubmatchIndex(b) }
func (r *Regexp) FindAll(b []byte, n int) [][]byte     { return r.get().FindAll(b, n) }
func (r *Regexp) FindAllIndex(b []byte, n int) [][]int { return r.get().FindAllIndex(b, n) }
func (r *Regexp) FindAllSubmatch(b []byte, n int) [][][]byte {
	return r.get().FindAllSubmatch(b, n)
}
func (r *Regexp) FindAllSubmatchIndex(b []byte, n int) [][]int {
	return r.get().FindAllSubmatchIndex(b, n)
}

func (r *Regexp) FindString(s string) string             { return r.get().FindString(s) }
func (r *Regexp) FindStringIndex(s string) []int         { return r.get().FindStringIndex(s) }
func (r *Regexp) FindStringSubmatch(s string) []string   { return r.get().FindStringSubmatch(s) }
func (r *Regexp) FindStringSubmatchIndex(s string) []int { return r.get().FindStringSubmatchIndex(s) }
func (r *Regexp) FindAllString(s string, n int) []string { return r.get().FindAllString(s, n) }
func (r *Regexp) FindAllStringIndex(s string, n int) [][]int {
	return r.get().FindAllStringIndex(s, n)
}
func (r *Regexp) FindAllStringSubmatch(s string, n int) [][]string {
	return r.get().FindAllStringSubmatch(s, n)
}
func (r *Regexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	return r.get().FindAllStringSubmatchIndex(s, n)
}

func (r *Regexp) ReplaceAllString(src, repl string) string {
	return r.get().ReplaceAllString(src, repl)
}
func (r *Regexp) ReplaceAllLiteralString(src, repl string) string {
	return r.get().ReplaceAllLiteralString(src, repl)
}
func (r *Regexp) ReplaceAllStringFunc(src string, f func(string) string) string {
	return r.get().ReplaceAllStringFunc(src, f)
}
func (r *Regexp) ReplaceAll(src, repl []byte) []byte { return r.get().ReplaceAll(src, repl) }
func (r *Regexp) ReplaceAllFunc(src []byte, f func([]byte) []byte) []byte {
	return r.get().ReplaceAllFunc(src, f)
}
func (r *Regexp) Split(s string, n int) []string { return r.get().Split(s, n) }
