package lazyre

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestLazyCompilesOnUseOnly(t *testing.T) {
	r := New(`^a(b+)c$`)
	if r.re != nil {
		t.Fatal("compiled before use")
	}
	if got := r.FindStringSubmatch("abbc"); len(got) != 2 || got[1] != "bb" {
		t.Errorf("%q", got)
	}
	if r.String() != `^a(b+)c$` || !r.MatchString("abc") || r.MatchString("ac") {
		t.Error("match")
	}
}

func TestCompileAllFindsABadExpression(t *testing.T) {
	if err := CompileAll(); err != nil {
		t.Fatalf("an expression made so far does not compile: %v", err)
	}
	bad := New(`(`)
	defer func() {
		mu.Lock()
		all = all[:len(all)-1]
		mu.Unlock()
	}()
	if err := CompileAll(); err == nil {
		t.Error("an invalid expression passed")
	}
	_ = bad
}

// A package-level regexp.MustCompile builds its program in every command's
// start-up: they are lazyre.New.
func TestNoEagerPackageLevelRegexps(t *testing.T) {
	root := filepath.Join("..", "..")
	var eager []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || name == "bench" || name == "testdata" || name == "fixtures") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			ast.Inspect(gd, func(n ast.Node) bool {
				if _, ok := n.(*ast.FuncLit); ok {
					return false // run when called
				}
				if c, ok := n.(*ast.CallExpr); ok {
					if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "MustCompile" {
						if x, ok := s.X.(*ast.Ident); ok && x.Name == "regexp" {
							eager = append(eager, path)
						}
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(eager) > 0 {
		t.Errorf("package-level regexp.MustCompile (use lazyre.New): %v", eager)
	}
}
