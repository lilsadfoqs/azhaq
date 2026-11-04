package gqlschema

import (
	"os"
	"strings"
	"testing"
)

// The SDL adds a schema { … } block only when a root type is not simply
// Query, Mutation or Subscription.
func TestSDLAddsASchemaBlockOnlyForOtherRootTypeNames(t *testing.T) {
	data, err := os.ReadFile("testdata/introspection.json")
	if err != nil {
		t.Fatal(err)
	}
	_, other, ok := Read(data)
	if !ok || !strings.HasPrefix(other.SDL(), "schema {\n  query: Root\n") {
		t.Fatalf("a query root named Root: %.80s", other.SDL())
	}
	renamed := strings.ReplaceAll(string(data), `"Root"`, `"Query"`)
	_, plain, ok := Read([]byte(renamed))
	if !ok {
		t.Fatal("no schema after renaming the root")
	}
	if strings.Contains(plain.SDL(), "schema {") || !strings.Contains(plain.SDL(), "type Query {") {
		t.Errorf("roots Query, Mutation and Subscription: %.120s", plain.SDL())
	}
}
