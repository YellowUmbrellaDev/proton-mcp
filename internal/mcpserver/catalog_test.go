package mcpserver

import (
	"strings"
	"testing"
)

func TestCatalogCoversTheCommandTree(t *testing.T) {
	tools, left, err := Catalog(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(tools)+len(left) != 448 {
		t.Fatalf("every runnable command is a tool or has a reason: %d tools + %d left out != 448", len(tools), len(left))
	}
	t.Logf("%d tools, %d left out", len(tools), len(left))
	for k, why := range left {
		t.Logf("left out: %-28s %s", k, why)
	}
	for _, tool := range tools {
		if len(tool.Name) > 64 {
			t.Errorf("tool name too long (%d): %s", len(tool.Name), tool.Name)
		}
		if strings.ContainsAny(tool.Name, " -") {
			t.Errorf("bad tool name %q", tool.Name)
		}
		schema(tool) // must not panic
	}
}

func TestEveryToolRegisters(t *testing.T) {
	_, tools, err := newForTest()
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) < 400 {
		t.Fatalf("only %d tools registered", len(tools))
	}
}
