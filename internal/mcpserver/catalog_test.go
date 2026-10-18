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

func TestSendingMailNeedsConfirm(t *testing.T) {
	tools, _, err := Catalog(Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"mail_messages_send": true, "mail_messages_reply": true, "mail_messages_forward": true, "mail_drafts_delete": true, "drive_items_delete": true, "contacts_merge": true}
	for _, tool := range tools {
		if want[tool.Name] && !tool.Irreversible {
			t.Errorf("%s runs without confirm", tool.Name)
		}
		delete(want, tool.Name)
	}
	for n := range want {
		t.Errorf("tool %s does not exist", n)
	}
}

// A verify command sends an email or an SMS, or confirms an address. It has to
// be a write tool: advertised as read-only with no dry_run, a caller could not
// preview it.
func TestVerifyToolsAreWriteTools(t *testing.T) {
	tools, _, err := Catalog(Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, tool := range tools {
		if tool.Path[len(tool.Path)-1] != "verify" {
			continue
		}
		found++
		if !tool.Mutating {
			t.Errorf("%s is not marked as a write tool", tool.Name)
		}
		if _, ok := schema(tool)["properties"].(map[string]any)["dry_run"]; !ok {
			t.Errorf("%s has no dry_run input", tool.Name)
		}
		if a := annotations(tool); a.ReadOnlyHint {
			t.Errorf("%s is advertised as read-only", tool.Name)
		}
	}
	if found != 4 {
		t.Errorf("expected 4 verify tools, found %d", found)
	}
}
