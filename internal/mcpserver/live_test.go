package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// live runs against a real saved session: PROTON_MCP_LIVE=<profile>, with
// XDG_CONFIG_HOME pointing at the directory that holds it.
func live(t *testing.T) *mcp.ClientSession {
	profile := os.Getenv("PROTON_MCP_LIVE")
	if profile == "" {
		t.Skip("PROTON_MCP_LIVE not set")
	}
	srv, _, err := New(Config{
		Version: "live",
		Runner:  func(context.Context) (Runner, error) { return Runner{Profile: profile}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	a, b := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, a, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(ctx, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		switch c := c.(type) {
		case *mcp.TextContent:
			sb.WriteString(c.Text)
		case *mcp.EmbeddedResource:
			sb.WriteString("[blob " + c.Resource.URI + "]")
		}
	}
	return sb.String(), res.IsError
}

func TestLiveRead(t *testing.T) {
	cs := live(t)
	tools, _ := cs.ListTools(context.Background(), nil)
	t.Logf("tools listed over MCP: %d", len(tools.Tools))

	out, isErr := call(t, cs, "mail_messages_list", map[string]any{"limit": 2})
	t.Logf("mail_messages_list isErr=%v bytes=%d", isErr, len(out))
	if isErr {
		t.Fatal(out)
	}
	var env struct {
		Items []struct{ ID, Subject string } `json:"messages"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || len(env.Items) == 0 {
		t.Fatalf("no items parsed: %v\n%.300s", err, out)
	}
	id := env.Items[0].ID
	body, isErr := call(t, cs, "mail_messages_get", map[string]any{"ref": id})
	t.Logf("mail_messages_get isErr=%v bytes=%d", isErr, len(body))
	if isErr || len(body) < 100 {
		t.Fatal(body)
	}
	for _, name := range []string{"calendar_events_list", "drive_items_list", "contacts_list", "account_get", "pass_vaults_list"} {
		o, e := call(t, cs, name, map[string]any{})
		t.Logf("%-22s isErr=%-5v bytes=%-6d %.90q", name, e, len(o), strings.ReplaceAll(o, "\n", " "))
	}
}

func field(t *testing.T, raw, key string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("not JSON: %v\n%.300s", err, raw)
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	t.Fatalf("no %q in %.300s", key, raw)
	return ""
}

// TestLiveWrite creates things of its own with a unique name, reads them back,
// and removes them.
func TestLiveWrite(t *testing.T) {
	cs := live(t)
	tag := "proton-mcp-test-" + time.Now().Format("150405")
	ok := func(name string, args map[string]any) string {
		out, isErr := call(t, cs, name, args)
		t.Logf("%-28s err=%-5v %.110q", name, isErr, strings.ReplaceAll(out, "\n", " "))
		if isErr {
			t.Fatalf("%s failed: %s", name, out)
		}
		return out
	}

	// --- Drive: folder, upload (file content travels in the request), download.
	dir := "/" + tag
	t.Cleanup(func() {
		call(t, cs, "drive_items_delete", map[string]any{"path": []any{dir}, "confirm": true})
	})
	ok("drive_items_create", map[string]any{"path": dir})
	ok("drive_items_upload", map[string]any{
		"src":  map[string]any{"name": "hello.txt", "text": "hola desde el MCP\n"},
		"dest": dir,
	})
	got := ok("drive_items_download", map[string]any{"path": dir + "/hello.txt"})
	if !strings.Contains(got, "hola desde el MCP") {
		t.Errorf("download did not return the uploaded content: %q", got)
	}

	// An irreversible command without confirm is only previewed.
	pre, _ := call(t, cs, "drive_items_delete", map[string]any{"path": []any{dir}})
	if !strings.Contains(pre, "Nothing was changed") {
		t.Errorf("unconfirmed delete was not held back: %.200s", pre)
	}
	ls := ok("drive_items_list", map[string]any{"path": dir})
	if !strings.Contains(ls, "hello.txt") {
		t.Errorf("the preview must not have deleted the file: %.200s", ls)
	}
	ok("drive_items_delete", map[string]any{"path": []any{dir}, "confirm": true})

	// --- Contacts: create, update, delete.
	c := ok("contacts_create", map[string]any{"name": tag, "email": []any{tag + "@example.com"}})
	_ = c
	list := ok("contacts_list", map[string]any{"keyword": tag})
	var cl struct {
		Contacts []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"contacts"`
	}
	if err := json.Unmarshal([]byte(list), &cl); err != nil || len(cl.Contacts) != 1 {
		t.Fatalf("expected exactly the contact just made: %v\n%.300s", err, list)
	}
	id := cl.Contacts[0].ID
	ok("contacts_update", map[string]any{"ref": id, "organization": []any{"MCP test"}})
	got = ok("contacts_get", map[string]any{"ref": id})
	if !strings.Contains(got, "MCP test") {
		t.Errorf("update not visible: %.300s", got)
	}
	ok("contacts_delete", map[string]any{"ref": []any{id}, "confirm": true})

	// --- Mail: a draft with an attachment, read back, then removed.
	ok("mail_drafts_create", map[string]any{
		"to": []any{tag + "@example.com"}, "subject": tag, "body": "borrador de prueba",
		"attach": []any{map[string]any{"name": "nota.txt", "text": "adjunto"}},
	})
	dl := ok("mail_drafts_list", map[string]any{})
	var dr struct {
		Drafts []struct{ ID, Subject string } `json:"drafts"`
	}
	_ = json.Unmarshal([]byte(dl), &dr)
	n := 0
	for _, m := range dr.Drafts {
		if m.Subject == tag {
			n++
			ok("mail_drafts_delete", map[string]any{"ref": []any{m.ID}, "confirm": true})
		}
	}
	if n != 1 {
		t.Errorf("expected one draft with subject %s, found %d", tag, n)
	}
}

// TestLiveSweep calls every read-only tool that needs no input and reports the
// ones that fail, so a systematic mistake in how arguments are built shows up as
// a pattern.
func TestLiveSweep(t *testing.T) {
	cs := live(t)
	tools, _, _ := Catalog(Options{})
	type res struct {
		name string
		out  string
		err  bool
		took time.Duration
	}
	jobs := make(chan Tool)
	results := make(chan res)
	for i := 0; i < 4; i++ {
		go func() {
			for tool := range jobs {
				start := time.Now()
				out, e := call(t, cs, tool.Name, map[string]any{})
				results <- res{tool.Name, out, e, time.Since(start)}
			}
		}()
	}
	n := 0
	go func() {
		for _, tool := range tools {
			if tool.Mutating || tool.Download {
				continue
			}
			required := false
			for _, p := range tool.Params {
				required = required || p.Required
			}
			if required {
				continue
			}
			n++
			jobs <- tool
		}
		close(jobs)
	}()
	failed, slowest := 0, res{}
	time.Sleep(time.Second)
	for i := 0; ; i++ {
		select {
		case r := <-results:
			if r.took > slowest.took {
				slowest = r
			}
			if r.err {
				failed++
				t.Logf("FAIL %-44s %.130q", r.name, strings.ReplaceAll(r.out, "\n", " "))
			}
		case <-time.After(30 * time.Second):
			t.Logf("swept %d read tools, %d returned an error; slowest %s took %s", n, failed, slowest.name, slowest.took)
			return
		}
	}
}
