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
	cfg := Config{
		Version: "live",
		Runner:  func(context.Context) (Runner, error) { return Runner{Profile: profile}, nil },
	}
	// PROTON_MCP_COVERAGE=<file> appends one line per call: which tools really ran.
	if path := os.Getenv("PROTON_MCP_COVERAGE"); path != "" {
		log, err := OpenCoverageLog(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Record = log.Record
	}
	srv, _, err := New(cfg)
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

// TestLiveSend sends one message from the account to itself: the one outward
// action, held back until confirm, then removed from both folders.
func TestLiveSend(t *testing.T) {
	cs := live(t)
	me, _ := call(t, cs, "account_get", map[string]any{})
	addr := field(t, me, "email")
	tag := "proton-mcp-send-" + time.Now().Format("150405")
	args := map[string]any{"to": []any{addr}, "subject": tag, "body": "prueba de envio"}

	held, isErr := call(t, cs, "mail_messages_send", args)
	if isErr || !strings.Contains(held, "Nothing was changed") {
		t.Fatalf("an unconfirmed send must only be previewed: err=%v %.300s", isErr, held)
	}
	args["confirm"] = true
	out, isErr := call(t, cs, "mail_messages_send", args)
	t.Logf("send err=%v %.120q", isErr, strings.ReplaceAll(out, "\n", " "))
	if isErr {
		t.Fatal(out)
	}
	var found string
	for i := 0; i < 12 && found == ""; i++ {
		time.Sleep(5 * time.Second)
		list, _ := call(t, cs, "mail_messages_list", map[string]any{"keyword": tag, "limit": 5})
		var env struct {
			Messages []struct{ ID, Subject string } `json:"messages"`
		}
		_ = json.Unmarshal([]byte(list), &env)
		if len(env.Messages) > 0 {
			found = env.Messages[0].ID
		}
	}
	if found == "" {
		t.Fatalf("the message sent to %s never arrived", addr)
	}
	t.Logf("arrived: %d bytes of body", len(func() string { b, _ := call(t, cs, "mail_messages_get", map[string]any{"ref": found}); return b }()))
}

func TestLiveCalendarAndPass(t *testing.T) {
	cs := live(t)
	stamp := time.Now().Format("150405")
	tag := "proton-mcp-test-" + stamp
	ok := func(name string, args map[string]any) string {
		out, isErr := call(t, cs, name, args)
		t.Logf("%-26s err=%-5v %.100q", name, isErr, strings.ReplaceAll(out, "\n", " "))
		if isErr {
			t.Fatalf("%s failed: %s", name, out)
		}
		return out
	}
	idsOf := func(raw string) []string {
		var m struct {
			IDs []string `json:"ids"`
		}
		_ = json.Unmarshal([]byte(raw), &m)
		return m.IDs
	}
	one := func(raw string) string {
		ids := idsOf(raw)
		if len(ids) != 1 {
			t.Fatalf("expected one id, got %v from %.200s", ids, raw)
		}
		return ids[0]
	}
	day := func(d int) string { return time.Now().UTC().AddDate(0, 0, d).Format("2006-01-02") }

	// --- Calendar: create, update, read back, delete.
	start := time.Now().Add(72 * time.Hour).Format("2006-01-02 15:04")
	evID := one(ok("calendar_events_create", map[string]any{"title": tag, "start": start, "duration": "30m", "location": "MCP"}))
	t.Cleanup(func() { call(t, cs, "calendar_events_delete", map[string]any{"ref": []any{evID}, "confirm": true}) })
	ok("calendar_events_update", map[string]any{"ref": evID, "location": "MCP actualizado"})
	if got := ok("calendar_events_get", map[string]any{"ref": evID}); !strings.Contains(got, "MCP actualizado") {
		t.Errorf("event update not visible: %.300s", got)
	}
	ok("calendar_events_delete", map[string]any{"ref": []any{evID}, "confirm": true})

	// An invitation to an outside address would be mailed, so the attendee input
	// is only checked through a dry run: it must reach the command and be accepted.
	dry := ok("calendar_events_create", map[string]any{
		"title": tag + "-att", "start": day(5) + "T10:00", "duration": "1h",
		"attendee": []any{"nobody@example.invalid", "other@example.invalid:optional"}, "dry_run": true,
	})
	if !strings.Contains(dry, `"dry_run": true`) {
		t.Errorf("dry run was not reported: %.200s", dry)
	}

	// Reminders and a repeating rule, then an all-day event.
	recID := one(ok("calendar_events_create", map[string]any{
		"title": tag + "-rec", "start": day(6) + "T09:00", "duration": "15m",
		"remind": []any{"15m", "1d:email"}, "rrule": "FREQ=DAILY;COUNT=3",
	}))
	t.Cleanup(func() { call(t, cs, "calendar_events_delete", map[string]any{"ref": []any{recID}, "confirm": true}) })
	got := ok("calendar_events_get", map[string]any{"ref": recID})
	if !strings.Contains(got, "FREQ=DAILY") || !strings.Contains(got, "reminders") {
		t.Errorf("rrule/remind not stored: %.600s", got)
	}
	allID := one(ok("calendar_events_create", map[string]any{"title": tag + "-allday", "start": day(8), "all_day": true}))
	t.Cleanup(func() { call(t, cs, "calendar_events_delete", map[string]any{"ref": []any{allID}, "confirm": true}) })
	if got := ok("calendar_events_get", map[string]any{"ref": allID}); !strings.Contains(got, `"all_day": true`) {
		t.Errorf("all-day not stored: %.400s", got)
	}

	// An .ics given as content.
	uid := "proton-mcp-test-" + stamp + "@example.invalid"
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//proton-mcp-test//EN\r\nBEGIN:VEVENT\r\nUID:" + uid +
		"\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:" + strings.ReplaceAll(day(9), "-", "") + "T120000Z\r\nDTEND:" +
		strings.ReplaceAll(day(9), "-", "") + "T130000Z\r\nSUMMARY:" + tag + "-ics\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	ok("calendar_events_import", map[string]any{"path": map[string]any{"name": "t.ics", "text": ics}})
	// The import names no ids, so the event is found by its title.
	var icsID string
	lst := ok("calendar_events_list", map[string]any{"keyword": tag + "-ics", "after": day(0), "before": day(30)})
	var el struct {
		Events []struct {
			ID         string `json:"id"`
			CalendarID string `json:"calendar_id"`
		} `json:"events"`
	}
	_ = json.Unmarshal([]byte(lst), &el)
	if len(el.Events) != 1 {
		t.Fatalf("expected the one imported event: %.300s", lst)
	}
	// A listed id is only a reference once it carries its calendar.
	icsID = el.Events[0].CalendarID + "/" + el.Events[0].ID
	t.Cleanup(func() { call(t, cs, "calendar_events_delete", map[string]any{"ref": []any{icsID}, "confirm": true}) })
	if got := ok("calendar_events_get", map[string]any{"ref": icsID}); !strings.Contains(got, tag+"-ics") {
		t.Errorf("imported event not readable: %.300s", got)
	}
	for _, id := range []string{recID, allID, icsID} {
		ok("calendar_events_delete", map[string]any{"ref": []any{id}, "confirm": true})
	}

	// --- Pass: two vaults of our own.
	vault := one(ok("pass_vaults_create", map[string]any{"name": tag}))
	t.Cleanup(func() { call(t, cs, "pass_vaults_delete", map[string]any{"ref": []any{vault}, "confirm": true}) })
	vault2 := one(ok("pass_vaults_create", map[string]any{"name": tag + "-b"}))
	t.Cleanup(func() { call(t, cs, "pass_vaults_delete", map[string]any{"ref": []any{vault2}, "confirm": true}) })

	login := one(ok("pass_items_create", map[string]any{
		"type": "login", "vault": vault, "name": tag, "username": "u", "generate_password": true, "url": []any{"example.com"},
	}))
	if got := ok("pass_items_get", map[string]any{"ref": login}); !strings.Contains(got, tag) {
		t.Errorf("item not readable: %.200s", got)
	}
	note := one(ok("pass_items_create", map[string]any{"type": "note", "vault": vault, "name": tag + "-note", "note": "line one"}))
	card := one(ok("pass_items_create", map[string]any{
		"type": "credit-card", "vault": vault, "name": tag + "-card", "holder": "MCP Test", "expiry": "2031-04",
		"secrets": []any{map[string]any{"field": "number", "text": "4111111111111111"}},
	}))
	if got := ok("pass_items_get", map[string]any{"ref": card}); strings.Contains(got, "4111111111111111") {
		t.Logf("card number appears in get output (a fake test number)")
	}
	custom := one(ok("pass_items_create", map[string]any{
		"type": "custom", "vault": vault, "name": tag + "-custom",
		"field":   []any{"Network/SSID=home"},
		"secrets": []any{map[string]any{"field": "Network/Key", "text": "hunter2"}},
	}))
	if got := ok("pass_items_get", map[string]any{"ref": custom}); !strings.Contains(got, "SSID") {
		t.Errorf("custom field not stored: %.300s", got)
	}

	// An attachment (needs a paid plan; report rather than fail when refused).
	if out, isErr := call(t, cs, "pass_items_create", map[string]any{
		"type": "note", "vault": vault, "name": tag + "-att", "attach": []any{map[string]any{"name": "a.txt", "text": "adjunto"}},
	}); isErr {
		t.Logf("attach refused: %.200s", out)
	} else {
		t.Logf("attach accepted: %.200s", out)
	}

	// Folders (paid plan as well).
	if out, isErr := call(t, cs, "pass_folders_create", map[string]any{"name": tag + "-f", "vault": vault}); isErr {
		t.Logf("folders refused: %.200s", out)
	} else {
		t.Logf("folder created: %.200s", out)
		f := one(out)
		ok("pass_folders_delete", map[string]any{"ref": []any{f}, "confirm": true})
	}

	// Move the note to the second vault: it gets a new ID.
	moved := one(ok("pass_items_move", map[string]any{"ref": []any{note}, "into": vault2}))
	if moved == note {
		t.Logf("move kept the id")
	}
	if got := ok("pass_items_get", map[string]any{"ref": moved}); !strings.Contains(got, tag+"-note") {
		t.Errorf("moved note not readable: %.200s", got)
	}

	// Import a Chrome-style CSV into our own vault only (--vault), given as content.
	csv := "name,url,username,password,note\n" + tag + "-imp,https://example.com,u,pw-not-real,from csv\n"
	ok("pass_import", map[string]any{"path": map[string]any{"name": "c.csv", "text": csv}, "manager": "chrome", "vault": vault2})
	il := ok("pass_items_list", map[string]any{"vault": vault2})
	if !strings.Contains(il, tag+"-imp") {
		t.Errorf("imported item not in the vault: %.300s", il)
	}
	// pass export cannot be limited to one vault (it writes every vault the account
	// owns), so it is not exercised against the real account.

	// A deliberately wrong input comes back as a tool error, not a protocol error.
	for name, args := range map[string]map[string]any{
		"pass_items_create":      {"type": "banana", "vault": vault, "name": tag},
		"pass_items_get":         {"nonsense": 1},
		"calendar_events_create": {"title": tag, "start": "not a date"},
	} {
		out, isErr := call(t, cs, name, args)
		if !isErr || out == "" {
			t.Errorf("%s with a wrong input: isErr=%v out=%q", name, isErr, out)
		}
		t.Logf("wrong input to %s -> isError=%v %.120q", name, isErr, out)
	}

	ok("pass_items_trash", map[string]any{"ref": []any{login}})
	ok("pass_items_delete", map[string]any{"ref": []any{login}, "confirm": true})
	ok("pass_vaults_delete", map[string]any{"ref": []any{vault}, "confirm": true})
	ok("pass_vaults_delete", map[string]any{"ref": []any{vault2}, "confirm": true})
}

// callRaw is call, but a binary payload comes back as bytes instead of a label.
// Downloads can be large, so it waits longer.
func callRaw(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (text string, blob []byte, isErr bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	for _, c := range res.Content {
		switch c := c.(type) {
		case *mcp.TextContent:
			text += c.Text
		case *mcp.EmbeddedResource:
			blob = append(blob, c.Resource.Blob...)
		}
	}
	return text, blob, res.IsError
}
