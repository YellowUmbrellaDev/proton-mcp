package mcpserver

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const x1ProbeCalendar = "proton-mcp-test-probe-152139"

// officialCLI runs the unmodified proton CLI binary against the same session,
// to check from outside the MCP wrapper what really happened.
func officialCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	bin := officialBinary(t)
	cmd := exec.Command(bin, args...)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "PROTON_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// idsOf reads the IDs a create tool reports: one `id`, or a list under `ids`.
func idsOf(t *testing.T, raw string) []string {
	t.Helper()
	var m struct {
		ID  string   `json:"id"`
		IDs []string `json:"ids"`
	}
	_ = json.Unmarshal([]byte(raw), &m)
	if m.ID != "" {
		return []string{m.ID}
	}
	if len(m.IDs) == 0 {
		t.Fatalf("no id in %.200s", raw)
	}
	return m.IDs
}

// TestExtraX1 executes, for real, the tools earlier runs only previewed: calendar
// links and booking pages on the empty probe calendar, one calendar and one mail
// setting (restored), and emptying a folder of our own.
//
// SMTP tokens and custom domains ask for the account password, which this test
// does not have: it shows the refusal instead.
func TestExtraX1(t *testing.T) {
	cs := live(t)
	own := ownAddress(t)
	tag := "proton-mcp-test-" + time.Now().Format("20060102-150405")
	run := func(name string, args map[string]any) (string, bool) {
		t.Helper()
		out, isErr := call(t, cs, name, args)
		t.Logf("%-38s err=%-5v %.140q", name, isErr, strings.ReplaceAll(out, "\n", " "))
		return out, isErr
	}
	ok := func(name string, args map[string]any) string {
		t.Helper()
		out, isErr := run(name, args)
		if isErr {
			t.Fatalf("%s failed: %s", name, out)
		}
		return out
	}

	// --- The probe calendar, found by its exact name.
	var calID string
	{
		out := ok("calendar_settings_calendars_list", map[string]any{})
		var m struct {
			Calendars []struct{ ID, Name string } `json:"calendars"`
		}
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatal(err)
		}
		for _, c := range m.Calendars {
			if c.Name == x1ProbeCalendar {
				calID = c.ID
			}
		}
		if calID == "" {
			t.Skipf("probe calendar %s does not exist", x1ProbeCalendar)
		}
	}

	// --- (1) Public link to the empty calendar.
	linksOf := func() []struct{ ID, Name string } {
		out := ok("calendar_settings_links_list", map[string]any{"calendar": calID})
		var m struct {
			Links []struct{ ID, Name string } `json:"links"`
		}
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("links list: %v\n%.300s", err, out)
		}
		return m.Links
	}
	if n := len(linksOf()); n != 0 {
		t.Fatalf("probe calendar already has %d links; refusing to touch them", n)
	}
	linkName := tag + "-link"
	var linkID string
	t.Cleanup(func() {
		if linkID != "" {
			call(t, cs, "calendar_settings_links_revoke", map[string]any{"ref": []any{linkID}})
		}
	})
	linkID = idsOf(t, ok("calendar_settings_links_create", map[string]any{"ref": calID, "access": "limited", "name": linkName}))[0]
	// The URL is a secret: assert on it without logging it.
	if raw, isErr := call(t, cs, "calendar_settings_links_get", map[string]any{"ref": linkID}); isErr || !strings.Contains(raw, "https://") || !strings.Contains(raw, linkName) {
		t.Errorf("links get: err=%v lacks a URL or its name (%d bytes)", isErr, len(raw))
	} else {
		t.Logf("calendar_settings_links_get ok, %d bytes (URL not shown)", len(raw))
	}
	ok("calendar_settings_links_update", map[string]any{"ref": linkID, "name": linkName + "-renamed"})
	if ls := linksOf(); len(ls) != 1 || ls[0].ID != linkID || ls[0].Name != linkName+"-renamed" {
		t.Errorf("link rename not visible: %+v", ls)
	}
	ok("calendar_settings_links_revoke", map[string]any{"ref": []any{linkID}})
	if ls := linksOf(); len(ls) != 0 {
		t.Errorf("link survived its revoke: %+v", ls)
	}
	if out, _ := officialCLI(t, "calendar", "settings", "links", "list", "--calendar", calID); !strings.Contains(out, "No links") {
		t.Errorf("official CLI still lists a link: %s", out)
	}
	linkID = ""

	// --- (2) Booking page on the same calendar.
	pageTitle := tag + "-page"
	type page struct{ ID, Title, Notice string }
	pagesOf := func() []page {
		out := ok("calendar_booking_pages_list", map[string]any{})
		var m struct {
			Pages []page `json:"booking_pages"`
		}
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("booking pages list: %v\n%.300s", err, out)
		}
		return m.Pages
	}
	pageGone := func(id string) bool {
		for _, p := range pagesOf() {
			if p.ID == id {
				return false
			}
		}
		return true
	}
	var pageID string
	t.Cleanup(func() {
		if pageID != "" {
			call(t, cs, "calendar_booking_pages_delete", map[string]any{"ref": []any{pageID}, "confirm": true})
		}
	})
	out, isErr := run("calendar_booking_pages_create", map[string]any{
		"title": pageTitle, "calendar": calID, "duration": "30m", "notice": "2h",
		"available": []any{"mon-fri=09:00-12:00"}, "description": "proton-mcp test, safe to delete", "location": "MCP test",
	})
	if isErr {
		t.Errorf("booking page create refused: %s", out)
	} else {
		pageID = idsOf(t, out)[0]
		var found page
		for _, p := range pagesOf() {
			if p.ID == pageID {
				found = p
			}
		}
		if found.Title != pageTitle || found.Notice != "2h" {
			t.Errorf("created page not as asked: %+v", found)
		}
		ok("calendar_booking_pages_update", map[string]any{"ref": pageID, "notice": "48h", "duration": "1h", "title": pageTitle + "-b"})
		found = page{}
		for _, p := range pagesOf() {
			if p.ID == pageID {
				found = p
			}
		}
		if found.Title != pageTitle+"-b" || found.Notice != "48h" {
			t.Errorf("update not visible: %+v", found)
		}
		// Held until confirmed.
		if o, _ := run("calendar_booking_pages_delete", map[string]any{"ref": []any{pageID}}); !strings.Contains(o, "Nothing was changed") || pageGone(pageID) {
			t.Errorf("delete without confirm must only preview: %.200s", o)
		}
		ok("calendar_booking_pages_delete", map[string]any{"ref": []any{pageID}, "confirm": true})
		if !pageGone(pageID) {
			t.Errorf("booking page survived its delete")
		}
		if o, _ := officialCLI(t, "calendar", "booking-pages", "list"); strings.Contains(o, "proton-mcp-test") {
			t.Errorf("official CLI still lists our page: %s", o)
		}
		pageID = ""
	}

	// --- (3) One calendar setting, restored.
	settingRestore := func(tool, key, field string, flip map[string]string) {
		raw := ok(tool+"_get", map[string]any{})
		var cur map[string]any
		if err := json.Unmarshal([]byte(raw), &cur); err != nil {
			t.Fatal(err)
		}
		orig, _ := cur[field].(string)
		other, known := flip[orig]
		if !known {
			t.Fatalf("%s %s has unexpected original value %q", tool, field, orig)
		}
		read := func() string {
			var m map[string]any
			_ = json.Unmarshal([]byte(ok(tool+"_get", map[string]any{})), &m)
			s, _ := m[field].(string)
			return s
		}
		t.Cleanup(func() {
			call(t, cs, tool+"_set", map[string]any{"key": key, "value": orig})
		})
		ok(tool+"_set", map[string]any{"key": key, "value": other})
		if got := read(); got != other {
			t.Errorf("%s %s = %q after set, want %q", tool, field, got, other)
		}
		ok(tool+"_set", map[string]any{"key": key, "value": orig})
		if got := read(); got != orig {
			t.Errorf("%s %s = %q after restore, want %q", tool, field, got, orig)
		}
	}
	onoff := map[string]string{"on": "off", "off": "on"}
	settingRestore("calendar_settings", "week-numbers", "week_numbers", onoff)
	// --- (5) One mail setting, restored.
	settingRestore("mail_settings", "unread-favicon", "unread_favicon", onoff)

	// --- (4) and (7): both need the account password, which we do not have.
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"mail_settings_smtp_tokens_create", map[string]any{"ref": own, "name": tag + "-tok"}},
		{"mail_settings_domains_create", map[string]any{"domain": tag + ".invalid"}},
	} {
		out, isErr := run(c.tool, c.args)
		if !isErr || !strings.Contains(strings.ToLower(out), "password") {
			t.Errorf("%s without a password should be refused for it: err=%v %.200s", c.tool, isErr, out)
		}
	}
	if o, e := officialCLI(t, "mail", "settings", "smtp-tokens", "create", own, "--name", tag+"-tok", "--no-input"); e == nil || !strings.Contains(o, "password") {
		t.Errorf("official CLI: %v %s", e, o)
	} else {
		t.Logf("official CLI refuses smtp-tokens create: %.120q", o)
	}
	if o, e := officialCLI(t, "mail", "settings", "domains", "create", tag+".invalid", "--no-input"); e == nil || !strings.Contains(o, "password") {
		t.Errorf("official CLI: %v %s", e, o)
	} else {
		t.Logf("official CLI refuses domains create: %.120q", o)
	}

	// --- (6) mail_messages_empty on a folder of our own holding only our mail.
	me, _ := call(t, cs, "account_get", map[string]any{})
	self := field(t, me, "email")
	folder := tag + "-fld"
	type row struct {
		ID      string `json:"id"`
		Subject string `json:"subject"`
	}
	listIn := func(f string) []row {
		out, isErr := call(t, cs, "mail_messages_list", map[string]any{"folder": f, "limit": 50})
		if isErr {
			return nil
		}
		var m struct {
			Messages []row `json:"messages"`
		}
		_ = json.Unmarshal([]byte(out), &m)
		return m.Messages
	}
	sweep := func() {
		for _, f := range []string{"inbox", "sent", "trash", "archive", "all", folder} {
			for _, m := range listIn(f) {
				if strings.HasPrefix(m.Subject, tag) {
					call(t, cs, "mail_messages_delete", map[string]any{"ref": []any{m.ID}, "confirm": true})
				}
			}
		}
	}
	t.Cleanup(func() {
		sweep()
		call(t, cs, "mail_settings_folders_delete", map[string]any{"ref": []any{folder}, "confirm": true})
	})
	ok("mail_settings_folders_create", map[string]any{"name": folder})
	subjects := []string{tag + "-m1", tag + "-m2"}
	for _, s := range subjects {
		ok("mail_messages_send", map[string]any{"to": []any{self}, "subject": s, "body": "x1 " + s, "confirm": true})
	}
	for _, s := range subjects {
		var id string
		for i := 0; i < 30 && id == ""; i++ {
			for _, m := range listIn("inbox") {
				if m.Subject == s {
					id = m.ID
				}
			}
			if id == "" {
				time.Sleep(4 * time.Second)
			}
		}
		if id == "" {
			t.Fatalf("%s never reached the inbox", s)
		}
		ok("mail_messages_move", map[string]any{"ref": []any{id}, "into": folder})
	}
	// The official CLI must see exactly our two messages in the folder, right before emptying.
	cliFolder := func() (total int, subs []string) {
		out, err := officialCLI(t, "mail", "messages", "list", "--folder", folder, "--limit", "0", "--output", "json")
		if err != nil {
			t.Fatalf("official CLI list: %v %s", err, out)
		}
		var m struct {
			Messages []row `json:"messages"`
			Total    int   `json:"total"`
		}
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("official CLI list not JSON: %v %.200s", err, out)
		}
		for _, r := range m.Messages {
			subs = append(subs, r.Subject)
		}
		return len(m.Messages), subs
	}
	var n int
	var subs []string
	for i := 0; i < 20; i++ {
		n, subs = cliFolder()
		if n == len(subjects) {
			break
		}
		time.Sleep(4 * time.Second)
	}
	if n != len(subjects) {
		t.Fatalf("folder holds %d messages (%v), want exactly ours: %v; not emptying", n, subs, subjects)
	}
	for _, s := range subs {
		if !strings.HasPrefix(s, tag) {
			t.Fatalf("folder holds a message that is not ours (%q); not emptying", s)
		}
	}
	t.Logf("official CLI: folder %s holds exactly our %d messages %v", folder, n, subs)
	if o, _ := run("mail_messages_empty", map[string]any{"folder": folder}); !strings.Contains(o, "Nothing was changed") {
		t.Errorf("empty without confirm must only preview: %.200s", o)
	}
	if n, _ := cliFolder(); n != len(subjects) {
		t.Fatalf("preview changed the folder: %d messages", n)
	}
	ok("mail_messages_empty", map[string]any{"folder": folder, "confirm": true})
	for i := 0; i < 20; i++ {
		if n, _ = cliFolder(); n == 0 {
			break
		}
		time.Sleep(4 * time.Second)
	}
	if n != 0 {
		t.Errorf("folder still holds %d messages after empty", n)
	}
	sweep()
	ok("mail_settings_folders_delete", map[string]any{"ref": []any{folder}, "confirm": true})
}
