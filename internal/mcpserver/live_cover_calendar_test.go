package mcpserver

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// TestCoverCalendar calls every calendar tool nobody had run yet.
//
// REAL runs touch only a throwaway calendar named proton-mcp-test-* and an event
// of ours in it (no attendees). Everything that publishes (links, booking pages),
// shares, answers invitations or changes the account's existing settings is DRY.
//
// Deleting a calendar needs the account password. PROTON_MCP_PASSWORD_FILE names
// a file holding it: with it the test makes its own calendar and really deletes
// it. Without it the test reuses a leftover proton-mcp-test-* calendar (making
// one only when none exists) and only previews the delete.
func TestCoverCalendar(t *testing.T) {
	cs := live(t)
	tag := "proton-mcp-test-" + time.Now().Format("20060102-150405")
	pwFile := os.Getenv("PROTON_MCP_PASSWORD_FILE")
	var pw string
	if pwFile != "" {
		b, err := os.ReadFile(pwFile)
		if err != nil {
			t.Fatal(err)
		}
		pw = strings.TrimRight(string(b), "\r\n")
	}

	run := func(name string, args map[string]any) (string, bool) {
		t.Helper()
		out, isErr := call(t, cs, name, args)
		t.Logf("%-40s err=%-5v %.150q", name, isErr, strings.ReplaceAll(out, "\n", " "))
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
	// clean is a tool that may legitimately refuse: the refusal must be a CLI
	// sentence naming the problem, never empty or a Go error dump.
	clean := func(name string, args map[string]any, wantInErr ...string) {
		t.Helper()
		out, isErr := run(name, args)
		if !isErr {
			return
		}
		if strings.TrimSpace(out) == "" || strings.Contains(out, "panic") || strings.Contains(out, "goroutine") {
			t.Errorf("%s: unclear error %q", name, out)
		}
		for _, w := range wantInErr {
			if !strings.Contains(strings.ToLower(out), strings.ToLower(w)) {
				t.Errorf("%s: error %q does not mention %q", name, out, w)
			}
		}
	}
	one := func(raw string) string {
		var m struct {
			IDs []string `json:"ids"`
		}
		_ = json.Unmarshal([]byte(raw), &m)
		if len(m.IDs) != 1 {
			t.Fatalf("expected one id in %.200s", raw)
		}
		return m.IDs[0]
	}

	// --- Fixture: a calendar of our own.
	type cal struct{ ID, Name string }
	listCals := func() []cal {
		out := ok("calendar_settings_calendars_list", map[string]any{})
		var m struct {
			Calendars []cal `json:"calendars"`
		}
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("calendars list is not JSON: %v\n%.300s", err, out)
		}
		return m.Calendars
	}
	var calID, calName string
	if pw != "" {
		calName = tag
		calID = one(ok("calendar_settings_calendars_create", map[string]any{"name": calName, "color": "purple"}))
		t.Cleanup(func() {
			call(t, cs, "calendar_settings_calendars_delete", map[string]any{"ref": []any{calID}, "password": pw, "confirm": true})
		})
	} else {
		for _, c := range listCals() {
			if strings.HasPrefix(c.Name, "proton-mcp-test-") {
				calID, calName = c.ID, c.Name
			}
		}
		if calID == "" {
			calName = tag
			calID = one(ok("calendar_settings_calendars_create", map[string]any{"name": calName}))
			t.Logf("created %s (%s); deleting it needs the account password, so it stays", calName, calID)
		} else {
			ok("calendar_settings_calendars_create", map[string]any{"name": tag + "-dry", "dry_run": true})
		}
	}

	// --- REAL on our calendar.
	if got := ok("calendar_settings_calendars_get", map[string]any{"ref": calID}); !strings.Contains(got, calName) {
		t.Errorf("calendar get lacks its name: %.300s", got)
	}
	ok("calendar_settings_calendars_update", map[string]any{"ref": calID, "color": "pacific", "default_duration": "30m", "remind": []any{"15m"}, "busy": "off"})
	if got := ok("calendar_settings_calendars_get", map[string]any{"ref": calID}); !strings.Contains(got, `"default_duration_minutes": 30`) {
		t.Errorf("calendar update not visible: %.400s", got)
	}
	// Nobody but the owner is on it.
	if got := ok("calendar_settings_calendars_share_get", map[string]any{"ref": calID}); !strings.Contains(got, "owner") {
		t.Errorf("share get does not show the owner: %.300s", got)
	}

	day := time.Now().UTC().AddDate(0, 0, 9).Format("2006-01-02")
	ev := one(ok("calendar_events_create", map[string]any{
		"title": tag + "-ev", "start": day + "T10:00", "duration": "1h", "calendar": calID,
	}))
	evRef := ev // the id already carries its calendar
	t.Cleanup(func() { call(t, cs, "calendar_events_delete", map[string]any{"ref": []any{evRef}, "confirm": true}) })

	exp, blob, isErr := callRaw(t, cs, "calendar_events_export", map[string]any{"calendar": calID, "after": day, "before": day})
	t.Logf("calendar_events_export err=%v %d bytes", isErr, len(exp)+len(blob))
	if isErr {
		t.Fatalf("export failed: %s", exp)
	}
	if !strings.Contains(exp, "BEGIN:VCALENDAR") || !strings.Contains(exp, tag+"-ev") {
		t.Errorf("export lacks our event: %.400s", exp)
	}

	// Our own event has no invitation to answer: a clean refusal, or an answer
	// that reaches nobody.
	clean("calendar_events_respond", map[string]any{"ref": evRef, "answer": "accept"})

	if out, _ := run("calendar_busy_times_list", map[string]any{"email": []any{"me@sigterm.vodka"}, "after": day, "before": day}); out == "" {
		t.Error("busy times returned nothing at all")
	}

	// --- READ on existing booking pages: only reads.
	pages := ok("calendar_booking_pages_list", map[string]any{})
	var pl struct {
		Pages []struct{ ID, Title string } `json:"booking_pages"`
	}
	if err := json.Unmarshal([]byte(pages), &pl); err != nil || len(pl.Pages) == 0 {
		t.Logf("no booking page to read (%v): %.200s", err, pages)
		clean("calendar_booking_pages_get", map[string]any{"ref": tag})
	} else {
		ok("calendar_booking_pages_get", map[string]any{"ref": pl.Pages[0].ID})
	}
	pageRef := tag
	if len(pl.Pages) > 0 {
		pageRef = pl.Pages[0].ID
	}

	// --- DRY: publishing, sharing, answering, and the account's own settings.
	ok("calendar_booking_pages_create", map[string]any{
		"title": tag + "-page", "calendar": calID, "duration": "30m", "notice": "2h",
		"available": []any{"mon-fri=09:00-12:00"}, "description": "x", "location": "MCP", "dry_run": true,
	})
	ok("calendar_booking_pages_update", map[string]any{"ref": pageRef, "duration": "1h", "notice": "48h", "dry_run": true})
	ok("calendar_booking_pages_delete", map[string]any{"ref": []any{pageRef}, "dry_run": true})
	if out, _ := run("calendar_booking_pages_delete", map[string]any{"ref": []any{pageRef}}); !strings.Contains(out, "Nothing was changed") {
		t.Errorf("an irreversible tool without confirm must only preview: %.200s", out)
	}

	ok("calendar_settings_links_create", map[string]any{"ref": calID, "access": "limited", "name": tag + "-link", "dry_run": true})
	clean("calendar_settings_links_get", map[string]any{"ref": tag + "-link"}, "link")
	clean("calendar_settings_links_update", map[string]any{"ref": tag + "-link", "name": "x", "dry_run": true}, "link")
	clean("calendar_settings_links_revoke", map[string]any{"ref": []any{tag + "-link"}, "dry_run": true}, "link")

	ok("calendar_settings_calendars_share_add", map[string]any{"ref": calID, "email": "nobody@example.invalid", "access": "editor", "dry_run": true})
	clean("calendar_settings_calendars_share_update", map[string]any{"ref": calID, "email": "nobody@example.invalid", "access": "viewer", "dry_run": true})
	clean("calendar_settings_calendars_share_remove", map[string]any{"ref": calID, "email": "nobody@example.invalid", "dry_run": true})

	clean("calendar_invitations_accept", map[string]any{"ref": []any{tag + "-none"}, "dry_run": true})
	clean("calendar_invitations_decline", map[string]any{"ref": []any{tag + "-none"}, "dry_run": true})
	// Leaving a calendar only works on one somebody shared with us; ours is ours.
	clean("calendar_settings_calendars_leave", map[string]any{"ref": []any{calID}, "dry_run": true})

	ok("calendar_settings_set", map[string]any{"key": "view", "value": "week", "dry_run": true})

	// Deleting a calendar asks for the password: previewed here unless the test has one.
	if pw == "" {
		ok("calendar_settings_calendars_delete", map[string]any{"ref": []any{calID}, "dry_run": true})
	} else {
		ok("calendar_events_delete", map[string]any{"ref": []any{evRef}, "confirm": true})
		ok("calendar_settings_calendars_delete", map[string]any{"ref": []any{calID}, "password": pw, "confirm": true})
		for _, c := range listCals() {
			if c.ID == calID {
				t.Errorf("calendar %s survived its delete", calName)
			}
		}
	}
}
