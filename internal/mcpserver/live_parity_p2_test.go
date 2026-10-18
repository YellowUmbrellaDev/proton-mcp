package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestParityP2 holds the MCP tools that mutate against the official Proton CLI
// (an independent binary, PROTON_OFFICIAL_CLI) on a real account, and compares
// what they answer. Every call on both sides is a preview: the MCP side with
// dry_run:true, the CLI side with --dry-run. The test refuses to run anything
// else: a case whose CLI line lacks --dry-run or whose MCP input lacks
// dry_run:true for a tool that writes stops the test before it calls anything.
//
// The CLI lines are written by hand from `proton <command> --help`, never
// produced by the wrapper's own argv code, so the two sides are independent.
//
// PARITY_P2_TABLE=<file> also writes a human-readable table.
func TestParityP2(t *testing.T) {
	cs := live(t)
	bin := officialBinary(t)
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("official CLI not found: %v", err)
	}

	// Which tools write, as the MCP server itself declares.
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	writes := map[string]bool{}
	for _, tl := range tools.Tools {
		writes[tl.Name] = tl.Annotations == nil || !tl.Annotations.ReadOnlyHint
	}

	cliRun := func(args ...string) (string, bool) {
		full := append([]string{"--output", "json", "--no-input", "--no-log", "--zone", "UTC"}, args...)
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, full...)
		var out, errw bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errw
		err := cmd.Run()
		if err != nil {
			msg := strings.TrimSpace(errw.String())
			if msg == "" {
				msg = err.Error()
			}
			return msg, true
		}
		return strings.TrimSpace(out.String()), false
	}

	// str prints an ID; a number (a Pass mailbox id) must not turn into 7.5e+06.
	str := func(v any) string {
		if f, ok := v.(float64); ok {
			return strconv.FormatFloat(f, 'f', -1, 64)
		}
		return fmt.Sprint(v)
	}
	// entries returns the list under key in what the CLI printed for cmd.
	entries := func(key string, cmd ...string) []map[string]any {
		out, isErr := cliRun(cmd...)
		if isErr {
			t.Fatalf("%v: %s", cmd, out)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("%v: %v", cmd, err)
		}
		list, _ := m[key].([]any)
		var res []map[string]any
		for _, e := range list {
			if o, ok := e.(map[string]any); ok {
				res = append(res, o)
			}
		}
		if len(res) == 0 {
			t.Fatalf("%v: nothing under %q", cmd, key)
		}
		return res
	}
	// pick reads one field of the first element of a list the CLI itself prints.
	pick := func(key, field string, cmd ...string) string {
		return str(entries(key, cmd...)[0][field])
	}
	// firstWhere is pick with a filter.
	firstWhere := func(key, field string, ok func(map[string]any) bool, cmd ...string) string {
		for _, e := range entries(key, cmd...) {
			if ok(e) {
				return str(e[field])
			}
		}
		t.Fatalf("%v: no matching entry under %q", cmd, key)
		return ""
	}

	keyID := pick("keys", "id", "account", "keys", "list")
	sessionID := firstWhere("sessions", "uid", func(e map[string]any) bool { return e["current"] == false }, "account", "sessions", "list")
	calID := firstWhere("calendars", "id", func(e map[string]any) bool { return e["name"] == "My calendar" }, "calendar", "settings", "calendars", "list")
	computerID := pick("computers", "id", "drive", "computers", "list")
	secKeyID := pick("security_keys", "id", "account", "settings", "security-keys", "list")
	emergID := pick("emergency_contacts", "id", "account", "settings", "emergency-access", "list")
	addrID := pick("addresses", "id", "mail", "settings", "addresses", "list")
	domain := pick("domains", "domain", "mail", "settings", "domains", "list")
	fwdID := pick("forwardings", "id", "mail", "settings", "forwarding", "list")
	importID := pick("imports", "id", "mail", "settings", "imports", "list")
	smtpID := pick("smtp_tokens", "id", "mail", "settings", "smtp-tokens", "list")
	mailboxID := pick("mailboxes", "id", "pass", "settings", "mailboxes", "list")
	vault := pick("vaults", "name", "pass", "vaults", "list")
	bookingID := pick("booking_pages", "id", "calendar", "booking-pages", "list")
	albumID := pick("albums", "link_id", "drive", "photos", "albums", "list")
	photoID := pick("photos", "link_id", "drive", "photos", "list", "--limit", "1")
	listID := pick("mailing_lists", "id", "mail", "mailing-lists", "list", "--limit", "1")
	msgID := pick("messages", "id", "mail", "messages", "list", "--limit", "1")
	itemID := firstWhere("items", "item_id", func(e map[string]any) bool { return e["type"] == "login" }, "pass", "items", "list", "--limit", "5")

	const (
		pw    = "throwaway-password-1"
		pw2   = "throwaway-password-2"
		other = "nobody@example.invalid"
	)
	own := ownAddress(t)
	dir := t.TempDir()
	secretFile := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pf := secretFile("pw", pw)
	pf2 := secretFile("pw2", pw2)
	imapPf := secretFile("imap", "throwaway-imap")
	extraPf := secretFile("extra", "throwaway-extra")

	type pcase struct {
		tool string
		mcp  map[string]any
		cli  []string
	}
	// dropped are the output fields that differ between two runs of the same
	// call and are removed before comparing: the name of a key that is
	// generated at random.
	dropped := map[string][]string{"account_keys_create": {"name"}}
	// explained are differences whose cause is the official CLI, not the
	// wrapper: the build the MCP server runs has a fix the v5.1.0 binary lacks.
	// Each is expected exactly as described and nothing else.
	const fetchMetadata = "Refusing to change anything under --dry-run: POST /drive/shares/"
	a := func(v ...string) []any {
		out := make([]any, len(v))
		for i, s := range v {
			out[i] = s
		}
		return out
	}
	m := func(kv ...any) map[string]any {
		out := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}
	c := func(tool string, mcp map[string]any, cli ...string) pcase { return pcase{tool, mcp, cli} }

	cases := []pcase{
		c("account_breaches_disable", m(), "account", "breaches", "disable"),
		c("account_breaches_disable", m("emails", true), "account", "breaches", "disable", "--emails"),
		c("account_keys_create", m("ref", own, "password", pw), "account", "keys", "create", own, "--password-file", pf),
		c("account_keys_create", m("ref", keyID, "password", pw), "account", "keys", "create", keyID, "--password-file", pf),
		c("account_security_log_delete", m("password", pw), "account", "security-log", "delete", "--password-file", pf),
		c("account_sessions_revoke", m("ref", a(sessionID), "password", pw), "account", "sessions", "revoke", sessionID, "--password-file", pf),
		c("account_sessions_revoke", m("others", true, "password", pw), "account", "sessions", "revoke", "--others", "--password-file", pf),
		c("account_settings_emergency_access_add", m("email", other, "wait", "3d", "password", pw), "account", "settings", "emergency-access", "add", other, "--wait", "3d", "--password-file", pf),
		c("account_settings_emergency_access_remove", m("ref", a(emergID), "password", pw), "account", "settings", "emergency-access", "remove", emergID, "--password-file", pf),
		c("account_settings_emergency_access_update", m("ref", emergID, "wait", "3d", "password", pw), "account", "settings", "emergency-access", "update", emergID, "--wait", "3d", "--password-file", pf),
		c("account_settings_password_set", m("password", pw, "new_password", pw2), "account", "settings", "password", "set", "--password-file", pf, "--new-password-file", pf2),
		c("account_settings_recovery_contacts_add", m("email", other, "password", pw), "account", "settings", "recovery-contacts", "add", other, "--password-file", pf),
		c("account_settings_recovery_email_disable", m("password", pw), "account", "settings", "recovery-email", "disable", "--password-file", pf),
		c("account_settings_recovery_email_set", m("email", other, "password", pw), "account", "settings", "recovery-email", "set", other, "--password-file", pf),
		c("account_settings_recovery_phone_set", m("phone", "+43 660 1234567", "password", pw), "account", "settings", "recovery-phone", "set", "+43 660 1234567", "--password-file", pf),
		c("account_settings_recovery_phrase_disable", m("password", pw), "account", "settings", "recovery-phrase", "disable", "--password-file", pf),
		c("account_settings_recovery_phrase_set", m("password", pw), "account", "settings", "recovery-phrase", "set", "--password-file", pf),
		c("account_settings_second_password_enable", m("password", pw, "new_password", pw2), "account", "settings", "second-password", "enable", "--password-file", pf, "--new-password-file", pf2),
		c("account_settings_security_keys_create", m("name", "parity probe", "password", pw), "account", "settings", "security-keys", "create", "--name", "parity probe", "--password-file", pf),
		c("account_settings_security_keys_delete", m("ref", secKeyID, "password", pw), "account", "settings", "security-keys", "delete", secKeyID, "--password-file", pf),
		c("account_settings_security_keys_update", m("ref", secKeyID, "name", "parity probe"), "account", "settings", "security-keys", "update", secKeyID, "--name", "parity probe"),
		c("account_settings_sentinel_disable", m(), "account", "settings", "sentinel", "disable"),
		c("account_settings_sentinel_disable", m("emails", true), "account", "settings", "sentinel", "disable", "--emails"),
		c("account_settings_two_factor_disable", m("password", pw, "totp", "123456"), "account", "settings", "two-factor", "disable", "--password-file", pf, "--totp", "123456"),

		c("calendar_booking_pages_create", m("title", "parity probe", "duration", "1h", "available", a("tue=14:00-18:00"), "notice", "48h"),
			"calendar", "booking-pages", "create", "--title", "parity probe", "--duration", "1h", "--available", "tue=14:00-18:00", "--notice", "48h"),
		c("calendar_booking_pages_delete", m("ref", a(bookingID)), "calendar", "booking-pages", "delete", bookingID),
		c("calendar_booking_pages_update", m("ref", bookingID, "duration", "1h", "notice", "2h"), "calendar", "booking-pages", "update", bookingID, "--duration", "1h", "--notice", "2h"),
		c("calendar_settings_calendars_create", m("name", "parity probe", "color", "pacific"), "calendar", "settings", "calendars", "create", "--name", "parity probe", "--color", "pacific"),
		c("calendar_settings_calendars_delete", m("ref", a(calID), "password", pw), "calendar", "settings", "calendars", "delete", calID, "--password-file", pf),
		c("calendar_settings_calendars_share_add", m("ref", calID, "email", other, "access", "editor"), "calendar", "settings", "calendars", "share", "add", calID, other, "--access", "editor"),
		c("calendar_settings_links_create", m("ref", calID, "access", "full", "name", "parity probe"), "calendar", "settings", "links", "create", calID, "--access", "full", "--name", "parity probe"),
		c("calendar_settings_set", m("key", "view", "value", "week"), "calendar", "settings", "set", "view", "week"),

		c("contacts_merge", m(), "contacts", "merge"),

		c("drive_computers_delete", m("ref", a(computerID)), "drive", "computers", "delete", computerID),
		c("drive_computers_update", m("ref", computerID, "name", "parity probe"), "drive", "computers", "update", computerID, "--name", "parity probe"),
		c("drive_invitations_accept", m("ref", a("parity-no-such-invitation")), "drive", "invitations", "accept", "parity-no-such-invitation"),
		c("drive_invitations_decline", m("ref", a("parity-no-such-invitation")), "drive", "invitations", "decline", "parity-no-such-invitation"),
		c("drive_items_abuse", m("path", "/", "shared", "parity-no-such-share", "category", "malware", "good_faith", true),
			"drive", "items", "abuse", "/", "--shared", "parity-no-such-share", "--category", "malware", "--good-faith"),
		c("drive_items_share_add", m("path", "/Backups", "email", other, "access", "editor", "message", "hi"), "drive", "items", "share", "add", "/Backups", other, "--access", "editor", "--message", "hi"),
		c("drive_items_share_confirm", m("path", "/Backups", "email", other), "drive", "items", "share", "confirm", "/Backups", other),
		c("drive_items_share_remove", m("path", "/Backups", "email", other), "drive", "items", "share", "remove", "/Backups", other),
		c("drive_items_share_resend", m("path", "/Backups", "email", other), "drive", "items", "share", "resend", "/Backups", other),
		c("drive_items_share_update", m("path", "/Backups", "email", other, "access", "editor"), "drive", "items", "share", "update", "/Backups", other, "--access", "editor"),
		c("drive_photos_albums_share_add", m("ref", albumID, "email", other, "access", "editor", "message", "hi"), "drive", "photos", "albums", "share", "add", albumID, other, "--access", "editor", "--message", "hi"),
		c("drive_photos_albums_share_confirm", m("ref", albumID, "email", other), "drive", "photos", "albums", "share", "confirm", albumID, other),
		c("drive_photos_albums_share_remove", m("ref", albumID, "email", other), "drive", "photos", "albums", "share", "remove", albumID, other),
		c("drive_photos_albums_share_resend", m("ref", albumID, "email", other), "drive", "photos", "albums", "share", "resend", albumID, other),
		c("drive_photos_albums_share_update", m("ref", albumID, "email", other, "access", "editor"), "drive", "photos", "albums", "share", "update", albumID, other, "--access", "editor"),
		c("drive_photos_links_create", m("ref", photoID, "expires", "7d"), "drive", "photos", "links", "create", photoID, "--expires", "7d"),
		c("drive_photos_links_create", m("ref", photoID, "link_password", "throwaway-link"), "drive", "photos", "links", "create", photoID, "--link-password-file", secretFile("link", "throwaway-link")),
		c("drive_photos_links_revoke", m("ref", photoID), "drive", "photos", "links", "revoke", photoID),
		c("drive_photos_share_add", m("ref", photoID, "email", other, "access", "editor", "message", "hi"), "drive", "photos", "share", "add", photoID, other, "--access", "editor", "--message", "hi"),
		c("drive_photos_share_confirm", m("ref", photoID, "email", other), "drive", "photos", "share", "confirm", photoID, other),
		c("drive_photos_share_remove", m("ref", photoID, "email", other), "drive", "photos", "share", "remove", photoID, other),
		c("drive_photos_share_resend", m("ref", photoID, "email", other), "drive", "photos", "share", "resend", photoID, other),
		c("drive_photos_share_update", m("ref", photoID, "email", other, "access", "editor"), "drive", "photos", "share", "update", photoID, other, "--access", "editor"),
		c("drive_settings_set", m("key", "version-history", "value", "30d"), "drive", "settings", "set", "version-history", "30d"),
		c("drive_trash_empty", m(), "drive", "trash", "empty"),

		c("mail_mailing_lists_remove", m("ref", a(listID)), "mail", "mailing-lists", "remove", listID),
		c("mail_mailing_lists_unsubscribe", m("ref", a(listID)), "mail", "mailing-lists", "unsubscribe", listID),
		c("mail_mailing_lists_update", m("ref", a(listID), "into", "Archive", "mark_read", true), "mail", "mailing-lists", "update", listID, "--into", "Archive", "--mark-read"),
		c("mail_messages_empty", m("folder", "trash"), "mail", "messages", "empty", "--folder", "trash"),
		c("mail_messages_mark_phishing", m("ref", a(msgID)), "mail", "messages", "mark", "phishing", msgID),
		c("mail_settings_addresses_create", m("email", "parity-probe@example.invalid", "display_name", "Probe", "password", pw), "mail", "settings", "addresses", "create", "parity-probe@example.invalid", "--display-name", "Probe", "--password-file", pf),
		c("mail_settings_addresses_disable", m("ref", a(addrID), "password", pw), "mail", "settings", "addresses", "disable", addrID, "--password-file", pf),
		c("mail_settings_addresses_update", m("ref", addrID, "display_name", "Probe", "signature", "parity", "html", true), "mail", "settings", "addresses", "update", addrID, "--display-name", "Probe", "--signature", "parity", "--html"),
		c("mail_settings_addresses_update", m("ref", addrID, "clear_signature", true), "mail", "settings", "addresses", "update", addrID, "--clear-signature"),
		c("mail_settings_autoreply_disable", m("password", pw), "mail", "settings", "autoreply", "disable", "--password-file", pf),
		c("mail_settings_autoreply_enable", m("password", pw), "mail", "settings", "autoreply", "enable", "--password-file", pf),
		c("mail_settings_domains_create", m("domain", "parity-probe.invalid", "password", pw), "mail", "settings", "domains", "create", "parity-probe.invalid", "--password-file", pf),
		c("mail_settings_domains_delete", m("ref", domain, "password", pw), "mail", "settings", "domains", "delete", domain, "--password-file", pf),
		c("mail_settings_domains_update", m("ref", domain, "catch_all", "none", "password", pw), "mail", "settings", "domains", "update", domain, "--catch-all", "none", "--password-file", pf),
		c("mail_settings_forwarding_create", m("ref", own, "email", other, "password", pw), "mail", "settings", "forwarding", "create", own, other, "--password-file", pf),
		c("mail_settings_forwarding_delete", m("ref", a(fwdID), "password", pw), "mail", "settings", "forwarding", "delete", fwdID, "--password-file", pf),
		c("mail_settings_forwarding_disable", m("ref", a(fwdID)), "mail", "settings", "forwarding", "disable", fwdID),
		c("mail_settings_imports_create", m("login", "jane@fastmail.com", "imap_password", "throwaway-imap", "after", "2024-01-01", "label", "Fastmail", "skip", a("Spam", "Archive/*"), "port", 993, "server", "imap.example.com"),
			"mail", "settings", "imports", "create", "jane@fastmail.com", "--imap-password-file", imapPf, "--after", "2024-01-01", "--label", "Fastmail", "--skip", "Spam", "--skip", "Archive/*", "--port", "993", "--server", "imap.example.com"),
		c("mail_settings_imports_delete", m("ref", a(importID)), "mail", "settings", "imports", "delete", importID),
		c("mail_settings_set", m("key", "view-mode", "value", "conversations"), "mail", "settings", "set", "view-mode", "conversations"),
		c("mail_settings_smtp_tokens_create", m("ref", own, "name", "parity probe", "password", pw), "mail", "settings", "smtp-tokens", "create", own, "--name", "parity probe", "--password-file", pf),
		c("mail_settings_smtp_tokens_delete", m("ref", a(smtpID), "password", pw), "mail", "settings", "smtp-tokens", "delete", smtpID, "--password-file", pf),

		c("pass_items_share_add", m("ref", itemID, "email", other, "access", "editor"), "pass", "items", "share", "add", itemID, other, "--access", "editor"),
		c("pass_items_share_confirm", m("ref", itemID, "email", other), "pass", "items", "share", "confirm", itemID, other),
		c("pass_settings_extra_password_enable", m("extra_password", "throwaway-extra"), "pass", "settings", "extra-password", "enable", "--extra-password-file", extraPf),
		c("pass_settings_mailboxes_update", m("ref", mailboxID, "default", true), "pass", "settings", "mailboxes", "update", mailboxID, "--default"),
		c("pass_trash_empty", m(), "pass", "trash", "empty"),
		c("pass_vaults_share_add", m("ref", vault, "email", other, "access", "editor"), "pass", "vaults", "share", "add", vault, other, "--access", "editor"),
		c("pass_vaults_share_confirm", m("ref", vault, "email", other), "pass", "vaults", "share", "confirm", vault, other),
	}

	// The guard: every tool in the table writes, and nothing runs unless both
	// sides are previews. The preview flags are added here, once, and the final
	// lines are checked again before the first call.
	hasFlag := func(args []string, f string) bool {
		for _, s := range args {
			if s == f || s == f+"=true" {
				return true
			}
		}
		return false
	}
	for i := range cases {
		k := &cases[i]
		w, known := writes[k.tool]
		if !known {
			t.Fatalf("%s is not a tool of this server", k.tool)
		}
		if !w {
			t.Fatalf("%s is not tagged as writing; this table is for writes only", k.tool)
		}
		if hasFlag(k.cli, "--yes") || hasFlag(k.cli, "-y") || k.mcp["confirm"] != nil {
			t.Fatalf("refusing to run: %s asks to confirm", k.tool)
		}
		k.mcp["dry_run"] = true
		k.cli = append([]string{"--dry-run"}, k.cli...)
	}
	for _, k := range cases {
		if d, _ := k.mcp["dry_run"].(bool); !d || !hasFlag(k.cli, "--dry-run") || k.mcp["confirm"] != nil {
			t.Fatalf("refusing to run %s: not a preview on both sides (%v)", k.tool, k.cli)
		}
	}

	norm := func(s string) (any, bool) {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return strings.TrimSpace(s), false
		}
		return v, true
	}
	short := func(s string) string {
		s = strings.Join(strings.Fields(s), " ")
		if len(s) > 110 {
			s = s[:110] + "..."
		}
		return strings.ReplaceAll(s, "|", "/")
	}
	// tmpPath maps the random working paths of either side to one token, so an
	// error naming a throwaway file compares by what it says.
	tmpNorm := func(s string) string {
		for _, p := range []string{dir, os.TempDir() + "/proton-mcp-"} {
			for strings.Contains(s, p) {
				i := strings.Index(s, p)
				j := i
				for j < len(s) && s[j] != ' ' && s[j] != '"' && s[j] != '\'' && s[j] != ':' {
					j++
				}
				s = s[:i] + "<tmp>" + s[j:]
			}
		}
		return s
	}

	type row struct{ tool, mcp, cli, verdict string }
	var rows []row
	verdictOf := map[string]string{}
	for _, k := range cases {
		mOut, mErr := call(t, cs, k.tool, k.mcp)
		cOut, cErr := cliRun(k.cli...)
		mDesc, cDesc := "ok", "ok"
		if mErr {
			mDesc = "ERR"
		}
		if cErr {
			cDesc = "ERR"
		}
		v := "SAME"
		switch {
		case !mErr && cErr && strings.HasPrefix(k.tool, "drive_photos_albums_share_") && strings.Contains(cOut, fetchMetadata) && strings.Contains(cOut, "/links/fetch_metadata"):
			// v5.1.0 counts the link-metadata lookup (a POST that only reads) as a
			// write and refuses it under --dry-run; this repo's fork (e0d4f43)
			// marks it a read. Same on every call to the album share tools.
			v = "DIFFERENT-EXPLAINED (official CLI v5.1.0 refuses a read-only POST under --dry-run; fixed in the fork, e0d4f43)"
		case mErr != cErr:
			v = "DIFFERENT (one side failed)"
		case mErr:
			if tmpNorm(strings.TrimSpace(mOut)) != tmpNorm(strings.TrimSpace(cOut)) {
				v = "DIFFERENT (error text)"
			}
		default:
			mv, mj := norm(mOut)
			cv, cj := norm(cOut)
			for _, f := range dropped[k.tool] {
				if mm, ok := mv.(map[string]any); ok {
					delete(mm, f)
				}
				if cm, ok := cv.(map[string]any); ok {
					delete(cm, f)
				}
			}
			if mj != cj || !reflect.DeepEqual(mv, cv) {
				v = "DIFFERENT (output)"
			}
			// counts of bulk previews must match, said out loud
			if mj && cj {
				mm, _ := mv.(map[string]any)
				cm, _ := cv.(map[string]any)
				if mm["count"] != nil || cm["count"] != nil {
					t.Logf("%s: previewed count MCP=%v CLI=%v", k.tool, mm["count"], cm["count"])
				}
			}
		}
		if strings.HasPrefix(v, "DIFFERENT") && !strings.HasPrefix(v, "DIFFERENT-EXPLAINED") {
			t.Errorf("%s %v: %s\n  MCP(%s): %.300s\n  CLI(%s): %.300s", k.tool, k.cli, v, mDesc, mOut, cDesc, cOut)
		}
		t.Logf("%-46s MCP=%-3s CLI=%-3s %s", k.tool, mDesc, cDesc, v)
		rows = append(rows, row{k.tool, mDesc + ": " + short(mOut), cDesc + ": " + short(cOut), v})
		if prev, ok := verdictOf[k.tool]; !ok || (prev == "SAME" && v != "SAME") {
			verdictOf[k.tool] = v
		}
	}

	var same, diff, explained int
	for _, v := range verdictOf {
		switch {
		case v == "SAME":
			same++
		case strings.HasPrefix(v, "DIFFERENT-EXPLAINED"):
			explained++
		default:
			diff++
		}
	}
	summary := fmt.Sprintf("tools=%d cases=%d SAME=%d DIFFERENT-EXPLAINED(cli)=%d DIFFERENT=%d COULD-NOT-COMPARE=0", len(verdictOf), len(cases), same, explained, diff)
	t.Logf("PARITY P2 SUMMARY: %s", summary)

	if path := os.Getenv("PARITY_P2_TABLE"); path != "" {
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].tool < rows[j].tool })
		var sb strings.Builder
		sb.WriteString("| tool | MCP result | CLI result | verdict |\n|---|---|---|---|\n")
		for _, r := range rows {
			fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", r.tool, r.mcp, r.cli, r.verdict)
		}
		fmt.Fprintf(&sb, "\nSummary: %s\n", summary)
		if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
