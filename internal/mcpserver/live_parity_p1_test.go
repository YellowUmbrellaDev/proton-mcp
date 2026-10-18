package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/roman-16/proton-cli/internal/crypto/pgp"
)

// TestParityP1 holds the 77 tools that failed in the first live sweep up
// against the official CLI. Each row is an intent written the way a person
// would type it for the official binary (PROTON_OFFICIAL_CLI) and the same intent as an MCP
// call. Both run against the same saved session; every mutation carries
// --dry-run / dry_run, so nothing on the account changes. An error that is the
// same text on both sides shows the tool is faithful and the error is the
// account's state.
//
// Placeholders in cliArgs: {secret} and {key} are paths of files holding the
// throwaway secret text and a public key; they are what the MCP side writes
// itself from the string / file inputs.
func TestParityP1(t *testing.T) {
	bin := officialBinary(t)
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("official CLI not found at %s", bin)
	}
	cs := live(t)
	dir := t.TempDir()
	const secretText = "not-a-real-password"
	secretPath := filepath.Join(dir, "secret")
	must(t, os.WriteFile(secretPath, []byte(secretText), 0o600))

	base := []string{"--output", "json", "--no-input", "--no-log", "--zone", "UTC"}
	cliRead := func(args ...string) []byte {
		out, _, code := runCLI(bin, append(append([]string{}, base...), args...))
		if code != 0 {
			t.Fatalf("setup read %v failed", args)
		}
		return out
	}
	// --- real ids, read from the account.
	var keys struct {
		Keys []struct{ ID, Status string }
	}
	must(t, json.Unmarshal(cliRead("account", "keys", "list"), &keys))
	fwdKey, primaryKey := "", ""
	for _, k := range keys.Keys {
		if k.Status == "forwarding" && fwdKey == "" {
			fwdKey = k.ID
		}
		if k.Status == "primary" && primaryKey == "" {
			primaryKey = k.ID
		}
	}
	const fakeKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	if fwdKey == "" {
		fwdKey = fakeKey
	}
	// A throwaway private key for the import: nothing of the account's.
	throwaway, err := pgp.GenerateKey("p1", "p1@example.invalid")
	must(t, err)
	keyArmor, err := throwaway.Armor()
	must(t, err)
	keyPath := filepath.Join(dir, "k.asc")
	must(t, os.WriteFile(keyPath, []byte(keyArmor), 0o600))

	var addrs struct {
		Addresses []struct {
			Email  string
			Status int
		}
	}
	must(t, json.Unmarshal(cliRead("mail", "settings", "addresses", "list"), &addrs))
	disabled, enabled := "", ""
	for _, a := range addrs.Addresses {
		if a.Status == 0 && disabled == "" {
			disabled = a.Email
		}
		if a.Status == 1 && enabled == "" {
			enabled = a.Email
		}
	}
	var cals struct{ Calendars []struct{ ID, Name string } }
	must(t, json.Unmarshal(cliRead("calendar", "settings", "calendars", "list"), &cals))
	calID := cals.Calendars[0].ID
	var evs struct {
		Events []struct {
			ID         string
			CalendarID string `json:"calendar_id"`
		}
	}
	must(t, json.Unmarshal(cliRead("calendar", "events", "list", "--limit", "1"), &evs))
	evRef := evs.Events[0].CalendarID + "/" + evs.Events[0].ID
	var vols struct{ Volumes []struct{ ID string } }
	must(t, json.Unmarshal(cliRead("drive", "volumes", "list"), &vols))
	var photos struct {
		Photos []struct {
			LinkID string `json:"link_id"`
		}
	}
	must(t, json.Unmarshal(cliRead("drive", "photos", "list", "--limit", "1"), &photos))
	var msgs struct{ Messages []struct{ ID string } }
	must(t, json.Unmarshal(cliRead("mail", "messages", "list", "--limit", "1"), &msgs))
	var fwds struct{ Forwardings []struct{ ID string } }
	must(t, json.Unmarshal(cliRead("mail", "settings", "forwarding", "list"), &fwds))
	var imps struct{ Imports []struct{ Account string } }
	must(t, json.Unmarshal(cliRead("mail", "settings", "imports", "list"), &imps))
	var pitems struct{ Items []struct{ Name string } }
	must(t, json.Unmarshal(cliRead("pass", "items", "list", "--limit", "1"), &pitems))
	var vaults struct{ Vaults []struct{ Name string } }
	must(t, json.Unmarshal(cliRead("pass", "vaults", "list"), &vaults))
	var emerg struct {
		Contacts []struct{ Contact, Direction string } `json:"emergency_contacts"`
	}
	must(t, json.Unmarshal(cliRead("account", "settings", "emergency-access", "list"), &emerg))
	emContact := "nobody@example.invalid"
	if len(emerg.Contacts) > 0 {
		emContact = emerg.Contacts[0].Contact
	}
	login, vault, volume := pitems.Items[0].Name, vaults.Vaults[0].Name, vols.Volumes[0].ID
	msg, photo, fwd, imp := msgs.Messages[0].ID, photos.Photos[0].LinkID, fwds.Forwardings[0].ID, imps.Imports[0].Account
	var wl struct {
		Watched []struct {
			Email string
			Type  string
		} `json:"watched_addresses"`
	}
	must(t, json.Unmarshal(cliRead("pass", "breaches", "list"), &wl))
	watched := wl.Watched[0].Email
	const nobody = "nobody@example.invalid"
	const link = "9fK2pQ7xNv4mB8"
	S := secretText

	type L = []any
	type M = map[string]any
	type row struct {
		tool string
		mcp  M
		cli  []string
		dry  bool // mutating: dry_run / --dry-run
		raw  bool // download: no --output json
		note string
	}
	rows := []row{
		{tool: "account_breaches_enable", mcp: M{"emails": true}, cli: []string{"account", "breaches", "enable", "--emails"}, dry: true},
		{tool: "account_breaches_get", mcp: M{"ref": "Canva"}, cli: []string{"account", "breaches", "get", "Canva"}},
		{tool: "account_breaches_reopen", mcp: M{"ref": L{"Canva"}}, cli: []string{"account", "breaches", "reopen", "Canva"}, dry: true},
		{tool: "account_breaches_resolve", mcp: M{"ref": L{"Canva"}}, cli: []string{"account", "breaches", "resolve", "Canva"}, dry: true},
		{tool: "account_keys_delete", mcp: M{"ref": L{fwdKey}, "password": S}, cli: []string{"account", "keys", "delete", fwdKey, "--password-file", "{secret}"}, dry: true},
		{tool: "account_keys_delete", mcp: M{"ref": L{fakeKey}, "password": S}, cli: []string{"account", "keys", "delete", fakeKey, "--password-file", "{secret}"}, dry: true},
		{tool: "account_keys_import", mcp: M{"ref": enabled, "src": M{"name": "k.asc", "text": keyArmor}, "password": S}, cli: []string{"account", "keys", "import", enabled, "{key}", "--password-file", "{secret}"}, dry: true},
		{tool: "account_keys_reactivate", mcp: M{"password": S, "previous_password": S}, cli: []string{"account", "keys", "reactivate", "--password-file", "{secret}", "--previous-password-file", "{secret}"}, dry: true},
		{tool: "account_keys_update", mcp: M{"ref": fwdKey, "obsolete": false, "password": S}, cli: []string{"account", "keys", "update", fwdKey, "--obsolete=false", "--password-file", "{secret}"}, dry: true},
		{tool: "account_security_log_disable", mcp: M{"password": S}, cli: []string{"account", "security-log", "disable", "--password-file", "{secret}"}, dry: true},
		{tool: "account_security_log_enable", mcp: M{"password": S}, cli: []string{"account", "security-log", "enable", "--password-file", "{secret}"}, dry: true},
		{tool: "account_security_log_enable", mcp: M{"detailed": true, "password": S}, cli: []string{"account", "security-log", "enable", "--detailed", "--password-file", "{secret}"}, dry: true},
		{tool: "account_settings_emergency_access_access", mcp: M{"ref": emContact, "as": "p1probe"}, cli: []string{"account", "settings", "emergency-access", "access", emContact, "--as", "p1probe"}, dry: true},
		{tool: "account_settings_emergency_access_cancel", mcp: M{"ref": emContact, "password": S}, cli: []string{"account", "settings", "emergency-access", "cancel", emContact, "--password-file", "{secret}"}, dry: true},
		{tool: "account_settings_emergency_access_grant", mcp: M{"ref": emContact, "password": S}, cli: []string{"account", "settings", "emergency-access", "grant", emContact, "--password-file", "{secret}"}, dry: true},
		{tool: "account_settings_emergency_access_request", mcp: M{"ref": emContact}, cli: []string{"account", "settings", "emergency-access", "request", emContact}, dry: true},
		{tool: "account_settings_recovery_contacts_get", mcp: M{"ref": nobody}, cli: []string{"account", "settings", "recovery-contacts", "get", nobody}},
		{tool: "account_settings_recovery_contacts_remove", mcp: M{"ref": L{nobody}, "password": S}, cli: []string{"account", "settings", "recovery-contacts", "remove", nobody, "--password-file", "{secret}"}, dry: true},
		{tool: "account_settings_recovery_email_enable", mcp: M{"password": S}, cli: []string{"account", "settings", "recovery-email", "enable", "--password-file", "{secret}"}, dry: true},
		{tool: "account_settings_recovery_email_verify", mcp: M{}, cli: []string{"account", "settings", "recovery-email", "verify"}, dry: true},
		{tool: "account_settings_recovery_phone_disable", mcp: M{"password": S}, cli: []string{"account", "settings", "recovery-phone", "disable", "--password-file", "{secret}"}, dry: true},
		{tool: "account_settings_recovery_phone_enable", mcp: M{"password": S}, cli: []string{"account", "settings", "recovery-phone", "enable", "--password-file", "{secret}"}, dry: true},
		{tool: "account_settings_recovery_phone_verify", mcp: M{}, cli: []string{"account", "settings", "recovery-phone", "verify"}, dry: true},
		{tool: "account_settings_recovery_phone_verify", mcp: M{"code": "123456"}, cli: []string{"account", "settings", "recovery-phone", "verify", "--code", "123456"}, dry: true},
		{tool: "account_settings_second_password_disable", mcp: M{"password": S}, cli: []string{"account", "settings", "second-password", "disable", "--password-file", "{secret}"}, dry: true},
		{tool: "account_settings_second_password_set", mcp: M{"password": S, "new_password": S + "-new"}, cli: []string{"account", "settings", "second-password", "set", "--password-file", "{secret}", "--new-password-file", "{secret2}"}, dry: true},
		{tool: "account_settings_sentinel_enable", mcp: M{"emails": true}, cli: []string{"account", "settings", "sentinel", "enable", "--emails"}, dry: true},
		{tool: "account_settings_two_factor_enable", mcp: M{"password": S}, cli: []string{"account", "settings", "two-factor", "enable", "--password-file", "{secret}"}, dry: true},

		{tool: "calendar_events_respond", mcp: M{"ref": evRef, "answer": "accept"}, cli: []string{"calendar", "events", "respond", evRef, "--answer", "accept"}, dry: true},
		{tool: "calendar_invitations_accept", mcp: M{"ref": L{"p1-none"}}, cli: []string{"calendar", "invitations", "accept", "p1-none"}, dry: true},
		{tool: "calendar_invitations_decline", mcp: M{"ref": L{"p1-none"}}, cli: []string{"calendar", "invitations", "decline", "p1-none"}, dry: true},
		{tool: "calendar_settings_calendars_leave", mcp: M{"ref": L{calID}}, cli: []string{"calendar", "settings", "calendars", "leave", calID}, dry: true},
		{tool: "calendar_settings_calendars_share_remove", mcp: M{"ref": calID, "email": nobody}, cli: []string{"calendar", "settings", "calendars", "share", "remove", calID, nobody}, dry: true},
		{tool: "calendar_settings_calendars_share_update", mcp: M{"ref": calID, "email": nobody, "access": "viewer"}, cli: []string{"calendar", "settings", "calendars", "share", "update", calID, nobody, "--access", "viewer"}, dry: true},
		{tool: "calendar_settings_links_get", mcp: M{"ref": "p1-nolink"}, cli: []string{"calendar", "settings", "links", "get", "p1-nolink"}},
		{tool: "calendar_settings_links_revoke", mcp: M{"ref": L{"p1-nolink"}}, cli: []string{"calendar", "settings", "links", "revoke", "p1-nolink"}, dry: true},
		{tool: "calendar_settings_links_update", mcp: M{"ref": "p1-nolink", "name": "x"}, cli: []string{"calendar", "settings", "links", "update", "p1-nolink", "--name", "x"}, dry: true},

		{tool: "drive_invitations_abuse", mcp: M{"ref": "p1-none", "category": "spam", "good_faith": true}, cli: []string{"drive", "invitations", "abuse", "p1-none", "--category", "spam", "--good-faith"}, dry: true},
		{tool: "drive_items_revisions_abuse", mcp: M{"path": "/p1-none", "revision_ref": "p1-rev", "shared": "p1-none", "category": "spam", "good_faith": true}, cli: []string{"drive", "items", "revisions", "abuse", "/p1-none", "p1-rev", "--shared", "p1-none", "--category", "spam", "--good-faith"}, dry: true},
		{tool: "drive_photos_links_get", mcp: M{"ref": photo}, cli: []string{"drive", "photos", "links", "get", photo}},
		{tool: "drive_shared_leave", mcp: M{"ref": L{"p1-none"}}, cli: []string{"drive", "shared", "leave", "p1-none"}, dry: true},
		{tool: "drive_volumes_delete", mcp: M{"ref": L{volume}}, cli: []string{"drive", "volumes", "delete", volume}, dry: true},
		{tool: "drive_volumes_restore", mcp: M{"ref": L{volume}}, cli: []string{"drive", "volumes", "restore", volume}, dry: true},

		{tool: "mail_messages_receipt", mcp: M{"ref": L{msg}}, cli: []string{"mail", "messages", "receipt", msg}, dry: true},
		{tool: "mail_messages_unsubscribe", mcp: M{"ref": L{msg}}, cli: []string{"mail", "messages", "unsubscribe", msg}, dry: true},
		{tool: "mail_protected_attachments_download", mcp: M{"link": link, "attachment_ref": "x", "eo_password": S}, cli: []string{"mail", "protected", "attachments", "download", link, "x", "--eo-password-file", "{secret}", "--dest", "-"}, raw: true},
		{tool: "mail_protected_attachments_list", mcp: M{"link": link, "eo_password": S}, cli: []string{"mail", "protected", "attachments", "list", link, "--eo-password-file", "{secret}"}},
		{tool: "mail_protected_get", mcp: M{"link": link, "eo_password": S}, cli: []string{"mail", "protected", "get", link, "--eo-password-file", "{secret}"}},
		{tool: "mail_protected_reply", mcp: M{"link": link, "eo_password": S, "body": "x"}, cli: []string{"mail", "protected", "reply", link, "--eo-password-file", "{secret}", "--body", "x"}, dry: true},
		{tool: "mail_settings_addresses_delete", mcp: M{"ref": L{disabled}, "password": S}, cli: []string{"mail", "settings", "addresses", "delete", disabled, "--password-file", "{secret}"}, dry: true},
		{tool: "mail_settings_addresses_enable", mcp: M{"ref": L{disabled}, "password": S}, cli: []string{"mail", "settings", "addresses", "enable", disabled, "--password-file", "{secret}"}, dry: true},
		{tool: "mail_settings_addresses_reorder", mcp: M{"ref": L{enabled}}, cli: []string{"mail", "settings", "addresses", "reorder", enabled}, dry: true},
		{tool: "mail_settings_autoreply_set", mcp: M{"repeat": "permanent", "body": "fuera", "password": S}, cli: []string{"mail", "settings", "autoreply", "set", "--repeat", "permanent", "--body", "fuera", "--password-file", "{secret}"}, dry: true},
		{tool: "mail_settings_categories_disable", mcp: M{"ref": L{"social"}}, cli: []string{"mail", "settings", "categories", "disable", "social"}, dry: true},
		{tool: "mail_settings_categories_enable", mcp: M{"ref": L{"social"}}, cli: []string{"mail", "settings", "categories", "enable", "social"}, dry: true},
		{tool: "mail_settings_categories_update", mcp: M{"ref": "social", "notify": false}, cli: []string{"mail", "settings", "categories", "update", "social", "--notify=false"}, dry: true},
		{tool: "mail_settings_folders_reorder", mcp: M{"ref": L{"p1-nofolder"}}, cli: []string{"mail", "settings", "folders", "reorder", "p1-nofolder"}, dry: true},
		{tool: "mail_settings_folders_reorder", mcp: M{"alphabetical": true}, cli: []string{"mail", "settings", "folders", "reorder", "--alphabetical"}, dry: true},
		{tool: "mail_settings_forwarding_accept", mcp: M{"ref": L{fwd}, "password": S}, cli: []string{"mail", "settings", "forwarding", "accept", fwd, "--password-file", "{secret}"}, dry: true},
		{tool: "mail_settings_forwarding_decline", mcp: M{"ref": L{fwd}}, cli: []string{"mail", "settings", "forwarding", "decline", fwd}, dry: true},
		{tool: "mail_settings_forwarding_enable", mcp: M{"ref": L{fwd}}, cli: []string{"mail", "settings", "forwarding", "enable", fwd}, dry: true},
		{tool: "mail_settings_forwarding_resend", mcp: M{"ref": L{fwd}}, cli: []string{"mail", "settings", "forwarding", "resend", fwd}, dry: true},
		{tool: "mail_settings_imports_cancel", mcp: M{"ref": L{imp}}, cli: []string{"mail", "settings", "imports", "cancel", imp}, dry: true},
		{tool: "mail_settings_imports_resume", mcp: M{"ref": imp, "imap_password": S}, cli: []string{"mail", "settings", "imports", "resume", imp, "--imap-password-file", "{secret}"}, dry: true},
		{tool: "mail_settings_imports_undo", mcp: M{"ref": L{imp}}, cli: []string{"mail", "settings", "imports", "undo", imp}, dry: true},

		{tool: "pass_breaches_create", mcp: M{"email": "p1-parity@example.com"}, cli: []string{"pass", "breaches", "create", "p1-parity@example.com"}, dry: true},
		{tool: "pass_breaches_delete", mcp: M{"ref": "p1-parity@example.com"}, cli: []string{"pass", "breaches", "delete", "p1-parity@example.com"}, dry: true},
		{tool: "pass_breaches_resend", mcp: M{"ref": "p1-parity@example.com"}, cli: []string{"pass", "breaches", "resend", "p1-parity@example.com"}, dry: true},
		{tool: "pass_breaches_resolve", mcp: M{"ref": L{"p1-parity@example.com"}}, cli: []string{"pass", "breaches", "resolve", "p1-parity@example.com"}, dry: true},
		{tool: "pass_breaches_resolve", mcp: M{"ref": L{watched}}, cli: []string{"pass", "breaches", "resolve", watched}, dry: true},
		{tool: "pass_breaches_verify", mcp: M{"ref": "p1-parity@example.com", "code": "123456"}, cli: []string{"pass", "breaches", "verify", "p1-parity@example.com", "--code", "123456"}, dry: true},
		{tool: "pass_export", mcp: M{"format": "banana"}, cli: []string{"pass", "export", "--format", "banana", "--dest", "-"}, raw: true},
		{tool: "pass_export", mcp: M{"format": "json", "no_attachments": true, "passphrase": S}, cli: []string{"pass", "export", "--format", "json", "--no-attachments", "--passphrase-file", "{secret}", "--dest", "-"}, raw: true, note: "content is encrypted and never printed"},
		{tool: "pass_invitations_accept", mcp: M{"ref": L{"p1-none"}}, cli: []string{"pass", "invitations", "accept", "p1-none"}, dry: true},
		{tool: "pass_invitations_decline", mcp: M{"ref": L{"p1-none"}}, cli: []string{"pass", "invitations", "decline", "p1-none"}, dry: true},
		{tool: "pass_items_passkeys_remove", mcp: M{"ref": login, "passkey_ref": L{"nobody"}}, cli: []string{"pass", "items", "passkeys", "remove", login, "nobody"}, dry: true},
		{tool: "pass_items_share_remove", mcp: M{"ref": login, "email": nobody}, cli: []string{"pass", "items", "share", "remove", login, nobody}, dry: true},
		{tool: "pass_items_share_update", mcp: M{"ref": login, "email": nobody, "access": "editor"}, cli: []string{"pass", "items", "share", "update", login, nobody, "--access", "editor"}, dry: true},
		{tool: "pass_settings_domains_update", mcp: M{"ref": "passmail.com", "display_name": "P1 parity"}, cli: []string{"pass", "settings", "domains", "update", "passmail.com", "--display-name", "P1 parity"}, dry: true},
		{tool: "pass_settings_extra_password_disable", mcp: M{"extra_password": S}, cli: []string{"pass", "settings", "extra-password", "disable", "--extra-password-file", "{secret}"}, dry: true},
		{tool: "pass_vaults_share_remove", mcp: M{"ref": vault, "email": nobody}, cli: []string{"pass", "vaults", "share", "remove", vault, nobody}, dry: true},
		{tool: "pass_vaults_share_update", mcp: M{"ref": vault, "email": nobody, "access": "editor"}, cli: []string{"pass", "vaults", "share", "update", vault, nobody, "--access", "editor"}, dry: true},
		{tool: "pass_vaults_transfer", mcp: M{"ref": vault, "email": nobody}, cli: []string{"pass", "vaults", "transfer", vault, nobody}, dry: true},
	}

	secret2 := filepath.Join(dir, "secret2")
	must(t, os.WriteFile(secret2, []byte(secretText+"-new"), 0o600))
	subst := strings.NewReplacer("{secret}", secretPath, "{secret2}", secret2, "{key}", keyPath)

	catalog, _, err := Catalog(Options{})
	must(t, err)
	mutating := map[string]bool{}
	for _, tl := range catalog {
		mutating[tl.Name] = tl.Mutating
	}
	for _, r := range rows {
		if r.dry != mutating[r.tool] {
			t.Fatalf("%s: row says dry=%v but the catalog says mutating=%v", r.tool, r.dry, mutating[r.tool])
		}
	}

	var table strings.Builder
	table.WriteString("| tool | MCP result | CLI result | verdict |\n|---|---|---|---|\n")
	counts := map[string]int{}
	perTool := map[string]string{}
	rank := map[string]int{"SAME": 0, "COULD-NOT-COMPARE": 1, "DIFFERENT": 2}
	bare := 0
	var bareList []string

	for _, r := range rows {
		mcpArgs := M{}
		for k, v := range r.mcp {
			mcpArgs[k] = v
		}
		cliArgs := make([]string, len(r.cli))
		for i, a := range r.cli {
			cliArgs[i] = subst.Replace(a)
		}
		full := append([]string{}, base...)
		if r.raw {
			full = []string{"--no-input", "--no-log", "--zone", "UTC"}
		}
		if r.dry {
			mcpArgs["dry_run"] = true
			full = append(full, "--dry-run")
		}
		full = append(full, cliArgs...)

		// Safety guard: a write tool is only ever called as a preview, and no
		// side ever confirms.
		if _, ok := mcpArgs["confirm"]; ok {
			t.Fatalf("%s: a parity row must never pass confirm", r.tool)
		}
		for _, a := range full {
			if a == "--yes" || a == "-y" || a == "--confirm" {
				t.Fatalf("%s: a parity row must never answer yes for the CLI", r.tool)
			}
		}
		if mutating[r.tool] && (mcpArgs["dry_run"] != true || !contains(full, "--dry-run")) {
			t.Fatalf("%s is a write tool and must run as a dry run on both sides", r.tool)
		}
		mtext, mErr := callMCPNoFail(cs, r.tool, mcpArgs)
		cout, cerr, ccode := runCLI(bin, full)
		cliText := strings.TrimSpace(string(cout))
		cliFailed := ccode != 0
		if cliFailed {
			cliText = strings.TrimSpace(string(cerr))
		}
		mtext = strings.TrimSpace(mtext)

		verdict, why := compare(mErr, mtext, cliFailed, cliText)
		if r.note != "" {
			why += " (" + r.note + ")"
		}
		if cliFailed && mErr && verdict == "SAME" && isBare(cliText) {
			bare++
			bareList = append(bareList, r.tool)
			why += " BARE-ERROR"
		}
		counts[verdict]++
		if rank[verdict] >= rank[perTool[r.tool]] {
			if _, seen := perTool[r.tool]; !seen || rank[verdict] > rank[perTool[r.tool]] {
				perTool[r.tool] = verdict
			}
		}
		mc, cc := cell(mErr, mtext), cell(cliFailed, cliText)
		if r.raw && !mErr && !cliFailed {
			// an export's content is never printed
			mc, cc = fmt.Sprintf("ok %d bytes", len(mtext)), fmt.Sprintf("ok %d bytes", len(cliText))
		}
		fmt.Fprintf(&table, "| %s | %s | %s | %s %s |\n", r.tool, mc, cc, verdict, why)
		t.Logf("%-46s %-9s %s", r.tool, verdict, why)
		if verdict == "DIFFERENT" {
			t.Errorf("%s differs\n MCP: %.300q\n CLI: %.300q", r.tool, mtext, cliText)
		}
	}
	tools := map[string]int{}
	for _, v := range perTool {
		tools[v]++
	}
	var names []string
	for k := range perTool {
		names = append(names, k)
	}
	sort.Strings(names)
	_ = names
	summary := fmt.Sprintf("PARITY P1: %d rows over %d tools; rows SAME=%d DIFFERENT=%d COULD-NOT-COMPARE=%d; tools SAME=%d DIFFERENT=%d COULD-NOT-COMPARE=%d; bare-error rows=%d %v",
		len(rows), len(perTool), counts["SAME"], counts["DIFFERENT"], counts["COULD-NOT-COMPARE"], tools["SAME"], tools["DIFFERENT"], tools["COULD-NOT-COMPARE"], bare, bareList)
	t.Log(summary)
	fmt.Println(summary)
	if path := os.Getenv("PROTON_PARITY_TABLE"); path != "" {
		must(t, os.WriteFile(path, []byte(table.String()+"\n"+summary+"\n"), 0o644))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func runCLI(bin string, args []string) (stdout, stderr []byte, code int) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	cmd.Stdin = bytes.NewReader(nil)
	err := cmd.Run()
	code = 0
	if err != nil {
		code = 1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	return o.Bytes(), e.Bytes(), code
}

func callMCPNoFail(cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return "protocol error: " + err.Error(), true
	}
	var sb strings.Builder
	for _, c := range res.Content {
		switch c := c.(type) {
		case *mcp.TextContent:
			sb.WriteString(c.Text)
		case *mcp.EmbeddedResource:
			sb.WriteString(string(c.Resource.Blob))
		}
	}
	return sb.String(), res.IsError
}

// volatile fields are dropped before two JSON results are compared.
var volatile = map[string]bool{
	"time": true, "timestamp": true, "duration": true, "elapsed": true, "took": true,
}

// shape keeps the keys and types of a JSON value and drops its content, for
// results that are encrypted or random on every run.
func shape(v any) any {
	switch v := v.(type) {
	case map[string]any:
		m := map[string]any{}
		for k, e := range v {
			m[k] = shape(e)
		}
		return m
	case []any:
		if len(v) == 0 {
			return []any{}
		}
		return []any{shape(v[0])}
	case string:
		return "s"
	case float64:
		return "n"
	case bool:
		return "b"
	}
	return v
}

func strip(v any) any {
	switch v := v.(type) {
	case map[string]any:
		m := map[string]any{}
		for k, e := range v {
			if !volatile[k] {
				m[k] = strip(e)
			}
		}
		return m
	case []any:
		for i := range v {
			v[i] = strip(v[i])
		}
	}
	return v
}

func compare(mErr bool, mText string, cErr bool, cText string) (verdict, why string) {
	switch {
	case mErr != cErr:
		return "DIFFERENT", fmt.Sprintf("MCP error=%v, CLI error=%v", mErr, cErr)
	case mErr:
		if mText == cText {
			return "SAME", "identical error text"
		}
		return "DIFFERENT", "error text differs"
	}
	const pgpMsg = "-----BEGIN PGP MESSAGE-----"
	if strings.HasPrefix(mText, pgpMsg) && strings.HasPrefix(cText, pgpMsg) {
		return "SAME", "both an armored encrypted message (ciphertext differs per run)"
	}
	var a, b any
	ea, eb := json.Unmarshal([]byte(mText), &a), json.Unmarshal([]byte(cText), &b)
	if ea != nil || eb != nil {
		if mText == cText {
			return "SAME", "identical text"
		}
		return "DIFFERENT", "output differs and is not JSON"
	}
	if fmt.Sprint(strip(a)) == fmt.Sprint(strip(b)) {
		return "SAME", "identical JSON"
	}
	if fmt.Sprint(shape(a)) == fmt.Sprint(shape(b)) {
		return "SAME", "same JSON shape (values are random per run)"
	}
	return "DIFFERENT", "JSON differs"
}

var bareRe = regexp.MustCompile(`^(?:Error:\s*)?(?:HTTP\s*)?\d{3,5}\.?$|^(?:Error:\s*)?(?:[A-Za-z ]{0,20})?(?:code|status)\s*[:=]?\s*\d{3,5}\.?$`)

// isBare says the whole error is a code with no sentence around it.
func isBare(text string) bool {
	first := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	if bareRe.MatchString(first) {
		return true
	}
	words := strings.Fields(strings.TrimPrefix(first, "Error:"))
	return len(words) < 3
}

func cell(isErr bool, s string) string {
	s = strings.NewReplacer("\n", " / ", "|", "\\|").Replace(s)
	if len(s) > 150 {
		s = s[:150] + "..."
	}
	if isErr {
		return "ERR " + s
	}
	return "ok " + s
}
