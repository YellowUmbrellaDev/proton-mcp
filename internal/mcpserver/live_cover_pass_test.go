package mcpserver

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestCoverPass runs every Pass tool nobody had executed. Everything real
// happens inside a vault of its own (proton-mcp-test-*) or on objects made here
// and removed here; anything that would reach other people, change the account's
// security, or empty shared state is a dry run or only previewed.
//
// REAL tools are expected to succeed; DRY ones are called with dry_run (or are
// held back by the irreversible-confirm rule); ERR ones are called with an input
// that cannot act, and must answer with a CLI message, not a protocol error.
func TestCoverPass(t *testing.T) {
	cs := live(t)
	stamp := time.Now().Format("150405")
	tag := "proton-mcp-test-" + stamp
	const own = "me@sigterm.vodka" // an address of this account: the only one mail goes to
	const primary = "sigterm015@proton.me"
	const other = "nobody@example.invalid"

	const (
		real = "REAL"
		dry  = "DRY"
		errc = "ERR"
		any_ = "ANY"
	)
	secretTools := map[string]bool{
		"pass_links_create": true, "pass_links_get": true, "pass_settings_access_tokens_create": true,
		"pass_items_totp": true, "pass_items_get": true, "pass_items_revisions_get": true,
		"pass_breaches_verify": true,
	}
	// step calls one tool and checks what the mode promises.
	step := func(mode, name string, args map[string]any) string {
		t.Helper()
		out, isErr := call(t, cs, name, args)
		show := strings.ReplaceAll(out, "\n", " ")
		if secretTools[name] {
			show = "(not shown)"
		}
		t.Logf("%-4s %-44s err=%-5v %.110q", mode, name, isErr, show)
		switch mode {
		case real, dry:
			if isErr {
				t.Errorf("%s (%s) failed: %.300s", name, mode, out)
			}
		case errc:
			if !isErr || strings.TrimSpace(out) == "" {
				t.Errorf("%s should refuse with a message: err=%v %.200s", name, isErr, out)
			}
		}
		if isErr {
			for _, bad := range []string{"is not an input of this tool", " is required", "must be a", "protocol"} {
				if strings.Contains(out, bad) {
					t.Errorf("%s: argument building defect: %.300s", name, out)
				}
			}
		}
		return out
	}
	ids := func(raw string) []string {
		var m struct {
			IDs []string `json:"ids"`
		}
		_ = json.Unmarshal([]byte(raw), &m)
		return m.IDs
	}
	one := func(raw string) string {
		t.Helper()
		v := ids(raw)
		if len(v) != 1 {
			t.Fatalf("expected one id from %.200s", raw)
		}
		return v[0]
	}
	cleanup := func(name string, args map[string]any) {
		t.Cleanup(func() {
			out, _ := call(t, cs, name, args)
			t.Logf("cleanup %s: %.100q", name, strings.ReplaceAll(out, "\n", " "))
		})
	}

	// ---- The vault everything lives in.
	vault := one(step(real, "pass_vaults_create", map[string]any{"name": tag}))
	cleanup("pass_vaults_delete", map[string]any{"ref": []any{vault}, "confirm": true})

	// ---- Vaults: get, update, hide, unhide (all on our own vault).
	step(real, "pass_vaults_get", map[string]any{"ref": vault})
	step(real, "pass_vaults_update", map[string]any{"ref": vault, "description": "proton-mcp-test", "icon": "star", "color": "teal"})
	step(real, "pass_vaults_hide", map[string]any{"ref": []any{vault}})
	step(real, "pass_vaults_unhide", map[string]any{"ref": []any{vault}})
	step(real, "pass_vaults_share_get", map[string]any{"ref": vault})
	// Sharing with, or giving a vault to, another person is never executed.
	step(dry, "pass_vaults_share_add", map[string]any{"ref": vault, "email": other, "access": "viewer", "dry_run": true})
	step(errc, "pass_vaults_share_update", map[string]any{"ref": vault, "email": other, "access": "editor", "dry_run": true})
	step(dry, "pass_vaults_share_confirm", map[string]any{"ref": vault, "email": other, "dry_run": true})
	step(errc, "pass_vaults_share_remove", map[string]any{"ref": vault, "email": other, "dry_run": true})
	// Transferring is irreversible, so it is held; the recipient is not a member,
	// so the CLI refuses the plan with a clear message.
	step(errc, "pass_vaults_transfer", map[string]any{"ref": vault, "email": other})
	step(errc, "pass_vaults_transfer", map[string]any{"ref": vault, "email": other, "dry_run": true})
	step(errc, "pass_invitations_accept", map[string]any{"ref": []any{tag + "-none"}, "dry_run": true})
	step(errc, "pass_invitations_decline", map[string]any{"ref": []any{tag + "-none"}, "dry_run": true})

	// ---- Items: a login with a TOTP secret and an attachment.
	login := one(step(real, "pass_items_create", map[string]any{
		"type": "login", "vault": vault, "name": tag + "-login", "username": "u", "generate_password": true,
		"secrets": []any{map[string]any{"field": "totp-uri", "text": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=x"}},
		"attach":  []any{map[string]any{"name": "a.txt", "text": "adjunto"}},
	}))
	note := one(step(real, "pass_items_create", map[string]any{"type": "note", "vault": vault, "name": tag + "-note", "note": "n"}))
	step(real, "pass_items_totp", map[string]any{"ref": login})
	step(real, "pass_items_update", map[string]any{"ref": login, "username": "u2", "note": "changed"})
	step(real, "pass_items_pin", map[string]any{"ref": []any{login}})
	step(real, "pass_items_unpin", map[string]any{"ref": []any{login}})
	step(real, "pass_items_exclude", map[string]any{"ref": []any{login}})
	step(real, "pass_items_include", map[string]any{"ref": []any{login}})
	step(real, "pass_items_revisions_list", map[string]any{"ref": login})
	step(real, "pass_items_revisions_get", map[string]any{"ref": login, "revision_ref": "1"})
	step(real, "pass_items_revisions_restore", map[string]any{"ref": login, "revision_ref": "1"})
	step(real, "pass_items_passkeys_list", map[string]any{"ref": login})
	// No passkey can be made through the CLI, so there is nothing to remove.
	step(errc, "pass_items_passkeys_remove", map[string]any{"ref": login, "passkey_ref": []any{"nobody"}})

	step(real, "pass_items_attachments_list", map[string]any{"ref": login})
	step(real, "pass_items_attachments_update", map[string]any{"ref": login, "attachment_ref": "a.txt", "name": "b.txt"})
	text, blob, isErr := callRaw(t, cs, "pass_items_attachments_download", map[string]any{"ref": login, "attachment_ref": "b.txt"})
	if isErr || !strings.Contains(text+string(blob), "adjunto") {
		t.Errorf("attachment download: err=%v %.100q", isErr, text)
	}
	t.Logf("REAL pass_items_attachments_download err=%v bytes=%d", isErr, len(text)+len(blob))
	step(real, "pass_items_update", map[string]any{"ref": login, "detach": []any{"b.txt"}})
	step(real, "pass_items_attachments_list", map[string]any{"ref": login, "removed": true})
	step(real, "pass_items_attachments_restore", map[string]any{"ref": login, "attachment_ref": []any{"b.txt"}})

	// Sharing an item with another person: preview only.
	step(real, "pass_items_share_get", map[string]any{"ref": login})
	step(dry, "pass_items_share_add", map[string]any{"ref": login, "email": other, "access": "viewer", "dry_run": true})
	step(errc, "pass_items_share_update", map[string]any{"ref": login, "email": other, "access": "editor", "dry_run": true})
	step(dry, "pass_items_share_confirm", map[string]any{"ref": login, "email": other, "dry_run": true})
	step(errc, "pass_items_share_remove", map[string]any{"ref": login, "email": other, "dry_run": true})

	// A link to our own item, deleted at once.
	var lk struct {
		LinkID string `json:"link_id"`
	}
	_ = json.Unmarshal([]byte(step(real, "pass_links_create", map[string]any{"ref": login, "expires": "1h", "views": 1})), &lk)
	link := lk.LinkID
	if link == "" {
		t.Fatal("no link_id in the created link")
	}
	cleanup("pass_links_revoke", map[string]any{"ref": []any{link}})
	step(real, "pass_links_get", map[string]any{"ref": link})
	step(real, "pass_links_revoke", map[string]any{"ref": []any{link}})

	// Trash: restore by exact id. The trash is never emptied for real, it may hold
	// other people's items.
	step(real, "pass_items_trash", map[string]any{"ref": []any{note}})
	step(real, "pass_trash_restore", map[string]any{"ref": []any{note}})
	held := step(dry, "pass_trash_empty", map[string]any{})
	if !strings.Contains(held, "Nothing was changed") {
		t.Errorf("an unconfirmed trash empty must only be previewed: %.200s", held)
	}
	step(dry, "pass_trash_empty", map[string]any{"dry_run": true})

	// ---- Folders.
	folder := one(step(real, "pass_folders_create", map[string]any{"name": tag + "-f", "vault": vault}))
	step(real, "pass_folders_update", map[string]any{"ref": folder, "name": tag + "-g"})

	// ---- Aliases and their contacts.
	alias := one(step(real, "pass_aliases_create", map[string]any{
		"prefix": tag, "mailbox": []any{primary}, "vault": vault, "name": tag + "-alias",
	}))
	step(real, "pass_aliases_disable", map[string]any{"ref": alias})
	step(real, "pass_aliases_enable", map[string]any{"ref": alias})
	step(real, "pass_aliases_contacts_create", map[string]any{"ref": alias, "email": "seller@example.com", "name": "Seller"})
	step(real, "pass_aliases_contacts_list", map[string]any{"ref": alias})
	step(real, "pass_aliases_contacts_block", map[string]any{"ref": alias, "alias_contact_ref": []any{"seller@example.com"}})
	step(real, "pass_aliases_contacts_allow", map[string]any{"ref": alias, "alias_contact_ref": []any{"seller@example.com"}})
	step(real, "pass_aliases_contacts_delete", map[string]any{"ref": alias, "alias_contact_ref": []any{"seller@example.com"}, "confirm": true})
	// Breach monitoring on our own alias: pause and resume.
	var aliasAddr string
	{
		var lst struct {
			Aliases []struct {
				Alias string `json:"alias"`
				Name  string `json:"name"`
			} `json:"aliases"`
		}
		out := step(real, "pass_aliases_list", map[string]any{"vault": vault})
		_ = json.Unmarshal([]byte(out), &lst)
		for _, a := range lst.Aliases {
			if a.Name == tag+"-alias" {
				aliasAddr = a.Alias
			}
		}
		if aliasAddr == "" {
			t.Fatalf("our alias is not listed: %.300s", out)
		}
	}
	step(real, "pass_breaches_disable", map[string]any{"ref": aliasAddr})
	step(real, "pass_breaches_enable", map[string]any{"ref": aliasAddr})
	step(real, "pass_breaches_get", map[string]any{"ref": aliasAddr})

	// ---- Breaches on an address of this account that Pass does not watch yet:
	// the code goes to our own mailbox and is read back through the mail tools.
	start := time.Now().Add(-time.Minute).Unix()
	cleanup("pass_breaches_delete", map[string]any{"ref": own, "confirm": true})
	// Proton limits verification emails per address; the CLI waits and retries, so
	// a refused creation takes minutes. That is a legitimate refusal: the rest of
	// the breach tools are then only planned.
	createOut, _, createErr := callRaw(t, cs, "pass_breaches_create", map[string]any{"email": own})
	t.Logf("REAL pass_breaches_create err=%v %.110q", createErr, strings.ReplaceAll(createOut, "\n", " "))
	if createErr {
		if !strings.Contains(createOut, "Too many verification emails") {
			t.Fatalf("pass_breaches_create failed: %.300s", createOut)
		}
		t.Logf("verification emails are rate limited; the remaining breach tools are only planned")
		for _, tool := range []string{"pass_breaches_resend", "pass_breaches_resolve", "pass_breaches_disable", "pass_breaches_enable"} {
			args := map[string]any{"ref": own, "dry_run": true}
			if tool == "pass_breaches_resolve" {
				args["ref"] = []any{own}
			}
			step(any_, tool, args)
		}
		step(any_, "pass_breaches_get", map[string]any{"ref": own})
		step(any_, "pass_breaches_verify", map[string]any{"ref": own, "code": "000000"})
		step(any_, "pass_breaches_delete", map[string]any{"ref": own, "confirm": true})
	} else {
		step(real, "pass_breaches_resend", map[string]any{"ref": own})
		code, mailIDs := "", map[string]bool{}
		for i := 0; i < 16 && code == ""; i++ {
			time.Sleep(5 * time.Second)
			list, _ := call(t, cs, "mail_messages_list", map[string]any{"keyword": "confirm your email address", "limit": 10})
			var env struct {
				Messages []struct {
					ID      string `json:"id"`
					Subject string `json:"subject"`
					Time    int64  `json:"time"`
				} `json:"messages"`
			}
			_ = json.Unmarshal([]byte(list), &env)
			newest := int64(0)
			for _, m := range env.Messages {
				if m.Time < start || !strings.Contains(m.Subject, "Proton Pass") {
					continue
				}
				mailIDs[m.ID] = true
				if m.Time >= newest {
					body, _ := call(t, cs, "mail_messages_get", map[string]any{"ref": m.ID})
					if c := regexp.MustCompile(`(?:\\n|\s)(\d{6})(?:\\n|\s)`).FindStringSubmatch(body); c != nil {
						code, newest = c[1], m.Time
					}
				}
			}
		}
		t.Cleanup(func() {
			for id := range mailIDs {
				call(t, cs, "mail_messages_delete", map[string]any{"ref": []any{id}, "confirm": true})
			}
		})
		if code == "" {
			t.Fatalf("no confirmation code arrived at %s", own)
		}
		step(real, "pass_breaches_verify", map[string]any{"ref": own, "code": code})
		step(any_, "pass_breaches_resolve", map[string]any{"ref": []any{own}}) // needs a plan with breach detail
		step(real, "pass_breaches_disable", map[string]any{"ref": own})
		step(real, "pass_breaches_enable", map[string]any{"ref": own})
		step(real, "pass_breaches_get", map[string]any{"ref": own})
		step(real, "pass_breaches_delete", map[string]any{"ref": own, "confirm": true})
	}

	// ---- Settings: a mailbox, a domain and a token of our own.
	step(real, "pass_settings_mailboxes_create", map[string]any{"email": own})
	cleanup("pass_settings_mailboxes_delete", map[string]any{"ref": own, "transfer_to": primary, "confirm": true})
	step(any_, "pass_settings_mailboxes_resend", map[string]any{"ref": own})
	step(any_, "pass_settings_mailboxes_verify", map[string]any{"ref": own, "code": "000000"})
	// Changing which mailbox is the default would change where every new alias
	// delivers: previewed only.
	step(dry, "pass_settings_mailboxes_update", map[string]any{"ref": own, "default": true, "dry_run": true})
	step(real, "pass_settings_mailboxes_delete", map[string]any{"ref": own, "transfer_to": primary, "confirm": true})

	domain := tag + ".example.com"
	step(real, "pass_settings_domains_create", map[string]any{"domain": domain})
	cleanup("pass_settings_domains_delete", map[string]any{"ref": domain, "confirm": true})
	step(real, "pass_settings_domains_get", map[string]any{"ref": domain})
	step(errc, "pass_settings_domains_update", map[string]any{"ref": domain, "display_name": "MCP test"}) // a domain with no DNS entries is refused
	step(errc, "pass_settings_domains_update", map[string]any{"ref": domain, "random_prefix": true, "dry_run": true})
	step(real, "pass_settings_domains_delete", map[string]any{"ref": domain, "confirm": true})

	step(real, "pass_settings_access_tokens_create", map[string]any{"name": tag + "-tok", "expires": "1h", "vault": []any{vault}})
	cleanup("pass_settings_access_tokens_delete", map[string]any{"ref": []any{tag + "-tok"}, "confirm": true})
	step(real, "pass_settings_access_tokens_get", map[string]any{"ref": tag + "-tok"})
	step(real, "pass_settings_access_tokens_update", map[string]any{"ref": tag + "-tok", "vault": []any{vault}})
	step(real, "pass_settings_access_tokens_activity_list", map[string]any{"ref": tag + "-tok"})
	step(real, "pass_settings_access_tokens_delete", map[string]any{"ref": []any{tag + "-tok"}, "confirm": true})

	// ---- The account's Pass lock: never changed. The password is a throwaway, so
	// even a slip could not lock the account with a value anybody uses.
	step(dry, "pass_settings_extra_password_enable", map[string]any{"extra_password": "proton-mcp-test-dry-" + stamp, "dry_run": true})
	step(errc, "pass_settings_extra_password_disable", map[string]any{"extra_password": "proton-mcp-test-dry-" + stamp, "dry_run": true})

	// ---- Export writes every vault the account owns, passwords included, and cannot
	// be limited to one: only an input the CLI refuses is sent.
	step(errc, "pass_export", map[string]any{"format": "banana"})

	step(real, "pass_vaults_delete", map[string]any{"ref": []any{vault}, "confirm": true})
}
