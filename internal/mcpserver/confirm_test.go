package mcpserver

import (
	"context"
	"strings"
	"testing"
)

// Anything that reaches other people, a public link, or the way the account can be
// recovered must wait for confirm. The rule is read off the whole path: the last
// word of `drive items share add` is just "add".
func TestEveryToolThatReachesPeopleWaitsForConfirm(t *testing.T) {
	tools, _, err := Catalog(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools {
		if !tool.Mutating {
			continue
		}
		path := strings.Join(tool.Path, " ")
		reaches := false
		for _, seg := range tool.Path[:len(tool.Path)-1] {
			switch seg {
			case "share", "invitations", "emergency-access", "recovery-contacts", "forwarding", "shared", "links":
				reaches = true
			}
		}
		switch tool.Path[len(tool.Path)-1] {
		case "send", "reply", "forward", "invite", "resend", "respond", "request", "access", "transfer", "grant", "merge", "accept", "decline", "abuse":
			reaches = true
		}
		if reaches && !tool.NeedsConfirm() {
			t.Errorf("%s (%s) reaches other people but runs on a first call", tool.Name, path)
		}
	}
}

func TestNamedExamplesAreHeld(t *testing.T) {
	tools, _, _ := Catalog(Options{})
	held := map[string]bool{}
	for _, tool := range tools {
		held[tool.Name] = tool.NeedsConfirm()
	}
	for _, name := range []string{
		"drive_items_share_add", "pass_vaults_share_add", "pass_items_share_add", "drive_photos_share_add",
		"calendar_settings_calendars_share_add", "account_settings_emergency_access_add",
		"account_settings_recovery_contacts_add", "mail_settings_forwarding_create",
		"drive_invitations_accept", "mail_messages_send", "pass_vaults_transfer",
		"pass_export", "account_keys_export",
	} {
		if v, ok := held[name]; !ok {
			t.Errorf("tool %s does not exist", name)
		} else if !v {
			t.Errorf("%s runs without confirm", name)
		}
	}
	// A plain read must not be held.
	for _, name := range []string{"mail_messages_list", "drive_items_list", "pass_items_list", "drive_items_share_get"} {
		if held[name] {
			t.Errorf("%s is a read and must not wait for confirm", name)
		}
	}
}

// pass_export is a read with no preview. Without confirm it is not run at all, and
// the caller is told how to go ahead; a dry_run is refused rather than run for
// real. The check is on the message because nothing may reach the CLI: the
// runner here has no profile at all.
func TestHeldDownloadIsNotRun(t *testing.T) {
	tools, _, _ := Catalog(Options{})
	var export Tool
	for _, tool := range tools {
		if tool.Name == "pass_export" {
			export = tool
		}
	}
	if export.Name == "" || !export.Download || !export.NeedsConfirm() {
		t.Fatalf("pass_export is not a held download: %+v", export)
	}
	r := Runner{Profile: "no-such-profile-xyz"}
	res := r.Call(context.Background(), export, map[string]any{})
	if !res.Held || res.IsError || !strings.Contains(res.Text, "confirm: true") {
		t.Errorf("a first call must wait for confirm without running anything: %+v", res)
	}
	res = r.Call(context.Background(), export, map[string]any{"dry_run": true})
	if !res.IsError || !strings.Contains(res.Text, "dry_run does not apply") {
		t.Errorf("dry_run on a download must be refused, not run: %+v", res)
	}
}
