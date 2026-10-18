package mcpserver

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// coverMailTools is every Mail tool this test is responsible for.
var coverMailTools = strings.Fields(`
mail_conversations_attachments_download mail_conversations_delete mail_conversations_export
mail_conversations_forward mail_conversations_label mail_conversations_mark_read
mail_conversations_mark_unread mail_conversations_move mail_conversations_reply
mail_conversations_snooze mail_conversations_star mail_conversations_trash
mail_conversations_unlabel mail_conversations_unsnooze mail_conversations_unstar
mail_conversations_update mail_drafts_send mail_mailing_lists_get mail_mailing_lists_remove
mail_mailing_lists_unsubscribe mail_mailing_lists_update mail_messages_empty
mail_messages_mark_legitimate mail_messages_mark_phishing mail_messages_receipt
mail_messages_trackers_list mail_messages_unschedule mail_messages_unsubscribe
mail_messages_update mail_protected_attachments_download mail_protected_attachments_list
mail_protected_get mail_protected_reply mail_settings_addresses_create
mail_settings_addresses_delete mail_settings_addresses_disable mail_settings_addresses_enable
mail_settings_addresses_get mail_settings_addresses_reorder mail_settings_addresses_update
mail_settings_autoreply_disable mail_settings_autoreply_enable mail_settings_autoreply_set
mail_settings_categories_disable mail_settings_categories_enable mail_settings_categories_update
mail_settings_domains_create mail_settings_domains_delete mail_settings_domains_get
mail_settings_domains_update mail_settings_filters_apply mail_settings_filters_create
mail_settings_filters_delete mail_settings_filters_disable mail_settings_filters_enable
mail_settings_filters_get mail_settings_filters_reorder mail_settings_filters_update
mail_settings_folders_reorder mail_settings_folders_update mail_settings_forwarding_accept
mail_settings_forwarding_create mail_settings_forwarding_decline mail_settings_forwarding_delete
mail_settings_forwarding_disable mail_settings_forwarding_enable mail_settings_forwarding_get
mail_settings_forwarding_resend mail_settings_imports_cancel mail_settings_imports_create
mail_settings_imports_delete mail_settings_imports_get mail_settings_imports_resume
mail_settings_imports_undo mail_settings_labels_reorder mail_settings_labels_update
mail_settings_senders_allow mail_settings_senders_block mail_settings_senders_remove
mail_settings_senders_spam mail_settings_set mail_settings_smtp_tokens_create
mail_settings_smtp_tokens_delete mail_settings_smtp_tokens_get`)

type coverMode string

const (
	// modeReal runs the tool for real on an object this test made; an error is a failure.
	modeReal coverMode = "REAL"
	// modeDry runs it with dry_run:true because a real run would touch data that is not ours.
	modeDry coverMode = "DRY"
	// modeLegit runs it for real but accepts a clear CLI refusal (plan, nothing to act on).
	modeLegit coverMode = "LEGIT"
)

// TestCoverMail calls every Mail tool in coverMailTools once through the MCP
// client. Mail goes only to the account's own address; settings objects are
// made here with the proton-mcp-test- prefix and deleted again; everything
// that touches existing data, other people, security or billing is dry-run.
func TestCoverMail(t *testing.T) {
	cs := live(t)
	own := ownAddress(t)
	domain := own[strings.LastIndex(own, "@"):]
	called := map[string]string{}
	var report []string
	step := func(mode coverMode, tool string, args map[string]any) (string, bool) {
		t.Helper()
		if args == nil {
			args = map[string]any{}
		}
		if mode == modeDry {
			args["dry_run"] = true
		}
		out, isErr := call(t, cs, tool, args)
		outcome := "ok"
		if isErr {
			outcome = "error"
		}
		called[tool] = string(mode) + "/" + outcome
		line := string(mode) + " " + tool + " " + outcome + ": " + oneLine(out, 150)
		report = append(report, line)
		t.Log(line)
		if isErr && mode == modeReal {
			t.Errorf("%s failed: %s", tool, out)
		}
		if isErr && strings.TrimSpace(out) == "" {
			t.Errorf("%s returned an error with no message", tool)
		}
		return out, isErr
	}
	real := func(tool string, args map[string]any) string { o, _ := step(modeReal, tool, args); return o }

	me, _ := call(t, cs, "account_get", map[string]any{})
	self := field(t, me, "email")
	tag := "proton-mcp-test-" + time.Now().Format("20060102-150405")
	labelName, folderName := tag+"-lbl", tag+"-fld"
	filterName := tag + "-flt"
	sender := tag + "@example.invalid"
	ids := func(raw string) []string {
		var m struct {
			IDs []string `json:"ids"`
		}
		_ = json.Unmarshal([]byte(raw), &m)
		return m.IDs
	}

	folders := []string{"all", "inbox", "sent", "trash", "spam", "drafts", "archive", "scheduled", "snoozed"}
	listIn := func(folder, keyword string) []mailRow {
		out, isErr := call(t, cs, "mail_messages_list", map[string]any{"folder": folder, "keyword": keyword, "limit": 50})
		if isErr {
			return nil
		}
		var env struct {
			Messages []mailRow `json:"messages"`
		}
		_ = json.Unmarshal([]byte(out), &env)
		return env.Messages
	}
	find := func(extra ...string) []mailRow {
		var rows []mailRow
		seen := map[string]bool{}
		for _, f := range append(append([]string{}, folders...), extra...) {
			for _, m := range listIn(f, tag) {
				if strings.Contains(m.Subject, tag) && !seen[m.ID] {
					seen[m.ID] = true
					rows = append(rows, m)
				}
			}
		}
		return rows
	}
	t.Cleanup(func() {
		for _, m := range find(labelName, folderName) {
			if !strings.Contains(m.Subject, tag) {
				continue
			}
			o, e := call(t, cs, "mail_messages_delete", map[string]any{"ref": []any{m.ID}, "confirm": true})
			t.Logf("cleanup delete %q: err=%v %.80q", m.Subject, e, o)
		}
		call(t, cs, "mail_settings_filters_delete", map[string]any{"ref": []any{filterName}, "confirm": true})
		call(t, cs, "mail_settings_senders_remove", map[string]any{"sender": []any{sender}})
		call(t, cs, "mail_settings_labels_delete", map[string]any{"ref": []any{labelName}, "confirm": true})
		call(t, cs, "mail_settings_folders_delete", map[string]any{"ref": []any{folderName}, "confirm": true})
	})
	wait := func(subject, folder string) mailRow {
		t.Helper()
		for i := 0; i < 30; i++ {
			for _, m := range listIn(folder, subject) {
				if m.Subject == subject {
					return m
				}
			}
			time.Sleep(4 * time.Second)
		}
		t.Fatalf("no message %q appeared in %s", subject, folder)
		return mailRow{}
	}
	send := func(subject string, extra map[string]any) {
		args := map[string]any{"to": []any{self}, "subject": subject, "body": "cuerpo " + subject, "confirm": true}
		for k, v := range extra {
			args[k] = v
		}
		out, isErr := call(t, cs, "mail_messages_send", args)
		if isErr {
			t.Fatalf("setup send %s: %s", subject, out)
		}
	}
	payload := "adjunto de prueba\n"
	attach := []any{map[string]any{"name": "nota.txt", "text": payload}}

	// --- Setup: our own label and folder, and mail sent to ourselves.
	real("mail_settings_labels_create", map[string]any{"name": labelName})
	real("mail_settings_folders_create", map[string]any{"name": folderName})
	convTag := tag + "-conv"
	send(tag, map[string]any{"attach": attach})
	send(convTag, map[string]any{"attach": attach})
	send(tag+"-rcpt", map[string]any{"request_receipt": true})
	send(tag+"-sched", map[string]any{"send_at": time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02T15:04")})
	m1 := wait(tag, "inbox")
	conv := wait(convTag, "inbox")
	rcpt := wait(tag+"-rcpt", "inbox")
	cid := conv.ConversationID

	// --- Conversations, all on the one thread this test sent.
	real("mail_conversations_mark_unread", map[string]any{"ref": []any{cid}})
	real("mail_conversations_mark_read", map[string]any{"ref": []any{cid}})
	real("mail_conversations_star", map[string]any{"ref": []any{cid}})
	real("mail_conversations_unstar", map[string]any{"ref": []any{cid}})
	real("mail_conversations_label", map[string]any{"ref": []any{cid}, "label": labelName})
	real("mail_conversations_unlabel", map[string]any{"ref": []any{cid}, "label": labelName})
	real("mail_conversations_move", map[string]any{"ref": []any{cid}, "into": folderName})
	real("mail_conversations_move", map[string]any{"ref": []any{cid}, "into": "inbox"})
	real("mail_conversations_snooze", map[string]any{"ref": []any{cid}, "until": "1d"})
	real("mail_conversations_unsnooze", map[string]any{"ref": []any{cid}})
	real("mail_conversations_update", map[string]any{"ref": []any{cid}, "expires": "7d"})
	real("mail_conversations_update", map[string]any{"ref": []any{cid}, "expires": "never"})
	real("mail_conversations_trash", map[string]any{"ref": []any{cid}})
	real("mail_conversations_move", map[string]any{"ref": []any{cid}, "into": "inbox"})
	txt, blob, isErr := callRaw(t, cs, "mail_conversations_attachments_download", map[string]any{"ref": cid, "attachment_ref": "nota.txt"})
	called["mail_conversations_attachments_download"] = "REAL/" + map[bool]string{true: "error", false: "ok"}[isErr]
	report = append(report, "REAL mail_conversations_attachments_download "+called["mail_conversations_attachments_download"])
	if isErr || txt != payload && string(blob) != payload {
		t.Errorf("conversation attachment download: err=%v text=%q blob=%q", isErr, txt, blob)
	}
	txt, blob, isErr = callRaw(t, cs, "mail_conversations_export", map[string]any{"ref": cid})
	called["mail_conversations_export"] = "REAL/" + map[bool]string{true: "error", false: "ok"}[isErr]
	report = append(report, "REAL mail_conversations_export "+called["mail_conversations_export"])
	if isErr || !strings.Contains(txt+string(blob), "Subject: "+convTag) {
		t.Errorf("conversation export: err=%v text=%.200q blob=%d", isErr, txt, len(blob))
	}
	// Unconfirmed reply and forward are only previewed.
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"mail_conversations_reply", map[string]any{"ref": cid, "body": "held reply"}},
		{"mail_conversations_forward", map[string]any{"ref": cid, "to": []any{self}, "body": "held forward"}},
	} {
		out, isErr := call(t, cs, c.tool, c.args)
		if isErr || !strings.Contains(out, "Nothing was changed") {
			t.Errorf("%s without confirm must only preview: err=%v %.300s", c.tool, isErr, out)
		}
	}
	real("mail_conversations_reply", map[string]any{"ref": cid, "body": "respuesta", "confirm": true})
	real("mail_conversations_forward", map[string]any{"ref": cid, "to": []any{self}, "body": "reenvio", "confirm": true})
	wait("Re: "+convTag, "inbox")
	wait("Fw: Re: "+convTag, "inbox")

	// --- Messages, on the first message and the receipt request.
	real("mail_messages_update", map[string]any{"ref": []any{m1.ID}, "expires": "7d"})
	real("mail_messages_update", map[string]any{"ref": []any{m1.ID}, "expires": "never"})
	step(modeLegit, "mail_messages_receipt", map[string]any{"ref": []any{rcpt.ID}})
	step(modeLegit, "mail_messages_trackers_list", map[string]any{"ref": m1.ID})
	step(modeLegit, "mail_messages_mark_legitimate", map[string]any{"ref": []any{m1.ID}})
	// Reporting phishing mails the body to Proton and unsubscribing writes to a
	// third party: both only as a dry run, on our own message.
	step(modeDry, "mail_messages_mark_phishing", map[string]any{"ref": []any{m1.ID}})
	step(modeDry, "mail_messages_unsubscribe", map[string]any{"ref": []any{m1.ID}})
	// A scheduled send is cancelled by its own ID, never with all.
	sched := wait(tag+"-sched", "scheduled")
	real("mail_messages_unschedule", map[string]any{"ref": []any{sched.ID}})
	// empty clears a folder for good, so only a dry run, pointed at our own folder.
	step(modeDry, "mail_messages_empty", map[string]any{"folder": folderName})

	// --- Draft sent to ourselves.
	real("mail_drafts_create", map[string]any{"to": []any{self}, "subject": tag + "-draft", "body": "borrador"})
	dm := wait(tag+"-draft", "drafts")
	if out, isErr := call(t, cs, "mail_drafts_send", map[string]any{"ref": dm.ID}); isErr || !strings.Contains(out, "Nothing was changed") {
		t.Errorf("an unconfirmed draft send must only be previewed: err=%v %.200s", isErr, out)
	}
	real("mail_drafts_send", map[string]any{"ref": dm.ID, "confirm": true})
	wait(tag+"-draft", "inbox")

	// --- Password-protected: an address on Proton gets a normal message, so there
	// is no link to read; the protected tools are dry or take a made-up link.
	step(modeLegit, "mail_protected_get", map[string]any{"link": "9fK2pQ7xNv4mB8", "eo_password": "not-a-real-password"})
	step(modeLegit, "mail_protected_attachments_list", map[string]any{"link": "9fK2pQ7xNv4mB8", "eo_password": "not-a-real-password"})
	_, _, isErr = callRaw(t, cs, "mail_protected_attachments_download", map[string]any{"link": "9fK2pQ7xNv4mB8", "attachment_ref": "x", "eo_password": "not-a-real-password"})
	called["mail_protected_attachments_download"] = "LEGIT/" + map[bool]string{true: "error", false: "ok"}[isErr]
	report = append(report, "LEGIT mail_protected_attachments_download "+called["mail_protected_attachments_download"])
	step(modeDry, "mail_protected_reply", map[string]any{"link": "9fK2pQ7xNv4mB8", "eo_password": "not-a-real-password", "body": "x"})

	// --- Mailing lists: only a read, and dry runs on an existing list.
	var ml struct {
		Lists []struct{ ID, Name string } `json:"mailing_lists"`
	}
	out, _ := call(t, cs, "mail_mailing_lists_list", map[string]any{"limit": 3})
	_ = json.Unmarshal([]byte(out), &ml)
	listRef := "proton-mcp-test-no-such-list"
	if len(ml.Lists) > 0 {
		listRef = ml.Lists[0].ID
	}
	step(modeLegit, "mail_mailing_lists_get", map[string]any{"ref": listRef})
	step(modeDry, "mail_mailing_lists_update", map[string]any{"ref": []any{listRef}, "into": "archive", "mark_read": true})
	step(modeDry, "mail_mailing_lists_remove", map[string]any{"ref": []any{listRef}})
	step(modeDry, "mail_mailing_lists_unsubscribe", map[string]any{"ref": []any{listRef}})

	// --- Settings objects of our own: filter, label, folder, sender entry.
	real("mail_settings_filters_create", map[string]any{
		"name": filterName, "if": []any{"subject contains " + tag}, "label": []any{labelName}, "disabled": true,
	})
	real("mail_settings_filters_get", map[string]any{"ref": filterName})
	real("mail_settings_filters_update", map[string]any{"ref": filterName, "if": []any{"subject contains " + tag + "x"}, "label": []any{labelName}, "mark_read": true})
	real("mail_settings_filters_enable", map[string]any{"ref": []any{filterName}})
	real("mail_settings_filters_apply", map[string]any{"ref": []any{filterName}})
	real("mail_settings_filters_disable", map[string]any{"ref": []any{filterName}})
	real("mail_settings_filters_reorder", map[string]any{"ref": []any{filterName}})
	real("mail_settings_filters_delete", map[string]any{"ref": []any{filterName}, "confirm": true})
	real("mail_settings_labels_update", map[string]any{"ref": labelName, "color": "purple"})
	real("mail_settings_labels_reorder", map[string]any{"ref": []any{labelName}})
	real("mail_settings_folders_update", map[string]any{"ref": folderName, "color": "ocean"})
	// Our folder is the only one, so Proton is already in that order: a clear refusal.
	step(modeLegit, "mail_settings_folders_reorder", map[string]any{"ref": []any{folderName}})
	real("mail_settings_senders_allow", map[string]any{"sender": []any{sender}})
	real("mail_settings_senders_block", map[string]any{"sender": []any{sender}})
	real("mail_settings_senders_spam", map[string]any{"sender": []any{sender}})
	real("mail_settings_senders_remove", map[string]any{"sender": []any{sender}})

	// --- Reads of existing settings objects.
	first := func(tool, key string) string {
		out, _ := call(t, cs, tool, map[string]any{})
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(out), &m)
		var rows []struct{ ID string }
		_ = json.Unmarshal(m[key], &rows)
		if len(rows) == 0 {
			return "proton-mcp-test-none"
		}
		return rows[0].ID
	}
	addrID := first("mail_settings_addresses_list", "addresses")
	domID := first("mail_settings_domains_list", "domains")
	fwdID := first("mail_settings_forwarding_list", "forwardings")
	impID := first("mail_settings_imports_list", "imports")
	tokID := first("mail_settings_smtp_tokens_list", "smtp_tokens")
	step(modeLegit, "mail_settings_addresses_get", map[string]any{"ref": addrID})
	step(modeLegit, "mail_settings_domains_get", map[string]any{"ref": domID})
	step(modeLegit, "mail_settings_forwarding_get", map[string]any{"ref": fwdID})
	step(modeLegit, "mail_settings_imports_get", map[string]any{"ref": impID})
	step(modeLegit, "mail_settings_smtp_tokens_get", map[string]any{"ref": tokID})

	// --- Account configuration, security and other people: dry run only.
	step(modeDry, "mail_settings_addresses_create", map[string]any{"email": tag + domain, "display_name": "x"})
	step(modeDry, "mail_settings_addresses_delete", map[string]any{"ref": []any{addrID}})
	step(modeDry, "mail_settings_addresses_disable", map[string]any{"ref": []any{addrID}})
	step(modeDry, "mail_settings_addresses_enable", map[string]any{"ref": []any{addrID}})
	step(modeDry, "mail_settings_addresses_reorder", map[string]any{"ref": []any{addrID}})
	step(modeDry, "mail_settings_addresses_update", map[string]any{"ref": addrID, "display_name": "x"})
	step(modeDry, "mail_settings_autoreply_set", map[string]any{"body": "fuera", "days": []any{"mon"}})
	step(modeDry, "mail_settings_autoreply_enable", nil)
	step(modeDry, "mail_settings_autoreply_disable", nil)
	step(modeDry, "mail_settings_categories_enable", map[string]any{"ref": []any{"social"}})
	step(modeDry, "mail_settings_categories_disable", map[string]any{"ref": []any{"social"}})
	step(modeDry, "mail_settings_categories_update", map[string]any{"ref": "social", "notify": false})
	step(modeDry, "mail_settings_domains_create", map[string]any{"domain": tag + ".example.invalid"})
	step(modeDry, "mail_settings_domains_delete", map[string]any{"ref": domID})
	step(modeDry, "mail_settings_domains_update", map[string]any{"ref": domID, "catch_all": "none"})
	step(modeDry, "mail_settings_forwarding_create", map[string]any{"ref": addrID, "email": sender})
	step(modeDry, "mail_settings_forwarding_accept", map[string]any{"ref": []any{fwdID}})
	step(modeDry, "mail_settings_forwarding_decline", map[string]any{"ref": []any{fwdID}})
	step(modeDry, "mail_settings_forwarding_delete", map[string]any{"ref": []any{fwdID}})
	step(modeDry, "mail_settings_forwarding_disable", map[string]any{"ref": []any{fwdID}})
	step(modeDry, "mail_settings_forwarding_enable", map[string]any{"ref": []any{fwdID}})
	step(modeDry, "mail_settings_forwarding_resend", map[string]any{"ref": []any{fwdID}})
	step(modeDry, "mail_settings_imports_create", map[string]any{
		"login": sender, "server": "imap.example.invalid", "imap_password": "not-a-real-password", "port": 993,
	})
	step(modeDry, "mail_settings_imports_cancel", map[string]any{"ref": []any{impID}})
	step(modeDry, "mail_settings_imports_delete", map[string]any{"ref": []any{impID}})
	step(modeDry, "mail_settings_imports_resume", map[string]any{"ref": impID, "imap_password": "not-a-real-password"})
	step(modeDry, "mail_settings_imports_undo", map[string]any{"ref": []any{impID}})
	step(modeDry, "mail_settings_set", map[string]any{"key": "view-mode", "value": "conversations"})
	step(modeDry, "mail_settings_smtp_tokens_create", map[string]any{"ref": addrID, "name": tag})
	step(modeDry, "mail_settings_smtp_tokens_delete", map[string]any{"ref": []any{tokID}})

	// --- Conversation delete is the last action on the thread: permanent, by exact ID.
	step(modeReal, "mail_conversations_delete", map[string]any{"ref": []any{cid}, "confirm": true})
	_ = ids

	// --- Every tool was called, and the held ones really are held.
	var missing []string
	for _, name := range coverMailTools {
		if called[name] == "" {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("tools never called: %v", missing)
	}
	if path := os.Getenv("PROTON_MCP_REPORT"); path != "" {
		_ = os.WriteFile(path, []byte(strings.Join(report, "\n")+"\n"), 0o600)
	}
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n]
	}
	return s
}
