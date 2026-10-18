package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// callRaw is call, but a binary payload comes back as bytes.
func callRaw(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (text string, blob []byte, isErr bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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

type mailRow struct {
	ID             string   `json:"id"`
	ConversationID string   `json:"conversation_id"`
	Subject        string   `json:"subject"`
	Unread         int      `json:"unread"`
	NumAttachments int      `json:"num_attachments"`
	Labels         []string `json:"labels"`
}

// TestLiveMail drives the mail tools on messages of its own: it sends mail to
// the account's own address and works on the received copies. Everything it
// makes has a subject or name that starts with proton-mcp-test- and a
// timestamp, and is removed by exact ID at the end.
func TestLiveMail(t *testing.T) {
	cs := live(t)
	ok := func(name string, args map[string]any) string {
		t.Helper()
		out, isErr := call(t, cs, name, args)
		t.Logf("%-34s %.100q", name, strings.ReplaceAll(out, "\n", " "))
		if isErr {
			t.Fatalf("%s failed: %s", name, out)
		}
		return out
	}

	me, _ := call(t, cs, "account_get", map[string]any{})
	self := field(t, me, "email")
	tag := "proton-mcp-test-" + time.Now().Format("150405")
	if !strings.HasPrefix(tag, "proton-mcp-test-") {
		t.Fatal("bad tag")
	}

	folders := []string{"all", "inbox", "sent", "trash", "spam", "drafts", "archive"}
	// find lists what carries this run's tag, in every folder that could hold it.
	find := func(extra ...string) []mailRow {
		var rows []mailRow
		seen := map[string]bool{}
		for _, f := range append(folders, extra...) {
			out, isErr := call(t, cs, "mail_messages_list", map[string]any{"folder": f, "keyword": tag, "limit": 50})
			if isErr {
				continue
			}
			var env struct {
				Messages []mailRow `json:"messages"`
			}
			_ = json.Unmarshal([]byte(out), &env)
			for _, m := range env.Messages {
				if strings.Contains(m.Subject, tag) && !seen[m.ID] {
					seen[m.ID] = true
					rows = append(rows, m)
				}
			}
		}
		return rows
	}
	var labelName, folderName string
	t.Cleanup(func() {
		for _, m := range find(labelName, folderName) {
			if !strings.Contains(m.Subject, tag) {
				continue
			}
			o, e := call(t, cs, "mail_messages_delete", map[string]any{"ref": []any{m.ID}, "confirm": true})
			t.Logf("cleanup delete %q: err=%v %.80q", m.Subject, e, o)
		}
		if labelName != "" {
			call(t, cs, "mail_settings_labels_delete", map[string]any{"ref": []any{labelName}, "confirm": true})
		}
		if folderName != "" {
			call(t, cs, "mail_settings_folders_delete", map[string]any{"ref": []any{folderName}, "confirm": true})
		}
	})
	// wait polls one folder for a message with this exact subject.
	wait := func(subject, folder string) mailRow {
		t.Helper()
		for i := 0; i < 24; i++ {
			out, _ := call(t, cs, "mail_messages_list", map[string]any{"folder": folder, "keyword": subject, "limit": 20})
			var env struct {
				Messages []mailRow `json:"messages"`
			}
			_ = json.Unmarshal([]byte(out), &env)
			for _, m := range env.Messages {
				if m.Subject == subject {
					return m
				}
			}
			time.Sleep(5 * time.Second)
		}
		t.Fatalf("no message %q appeared in %s", subject, folder)
		return mailRow{}
	}
	// row reads one message back by ID (list lags the index, so ask by folder).
	row := func(id, folder string) (mailRow, bool) {
		out, _ := call(t, cs, "mail_messages_list", map[string]any{"folder": folder, "keyword": tag, "limit": 50})
		var env struct {
			Messages []mailRow `json:"messages"`
		}
		_ = json.Unmarshal([]byte(out), &env)
		for _, m := range env.Messages {
			if m.ID == id {
				return m, true
			}
		}
		return mailRow{}, false
	}
	eventually := func(what string, cond func() bool) {
		t.Helper()
		for i := 0; i < 12; i++ {
			if cond() {
				return
			}
			time.Sleep(4 * time.Second)
		}
		t.Errorf("never became true: %s", what)
	}

	// --- Send to self, with an attachment.
	payload := "línea uno\nlínea dos\ttab\n\x01\x02 fin\n"
	ok("mail_messages_send", map[string]any{
		"to": []any{self}, "subject": tag, "body": "cuerpo de prueba",
		"attach": []any{map[string]any{"name": "nota.txt", "text": payload}},
		"confirm": true,
	})
	msg := wait(tag, "inbox")
	id := msg.ID
	t.Logf("received copy %s attachments=%d", id[:8], msg.NumAttachments)

	// --- Unconfirmed send, reply and forward are only previewed.
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"mail_messages_send", map[string]any{"to": []any{self}, "subject": tag + "-held", "body": "x"}},
		{"mail_messages_reply", map[string]any{"ref": id, "body": "held reply"}},
		{"mail_messages_forward", map[string]any{"ref": id, "to": []any{self}, "body": "held forward"}},
	} {
		out, isErr := call(t, cs, c.tool, c.args)
		if isErr || !strings.Contains(out, "Nothing was changed") {
			t.Errorf("%s without confirm must only preview: err=%v %.300s", c.tool, isErr, out)
		}
	}

	// --- Read state.
	ok("mail_messages_mark_unread", map[string]any{"ref": []any{id}})
	eventually("unread", func() bool { m, f := row(id, "inbox"); return f && m.Unread == 1 })
	ok("mail_messages_mark_read", map[string]any{"ref": []any{id}})
	eventually("read", func() bool { m, f := row(id, "inbox"); return f && m.Unread == 0 })

	// --- Star.
	ok("mail_messages_star", map[string]any{"ref": []any{id}})
	eventually("starred", func() bool { m, f := row(id, "starred"); return f && slices.Contains(m.Labels, "10") })
	ok("mail_messages_unstar", map[string]any{"ref": []any{id}})
	eventually("unstarred", func() bool { _, f := row(id, "starred"); return !f })

	// --- Label.
	labelName = tag + "-lbl"
	ok("mail_settings_labels_create", map[string]any{"name": labelName})
	ok("mail_messages_label", map[string]any{"ref": []any{id}, "label": labelName})
	eventually("labelled", func() bool { _, f := row(id, labelName); return f })
	if m, f := row(id, "inbox"); !f {
		t.Errorf("labelling must leave the message in the inbox")
	} else {
		t.Logf("labels after label: %v", m.Labels)
	}
	ok("mail_messages_unlabel", map[string]any{"ref": []any{id}, "label": labelName})
	eventually("unlabelled", func() bool { _, f := row(id, labelName); return !f })

	// --- Move between folders.
	folderName = tag + "-fld"
	ok("mail_settings_folders_create", map[string]any{"name": folderName})
	ok("mail_messages_move", map[string]any{"ref": []any{id}, "into": folderName})
	eventually("in folder", func() bool { _, f := row(id, folderName); return f })
	eventually("out of inbox", func() bool { _, f := row(id, "inbox"); return !f })
	ok("mail_messages_move", map[string]any{"ref": []any{id}, "into": "archive"})
	eventually("in archive", func() bool { _, f := row(id, "archive"); return f })
	ok("mail_messages_move", map[string]any{"ref": []any{id}, "into": "inbox"})
	eventually("back in inbox", func() bool { _, f := row(id, "inbox"); return f })

	// --- Trash and restore.
	ok("mail_messages_trash", map[string]any{"ref": []any{id}})
	eventually("in trash", func() bool { _, f := row(id, "trash"); return f })
	ok("mail_messages_move", map[string]any{"ref": []any{id}, "into": "inbox"})
	eventually("restored", func() bool { _, f := row(id, "inbox"); return f })

	// --- Read it, export it, attachments.
	if got := ok("mail_messages_get", map[string]any{"ref": id}); !strings.Contains(got, "cuerpo de prueba") {
		t.Errorf("get lacks the body: %.300s", got)
	}
	exp, blob, isErr := callRaw(t, cs, "mail_messages_export", map[string]any{"ref": []any{id}})
	if isErr || !strings.Contains(exp+string(blob), "Subject: "+tag) {
		t.Errorf("export did not return the message: err=%v text=%.200q blob=%d bytes", isErr, exp, len(blob))
	}
	al := ok("mail_messages_attachments_list", map[string]any{"ref": id})
	if !strings.Contains(al, "nota.txt") {
		t.Errorf("attachment list lacks nota.txt: %.300s", al)
	}
	txt, blob, isErr := callRaw(t, cs, "mail_messages_attachments_download", map[string]any{"ref": id, "attachment_ref": "nota.txt"})
	if isErr || txt != payload && string(blob) != payload {
		t.Errorf("downloaded attachment differs: err=%v text=%q blob=%q want %q", isErr, txt, blob, payload)
	}
	all := ok("mail_conversations_attachments_list", map[string]any{"ref": msg.ConversationID})
	if !strings.Contains(all, "nota.txt") {
		t.Errorf("conversation attachment list lacks nota.txt: %.300s", all)
	}

	// --- Conversations.
	cl := ok("mail_conversations_list", map[string]any{"folder": "all", "keyword": tag})
	if !strings.Contains(cl, msg.ConversationID) {
		t.Errorf("conversation list lacks our thread: %.300s", cl)
	}
	if cg := ok("mail_conversations_get", map[string]any{"ref": msg.ConversationID}); !strings.Contains(cg, "cuerpo de prueba") {
		t.Errorf("conversation get lacks the body: %.300s", cg)
	}
	ok("mail_conversations_get", map[string]any{"ref": msg.ConversationID, "summary": true})
	ok("mail_conversations_count", map[string]any{})
	ok("mail_conversations_count", map[string]any{"folder": "inbox"})
	ok("mail_messages_count", map[string]any{})
	var cnt struct {
		Rows []struct {
			Name  string `json:"name"`
			Total int    `json:"total"`
		} `json:"folders_or_labels"`
	}
	_ = json.Unmarshal([]byte(ok("mail_messages_count", map[string]any{"folder": "inbox"})), &cnt)
	if len(cnt.Rows) != 1 || cnt.Rows[0].Total < 1 {
		t.Errorf("inbox count unexpected: %+v", cnt)
	}

	// --- Confirmed reply and forward, to self.
	ok("mail_messages_reply", map[string]any{"ref": id, "body": "respuesta de prueba", "confirm": true})
	re := wait("Re: "+tag, "inbox")
	ok("mail_messages_forward", map[string]any{"ref": id, "to": []any{self}, "body": "reenvio de prueba", "confirm": true})
	fw := wait("Fw: "+tag, "inbox")
	if fw.NumAttachments != 1 {
		t.Errorf("forward should carry the attachment, has %d", fw.NumAttachments)
	}
	if got := ok("mail_messages_get", map[string]any{"ref": re.ID}); !strings.Contains(got, "respuesta de prueba") {
		t.Errorf("reply body missing: %.300s", got)
	}
	// None of the held calls sent anything.
	for _, m := range find() {
		if strings.HasSuffix(m.Subject, "-held") || strings.Contains(m.Subject, "held") {
			t.Errorf("a held call sent %q", m.Subject)
		}
	}
	if n := len(find()); n < 3 {
		t.Errorf("expected at least the original, reply and forward, found %d", n)
	}

	// --- A binary attachment survives the trip as bytes.
	bin := []byte{0, 1, 2, 0xff, 0xfe, 0x80, 'p', 'n', 'g', 0, 0xc3, 0x28}
	binTag := tag + "-bin"
	ok("mail_messages_send", map[string]any{
		"to": []any{self}, "subject": binTag, "body": "binario",
		"attach":  []any{map[string]any{"name": "datos.bin", "base64": "AAEC//6AcG5nAMMo"}},
		"confirm": true,
	})
	bm := wait(binTag, "inbox")
	_, got, isErr := callRaw(t, cs, "mail_messages_attachments_download", map[string]any{"ref": bm.ID, "attachment_ref": "datos.bin"})
	if isErr || !bytes.Equal(got, bin) {
		t.Errorf("binary attachment differs: err=%v got=% x want % x", isErr, got, bin)
	}

	// --- Drafts: create, update, read back.
	ok("mail_drafts_create", map[string]any{"to": []any{self}, "subject": tag + "-draft", "body": "primero"})
	dm := wait(tag+"-draft", "drafts")
	ok("mail_drafts_update", map[string]any{"ref": dm.ID, "subject": tag + "-draft2", "body": "segundo"})
	dm2 := wait(tag+"-draft2", "drafts")
	if got := ok("mail_messages_get", map[string]any{"ref": dm2.ID}); !strings.Contains(got, "segundo") {
		t.Errorf("draft update not visible: %.300s", got)
	}

	// --- Settings reads.
	for _, name := range []string{
		"mail_settings_get", "mail_settings_list", "mail_settings_autoreply_get", "mail_settings_labels_list",
		"mail_settings_folders_list", "mail_settings_addresses_list", "mail_settings_filters_list",
		"mail_settings_categories_list", "mail_settings_senders_list", "mail_settings_forwarding_list",
		"mail_settings_domains_list", "mail_mailing_lists_list", "mail_drafts_list",
	} {
		out, e := call(t, cs, name, map[string]any{})
		t.Logf("%-34s err=%-5v bytes=%-6d %.80q", name, e, len(out), strings.ReplaceAll(out, "\n", " "))
		if e {
			t.Errorf("%s failed: %s", name, out)
		}
	}
	if ll, _ := call(t, cs, "mail_settings_labels_list", map[string]any{}); !strings.Contains(ll, labelName) {
		t.Errorf("label list lacks the label just made")
	}
}
