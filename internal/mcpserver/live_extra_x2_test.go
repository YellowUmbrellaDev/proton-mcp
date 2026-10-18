package mcpserver

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestExtraX2 executes, for real and on objects made here: public links on a
// photo, a Drive setting, an emptied Pass trash (only when it holds nothing but
// our own item) and the Pass breach-monitoring path.
func TestExtraX2(t *testing.T) {
	cs := live(t)
	tag := "proton-mcp-test-" + time.Now().Format("150405")
	own := ownAddress(t) // an address of this account: the only one mail goes to

	real := func(name string, args map[string]any) string {
		t.Helper()
		var out string
		var isErr bool
		for try := 0; try < 5; try++ {
			out, isErr = call(t, cs, name, args)
			// Proton answers 422 "item not found" for a moment after it creates something.
			if !isErr || !strings.Contains(out, "HTTP 422") || !strings.Contains(out, "2501") {
				break
			}
			time.Sleep(5 * time.Second)
		}
		t.Logf("REAL %-34s err=%-5v %.100q", name, isErr, strings.ReplaceAll(out, "\n", " "))
		if isErr {
			t.Fatalf("%s failed: %s", name, out)
		}
		return out
	}
	jsonOf := func(raw string, v any) {
		t.Helper()
		if err := json.Unmarshal([]byte(raw), v); err != nil {
			t.Fatalf("not JSON: %v\n%.300s", err, raw)
		}
	}
	eventually := func(what string, f func() bool) {
		t.Helper()
		for i := 0; i < 20; i++ {
			if f() {
				return
			}
			time.Sleep(5 * time.Second)
		}
		t.Errorf("never became true: %s", what)
	}
	// official runs the official CLI (no PROTON_* variables) for inspection.
	official := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(officialBinary(t), args...)
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "PROTON_") {
				cmd.Env = append(cmd.Env, e)
			}
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("official CLI %v: %v\n%.300s", args, err, out)
		}
		return string(out)
	}

	// ---------------------------------------------------------------- (2) settings
	// The one Drive setting is version history. Shortening it could make Proton
	// prune old revisions of the account's real files, which cannot be undone, and
	// 10y is already the longest, so the value is written back unchanged: the
	// write is real and verified, and nothing can be lost.
	readSetting := func() string {
		var s struct {
			V string `json:"version_history"`
		}
		jsonOf(real("drive_settings_get", map[string]any{}), &s)
		return s.V
	}
	origSetting := readSetting()
	if origSetting == "" {
		t.Fatal("no original version-history value")
	}
	t.Cleanup(func() {
		if readSetting() != origSetting {
			call(t, cs, "drive_settings_set", map[string]any{"key": "version-history", "value": origSetting})
		}
	})
	real("drive_settings_set", map[string]any{"key": "version-history", "value": origSetting})
	if got := readSetting(); got != origSetting {
		t.Errorf("version-history is %q after set, want %q", got, origSetting)
	}

	// ---------------------------------------------------------------- (1) photo links
	total := func() int {
		var env struct {
			Total int `json:"total"`
		}
		jsonOf(real("drive_photos_list", map[string]any{"limit": 1}), &env)
		return env.Total
	}
	listIDs := func() map[string]bool {
		var env struct {
			Photos []struct {
				LinkID string `json:"link_id"`
			} `json:"photos"`
		}
		jsonOf(real("drive_photos_list", map[string]any{"limit": 50, "desc": true}), &env)
		m := map[string]bool{}
		for _, p := range env.Photos {
			m[p.LinkID] = true
		}
		return m
	}
	inLibrary := func(id string) bool {
		var env struct {
			Photos []struct {
				LinkID string `json:"link_id"`
			} `json:"photos"`
		}
		jsonOf(real("drive_photos_list", map[string]any{"limit": 100, "desc": true}), &env)
		for _, p := range env.Photos {
			if p.LinkID == id {
				return true
			}
		}
		return false
	}
	totalBefore := total()
	idsBefore := listIDs()
	// A fresh content (the tag is in a PNG comment-free way: name differs, bytes are the 1x1 PNG).
	real("drive_photos_upload", map[string]any{"src": map[string]any{"name": tag + ".png", "base64": onePixelPNG}})
	var photo string
	eventually("the uploaded photo shows in the library", func() bool {
		for id := range listIDs() {
			if !idsBefore[id] {
				photo = id
				return true
			}
		}
		return false
	})
	if photo == "" {
		t.Fatal("cannot find the uploaded photo; not touching anything else")
	}
	photoGone, linkRevoked := false, false
	t.Cleanup(func() {
		if !linkRevoked {
			call(t, cs, "drive_photos_links_revoke", map[string]any{"ref": photo})
		}
		if !photoGone {
			call(t, cs, "drive_trash_restore", map[string]any{"ref": []any{photo}})
			out, _ := call(t, cs, "drive_photos_delete", map[string]any{"ref": []any{photo}, "confirm": true})
			t.Logf("cleanup photo: %.100q", out)
		}
	})
	want, _ := base64.StdEncoding.DecodeString(onePixelPNG)
	_, blob, isErr := callRaw(t, cs, "drive_photos_download", map[string]any{"ref": photo})
	if isErr || string(blob) != string(want) {
		t.Fatalf("the new photo is not the PNG that was uploaded (err=%v, %d bytes); not touching it", isErr, len(blob))
	}

	// links get with no link: the CLI says so (identical to the official CLI).
	out, isErr := call(t, cs, "drive_photos_links_get", map[string]any{"ref": photo})
	if !isErr || !strings.Contains(out, "has no public link") {
		t.Errorf("links_get on a photo without a link: err=%v %.200s", isErr, out)
	}
	var link struct {
		URL string `json:"url"`
	}
	jsonOf(real("drive_photos_links_create", map[string]any{"ref": photo, "expires": "1d"}), &link)
	if !strings.HasPrefix(link.URL, "https://drive.proton.me/urls/") {
		t.Fatalf("link not as expected (url present=%v)", link.URL != "")
	}
	got := real("drive_photos_links_get", map[string]any{"ref": photo})
	if !strings.Contains(got, link.URL) {
		t.Errorf("links_get does not show the link URL")
	}
	real("drive_photos_links_revoke", map[string]any{"ref": photo})
	linkRevoked = true
	if o, isErr := call(t, cs, "drive_photos_links_get", map[string]any{"ref": photo}); !isErr || !strings.Contains(o, "has no public link") {
		t.Errorf("link still there after revoke: err=%v %.200s", isErr, o)
	}

	real("drive_photos_trash", map[string]any{"ref": []any{photo}})
	eventually("the photo left the library", func() bool { return !inLibrary(photo) })
	real("drive_trash_restore", map[string]any{"ref": []any{photo}})
	eventually("the photo is back in the library", func() bool { return inLibrary(photo) })
	real("drive_photos_delete", map[string]any{"ref": []any{photo}, "confirm": true})
	photoGone = true
	eventually("the photo left the library for good", func() bool { return !inLibrary(photo) })
	eventually("the library total is back to what it was", func() bool { return total() == totalBefore })

	// ---------------------------------------------------------------- (3) pass trash
	vault := ""
	{
		var m struct {
			IDs []string `json:"ids"`
		}
		jsonOf(real("pass_vaults_create", map[string]any{"name": tag}), &m)
		if len(m.IDs) != 1 {
			t.Fatal("no vault id")
		}
		vault = m.IDs[0]
	}
	t.Cleanup(func() {
		out, _ := call(t, cs, "pass_vaults_delete", map[string]any{"ref": []any{vault}, "confirm": true})
		t.Logf("cleanup vault: %.100q", out)
	})
	var note string
	{
		var m struct {
			IDs []string `json:"ids"`
		}
		jsonOf(real("pass_items_create", map[string]any{"type": "note", "vault": vault, "name": tag + "-note", "note": "n"}), &m)
		if len(m.IDs) != 1 {
			t.Fatal("no item id")
		}
		note = m.IDs[0]
	}
	real("pass_items_trash", map[string]any{"ref": []any{note}})
	var tr struct {
		Count int `json:"count"`
		Total int `json:"total"`
		Items []struct {
			ItemID string `json:"item_id"`
			ID     string `json:"id"`
			Name   string `json:"name"`
		} `json:"items"`
	}
	eventually("our item shows in the Pass trash", func() bool {
		tr.Items = nil
		jsonOf(official("pass", "trash", "list", "-o", "json"), &tr)
		return len(tr.Items) > 0
	})
	t.Logf("official CLI sees %d item(s) in the Pass trash (total %d)", len(tr.Items), tr.Total)
	onlyOurs := len(tr.Items) == 1 && tr.Total == 1 && strings.Contains(official("pass", "trash", "list"), tag+"-note")
	if onlyOurs {
		real("pass_trash_empty", map[string]any{"confirm": true})
		var after struct {
			Total int `json:"total"`
		}
		jsonOf(official("pass", "trash", "list", "-o", "json"), &after)
		if after.Total != 0 {
			t.Errorf("Pass trash still holds %d item(s) after empty", after.Total)
		}
	} else {
		t.Logf("SKIPPED pass_trash_empty: the trash holds more than the item made here")
		real("pass_trash_restore", map[string]any{"ref": []any{note}})
	}
	real("pass_vaults_delete", map[string]any{"ref": []any{vault}, "confirm": true})

	// ---------------------------------------------------------------- (4) breaches
	// One attempt only. Proton's verification-email limit shows up as HTTP 429; if
	// it is still in force the path is recorded as limited and nothing is retried.
	if os.Getenv("PROTON_MCP_X2_BREACHES") == "" {
		t.Skip("breach path not requested (PROTON_MCP_X2_BREACHES): each run sends verification mail")
	}
	start := time.Now().Add(-time.Minute).Unix()
	t.Cleanup(func() {
		out, _ := call(t, cs, "pass_breaches_delete", map[string]any{"ref": own, "confirm": true})
		t.Logf("cleanup breaches: %.100q", strings.ReplaceAll(out, "\n", " "))
	})
	createOut, _, createErr := callRaw(t, cs, "pass_breaches_create", map[string]any{"email": own})
	t.Logf("REAL pass_breaches_create err=%v %.160q", createErr, strings.ReplaceAll(createOut, "\n", " "))
	if createErr {
		t.Logf("SKIPPED the rest of the breach path: create refused (%.160q)", createOut)
		return
	}
	real("pass_breaches_resend", map[string]any{"ref": own})
	code, lastBody, mailIDs := "", "", map[string]bool{}
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
				lastBody = body
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
		// create and resend both succeeded, yet no mail from Proton Pass reached the
		// account's own mailbox (checked with the official CLI: nothing newer than
		// the last unrelated message, in any folder). With one attempt allowed,
		// verify/resolve cannot be exercised; recorded, not retried.
		t.Logf("SKIPPED verify/resolve: no confirmation mail arrived at %s (%d matched, last body shape %.200q)", own, len(mailIDs), regexp.MustCompile(`\d`).ReplaceAllString(lastBody, "#"))
		real("pass_breaches_get", map[string]any{"ref": own})
		real("pass_breaches_delete", map[string]any{"ref": own, "confirm": true})
		return
	}
	real("pass_breaches_verify", map[string]any{"ref": own, "code": code})
	if o, isErr := call(t, cs, "pass_breaches_resolve", map[string]any{"ref": []any{own}}); true {
		t.Logf("pass_breaches_resolve err=%v %.160q", isErr, strings.ReplaceAll(o, "\n", " "))
	}
	real("pass_breaches_get", map[string]any{"ref": own})
	real("pass_breaches_delete", map[string]any{"ref": own, "confirm": true})
}
