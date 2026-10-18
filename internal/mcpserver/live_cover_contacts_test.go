package mcpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pgphelper "github.com/roman-16/proton-cli/internal/crypto/pgp"
)

// TestCoverContacts runs the contact key and email-setting tools, and the local
// index tools, once each, on objects of its own.
//
// The index tools write an encrypted copy of the account under the profile's
// config directory, so they only run when XDG_CONFIG_HOME is a scratch copy
// (sessions and idcache linked in, nothing else): the real session directory is
// never given an index. The scratch directory is checked, then emptied again by
// index_delete.
//
// contacts_merge is not part of this test on purpose: the address book holds
// duplicate sets that are not ours, so a real merge would fold other people's
// contacts. The preview shows them (see TestLiveContacts, which only previews).
func TestCoverContacts(t *testing.T) {
	t.Run("keys", coverContactKeys)
	t.Run("index", coverIndex)
}

func coverContactKeys(t *testing.T) {
	l := newContactsLive(t)
	t.Cleanup(l.reap)
	tag := l.tag
	addr := tag + "-key@example.com"

	// A throwaway OpenPGP public key for an address of our own.
	key, err := pgphelper.GenerateKey(tag, addr)
	if err != nil {
		t.Fatal(err)
	}
	armored, err := key.GetArmoredPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := map[string]any{"name": "pub.asc", "text": armored}

	l.ok("contacts_create", map[string]any{"name": tag + "-keys", "email": []any{addr}})
	ids := l.find(tag + "-keys")
	if len(ids) != 1 {
		t.Fatalf("expected one contact of ours, found %v", ids)
	}
	id := ids[0]

	steps := []struct {
		tool    string
		args    map[string]any
		want    []string // substrings the output must carry
		wantErr string   // non-empty: a clean CLI refusal containing this is the expected result
	}{
		// No key yet, so encryption cannot be turned on: a plain CLI refusal.
		{"contacts_emails_update", map[string]any{"ref": addr, "encrypt": "on"}, nil, "no key to encrypt"},
		{"contacts_keys_trust", map[string]any{"ref": id, "key": keyFile, "dry_run": true}, []string{"dry_run"}, ""},
		{"contacts_keys_trust", map[string]any{"ref": id, "key": keyFile}, nil, ""},
		{"contacts_keys_list", map[string]any{"ref": id}, []string{addr}, ""},
		{"contacts_emails_list", map[string]any{"ref": id}, []string{addr}, ""},
		{"contacts_emails_update", map[string]any{"ref": addr, "encrypt": "on", "dry_run": true}, []string{"dry_run"}, ""},
		{"contacts_emails_update", map[string]any{"ref": addr, "encrypt": "on", "scheme": "pgp-mime"}, nil, ""},
		{"contacts_emails_update", map[string]any{"ref": addr, "encrypt": "off", "sign": "default"}, nil, ""},
		{"contacts_keys_untrust", map[string]any{"ref": id, "dry_run": true}, []string{"dry_run"}, ""},
		{"contacts_keys_untrust", map[string]any{"ref": id}, nil, ""},
		{"contacts_keys_list", map[string]any{"ref": id}, nil, ""},
	}
	for i, s := range steps {
		out, isErr := l.run(s.tool, s.args)
		t.Logf("step %d %-24s err=%-5v %.160q", i, s.tool, isErr, strings.ReplaceAll(out, "\n", " "))
		switch {
		case s.wantErr != "":
			if !isErr || !strings.Contains(out, s.wantErr) {
				t.Errorf("step %d %s: want a refusal containing %q, got err=%v %.300s", i, s.tool, s.wantErr, isErr, out)
			}
		case isErr:
			t.Fatalf("step %d %s failed: %s", i, s.tool, out)
		}
		mustContain(t, s.tool, out, s.want...)
		if s.tool == "contacts_keys_list" && s.want == nil && strings.Contains(out, key.GetFingerprint()) {
			t.Errorf("the key is still listed after untrust: %.300s", out)
		}
	}
	l.ok("contacts_delete", map[string]any{"ref": []any{id}, "confirm": true})

	// contacts_merge: a pair of our own, previewed only. The command folds every
	// duplicate set in the address book; when the preview counts more than our
	// pair it must not run for real, and the address book here has others.
	count := func() int {
		out := l.ok("contacts_merge", map[string]any{})
		mustContain(t, "contacts_merge", out, "Nothing was changed")
		var r struct {
			Count int `json:"count"`
		}
		if i, j := strings.Index(out, "{"), strings.LastIndex(out, "}"); i < 0 || j < i || json.Unmarshal([]byte(out[i:j+1]), &r) != nil {
			t.Fatalf("no count in the merge preview: %.300s", out)
		}
		return r.Count
	}
	before := count()
	for _, n := range []string{"-m1", "-m2"} {
		l.ok("contacts_create", map[string]any{"name": tag + n, "email": []any{tag + "-dup@example.com"}})
	}
	if after := count(); after != before+1 {
		t.Errorf("our pair should add exactly one to the preview: %d -> %d", before, after)
	} else if before == 0 {
		t.Logf("the preview held only our pair: a real merge would have been safe")
	} else {
		t.Logf("the preview also folds %d contacts that are not ours: merge stays preview-only", before)
	}
	l.reap()
	if left := l.find(tag); len(left) != 0 {
		t.Errorf("contacts of this run are still there: %v", left)
	}
}

// coverIndex runs the index tools against a scratch config directory only. The
// account is slow (a calendar dry run alone takes ~40 s), so it uses the client
// with the long timeout.
func coverIndex(t *testing.T) {
	cs := live(t)
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" || !strings.Contains(cfg, "scratch") {
		t.Skipf("index tools need a scratch XDG_CONFIG_HOME (got %q); not touching the real session directory", cfg)
	}
	dir := filepath.Join(cfg, "proton-cli", "index")
	t.Cleanup(func() { os.RemoveAll(dir) })
	idx := []struct {
		tool string
		args map[string]any
		want string
	}{
		{"index_create", map[string]any{"ref": []any{"calendar"}, "dry_run": true}, `"dry_run": true`},
		{"index_create", map[string]any{"ref": []any{"calendar"}}, "ndexed"},
		{"index_update", map[string]any{}, "ndexed"},
		{"index_delete", map[string]any{"ref": []any{"calendar"}, "dry_run": true}, "dry_run"},
		{"index_delete", map[string]any{"ref": []any{"calendar"}, "confirm": true}, "eleted"},
	}
	for i, s := range idx {
		text, _, isErr := callRaw(t, cs, s.tool, s.args)
		t.Logf("%-14s err=%-5v %.140q", s.tool, isErr, strings.ReplaceAll(text, "\n", " "))
		if isErr {
			t.Fatalf("%s failed: %s", s.tool, text)
		}
		out := text
		mustContain(t, s.tool, out, s.want)
		if _, err := os.Stat(dir); i == 1 && err != nil {
			t.Errorf("index_create left nothing under %s: %v", dir, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*", "*")); len(left) != 0 {
		t.Errorf("index files remain after index_delete: %v", left)
	}
}
