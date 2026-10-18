package mcpserver

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// TestCoverAccount calls every tool of the account area that nothing else
// exercises. This is the most sensitive area of the account, so the rule is
// strict: only harmless, reversible settings run for real, each read back after
// it is set and restored to the exact value it had. Everything that touches a
// password, recovery method, two-factor, security key, sentinel, key, session or
// another person is called with dry_run, so the CLI parses and plans it and
// nothing is sent. No session is ever revoked.
func TestCoverAccount(t *testing.T) {
	cs := live(t)
	own := ownAddress(t)
	run := func(name string, args map[string]any) (string, bool) { return call(t, cs, name, args) }
	show := func(name, mode string, out string, isErr bool) {
		t.Logf("%-46s %-7s err=%-5v %.160q", name, mode, isErr, strings.ReplaceAll(out, "\n", " "))
	}

	// getSettings reads the account settings now in effect, as key -> value.
	getSettings := func() map[string]string {
		out, isErr := run("account_settings_get", map[string]any{})
		if isErr {
			t.Fatalf("account_settings_get: %s", out)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("settings are not JSON: %v\n%.300s", err, out)
		}
		got := map[string]string{}
		for k, v := range m {
			if s, ok := v.(string); ok {
				got[k] = s
			}
		}
		return got
	}

	// --- REAL: reversible settings, restored and read back.

	// week_start is a display preference with no effect on anything else.
	t.Run("settings_set_week_start", func(t *testing.T) {
		before := getSettings()
		orig := before["week_start"]
		if orig == "" {
			t.Fatalf("no week_start in settings: %v", before)
		}
		restore := func() { run("account_settings_set", map[string]any{"key": "week-start", "value": orig}) }
		t.Cleanup(restore)
		next := "monday"
		if orig == "monday" {
			next = "sunday"
		}
		out, isErr := run("account_settings_set", map[string]any{"key": "week-start", "value": next})
		show("account_settings_set", "REAL", out, isErr)
		if isErr {
			t.Fatal(out)
		}
		if got := getSettings()["week_start"]; got != next {
			t.Errorf("week_start after set = %q, want %q", got, next)
		}
		out, isErr = run("account_settings_set", map[string]any{"key": "week-start", "value": orig})
		show("account_settings_set", "RESTORE", out, isErr)
		if isErr {
			t.Fatal(out)
		}
		if got := getSettings()["week_start"]; got != orig {
			t.Errorf("week_start after restore = %q, want the original %q", got, orig)
		}
	})

	// The "meet" product-update email is off on this account; turn it on and
	// off again, which also covers the disable path. If it is on, do the reverse.
	t.Run("notifications_toggle", func(t *testing.T) {
		const ref = "meet"
		isOn := func() bool {
			out, isErr := run("account_settings_notifications_list", map[string]any{})
			if isErr {
				t.Fatalf("notifications list: %s", out)
			}
			// the JSON shape is not fixed here; find the entry mentioning the ref
			var v any
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("not JSON: %v", err)
			}
			var found *bool
			var walk func(any)
			walk = func(x any) {
				switch x := x.(type) {
				case map[string]any:
					if n, _ := x["name"].(string); n == ref {
						for _, k := range []string{"on", "enabled"} {
							if b, ok := x[k].(bool); ok {
								found = &b
							}
						}
					}
					for _, c := range x {
						walk(c)
					}
				case []any:
					for _, c := range x {
						walk(c)
					}
				}
			}
			walk(v)
			if found == nil {
				t.Fatalf("no state for %q in %.400s", ref, out)
			}
			return *found
		}
		orig := isOn()
		set := func(on bool) {
			name := "account_settings_notifications_disable"
			if on {
				name = "account_settings_notifications_enable"
			}
			out, isErr := run(name, map[string]any{"ref": []any{ref}})
			show(name, "REAL", out, isErr)
			if isErr {
				t.Fatal(out)
			}
			if got := isOn(); got != on {
				t.Errorf("%s: state is %v, want %v", name, got, on)
			}
		}
		t.Cleanup(func() {
			name := "account_settings_notifications_disable"
			if orig {
				name = "account_settings_notifications_enable"
			}
			run(name, map[string]any{"ref": []any{ref}})
		})
		set(!orig)
		set(orig)
	})

	// --- READS.
	reads := []struct {
		name string
		args map[string]any
		why  string // when an error is the legitimate answer
	}{
		{"account_breaches_get", map[string]any{"ref": "proton-mcp-nonexistent"}, "this account has no breaches"},
		{"account_settings_recovery_contacts_get", map[string]any{"ref": "proton-mcp-nonexistent"}, "this account has no recovery contacts"},
		{"account_settings_emergency_access_get", map[string]any{"ref": "proton-mcp-nonexistent"}, "no such emergency contact"},
	}
	for _, r := range reads {
		out, isErr := run(r.name, r.args)
		show(r.name, "READ", out, isErr)
		if isErr && r.why == "" {
			t.Errorf("%s: %s", r.name, out)
		}
		if isErr && strings.TrimSpace(out) == "" {
			t.Errorf("%s failed with no message", r.name)
		}
	}

	// A public key is public: exporting it reads nothing secret and writes
	// nothing. It runs for real, on the first address key.
	var pubKey string
	t.Run("keys_export_public", func(t *testing.T) {
		keyID := firstKeyID(t, run)
		out, isErr := run("account_keys_export", map[string]any{"ref": []any{keyID}})
		show("account_keys_export", "REAL", out, isErr)
		if isErr {
			t.Fatal(out)
		}
		if !strings.Contains(out, "BEGIN PGP PUBLIC KEY BLOCK") {
			t.Errorf("export is not a public key: %.200s", out)
		}
		pubKey = out
	})

	// The same read for the existing emergency contact, by its real id.
	t.Run("emergency_access_get_real", func(t *testing.T) {
		out, isErr := run("account_settings_emergency_access_list", map[string]any{})
		if isErr {
			t.Skipf("emergency access list: %s", out)
		}
		id := regexp.MustCompile(`"id":\s*"([^"]+)"`).FindStringSubmatch(out)
		if id == nil {
			t.Skip("no emergency contact to read")
		}
		out, isErr = run("account_settings_emergency_access_get", map[string]any{"ref": id[1]})
		show("account_settings_emergency_access_get", "READ", out, isErr)
		if isErr {
			t.Errorf("get by real id failed: %s", out)
		}
	})

	// --- DRY: everything that touches credentials, recovery, 2FA, keys,
	// sessions, sentinel, monitoring, security keys, or other people.
	const (
		fakeKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
		fakeArm = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"
	)
	d := func(m map[string]any) map[string]any {
		m["dry_run"] = true
		return m
	}
	importSrc := fakeArm
	if pubKey != "" {
		importSrc = pubKey // a real public key, so the import is planned for real
	}
	dry := []struct {
		name string
		args map[string]any
	}{
		{"account_breaches_disable", d(map[string]any{})},
		{"account_breaches_enable", d(map[string]any{})},
		{"account_breaches_reopen", d(map[string]any{"ref": []any{"proton-mcp-nonexistent"}})},
		{"account_breaches_resolve", d(map[string]any{"ref": []any{"proton-mcp-nonexistent"}})},
		{"account_keys_create", d(map[string]any{"ref": own})},
		{"account_keys_delete", d(map[string]any{"ref": []any{fakeKey}})},
		{"account_keys_import", d(map[string]any{"ref": own, "src": map[string]any{"name": "k.asc", "text": importSrc}})},
		{"account_keys_reactivate", d(map[string]any{})},
		{"account_keys_update", d(map[string]any{"ref": fakeKey, "obsolete": false})},
		{"account_security_log_delete", d(map[string]any{})},
		{"account_security_log_disable", d(map[string]any{})},
		{"account_security_log_enable", d(map[string]any{})},
		{"account_sessions_revoke", d(map[string]any{"ref": []any{"proton-mcp-nonexistent"}})},
		{"account_settings_emergency_access_access", d(map[string]any{"ref": "proton-mcp-nonexistent"})},
		{"account_settings_emergency_access_add", d(map[string]any{"email": "proton-mcp-test@example.com", "wait": "3d"})},
		{"account_settings_emergency_access_cancel", d(map[string]any{"ref": "proton-mcp-nonexistent"})},
		{"account_settings_emergency_access_grant", d(map[string]any{"ref": "proton-mcp-nonexistent"})},
		{"account_settings_emergency_access_remove", d(map[string]any{"ref": []any{"proton-mcp-nonexistent"}})},
		{"account_settings_emergency_access_request", d(map[string]any{"ref": "proton-mcp-nonexistent"})},
		{"account_settings_emergency_access_update", d(map[string]any{"ref": "proton-mcp-nonexistent", "wait": "3d"})},
		{"account_settings_password_set", d(map[string]any{})},
		{"account_settings_recovery_contacts_add", d(map[string]any{"email": "proton-mcp-test@example.com"})},
		{"account_settings_recovery_contacts_remove", d(map[string]any{"ref": []any{"proton-mcp-nonexistent"}})},
		{"account_settings_recovery_email_disable", d(map[string]any{})},
		{"account_settings_recovery_email_enable", d(map[string]any{})},
		{"account_settings_recovery_email_set", d(map[string]any{"email": "proton-mcp-test@example.com"})},
		{"account_settings_recovery_phone_disable", d(map[string]any{})},
		{"account_settings_recovery_phone_enable", d(map[string]any{})},
		{"account_settings_recovery_phone_set", d(map[string]any{"phone": "+34600000000"})},
		{"account_settings_recovery_phrase_disable", d(map[string]any{})},
		{"account_settings_recovery_phrase_set", d(map[string]any{})},
		{"account_settings_second_password_disable", d(map[string]any{})},
		{"account_settings_second_password_enable", d(map[string]any{})},
		{"account_settings_second_password_set", d(map[string]any{})},
		{"account_settings_security_keys_create", d(map[string]any{"name": "proton-mcp-test-key"})},
		{"account_settings_security_keys_delete", d(map[string]any{"ref": "proton-mcp-nonexistent"})},
		{"account_settings_security_keys_update", d(map[string]any{"ref": "proton-mcp-nonexistent", "name": "proton-mcp-test-renamed"})},
		{"account_settings_sentinel_disable", d(map[string]any{})},
		{"account_settings_sentinel_enable", d(map[string]any{})},
		{"account_settings_two_factor_disable", d(map[string]any{})},
		{"account_settings_two_factor_enable", d(map[string]any{})},
	}
	for _, c := range dry {
		out, isErr := run(c.name, c.args)
		show(c.name, "DRY", out, isErr)
		if strings.TrimSpace(out) == "" {
			t.Errorf("%s: empty answer", c.name)
		}
	}

	// DRY again, now naming objects that really exist, so the plan is made for
	// them rather than refused as unknown. dry_run plans the change and sends
	// nothing; the lists are compared afterwards to prove it.
	t.Run("dry_against_real_ids", func(t *testing.T) {
		listOf := func(name string) string {
			out, isErr := run(name, map[string]any{})
			if isErr {
				t.Fatalf("%s: %s", name, out)
			}
			return out
		}
		idRe := regexp.MustCompile(`"id":\s*"([^"]+)"`)
		keysBefore := listOf("account_keys_list")
		secBefore := listOf("account_settings_security_keys_list")
		emBefore := listOf("account_settings_emergency_access_list")
		key := idRe.FindStringSubmatch(keysBefore)
		sec := idRe.FindStringSubmatch(secBefore)
		em := idRe.FindStringSubmatch(emBefore)
		if key == nil || sec == nil || em == nil {
			t.Skip("the account has no key, security key or emergency contact to plan against")
		}
		for _, c := range []struct {
			name string
			args map[string]any
		}{
			{"account_keys_update", d(map[string]any{"ref": key[1], "obsolete": false})},
			{"account_keys_delete", d(map[string]any{"ref": []any{key[1]}})},
			{"account_settings_security_keys_update", d(map[string]any{"ref": sec[1], "name": "proton-mcp-test-renamed"})},
			{"account_settings_security_keys_delete", d(map[string]any{"ref": sec[1]})},
			{"account_settings_emergency_access_update", d(map[string]any{"ref": em[1], "wait": "3d"})},
			{"account_settings_emergency_access_cancel", d(map[string]any{"ref": em[1]})},
			{"account_settings_emergency_access_remove", d(map[string]any{"ref": []any{em[1]}})},
			{"account_settings_emergency_access_request", d(map[string]any{"ref": em[1]})},
			{"account_settings_emergency_access_grant", d(map[string]any{"ref": em[1]})},
		} {
			out, isErr := run(c.name, c.args)
			show(c.name, "DRY+id", out, isErr)
			if !isErr && !strings.Contains(out, `"dry_run": true`) {
				t.Errorf("%s ran for real? %.200s", c.name, out)
			}
		}
		if got := listOf("account_keys_list"); got != keysBefore {
			t.Errorf("keys changed")
		}
		if got := listOf("account_settings_security_keys_list"); got != secBefore {
			t.Errorf("security keys changed")
		}
		if got := listOf("account_settings_emergency_access_list"); got != emBefore {
			t.Errorf("emergency contacts changed")
		}
	})
}

// firstKeyID returns the id of the first key `account keys list` shows.
func firstKeyID(t *testing.T, run func(string, map[string]any) (string, bool)) string {
	out, isErr := run("account_keys_list", map[string]any{})
	if isErr {
		t.Fatalf("account_keys_list: %s", out)
	}
	m := regexp.MustCompile(`"id":\s*"([^"]+)"`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no key id in %.300s", out)
	}
	return m[1]
}
