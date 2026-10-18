package mcpserver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"time"
)

// contactsLive is the harness the contacts and account live tests share.
type contactsLive struct {
	t   *testing.T
	run func(name string, args map[string]any) (string, bool)
	tag string
}

func newContactsLive(t *testing.T) *contactsLive {
	cs := live(t)
	return &contactsLive{
		t:   t,
		tag: "proton-mcp-test-" + time.Now().Format("20060102-150405"),
		run: func(name string, args map[string]any) (string, bool) { return call(t, cs, name, args) },
	}
}

func (l *contactsLive) ok(name string, args map[string]any) string {
	l.t.Helper()
	out, isErr := l.run(name, args)
	l.t.Logf("%-26s err=%-5v %.140q", name, isErr, strings.ReplaceAll(out, "\n", " "))
	if isErr {
		l.t.Fatalf("%s failed: %s", name, out)
	}
	return out
}

func (l *contactsLive) ids(raw string) []string {
	var m struct {
		IDs []string `json:"ids"`
	}
	_ = json.Unmarshal([]byte(raw), &m)
	return m.IDs
}

// find returns the ids of the contacts whose name contains the test tag plus
// suffix. It matches on a keyword that only this run's contacts carry.
func (l *contactsLive) find(keyword string) []string {
	l.t.Helper()
	out := l.ok("contacts_list", map[string]any{"keyword": keyword, "limit": 0})
	var cl struct {
		Contacts []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"contacts"`
	}
	if err := json.Unmarshal([]byte(out), &cl); err != nil {
		l.t.Fatalf("contacts_list is not JSON: %v\n%.300s", err, out)
	}
	var ids []string
	for _, c := range cl.Contacts {
		if strings.HasPrefix(c.Name, l.tag) {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

// reap removes, by exact id, every contact of this run that is still there.
func (l *contactsLive) reap() {
	for _, id := range l.find(l.tag) {
		l.run("contacts_delete", map[string]any{"ref": []any{id}, "confirm": true})
	}
}

func tinyPNG(t *testing.T) string {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for x := 0; x < 8; x++ {
		for y := 0; y < 8; y++ {
			img.Set(x, y, color.RGBA{R: 200, G: uint8(x * 30), B: 80, A: 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func mustContain(t *testing.T, what, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("%s lacks %q: %.400s", what, w, got)
		}
	}
}

// TestLiveContacts exercises the contact tools with contacts of its own: a
// create with every kind of field, an import and an export of a vCard, a
// throwaway group, the photo file input and the key listing. Everything it
// makes carries the run's tag and is removed by exact id.
func TestLiveContacts(t *testing.T) {
	l := newContactsLive(t)
	t.Cleanup(l.reap)
	tag := l.tag

	// --- create with many fields
	full := tag + "-full"
	l.ok("contacts_create", map[string]any{
		"name":         full,
		"first_name":   "Prueba",
		"last_name":    "Completa",
		"email":        []any{"work:" + tag + "-a@example.com", "home:" + tag + "-b@example.com", tag + "-c@example.com"},
		"phone":        []any{"cell:+34600111222", "work:+34910000000"},
		"address":      []any{"home:Calle Mayor 1;Madrid;;28001;Espana"},
		"birthday":     "1990-01-31",
		"organization": []any{"Proton MCP Test SL"},
		"job_title":    []any{"Tester"},
		"nickname":     []any{"probador"},
		"website":      []any{"https://example.com/prueba"},
		"note":         []any{"nota de prueba"},
	})
	ids := l.find(full)
	if len(ids) != 1 {
		t.Fatalf("expected one contact named %s, found %v", full, ids)
	}
	fullID := ids[0]
	got := l.ok("contacts_get", map[string]any{"ref": fullID})
	mustContain(t, "contacts_get", got,
		tag+"-a@example.com", tag+"-b@example.com", tag+"-c@example.com",
		"+34600111222", "+34910000000", "Calle Mayor", "1990-01-31",
		"Proton MCP Test SL", "Tester", "probador", "example.com/prueba", "nota de prueba")
	em := l.ok("contacts_emails_list", map[string]any{"ref": fullID})
	mustContain(t, "contacts_emails_list", em, tag+"-a@example.com", tag+"-b@example.com")

	// An unknown input is refused instead of dropped.
	if out, isErr := l.run("contacts_create", map[string]any{"name": tag + "-bad", "colour": "red"}); !isErr {
		t.Errorf("an unknown input must be an error: %.200s", out)
	}

	// --- photo as a base64 file input, then cleared
	l.ok("contacts_update", map[string]any{
		"ref":   fullID,
		"photo": map[string]any{"name": "pixel.png", "base64": tinyPNG(t)},
	})
	got = l.ok("contacts_get", map[string]any{"ref": fullID})
	mustContain(t, "contacts_get after photo", strings.ToLower(got), "photo")
	if !strings.Contains(got, "data:image") {
		t.Errorf("the photo was not stored as an image: %.300s", got)
	}
	l.ok("contacts_update", map[string]any{"ref": fullID, "clear_photo": true})

	// --- keys: read only (an empty list is the normal answer for a new contact)
	l.ok("contacts_keys_list", map[string]any{"ref": fullID})

	// --- import a vCard given as {name,text}, then export it
	imp := tag + "-import"
	vcf := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:" + imp + "\r\nN:Importado;Prueba;;;\r\n" +
		"EMAIL;TYPE=work:" + tag + "-imp@example.com\r\nTEL;TYPE=cell:+34600333444\r\n" +
		"ORG:Importadora SL\r\nNOTE:importada por el MCP\r\nEND:VCARD\r\n"
	l.ok("contacts_import", map[string]any{"path": map[string]any{"name": "in.vcf", "text": vcf}})
	ids = l.find(imp)
	if len(ids) != 1 {
		t.Fatalf("expected one imported contact, found %v", ids)
	}
	importedID := ids[0]
	exp := l.ok("contacts_export", map[string]any{"ref": []any{importedID}})
	mustContain(t, "contacts_export", exp, "BEGIN:VCARD", imp, tag+"-imp@example.com", "+34600333444", "Importadora SL", "END:VCARD")

	// --- a throwaway group: create, add, read, remove, delete
	gname := tag + "-group"
	g := l.ids(l.ok("contacts_groups_create", map[string]any{"name": gname, "color": "#8080FF"}))
	if len(g) != 1 {
		t.Fatalf("expected one group id, got %v", g)
	}
	gid := g[0]
	t.Cleanup(func() { l.run("contacts_groups_delete", map[string]any{"ref": []any{gid}, "confirm": true}) })
	l.ok("contacts_groups_update", map[string]any{"ref": gid, "name": gname + "-2"})
	l.ok("contacts_groups_add", map[string]any{"ref": gid, "contact_ref": []any{importedID}})
	got = l.ok("contacts_groups_get", map[string]any{"ref": gid})
	mustContain(t, "contacts_groups_get after add", got, tag+"-imp@example.com")
	l.ok("contacts_groups_remove", map[string]any{"ref": gid, "contact_ref": []any{importedID}})
	got = l.ok("contacts_groups_get", map[string]any{"ref": gid})
	if strings.Contains(got, tag+"-imp@example.com") {
		t.Errorf("the contact is still in the group after remove: %.300s", got)
	}
	pre, _ := l.run("contacts_groups_delete", map[string]any{"ref": []any{gid}})
	mustContain(t, "unconfirmed groups_delete", pre, "Nothing was changed")
	l.ok("contacts_groups_delete", map[string]any{"ref": []any{gid}, "confirm": true})
	if lst := l.ok("contacts_groups_list", map[string]any{"limit": 0}); strings.Contains(lst, tag) {
		t.Errorf("the group survived its delete: %.300s", lst)
	}

	// --- merge: only ever previewed. The command folds every duplicate in the
	// whole address book and takes no filter, so running it for real would touch
	// contacts this test did not make.
	foldable := func() int {
		pre, isErr := l.run("contacts_merge", map[string]any{})
		if isErr || !strings.Contains(pre, "Nothing was changed") {
			t.Fatalf("contacts_merge without confirm must only preview: err=%v %.300s", isErr, pre)
		}
		i := strings.Index(pre, "{")
		j := strings.LastIndex(pre, "}")
		var r struct {
			Count  int  `json:"count"`
			DryRun bool `json:"dry_run"`
		}
		if i < 0 || j < i || json.Unmarshal([]byte(pre[i:j+1]), &r) != nil || !r.DryRun {
			t.Fatalf("the merge preview is not a dry-run result: %.300s", pre)
		}
		return r.Count
	}
	before := foldable()
	for _, n := range []string{"-m1", "-m2"} {
		l.ok("contacts_create", map[string]any{"name": tag + n, "email": []any{tag + "-dup@example.com"}})
	}
	if after := foldable(); after != before+1 {
		t.Errorf("two contacts sharing an address should add one to the merge preview: %d -> %d", before, after)
	}
	if n := len(l.find(tag + "-m")); n != 2 {
		t.Errorf("the merge preview changed the address book: %d of 2 contacts left", n)
	}

	// --- delete: preview first, then by exact id
	pre, _ = l.run("contacts_delete", map[string]any{"ref": []any{fullID}})
	mustContain(t, "unconfirmed contacts_delete", pre, "Nothing was changed")
	if n := len(l.find(full)); n != 1 {
		t.Errorf("the delete preview removed the contact: %d left", n)
	}
	l.reap()
	if left := l.find(tag); len(left) != 0 {
		t.Errorf("contacts of this run are still there: %v", left)
	}
}

// TestLiveAccount calls the account tools that read, and nothing that changes
// credentials, recovery, two-factor, keys, sessions or the security log.
func TestLiveAccount(t *testing.T) {
	l := newContactsLive(t)
	me := l.ok("account_get", map[string]any{})
	if !strings.Contains(field(t, me, "email"), "@") {
		t.Errorf("account_get has no email: %.200s", me)
	}
	for _, name := range []string{"account_settings_list", "account_settings_get", "account_sessions_list",
		"account_security_log_list", "account_breaches_list", "account_settings_notifications_list"} {
		l.ok(name, map[string]any{})
	}
	l.ok("account_sessions_list", map[string]any{"limit": 2, "sort": "created", "desc": true})

	list := l.ok("account_keys_list", map[string]any{})
	var kl struct {
		Keys []struct {
			ID string `json:"id"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(list), &kl); err != nil || len(kl.Keys) == 0 {
		t.Fatalf("no keys parsed: %v\n%.300s", err, list)
	}
	l.ok("account_keys_get", map[string]any{"ref": kl.Keys[0].ID})
	// The key export needs the account password, which a server never holds.
	if out, isErr := l.run("account_keys_get", map[string]any{"ref": "does-not-exist"}); !isErr {
		t.Errorf("an unknown key must be an error: %.200s", out)
	}
}
