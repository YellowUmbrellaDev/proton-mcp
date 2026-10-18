package mcpserver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// driveTools is every tool this test must have called at least once.
var driveTools = strings.Fields(`
drive_computers_delete drive_computers_update drive_invitations_abuse drive_invitations_accept
drive_invitations_decline drive_items_abuse drive_items_revisions_abuse drive_items_revisions_delete
drive_items_revisions_restore drive_items_share_add drive_items_share_confirm drive_items_share_remove
drive_items_share_resend drive_items_share_update drive_links_create drive_links_revoke
drive_photos_albums_add drive_photos_albums_create drive_photos_albums_delete drive_photos_albums_remove
drive_photos_albums_share_add drive_photos_albums_share_confirm drive_photos_albums_share_get
drive_photos_albums_share_remove drive_photos_albums_share_resend drive_photos_albums_share_update
drive_photos_albums_update drive_photos_delete drive_photos_download drive_photos_favorite
drive_photos_links_create drive_photos_links_revoke drive_photos_share_add drive_photos_share_confirm
drive_photos_share_get drive_photos_share_remove drive_photos_share_resend drive_photos_share_update
drive_photos_trash drive_photos_unfavorite drive_photos_upload drive_settings_set drive_shared_add
drive_shared_leave drive_shared_remove drive_trash_empty drive_volumes_delete drive_volumes_restore`)

// onePixelPNG is a valid 1x1 PNG.
const onePixelPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"

// TestCoverDrive calls every Drive tool in driveTools. Real runs only touch
// objects made here (a folder, one file, a public link to it, one photo, one
// album); everything that reaches other people, the account's settings or
// existing data is a dry run or is held back for want of confirm.
func TestCoverDrive(t *testing.T) {
	cs := live(t)
	stamp := time.Now().Format("150405")
	tag := "proton-mcp-test-" + stamp
	root := "/" + tag
	called := map[string]string{}

	// run calls a tool, notes how it ended, and fails the test on a protocol
	// problem only; the caller decides what the text must say.
	run := func(mode, name string, args map[string]any) (string, bool) {
		t.Helper()
		out, isErr := call(t, cs, name, args)
		if prev, ok := called[name]; !ok || prev == "DRY" {
			called[name] = mode
		}
		t.Logf("[%s] %-34s err=%-5v %.140q", mode, name, isErr, strings.ReplaceAll(out, "\n", " "))
		return out, isErr
	}
	real := func(name string, args map[string]any) string {
		t.Helper()
		out, isErr := run("REAL", name, args)
		// Proton answers 422 "item not found" for a moment after it creates
		// something it is about to look up (an entry just added, a link just made).
		// That is the server catching up, so ask again a few times before failing.
		for try := 0; isErr && try < 4 && strings.Contains(out, "HTTP 422") && strings.Contains(out, "2501"); try++ {
			time.Sleep(5 * time.Second)
			out, isErr = run("REAL", name, args)
		}
		if isErr {
			t.Fatalf("%s failed: %s", name, out)
		}
		return out
	}
	// dry plans the command without doing it.
	dry := func(name string, args map[string]any) string {
		t.Helper()
		args["dry_run"] = true
		out, isErr := run("DRY", name, args)
		if isErr {
			t.Errorf("%s dry run failed: %s", name, out)
		}
		return out
	}
	// refused expects a clear CLI message, not a crash.
	refused := func(name string, args map[string]any, want string) {
		t.Helper()
		out, isErr := run("ERR", name, args)
		if !isErr || !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("%s: want an error containing %q, got err=%v %.200s", name, want, isErr, out)
		}
	}
	// held expects the irreversible tool to be previewed only.
	held := func(name string, args map[string]any) {
		t.Helper()
		out, isErr := run("DRY", name, args)
		if isErr || !strings.Contains(out, "Nothing was changed") {
			t.Errorf("%s was not held back: err=%v %.200s", name, isErr, out)
		}
	}
	jsonOf := func(raw string, v any) {
		t.Helper()
		if err := json.Unmarshal([]byte(raw), v); err != nil {
			t.Fatalf("not JSON: %v\n%.300s", err, raw)
		}
	}
	firstID := func(raw string) string {
		var m struct {
			IDs []string `json:"ids"`
		}
		jsonOf(raw, &m)
		if len(m.IDs) != 1 {
			t.Fatalf("expected one id: %.200s", raw)
		}
		return m.IDs[0]
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

	// --- Cleanups, by exact ID or path, registered as each object is made.
	t.Cleanup(func() {
		out, _ := call(t, cs, "drive_items_delete", map[string]any{"path": []any{root}, "confirm": true})
		t.Logf("cleanup folder %s: %.100q", root, out)
	})

	// --- A folder with one file that has two revisions.
	real("drive_items_create", map[string]any{"path": root})
	file := root + "/doc.txt"
	real("drive_items_upload", map[string]any{"src": map[string]any{"name": "doc.txt", "text": "version one"}, "dest": root})
	real("drive_items_upload", map[string]any{"src": map[string]any{"name": "doc.txt", "text": "version two"}, "dest": root, "if_exists": "replace"})
	var revs struct {
		Revisions []struct {
			ID    string `json:"id"`
			State int    `json:"state"`
		} `json:"revisions"`
	}
	jsonOf(real("drive_items_revisions_list", map[string]any{"path": file}), &revs)
	if len(revs.Revisions) != 2 {
		t.Fatalf("want 2 revisions: %+v", revs)
	}
	var cur, old string
	for _, r := range revs.Revisions {
		if r.State == 1 {
			cur = r.ID
		} else {
			old = r.ID
		}
	}
	if cur == "" || old == "" {
		t.Fatalf("could not tell the current revision from the old one: %+v", revs)
	}
	read := func(path string) string {
		t.Helper()
		text, blob, isErr := callRaw(t, cs, "drive_items_download", map[string]any{"path": path})
		if isErr {
			t.Fatalf("download %s: %s", path, text)
		}
		return string(blob) + text
	}
	// Restore the old revision: the content flips back to version one, and the
	// restored one becomes the current revision. Then delete the other old one.
	real("drive_items_revisions_restore", map[string]any{"path": file, "revision_ref": old})
	eventually("the restored content is served", func() bool { return read(file) == "version one" })
	jsonOf(real("drive_items_revisions_list", map[string]any{"path": file}), &revs)
	var obsolete string
	for _, r := range revs.Revisions {
		if r.State != 1 {
			obsolete = r.ID
		}
	}
	if obsolete == "" {
		t.Fatalf("no obsolete revision to delete after restore: %+v", revs)
	}
	// Unconfirmed: held. Confirmed: gone.
	held("drive_items_revisions_delete", map[string]any{"path": file, "revision_ref": obsolete})
	real("drive_items_revisions_delete", map[string]any{"path": file, "revision_ref": obsolete, "confirm": true})
	jsonOf(real("drive_items_revisions_list", map[string]any{"path": file}), &revs)
	for _, r := range revs.Revisions {
		if r.ID == obsolete {
			t.Errorf("revision %s is still listed after delete", obsolete)
		}
	}
	// Only something shared with you can be reported, so on our own file the CLI
	// explains that; that message is the legitimate outcome.
	refused("drive_items_revisions_abuse", map[string]any{"path": file, "revision_ref": cur, "category": "spam", "dry_run": true}, "shared with you")

	// --- A public link to the file: create, read back, change expiry and
	// password, open it through the tool by URL, revoke, verify it is gone.
	var link struct {
		URL        string `json:"url"`
		ExpireTime int64  `json:"expire_time"`
	}
	linkRevoked := false
	t.Cleanup(func() {
		if !linkRevoked {
			out, _ := call(t, cs, "drive_links_revoke", map[string]any{"path": file})
			t.Logf("cleanup link: %.100q", out)
		}
	})
	jsonOf(real("drive_links_create", map[string]any{"path": file, "expires": "1d"}), &link)
	if !strings.HasPrefix(link.URL, "https://drive.proton.me/urls/") || link.ExpireTime == 0 {
		t.Fatalf("link not as expected: %+v", link)
	}
	first := link.ExpireTime
	jsonOf(real("drive_links_create", map[string]any{"path": file, "expires": "7d", "link_password": "mcp-test-pass"}), &link)
	if link.ExpireTime <= first {
		t.Errorf("expiry did not move: %d then %d", first, link.ExpireTime)
	}
	got := real("drive_links_get", map[string]any{"path": file})
	if !strings.Contains(got, link.URL) {
		t.Errorf("links_get does not show the link URL")
	}
	// A report planned through our own link: dry, nothing is sent.
	dry("drive_items_abuse", map[string]any{"path": "/", "category": "spam", "good_faith": true, "link": link.URL, "link_password": "mcp-test-pass"})
	// Through the link, by URL and password: the --link input.
	out := real("drive_items_get", map[string]any{"path": "/", "link": link.URL, "link_password": "mcp-test-pass"})
	if !strings.Contains(out, "doc.txt") {
		t.Errorf("item reached through the link is not doc.txt: %.300s", out)
	}
	link.ExpireTime = 0
	jsonOf(real("drive_links_create", map[string]any{"path": file, "clear_link_password": true, "expires": "never"}), &link)
	if link.ExpireTime != 0 {
		t.Errorf("expires never left an expiry: %d", link.ExpireTime)
	}
	// Saving our own link in "shared with me", then dropping only that entry.
	var before, after struct {
		Items []struct {
			Token string `json:"token"`
		} `json:"items"`
	}
	jsonOf(real("drive_shared_list", map[string]any{}), &before)
	addOut, addErr := run("REAL", "drive_shared_add", map[string]any{"url": link.URL})
	if addErr {
		// Own link may be refused: a clear CLI message is fine, and recorded.
		called["drive_shared_add"] = "ERR"
		t.Logf("shared_add refused own link: %.200s", addOut)
		refused("drive_shared_remove", map[string]any{"ref": []any{"proton-mcp-test-no-such-entry"}, "dry_run": true}, "")
	} else {
		jsonOf(real("drive_shared_list", map[string]any{}), &after)
		known := map[string]bool{}
		for _, it := range before.Items {
			known[it.Token] = true
		}
		var added []string
		for _, it := range after.Items {
			if !known[it.Token] {
				added = append(added, it.Token)
			}
		}
		if len(added) != 1 {
			t.Fatalf("expected one new shared entry, got %v from %.300s", added, addOut)
		}
		t.Cleanup(func() {
			out, _ := call(t, cs, "drive_shared_remove", map[string]any{"ref": []any{added[0]}})
			t.Logf("cleanup shared entry: %.100q", out)
		})
		real("drive_shared_remove", map[string]any{"ref": []any{added[0]}})
		jsonOf(real("drive_shared_list", map[string]any{}), &after)
		for _, it := range after.Items {
			if it.Token == added[0] {
				t.Errorf("shared entry %s is still listed after remove", added[0])
			}
		}
	}
	real("drive_links_revoke", map[string]any{"path": file})
	linkRevoked = true
	if o, isErr := call(t, cs, "drive_links_get", map[string]any{"path": file}); !isErr || !strings.Contains(o, "has no public link") {
		t.Errorf("link still there after revoke: err=%v %.200s", isErr, o)
	}
	// Left a shared item: leave is irreversible and aimed at somebody else's data.
	// The CLI looks the entry up first, so a name that is not there is a plain error.
	refused("drive_shared_leave", map[string]any{"ref": []any{"proton-mcp-test-no-such-entry"}}, "no shared item")

	// --- Sharing with people is DRY only, on our own file.
	const someone = "nobody@example.invalid"
	dry("drive_items_share_add", map[string]any{"path": file, "email": someone, "access": "viewer", "message": "mcp test"})
	dry("drive_items_share_update", map[string]any{"path": file, "email": someone, "access": "editor"})
	dry("drive_items_share_confirm", map[string]any{"path": file, "email": someone})
	dry("drive_items_share_resend", map[string]any{"path": file, "email": someone})
	dry("drive_items_share_remove", map[string]any{"path": file, "email": someone})

	// --- Invitations: none exist, so each is a clear error or a dry plan.
	var invs struct {
		Invitations []struct {
			ID string `json:"id"`
		} `json:"invitations"`
	}
	_ = json.Unmarshal([]byte(real("drive_invitations_list", map[string]any{})), &invs)
	inv := "proton-mcp-test-no-such-invitation"
	if len(invs.Invitations) > 0 {
		t.Logf("invitations exist; only dry runs touch them")
		inv = invs.Invitations[0].ID
	}
	for _, name := range []string{"drive_invitations_accept", "drive_invitations_decline"} {
		out, isErr := run("DRY", name, map[string]any{"ref": []any{inv}, "dry_run": true})
		if isErr && !strings.Contains(strings.ToLower(out), "invitation") {
			t.Errorf("%s: unclear error: %.200s", name, out)
		}
		if isErr {
			called[name] = "ERR"
		}
	}
	out, isErr := run("DRY", "drive_invitations_abuse", map[string]any{"ref": inv, "category": "spam", "good_faith": true, "dry_run": true})
	if isErr {
		called["drive_invitations_abuse"] = "ERR"
		if !strings.Contains(strings.ToLower(out), "invitation") {
			t.Errorf("drive_invitations_abuse: unclear error: %.200s", out)
		}
	}

	// --- Computers, volumes, trash, settings: existing data, DRY or held.
	var comps struct {
		Computers []struct {
			ID string `json:"id"`
		} `json:"computers"`
	}
	jsonOf(real("drive_computers_list", map[string]any{}), &comps)
	comp := "proton-mcp-test-no-such-computer"
	if len(comps.Computers) > 0 {
		comp = comps.Computers[0].ID
	}
	dry("drive_computers_update", map[string]any{"ref": comp, "name": tag})
	dry("drive_computers_delete", map[string]any{"ref": []any{comp}})
	held("drive_computers_delete", map[string]any{"ref": []any{comp}})
	var vols struct {
		Volumes []struct {
			ID string `json:"id"`
		} `json:"volumes"`
	}
	jsonOf(real("drive_volumes_list", map[string]any{}), &vols)
	vol := "proton-mcp-test-no-such-volume"
	if len(vols.Volumes) > 0 {
		vol = vols.Volumes[0].ID
	}
	// Only a volume a password reset locked can be deleted or restored; the
	// account's one volume is active, so the CLI says so and nothing happens.
	refused("drive_volumes_delete", map[string]any{"ref": []any{vol}, "dry_run": true}, "not locked")
	refused("drive_volumes_restore", map[string]any{"ref": []any{vol}, "dry_run": true}, "not locked")
	held("drive_trash_empty", map[string]any{})
	dry("drive_trash_empty", map[string]any{})
	dry("drive_settings_set", map[string]any{"key": "version-history", "value": "30d"})

	// --- Photos: one tiny PNG of our own, through its whole life.
	topPhotos := func() map[string]bool {
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
	photoBefore := topPhotos()
	real("drive_photos_upload", map[string]any{"src": map[string]any{"name": tag + ".png", "base64": onePixelPNG}})
	var photo string
	eventually("the uploaded photo shows in the library", func() bool {
		for id := range topPhotos() {
			if !photoBefore[id] {
				photo = id
				return true
			}
		}
		return false
	})
	if photo == "" {
		t.Fatal("cannot find the uploaded photo; not touching anything else")
	}
	photoGone := false
	t.Cleanup(func() {
		if !photoGone {
			out, _ := call(t, cs, "drive_photos_delete", map[string]any{"ref": []any{photo}, "confirm": true})
			t.Logf("cleanup photo: %.100q", out)
		}
	})
	// It is ours only if its bytes are the PNG just sent.
	want, _ := base64.StdEncoding.DecodeString(onePixelPNG)
	_, blob, isErr2 := callRaw(t, cs, "drive_photos_download", map[string]any{"ref": photo})
	called["drive_photos_download"] = "REAL"
	if isErr2 || !bytes.Equal(blob, want) {
		t.Fatalf("the new photo is not the PNG that was uploaded (err=%v, %d bytes); not touching it", isErr2, len(blob))
	}
	real("drive_photos_favorite", map[string]any{"ref": []any{photo}})
	if o := real("drive_photos_list", map[string]any{"tag": "favorites", "limit": 100, "desc": true}); !strings.Contains(o, photo) {
		t.Errorf("favorited photo not listed under tag favorites")
	}
	real("drive_photos_unfavorite", map[string]any{"ref": []any{photo}})
	real("drive_photos_share_get", map[string]any{"ref": photo})

	// Album of our own.
	albumGone := false
	var albumID string
	albumName := tag + "-album"
	albumID = firstID(real("drive_photos_albums_create", map[string]any{"name": albumName}))
	t.Cleanup(func() {
		if !albumGone {
			out, _ := call(t, cs, "drive_photos_albums_delete", map[string]any{"ref": []any{albumID}, "confirm": true})
			t.Logf("cleanup album: %.100q", out)
		}
	})
	real("drive_photos_albums_add", map[string]any{"ref": albumID, "photo_ref": []any{photo}})
	eventually("the photo is in the album", func() bool {
		return strings.Contains(real("drive_photos_list", map[string]any{"album": albumID}), photo)
	})
	albumName += "-renamed"
	real("drive_photos_albums_update", map[string]any{"ref": albumID, "name": albumName, "cover": photo})
	real("drive_photos_albums_share_get", map[string]any{"ref": albumID})
	real("drive_photos_albums_remove", map[string]any{"ref": albumID, "photo_ref": []any{photo}})
	eventually("the photo is out of the album", func() bool {
		return !strings.Contains(real("drive_photos_list", map[string]any{"album": albumID}), photo)
	})
	dry("drive_photos_albums_share_add", map[string]any{"ref": albumID, "email": someone, "access": "viewer"})
	dry("drive_photos_albums_share_update", map[string]any{"ref": albumID, "email": someone, "access": "editor"})
	dry("drive_photos_albums_share_confirm", map[string]any{"ref": albumID, "email": someone})
	dry("drive_photos_albums_share_resend", map[string]any{"ref": albumID, "email": someone})
	dry("drive_photos_albums_share_remove", map[string]any{"ref": albumID, "email": someone})
	// Held first, then for real; the photo itself stays (no delete_photos).
	held("drive_photos_albums_delete", map[string]any{"ref": []any{albumID}})
	real("drive_photos_albums_delete", map[string]any{"ref": []any{albumID}, "confirm": true})
	albumGone = true
	eventually("the album is gone", func() bool {
		return !strings.Contains(real("drive_photos_albums_list", map[string]any{}), albumID)
	})

	// Sharing and public links of a photo or album: DRY only.
	dry("drive_photos_links_create", map[string]any{"ref": photo, "expires": "1d"})
	dry("drive_photos_links_revoke", map[string]any{"ref": photo})
	dry("drive_photos_share_add", map[string]any{"ref": photo, "email": someone, "access": "viewer"})
	dry("drive_photos_share_update", map[string]any{"ref": photo, "email": someone, "access": "editor"})
	dry("drive_photos_share_confirm", map[string]any{"ref": photo, "email": someone})
	dry("drive_photos_share_resend", map[string]any{"ref": photo, "email": someone})
	dry("drive_photos_share_remove", map[string]any{"ref": photo, "email": someone})

	// Trash the photo, bring it back from the trash (a trashed photo is no
	// longer in the library, and `photos delete` looks there), then delete it for
	// good and check it is gone from the library and from the trash.
	real("drive_photos_trash", map[string]any{"ref": []any{photo}})
	eventually("the photo left the library", func() bool { return !inLibrary(photo) })
	real("drive_trash_restore", map[string]any{"ref": []any{photo}})
	eventually("the photo is back in the library", func() bool { return inLibrary(photo) })
	held("drive_photos_delete", map[string]any{"ref": []any{photo}})
	if !inLibrary(photo) {
		t.Fatal("the held delete removed the photo")
	}
	real("drive_photos_delete", map[string]any{"ref": []any{photo}, "confirm": true})
	photoGone = true
	eventually("the photo left the library for good", func() bool { return !inLibrary(photo) })
	eventually("the photo is not in the trash", func() bool {
		o, isErr := call(t, cs, "drive_trash_list", map[string]any{"limit": 50, "sort": "trashed", "desc": true})
		return !isErr && !strings.Contains(o, photo)
	})

	// --- Every tool in the list was called.
	var missing []string
	for _, name := range driveTools {
		if called[name] == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("not called: %v", missing)
	}
	counts := map[string]int{}
	var names []string
	for _, name := range driveTools {
		counts[called[name]]++
		names = append(names, name+"="+called[name])
	}
	sort.Strings(names)
	t.Logf("modes: %v", counts)
	if path := os.Getenv("PROTON_MCP_MODES"); path != "" {
		_ = os.WriteFile(path, []byte(strings.Join(names, "\n")+"\n"), 0o600)
	}
}
