package mcpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// callRaw is call, but it hands back the bytes of an embedded blob too.
func callRaw(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (text string, blob []byte, isErr bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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

// TestLiveDrive exercises the Drive tools inside one folder of its own and
// removes it. Nothing is shared and no public link is made.
func TestLiveDrive(t *testing.T) {
	cs := live(t)
	tag := "proton-mcp-test-" + time.Now().Format("150405")
	root := "/" + tag

	ok := func(name string, args map[string]any) string {
		t.Helper()
		out, isErr := call(t, cs, name, args)
		t.Logf("%-28s %.100q", name, strings.ReplaceAll(out, "\n", " "))
		if isErr {
			t.Fatalf("%s failed: %s", name, out)
		}
		return out
	}
	upload := func(file map[string]any, dest string, extra map[string]any) string {
		t.Helper()
		args := map[string]any{"src": file, "dest": dest}
		for k, v := range extra {
			args[k] = v
		}
		return ok("drive_items_upload", args)
	}
	listing := func(path string) string { return ok("drive_items_list", map[string]any{"path": path}) }
	names := func(path string) map[string]bool {
		t.Helper()
		var env struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		raw := listing(path)
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
			t.Fatalf("list %s is not JSON: %v\n%.300s", path, err, raw)
		}
		m := map[string]bool{}
		for _, it := range env.Items {
			m[it.Name] = true
		}
		return m
	}
	wantNames := func(path string, want ...string) {
		t.Helper()
		got := names(path)
		if len(got) != len(want) {
			t.Errorf("%s holds %v, want %v", path, got, want)
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("%s does not hold %q (has %v)", path, w, got)
			}
		}
	}
	download := func(path string) []byte {
		t.Helper()
		text, blob, isErr := callRaw(t, cs, "drive_items_download", map[string]any{"path": path})
		if isErr {
			t.Fatalf("download %s: %s", path, text)
		}
		if blob != nil {
			return blob
		}
		return []byte(text)
	}
	ids := func(raw string) []string {
		var m struct {
			IDs []string `json:"ids"`
		}
		_ = json.Unmarshal([]byte(raw), &m)
		return m.IDs
	}

	// The folder goes whatever happens: by exact path, and only this one.
	t.Cleanup(func() {
		out, _ := call(t, cs, "drive_items_delete", map[string]any{"path": []any{root}, "confirm": true})
		t.Logf("cleanup delete %s: %.120q", root, strings.ReplaceAll(out, "\n", " "))
	})

	// --- Folders: create (nested, missing parents made), get, list.
	ok("drive_items_create", map[string]any{"path": root + "/a/b/c"})
	ok("drive_items_create", map[string]any{"path": root + "/dest"})
	wantNames(root, "a", "dest")
	wantNames(root+"/a", "b")
	if got := ok("drive_items_get", map[string]any{"path": root + "/a"}); !strings.Contains(got, `"type": "folder"`) {
		t.Errorf("get on a folder: %.200s", got)
	}

	// --- Binary upload, ~2 MB of random bytes, back byte for byte.
	big := make([]byte, 2<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	upload(map[string]any{"name": "random.bin", "base64": base64.StdEncoding.EncodeToString(big)}, root, nil)
	if got := download(root + "/random.bin"); !bytes.Equal(got, big) {
		t.Errorf("binary round trip differs: sent %d bytes, got %d", len(big), len(got))
	}
	// Every byte value, so nothing that looks like text or a line ending is changed.
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	upload(map[string]any{"name": "bytes.bin", "base64": base64.StdEncoding.EncodeToString(all)}, root, nil)
	if got := download(root + "/bytes.bin"); !bytes.Equal(got, all) {
		t.Errorf("0..255 round trip differs: got %d bytes", len(got))
	}

	// --- Text comes back exactly, whitespace included.
	const spaced = "\n  linea con espacios  \n\náéí ☃\n\n"
	upload(map[string]any{"name": "spaced.txt", "text": spaced}, root, nil)
	if got := download(root + "/spaced.txt"); string(got) != spaced {
		t.Errorf("text round trip differs: got %q want %q", got, spaced)
	}

	// --- if_exists: refused by default, then rename / replace / skip.
	upload(map[string]any{"name": "dup.txt", "text": "one"}, root+"/dest", nil)
	if out, isErr := call(t, cs, "drive_items_upload", map[string]any{"src": map[string]any{"name": "dup.txt", "text": "two"}, "dest": root + "/dest"}); !isErr {
		t.Errorf("a name already taken must be refused without if_exists: %.200s", out)
	}
	upload(map[string]any{"name": "dup.txt", "text": "skipped"}, root+"/dest", map[string]any{"if_exists": "skip"})
	if got := download(root + "/dest/dup.txt"); string(got) != "one" {
		t.Errorf("skip changed the file: %q", got)
	}
	upload(map[string]any{"name": "dup.txt", "text": "renamed"}, root+"/dest", map[string]any{"if_exists": "rename"})
	if n := names(root + "/dest"); len(n) != 2 || !n["dup.txt"] {
		t.Errorf("rename should keep both files: %v", n)
	}
	upload(map[string]any{"name": "dup.txt", "text": "replaced"}, root+"/dest", map[string]any{"if_exists": "replace"})
	if got := download(root + "/dest/dup.txt"); string(got) != "replaced" {
		t.Errorf("replace did not take: %q", got)
	}
	wantNames(root+"/dest", "dup.txt", func() string {
		for n := range names(root + "/dest") {
			if n != "dup.txt" {
				return n
			}
		}
		return ""
	}())

	// --- Revisions: the replace left the first version behind.
	var revs struct {
		Revisions []struct {
			ID    string `json:"id"`
			State int    `json:"state"`
			Size  int    `json:"size"`
		} `json:"revisions"`
	}
	raw := ok("drive_items_revisions_list", map[string]any{"path": root + "/dest/dup.txt"})
	if err := json.Unmarshal([]byte(raw), &revs); err != nil || len(revs.Revisions) != 2 {
		t.Fatalf("expected 2 revisions after a replace: %v\n%.300s", err, raw)
	}
	found := map[string]bool{}
	for _, r := range revs.Revisions {
		text, blob, isErr := callRaw(t, cs, "drive_items_revisions_download", map[string]any{"path": root + "/dest/dup.txt", "revision_ref": r.ID})
		if isErr {
			t.Fatalf("revisions_download: %s", text)
		}
		if blob != nil {
			text = string(blob)
		}
		found[text] = true
	}
	if !found["one"] || !found["replaced"] {
		t.Errorf("revisions should hold both versions, got %v", found)
	}

	// --- Rename, move, copy.
	ok("drive_items_update", map[string]any{"path": root + "/dest/dup.txt", "name": "renamed.txt"})
	if got := download(root + "/dest/renamed.txt"); string(got) != "replaced" {
		t.Errorf("renamed file changed: %q", got)
	}
	ok("drive_items_move", map[string]any{"path": []any{root + "/dest/renamed.txt"}, "into": root + "/a/b"})
	wantNames(root+"/a/b", "c", "renamed.txt")
	ok("drive_items_copy", map[string]any{"path": []any{root + "/a/b/renamed.txt"}, "into": root + "/a/b/c"})
	wantNames(root+"/a/b/c", "renamed.txt")
	wantNames(root+"/a/b", "c", "renamed.txt")
	if got := download(root + "/a/b/c/renamed.txt"); string(got) != "replaced" {
		t.Errorf("copy differs: %q", got)
	}

	// --- Recursive listing and a filtered listing.
	if got := ok("drive_items_list", map[string]any{"path": root, "recursive": true, "pattern": "renamed.txt"}); strings.Count(got, `"name": "renamed.txt"`) != 2 {
		t.Errorf("recursive pattern list should find both copies: %.400s", got)
	}

	// --- An unconfirmed delete is only previewed.
	pre, isErr := call(t, cs, "drive_items_delete", map[string]any{"path": []any{root + "/a"}})
	if isErr || !strings.Contains(pre, "Nothing was changed") {
		t.Errorf("unconfirmed delete was not held back: err=%v %.200s", isErr, pre)
	}
	wantNames(root, "a", "dest", "random.bin", "bytes.bin", "spaced.txt")
	wantNames(root+"/a/b", "c", "renamed.txt")

	// --- Trash, restore, trash again; a trashed item is addressed by its ID.
	tr := ids(ok("drive_items_trash", map[string]any{"path": []any{root + "/a/b/c/renamed.txt"}}))
	if len(tr) != 1 {
		t.Fatalf("trash returned ids %v", tr)
	}
	wantNames(root + "/a/b/c")
	inTrash := func(id string) bool {
		t.Helper()
		raw := ok("drive_trash_list", map[string]any{"limit": 20, "sort": "trashed", "desc": true})
		return strings.Contains(raw, id)
	}
	if !inTrash(tr[0]) {
		t.Errorf("trashed item %s is not in the trash list", tr[0])
	}
	ok("drive_trash_restore", map[string]any{"ref": []any{tr[0]}})
	wantNames(root+"/a/b/c", "renamed.txt")
	if inTrash(tr[0]) {
		t.Errorf("restored item is still listed in the trash")
	}
	tr = ids(ok("drive_items_trash", map[string]any{"path": []any{root + "/a/b/c/renamed.txt"}}))
	if len(tr) != 1 || !inTrash(tr[0]) {
		t.Errorf("trashing again: ids %v", tr)
	}
	// Bring it back so deleting the folder takes it too: there is no way to delete
	// one trashed item by ID, and the trash must not be emptied.
	ok("drive_trash_restore", map[string]any{"ref": []any{tr[0]}})
	wantNames(root+"/a/b/c", "renamed.txt")

	// --- Read-only tools around Drive.
	for _, name := range []string{"drive_shared_list", "drive_sharing_list", "drive_links_list", "drive_invitations_list", "drive_volumes_list", "drive_computers_list", "drive_settings_list", "drive_photos_list", "drive_photos_albums_list"} {
		args := map[string]any{}
		if name == "drive_photos_list" {
			args["limit"] = 2
		}
		out := ok(name, args)
		if !strings.HasPrefix(strings.TrimSpace(out), "{") {
			t.Errorf("%s did not return JSON: %.120s", name, out)
		}
	}
	if got := ok("drive_items_share_get", map[string]any{"path": root + "/a"}); got == "" {
		t.Errorf("share_get on an unshared folder returned nothing")
	}
	if out, isErr := call(t, cs, "drive_links_get", map[string]any{"path": root + "/a"}); !isErr || !strings.Contains(out, "has no public link") {
		t.Errorf("links_get on a folder without a link should say so: err=%v %.200s", isErr, out)
	}
	var photos struct {
		Photos []struct {
			LinkID string `json:"link_id"`
		} `json:"photos"`
	}
	if err := json.Unmarshal([]byte(ok("drive_photos_list", map[string]any{"limit": 1})), &photos); err == nil && len(photos.Photos) == 1 {
		// Metadata only: a photo download is not attempted (it would pull a real file).
		out, _ := call(t, cs, "drive_photos_links_get", map[string]any{"ref": photos.Photos[0].LinkID})
		if !strings.Contains(out, "link") {
			t.Errorf("photos_links_get returned nothing useful: %.200s", out)
		}
	}

	// --- Delete the folder for real, then check it is gone.
	ok("drive_items_delete", map[string]any{"path": []any{root}, "confirm": true})
	if got := listing("/"); strings.Contains(got, tag) {
		t.Errorf("%s is still in the drive root after delete", tag)
	}
}
