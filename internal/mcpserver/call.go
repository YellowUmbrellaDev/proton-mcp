package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/roman-16/proton-cli/internal/app"
	"github.com/roman-16/proton-cli/internal/cli"
	"github.com/roman-16/proton-cli/internal/mimetype"
)

// Result is what one call produced.
type Result struct {
	Text    string
	Blob    []byte
	IsError bool
	// A download also says what it fetched: the file's own name, its type, and
	// the uri it is known by. The bytes are Blob, or Text when they are text.
	Name     string
	MIMEType string
	URI      string
	// Held says the call was only previewed (an irreversible tool without
	// confirm), so nothing was changed.
	Held bool
	// DryRun says the caller asked for a preview.
	DryRun bool
}

// Runner runs a tool on behalf of one profile.
type Runner struct {
	// Profile is the saved session the commands act as.
	Profile string
	// Confirm is the confirmation policy handed to every command ("" is the
	// CLI's own).
	Confirm string
	// Zone is the IANA time zone commands work in. A server has no zone of its
	// own worth trusting: the CLI would read /etc/localtime, which on most hosts
	// resolves to "Etc/UTC", a name Proton refuses. "" means UTC.
	Zone string
}

// Call runs one tool with the caller's input.
func (r Runner) Call(ctx context.Context, t Tool, input map[string]any) Result {
	dir, err := os.MkdirTemp("", "proton-mcp-*")
	if err != nil {
		return failure("could not make a working directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	args, err := argv(t, input, dir)
	if err != nil {
		return failure("%v", err)
	}

	dry, _ := input["dry_run"].(bool)
	confirmed, _ := input["confirm"].(bool)
	held := false
	if t.Irreversible && !confirmed && !dry {
		// Nothing irreversible runs on a first call: it is previewed, and the
		// caller is told how to go through with it.
		dry, held = true, true
	}
	if t.Download && dry {
		// A download is a read: there is no preview of it to give, and running it
		// "as a dry run" would just run it. So it is not run at all.
		if held {
			return Result{Text: "Nothing was run. This hands over secrets in the clear, so it waits for a go-ahead.\n\nCall again with confirm: true to do it.", Held: true, DryRun: true}
		}
		return failure("dry_run does not apply to a download: it reads and returns what it finds, with no preview. Leave dry_run out.")
	}

	zone := r.Zone
	if zone == "" {
		zone = "UTC"
	}
	// The same safety flags for every tool; only the output format differs, because
	// a download's payload is the answer itself and not a JSON envelope.
	global := []string{"--no-input", "--no-log", "--quiet", "--profile", r.Profile, "--zone", zone}
	if !t.Download {
		global = append(global, "--output", "json")
	}
	out := filepath.Join(dir, "download")
	if r.Confirm != "" {
		global = append(global, "--confirm", r.Confirm)
	}
	if dry {
		global = append(global, "--dry-run")
	}
	if confirmed {
		global = append(global, "--yes")
	}
	full := append(append([]string{}, global...), t.Path...)
	if t.Download {
		// The file is written under its own name into a directory of ours and
		// read back, which is how the result knows that name; the flag has to
		// precede the `--` that ends the flags.
		full = append(full, "--dest-dir="+out)
	}
	full = append(full, args...)

	var stdout, errw bytes.Buffer
	code, runErr := cli.Run(ctx, full, app.Streams{Out: &stdout, Err: &errw, In: bytes.NewReader(nil)})
	if runErr != nil || code != 0 {
		msg := strings.TrimSpace(errw.String())
		if msg == "" && runErr != nil {
			msg = runErr.Error()
		}
		return Result{Text: msg, IsError: true, Held: held, DryRun: dry}
	}
	res := Result{Held: held, DryRun: dry}
	switch {
	case t.Download:
		name, data, err := readDownload(out)
		if err != nil {
			return failure("%v", err)
		}
		res.Name, res.MIMEType, res.URI = name, mimetype.ByName(name), downloadURI(t, input, name)
		if utf8.Valid(data) {
			// A file's own leading and trailing whitespace is part of its content.
			res.Text = string(data)
		} else {
			res.Blob = data
		}
	default:
		res.Text = strings.TrimSpace(stdout.String())
	}
	if held {
		res.Text = "Nothing was changed. This cannot be undone, so it was only previewed:\n\n" +
			res.Text + "\n\nCall again with confirm: true to do it."
	}
	if strings.TrimSpace(res.Text) == "" && res.Blob == nil {
		res.Text = "Done."
	}
	return res
}

// readDownload returns the one file a download command wrote under dir.
func readDownload(dir string) (name string, data []byte, err error) {
	var found []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			found = append(found, p)
		}
		return nil
	})
	if len(found) != 1 {
		return "", nil, fmt.Errorf("a download returns exactly one file, and this one produced %d: pick a single item", len(found))
	}
	data, err = os.ReadFile(found[0])
	if err != nil {
		return "", nil, err
	}
	rel, _ := filepath.Rel(dir, found[0])
	return filepath.ToSlash(rel), data, nil
}

func failure(format string, a ...any) Result {
	return Result{Text: fmt.Sprintf(format, a...), IsError: true}
}

// argv turns the caller's input into the command's positionals and flags,
// writing any file content under dir.
func argv(t Tool, input map[string]any, dir string) ([]string, error) {
	known := map[string]bool{"dry_run": true, "confirm": true}
	var positional, flags []string
	files := 0
	writeFile := func(v any) (string, error) {
		obj, ok := v.(map[string]any)
		if !ok {
			return "", fmt.Errorf("a file is {name, text} or {name, base64}")
		}
		name, _ := obj["name"].(string)
		name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
		if name == "" || name == "." || name == ".." || name == "/" {
			return "", fmt.Errorf("a file needs a name")
		}
		var data []byte
		switch {
		case obj["base64"] != nil:
			s, _ := obj["base64"].(string)
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return "", fmt.Errorf("file %s: base64 is not valid: %v", name, err)
			}
			data = b
		case obj["text"] != nil:
			s, _ := obj["text"].(string)
			data = []byte(s)
		default:
			return "", fmt.Errorf("file %s has neither text nor base64", name)
		}
		files++
		sub := filepath.Join(dir, strconv.Itoa(files))
		if err := os.Mkdir(sub, 0o700); err != nil {
			return "", err
		}
		p := filepath.Join(sub, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return "", err
		}
		return p, nil
	}
	secret := func(text string) (string, error) {
		files++
		p := filepath.Join(dir, "secret-"+strconv.Itoa(files))
		return p, os.WriteFile(p, []byte(text), 0o600)
	}

	for _, p := range t.Params {
		known[p.Prop] = true
		v, given := input[p.Prop]
		if !given || v == nil {
			if p.Required {
				return nil, fmt.Errorf("%s is required", p.Prop)
			}
			continue
		}
		if len(p.Enum) > 0 {
			if s, ok := v.(string); ok && !contains(p.Enum, s) {
				return nil, fmt.Errorf("%s accepts: %s", p.Prop, strings.Join(p.Enum, ", "))
			}
		}
		add := func(vals ...string) {
			if p.Positional {
				positional = append(positional, vals...)
				return
			}
			for _, s := range vals {
				flags = append(flags, "--"+p.Flag+"="+s)
			}
		}
		switch p.Kind {
		case kString:
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be a string", p.Prop)
			}
			if p.Positional {
				positional = append(positional, s)
			} else {
				flags = append(flags, "--"+p.Flag+"="+s)
			}
		case kBool:
			b, ok := v.(bool)
			if !ok {
				return nil, fmt.Errorf("%s must be true or false", p.Prop)
			}
			flags = append(flags, "--"+p.Flag+"="+strconv.FormatBool(b))
		case kInt:
			f, ok := v.(float64)
			if !ok || f != float64(int(f)) {
				return nil, fmt.Errorf("%s must be a whole number", p.Prop)
			}
			flags = append(flags, "--"+p.Flag+"="+strconv.Itoa(int(f)))
		case kStrings:
			list, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("%s must be a list of strings", p.Prop)
			}
			for _, e := range list {
				s, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("%s must be a list of strings", p.Prop)
				}
				add(s)
			}
		case kFile:
			path, err := writeFile(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p.Prop, err)
			}
			add(path)
		case kFiles:
			list, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("%s must be a list of files", p.Prop)
			}
			for _, e := range list {
				path, err := writeFile(e)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", p.Prop, err)
				}
				add(path)
			}
		case kSecretFile:
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be a string", p.Prop)
			}
			path, err := secret(s)
			if err != nil {
				return nil, err
			}
			flags = append(flags, "--"+p.Flag+"="+path)
		case kFieldFiles:
			list, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("%s must be a list of {field, text}", p.Prop)
			}
			for _, e := range list {
				obj, ok := e.(map[string]any)
				field, _ := obj["field"].(string)
				text, tok := obj["text"].(string)
				if !ok || field == "" || !tok {
					return nil, fmt.Errorf("%s must be a list of {field, text}", p.Prop)
				}
				path, err := secret(text)
				if err != nil {
					return nil, err
				}
				flags = append(flags, "--"+p.Flag+"="+field+"="+path)
			}
		}
	}
	for k := range input {
		if !known[k] {
			return nil, fmt.Errorf("%s is not an input of this tool", k)
		}
	}
	// `--` ends the flags, so a reference that starts with a dash is still a
	// reference.
	out := append([]string{}, flags...)
	if len(positional) > 0 {
		out = append(out, "--")
		out = append(out, positional...)
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// DecodeInput reads a tool call's arguments.
func DecodeInput(raw json.RawMessage) (map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("the input is not a JSON object: %v", err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}
