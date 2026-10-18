// Package mcpserver exposes the CLI's command tree as MCP tools.
//
// The tools are not written one by one: each runnable command becomes a tool,
// built from the same declarations the CLI answers --help from. A command added
// to the CLI is therefore a tool the moment it exists, and the two cannot
// disagree about what a command takes. The one thing decided here is which
// commands do not belong on a server at all.
package mcpserver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/roman-16/proton-cli/internal/cli"
	"github.com/roman-16/proton-cli/internal/cli/kit"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// kind is how a parameter reaches the command line.
type kind int

const (
	kString kind = iota
	kBool
	kInt
	kStrings
	// kFile is content a command would read from a path. A server has no business
	// reading its own disk for a caller, so the content travels in the request
	// and is written to a private temporary file for the length of one call.
	kFile
	kFiles
	// kSecretFile is a password the CLI takes as the path of a file holding it,
	// so that it never appears in argv. Here it is a plain string that becomes
	// such a file.
	kSecretFile
	// kFieldFiles is `NAME=FILE`, once per secret field.
	kFieldFiles
)

// Param is one input of a tool: a positional argument or a flag.
type Param struct {
	// Prop is the name in the tool's input.
	Prop string
	// Flag is the flag it feeds, without dashes; empty for a positional.
	Flag       string
	Kind       kind
	Required   bool
	Variadic   bool
	Usage      string
	Enum       []string
	Positional bool
}

// Tool is one command as a tool.
type Tool struct {
	Name         string
	Path         []string
	Description  string
	Params       []Param
	Mutating     bool
	Irreversible bool
	// Download marks a command that writes a payload to a local path. Its
	// destination is fixed to standard output and the payload is returned.
	Download bool
}

// Some commands cannot be taken back, or reach other people, although the CLI
// does not call them irreversible. A server must not run them on a first call: it
// previews them until the caller passes confirm.
//
// What decides it is the whole path, not the last word. `drive items share add`
// ends in `add`, a verb a hundred harmless commands share; what makes it reach
// someone is the `share` in the middle. So there are two lists: groups of
// commands whose every mutating member reaches people, and single verbs that do
// so wherever they appear.

// reachingGroups are path segments such that any mutating command beneath them
// acts on other people, a public link, or the way the account can be recovered or
// reached: sharing, invitations, emergency access, recovery contacts and
// forwarding.
var reachingGroups = map[string]bool{
	"share": true, "invitations": true, "emergency-access": true,
	"recovery-contacts": true, "forwarding": true, "shared": true, "links": true,
}

// reachingVerbs are verbs that reach people or cannot be undone wherever they
// are used: sending, answering an invitation, handing something over, merging.
var reachingVerbs = map[string]bool{
	"send": true, "reply": true, "forward": true, "invite": true, "resend": true,
	"respond": true, "request": true, "access": true, "transfer": true,
	"grant": true, "merge": true, "accept": true, "decline": true, "abuse": true,
	"unsubscribe": true, "receipt": true, "phishing": true, "legitimate": true,
}

// exportsSecrets are read-only commands whose output is every secret of the
// account in the clear. They have no preview, so they are held like a write.
var exportsSecrets = map[string]bool{"pass export": true, "account keys export": true}

// alsoMutating are verbs the CLI's own list of mutating verbs leaves out although
// every command with one goes through kit.Mutate: `verify` sends a confirmation
// email or SMS, or marks an address as confirmed. Left out, a tool is advertised
// as read-only and has no dry_run input, so a caller could not preview it.
var alsoMutating = map[string]bool{"verify": true}

// NeedsConfirm says whether a tool is previewed until the caller passes confirm.
func (t Tool) NeedsConfirm() bool {
	if t.Irreversible || exportsSecrets[strings.Join(t.Path, " ")] {
		return true
	}
	if !t.Mutating {
		return false
	}
	if reachingVerbs[t.Path[len(t.Path)-1]] {
		return true
	}
	for _, seg := range t.Path[:len(t.Path)-1] {
		if reachingGroups[seg] {
			return true
		}
	}
	return false
}

// Options decide which commands become tools.
type Options struct {
	// EnableAPI exposes `api`, the raw request escape hatch.
	EnableAPI bool
}

// excluded are the commands that make no sense on a server, or that a caller
// must never be handed. Each has a reason, which the catalog test prints, so an
// addition here is a decision rather than an omission.
var excluded = map[string]string{
	"account login":           "the session is made by the server's own sign-in, not by a tool",
	"account logout":          "it would end the server's session for everyone",
	"account delete":          "deletes the Proton account",
	"account sessions create": "approves another device into the account",
	"account profiles list":   "profiles are the server's own bookkeeping",
	"account profiles delete": "profiles are the server's own bookkeeping",
	"report":                  "reads this machine's diagnostic log",
	"update":                  "replaces the server's binary",
	"uninstall":               "removes the server's binary",
	"completion":              "shell completion",
	"skill":                   "prints guidance for a terminal agent",
	"version":                 "not about the account",
	"changelog":               "not about the account",
	"help":                    "not about the account",
}

// Reason says why a command is not a tool, or "" when it is one.
func Reason(path []string, c *cobra.Command, o Options) string {
	if c.Hidden {
		return "hidden"
	}
	key := strings.Join(path, " ")
	if key == "api" && !o.EnableAPI {
		return "a raw request skips every guard the other commands have; enable it explicitly"
	}
	if why, ok := excluded[key]; ok {
		return why
	}
	if c.Name() == "watch" {
		return "never returns"
	}
	return ""
}

// Catalog builds the tools from the CLI's command tree, in a stable order, and
// the commands it left out with the reason for each.
func Catalog(o Options) (tools []Tool, left map[string]string, err error) {
	left = map[string]string{}
	enums := kit.DeclaredEnums()
	names := map[string]string{}
	var walk func(c *cobra.Command) error
	walk = func(c *cobra.Command) error {
		if !c.HasSubCommands() && c.Runnable() {
			path := strings.Fields(c.CommandPath())[1:]
			if why := Reason(path, c, o); why != "" {
				left[strings.Join(path, " ")] = why
			} else {
				t, err := build(c, path, enums)
				if err != nil {
					return err
				}
				if other, dup := names[t.Name]; dup {
					return fmt.Errorf("tool name %s is made by both %q and %q", t.Name, other, strings.Join(path, " "))
				}
				names[t.Name] = strings.Join(path, " ")
				tools = append(tools, t)
			}
		}
		for _, s := range c.Commands() {
			if err := walk(s); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(cli.Root()); err != nil {
		return nil, nil, err
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools, left, nil
}

func build(c *cobra.Command, path []string, enums map[string][]string) (Tool, error) {
	t := Tool{
		Name:         strings.ReplaceAll(strings.Join(path, "_"), "-", "_"),
		Path:         path,
		Mutating:     kit.Mutating[c.Name()] || alsoMutating[c.Name()],
		Irreversible: kit.Irreversible[c.Name()],
	}
	if t.NeedsConfirm() {
		t.Irreversible = true
	}
	t.Description = describe(c, path)
	used := map[string]bool{"dry_run": true, "confirm": true}
	take := func(prop string) error {
		if used[prop] {
			return fmt.Errorf("%s: two inputs are called %q", strings.Join(path, " "), prop)
		}
		used[prop] = true
		return nil
	}

	local := isLocalPositional
	for _, a := range kit.Arguments(c.Use) {
		p := Param{
			Prop:       strings.ToLower(a.Name),
			Kind:       kString,
			Required:   !a.Optional,
			Variadic:   a.Variadic,
			Positional: true,
			Usage:      kit.Placeholders[a.Name].Means,
		}
		if a.Variadic {
			p.Kind = kStrings
		}
		if local(path, a.Name) {
			p.Kind = kFile
			p.Usage = "the file's content, as {name, text} or {name, base64}"
		}
		if err := take(p.Prop); err != nil {
			return t, err
		}
		t.Params = append(t.Params, p)
	}

	hasDest := c.LocalFlags().Lookup("dest") != nil
	t.Download = hasDest && c.LocalFlags().Lookup("dest-dir") != nil
	var ferr error
	c.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if ferr != nil || f.Hidden || f.Name == "help" || f.Name == "version" {
			return
		}
		if t.Download && (f.Name == "dest" || f.Name == "dest-dir" || f.Name == "force") {
			return
		}
		if f.Value.Type() == "bool" && strings.Contains(f.Usage, "asked for at the prompt") {
			return // a server cannot ask; the same secret arrives through its -file twin
		}
		if len(path) >= 2 && path[len(path)-1] == "upload" && f.Name == "recursive" {
			return // a directory would be a directory of the server
		}
		p := Param{Prop: strings.ReplaceAll(f.Name, "-", "_"), Flag: f.Name, Usage: strings.ReplaceAll(f.Usage, "\n", " ")}
		switch f.Value.Type() {
		case "bool":
			p.Kind = kBool
		case "int":
			p.Kind = kInt
		case "stringArray", "stringSlice":
			p.Kind = kStrings
		default:
			p.Kind = kString
		}
		switch {
		case f.Name == "secret-file":
			p.Kind, p.Prop = kFieldFiles, "secrets"
			p.Usage = "secret fields, each {field, text}"
		case strings.HasSuffix(f.Name, "-file") && (strings.Contains(f.Name, "password") || strings.Contains(f.Name, "phrase")):
			p.Kind = kSecretFile
			p.Prop = strings.ReplaceAll(strings.TrimSuffix(f.Name, "-file"), "-", "_")
			p.Usage = strings.Replace(p.Usage, "from a file, or - for stdin", "", 1)
		case isFileFlag(f.Name):
			p.Kind = kFile
			if f.Value.Type() == "stringArray" {
				p.Kind = kFiles
			}
			p.Usage += " (give the content as {name, text} or {name, base64})"
		}
		if v, ok := enums[c.CommandPath()+" --"+f.Name]; ok {
			p.Enum = v
		}
		if ann := f.Annotations[cobra.BashCompOneRequiredFlag]; len(ann) == 1 && ann[0] == "true" {
			p.Required = true
		}
		if err := take(p.Prop); err != nil {
			ferr = err
			return
		}
		t.Params = append(t.Params, p)
	})
	return t, ferr
}

// isLocalPositional says whether a positional is a path on the caller's disk,
// as opposed to a path in Drive or a reference to something in the account.
func isLocalPositional(path []string, placeholder string) bool {
	switch placeholder {
	case "SRC":
		return true
	case "PATH":
		return path[len(path)-1] == "import"
	}
	return false
}

// isFileFlag is a flag whose value is a file the command reads.
func isFileFlag(name string) bool {
	switch name {
	case "attach", "attach-inline", "eml", "key", "recovery-file", "photo":
		return true
	}
	return false
}

func describe(c *cobra.Command, path []string) string {
	d := c.Short
	if long := strings.TrimSpace(c.Long); long != "" {
		first, _, _ := strings.Cut(long, "\n\n")
		first = strings.Join(strings.Fields(first), " ")
		if first != "" && !strings.HasPrefix(first, strings.TrimSuffix(c.Short, ".")) {
			d += ". " + first
		}
	}
	if len(d) > 700 {
		d = d[:700] + "…"
	}
	return fmt.Sprintf("%s (proton %s)", strings.TrimSpace(d), strings.Join(path, " "))
}
