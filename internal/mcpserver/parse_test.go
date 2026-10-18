package mcpserver

import (
	"regexp"
	"strings"
	"testing"

	"github.com/roman-16/proton-cli/internal/cli"
)

// sample is an input that fills every parameter a tool declares, with a value of
// the right shape.
func sample(t Tool) map[string]any {
	in := map[string]any{}
	file := map[string]any{"name": "f.txt", "text": "x"}
	for _, p := range t.Params {
		switch p.Kind {
		case kBool:
			in[p.Prop] = true
		case kInt:
			in[p.Prop] = float64(1)
		case kStrings:
			in[p.Prop] = []any{"a@example.com"}
		case kFile:
			in[p.Prop] = file
		case kFiles:
			in[p.Prop] = []any{file}
		case kSecretFile:
			in[p.Prop] = "s3cret"
		case kFieldFiles:
			in[p.Prop] = []any{map[string]any{"field": "f", "text": "t"}}
		default:
			v := "a@example.com"
			if len(p.Enum) > 0 {
				v = p.Enum[0]
			}
			in[p.Prop] = v
		}
	}
	return in
}

// valueLevel are refusals about what a value means, which a sample cannot know:
// they prove the command line was understood and reached validation.
var valueLevel = regexp.MustCompile(`There is no \w+ setting called|Name one address, or pass --type`)

// Every tool, with every parameter set, must produce a command line the CLI's own
// parser accepts. This is what proves the schema and the argument builder agree
// with the command tree for all of them, not only the ones tried against an
// account.
func TestEveryToolBuildsAParseableCommandLine(t *testing.T) {
	tools, _, err := Catalog(Options{})
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	for _, tool := range tools {
		dir := t.TempDir()
		args, err := argv(tool, sample(tool), dir)
		if err != nil {
			t.Errorf("%s: %v", tool.Name, err)
			bad++
			continue
		}
		line := append(append([]string{}, tool.Path...), args...)
		if tool.Download {
			line = append([]string{}, tool.Path...)
			line = append(line, "--dest=-")
			line = append(line, args...)
		}
		if err := cli.Check(line); err != nil && !valueLevel.MatchString(err.Error()) {
			t.Errorf("%s: the CLI refuses %q: %v", tool.Name, strings.Join(line, " "), err)
			bad++
		}
	}
	t.Logf("%d tools checked, %d refused", len(tools), bad)
}
