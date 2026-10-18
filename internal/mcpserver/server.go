package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Config is what a server is built from.
type Config struct {
	Version string
	Options Options
	// Runner picks who a call acts as. A multi-user server returns a different
	// profile per request; a single-user one returns the same.
	Runner func(ctx context.Context) (Runner, error)
	// Allow decides whether the caller may use a tool, for scopes. Nil allows
	// everything.
	Allow func(ctx context.Context, t Tool) error
	// Record is told the outcome of every call. It is how coverage is measured:
	// which tools have really run, against a real account, and which only exist.
	Record func(t Tool, r Result)
}

// observe tells the configured hook about a call, if there is one.
func (c Config) observe(t Tool, r Result) {
	if c.Record != nil {
		c.Record(t, r)
	}
}

// New builds an MCP server with one tool per command.
func New(c Config) (*mcp.Server, []Tool, error) {
	tools, _, err := Catalog(c.Options)
	if err != nil {
		return nil, nil, err
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "proton-mcp", Version: c.Version}, nil)
	for _, t := range tools {
		t := t
		s.AddTool(&mcp.Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: schema(t),
			Annotations: annotations(t),
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if c.Allow != nil {
				if err := c.Allow(ctx, t); err != nil {
					return textResult(err.Error(), true), nil
				}
			}
			in, err := DecodeInput(req.Params.Arguments)
			if err != nil {
				return textResult(err.Error(), true), nil
			}
			run, err := c.Runner(ctx)
			if err != nil {
				return textResult(fmt.Sprintf("no Proton session for this caller: %v", err), true), nil
			}
			res := run.Call(ctx, t, in)
			c.observe(t, res)
			return toResult(res), nil
		})
	}
	return s, tools, nil
}

func textResult(text string, isErr bool) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}, IsError: isErr}
}

func toResult(r Result) *mcp.CallToolResult {
	if r.Blob != nil {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.EmbeddedResource{
			Resource: &mcp.ResourceContents{URI: "proton://download/" + r.Name, MIMEType: "application/octet-stream", Blob: r.Blob},
		}}}
	}
	return textResult(r.Text, r.IsError)
}

func annotations(t Tool) *mcp.ToolAnnotations {
	open := true
	a := &mcp.ToolAnnotations{ReadOnlyHint: !t.Mutating, OpenWorldHint: &open}
	if t.Mutating {
		destructive := t.Irreversible
		a.DestructiveHint = &destructive
	}
	return a
}

// schema is the tool's input as JSON Schema.
func schema(t Tool) map[string]any {
	props := map[string]any{}
	var required []string
	file := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":   map[string]any{"type": "string"},
			"text":   map[string]any{"type": "string"},
			"base64": map[string]any{"type": "string"},
		},
		"required": []string{"name"},
	}
	for _, p := range t.Params {
		var s map[string]any
		switch p.Kind {
		case kBool:
			s = map[string]any{"type": "boolean"}
		case kInt:
			s = map[string]any{"type": "integer"}
		case kStrings:
			s = map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
		case kFile:
			s = clone(file)
		case kFiles:
			s = map[string]any{"type": "array", "items": clone(file)}
		case kFieldFiles:
			s = map[string]any{"type": "array", "items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"field": map[string]any{"type": "string"},
					"text":  map[string]any{"type": "string"},
				},
				"required": []string{"field", "text"},
			}}
		default:
			s = map[string]any{"type": "string"}
		}
		if p.Usage != "" {
			s["description"] = p.Usage
		}
		if len(p.Enum) > 0 {
			s["enum"] = p.Enum
		}
		props[p.Prop] = s
		if p.Required {
			required = append(required, p.Prop)
		}
	}
	if t.Mutating {
		props["dry_run"] = map[string]any{"type": "boolean", "description": "Preview the change without making it."}
	}
	if t.Irreversible {
		props["confirm"] = map[string]any{"type": "boolean", "description": "Required to go through with something that cannot be undone. Without it the call is only previewed."}
	}
	out := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
