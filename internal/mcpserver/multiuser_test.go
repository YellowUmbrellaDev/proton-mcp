package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/roman-16/proton-cli/internal/mcpauth"
)

// withToken is the context a verified request reaches a tool call with.
func withToken(subject string, scopes ...string) context.Context {
	var got context.Context
	h := auth.RequireBearerToken(func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return &auth.TokenInfo{UserID: subject, Scopes: scopes, Expiration: time.Now().Add(time.Hour)}, nil
	}, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Context() }))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer x")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got == nil {
		panic("token was not accepted")
	}
	return got
}

func TestRunnerFromTokenGivesEachSubjectItsOwnProfile(t *testing.T) {
	defaults := Runner{Profile: "ignored", Confirm: "ask", Zone: "UTC"}
	from := RunnerFromToken(defaults)

	var wg sync.WaitGroup
	for _, subject := range []string{"alice", "bob", "alice", "bob", "carol-2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := from(withToken(subject, mcpauth.ScopeRead))
			if err != nil {
				t.Errorf("%s: %v", subject, err)
				return
			}
			if r != (Runner{Profile: subject, Confirm: "ask", Zone: "UTC"}) {
				t.Errorf("%s got %+v", subject, r)
			}
		}()
	}
	wg.Wait()
	if defaults.Profile != "ignored" {
		t.Fatal("the defaults were modified")
	}
}

func TestRunnerFromTokenRefusesWhatIsNotAProfile(t *testing.T) {
	from := RunnerFromToken(Runner{})
	if _, err := from(context.Background()); err == nil {
		t.Error("no token: want an error")
	}
	for _, subject := range []string{"", "../x", "a/b", "..", ".hidden", "a\\b", "x y", strings.Repeat("a", 65)} {
		if r, err := from(withToken(subject, mcpauth.ScopeWrite)); err == nil {
			t.Errorf("subject %q accepted as profile %q", subject, r.Profile)
		}
	}
}

func TestAllowByScope(t *testing.T) {
	read := Tool{Name: "mail_messages_list"}
	write := Tool{Name: "mail_messages_delete", Mutating: true}
	allow := AllowByScope()
	cases := []struct {
		name    string
		ctx     context.Context
		tool    Tool
		wantErr string
	}{
		{"no token", context.Background(), read, "no verified token"},
		{"no scopes", withToken("a"), read, "no Proton access"},
		{"foreign scope", withToken("a", "openid"), read, "no Proton access"},
		{"read reads", withToken("a", mcpauth.ScopeRead), read, ""},
		{"read cannot write", withToken("a", mcpauth.ScopeRead), write, "read-only"},
		{"write reads", withToken("a", mcpauth.ScopeWrite), read, ""},
		{"write writes", withToken("a", mcpauth.ScopeWrite), write, ""},
		{"both write", withToken("a", mcpauth.ScopeRead, mcpauth.ScopeWrite), write, ""},
	}
	for _, c := range cases {
		err := allow(c.ctx, c.tool)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: err = %v, want it to contain %q", c.name, err, c.wantErr)
		}
	}
	err := allow(withToken("a", mcpauth.ScopeRead), write)
	if !strings.Contains(err.Error(), "write access") || !strings.Contains(err.Error(), "connect again") {
		t.Errorf("the denial does not say how to get write access: %v", err)
	}
}

// A read-only grant is turned away over the wire, before any command is run: the
// Runner here fails the test if it is ever reached.
func TestReadOnlyTokenIsDeniedMutatingToolOverHTTP(t *testing.T) {
	srv, _, err := New(Config{
		Version: "test",
		Runner: func(context.Context) (Runner, error) {
			t.Error("the runner was reached by a denied call")
			return Runner{}, nil
		},
		Allow: AllowByScope(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verify := func(_ context.Context, tok string, _ *http.Request) (*auth.TokenInfo, error) {
		if tok != "ro" {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: "alice", Scopes: []string{mcpauth.ScopeRead}, Expiration: time.Now().Add(time.Hour)}, nil
	}
	mcpH := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	ts := httptest.NewServer(auth.RequireBearerToken(verify, nil)(mcpH))
	defer ts.Close()

	// Without a token the endpoint is closed.
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer ro")
		return http.DefaultTransport.RoundTrip(r)
	})}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: ts.URL, HTTPClient: hc, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "mail_messages_delete", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if !res.IsError || !strings.Contains(text, "read-only") {
		t.Fatalf("want a read-only denial, got error=%v %q", res.IsError, text)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
