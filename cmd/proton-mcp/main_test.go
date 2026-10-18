package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roman-16/proton-cli/internal/mcpauth"
	"github.com/roman-16/proton-cli/internal/protonlogin"
)

func keyFile(t *testing.T, content string) string {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadKey(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, 32)
	cases := []struct {
		name, content string
		want          []byte // nil: refused
	}{
		{"base64 of 32 bytes", base64.StdEncoding.EncodeToString(raw) + "\n", raw},
		{"raw url base64", base64.RawURLEncoding.EncodeToString(raw), raw},
		{"exactly 32 bytes", strings.Repeat("k", 32) + "\n", []byte(strings.Repeat("k", 32))},
		{"too short", "short", nil},
		{"base64 of 16 bytes", base64.StdEncoding.EncodeToString(raw[:16]), nil},
		{"empty", "", nil},
	}
	for _, c := range cases {
		got, err := loadKey(keyFile(t, c.content))
		if c.want == nil {
			if err == nil {
				t.Errorf("%s: accepted", c.name)
			}
			continue
		}
		if err != nil || !bytes.Equal(got, c.want) {
			t.Errorf("%s: got %x, %v", c.name, got, err)
		}
	}
	long, err := loadKey(keyFile(t, strings.Repeat("long secret ", 10)))
	if err != nil || len(long) != 32 {
		t.Errorf("a long secret: %d bytes, %v", len(long), err)
	}
	if _, err := loadKey(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file was accepted")
	}
}

func TestParseIssuer(t *testing.T) {
	for in, want := range map[string]string{
		"https://proton-mcp.example.com":  "https://proton-mcp.example.com",
		"https://proton-mcp.example.com/": "https://proton-mcp.example.com",
		"http://127.0.0.1:8080":           "http://127.0.0.1:8080",
	} {
		if got, err := parseIssuer(in); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "proton-mcp.example.com", "ftp://x", "https://x/path", "https://x?q=1", "https://"} {
		if _, err := parseIssuer(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func get(h http.Handler, path string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// noLogin is a Login that never signs anybody in: these tests only look at what
// the mux lets through, not at the sign-in.
type noLogin struct{}

func (noLogin) Start(context.Context) (mcpauth.Attempt, error) {
	return mcpauth.Attempt{}, errors.New("no sign-in in this test")
}
func (noLogin) Check(context.Context, string) (mcpauth.Status, error) {
	return mcpauth.Status{State: mcpauth.Failed, Message: "no sign-in in this test"}, nil
}
func (noLogin) Forget(context.Context, string) error { return nil }

// authServer builds a real authorization server over a temp state file.
func authServer(t *testing.T) *mcpauth.Server {
	t.Helper()
	as, err := mcpauth.New(mcpauth.Config{
		Issuer:    "https://proton-mcp.example.com",
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Key:       bytes.Repeat([]byte{7}, 32),
		Login:     noLogin{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = as.Close() })
	return as
}

var reached = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("mcp")) })

func TestHealthzNeedsNoToken(t *testing.T) {
	as := authServer(t)
	for name, h := range map[string]http.Handler{
		"static": staticMux("secret", reached),
		"oauth":  oauthMux(as, reached),
	} {
		rec := get(h, "/healthz")
		if rec.Code != 200 || rec.Body.String() != "ok" {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Body.String())
		}
	}
}

func TestStaticModeNeedsTheToken(t *testing.T) {
	h := staticMux("secret\n", reached)
	if rec := get(h, "/mcp"); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
	if rec := get(h, "/mcp", "Authorization", "Bearer secret"); rec.Code != 200 {
		t.Errorf("token: %d", rec.Code)
	}
}

// The MCP endpoint is closed to anything the authorization server did not issue.
func TestOAuthModeClosesTheMCPPath(t *testing.T) {
	h := oauthMux(authServer(t), reached)
	for _, hdr := range [][]string{nil, {"Authorization", "Bearer guess"}} {
		rec := get(h, mcpauth.MCPPath, hdr...)
		if rec.Code != http.StatusUnauthorized || rec.Body.String() == "mcp" {
			t.Errorf("%v: %d", hdr, rec.Code)
		}
	}
	// Everything else belongs to the authorization server.
	if rec := get(h, "/.well-known/oauth-authorization-server"); rec.Code == 200 && rec.Body.String() == "mcp" {
		t.Error("the MCP handler answered an auth path")
	}
}

// run returns its errors instead of exiting, so the deferred Close of the login
// and of the authorization server always runs: log.Fatal would skip it.
func TestRunReturnsAnErrorInsteadOfExiting(t *testing.T) {
	for name, args := range map[string][]string{
		"oauth without its files":    {"-oauth", "-issuer", "https://x.example"},
		"oauth with a shared token":  {"-oauth", "-token-file", "/dev/null", "-issuer", "https://x.example", "-state", "s", "-key-file", "k"},
		"http with no auth at all":   {"-addr", "127.0.0.1:0"},
		"a zone that does not exist": {"-zone", "Not/AZone"},
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		if err := run(fs, args); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// -keep-anonymous-session reaches the sign-in, and is off unless given.
func TestKeepAnonymousSessionReachesTheLogin(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop here")
	defer func(orig func(protonlogin.Config) (mcpauth.Login, error)) { newLogin = orig }(newLogin)
	for _, keep := range []bool{false, true} {
		var got *protonlogin.Config
		newLogin = func(cfg protonlogin.Config) (mcpauth.Login, error) {
			got = &cfg
			return nil, stop
		}
		args := []string{"-oauth", "-issuer", "https://x.example", "-state", filepath.Join(dir, "state"), "-key-file", key}
		if keep {
			args = append(args, "-keep-anonymous-session")
		}
		if err := run(flag.NewFlagSet("t", flag.ContinueOnError), args); !errors.Is(err, stop) {
			t.Fatalf("run = %v, want it to reach the login", err)
		}
		if got == nil || got.KeepAnonymousSession != keep {
			t.Errorf("with the flag %v the login got %+v", keep, got)
		}
	}
}
