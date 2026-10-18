package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/roman-16/proton-cli/internal/mcpauth"
	"github.com/roman-16/proton-cli/internal/protonlogin"
)

// newLogin builds the sign-in the authorization server sends people through: the
// Proton "sign in with another device" flow.
var newLogin = func(cfg protonlogin.Config) (mcpauth.Login, error) {
	return protonlogin.New(cfg)
}

// forwardedClientIP names the client of a request for the rate limit when the
// server sits behind a reverse proxy that writes X-Forwarded-For. It takes the
// last entry, the one the proxy itself appended: the earlier ones are whatever
// the caller sent. Only use it when every request really arrives through that
// proxy, otherwise a caller can pick its own address.
func forwardedClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loadKey reads the key that seals what the authorization server keeps at rest.
// The file holds either the base64 of 32 bytes, or at least 32 bytes of anything
// (a longer secret is hashed down to 32). Surrounding whitespace is ignored.
func loadKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(raw))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(text); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	switch b := []byte(text); {
	case len(b) == 32:
		return b, nil
	case len(b) > 32:
		sum := sha256.Sum256(b)
		return sum[:], nil
	}
	return nil, fmt.Errorf("%s holds fewer than 32 bytes and is not the base64 of 32 bytes", path)
}

// parseIssuer checks the public base URL the clients are told about.
func parseIssuer(s string) (string, error) {
	s = strings.TrimRight(s, "/")
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("-issuer must be a base URL such as https://proton-mcp.example.com, not %q", s)
	}
	return s, nil
}

// healthz answers the container healthcheck. It reveals nothing and needs no
// token.
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// staticMux serves one account behind one shared bearer token, for local use.
func staticMux(secret string, mcpHandler http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.Handle("/", bearer(secret, mcpHandler))
	return mux
}

// oauthMux serves many accounts: the authorization server owns everything but
// the MCP endpoint, which only a verified bearer token reaches.
func oauthMux(as *mcpauth.Server, mcpHandler http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.Handle("/", as.Handler())
	mux.Handle(mcpauth.MCPPath, auth.RequireBearerToken(as.Verifier(), &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: as.ResourceMetadataURL(),
	})(mcpHandler))
	return mux
}

func streamable(server *mcp.Server) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
}
