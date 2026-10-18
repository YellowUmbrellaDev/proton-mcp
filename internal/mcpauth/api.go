// Package mcpauth is the OAuth 2.1 authorization server that sits in front of the
// MCP endpoint, so a client such as Executor can connect the way it connects to
// Gmail or Atlassian: discover, register, send the person to a login page, get a
// code back, exchange it for tokens, refresh them.
//
// Proton offers no OAuth to third parties, so the "login" this server asks for is
// Proton's own "sign in with another device" code (see Login): the person approves
// a code in a Proton app they are already signed in on, and the account password
// never reaches this server.
//
// This file is the contract between the pieces. The authorization server fills in
// New and the methods below; the Proton login lives in internal/protonlogin; the
// wiring lives in cmd/proton-mcp and internal/mcpserver. Change a signature here
// only together with everyone who calls it.
package mcpauth

import (
	"context"
	"net/http"
	"time"
)

// Scopes the server understands. A tool that changes anything needs ScopeWrite.
const (
	ScopeRead  = "proton:read"
	ScopeWrite = "proton:write"
)

// MCPPath is where the MCP endpoint is served, under the issuer.
const MCPPath = "/mcp"

// Login is the upstream sign-in a person goes through before a client is given a
// code. One Attempt is one person trying to sign in once.
//
// A successful login leaves a saved Proton session behind, identified by the
// Subject it returns; the MCP server later runs every tool call as that subject.
type Login interface {
	// Start begins a sign-in and returns what to show the person: a code to
	// approve in a Proton app that is already signed in.
	Start(ctx context.Context) (Attempt, error)
	// Check says where an Attempt stands. It never blocks.
	Check(ctx context.Context, attemptID string) (Status, error)
	// Forget destroys everything held for a Subject, including the session at
	// Proton. It is idempotent: forgetting a subject twice is not an error.
	Forget(ctx context.Context, subject string) error
}

// Attempt is a sign-in in progress.
type Attempt struct {
	ID        string
	Code      string // the text to put in front of the person (also drawn as a QR code)
	ExpiresAt time.Time
}

// State is how far a sign-in has got.
type State int

const (
	Waiting  State = iota // nobody has approved the code yet
	Approved              // approved; Status.Subject names the saved session
	Failed                // expired, refused or broken; Status.Message says why
)

// Status is the answer to Login.Check.
type Status struct {
	State   State
	Subject string // set when Approved
	Message string // set when Failed; safe to show the person
}

// Config is what New needs.
type Config struct {
	// Issuer is the public base URL, with no trailing slash, e.g.
	// https://proton-mcp.yellowumbrella.dev. The MCP resource is Issuer+MCPPath.
	Issuer string
	// StatePath is where clients, grants and tokens are kept.
	StatePath string
	// Key is 32 bytes that seal anything sensitive at rest.
	Key   []byte
	Login Login
	// Scopes the server offers; defaults to ScopeRead and ScopeWrite.
	Scopes []string
	// AllowRedirect decides whether a client may register a redirect URI. The
	// default accepts https URIs and http only on a loopback host.
	AllowRedirect func(uri string) bool
	// Now is the clock, replaceable in tests.
	Now func() time.Time
	// Lifetimes; zero values mean: code 60s, access 1h, refresh 30 days.
	CodeTTL, AccessTTL, RefreshTTL time.Duration
	// RateLimit bounds requests per client IP to /register, /authorize, /token
	// and /revoke; the zero value means 20 a minute with bursts of 10.
	RateLimit RateLimit
	// ClientIP names the client of a request for the rate limit. The default is
	// the host of RemoteAddr; behind a reverse proxy, set it to read the
	// header the proxy writes (and only trust that header from the proxy).
	ClientIP func(*http.Request) string
}

// The authorization server itself (Server, New, Handler, Verifier,
// ResourceMetadataURL, Close) is in server.go and the files next to it.
