// Command proton-mcp serves the Proton CLI's commands as MCP tools.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/roman-16/proton-cli/internal/mcpauth"
	"github.com/roman-16/proton-cli/internal/mcpserver"
	"github.com/roman-16/proton-cli/internal/protonlogin"
)

var version = "dev"

func main() {
	if err := run(flag.CommandLine, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// run is main without log.Fatal: Fatal exits without running deferred calls, and
// the deferred Close of the login and the authorization server is what revokes
// the sign-ins nobody finished.
func run(fs *flag.FlagSet, args []string) error {
	var (
		profile   = fs.String("profile", "default", "saved session the tools act as (static-token and stdio modes)")
		stdio     = fs.Bool("stdio", false, "serve one client over stdin/stdout instead of HTTP")
		addr      = fs.String("addr", "127.0.0.1:8080", "HTTP listen address")
		token     = fs.String("token-file", "", "file holding the bearer token HTTP clients must present")
		oauth     = fs.Bool("oauth", false, "serve many people behind OAuth: each signs in once and their tool calls act as their own Proton session")
		issuer    = fs.String("issuer", "", "with -oauth: the public base URL, e.g. https://proton-mcp.example.com")
		state     = fs.String("state", "", "with -oauth: file where clients, grants and tokens are kept")
		keyFile   = fs.String("key-file", "", "with -oauth: file holding the key that seals the state (32+ bytes, or base64 of 32 bytes)")
		enableAPI = fs.Bool("enable-api", false, "expose the raw `api` command")
		confirm   = fs.String("confirm", "", "confirmation policy handed to every command")
		zone      = fs.String("zone", "UTC", "IANA time zone commands work in")
		perMinute = fs.Float64("max-calls-per-minute", 30, "average tool calls a minute (0 for no limit)")
		burst     = fs.Int("burst", 5, "tool calls allowed back to back")
		behind    = fs.Bool("behind-proxy", false, "with -oauth: take the client address for rate limits from the last X-Forwarded-For entry (only when every request arrives through that proxy)")
		list      = fs.Bool("list", false, "print the tools and exit")
		keepAnon  = fs.Bool("keep-anonymous-session", false, "with -oauth: do not revoke the anonymous Proton session a sign-in was opened under once it is approved. An escape hatch, for if approved sign-ins stop working right after they succeed")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts := mcpserver.Options{EnableAPI: *enableAPI}
	if *list {
		tools, left, err := mcpserver.Catalog(opts)
		if err != nil {
			return err
		}
		for _, t := range tools {
			fmt.Println(t.Name)
		}
		fmt.Fprintf(os.Stderr, "%d tools, %d commands left out\n", len(tools), len(left))
		return nil
	}

	if *oauth {
		switch {
		case *token != "":
			return errors.New("-oauth and -token-file cannot be combined: a shared token would bypass the per-person sign-in")
		case *stdio:
			return errors.New("-oauth needs HTTP: it cannot be combined with -stdio")
		case *state == "" || *keyFile == "":
			return errors.New("-oauth needs -issuer, -state and -key-file")
		}
	}
	// Commands read the process's local time zone, which is global to the process,
	// so it is settled once, here, before anything is served; every call then
	// names this same zone and writes nothing.
	loc, err := time.LoadLocation(*zone)
	if err != nil {
		return fmt.Errorf("-zone: %v", err)
	}
	time.Local = loc

	defaults := mcpserver.Runner{Profile: *profile, Confirm: *confirm, Zone: *zone}
	cfg := mcpserver.Config{
		Version: version,
		Options: opts,
		Runner:  func(context.Context) (mcpserver.Runner, error) { return defaults, nil },
		Limiter: mcpserver.NewLimiter(*perMinute, *burst),
	}
	var authSrv *mcpauth.Server
	var clientIP func(*http.Request) string
	if *behind {
		clientIP = forwardedClientIP
	}
	if *oauth {
		base, err := parseIssuer(*issuer)
		if err != nil {
			return err
		}
		*issuer = base
		key, err := loadKey(*keyFile)
		if err != nil {
			return err
		}
		login, err := newLogin(loginConfig(*keepAnon, os.Stderr))
		if err != nil {
			return err
		}
		if c, ok := login.(io.Closer); ok {
			// Revokes the sign-ins nobody finished, so shutdown leaves no session at Proton.
			defer func() { _ = c.Close() }()
		}
		authSrv, err = mcpauth.New(mcpauth.Config{Issuer: base, StatePath: *state, Key: key, Login: login, ClientIP: clientIP})
		if err != nil {
			return err
		}
		defer func() { _ = authSrv.Close() }()
		cfg.Runner = mcpserver.RunnerFromToken(defaults)
		cfg.Allow = mcpserver.AllowByScope()
	}
	server, tools, err := mcpserver.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *stdio {
		return server.Run(ctx, &mcp.StdioTransport{})
	}

	var mux *http.ServeMux
	switch {
	case *oauth:
		mux = oauthMux(authSrv, streamable(server))
		log.Printf("proton-mcp %s: %d tools, OAuth mode, issuer %s, listening on %s", version, len(tools), *issuer, *addr)
	case *token != "":
		secret, err := os.ReadFile(*token)
		if err != nil {
			return err
		}
		if err := checkToken(string(secret)); err != nil {
			return fmt.Errorf("--token-file: %v", err)
		}
		mux = staticMux(string(secret), streamable(server))
		log.Printf("proton-mcp %s: %d tools on http://%s", version, len(tools), *addr)
	default:
		return errors.New("HTTP needs --token-file or --oauth: refusing to serve a Proton account without authentication")
	}
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// loginConfig is the configuration of the Proton login. Its operator warnings (a
// session Proton ended together with its parent, a revoke that keeps failing) are
// the signal for -keep-anonymous-session, so they must reach the log: the login's
// own default is to discard everything. Info and up never carry tokens.
func loginConfig(keepAnonymous bool, w io.Writer) protonlogin.Config {
	return protonlogin.Config{
		KeepAnonymousSession: keepAnonymous,
		Logger:               slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
}

// minTokenBytes is the shortest bearer token the server will accept. A file that
// is empty, or only whitespace, would otherwise become the header "Bearer " and
// let in any client that sends it.
const minTokenBytes = 16

func checkToken(secret string) error {
	if n := len(trim(secret)); n < minTokenBytes {
		return fmt.Errorf("the token is %d bytes after trimming, want at least %d (try: openssl rand -base64 32)", n, minTokenBytes)
	}
	return nil
}

func bearer(secret string, next http.Handler) http.Handler {
	token := trim(secret)
	want := "Bearer " + token
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An empty secret would make the wanted header "Bearer " and let in every
		// client that sends it, so with no secret nothing gets in.
		got := r.Header.Get("Authorization")
		if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
