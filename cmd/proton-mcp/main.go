// Command proton-mcp serves the Proton CLI's commands as MCP tools.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/roman-16/proton-cli/internal/mcpauth"
	"github.com/roman-16/proton-cli/internal/mcpserver"
)

var version = "dev"

func main() {
	var (
		profile   = flag.String("profile", "default", "saved session the tools act as (static-token and stdio modes)")
		stdio     = flag.Bool("stdio", false, "serve one client over stdin/stdout instead of HTTP")
		addr      = flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
		token     = flag.String("token-file", "", "file holding the bearer token HTTP clients must present")
		oauth     = flag.Bool("oauth", false, "serve many people behind OAuth: each signs in once and their tool calls act as their own Proton session")
		issuer    = flag.String("issuer", "", "with -oauth: the public base URL, e.g. https://proton-mcp.example.com")
		state     = flag.String("state", "", "with -oauth: file where clients, grants and tokens are kept")
		keyFile   = flag.String("key-file", "", "with -oauth: file holding the key that seals the state (32+ bytes, or base64 of 32 bytes)")
		enableAPI = flag.Bool("enable-api", false, "expose the raw `api` command")
		confirm   = flag.String("confirm", "", "confirmation policy handed to every command")
		zone      = flag.String("zone", "UTC", "IANA time zone commands work in")
		perMinute = flag.Float64("max-calls-per-minute", 30, "average tool calls a minute (0 for no limit)")
		burst     = flag.Int("burst", 5, "tool calls allowed back to back")
		behind    = flag.Bool("behind-proxy", false, "with -oauth: take the client address for rate limits from the last X-Forwarded-For entry (only when every request arrives through that proxy)")
		list      = flag.Bool("list", false, "print the tools and exit")
	)
	flag.Parse()

	opts := mcpserver.Options{EnableAPI: *enableAPI}
	if *list {
		tools, left, err := mcpserver.Catalog(opts)
		if err != nil {
			log.Fatal(err)
		}
		for _, t := range tools {
			fmt.Println(t.Name)
		}
		fmt.Fprintf(os.Stderr, "%d tools, %d commands left out\n", len(tools), len(left))
		return
	}

	if *oauth {
		switch {
		case *token != "":
			log.Fatal("-oauth and -token-file cannot be combined: a shared token would bypass the per-person sign-in")
		case *stdio:
			log.Fatal("-oauth needs HTTP: it cannot be combined with -stdio")
		case *state == "" || *keyFile == "":
			log.Fatal("-oauth needs -issuer, -state and -key-file")
		}
	}
	// Commands read the process's local time zone, which is global to the process,
	// so it is settled once, here, before anything is served; every call then
	// names this same zone and writes nothing.
	loc, err := time.LoadLocation(*zone)
	if err != nil {
		log.Fatalf("-zone: %v", err)
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
			log.Fatal(err)
		}
		*issuer = base
		key, err := loadKey(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
		login, err := newLogin()
		if err != nil {
			log.Fatal(err)
		}
		authSrv, err = mcpauth.New(mcpauth.Config{Issuer: base, StatePath: *state, Key: key, Login: login, ClientIP: clientIP})
		if err != nil {
			log.Fatal(err)
		}
		defer func() { _ = authSrv.Close() }()
		cfg.Runner = mcpserver.RunnerFromToken(defaults)
		cfg.Allow = mcpserver.AllowByScope()
	}
	server, tools, err := mcpserver.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *stdio {
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
		return
	}

	var mux *http.ServeMux
	switch {
	case *oauth:
		mux = oauthMux(authSrv, streamable(server))
		log.Printf("proton-mcp %s: %d tools, OAuth mode, issuer %s, listening on %s", version, len(tools), *issuer, *addr)
	case *token != "":
		secret, err := os.ReadFile(*token)
		if err != nil {
			log.Fatal(err)
		}
		mux = staticMux(string(secret), streamable(server))
		log.Printf("proton-mcp %s: %d tools on http://%s", version, len(tools), *addr)
	default:
		log.Fatal("HTTP needs --token-file or --oauth: refusing to serve a Proton account without authentication")
	}
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func bearer(secret string, next http.Handler) http.Handler {
	want := "Bearer " + string(trim(secret))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
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
