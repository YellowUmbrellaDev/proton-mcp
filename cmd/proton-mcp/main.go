// Command proton-mcp serves the Proton CLI's commands as MCP tools.
package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/roman-16/proton-cli/internal/mcpserver"
)

var version = "dev"

func main() {
	var (
		profile   = flag.String("profile", "default", "saved session the tools act as")
		stdio     = flag.Bool("stdio", false, "serve one client over stdin/stdout instead of HTTP")
		addr      = flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
		token     = flag.String("token-file", "", "file holding the bearer token HTTP clients must present")
		enableAPI = flag.Bool("enable-api", false, "expose the raw `api` command")
		confirm   = flag.String("confirm", "", "confirmation policy handed to every command")
		zone      = flag.String("zone", "UTC", "IANA time zone commands work in")
		perMinute = flag.Float64("max-calls-per-minute", 30, "average tool calls a minute (0 for no limit)")
		burst     = flag.Int("burst", 5, "tool calls allowed back to back")
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

	// Commands read the process's local time zone, which is global to the process
	// and read without a lock. Set it once, here, before anything is served; every
	// call then names this same zone and writes nothing.
	loc, err := time.LoadLocation(*zone)
	if err != nil {
		log.Fatalf("-zone: %v", err)
	}
	time.Local = loc

	runner := mcpserver.Runner{Profile: *profile, Confirm: *confirm, Zone: *zone}
	server, tools, err := mcpserver.New(mcpserver.Config{
		Version: version,
		Options: opts,
		Runner:  func(context.Context) (mcpserver.Runner, error) { return runner, nil },
		Limiter: mcpserver.NewLimiter(*perMinute, *burst),
	})
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
	if *token == "" {
		log.Fatal("HTTP needs --token-file: refusing to serve a Proton account without authentication")
	}
	secret, err := os.ReadFile(*token)
	if err != nil {
		log.Fatal(err)
	}
	if err := checkToken(string(secret)); err != nil {
		log.Fatalf("--token-file: %v", err)
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	log.Printf("proton-mcp %s: %d tools on http://%s", version, len(tools), *addr)
	srv := &http.Server{Addr: *addr, Handler: bearer(string(secret), handler)}
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
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
