package mcpauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// RateLimit bounds how often one client IP may call /register, /authorize and
// /token; each endpoint has its own bucket per IP.
type RateLimit struct {
	// PerMinute is the average number of requests a minute. Zero means the
	// default (20); a negative value turns the limit off.
	PerMinute float64
	// Burst is how many may come back to back. Zero means the default (10).
	Burst int
}

// Lifetimes the contract does not let a caller change.
const (
	// refreshGrace is how long a refresh token that has just been rotated may
	// still be used, once, so that two refreshes racing each other do not cost
	// the client its grant.
	refreshGrace = 10 * time.Second
	// loginTTL bounds a sign-in from /authorize to consent.
	loginTTL = 15 * time.Minute
	// maxPending caps the sign-ins in flight, all clients together.
	maxPending = 1000
	// purgeEvery is how often expired state is swept, lazily.
	purgeEvery = time.Minute
	// forgetRetry is how long to wait after a failed Login.Forget.
	forgetRetry = time.Minute
	// supersededKeep is how long a rotated refresh token is remembered, so
	// that its reuse is recognised and ends the grant.
	supersededKeep = 7 * 24 * time.Hour
	// unusedClientTTL is how long a registered client that never got a grant
	// is kept.
	unusedClientTTL = 24 * time.Hour
)

const wellKnown = "/.well-known"

// Server is the authorization server.
type Server struct {
	cfg      Config
	resource string // Issuer+MCPPath
	prefix   string // the path of the issuer, "" when it has none
	origin   string // scheme://host[:port] of the issuer
	store    *store
	limits   *limiter
	mux      *http.ServeMux

	mu        sync.Mutex
	st        *state
	pending   map[string]*pending // sign-ins in flight, by id; not persisted
	lastPurge time.Time

	drainMu sync.Mutex     // one round of Login.Forget calls at a time
	startup sync.WaitGroup // the drain New starts; Close waits for it
	retryAt time.Time      // after a failed Login.Forget, when to try again; guarded by mu
}

// New builds the server.
func New(cfg Config) (*Server, error) {
	issuer, err := url.Parse(cfg.Issuer)
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("mcpauth: Issuer is required")
	case err != nil:
		return nil, fmt.Errorf("mcpauth: Issuer: %w", err)
	case issuer.Scheme != "https" && !(issuer.Scheme == "http" && isLoopback(issuer.Hostname())):
		return nil, errors.New("mcpauth: Issuer must be https (http only on a loopback host)")
	case issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.ForceQuery:
		return nil, errors.New("mcpauth: Issuer must be a plain base URL")
	case strings.HasSuffix(cfg.Issuer, "/"):
		return nil, errors.New("mcpauth: Issuer must not end with a slash")
	}
	if cfg.StatePath == "" {
		return nil, errors.New("mcpauth: StatePath is required")
	}
	if cfg.Login == nil {
		return nil, errors.New("mcpauth: Login is required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{ScopeRead, ScopeWrite}
	}
	for _, sc := range cfg.Scopes {
		if sc == "" || strings.ContainsAny(sc, " \t\r\n\"\\") {
			return nil, fmt.Errorf("mcpauth: scope %q is not a valid scope token", sc)
		}
	}
	cfg.Scopes = slices.Clone(cfg.Scopes)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = 60 * time.Second
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = time.Hour
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 30 * 24 * time.Hour
	}
	if cfg.ClientIP == nil {
		cfg.ClientIP = remoteIP
	}
	st, err := newStore(cfg.StatePath, cfg.Key)
	if err != nil {
		return nil, err
	}
	loaded, err := st.load()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		resource: cfg.Issuer + MCPPath,
		prefix:   strings.TrimSuffix(issuer.EscapedPath(), "/"),
		origin:   issuer.Scheme + "://" + issuer.Host,
		store:    st,
		limits:   newLimiter(cfg.RateLimit),
		st:       loaded,
		pending:  map[string]*pending{},
	}
	s.mux = s.routes()
	if len(loaded.Forget) > 0 {
		// A previous run stopped before forgetting these; do it now rather
		// than at the first request. In the background, since Forget may
		// talk to Proton; Close waits for it.
		s.startup.Go(s.drainForget)
	}
	return s, nil
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	seen := map[string]bool{}
	handle := func(pattern string, h http.HandlerFunc) {
		if !seen[pattern] {
			seen[pattern] = true
			mux.HandleFunc(pattern, h)
		}
	}
	p := s.prefix
	// RFC 9728: the document of a resource is found by inserting the
	// well-known path before the resource's path.
	handle("GET "+wellKnown+"/oauth-protected-resource"+p+MCPPath, s.protectedResource)
	handle("GET "+wellKnown+"/oauth-protected-resource"+p, s.protectedResource)
	// RFC 8414 inserts the well-known path before the issuer's path; clients
	// also try the OpenID form and the form appended to the issuer.
	for _, doc := range []string{"/oauth-authorization-server", "/openid-configuration"} {
		handle("GET "+wellKnown+doc+p, s.serverMetadata)
		handle("GET "+p+wellKnown+doc, s.serverMetadata)
	}
	handle("POST "+p+"/register", s.limited("register", s.register))
	handle("GET "+p+"/authorize", s.limited("authorize", s.authorize))
	handle("GET "+p+"/login", s.loginPage)
	handle("GET "+p+"/login/status", s.loginStatus)
	handle("POST "+p+"/login/consent", s.consent)
	handle("POST "+p+"/token", s.limited("token", s.token))
	handle("POST "+p+"/revoke", s.limited("revoke", s.revoke))
	return mux
}

// Handler serves everything the authorization server owns: the well-known
// metadata documents, /register, /authorize, the login pages, /token and
// /revoke. It does not serve MCPPath.
func (s *Server) Handler() http.Handler { return s.mux }

// ResourceMetadataURL is the URL of the protected resource metadata document,
// for the WWW-Authenticate header of a 401.
func (s *Server) ResourceMetadataURL() string {
	return s.origin + wellKnown + "/oauth-protected-resource" + s.prefix + MCPPath
}

// Close releases the state. Everything is already on disk; what is left is to
// try once more to forget subjects whose last grant is gone.
func (s *Server) Close() error {
	s.startup.Wait()
	s.drainForget()
	return nil
}

func (s *Server) endpoint(path string) string { return s.cfg.Issuer + path }

func (s *Server) now() time.Time { return s.cfg.Now() }

// commit saves the state; the caller holds s.mu. A failed commit leaves the
// change in memory, where the next successful commit writes it too: use it as
// is only for changes that take something away (a revocation, a spent code),
// which must hold whether or not they reached the disk.
func (s *Server) commit() error { return s.store.save(s.st) }

// change applies fn to the state and commits it, all or nothing: if the commit
// fails, the state is put back exactly as it was before fn. Use it for changes
// that hand something to a client (a grant, tokens, a code, a registration), so
// that a failed write never leaves behind a change the client was not told
// about. The caller holds s.mu.
func (s *Server) change(fn func()) error {
	before, retryAt := s.st.clone(), s.retryAt
	fn()
	if err := s.commit(); err != nil {
		s.st, s.retryAt = before, retryAt
		return err
	}
	return nil
}

// maybePurge sweeps expired state at most once every purgeEvery; the caller
// holds s.mu. It reports whether anything changed.
func (s *Server) maybePurge(now time.Time) bool {
	if now.Sub(s.lastPurge) < purgeEvery {
		return false
	}
	s.lastPurge = now
	return s.purge(now)
}

func (s *Server) purge(now time.Time) bool {
	changed := false
	for id, p := range s.pending {
		if now.After(p.expires) {
			delete(s.pending, id)
		}
	}
	for id, g := range s.st.Grants {
		if now.After(g.Expires) {
			s.revokeGrant(id)
			changed = true
		}
	}
	for h, c := range s.st.Codes {
		// A used code is kept while its grant lives, so a replay can still
		// revoke that grant.
		if (!c.Used && now.After(c.Expires)) || (c.Used && s.st.Grants[c.GrantID] == nil) {
			delete(s.st.Codes, h)
			changed = true
		}
	}
	for h, a := range s.st.Access {
		if now.After(a.Expires) {
			delete(s.st.Access, h)
			changed = true
		}
	}
	for h, rt := range s.st.Refresh {
		if now.After(rt.Expires) {
			delete(s.st.Refresh, h)
			changed = true
		}
	}
	for subject, deadline := range s.st.Unbound {
		if now.After(deadline) {
			delete(s.st.Unbound, subject)
			s.queueForget(subject)
			changed = true
		}
	}
	for id, c := range s.st.Clients {
		if s.clientHasGrant(id) {
			continue
		}
		idle := now.Sub(c.LastUsed)
		if idle > s.cfg.RefreshTTL || (c.LastUsed.Equal(c.Created) && idle > unusedClientTTL) {
			delete(s.st.Clients, id)
			changed = true
		}
	}
	return changed
}

func (s *Server) clientHasGrant(clientID string) bool {
	for _, g := range s.st.Grants {
		if g.ClientID == clientID {
			return true
		}
	}
	return false
}

// revokeGrant ends a grant and every token it produced; the caller holds s.mu
// and commits. If it was the subject's last grant, the subject is queued to be
// forgotten.
func (s *Server) revokeGrant(id string) {
	g := s.st.Grants[id]
	if g == nil {
		return
	}
	delete(s.st.Grants, id)
	for h, a := range s.st.Access {
		if a.GrantID == id {
			delete(s.st.Access, h)
		}
	}
	for h, rt := range s.st.Refresh {
		if rt.GrantID == id {
			delete(s.st.Refresh, h)
		}
	}
	s.queueForget(g.Subject)
}

// queueForget asks for subject to be forgotten once nothing holds it any more;
// the caller holds s.mu.
func (s *Server) queueForget(subject string) {
	if s.subjectInUse(subject) || slices.Contains(s.st.Forget, subject) {
		return
	}
	s.st.Forget = append(s.st.Forget, subject)
	s.retryAt = time.Time{} // something new: try now
}

// subjectInUse reports whether a grant or an unconsented sign-in still needs
// the subject's session; the caller holds s.mu.
func (s *Server) subjectInUse(subject string) bool {
	if _, ok := s.st.Unbound[subject]; ok {
		return true
	}
	for _, g := range s.st.Grants {
		if g.Subject == subject {
			return true
		}
	}
	return false
}

// drainForget calls Login.Forget for every queued subject that is still unused.
// It runs outside s.mu, since Forget may talk to Proton. A subject leaves the
// durable queue only once its Forget has succeeded (or it is in use again), so
// a crash at any point leaves it queued for the next start; Forget is
// idempotent, so trying it again is safe. A failure keeps the subject queued
// for the next round.
func (s *Server) drainForget() {
	s.drainMu.Lock()
	defer s.drainMu.Unlock()
	s.mu.Lock()
	var todo []string
	for _, subject := range s.st.Forget {
		if !s.subjectInUse(subject) {
			todo = append(todo, subject)
		}
	}
	queued := len(s.st.Forget) > 0
	s.mu.Unlock()
	if !queued {
		return
	}

	forgotten := map[string]bool{}
	for _, subject := range todo {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := s.cfg.Login.Forget(ctx, subject); err == nil {
			forgotten[subject] = true
		}
		cancel()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.st.Forget)
	// Subjects queued while Forget ran were not tried and stay; one in use
	// again is queued anew when it is let go.
	s.st.Forget = slices.DeleteFunc(s.st.Forget, func(subject string) bool {
		return forgotten[subject] || s.subjectInUse(subject)
	})
	untried := slices.ContainsFunc(s.st.Forget, func(subject string) bool {
		return !slices.Contains(todo, subject)
	})
	if len(forgotten) < len(todo) && !untried {
		s.retryAt = s.now().Add(forgetRetry)
	}
	if len(s.st.Forget) != n {
		// If this fails, the disk still lists subjects already forgotten;
		// they are forgotten again after a restart, which is harmless.
		_ = s.commit()
	}
}

// drainIfQueued runs drainForget when some subject is waiting to be forgotten,
// unless the last attempt failed less than forgetRetry ago.
func (s *Server) drainIfQueued() {
	s.mu.Lock()
	queued := len(s.st.Forget) > 0 && !s.now().Before(s.retryAt)
	s.mu.Unlock()
	if queued {
		s.drainForget()
	}
}

// remoteIP is the default Config.ClientIP: the host part of RemoteAddr.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// parseScope splits a scope parameter, dropping repeats.
func parseScope(s string) []string {
	var out []string
	for _, f := range strings.Fields(s) {
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

func subset(sub, of []string) bool {
	for _, x := range sub {
		if !slices.Contains(of, x) {
			return false
		}
	}
	return true
}
