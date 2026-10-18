package mcpauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// fakeLogin approves an attempt after approveAfter checks, or fails it.
type fakeLogin struct {
	mu           sync.Mutex
	approveAfter int
	fail         string // when set, attempts fail with this message instead
	subject      string
	checks       map[string]int
	started      int
	forgotten    []string                   // subjects whose Forget succeeded
	attempts     []string                   // every Forget call
	onForget     func(subject string) error // when set, runs first; an error fails the call
}

func newFakeLogin() *fakeLogin {
	return &fakeLogin{approveAfter: 2, subject: "alice@proton", checks: map[string]int{}}
}

func (f *fakeLogin) Start(context.Context) (Attempt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started++
	return Attempt{ID: fmt.Sprintf("attempt-%d", f.started), Code: "QX7-4KPM", ExpiresAt: time.Now().Add(10 * time.Minute)}, nil
}

func (f *fakeLogin) Check(_ context.Context, id string) (Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks[id]++
	if f.checks[id] < f.approveAfter {
		return Status{State: Waiting}, nil
	}
	if f.fail != "" {
		return Status{State: Failed, Message: f.fail}, nil
	}
	return Status{State: Approved, Subject: f.subject}, nil
}

// Forget records the subject as forgotten unless onForget, when set, fails it.
// Every call, successful or not, is counted in attempts.
func (f *fakeLogin) Forget(_ context.Context, subject string) error {
	f.mu.Lock()
	f.attempts = append(f.attempts, subject)
	hook := f.onForget
	f.mu.Unlock()
	if hook != nil {
		if err := hook(subject); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forgotten = append(f.forgotten, subject)
	return nil
}

func (f *fakeLogin) setOnForget(hook func(subject string) error) {
	f.mu.Lock()
	f.onForget = hook
	f.mu.Unlock()
}

func (f *fakeLogin) forgetAttempts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.attempts...)
}

func (f *fakeLogin) forgets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.forgotten...)
}

func (f *fakeLogin) setSubject(s string) {
	f.mu.Lock()
	f.subject = s
	f.mu.Unlock()
}

// clock is a settable time source. It starts at the real time, because the
// SDK's bearer middleware checks expiry against time.Now.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// harness is the authorization server and a stub MCP endpoint behind one TLS
// test server, and a browser-like client that does not follow redirects.
type harness struct {
	t      *testing.T
	srv    *httptest.Server
	s      *Server
	login  *fakeLogin
	clock  *clock
	http   *http.Client // a browser: cookie jar, redirects not followed
	issuer string
	key    []byte
	state  string
}

type harnessOpt func(*Config)

func newHarness(t *testing.T, opts ...harnessOpt) *harness {
	return newHarnessAt(t, "", opts...)
}

// newHarnessAt serves the issuer under path prefix (e.g. "/proton").
func newHarnessAt(t *testing.T, prefix string, opts ...harnessOpt) *harness {
	t.Helper()
	h := &harness{t: t, login: newFakeLogin(), clock: &clock{t: time.Now()}}
	var handler http.Handler
	h.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	h.srv.StartTLS()
	t.Cleanup(h.srv.Close)
	h.issuer = h.srv.URL + prefix
	h.key = make([]byte, 32)
	_, _ = rand.Read(h.key)
	h.state = filepath.Join(t.TempDir(), "auth.json")
	cfg := Config{
		Issuer:    h.issuer,
		StatePath: h.state,
		Key:       h.key,
		Login:     h.login,
		Now:       h.clock.Now,
		RateLimit: RateLimit{PerMinute: -1},
	}
	for _, o := range opts {
		o(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	h.s = s

	mux := http.NewServeMux()
	mcp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ti := auth.TokenInfoFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"user": ti.UserID, "scopes": ti.Scopes, "grant": ti.Extra["grant"]})
	})
	mux.Handle(prefix+MCPPath, auth.RequireBearerToken(s.Verifier(), &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: s.ResourceMetadataURL(),
	})(mcp))
	mux.Handle("/", s.Handler())
	handler = mux

	jar, _ := cookiejar.New(nil)
	h.http = h.srv.Client()
	h.http.Jar = jar
	h.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return h
}

// newBrowser is another browser (its own cookies) talking to the same server.
func (h *harness) newBrowser() *http.Client {
	jar, _ := cookiejar.New(nil)
	c := *h.http
	c.Jar = jar
	return &c
}

type response struct {
	*http.Response
	body string
}

func (r response) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.body), &m); err != nil {
		t.Fatalf("not JSON (%d): %q", r.StatusCode, r.body)
	}
	return m
}

func (h *harness) do(c *http.Client, req *http.Request) response {
	h.t.Helper()
	if c == nil {
		c = h.http
	}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{resp, string(b)}
}

func (h *harness) get(rawURL string) response {
	h.t.Helper()
	req, _ := http.NewRequest("GET", rawURL, nil)
	return h.do(nil, req)
}

func (h *harness) postForm(c *http.Client, rawURL string, v url.Values) response {
	h.t.Helper()
	req, _ := http.NewRequest("POST", rawURL, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return h.do(c, req)
}

func (h *harness) postJSON(rawURL string, v any) response {
	h.t.Helper()
	b, _ := json.Marshal(v)
	req, _ := http.NewRequest("POST", rawURL, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	return h.do(nil, req)
}

func (h *harness) mcp(token string) response {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.issuer+MCPPath, strings.NewReader("{}"))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return h.do(nil, req)
}

const executorRedirect = "https://executor.example/api/oauth/callback"

// register does Executor's registration and returns the client id.
func (h *harness) register(redirect string, scope string) string {
	h.t.Helper()
	body := map[string]any{
		"client_name":                "Executor",
		"redirect_uris":              []string{redirect},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"application_type":           "web",
	}
	if scope != "" {
		body["scope"] = scope
	}
	r := h.postJSON(h.issuer+"/register", body)
	if r.StatusCode != http.StatusCreated {
		h.t.Fatalf("register: %d %s", r.StatusCode, r.body)
	}
	return r.json(h.t)["client_id"].(string)
}

type pkce struct{ verifier, challenge string }

func newPKCE() pkce {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	v := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(v))
	return pkce{v, base64.RawURLEncoding.EncodeToString(sum[:])}
}

// authorizeURL is an authorization request as Executor builds it.
func (h *harness) authorizeURL(clientID, redirect string, p pkce, scope, state string) string {
	v := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"code_challenge":        {p.challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"resource":              {h.issuer + MCPPath},
	}
	if scope != "" {
		v.Set("scope", scope)
	}
	return h.issuer + "/authorize?" + v.Encode()
}

var (
	reHidden = regexp.MustCompile(`name="(id|csrf)" value="([^"]+)"`)
	reScope  = regexp.MustCompile(`name="scope" value="([^"]+)"( checked)?`)
)

// consentForm is what the consent page carries.
type consentForm struct {
	id, csrf string
	page     string
	offered  map[string]bool // scope -> checked (hidden inputs count as checked)
}

// signIn follows /authorize through the waiting page and the polls up to the
// consent page.
func (h *harness) signIn(authorizeURL string) consentForm {
	h.t.Helper()
	r := h.get(authorizeURL)
	if r.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("authorize: %d %s", r.StatusCode, r.body)
	}
	loginURL := r.Header.Get("Location")
	if !strings.HasPrefix(loginURL, h.issuer+"/login?id=") {
		h.t.Fatalf("authorize went to %q", loginURL)
	}
	id := strings.TrimPrefix(loginURL, h.issuer+"/login?id=")
	for range 10 {
		page := h.get(loginURL)
		if page.StatusCode != http.StatusOK {
			h.t.Fatalf("login page: %d %s", page.StatusCode, page.body)
		}
		if strings.Contains(page.body, `action="`+h.issuer+`/login/consent"`) {
			f := consentForm{page: page.body, offered: map[string]bool{}}
			for _, m := range reHidden.FindAllStringSubmatch(page.body, -1) {
				if m[1] == "id" {
					f.id = m[2]
				} else {
					f.csrf = m[2]
				}
			}
			for _, m := range reScope.FindAllStringSubmatch(page.body, -1) {
				f.offered[m[1]] = m[2] != "" || !strings.Contains(page.body, `type="checkbox" name="scope" value="`+m[1]+`"`)
			}
			if f.id != id || f.csrf == "" {
				h.t.Fatalf("consent form: id %q csrf %q", f.id, f.csrf)
			}
			return f
		}
		// The page polls; a poll moves the sign-in on once the clock allows.
		h.clock.Advance(2 * time.Second)
		st := h.get(h.issuer + "/login/status?id=" + url.QueryEscape(id))
		if st.StatusCode != http.StatusOK {
			h.t.Fatalf("status: %d %s", st.StatusCode, st.body)
		}
		h.clock.Advance(2 * time.Second)
	}
	h.t.Fatal("never reached the consent page")
	return consentForm{}
}

// consent answers the form and returns the redirect back to the client.
func (h *harness) consent(f consentForm, allow bool, scopes ...string) *url.URL {
	h.t.Helper()
	v := url.Values{"id": {f.id}, "csrf": {f.csrf}, "action": {"deny"}}
	if allow {
		v.Set("action", "allow")
	}
	v["scope"] = scopes
	r := h.postForm(nil, h.issuer+"/login/consent", v)
	if r.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("consent: %d %s", r.StatusCode, r.body)
	}
	u, err := url.Parse(r.Header.Get("Location"))
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

// grantFlow runs the whole flow and returns the code's redirect parameters.
func (h *harness) code(clientID, redirect string, p pkce, scope string, consentScopes ...string) string {
	h.t.Helper()
	f := h.signIn(h.authorizeURL(clientID, redirect, p, scope, "st-123"))
	u := h.consent(f, true, consentScopes...)
	q := u.Query()
	if q.Get("state") != "st-123" || q.Get("iss") != h.issuer || q.Get("code") == "" {
		h.t.Fatalf("redirect back: %s", u)
	}
	return q.Get("code")
}

func (h *harness) exchange(clientID, redirect, code, verifier string) response {
	h.t.Helper()
	return h.postForm(nil, h.issuer+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirect},
		"code":          {code},
		"code_verifier": {verifier},
		"resource":      {h.issuer + MCPPath},
	})
}

func (h *harness) refresh(clientID, token string, extra ...string) response {
	h.t.Helper()
	v := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {token},
		"resource":      {h.issuer + MCPPath},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return h.postForm(nil, h.issuer+"/token", v)
}

type tokens struct{ access, refresh, scope string }

func (h *harness) tokensOf(r response) tokens {
	h.t.Helper()
	if r.StatusCode != http.StatusOK {
		h.t.Fatalf("token: %d %s", r.StatusCode, r.body)
	}
	m := r.json(h.t)
	return tokens{m["access_token"].(string), m["refresh_token"].(string), m["scope"].(string)}
}

// connect runs the flow end to end for a fresh client and returns its tokens.
func (h *harness) connect(scope string, consentScopes ...string) (clientID string, tok tokens) {
	h.t.Helper()
	clientID = h.register(executorRedirect, "")
	p := newPKCE()
	code := h.code(clientID, executorRedirect, p, scope, consentScopes...)
	return clientID, h.tokensOf(h.exchange(clientID, executorRedirect, code, p.verifier))
}

func wantOAuthError(t *testing.T, r response, status int, code string) {
	t.Helper()
	if r.StatusCode != status {
		t.Fatalf("status %d, want %d: %s", r.StatusCode, status, r.body)
	}
	if got := r.json(t)["error"]; got != code {
		t.Fatalf("error %v, want %s", got, code)
	}
}
