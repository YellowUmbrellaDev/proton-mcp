package mcpauth

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fileMode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestRegisterRedirectRules(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.AllowRedirect = func(u string) bool { return !strings.Contains(u, "blocked.example") }
	})
	for _, tc := range []struct {
		uri string
		ok  bool
	}{
		{"https://executor.example/api/oauth/callback", true},
		{"http://localhost:4788/api/oauth/callback", true},
		{"http://127.0.0.1:4788/api/oauth/callback", true},
		{"http://[::1]:4788/api/oauth/callback", true},
		{"http://executor.example/api/oauth/callback", false},
		{"https://executor.example/cb#frag", false},
		{"https://executor.example/cb#", false},
		{"javascript:alert(1)", false},
		{"custom-app://cb", false},
		{"/relative/cb", false},
		{"https://user:pw@executor.example/cb", false},
		{"https://blocked.example/cb", false},
	} {
		r := h.postJSON(h.issuer+"/register", map[string]any{"redirect_uris": []string{tc.uri}})
		if got := r.StatusCode == http.StatusCreated; got != tc.ok {
			t.Errorf("%s: %d %s", tc.uri, r.StatusCode, r.body)
		}
		if !tc.ok && r.json(t)["error"] != "invalid_redirect_uri" {
			t.Errorf("%s: error %v", tc.uri, r.json(t)["error"])
		}
	}
	// Answers are always public clients, with refresh_token added.
	r := h.postJSON(h.issuer+"/register", map[string]any{
		"redirect_uris": []string{executorRedirect}, "grant_types": []string{"authorization_code"},
	})
	m := r.json(t)
	if m["token_endpoint_auth_method"] != "none" || !slices.Contains(m["grant_types"].([]any), any("refresh_token")) {
		t.Fatalf("registration answer %v", m)
	}
	// Not JSON.
	req, _ := http.NewRequest("POST", h.issuer+"/register", strings.NewReader("redirect_uris=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if r := h.do(nil, req); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("form body: %d", r.StatusCode)
	}
}

// Errors before the redirect URI is trusted are shown on the page; after, they
// go back to the client.
func TestAuthorizeValidation(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	p := newPKCE()
	base := func() url.Values {
		u, _ := url.Parse(h.authorizeURL(clientID, executorRedirect, p, "", "st"))
		return u.Query()
	}
	get := func(v url.Values) response { return h.get(h.issuer + "/authorize?" + v.Encode()) }

	// Shown on the page, never redirected.
	for name, mutate := range map[string]func(url.Values){
		"unknown client":           func(v url.Values) { v.Set("client_id", "nope") },
		"no client":                func(v url.Values) { v.Del("client_id") },
		"unregistered redirect":    func(v url.Values) { v.Set("redirect_uri", "https://evil.example/api/oauth/callback") },
		"redirect with extra path": func(v url.Values) { v.Set("redirect_uri", executorRedirect+"/x") },
		"redirect with query":      func(v url.Values) { v.Set("redirect_uri", executorRedirect+"?a=b") },
		"redirect with other case": func(v url.Values) { v.Set("redirect_uri", strings.ToUpper(executorRedirect)) },
		"redirect with a slash":    func(v url.Values) { v.Set("redirect_uri", executorRedirect+"/") },
		"no redirect":              func(v url.Values) { v.Del("redirect_uri") },
		"repeated redirect":        func(v url.Values) { v.Add("redirect_uri", "https://evil.example/") },
	} {
		v := base()
		mutate(v)
		r := get(v)
		if r.StatusCode != http.StatusBadRequest || r.Header.Get("Location") != "" {
			t.Errorf("%s: %d, Location %q", name, r.StatusCode, r.Header.Get("Location"))
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
			t.Errorf("%s: not an HTML page", name)
		}
	}

	// Redirected back with an error.
	for name, tc := range map[string]struct {
		mutate func(url.Values)
		err    string
	}{
		"plain PKCE":      {func(v url.Values) { v.Set("code_challenge_method", "plain") }, "invalid_request"},
		"no method":       {func(v url.Values) { v.Del("code_challenge_method") }, "invalid_request"},
		"no challenge":    {func(v url.Values) { v.Del("code_challenge") }, "invalid_request"},
		"short challenge": {func(v url.Values) { v.Set("code_challenge", "abc") }, "invalid_request"},
		"token response":  {func(v url.Values) { v.Set("response_type", "token") }, "unsupported_response_type"},
		"other resource":  {func(v url.Values) { v.Set("resource", "https://other.example/mcp") }, "invalid_target"},
		"unknown scope":   {func(v url.Values) { v.Set("scope", ScopeRead+" admin") }, "invalid_scope"},
	} {
		v := base()
		tc.mutate(v)
		r := get(v)
		u, _ := url.Parse(r.Header.Get("Location"))
		if r.StatusCode != http.StatusSeeOther || u == nil || !strings.HasPrefix(u.String(), executorRedirect+"?") {
			t.Errorf("%s: %d %q", name, r.StatusCode, r.Header.Get("Location"))
			continue
		}
		if u.Query().Get("error") != tc.err || u.Query().Get("state") != "st" || u.Query().Get("iss") != h.issuer {
			t.Errorf("%s: %s", name, u)
		}
	}
	if h.login.started != 0 {
		t.Fatalf("Login.Start called %d times for invalid requests", h.login.started)
	}
}

func TestPKCE(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	p := newPKCE()
	code := h.code(clientID, executorRedirect, p, "")
	wrong := newPKCE()
	wantOAuthError(t, h.exchange(clientID, executorRedirect, code, wrong.verifier), http.StatusBadRequest, "invalid_grant")
	// A failed proof spends the code.
	wantOAuthError(t, h.exchange(clientID, executorRedirect, code, p.verifier), http.StatusBadRequest, "invalid_grant")

	// The challenge itself is not a verifier (plain would accept it).
	p2 := newPKCE()
	code2 := h.code(clientID, executorRedirect, p2, "")
	wantOAuthError(t, h.exchange(clientID, executorRedirect, code2, p2.challenge), http.StatusBadRequest, "invalid_grant")

	// No verifier at all.
	p3 := newPKCE()
	code3 := h.code(clientID, executorRedirect, p3, "")
	wantOAuthError(t, h.exchange(clientID, executorRedirect, code3, ""), http.StatusBadRequest, "invalid_request")
}

func TestCodeRedirectAndResourceBinding(t *testing.T) {
	h := newHarness(t)
	other := "http://localhost:9999/api/oauth/callback"
	r := h.postJSON(h.issuer+"/register", map[string]any{"client_name": "x", "redirect_uris": []string{executorRedirect, other}})
	clientID := r.json(t)["client_id"].(string)

	p := newPKCE()
	code := h.code(clientID, executorRedirect, p, "")
	wantOAuthError(t, h.exchange(clientID, other, code, p.verifier), http.StatusBadRequest, "invalid_grant")

	p = newPKCE()
	code = h.code(clientID, executorRedirect, p, "")
	wantOAuthError(t, h.postForm(nil, h.issuer+"/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"code_verifier": {p.verifier}, "redirect_uri": {executorRedirect},
		"resource": {"https://other.example/mcp"},
	}), http.StatusBadRequest, "invalid_target")

	// A code issued to one client is no good to another.
	other2 := h.register(executorRedirect, "")
	p = newPKCE()
	code = h.code(clientID, executorRedirect, p, "")
	wantOAuthError(t, h.exchange(other2, executorRedirect, code, p.verifier), http.StatusBadRequest, "invalid_grant")

	// Unknown client.
	wantOAuthError(t, h.exchange("nobody", executorRedirect, "x", p.verifier), http.StatusUnauthorized, "invalid_client")
}

func TestCodeExpires(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	p := newPKCE()
	code := h.code(clientID, executorRedirect, p, "")
	h.clock.Advance(61 * time.Second)
	wantOAuthError(t, h.exchange(clientID, executorRedirect, code, p.verifier), http.StatusBadRequest, "invalid_grant")
}

// A code used twice revokes everything it produced.
func TestCodeReplayRevokes(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	p := newPKCE()
	code := h.code(clientID, executorRedirect, p, "")
	tok := h.tokensOf(h.exchange(clientID, executorRedirect, code, p.verifier))
	tok2 := h.tokensOf(h.refresh(clientID, tok.refresh))
	if h.mcp(tok2.access).StatusCode != http.StatusOK {
		t.Fatal("token rejected before the replay")
	}
	wantOAuthError(t, h.exchange(clientID, executorRedirect, code, p.verifier), http.StatusBadRequest, "invalid_grant")
	for _, a := range []string{tok.access, tok2.access} {
		if h.mcp(a).StatusCode != http.StatusUnauthorized {
			t.Fatal("access token survived a code replay")
		}
	}
	wantOAuthError(t, h.refresh(clientID, tok2.refresh), http.StatusBadRequest, "invalid_grant")
	if got := h.login.forgets(); !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("Forget calls = %v", got)
	}
}

func TestRefreshRotationGraceAndReuse(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")

	// Rotation: the first use gives a new refresh token.
	tok2 := h.tokensOf(h.refresh(clientID, tok.refresh))
	// Grace: within 10 s the old one works once more (a racing refresh).
	h.clock.Advance(5 * time.Second)
	tok3 := h.tokensOf(h.refresh(clientID, tok.refresh))
	if tok3.refresh == tok2.refresh {
		t.Fatal("grace refresh returned the same token")
	}
	// Both branches still work.
	if h.mcp(tok2.access).StatusCode != http.StatusOK || h.mcp(tok3.access).StatusCode != http.StatusOK {
		t.Fatal("tokens from the race rejected")
	}
	// A third use of the old token, even inside the window, ends the grant.
	wantOAuthError(t, h.refresh(clientID, tok.refresh), http.StatusBadRequest, "invalid_grant")
	for _, a := range []string{tok2.access, tok3.access} {
		if h.mcp(a).StatusCode != http.StatusUnauthorized {
			t.Fatal("grant survived refresh token reuse")
		}
	}
	wantOAuthError(t, h.refresh(clientID, tok3.refresh), http.StatusBadRequest, "invalid_grant")
	if got := h.login.forgets(); !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("Forget calls = %v", got)
	}
}

func TestRefreshReuseAfterGrace(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")
	tok2 := h.tokensOf(h.refresh(clientID, tok.refresh))
	h.clock.Advance(11 * time.Second)
	wantOAuthError(t, h.refresh(clientID, tok.refresh), http.StatusBadRequest, "invalid_grant")
	if h.mcp(tok2.access).StatusCode != http.StatusUnauthorized {
		t.Fatal("grant survived reuse after the grace window")
	}
	wantOAuthError(t, h.refresh(clientID, tok2.refresh), http.StatusBadRequest, "invalid_grant")
}

// Another client presenting a refresh token gets nothing and ends nothing.
func TestRefreshOtherClient(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")
	stranger := h.register(executorRedirect, "")
	wantOAuthError(t, h.refresh(stranger, tok.refresh), http.StatusBadRequest, "invalid_grant")
	wantOAuthError(t, h.refresh(clientID, tok.refresh, "resource", "https://other.example/mcp"), http.StatusBadRequest, "invalid_target")
	h.tokensOf(h.refresh(clientID, tok.refresh))
}

func TestScopes(t *testing.T) {
	h := newHarness(t)

	// Write not requested: offered unticked; consenting without it gives read.
	clientID := h.register(executorRedirect, "")
	p := newPKCE()
	f := h.signIn(h.authorizeURL(clientID, executorRedirect, p, ScopeRead, "s"))
	if _, offered := f.offered[ScopeWrite]; offered {
		t.Fatalf("write offered although not requested: %v", f.offered)
	}
	u := h.consent(f, true, ScopeWrite) // a forged tick for a scope not offered
	tok := h.tokensOf(h.exchange(clientID, executorRedirect, u.Query().Get("code"), p.verifier))
	if tok.scope != ScopeRead {
		t.Fatalf("scope = %q", tok.scope)
	}

	// No scope parameter: write is offered but not ticked.
	p = newPKCE()
	f = h.signIn(h.authorizeURL(clientID, executorRedirect, p, "", "s"))
	if checked, ok := f.offered[ScopeWrite]; !ok || checked {
		t.Fatalf("no scope requested: offered %v", f.offered)
	}
	// Requested and then unticked by the person.
	p = newPKCE()
	f = h.signIn(h.authorizeURL(clientID, executorRedirect, p, ScopeRead+" "+ScopeWrite, "s"))
	if !f.offered[ScopeWrite] {
		t.Fatalf("write requested but not ticked: %v", f.offered)
	}
	u = h.consent(f, true)
	tok = h.tokensOf(h.exchange(clientID, executorRedirect, u.Query().Get("code"), p.verifier))
	if tok.scope != ScopeRead {
		t.Fatalf("unticked write still granted: %q", tok.scope)
	}

	// Narrowing on refresh, never widening.
	clientID, full := h.connect(ScopeRead+" "+ScopeWrite, ScopeWrite)
	if full.scope != ScopeRead+" "+ScopeWrite {
		t.Fatalf("full scope = %q", full.scope)
	}
	narrow := h.tokensOf(h.refresh(clientID, full.refresh, "scope", ScopeRead))
	if narrow.scope != ScopeRead {
		t.Fatalf("narrowed scope = %q", narrow.scope)
	}
	info := h.mcp(narrow.access).json(t)
	if s := info["scopes"].([]any); len(s) != 1 || s[0] != ScopeRead {
		t.Fatalf("narrowed token scopes = %v", s)
	}
	// The grant keeps its scopes: the next refresh without scope gets both back.
	again := h.tokensOf(h.refresh(clientID, narrow.refresh))
	if again.scope != ScopeRead+" "+ScopeWrite {
		t.Fatalf("grant scope after narrowing = %q", again.scope)
	}

	// A read-only grant cannot be widened.
	clientID, ro := h.connect(ScopeRead)
	wantOAuthError(t, h.refresh(clientID, ro.refresh, "scope", ScopeRead+" "+ScopeWrite), http.StatusBadRequest, "invalid_scope")
}

func TestVerifier(t *testing.T) {
	h := newHarness(t)
	_, tok := h.connect("")
	v := h.s.Verifier()
	ti, err := v(context.Background(), tok.access, nil)
	if err != nil || ti.UserID != "alice@proton" || ti.Extra["grant"] == "" || ti.Expiration.IsZero() {
		t.Fatalf("verify: %+v %v", ti, err)
	}
	for _, bad := range []string{"", "nope", tok.refresh} {
		if _, err := v(context.Background(), bad, nil); err == nil {
			t.Errorf("token %q accepted", bad)
		}
	}
	// Expired.
	h.clock.Advance(time.Hour + time.Second)
	if _, err := v(context.Background(), tok.access, nil); err == nil {
		t.Fatal("expired access token accepted")
	}
	if r := h.mcp(tok.access); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired token over HTTP: %d", r.StatusCode)
	}
}

// A token minted for another resource is not accepted: a server whose issuer
// differs (same state, same key) refuses tokens of the first one.
func TestVerifierResourceBinding(t *testing.T) {
	h := newHarness(t)
	_, tok := h.connect("")
	other, err := New(Config{Issuer: "https://other.example", StatePath: h.state, Key: h.key, Login: h.login, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Verifier()(context.Background(), tok.access, nil); err == nil {
		t.Fatal("token for another resource accepted")
	}
}

func TestRevokeAccessTokenAndLastGrant(t *testing.T) {
	h := newHarness(t)
	c1, t1 := h.connect("")
	c2, t2 := h.connect("")

	// Revoking an access token ends only that token.
	h.postForm(nil, h.issuer+"/revoke", url.Values{"token": {t1.access}, "client_id": {c1}})
	if h.mcp(t1.access).StatusCode != http.StatusUnauthorized {
		t.Fatal("revoked access token works")
	}
	h.tokensOf(h.refresh(c1, t1.refresh)) // grant still alive

	// Two grants for one subject: Forget only after the last.
	if r := h.postForm(nil, h.issuer+"/revoke", url.Values{"token": {t2.refresh}, "client_id": {c2}}); r.StatusCode != http.StatusOK {
		t.Fatal(r.body)
	}
	if got := h.login.forgets(); len(got) != 0 {
		t.Fatalf("Forget called while another grant holds the subject: %v", got)
	}
	// Another client may not revoke someone else's grant.
	r := h.postForm(nil, h.issuer+"/revoke", url.Values{"token": {t1.refresh}, "client_id": {c2}})
	if r.StatusCode != http.StatusOK && r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("foreign revoke: %d", r.StatusCode)
	}
	// Unknown tokens are not an error (RFC 7009 §2.2).
	if r := h.postForm(nil, h.issuer+"/revoke", url.Values{"token": {"unknown"}}); r.StatusCode != http.StatusOK {
		t.Fatalf("unknown token: %d", r.StatusCode)
	}
}

func TestRevokeOnlyOwnGrant(t *testing.T) {
	h := newHarness(t)
	c1, t1 := h.connect("")
	c2 := h.register(executorRedirect, "")
	r := h.postForm(nil, h.issuer+"/revoke", url.Values{"token": {t1.refresh}, "client_id": {c2}})
	wantOAuthError(t, r, http.StatusUnauthorized, "invalid_client")
	h.tokensOf(h.refresh(c1, t1.refresh))
	if got := h.login.forgets(); len(got) != 0 {
		t.Fatalf("Forget calls = %v", got)
	}
}

func TestConsentCSRF(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	f := h.signIn(h.authorizeURL(clientID, executorRedirect, newPKCE(), "", "s"))
	post := func(c *http.Client, v url.Values, origin string) response {
		req, _ := http.NewRequest("POST", h.issuer+"/login/consent", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		return h.do(c, req)
	}
	ok := url.Values{"id": {f.id}, "csrf": {f.csrf}, "action": {"allow"}}

	// Without the cookie (another browser, i.e. a cross-site attacker page).
	if r := post(h.newBrowser(), ok, ""); r.StatusCode != http.StatusForbidden {
		t.Fatalf("no cookie: %d", r.StatusCode)
	}
	// Cookie but wrong hidden field.
	bad := url.Values{"id": {f.id}, "csrf": {"forged"}, "action": {"allow"}}
	if r := post(nil, bad, ""); r.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong csrf: %d", r.StatusCode)
	}
	// Cookie and field, but from a foreign origin.
	if r := post(nil, ok, "https://evil.example"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", r.StatusCode)
	}
	// The real thing, once.
	if r := post(nil, ok, h.srv.URL); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("genuine consent: %d %s", r.StatusCode, r.body)
	}
	if r := post(nil, ok, h.srv.URL); r.StatusCode == http.StatusSeeOther {
		t.Fatal("consent accepted twice")
	}

	// The cookie is __Host-, Secure, HttpOnly, SameSite=Lax, Path=/.
	r := h.get(h.authorizeURL(clientID, executorRedirect, newPKCE(), "", "s"))
	sc := r.Header.Get("Set-Cookie")
	for _, want := range []string{"__Host-mcpauth-", "Path=/", "Secure", "HttpOnly", "SameSite=Lax"} {
		if !strings.Contains(sc, want) {
			t.Errorf("Set-Cookie %q lacks %q", sc, want)
		}
	}
	if strings.Contains(sc, "Domain=") {
		t.Errorf("Set-Cookie %q has a Domain", sc)
	}
	// A sign-in page opened in another browser shows nothing.
	other := h.newBrowser()
	req, _ := http.NewRequest("GET", r.Header.Get("Location"), nil)
	if page := h.do(other, req); page.StatusCode != http.StatusBadRequest || strings.Contains(page.body, "QX7-4KPM") {
		t.Fatalf("sign-in page in another browser: %d", page.StatusCode)
	}
}

func TestHTMLHeadersAndEscaping(t *testing.T) {
	h := newHarness(t)
	evil := `<script>alert("x")</script><img src=x onerror=alert(1)>`
	r := h.postJSON(h.issuer+"/register", map[string]any{"client_name": evil, "redirect_uris": []string{executorRedirect}})
	clientID := r.json(t)["client_id"].(string)
	f := h.signIn(h.authorizeURL(clientID, executorRedirect, newPKCE(), "", "s"))
	if strings.Contains(f.page, "<script>alert") || strings.Contains(f.page, "<img src=x") {
		t.Fatal("client_name not escaped")
	}
	if !strings.Contains(f.page, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;") {
		t.Fatalf("escaped client_name missing from the consent page")
	}

	page := h.get(h.issuer + "/authorize?client_id=nope")
	csp := page.Header.Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'none'", "img-src data:", "style-src 'unsafe-inline'", "script-src 'nonce-",
		"form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	for k, v := range map[string]string{
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
	} {
		if got := page.Header.Get(k); got != v {
			t.Errorf("%s = %q", k, got)
		}
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.RateLimit = RateLimit{PerMinute: 6, Burst: 2} })
	body := map[string]any{"redirect_uris": []string{executorRedirect}}
	codes := func() []int {
		var out []int
		for range 3 {
			out = append(out, h.postJSON(h.issuer+"/register", body).StatusCode)
		}
		return out
	}
	if got := codes(); !slices.Equal(got, []int{201, 201, 429}) {
		t.Fatalf("first burst: %v", got)
	}
	// One token every 10 s.
	h.clock.Advance(10 * time.Second)
	if got := codes(); !slices.Equal(got, []int{201, 429, 429}) {
		t.Fatalf("after 10s: %v", got)
	}
	// Each endpoint has its own bucket: /token is not yet limited.
	r := h.postForm(nil, h.issuer+"/token", url.Values{"grant_type": {"password"}})
	wantOAuthError(t, r, http.StatusBadRequest, "unsupported_grant_type")
	// A different IP has its own bucket.
	h2 := newHarness(t, func(c *Config) {
		c.RateLimit = RateLimit{PerMinute: 6, Burst: 1}
		c.ClientIP = func(r *http.Request) string { return r.Header.Get("X-Test-IP") }
	})
	send := func(ip string) int {
		req, _ := http.NewRequest("POST", h2.issuer+"/token", strings.NewReader("grant_type=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Test-IP", ip)
		return h2.do(nil, req).StatusCode
	}
	if a, b, c := send("1.1.1.1"), send("1.1.1.1"), send("2.2.2.2"); a != 400 || b != 429 || c != 400 {
		t.Fatalf("per-IP buckets: %d %d %d", a, b, c)
	}
}

func TestTokenEndpointErrors(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	wantOAuthError(t, h.postForm(nil, h.issuer+"/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}}),
		http.StatusBadRequest, "unsupported_grant_type")
	wantOAuthError(t, h.postForm(nil, h.issuer+"/token", url.Values{"client_id": {clientID}}),
		http.StatusBadRequest, "invalid_request")
	r := h.postForm(nil, h.issuer+"/token", url.Values{"grant_type": {"authorization_code", "refresh_token"}})
	wantOAuthError(t, r, http.StatusBadRequest, "invalid_request")
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("error response cacheable")
	}
	req, _ := http.NewRequest("POST", h.issuer+"/token", strings.NewReader(`{"grant_type":"refresh_token"}`))
	req.Header.Set("Content-Type", "application/json")
	wantOAuthError(t, h.do(nil, req), http.StatusBadRequest, "invalid_request")
	wantOAuthError(t, h.refresh(clientID, "not-a-token"), http.StatusBadRequest, "invalid_grant")
}

// An approved sign-in that is never consented to is forgotten once it expires.
func TestAbandonedSignInForgotten(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	h.signIn(h.authorizeURL(clientID, executorRedirect, newPKCE(), "", "s"))
	h.clock.Advance(loginTTL + 2*time.Minute)
	h.register(executorRedirect, "") // any request sweeps
	if got := h.login.forgets(); !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("Forget calls = %v", got)
	}
}

// Nothing secret reaches a URL the server builds or a header it sets, except
// the code in the redirect to the client.
func TestNoSecretsInLoginURLs(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	r := h.get(h.authorizeURL(clientID, executorRedirect, newPKCE(), "", "s"))
	loc := r.Header.Get("Location")
	ck := r.Cookies()
	if len(ck) != 1 || strings.Contains(loc, ck[0].Value) {
		t.Fatalf("CSRF token leaked into the login URL %q", loc)
	}
}

// A state file with no "forget" or "unbound" keys (an empty document, or one
// written by an earlier build) must load into usable collections: a nil map
// panics on the first write.
func TestStateWithoutOptionalCollectionsLoads(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	st, err := newStore(filepath.Join(t.TempDir(), "state.json"), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.save(&state{}); err != nil {
		t.Fatal(err)
	}
	s, err := st.load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Unbound == nil || s.Clients == nil || s.Grants == nil {
		t.Fatalf("a collection is nil after load: %+v", s)
	}
	s.Unbound["x"] = time.Now() // would panic on a nil map
}

// The browser writes its Origin canonically: host in lower case and no default
// port. An issuer configured as HTTPS://Proton.Example:443 must accept what a
// browser sends for it, and still refuse anything that is another origin.
func TestOriginIsComparedAsABrowserWritesIt(t *testing.T) {
	for _, tc := range []struct {
		issuer, origin string
		same           bool
	}{
		{"https://proton.example", "https://proton.example", true},
		{"HTTPS://Proton.Example", "https://proton.example", true},
		{"https://proton.example:443", "https://proton.example", true},
		{"http://proton.example:80", "http://proton.example", true},
		{"https://proton.example:8443", "https://proton.example:8443", true},
		{"https://proton.example:8443", "https://proton.example", false},
		{"https://proton.example", "http://proton.example", false},
		{"https://proton.example", "https://proton.example.evil.test", false},
		{"https://proton.example", "https://evil.test", false},
		{"https://proton.example", "null", false},
		{"https://proton.example", "https://proton.example/path", false},
		{"https://proton.example", "https://user@proton.example", false},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080", true},
		{"http://[::1]:8080", "http://[::1]:8080", true},
	} {
		u, err := url.Parse(tc.issuer)
		if err != nil {
			t.Fatal(err)
		}
		s := &Server{browser: canonicalOrigin(u)}
		if got := s.sameOrigin(tc.origin); got != tc.same {
			t.Errorf("issuer %q, Origin %q: got %v, want %v", tc.issuer, tc.origin, got, tc.same)
		}
	}
}
