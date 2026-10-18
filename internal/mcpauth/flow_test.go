package mcpauth

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// The whole flow, the way Executor walks it: 401 from the MCP endpoint, the
// resource metadata it names, the authorization server metadata, registration,
// the sign-in page, polling, consent, the code, tokens, an MCP call, refresh
// with rotation, and revocation.
func TestFullFlow(t *testing.T) {
	h := newHarness(t)

	// 1. Unauthenticated MCP call: 401 pointing at the resource metadata.
	r := h.mcp("")
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mcp without token: %d", r.StatusCode)
	}
	wantPRM := h.issuer + "/.well-known/oauth-protected-resource/mcp"
	if got := r.Header.Get("WWW-Authenticate"); got != `Bearer resource_metadata="`+wantPRM+`"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}

	// 2. Protected resource metadata.
	prm := h.get(wantPRM).json(t)
	if prm["resource"] != h.issuer+"/mcp" {
		t.Fatalf("resource = %v", prm["resource"])
	}
	if as := prm["authorization_servers"].([]any); len(as) != 1 || as[0] != h.issuer {
		t.Fatalf("authorization_servers = %v", as)
	}
	if bm := prm["bearer_methods_supported"].([]any); len(bm) != 1 || bm[0] != "header" {
		t.Fatalf("bearer_methods_supported = %v", bm)
	}
	if sc := prm["scopes_supported"].([]any); len(sc) != 2 || sc[0] != ScopeRead || sc[1] != ScopeWrite {
		t.Fatalf("scopes_supported = %v", sc)
	}

	// 3. Authorization server metadata.
	md := h.get(h.issuer + "/.well-known/oauth-authorization-server").json(t)
	want := map[string]any{
		"issuer":                 h.issuer,
		"authorization_endpoint": h.issuer + "/authorize",
		"token_endpoint":         h.issuer + "/token",
		"registration_endpoint":  h.issuer + "/register",
		"revocation_endpoint":    h.issuer + "/revoke",
		"authorization_response_iss_parameter_supported": true,
	}
	for k, v := range want {
		if md[k] != v {
			t.Errorf("%s = %v, want %v", k, md[k], v)
		}
	}
	for k, v := range map[string]string{
		"code_challenge_methods_supported":      "S256",
		"token_endpoint_auth_methods_supported": "none",
		"response_types_supported":              "code",
	} {
		if l := md[k].([]any); len(l) != 1 || l[0] != v {
			t.Errorf("%s = %v", k, l)
		}
	}

	// 4. Registration.
	reg := h.postJSON(h.issuer+"/register", map[string]any{
		"client_name":                "Executor",
		"redirect_uris":              []string{executorRedirect},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_post",
		"application_type":           "web",
	})
	if reg.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %s", reg.StatusCode, reg.body)
	}
	cl := reg.json(t)
	clientID := cl["client_id"].(string)
	if cl["token_endpoint_auth_method"] != "none" || cl["client_secret"] != nil {
		t.Fatalf("registration answer: %v", cl)
	}
	if ru := cl["redirect_uris"].([]any); len(ru) != 1 || ru[0] != executorRedirect {
		t.Fatalf("redirect_uris = %v", ru)
	}

	// 5. Authorize, sign in, consent (write requested, so ticked by default).
	p := newPKCE()
	f := h.signIn(h.authorizeURL(clientID, executorRedirect, p, ScopeRead+" "+ScopeWrite, "st-123"))
	if !f.offered[ScopeRead] || !f.offered[ScopeWrite] {
		t.Fatalf("offered %v", f.offered)
	}
	if !strings.Contains(f.page, "Executor") || !strings.Contains(f.page, "executor.example") {
		t.Fatal("consent page does not name the client and its redirect host")
	}
	back := h.consent(f, true, ScopeWrite)
	if back.Scheme+"://"+back.Host+back.Path != executorRedirect {
		t.Fatalf("redirected to %s", back)
	}
	q := back.Query()
	if q.Get("state") != "st-123" || q.Get("iss") != h.issuer {
		t.Fatalf("redirect params: %v", q)
	}

	// 6. Token.
	tr := h.exchange(clientID, executorRedirect, q.Get("code"), p.verifier)
	if cc := tr.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("token Cache-Control = %q", cc)
	}
	m := tr.json(t)
	if m["token_type"] != "Bearer" || m["expires_in"] != float64(3600) || m["scope"] != ScopeRead+" "+ScopeWrite {
		t.Fatalf("token response: %v", m)
	}
	tok := h.tokensOf(tr)

	// 7. MCP call with the token.
	call := h.mcp(tok.access)
	if call.StatusCode != http.StatusOK {
		t.Fatalf("mcp: %d %s", call.StatusCode, call.body)
	}
	info := call.json(t)
	if info["user"] != "alice@proton" || info["grant"] == "" || len(info["scopes"].([]any)) != 2 {
		t.Fatalf("token info: %v", info)
	}

	// 8. Refresh rotates: new pair, the new access token works.
	tok2 := h.tokensOf(h.refresh(clientID, tok.refresh))
	if tok2.refresh == tok.refresh || tok2.access == tok.access {
		t.Fatal("refresh did not rotate")
	}
	if h.mcp(tok2.access).StatusCode != http.StatusOK {
		t.Fatal("refreshed access token rejected")
	}

	// 9. Revoke the refresh token: grant gone, Forget called once.
	rv := h.postForm(nil, h.issuer+"/revoke", url.Values{"token": {tok2.refresh}, "client_id": {clientID}})
	if rv.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d %s", rv.StatusCode, rv.body)
	}
	if h.mcp(tok2.access).StatusCode != http.StatusUnauthorized {
		t.Fatal("access token still works after the grant was revoked")
	}
	wantOAuthError(t, h.refresh(clientID, tok2.refresh), http.StatusBadRequest, "invalid_grant")
	if got := h.login.forgets(); !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("Forget calls = %v", got)
	}
	// Revoking again is fine and forgets nothing more.
	h.postForm(nil, h.issuer+"/revoke", url.Values{"token": {tok2.refresh}, "client_id": {clientID}})
	if got := h.login.forgets(); len(got) != 1 {
		t.Fatalf("Forget calls after second revoke = %v", got)
	}
}

// Executor tries the path-inserted well-known URLs first, then the OpenID
// forms. With an issuer that has a path, the path-inserted ones must answer.
func TestExecutorDiscoveryOrder(t *testing.T) {
	h := newHarnessAt(t, "/proton")
	origin := h.srv.URL

	r := h.mcp("")
	prmURL := origin + "/.well-known/oauth-protected-resource/proton/mcp"
	if got := r.Header.Get("WWW-Authenticate"); got != `Bearer resource_metadata="`+prmURL+`"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	for _, u := range []string{prmURL, origin + "/.well-known/oauth-protected-resource/proton"} {
		prm := h.get(u)
		if prm.StatusCode != http.StatusOK || prm.json(t)["resource"] != h.issuer+"/mcp" {
			t.Fatalf("%s: %d %s", u, prm.StatusCode, prm.body)
		}
		// The resource must equal or prefix the MCP URL (Executor's check).
		if !strings.HasPrefix(h.issuer+MCPPath, prm.json(t)["resource"].(string)) {
			t.Fatal("resource does not prefix-match the MCP URL")
		}
	}
	// RFC 8414 path insertion first, then OpenID Connect path insertion, then
	// OpenID Connect appended.
	for _, u := range []string{
		origin + "/.well-known/oauth-authorization-server/proton",
		origin + "/.well-known/openid-configuration/proton",
		h.issuer + "/.well-known/openid-configuration",
	} {
		md := h.get(u)
		if md.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", u, md.StatusCode)
		}
		if md.json(t)["issuer"] != h.issuer || md.json(t)["token_endpoint"] != h.issuer+"/token" {
			t.Fatalf("%s: %s", u, md.body)
		}
	}
	// And the whole flow works under the prefix.
	_, tok := h.connect("")
	if h.mcp(tok.access).StatusCode != http.StatusOK {
		t.Fatal("token from a prefixed issuer rejected")
	}
}

// Without JavaScript the waiting page reloads itself; it shows the code as text
// and as an inline QR image.
func TestWaitingPage(t *testing.T) {
	h := newHarness(t)
	h.login.approveAfter = 100
	clientID := h.register(executorRedirect, "")
	r := h.get(h.authorizeURL(clientID, executorRedirect, newPKCE(), "", "s"))
	page := h.get(r.Header.Get("Location"))
	for _, want := range []string{
		`<meta http-equiv="refresh" content="5">`,
		`<p class="code">QX7-4KPM</p>`,
		`src="data:image/png;base64,`,
	} {
		if !strings.Contains(page.body, want) {
			t.Errorf("waiting page lacks %q", want)
		}
	}
	csp := page.Header.Get("Content-Security-Policy")
	nonce := between(csp, "'nonce-", "'")
	if nonce == "" || !strings.Contains(page.body, `<script nonce="`+nonce+`">`) {
		t.Fatalf("script nonce does not match the policy %q", csp)
	}
	// A new nonce for every response.
	again := h.get(r.Header.Get("Location"))
	if between(again.Header.Get("Content-Security-Policy"), "'nonce-", "'") == nonce {
		t.Fatal("nonce reused")
	}
}

// A failed sign-in shows Login's message and a way to start again.
func TestFailedSignIn(t *testing.T) {
	h := newHarness(t)
	h.login.fail = "The code expired <before> anyone approved it."
	clientID := h.register(executorRedirect, "")
	r := h.get(h.authorizeURL(clientID, executorRedirect, newPKCE(), "", "s"))
	loginURL := r.Header.Get("Location")
	var page response
	for range 5 {
		h.clock.Advance(2 * time.Second)
		page = h.get(loginURL)
		if strings.Contains(page.body, "expired") {
			break
		}
	}
	if !strings.Contains(page.body, "The code expired &lt;before&gt; anyone approved it.") {
		t.Fatalf("failure page: %s", page.body)
	}
	retry := between(page.body, `<a href="`, `"`)
	if !strings.HasPrefix(retry, h.issuer+"/authorize?") {
		t.Fatalf("retry link %q", retry)
	}
	h.login.fail = ""
	again := h.get(strings.ReplaceAll(retry, "&amp;", "&"))
	if again.StatusCode != http.StatusSeeOther {
		t.Fatalf("retry: %d %s", again.StatusCode, again.body)
	}
}

// Refusing consent sends access_denied back and forgets the session that was
// opened for nothing.
func TestConsentDenied(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	f := h.signIn(h.authorizeURL(clientID, executorRedirect, newPKCE(), "", "st"))
	u := h.consent(f, false)
	if u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "st" {
		t.Fatalf("deny redirect: %s", u)
	}
	if got := h.login.forgets(); !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("Forget calls = %v", got)
	}
}

// The state file holds no token in clear, and survives a restart.
func TestStatePersistsSealed(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")
	raw := readFile(t, h.state)
	for _, secret := range []string{tok.access, tok.refresh, "alice@proton", clientID} {
		if strings.Contains(raw, secret) {
			t.Fatalf("state file contains %q in clear", secret)
		}
	}
	if mode := fileMode(t, h.state); mode != 0o600 {
		t.Fatalf("state file mode %o", mode)
	}
	s2, err := New(Config{Issuer: h.issuer, StatePath: h.state, Key: h.key, Login: h.login, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	ti, err := s2.Verifier()(t.Context(), tok.access, nil)
	if err != nil || ti.UserID != "alice@proton" {
		t.Fatalf("after restart: %v %v", ti, err)
	}
	wrong := make([]byte, 32)
	if _, err := New(Config{Issuer: h.issuer, StatePath: h.state, Key: wrong, Login: h.login}); err == nil {
		t.Fatal("state opened with the wrong key")
	}
}

func between(s, from, to string) string {
	i := strings.Index(s, from)
	if i < 0 {
		return ""
	}
	s = s[i+len(from):]
	j := strings.Index(s, to)
	if j < 0 {
		return ""
	}
	return s[:j]
}
