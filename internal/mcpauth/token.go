package mcpauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// tokenError is an OAuth error the token and revocation endpoints answer with.
type tokenError struct {
	status      int
	code        string
	description string
}

func badRequest(code, desc string) *tokenError {
	return &tokenError{http.StatusBadRequest, code, desc}
}

var errServer = &tokenError{http.StatusInternalServerError, "server_error", ""}

// readForm reads an application/x-www-form-urlencoded body in which no
// parameter is repeated (RFC 6749 §3.2), and the client it names: client_id
// from the body, or the user name of Basic authentication.
func readForm(w http.ResponseWriter, r *http.Request) (url.Values, string, *tokenError) {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
		return nil, "", badRequest("invalid_request", "the body must be application/x-www-form-urlencoded")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		return nil, "", badRequest("invalid_request", "the body cannot be read")
	}
	form := r.PostForm
	for name, vals := range form {
		if len(vals) > 1 {
			return nil, "", badRequest("invalid_request", "repeated parameter "+name)
		}
	}
	clientID := form.Get("client_id")
	if user, _, ok := r.BasicAuth(); ok {
		if user, err := url.QueryUnescape(user); err == nil {
			if clientID != "" && clientID != user {
				return nil, "", &tokenError{http.StatusUnauthorized, "invalid_client", "two different clients named"}
			}
			clientID = user
		}
	}
	return form, clientID, nil
}

// token is the token endpoint: it exchanges a code, or rotates a refresh token.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	form, clientID, terr := readForm(w, r)
	if terr == nil {
		var resp map[string]any
		switch gt := form.Get("grant_type"); gt {
		case "authorization_code":
			resp, terr = s.exchangeCode(form, clientID)
		case "refresh_token":
			resp, terr = s.refresh(form, clientID)
		case "":
			terr = badRequest("invalid_request", "grant_type is required")
		default:
			terr = badRequest("unsupported_grant_type", "")
		}
		if terr == nil {
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}
	// A refused grant may have revoked something (a replayed code or refresh
	// token); its session is forgotten before the answer goes out.
	s.drainIfQueued()
	if terr.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	oauthError(w, terr.status, terr.code, terr.description)
}

// knownClient checks that a client is registered, and notes that it was used; the
// caller holds s.mu.
func (s *Server) knownClient(clientID string, now time.Time) *tokenError {
	if clientID == "" {
		return &tokenError{http.StatusUnauthorized, "invalid_client", "client_id is required"}
	}
	c := s.st.Clients[clientID]
	if c == nil {
		return &tokenError{http.StatusUnauthorized, "invalid_client", "unknown client"}
	}
	c.LastUsed = now
	return nil
}

func (s *Server) exchangeCode(form url.Values, clientID string) (map[string]any, *tokenError) {
	code, verifier := form.Get("code"), form.Get("code_verifier")
	if code == "" {
		return nil, badRequest("invalid_request", "code is required")
	}
	if verifier == "" {
		return nil, badRequest("invalid_request", "code_verifier is required")
	}
	if !validVerifier(verifier) {
		return nil, badRequest("invalid_grant", "code_verifier is malformed")
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePurge(now)
	if terr := s.knownClient(clientID, now); terr != nil {
		return nil, terr
	}
	hash := hashSecret(code)
	c := s.st.Codes[hash]
	switch {
	case c == nil:
		return nil, badRequest("invalid_grant", "unknown code")
	case c.Used:
		// A code used twice was stolen, or the client is broken: whatever it
		// produced is no longer to be trusted (RFC 6749 §4.1.2).
		s.revokeGrant(c.GrantID)
		delete(s.st.Codes, hash)
		if err := s.commit(); err != nil {
			return nil, errServer
		}
		return nil, badRequest("invalid_grant", "the code was already used")
	}
	// From here on the code is spent, whether the exchange succeeds or not: a
	// code presented with the wrong proof may have been intercepted.
	var terr *tokenError
	switch {
	case now.After(c.Expires):
		terr = badRequest("invalid_grant", "the code has expired")
	case !equal(c.ClientID, clientID):
		terr = badRequest("invalid_grant", "the code was issued to another client")
	case !equal(c.RedirectURI, form.Get("redirect_uri")):
		terr = badRequest("invalid_grant", "redirect_uri does not match the authorization request")
	case !equal(c.Challenge, s256(verifier)):
		terr = badRequest("invalid_grant", "code_verifier does not match the code_challenge")
	case form.Has("resource") && !equal(c.Resource, form.Get("resource")):
		terr = badRequest("invalid_target", "the code was issued for another resource")
	}
	if terr != nil {
		delete(s.st.Codes, hash)
		s.releaseUnbound(c.Subject)
		if err := s.commit(); err != nil {
			return nil, errServer
		}
		return nil, terr
	}

	g := &grant{
		ID:       newID(),
		ClientID: c.ClientID,
		Subject:  c.Subject,
		Scopes:   c.Scopes,
		Resource: c.Resource,
		Created:  now,
		Expires:  now.Add(s.cfg.RefreshTTL),
	}
	s.st.Grants[g.ID] = g
	c.Used, c.GrantID = true, g.ID
	// Kept until the grant ends, so that a replay can still be caught.
	c.Expires = g.Expires
	s.releaseUnbound(c.Subject) // the grant holds the session now
	resp := s.issue(g, g.Scopes, now)
	if err := s.commit(); err != nil {
		return nil, errServer
	}
	return resp, nil
}

func (s *Server) refresh(form url.Values, clientID string) (map[string]any, *tokenError) {
	text := form.Get("refresh_token")
	if text == "" {
		return nil, badRequest("invalid_request", "refresh_token is required")
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePurge(now)
	if terr := s.knownClient(clientID, now); terr != nil {
		return nil, terr
	}
	hash := hashSecret(text)
	rt := s.st.Refresh[hash]
	if rt == nil {
		return nil, badRequest("invalid_grant", "unknown refresh token")
	}
	g := s.st.Grants[rt.GrantID]
	switch {
	case g == nil || now.After(rt.Expires) || now.After(g.Expires):
		delete(s.st.Refresh, hash)
		_ = s.commit()
		return nil, badRequest("invalid_grant", "the refresh token has expired")
	case !equal(g.ClientID, clientID):
		// Not this client's token. Do not let a stranger end the grant.
		return nil, badRequest("invalid_grant", "the refresh token was issued to another client")
	case form.Has("resource") && !equal(g.Resource, form.Get("resource")):
		return nil, badRequest("invalid_target", "the grant is for another resource")
	}
	scopes := g.Scopes
	if form.Has("scope") {
		scopes = parseScope(form.Get("scope"))
		if len(scopes) == 0 || !subset(scopes, g.Scopes) {
			return nil, badRequest("invalid_scope", "the scope is broader than the grant")
		}
	}

	switch {
	case rt.Superseded.IsZero():
		rt.Superseded = now
		if keep := now.Add(supersededKeep); keep.Before(rt.Expires) {
			rt.Expires = keep
		}
	case !rt.GraceUsed && now.Sub(rt.Superseded) <= refreshGrace:
		// The client is racing itself: the answer to its first refresh is
		// still on the way. Let it through once.
		rt.GraceUsed = true
	default:
		// A rotated refresh token came back: one of the two holders is not
		// the client. End the grant (RFC 9700 §4.14.2).
		s.revokeGrant(g.ID)
		if err := s.commit(); err != nil {
			return nil, errServer
		}
		return nil, badRequest("invalid_grant", "the refresh token was already used")
	}
	g.Expires = now.Add(s.cfg.RefreshTTL)
	resp := s.issue(g, scopes, now)
	if err := s.commit(); err != nil {
		return nil, errServer
	}
	return resp, nil
}

// issue mints an access token with scopes and a fresh refresh token for the
// grant; the caller holds s.mu and commits.
func (s *Server) issue(g *grant, scopes []string, now time.Time) map[string]any {
	access, accessHash := newSecret()
	s.st.Access[accessHash] = &accessToken{
		GrantID:  g.ID,
		Scopes:   scopes,
		Resource: g.Resource,
		Expires:  now.Add(s.cfg.AccessTTL),
	}
	refresh, refreshHash := newSecret()
	s.st.Refresh[refreshHash] = &refreshToken{GrantID: g.ID, Expires: g.Expires}
	return map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(s.cfg.AccessTTL / time.Second),
		"refresh_token": refresh,
		"scope":         strings.Join(scopes, " "),
	}
}

// revoke is token revocation (RFC 7009). Revoking a refresh token ends its
// grant, and forgets the Proton session when no other grant uses it; revoking
// an access token ends only that token. Unknown tokens are not an error.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	form, clientID, terr := readForm(w, r)
	if terr == nil && form.Get("token") == "" {
		terr = badRequest("invalid_request", "token is required")
	}
	if terr != nil {
		oauthError(w, terr.status, terr.code, terr.description)
		return
	}
	hash := hashSecret(form.Get("token"))
	s.mu.Lock()
	grantID, isRefresh := "", false
	if rt := s.st.Refresh[hash]; rt != nil {
		grantID, isRefresh = rt.GrantID, true
	} else if a := s.st.Access[hash]; a != nil {
		grantID = a.GrantID
	}
	g := s.st.Grants[grantID]
	if g != nil && clientID != "" && !equal(g.ClientID, clientID) {
		s.mu.Unlock()
		oauthError(w, http.StatusUnauthorized, "invalid_client", "the token was issued to another client")
		return
	}
	var err error
	if g != nil || grantID != "" {
		if isRefresh {
			s.revokeGrant(grantID)
		} else {
			delete(s.st.Access, hash)
		}
		err = s.commit()
	}
	s.mu.Unlock()
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.drainIfQueued()
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// Verifier checks the bearer token of an MCP request and returns who it is for:
// TokenInfo.UserID is the Subject (the saved Proton session to act as),
// TokenInfo.Scopes what the grant allows, TokenInfo.Extra["grant"] its id.
func (s *Server) Verifier() auth.TokenVerifier {
	return func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		if token == "" {
			return nil, auth.ErrInvalidToken
		}
		hash := hashSecret(token)
		now := s.now()
		s.mu.Lock()
		defer s.mu.Unlock()
		a := s.st.Access[hash]
		if a == nil {
			return nil, auth.ErrInvalidToken
		}
		g := s.st.Grants[a.GrantID]
		switch {
		case now.After(a.Expires):
			delete(s.st.Access, hash)
			return nil, auth.ErrInvalidToken
		case g == nil, a.Resource != s.resource, g.Resource != s.resource:
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{
			Scopes:     append([]string(nil), a.Scopes...),
			Expiration: a.Expires,
			UserID:     g.Subject,
			Extra:      map[string]any{"grant": g.ID},
		}, nil
	}
}

// s256 is the PKCE transform of a code verifier (RFC 7636 §4.2).
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validVerifier: 43 to 128 unreserved characters (RFC 7636 §4.1).
func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// equal compares two strings in time that does not depend on where they differ.
func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
