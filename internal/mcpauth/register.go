package mcpauth

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maxBody          = 64 << 10
	maxClients       = 10000
	maxRedirectURIs  = 10
	maxClientNameLen = 100
	maxURILen        = 2000
)

// registration is the RFC 7591 request body, as far as this server reads it.
type registration struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// register is Dynamic Client Registration (RFC 7591). Every client is public:
// whatever authentication method it asks for, it is told "none", and it proves
// itself with PKCE.
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body must be application/json")
		return
	}
	var req registration
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if err := dec.Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body is not a client metadata document")
		return
	}

	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > maxRedirectURIs {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "between 1 and 10 redirect_uris are required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !s.redirectAllowed(u) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URIs must be https, or http on a loopback host, with no fragment")
			return
		}
	}

	grants := req.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	for _, g := range grants {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant type")
			return
		}
	}
	if !slices.Contains(grants, "authorization_code") {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "grant_types must include authorization_code")
		return
	}
	// Refresh tokens are issued whether or not a client asked for them, since
	// MCP clients do not send offline_access; say so in the answer.
	if !slices.Contains(grants, "refresh_token") {
		grants = append(grants, "refresh_token")
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "only the code response type is supported")
			return
		}
	}

	scopes := parseScope(req.Scope)
	if !subset(scopes, s.cfg.Scopes) {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unknown scope")
		return
	}

	name := strings.TrimSpace(req.ClientName)
	if !utf8.ValidString(name) {
		name = ""
	}
	if utf8.RuneCountInString(name) > maxClientNameLen {
		name = string([]rune(name)[:maxClientNameLen])
	}
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)

	now := s.now()
	c := &client{
		ID:           newID(),
		Name:         name,
		RedirectURIs: slices.Clone(req.RedirectURIs),
		GrantTypes:   grants,
		Scope:        strings.Join(scopes, " "),
		Created:      now,
		LastUsed:     now,
	}
	s.mu.Lock()
	s.maybePurge(now)
	if len(s.st.Clients) >= maxClients {
		s.mu.Unlock()
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many registered clients")
		return
	}
	s.st.Clients[c.ID] = c
	err := s.commit()
	s.mu.Unlock()
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.drainIfQueued()

	resp := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        now.Unix(),
		"redirect_uris":              c.RedirectURIs,
		"grant_types":                c.GrantTypes,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	if c.Name != "" {
		resp["client_name"] = c.Name
	}
	if c.Scope != "" {
		resp["scope"] = c.Scope
	}
	writeJSON(w, http.StatusCreated, resp)
}

// redirectAllowed says whether a redirect URI may be registered. The structural
// rules hold whatever Config.AllowRedirect says: an absolute URI, no fragment,
// no user info, https or http on a loopback host. AllowRedirect, when set, can
// only narrow that further.
func (s *Server) redirectAllowed(raw string) bool {
	if raw == "" || len(raw) > maxURILen || strings.Contains(raw, "#") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" {
		return false
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return false
		}
	default:
		return false
	}
	if s.cfg.AllowRedirect != nil {
		return s.cfg.AllowRedirect(raw)
	}
	return true
}
