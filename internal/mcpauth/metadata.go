package mcpauth

import (
	"encoding/json"
	"net/http"
)

// protectedResource serves the RFC 9728 document of the MCP endpoint.
func (s *Server) protectedResource(w http.ResponseWriter, r *http.Request) {
	writeMetadata(w, map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.cfg.Issuer},
		"scopes_supported":         s.cfg.Scopes,
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Proton",
	})
}

// serverMetadata serves the RFC 8414 document of the authorization server; the
// same document answers the OpenID Connect discovery URLs clients fall back to.
func (s *Server) serverMetadata(w http.ResponseWriter, r *http.Request) {
	writeMetadata(w, map[string]any{
		"issuer":                                         s.cfg.Issuer,
		"authorization_endpoint":                         s.endpoint("/authorize"),
		"token_endpoint":                                 s.endpoint("/token"),
		"registration_endpoint":                          s.endpoint("/register"),
		"revocation_endpoint":                            s.endpoint("/revoke"),
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"revocation_endpoint_auth_methods_supported":     []string{"none"},
		"scopes_supported":                               s.cfg.Scopes,
		"authorization_response_iss_parameter_supported": true,
	})
}

// Metadata is public: any origin may read it (RFC 9728 §3.1).
func writeMetadata(w http.ResponseWriter, doc map[string]any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(doc)
}

// writeJSON answers an API call that must never be cached.
func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// oauthError is an error response of RFC 6749 §5.2 (and its extensions).
func oauthError(w http.ResponseWriter, status int, code, description string) {
	body := map[string]string{"error": code}
	if description != "" {
		body["error_description"] = description
	}
	writeJSON(w, status, body)
}
