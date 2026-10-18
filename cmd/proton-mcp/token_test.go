package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnEmptyOrShortTokenFileIsRefused(t *testing.T) {
	for _, secret := range []string{"", "\n", "   \n", "short", "0123456789abcde\n"} {
		if err := checkToken(secret); err == nil {
			t.Errorf("%q accepted", secret)
		}
	}
	if err := checkToken("0123456789abcdef\n"); err != nil {
		t.Errorf("a 16-byte token refused: %v", err)
	}
}

// A token file that is only whitespace must never turn into the header "Bearer "
// and let in every client that sends it.
func TestBearerWithAnEmptySecretLetsNobodyIn(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("mcp")) })
	h := bearer("   \n", next)
	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("the header 'Bearer ' was let in")
	}
}
