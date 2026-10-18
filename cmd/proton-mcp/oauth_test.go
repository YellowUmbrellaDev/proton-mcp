package main

import (
	"net/http/httptest"
	"testing"
)

func TestForwardedClientIPTakesTheProxysOwnEntry(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.18.0.2:5555"
	if got := forwardedClientIP(r); got != "172.18.0.2" {
		t.Errorf("without the header: %q", got)
	}
	// The caller wrote the first entry; the proxy appended the last.
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")
	if got := forwardedClientIP(r); got != "203.0.113.9" {
		t.Errorf("with a spoofed first entry: %q", got)
	}
}
