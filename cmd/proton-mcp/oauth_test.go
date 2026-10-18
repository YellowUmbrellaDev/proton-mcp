package main

import (
	"bytes"
	"net/http/httptest"
	"strings"
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

// The login's operator warnings are the signal for -keep-anonymous-session, so
// they must be written; its own default would discard them.
func TestLoginWarningsReachTheLog(t *testing.T) {
	var out bytes.Buffer
	cfg := loginConfig(true, &out)
	if cfg.Logger == nil {
		t.Fatal("no logger: the login would discard its warnings")
	}
	cfg.Logger.Warn("a warning", "subject", "u1")
	cfg.Logger.Debug("a debug line that may carry error text")
	got := out.String()
	if !strings.Contains(got, "a warning") {
		t.Errorf("the warning was not written: %q", got)
	}
	if strings.Contains(got, "debug line") {
		t.Errorf("debug output reached the log: %q", got)
	}
	if !cfg.KeepAnonymousSession {
		t.Error("the flag did not reach the config")
	}
}
