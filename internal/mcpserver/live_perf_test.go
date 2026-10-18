package mcpserver

import (
	"testing"
	"time"
)

// TestLivePerf times single-threaded calls: the per-call cost of a trivial tool
// (key unlock included) and of the whole-address-book read behind contacts_list.
func TestLivePerf(t *testing.T) {
	cs := live(t)
	for i := 0; i < 4; i++ {
		start := time.Now()
		_, isErr := call(t, cs, "account_get", map[string]any{})
		t.Logf("account_get #%d err=%v took %s", i+1, isErr, time.Since(start).Round(time.Millisecond))
	}
	for i := 0; i < 2; i++ {
		start := time.Now()
		out, isErr := call(t, cs, "contacts_list", map[string]any{})
		t.Logf("contacts_list #%d err=%v bytes=%d took %s", i+1, isErr, len(out), time.Since(start).Round(time.Millisecond))
	}
}
