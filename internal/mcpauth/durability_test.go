package mcpauth

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"
)

var errDisk = errors.New("disk full")

// failCommits makes every write of the state fail with err, or work again
// when err is nil.
func (h *harness) failCommits(err error) {
	h.s.mu.Lock()
	h.s.store.failSave = err
	h.s.mu.Unlock()
}

// onDisk is the state as a fresh start would load it.
func (h *harness) onDisk() *state {
	h.t.Helper()
	st, err := newStore(h.state, h.key)
	if err != nil {
		h.t.Fatal(err)
	}
	s, err := st.load()
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

// inMemory runs fn on the live state under the server's lock.
func (h *harness) inMemory(fn func(*state)) {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	fn(h.s.st)
}

func (h *harness) revokeToken(clientID, token string) response {
	h.t.Helper()
	return h.postForm(nil, h.issuer+"/revoke", url.Values{"token": {token}, "client_id": {clientID}})
}

// blockForget makes Forget of subject wait until the returned release is
// called, after signalling entered; release(err) ends that call with err. Only
// the first release counts, so a test may also defer one to never hang.
func blockForget(f *fakeLogin, subject string) (entered <-chan struct{}, release func(error)) {
	in := make(chan struct{}, 1)
	out := make(chan error, 1)
	f.setOnForget(func(s string) error {
		if s != subject {
			return nil
		}
		select {
		case in <- struct{}{}:
		default:
		}
		err := <-out
		out <- err // later calls end the same way
		return err
	})
	var once sync.Once
	return in, func(err error) { once.Do(func() { out <- err }) }
}

func closed() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// A1: the process dies while Login.Forget is running. The subject must still
// be in the state file, and the next start must forget it.
func TestForgetSurvivesCrashMidDrain(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")
	entered, release := blockForget(h.login, "alice@proton")
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.revokeToken(clientID, tok.refresh)
	}()
	defer func() { release(errors.New("killed")); <-done }()
	<-entered

	// "Crash": the first server never gets past Forget. What a restart sees
	// is the file as it is now.
	if got := h.onDisk().Forget; !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("queue on disk mid-drain = %v, want [alice@proton]", got)
	}
	login2 := newFakeLogin()
	s2, err := New(Config{Issuer: h.issuer, StatePath: h.state, Key: h.key, Login: login2, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Close(); err != nil { // waits for the drain New started
		t.Fatal(err)
	}
	if got := login2.forgets(); !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("restarted server forgot %v, want [alice@proton]", got)
	}
	if got := h.onDisk().Forget; len(got) != 0 {
		t.Fatalf("queue on disk after the restart drained it = %v", got)
	}
}

// A2: a failed Forget keeps the subject queued, on disk too, and it is tried
// again once forgetRetry has passed.
func TestForgetFailureKeepsSubject(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")
	h.login.setOnForget(func(string) error { return errors.New("proton is down") })
	if r := h.revokeToken(clientID, tok.refresh); r.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d %s", r.StatusCode, r.body)
	}
	if got := h.login.forgetAttempts(); !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("Forget attempts = %v", got)
	}
	if got := h.onDisk().Forget; !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("queue on disk after a failed Forget = %v", got)
	}

	// Not retried before forgetRetry.
	h.login.setOnForget(nil)
	h.register(executorRedirect, "")
	if got := h.login.forgetAttempts(); len(got) != 1 {
		t.Fatalf("retried too early: %v", got)
	}
	h.clock.Advance(forgetRetry + time.Second)
	h.register(executorRedirect, "")
	if got := h.login.forgets(); !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("Forget after the retry delay = %v", got)
	}
	if got := h.onDisk().Forget; len(got) != 0 {
		t.Fatalf("queue on disk after a successful retry = %v", got)
	}
}

// A3: a subject queued while a drain is running is neither tried by it nor
// dropped by it.
func TestForgetQueuedDuringDrainSurvives(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")
	entered, release := blockForget(h.login, "alice@proton")
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.revokeToken(clientID, tok.refresh)
	}()
	defer func() { release(nil); <-done }()
	<-entered

	h.inMemory(func(*state) {
		h.s.queueForget("bob@proton")
		if err := h.s.commit(); err != nil {
			t.Error(err)
		}
	})
	release(nil)
	<-done
	done = closed()

	if got := h.login.forgets(); !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("Forget calls = %v", got)
	}
	if got := h.onDisk().Forget; !slices.Equal(got, []string{"bob@proton"}) {
		t.Fatalf("queue on disk after the drain = %v, want [bob@proton]", got)
	}
	h.register(executorRedirect, "") // the next request drains bob
	if got := h.login.forgets(); !slices.Equal(got, []string{"alice@proton", "bob@proton"}) {
		t.Fatalf("Forget calls = %v", got)
	}
}

// B1: a code exchange whose state write fails leaves the code unused, so the
// same code and verifier work on retry and the session survives.
func TestExchangeRetryAfterFailedCommit(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	p := newPKCE()
	code := h.code(clientID, executorRedirect, p, "")

	h.failCommits(errDisk)
	wantOAuthError(t, h.exchange(clientID, executorRedirect, code, p.verifier), http.StatusInternalServerError, "server_error")
	h.inMemory(func(st *state) {
		if len(st.Grants) != 0 || len(st.Access) != 0 || len(st.Refresh) != 0 {
			t.Errorf("a failed exchange left grants %d, access %d, refresh %d", len(st.Grants), len(st.Access), len(st.Refresh))
		}
		if c := st.Codes[hashSecret(code)]; c == nil || c.Used || c.GrantID != "" {
			t.Errorf("code after a failed exchange = %+v", c)
		}
		if _, ok := st.Unbound["alice@proton"]; !ok {
			t.Error("the session was let go by a failed exchange")
		}
	})

	h.failCommits(nil)
	tok := h.tokensOf(h.exchange(clientID, executorRedirect, code, p.verifier))
	if h.mcp(tok.access).StatusCode != http.StatusOK {
		t.Fatal("token from the retried exchange rejected")
	}
	if got := len(h.onDisk().Grants); got != 1 {
		t.Fatalf("%d grants on disk, want 1", got)
	}
	if got := h.login.forgetAttempts(); len(got) != 0 {
		t.Fatalf("Forget called: %v", got)
	}
}

// B2: a refresh whose state write fails rotates nothing: the presented token
// stays live, unrotated, and works on retry.
func TestRefreshRetryAfterFailedCommit(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")

	h.failCommits(errDisk)
	wantOAuthError(t, h.refresh(clientID, tok.refresh), http.StatusInternalServerError, "server_error")
	h.inMemory(func(st *state) {
		rt := st.Refresh[hashSecret(tok.refresh)]
		if rt == nil || !rt.Superseded.IsZero() || rt.GraceUsed {
			t.Errorf("refresh token after a failed refresh = %+v", rt)
		}
		if len(st.Refresh) != 1 || len(st.Access) != 1 {
			t.Errorf("a failed refresh left %d refresh and %d access tokens", len(st.Refresh), len(st.Access))
		}
	})

	h.failCommits(nil)
	// Past the grace window: a recorded rotation would make this a reuse
	// that ends the grant.
	h.clock.Advance(refreshGrace + time.Second)
	tok2 := h.tokensOf(h.refresh(clientID, tok.refresh))
	if h.mcp(tok2.access).StatusCode != http.StatusOK || h.mcp(tok.access).StatusCode != http.StatusOK {
		t.Fatal("tokens rejected after the retried refresh")
	}
	if got := h.login.forgetAttempts(); len(got) != 0 {
		t.Fatalf("Forget called: %v", got)
	}
}

// B3: a code that really was used still revokes its grant when replayed, also
// after an earlier exchange of it failed to be written.
func TestReplayAfterRetriedExchangeRevokes(t *testing.T) {
	h := newHarness(t)
	clientID := h.register(executorRedirect, "")
	p := newPKCE()
	code := h.code(clientID, executorRedirect, p, "")
	h.failCommits(errDisk)
	wantOAuthError(t, h.exchange(clientID, executorRedirect, code, p.verifier), http.StatusInternalServerError, "server_error")
	h.failCommits(nil)
	tok := h.tokensOf(h.exchange(clientID, executorRedirect, code, p.verifier))

	wantOAuthError(t, h.exchange(clientID, executorRedirect, code, p.verifier), http.StatusBadRequest, "invalid_grant")
	if h.mcp(tok.access).StatusCode != http.StatusUnauthorized {
		t.Fatal("access token survived a code replay")
	}
	wantOAuthError(t, h.refresh(clientID, tok.refresh), http.StatusBadRequest, "invalid_grant")
	if got := h.login.forgets(); !slices.Equal(got, []string{"alice@proton"}) {
		t.Fatalf("Forget calls = %v", got)
	}
	if got := len(h.onDisk().Grants); got != 0 {
		t.Fatalf("%d grants on disk after the replay", got)
	}
}

// A registration whose state write fails leaves no client behind.
func TestRegisterFailedCommitLeavesNoClient(t *testing.T) {
	h := newHarness(t)
	h.failCommits(errDisk)
	r := h.postJSON(h.issuer+"/register", map[string]any{
		"redirect_uris":              []string{executorRedirect},
		"token_endpoint_auth_method": "none",
	})
	wantOAuthError(t, r, http.StatusInternalServerError, "server_error")
	h.inMemory(func(st *state) {
		if len(st.Clients) != 0 {
			t.Errorf("%d clients after a failed registration", len(st.Clients))
		}
	})
}
