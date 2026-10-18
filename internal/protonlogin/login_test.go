package protonlogin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roman-16/proton-cli/internal/account/fork"
	"github.com/roman-16/proton-cli/internal/account/localkey"
	"github.com/roman-16/proton-cli/internal/account/session"
	pgphelper "github.com/roman-16/proton-cli/internal/crypto/pgp"
	"github.com/roman-16/proton-cli/internal/mcpauth"
	"github.com/roman-16/proton-cli/internal/profile"
)

const keyPassword = "the-stretched-key-password"

// fakeProton answers the endpoints a fork sign-in and a revoke use. The approving
// device is played by approve, which seals the key password to the code the test
// was shown.
type fakeProton struct {
	t   *testing.T
	srv *httptest.Server

	userKey, addrKey string

	mu         sync.Mutex
	approved   bool
	code       fork.Code
	clientKey  []byte
	revoked    []string
	revokeCode int
	sessions   int
	forks      int
	// opened lists the anonymous sessions handed out, in order; revokes counts the
	// DELETEs seen per session id.
	opened  []string
	revokes map[string]int
	// failFork and pullCode make the fork endpoints answer with that status.
	failFork int
	pullCode int
	// forkDiesWithParent plays a Proton that ends the forked session when the
	// anonymous one it was forked from is revoked; childDead records that it did.
	forkDiesWithParent bool
	childDead          bool
	// onRevoke, when set, sees every revoke as it arrives, under mu.
	onRevoke func(uid string)
}

// dropConnection, as revokeCode, makes a revoke get no answer at all.
const dropConnection = -1

func newFake(t *testing.T) *fakeProton {
	t.Helper()
	f := &fakeProton{t: t, revokeCode: 200, revokes: map[string]int{}}
	f.userKey = lockedKey(t, "user")
	f.addrKey = lockedKey(t, "address")
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func lockedKey(t *testing.T, name string) string {
	t.Helper()
	key, err := pgphelper.GenerateKey(name, name+"@example.invalid")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	locked, err := pgphelper.PGP.LockKey(key, []byte(keyPassword))
	if err != nil {
		t.Fatalf("lock key: %v", err)
	}
	armored, err := locked.Armor()
	if err != nil {
		t.Fatalf("armor key: %v", err)
	}
	return armored
}

func (f *fakeProton) reply(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeProton) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path
	switch {
	case p == "/auth/v4/sessions" && r.Method == http.MethodPost:
		f.sessions++
		uid := fmt.Sprintf("anon-%d", f.sessions)
		f.opened = append(f.opened, uid)
		f.reply(w, 200, map[string]any{"Code": 1000, "UID": uid, "AccessToken": "anon-access", "RefreshToken": "anon-refresh"})
	case p == "/auth/v4/sessions/forks" && r.Method == http.MethodGet:
		f.forks++
		if f.failFork != 0 {
			f.reply(w, f.failFork, map[string]any{"Code": 2000, "Error": "no fork for you"})
			return
		}
		f.reply(w, 200, map[string]any{"Code": 1000, "Selector": "selector-1", "UserCode": "ABCD1234"})
	case p == "/auth/v4/sessions/forks/selector-1":
		if f.pullCode != 0 {
			f.reply(w, f.pullCode, map[string]any{"Code": 2000, "Error": "unknown fork"})
			return
		}
		if !f.approved {
			f.reply(w, 422, map[string]any{"Code": 22000, "Error": "not yet"})
			return
		}
		payload, err := f.code.Seal(keyPassword)
		if err != nil {
			f.t.Errorf("seal: %v", err)
		}
		f.reply(w, 200, map[string]any{
			"Code": 1000, "UID": "child-uid", "AccessToken": "child-access",
			"RefreshToken": "child-refresh", "Payload": payload,
		})
	case f.childDead && r.Header.Get("x-pm-uid") == "child-uid" && p != "/auth/v4/refresh":
		f.reply(w, 401, map[string]any{})
	case p == "/auth/v4/refresh" && r.Method == http.MethodPost:
		// Nothing in these tests refreshes a live session.
		f.reply(w, 400, map[string]any{"Code": 10013, "Error": "invalid refresh token"})
	case p == "/core/v4/users":
		f.reply(w, 200, map[string]any{"Code": 1000, "User": map[string]any{
			"ID": "user-id", "Name": "someone", "Email": "someone@proton.me",
			"Keys": []map[string]any{{"ID": "user-key", "PrivateKey": f.userKey, "Primary": 1, "Active": 1}},
		}})
	case p == "/core/v4/addresses":
		f.reply(w, 200, map[string]any{"Code": 1000, "Addresses": []map[string]any{{
			"ID": "address", "Email": "someone@proton.me", "Status": 1, "Send": 1, "Receive": 1,
			"Keys": []map[string]any{{"ID": "address-key", "PrivateKey": f.addrKey, "Primary": 1, "Active": 1}},
		}}})
	case p == "/auth/v4/sessions/local/key" && r.Method == http.MethodPut:
		var body struct{ Key string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.clientKey, _ = base64.StdEncoding.DecodeString(body.Key)
		f.reply(w, 200, map[string]any{"Code": 1000})
	case p == "/auth/v4/sessions/local/key" && r.Method == http.MethodGet:
		f.reply(w, 200, map[string]any{"Code": 1000, "ClientKey": base64.StdEncoding.EncodeToString(f.clientKey)})
	case strings.HasPrefix(p, "/auth/v4/sessions/") && r.Method == http.MethodDelete:
		uid := strings.TrimPrefix(p, "/auth/v4/sessions/")
		f.revoked = append(f.revoked, uid)
		f.revokes[uid]++
		if f.onRevoke != nil {
			f.onRevoke(uid)
		}
		if f.forkDiesWithParent && strings.HasPrefix(uid, "anon-") {
			f.childDead = true
		}
		if f.revokeCode == dropConnection {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				f.t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		switch f.revokeCode {
		case 200:
		case 401:
			// What Proton answers a token it no longer accepts; the refresh that
			// follows is refused too, so the client reports ErrUnauthorized.
			f.reply(w, 401, map[string]any{"Code": 401, "Error": "Invalid access token"})
			return
		default:
			f.reply(w, f.revokeCode, map[string]any{"Code": 2000, "Error": "refused"})
			return
		}
		f.reply(w, 200, map[string]any{"Code": 1000})
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, p)
		f.reply(w, 404, map[string]any{"Code": 2501, "Error": "no such route"})
	}
}

func (f *fakeProton) approve(code string) {
	c, err := fork.Parse(code)
	if err != nil {
		f.t.Fatalf("the code does not parse: %v", err)
	}
	f.mu.Lock()
	f.code, f.approved = c, true
	f.mu.Unlock()
}

func (f *fakeProton) revokedUIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

type clock struct{ now atomic.Int64 }

func (c *clock) Now() time.Time          { return time.Unix(c.now.Load(), 0) }
func (c *clock) advance(d time.Duration) { c.now.Add(int64(d.Seconds())) }

func newLogin(t *testing.T, f *fakeProton, clk *clock) *Login {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	l, err := New(Config{BaseURL: f.srv.URL, AppVersion: "Other", Now: clk.Now, NewSubject: func() string { return "u0123456789abcdef" }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func newClock() *clock {
	c := &clock{}
	c.now.Store(1_800_000_000)
	return c
}

func sessionFile(t *testing.T, subject string) string {
	t.Helper()
	p, err := session.Path(profile.MustParse(subject))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStartReturnsACodeAPersonCanApprove(t *testing.T) {
	f := newFake(t)
	clk := newClock()
	l := newLogin(t, f, clk)
	a, err := l.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if a.ID == "" {
		t.Error("the attempt has no id")
	}
	code, err := fork.Parse(a.Code)
	if err != nil {
		t.Fatalf("the code does not parse: %v", err)
	}
	if code.UserCode != "ABCD1234" || len(code.Key) == 0 {
		t.Errorf("code = %+v, want the user code Proton issued and a key", code)
	}
	if want := clk.Now().Add(9 * time.Minute); !a.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", a.ExpiresAt, want)
	}
}

func TestCheckIsWaitingThenApprovedAndSavesAnUnlockedSession(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	ctx := context.Background()
	a, err := l.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	st, err := l.Check(ctx, a.ID)
	if err != nil || st.State != mcpauth.Waiting {
		t.Fatalf("Check = %+v, %v; want Waiting", st, err)
	}
	if _, err := os.Stat(sessionFile(t, "u0123456789abcdef")); !os.IsNotExist(err) {
		t.Fatalf("a session was saved before approval: %v", err)
	}

	f.approve(a.Code)
	st, err = l.Check(ctx, a.ID)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if st.State != mcpauth.Approved || st.Subject != "u0123456789abcdef" {
		t.Fatalf("Check = %+v, want Approved as u0123456789abcdef", st)
	}

	path := sessionFile(t, st.Subject)
	if !strings.HasPrefix(path, os.Getenv("XDG_CONFIG_HOME")) {
		t.Errorf("session at %s, want it under XDG_CONFIG_HOME", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the session file is missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	sess, err := session.Load(profile.MustParse(st.Subject))
	if err != nil || sess == nil {
		t.Fatalf("Load = %v, %v", sess, err)
	}
	if !sess.Unlocked() {
		t.Error("the session was saved locked: EncKeyBlob is empty")
	}
	if sess.UID != "child-uid" || sess.AccessToken != "child-access" || sess.RefreshToken != "child-refresh" {
		t.Errorf("the session holds %q/%q/%q, want the forked one", sess.UID, sess.AccessToken, sess.RefreshToken)
	}
	if sess.UserID != "user-id" || sess.Email != "someone@proton.me" {
		t.Errorf("identity = %q %q", sess.UserID, sess.Email)
	}
	// The blob opens with the client key Proton holds, and holds the key password.
	got, err := localkey.Unwrap(sess.EncKeyBlob, f.clientKey)
	if err != nil || got != keyPassword {
		t.Errorf("sealed key password = %q, %v; want the one the approval carried", got, err)
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1})
}

func TestCheckAfterApprovalIsIdempotent(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	ctx := context.Background()
	a, _ := l.Start(ctx)
	f.approve(a.Code)
	first, err := l.Check(ctx, a.ID)
	if err != nil || first.State != mcpauth.Approved {
		t.Fatalf("Check = %+v, %v", first, err)
	}
	before, err := os.ReadFile(sessionFile(t, first.Subject))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.approved = false // a redo would now see "waiting", and so fail
	f.mu.Unlock()

	second, err := l.Check(ctx, a.ID)
	if err != nil || second != first {
		t.Errorf("second Check = %+v, %v; want %+v", second, err, first)
	}
	after, _ := os.ReadFile(sessionFile(t, first.Subject))
	if string(before) != string(after) {
		t.Error("the second Check rewrote the session")
	}
}

func TestAnExpiredAttemptFailsAndStaysFailed(t *testing.T) {
	f := newFake(t)
	clk := newClock()
	l := newLogin(t, f, clk)
	ctx := context.Background()
	a, _ := l.Start(ctx)
	clk.advance(9*time.Minute + time.Second)
	f.approve(a.Code) // too late

	st, err := l.Check(ctx, a.ID)
	if err != nil || st.State != mcpauth.Failed || st.Message == "" {
		t.Fatalf("Check = %+v, %v; want Failed with a message", st, err)
	}
	if _, err := os.Stat(sessionFile(t, "u0123456789abcdef")); !os.IsNotExist(err) {
		t.Errorf("an expired attempt saved a session: %v", err)
	}
	again, _ := l.Check(ctx, a.ID)
	if again != st {
		t.Errorf("Check again = %+v, want %+v", again, st)
	}
}

func TestUnknownAttemptFails(t *testing.T) {
	l := newLogin(t, newFake(t), newClock())
	st, err := l.Check(context.Background(), "nope")
	if err != nil || st.State != mcpauth.Failed || st.Message == "" {
		t.Errorf("Check = %+v, %v; want Failed", st, err)
	}
}

func TestAnApprovalWithoutKeysFailsAndRevokesTheSession(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	ctx := context.Background()
	a, _ := l.Start(ctx)
	// An approval that sealed nothing: the code with its key removed seals "".
	code, _ := fork.Parse(a.Code)
	f.mu.Lock()
	f.code, f.approved = fork.Code{UserCode: code.UserCode, ClientID: code.ClientID}, true
	f.mu.Unlock()

	st, err := l.Check(ctx, a.ID)
	if err != nil || st.State != mcpauth.Failed {
		t.Fatalf("Check = %+v, %v; want Failed", st, err)
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"child-uid": 1, "anon-1": 1})
	if _, err := os.Stat(sessionFile(t, "u0123456789abcdef")); !os.IsNotExist(err) {
		t.Errorf("a locked session was saved: %v", err)
	}
}

func TestStatusAndLogsNeverCarrySecrets(t *testing.T) {
	f := newFake(t)
	var logs syncBuilder
	l := newLogin(t, f, newClock())
	l.cfg.Logger = newDebugLogger(&logs)
	ctx := context.Background()
	a, _ := l.Start(ctx)
	f.approve(a.Code)
	st, _ := l.Check(ctx, a.ID)
	l.revokes.Wait()
	code, _ := fork.Parse(a.Code)
	for _, secret := range []string{keyPassword, "child-access", "child-refresh", "anon-access", "anon-refresh", base64.StdEncoding.EncodeToString(code.Key)} {
		if strings.Contains(logs.String(), secret) || strings.Contains(st.Message, secret) {
			t.Errorf("a secret leaked into the logs or the status")
		}
	}
}

func TestForgetRevokesOnceAndDeletesEverything(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	ctx := context.Background()
	a, _ := l.Start(ctx)
	f.approve(a.Code)
	st, _ := l.Check(ctx, a.ID)
	name := profile.MustParse(st.Subject)

	cfg := os.Getenv("XDG_CONFIG_HOME")
	extra := []string{
		filepath.Join(cfg, "proton-cli", "idcache", st.Subject+".json"),
		filepath.Join(cfg, "proton-cli", "index", st.Subject, "x"),
	}
	for _, p := range extra {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1})
	if err := l.Forget(ctx, st.Subject); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1, "child-uid": 1})
	if s, err := session.Load(name); err != nil || s != nil {
		t.Errorf("session after Forget = %v, %v", s, err)
	}
	for _, p := range extra {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived Forget: %v", p, err)
		}
	}

	if err := l.Forget(ctx, st.Subject); err != nil {
		t.Errorf("second Forget: %v", err)
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1, "child-uid": 1})
	if err := l.Forget(ctx, "ueeeeeeeeeeeeeeee"); err != nil {
		t.Errorf("Forget of an unknown subject: %v", err)
	}
}

// signedIn runs one approved sign-in and returns its subject, once the revoke of
// the anonymous session it was opened under is over.
func signedIn(t *testing.T, f *fakeProton, l *Login) string {
	t.Helper()
	ctx := context.Background()
	a, err := l.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.approve(a.Code)
	st, err := l.Check(ctx, a.ID)
	if err != nil || st.State != mcpauth.Approved {
		t.Fatalf("Check = %+v, %v; want Approved", st, err)
	}
	l.revokes.Wait()
	return st.Subject
}

func (f *fakeProton) setRevokeCode(code int) {
	f.mu.Lock()
	f.revokeCode = code
	f.mu.Unlock()
}

// Only an answer that says the session no longer exists lets Forget delete what
// would be needed to revoke it later.
func TestForgetDeletesTheFilesOnlyWhenTheSessionIsGone(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		gone bool
	}{
		{"401: refused and not refreshable", 401, true},
		{"404", 404, true},
		{"400", 400, false},
		{"403", 403, false},
		{"409", 409, false},
		{"422", 422, false},
		{"500", 500, false},
		{"503", 503, false},
		{"no answer", dropConnection, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			l := newLogin(t, f, newClock())
			ctx := context.Background()
			subject := signedIn(t, f, l)
			name := profile.MustParse(subject)
			f.setRevokeCode(tc.code)

			err := l.Forget(ctx, subject)
			s, _ := session.Load(name)
			if tc.gone {
				if err != nil || s != nil {
					t.Fatalf("Forget = %v, session kept = %v; want the files deleted", err, s != nil)
				}
				return
			}
			if err == nil {
				t.Fatal("Forget succeeded though the session was not revoked")
			}
			if s == nil {
				t.Fatal("the session was deleted, so the revoke can never be retried")
			}

			// Proton recovers: the retry revokes it and deletes the files.
			f.setRevokeCode(200)
			if err := l.Forget(ctx, subject); err != nil {
				t.Fatalf("retried Forget: %v", err)
			}
			if s, _ := session.Load(name); s != nil {
				t.Error("the session survived a Forget that revoked it")
			}
			if got := f.revokeCounts(l)["child-uid"]; got != 2 {
				t.Errorf("the subject's session was revoked %d times, want 2", got)
			}
			// And a Forget of a subject that is no longer there asks Proton nothing.
			if err := l.Forget(ctx, subject); err != nil {
				t.Errorf("Forget after the files are gone: %v", err)
			}
			if got := f.revokeCounts(l)["child-uid"]; got != 2 {
				t.Errorf("a Forget of a forgotten subject revoked again (%d)", got)
			}
		})
	}
}

// A revoke that keeps failing is retried for ever, since the files are the only
// way to revoke later, and the operator is told to step in every
// forgetWarnEvery failures in a row.
func TestForgetWarnsWhenTheRevokeKeepsFailing(t *testing.T) {
	f := newFake(t)
	var logs syncBuilder
	l := newLogin(t, f, newClock())
	l.cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx := context.Background()
	subject := signedIn(t, f, l)
	f.setRevokeCode(403)

	for i := 1; i < forgetWarnEvery; i++ {
		if err := l.Forget(ctx, subject); err == nil {
			t.Fatal("Forget succeeded")
		}
	}
	if got := logs.String(); got != "" {
		t.Fatalf("warned before %d failures: %s", forgetWarnEvery, got)
	}
	if err := l.Forget(ctx, subject); err == nil {
		t.Fatal("Forget succeeded")
	}
	got := logs.String()
	if strings.Count(got, "level=WARN") != 1 || !strings.Contains(got, "revoke it by hand") || !strings.Contains(got, subject) {
		t.Errorf("after %d failures the log is %q, want one warning naming the subject", forgetWarnEvery, got)
	}
	for _, secret := range []string{"child-access", "child-refresh", "child-uid"} {
		if strings.Contains(got, secret) {
			t.Errorf("the warning carries %q", secret)
		}
	}
	if s, _ := session.Load(profile.MustParse(subject)); s == nil {
		t.Fatal("the session files were deleted after repeated failures")
	}

	// Success resets the count and removes the files.
	f.setRevokeCode(200)
	if err := l.Forget(ctx, subject); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if n := len(l.forgetFailures); n != 0 {
		t.Errorf("%d subjects still counted after a successful Forget", n)
	}
}

// syncBuilder is a strings.Builder the background revokes may log to.
type syncBuilder struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuilder) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuilder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestForgetRefusesTheDefaultProfile(t *testing.T) {
	l := newLogin(t, newFake(t), newClock())
	for _, s := range []string{"", "default", "../x"} {
		if err := l.Forget(context.Background(), s); err == nil {
			t.Errorf("Forget(%q) succeeded", s)
		}
	}
}

func TestConcurrentStartsDoNotRace(t *testing.T) {
	f := newFake(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	l, err := New(Config{BaseURL: f.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	const n = 20
	ids := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := l.Start(context.Background())
			if err != nil {
				t.Errorf("Start: %v", err)
				return
			}
			ids <- a.ID
			if _, err := l.Check(context.Background(), a.ID); err != nil {
				t.Errorf("Check: %v", err)
			}
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Errorf("duplicate attempt id %q", id)
		}
		seen[id] = true
	}
	if len(seen) != n {
		t.Errorf("got %d attempts, want %d", len(seen), n)
	}
}

func TestAttemptsAreCappedAndExpiredOnesPurged(t *testing.T) {
	f := newFake(t)
	clk := newClock()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	l, err := New(Config{BaseURL: f.srv.URL, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < maxAttempts; i++ {
		if _, err := l.Start(ctx); err != nil {
			t.Fatalf("Start %d: %v", i, err)
		}
	}
	if _, err := l.Start(ctx); err == nil {
		t.Fatal("Start past the cap succeeded")
	}
	clk.advance(9*time.Minute + retention + time.Second)
	if _, err := l.Start(ctx); err != nil {
		t.Fatalf("Start after expiry: %v", err)
	}
	if got := len(l.attempts); got != 1 {
		t.Errorf("%d attempts held, want the expired ones purged", got)
	}
}

func TestDefaultSubjectIsAValidProfileName(t *testing.T) {
	for i := 0; i < 50; i++ {
		s := randomSubject()
		if len(s) != 17 || s[0] != 'u' {
			t.Fatalf("subject %q, want u + 16 hex", s)
		}
		if _, err := profile.Parse(s); err != nil {
			t.Fatalf("subject %q is not a profile name: %v", s, err)
		}
	}
}

func newDebugLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// leaks reports the sessions Proton opened that were never revoked, once the
// background revokes have finished.
func (f *fakeProton) leaks(l *Login) []string {
	l.revokes.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, uid := range f.opened {
		if f.revokes[uid] == 0 {
			out = append(out, uid)
		}
	}
	return out
}

// revokeCounts is every revoke seen per session id, after the background ones
// have finished.
func (f *fakeProton) revokeCounts(l *Login) map[string]int {
	l.revokes.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for k, v := range f.revokes {
		out[k] = v
	}
	return out
}

func wantRevokes(t *testing.T, got map[string]int, want map[string]int) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("revokes = %v, want %v", got, want)
		return
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("revokes = %v, want %v", got, want)
			return
		}
	}
}

func TestAFailedForkRevokesTheSessionItOpenedUnder(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	f.failFork = 400
	if _, err := l.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded though Proton refused the fork")
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1})
	if got := len(l.attempts); got != 0 {
		t.Errorf("%d attempts held after a failed Start", got)
	}
}

func TestAMalformedCodeRevokesTheSessionItOpenedUnder(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	l.newCode = func(string, string) (fork.Code, error) { return fork.Code{}, errors.New("malformed user code") }
	if _, err := l.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded with a code that could not be made")
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1})
}

func TestTheCapIsCheckedBeforeAnySessionIsOpened(t *testing.T) {
	f := newFake(t)
	clk := newClock()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	l, err := New(Config{BaseURL: f.srv.URL, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < maxAttempts; i++ {
		if _, err := l.Start(ctx); err != nil {
			t.Fatalf("Start %d: %v", i, err)
		}
	}
	// Racing past the cap: none of these may open a session.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Start(ctx); err == nil {
				t.Error("Start past the cap succeeded")
			}
		}()
	}
	wg.Wait()
	f.mu.Lock()
	opened := len(f.opened)
	f.mu.Unlock()
	if opened != maxAttempts {
		t.Errorf("%d sessions opened, want %d: a refused Start opened one", opened, maxAttempts)
	}
	if got := f.revokeCounts(l); len(got) != 0 {
		t.Errorf("revoked %v while every attempt is live", got)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := f.leaks(l); len(got) != 0 {
		t.Errorf("leaked sessions after Close: %v", got)
	}
}

func TestAnExpiredAttemptIsRevokedOnceWhenPurged(t *testing.T) {
	f := newFake(t)
	clk := newClock()
	l := newLogin(t, f, clk)
	ctx := context.Background()
	a, _ := l.Start(ctx)
	if got := f.revokeCounts(l); len(got) != 0 {
		t.Fatalf("revoked %v while the code is valid", got)
	}
	clk.advance(9*time.Minute + time.Second)
	// Nobody polls it: the next Start purges it.
	if _, err := l.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1})

	// Neither a later poll nor a later purge revokes it again, and the person who
	// polls learns the code expired.
	st, err := l.Check(ctx, a.ID)
	if err != nil || st.State != mcpauth.Failed || st.Message != expiredMessage {
		t.Errorf("Check = %+v, %v; want Failed: expired", st, err)
	}
	clk.advance(retention)
	if _, err := l.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1, "anon-2": 1})
}

func TestAnExpiredAttemptIsRevokedWhenPolled(t *testing.T) {
	f := newFake(t)
	clk := newClock()
	l := newLogin(t, f, clk)
	ctx := context.Background()
	a, _ := l.Start(ctx)
	clk.advance(9*time.Minute + time.Second)
	for i := 0; i < 3; i++ {
		if st, _ := l.Check(ctx, a.ID); st.State != mcpauth.Failed {
			t.Fatalf("Check = %+v, want Failed", st)
		}
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1})
}

func TestAPermanentErrorOnThePullRevokesTheSession(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	ctx := context.Background()
	a, _ := l.Start(ctx)
	f.mu.Lock()
	f.pullCode = 404
	f.mu.Unlock()
	for i := 0; i < 2; i++ {
		if st, err := l.Check(ctx, a.ID); err != nil || st.State != mcpauth.Failed {
			t.Fatalf("Check = %+v, %v; want Failed", st, err)
		}
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1})
}

func TestATransientErrorOnThePullKeepsTheSession(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	ctx := context.Background()
	a, _ := l.Start(ctx)
	f.mu.Lock()
	f.pullCode = 429
	f.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if st, err := l.Check(cctx, a.ID); err == nil && st.State == mcpauth.Failed {
		t.Fatalf("Check = %+v, want the attempt kept", st)
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{})
}

func TestAnApprovalThatCannotBeFinishedRevokesTheIssuedSessionOnce(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	ctx := context.Background()
	a, _ := l.Start(ctx)
	code, _ := fork.Parse(a.Code)
	f.mu.Lock()
	f.code, f.approved = fork.Code{UserCode: code.UserCode, ClientID: code.ClientID}, true
	f.mu.Unlock()
	for i := 0; i < 3; i++ {
		if st, err := l.Check(ctx, a.ID); err != nil || st.State != mcpauth.Failed {
			t.Fatalf("Check = %+v, %v; want Failed", st, err)
		}
	}
	// Another purge, and a Close, find the attempt already ended.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"child-uid": 1, "anon-1": 1})
}

func TestAnApprovedAttemptIsNeverRevoked(t *testing.T) {
	f := newFake(t)
	clk := newClock()
	l := newLogin(t, f, clk)
	ctx := context.Background()
	a, _ := l.Start(ctx)
	f.approve(a.Code)
	if st, err := l.Check(ctx, a.ID); err != nil || st.State != mcpauth.Approved {
		t.Fatalf("Check = %+v, %v; want Approved", st, err)
	}
	clk.advance(9*time.Minute + retention + time.Second)
	if _, err := l.Start(ctx); err != nil { // purges the approved attempt
		t.Fatalf("Start: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// The second Start opened anon-2, which Close revokes. anon-1 is revoked once,
	// on approval, and neither the purge nor Close revokes it again.
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1, "anon-2": 1})
	if s, err := session.Load(profile.MustParse("u0123456789abcdef")); err != nil || s == nil {
		t.Errorf("the subject's session is gone: %v, %v", s, err)
	}
}

func TestCloseRevokesEveryLiveAttemptAndWaits(t *testing.T) {
	f := newFake(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	l, err := New(Config{BaseURL: f.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const n = 5
	for i := 0; i < n; i++ {
		if _, err := l.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close has waited: no further synchronisation before reading the fake.
	f.mu.Lock()
	got := map[string]int{}
	for k, v := range f.revokes {
		got[k] = v
	}
	f.mu.Unlock()
	want := map[string]int{}
	for i := 1; i <= n; i++ {
		want[fmt.Sprintf("anon-%d", i)] = 1
	}
	wantRevokes(t, got, want)
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := l.Start(ctx); err == nil {
		t.Error("Start after Close succeeded")
	}
	wantRevokes(t, f.revokeCounts(l), want)
}

func TestConcurrentStartCheckAndPurgeNeverRevokeTwice(t *testing.T) {
	f := newFake(t)
	clk := newClock()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	l, err := New(Config{BaseURL: f.srv.URL, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := l.Start(ctx)
			if err != nil {
				t.Errorf("Start: %v", err)
				return
			}
			var inner sync.WaitGroup
			for j := 0; j < 3; j++ {
				inner.Add(1)
				go func() {
					defer inner.Done()
					_, _ = l.Check(ctx, a.ID)
				}()
			}
			clk.advance(10 * time.Second)
			inner.Wait()
		}()
	}
	wg.Wait()
	clk.advance(9*time.Minute + time.Second)
	var closers sync.WaitGroup
	for i := 0; i < 3; i++ {
		closers.Add(2)
		go func() { defer closers.Done(); _, _ = l.Check(ctx, "x"); _, _ = l.Start(ctx) }()
		go func() { defer closers.Done(); _ = l.Close() }()
	}
	closers.Wait()
	_ = l.Close()
	counts := f.revokeCounts(l)
	for uid, c := range counts {
		if c != 1 {
			t.Errorf("session %s revoked %d times", uid, c)
		}
	}
	if got := f.leaks(l); len(got) != 0 {
		t.Errorf("leaked sessions: %v", got)
	}
}

// The anonymous session an approved sign-in was opened under is nobody's: it is
// revoked once, after the subject's session is saved, and the subject's session
// is never touched.
func TestAnApprovedSignInRevokesItsAnonymousSessionOnceAfterSaving(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	var savedFirst atomic.Bool
	f.onRevoke = func(uid string) {
		if uid != "anon-1" {
			return
		}
		s, err := session.Load(profile.MustParse("u0123456789abcdef"))
		savedFirst.Store(err == nil && s != nil && s.Unlocked() && s.UID == "child-uid")
	}
	ctx := context.Background()
	a, _ := l.Start(ctx)
	f.approve(a.Code)
	if st, err := l.Check(ctx, a.ID); err != nil || st.State != mcpauth.Approved {
		t.Fatalf("Check = %+v, %v; want Approved", st, err)
	}
	for i := 0; i < 3; i++ {
		_, _ = l.Check(ctx, a.ID)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1})
	if !savedFirst.Load() {
		t.Error("the anonymous session was revoked before the subject's session was saved")
	}
	if s, err := session.Load(profile.MustParse("u0123456789abcdef")); err != nil || s == nil || s.UID != "child-uid" {
		t.Errorf("the subject's session after the revoke = %v, %v", s, err)
	}
}

func TestKeepAnonymousSessionRevokesNothingOnApproval(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	l.cfg.KeepAnonymousSession = true
	signedIn(t, f, l)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	wantRevokes(t, f.revokeCounts(l), map[string]int{})

	// Every other end still revokes it.
	f2 := newFake(t)
	l2 := newLogin(t, f2, newClock())
	l2.cfg.KeepAnonymousSession = true
	if _, err := l2.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	wantRevokes(t, f2.revokeCounts(l2), map[string]int{"anon-1": 1})
}

// If Proton ends the forked session with its parent, the server says so and
// names the flag that avoids it. It does not try to undo anything.
func TestARevokeThatEndsTheNewSessionIsReported(t *testing.T) {
	for _, dies := range []bool{false, true} {
		t.Run(fmt.Sprintf("fork dies with parent: %v", dies), func(t *testing.T) {
			f := newFake(t)
			f.forkDiesWithParent = dies
			var logs syncBuilder
			l := newLogin(t, f, newClock())
			l.cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
			subject := signedIn(t, f, l)
			got := logs.String()
			warned := strings.Contains(got, "-keep-anonymous-session") && strings.Contains(got, subject)
			if warned != dies {
				t.Errorf("warned = %v, want %v; log: %q", warned, dies, got)
			}
			for _, secret := range []string{"child-access", "child-refresh", "anon-access", "anon-refresh", keyPassword} {
				if strings.Contains(got, secret) {
					t.Errorf("the log carries %q", secret)
				}
			}
			wantRevokes(t, f.revokeCounts(l), map[string]int{"anon-1": 1})
		})
	}
}

// A refused read right after the anonymous parent is revoked is only a sign that
// Proton ended the child when the subject was not forgotten on purpose. A consent
// that is denied forgets the subject while the probe may still be in flight, and
// that revocation is this server's own doing: no warning for it.
func TestADeniedConsentDoesNotWarnAboutTheParentRevoke(t *testing.T) {
	f := newFake(t)
	f.forkDiesWithParent = true // the probe will be refused, as in the real case the warning is for
	var logs syncBuilder
	l := newLogin(t, f, newClock())
	l.cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// The subject is forgotten (consent denied) the moment the anonymous parent's
	// revoke is seen, before the probe's answer is judged.
	f.onRevoke = func(uid string) {
		if strings.HasPrefix(uid, "anon-") {
			l.mu.Lock()
			l.forgotten["u0123456789abcdef"] = l.cfg.Now()
			l.mu.Unlock()
		}
	}
	signedIn(t, f, l)
	if got := logs.String(); strings.Contains(got, "-keep-anonymous-session") {
		t.Errorf("warned about a session this server revoked on purpose: %q", got)
	}
}

// Forget marks the subject before it touches Proton, so the probe sees it even if
// it runs first.
func TestForgetMarksTheSubjectBeforeRevoking(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	subject := signedIn(t, f, l)
	if l.wasForgotten(subject) {
		t.Fatal("a subject that was never forgotten is marked")
	}
	if err := l.Forget(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
	if !l.wasForgotten(subject) {
		t.Error("Forget did not mark the subject")
	}
}
