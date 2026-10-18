package protonlogin

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
}

func newFake(t *testing.T) *fakeProton {
	t.Helper()
	f := &fakeProton{t: t, revokeCode: 200}
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
		f.reply(w, 200, map[string]any{"Code": 1000, "UID": "anon-uid", "AccessToken": "anon-access", "RefreshToken": "anon-refresh"})
	case p == "/auth/v4/sessions/forks" && r.Method == http.MethodGet:
		f.forks++
		f.reply(w, 200, map[string]any{"Code": 1000, "Selector": "selector-1", "UserCode": "ABCD1234"})
	case p == "/auth/v4/sessions/forks/selector-1":
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
		f.revoked = append(f.revoked, strings.TrimPrefix(p, "/auth/v4/sessions/"))
		if f.revokeCode != 200 {
			f.reply(w, f.revokeCode, map[string]any{"Code": 10013, "Error": "session gone"})
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
	if len(f.revokedUIDs()) != 0 {
		t.Errorf("revoked %v on a good login", f.revokedUIDs())
	}
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
	if got := f.revokedUIDs(); len(got) != 1 || got[0] != "child-uid" {
		t.Errorf("revoked %v, want the issued child session", got)
	}
	if _, err := os.Stat(sessionFile(t, "u0123456789abcdef")); !os.IsNotExist(err) {
		t.Errorf("a locked session was saved: %v", err)
	}
}

func TestStatusAndLogsNeverCarrySecrets(t *testing.T) {
	f := newFake(t)
	var logs strings.Builder
	l := newLogin(t, f, newClock())
	l.cfg.Logger = newDebugLogger(&logs)
	ctx := context.Background()
	a, _ := l.Start(ctx)
	f.approve(a.Code)
	st, _ := l.Check(ctx, a.ID)
	code, _ := fork.Parse(a.Code)
	for _, secret := range []string{keyPassword, "child-access", "child-refresh", base64.StdEncoding.EncodeToString(code.Key)} {
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

	if err := l.Forget(ctx, st.Subject); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if got := f.revokedUIDs(); len(got) != 1 || got[0] != "child-uid" {
		t.Errorf("revoked %v, want exactly the subject's session once", got)
	}
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
	if got := f.revokedUIDs(); len(got) != 1 {
		t.Errorf("the second Forget revoked again: %v", got)
	}
	if err := l.Forget(ctx, "ueeeeeeeeeeeeeeee"); err != nil {
		t.Errorf("Forget of an unknown subject: %v", err)
	}
}

func TestForgetToleratesASessionProtonAlreadyRevoked(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	ctx := context.Background()
	a, _ := l.Start(ctx)
	f.approve(a.Code)
	st, _ := l.Check(ctx, a.ID)
	f.mu.Lock()
	f.revokeCode = 422
	f.mu.Unlock()
	if err := l.Forget(ctx, st.Subject); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if s, _ := session.Load(profile.MustParse(st.Subject)); s != nil {
		t.Error("the session survived")
	}
}

func TestForgetKeepsTheSessionWhenProtonCannotBeReached(t *testing.T) {
	f := newFake(t)
	l := newLogin(t, f, newClock())
	ctx := context.Background()
	a, _ := l.Start(ctx)
	f.approve(a.Code)
	st, _ := l.Check(ctx, a.ID)
	f.mu.Lock()
	f.revokeCode = 503
	f.mu.Unlock()
	if err := l.Forget(ctx, st.Subject); err == nil {
		t.Fatal("Forget succeeded though the revoke failed")
	}
	if s, _ := session.Load(profile.MustParse(st.Subject)); s == nil {
		t.Error("the session was deleted, so the revoke can never be retried")
	}
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

func newDebugLogger(w *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
