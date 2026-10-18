// Package protonlogin is the Proton side of the MCP server's OAuth login: the
// "sign in with another device" fork, driven one non-blocking step at a time so a
// web page can poll it.
//
// A person is shown a code, approves it in a Proton app they are already signed
// in on, and what this package keeps is a saved session under a subject name of
// its own - never the account password, which nothing here ever sees. Everything
// about the fork itself (the code, the payload, adopting the session, sealing the
// key password) is the CLI's own: this package only holds attempts in memory and
// names the profile the result is saved under.
package protonlogin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/roman-16/proton-cli/internal/account/fork"
	"github.com/roman-16/proton-cli/internal/account/session"
	"github.com/roman-16/proton-cli/internal/app"
	"github.com/roman-16/proton-cli/internal/mcpauth"
	"github.com/roman-16/proton-cli/internal/profile"
	"github.com/roman-16/proton-cli/internal/proton"
	"github.com/roman-16/proton-cli/internal/service/account"
)

var (
	_ mcpauth.Login = (*Login)(nil)
	// Close is an addition to mcpauth.Login, not part of it: a caller that owns
	// the Login closes it at shutdown if it can.
	_ io.Closer = (*Login)(nil)
)

const (
	// defaultTTL is how long Proton's own sign-in screen keeps a code.
	defaultTTL = 9 * time.Minute
	// maxAttempts bounds what a caller that never finishes can make this hold.
	maxAttempts = 200
	// retention is how long a finished or expired attempt is still answered, so a
	// page that polls once more after the end learns the end rather than "unknown".
	retention = 10 * time.Minute
	// revokeTimeout bounds one best-effort revoke of a session nobody will use.
	revokeTimeout = 10 * time.Second
	// forgetWarnEvery is how many failed revokes in a row of one subject's session
	// pass before the operator is told to revoke it by hand, and again after each
	// as many more.
	forgetWarnEvery = 10
)

// Config is what New needs; every field has a default.
type Config struct {
	// BaseURL is the Proton API, defaulting to Proton's.
	BaseURL    string
	AppVersion string
	Now        func() time.Time
	// NewSubject names the session a login leaves behind. It must return a valid
	// profile name that is not empty and not "default".
	NewSubject func() string
	TTL        time.Duration
	Logger     *slog.Logger
	// KeepAnonymousSession leaves the anonymous session a sign-in was opened under
	// standing when the sign-in is approved, instead of revoking it. It is an
	// escape hatch: whether Proton ends the session the fork issued along with the
	// one it was forked from has not been seen against the real service, and if it
	// does, every approved sign-in would die at once. Every end but Approved
	// revokes the anonymous session either way.
	KeepAnonymousSession bool
}

// Login implements mcpauth.Login against Proton.
type Login struct {
	cfg Config

	// newCode makes the fork code; fork.New, except in tests.
	newCode func(userCode, clientID string) (fork.Code, error)

	// mu guards attempts, closed and forgetFailures. When both are needed it is
	// taken after an attempt's own mutex, never before - except by purgeLocked,
	// which only ever TryLocks an attempt.
	mu       sync.Mutex
	attempts map[string]*attempt
	closed   bool
	// forgetFailures counts, per subject, the Forgets in a row whose revoke failed.
	forgetFailures map[string]int
	// revokes tracks the background revokes, so Close (and tests) can wait.
	revokes sync.WaitGroup
}

// attempt is one code on screen. Its own mutex serialises the polls of one
// attempt, so two tabs asking at once cannot finish the same fork twice.
//
// Every attempt owns a session at Proton from the moment Start opens it, and it
// must leave that session in exactly one of two places: with the subject, if the
// attempt ended Approved, or revoked. status is the once-only guard for that: it
// is set, under mu, by the one call that ends the attempt, and that call is the
// one that decides.
type attempt struct {
	mu       sync.Mutex
	client   *proton.Client
	selector string
	code     fork.Code
	subject  profile.Name
	// anon is the anonymous session the fork was opened under, set aside when an
	// approved fork makes client take up the session it issued. It is never the
	// subject's: every end revokes it, Approved included unless
	// Config.KeepAnonymousSession says otherwise.
	anon *proton.Client
	// expires is fixed when the attempt is made and never written again, so
	// purgeLocked may read it without mu.
	expires time.Time
	// status is set once the attempt has ended, and is then the answer for ever.
	status *mcpauth.Status
}

// New builds a Login.
func New(cfg Config) (*Login, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = proton.DefaultBaseURL
	}
	if cfg.AppVersion == "" {
		cfg.AppVersion = proton.DefaultAppVersion
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.NewSubject == nil {
		cfg.NewSubject = randomSubject
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Login{cfg: cfg, newCode: fork.New, attempts: map[string]*attempt{}, forgetFailures: map[string]int{}}, nil
}

func randomSubject() string { return "u" + randomHex(8) }

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("protonlogin: no randomness: %v", err))
	}
	return hex.EncodeToString(b)
}

// subjectName validates a subject as the profile it names. The empty name and
// "default" are refused: parsed they are the person's own default profile, and a
// login or a forget must never touch that.
func subjectName(subject string) (profile.Name, error) {
	if subject == "" || subject == profile.Default {
		return profile.Name{}, fmt.Errorf("%q is not a subject", subject)
	}
	return profile.Parse(subject)
}

func (l *Login) newClient(name profile.Name) *proton.Client {
	return proton.New(proton.Options{
		BaseURL: l.cfg.BaseURL, AppVersion: l.cfg.AppVersion,
		Profile: name.String(), Logger: l.cfg.Logger,
	})
}

// Start opens a fork on a client of its own and returns the code to show.
//
// The attempt takes its place under the cap before anything reaches Proton, so
// the cap cannot be lost after a session was opened. From then on it holds its
// own mutex until it is complete: nobody can poll, purge or close a half-built
// attempt, and every failure ends it through the same path as any other end,
// which revokes the session if one was opened.
func (l *Login) Start(ctx context.Context) (mcpauth.Attempt, error) {
	subject, err := subjectName(l.cfg.NewSubject())
	if err != nil {
		return mcpauth.Attempt{}, fmt.Errorf("protonlogin: new subject: %w", err)
	}
	c := l.newClient(subject)
	a := &attempt{client: c, subject: subject, expires: l.cfg.Now().Add(l.cfg.TTL)}
	a.mu.Lock()
	defer a.mu.Unlock()
	id := randomHex(16)

	l.mu.Lock()
	switch {
	case l.closed:
		l.mu.Unlock()
		return mcpauth.Attempt{}, errors.New("protonlogin: shut down")
	default:
		l.purgeLocked()
		if len(l.attempts) >= maxAttempts {
			l.mu.Unlock()
			return mcpauth.Attempt{}, errors.New("protonlogin: too many sign-ins in progress")
		}
	}
	l.attempts[id] = a
	l.mu.Unlock()

	// fail takes the attempt back out and ends it, revoking what was opened.
	fail := func(err error) (mcpauth.Attempt, error) {
		l.mu.Lock()
		delete(l.attempts, id)
		l.endLocked(a, failed("The sign-in could not be started."))
		l.mu.Unlock()
		return mcpauth.Attempt{}, err
	}

	if err := c.AnonymousSession(ctx); err != nil {
		return fail(fmt.Errorf("protonlogin: open a session: %w", err))
	}
	opened, err := c.NewFork(ctx)
	if err != nil {
		return fail(fmt.Errorf("protonlogin: open a fork: %w", err))
	}
	code, err := l.newCode(opened.UserCode, c.AppVersion())
	if err != nil {
		return fail(err)
	}
	a.selector, a.code = opened.Selector, code

	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return fail(errors.New("protonlogin: shut down"))
	}
	l.cfg.Logger.Debug("sign-in started", "attempt", id)
	return mcpauth.Attempt{ID: id, Code: code.String(), ExpiresAt: a.expires}, nil
}

// purgeLocked ends the attempts whose code has run out, which revokes their
// session, and forgets them once nobody is likely to ask about them any more. An
// attempt somebody is working on is left for a later purge.
func (l *Login) purgeLocked() {
	now := l.cfg.Now()
	for id, a := range l.attempts {
		if now.Before(a.expires) || !a.mu.TryLock() {
			continue
		}
		l.endLocked(a, failed(expiredMessage))
		a.mu.Unlock()
		if now.After(a.expires.Add(retention)) {
			delete(l.attempts, id)
		}
	}
}

func (l *Login) find(id string) *attempt {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.purgeLocked()
	return l.attempts[id]
}

const expiredMessage = "The code expired. Start again."

func failed(msg string) mcpauth.Status { return mcpauth.Status{State: mcpauth.Failed, Message: msg} }

// Check asks Proton once whether the code was approved.
func (l *Login) Check(ctx context.Context, id string) (mcpauth.Status, error) {
	a := l.find(id)
	if a == nil {
		return failed("This sign-in is not known or has expired. Start again."), nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.status != nil {
		return *a.status, nil
	}
	if !l.cfg.Now().Before(a.expires) {
		return l.end(a, failed(expiredMessage)), nil
	}
	approved, err := a.client.PullFork(ctx, a.selector)
	switch {
	case err == nil:
	case errors.Is(err, proton.ErrForkWaiting):
		return mcpauth.Status{State: mcpauth.Waiting}, nil
	case permanent(err):
		l.cfg.Logger.Debug("sign-in refused by Proton", "attempt", id, "error", err.Error())
		return l.end(a, failed("Proton no longer knows this code. Start again.")), nil
	default:
		// Nothing was learned about the fork; asking again is the remedy.
		return mcpauth.Status{}, fmt.Errorf("protonlogin: ask Proton about the code: %w", err)
	}

	status := l.finish(ctx, a, approved)
	return l.end(a, status), nil
}

// permanent says whether Proton answered, and answered no. A connection that
// failed or a server that is busy says nothing about the fork.
func permanent(err error) bool {
	var apiErr *proton.APIError
	return errors.As(err, &apiErr) && apiErr.HTTPStatus >= 400 && apiErr.HTTPStatus < 500 &&
		apiErr.HTTPStatus != 429
}

// end records the final answer and lets go of what the attempt held. The first
// answer stands: an attempt that has ended is never ended again.
func (l *Login) end(a *attempt, s mcpauth.Status) mcpauth.Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.endLocked(a, s)
}

// endLocked is end for a caller holding both a.mu and l.mu. An attempt that ends
// anything but Approved has its session revoked; one that ends Approved hands the
// session to its subject and must never touch it again. The anonymous session the
// fork was opened under is nobody's either way, so it is revoked on every end.
//
// Approved is only ever recorded once finish has saved the subject's session and
// opened the account with it, so revoking the anonymous one here comes after the
// subject's is safe on disk.
func (l *Login) endLocked(a *attempt, s mcpauth.Status) mcpauth.Status {
	if a.status != nil {
		return *a.status
	}
	a.status = &s
	c, anon := a.client, a.anon
	a.client, a.anon = nil, nil
	a.code = fork.Code{}
	switch {
	case s.State != mcpauth.Approved:
		l.revokeLater(c)
		if anon != nil {
			l.revokeLater(anon)
		}
	case anon != nil && !l.cfg.KeepAnonymousSession:
		l.revokeAnonymous(anon, c)
	}
	return s
}

// revokeAnonymous revokes the anonymous session of an approved sign-in, the same
// way revokeLater does, and then reads the account once with the subject's own
// client. Proton has not been seen to end a forked session with the session it
// was forked from, but if it does, that read is refused and the operator is told
// which flag keeps the anonymous sessions instead. Nothing is undone: the
// anonymous session cannot be brought back. Called with l.mu held.
func (l *Login) revokeAnonymous(anon, subject *proton.Client) {
	uid, _, _ := anon.Tokens()
	if uid == "" {
		return
	}
	l.revokes.Add(1)
	go func() {
		defer l.revokes.Done()
		ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
		defer cancel()
		if err := anon.RevokeSession(ctx, uid); err != nil && !gone(err) {
			l.cfg.Logger.Debug("the anonymous session of an approved sign-in could not be revoked", "error", err.Error())
			return
		}
		// The client still saves a refreshed session through the hook AdoptFork
		// gave it; reading the file back first keeps it from spending a refresh
		// token a tool call of the subject's has already replaced.
		subject.SetReloadHook(func() (string, string, bool) {
			name, err := profile.Parse(subject.Profile())
			if err != nil {
				return "", "", false
			}
			stored, err := session.Load(name)
			if err != nil || stored == nil {
				return "", "", false
			}
			return stored.AccessToken, stored.RefreshToken, true
		})
		check, cancelCheck := context.WithTimeout(context.Background(), revokeTimeout)
		defer cancelCheck()
		if _, err := account.New(subject, nil).Get(check); errors.Is(err, proton.ErrUnauthorized) {
			l.cfg.Logger.Warn("a sign-in was approved, but its session was refused right after the anonymous session it was opened under was revoked: revoking that session may end the new one. If every sign-in fails this way, run with -keep-anonymous-session",
				"subject", subject.Profile())
		}
	}()
}

// revokeLater revokes the session c holds, in the background and within
// revokeTimeout, so that nothing waiting on a request is held up by Proton. It is
// best effort: a failure says nothing about the attempt, which has ended either
// way, so it is only logged. Called with l.mu held.
func (l *Login) revokeLater(c *proton.Client) {
	uid, _, _ := c.Tokens()
	if uid == "" {
		return // no session was opened
	}
	l.revokes.Add(1)
	go func() {
		defer l.revokes.Done()
		ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
		defer cancel()
		if err := c.RevokeSession(ctx, uid); err != nil && !gone(err) {
			l.cfg.Logger.Debug("an abandoned sign-in session could not be revoked", "error", err.Error())
		}
	}()
}

// Close ends every attempt still waiting, revoking each one's session, and waits
// for the revokes to finish. An attempt being worked on is ended when its current
// poll is done, so a session that is just being approved is never revoked under
// the person who approved it. The Login refuses new sign-ins afterwards. Close is
// idempotent.
func (l *Login) Close() error {
	l.mu.Lock()
	l.closed = true
	live := make([]*attempt, 0, len(l.attempts))
	for _, a := range l.attempts {
		live = append(live, a)
	}
	l.mu.Unlock()
	for _, a := range live {
		a.mu.Lock()
		l.end(a, failed("The server is shutting down. Start again."))
		a.mu.Unlock()
	}
	l.revokes.Wait()
	return nil
}

// finish turns an approved fork into a saved, unlocked session of the subject.
// Every way it can fail leaves the client holding the session the fork issued, so
// that the end of the attempt revokes it.
func (l *Login) finish(ctx context.Context, a *attempt, approved *proton.ForkedSession) mcpauth.Status {
	// The fork's session replaces the anonymous one in a.client, and the anonymous
	// one is Proton's to reap only if nobody revokes it: keep it for the end.
	a.anon = l.newClient(a.subject)
	a.anon.SetTokens(a.client.Tokens())
	keyPass, err := a.code.Open(approved.Payload)
	if err != nil {
		l.cfg.Logger.Debug("the approval could not be opened", "error", err.Error())
		return l.abandon(a, approved, "The approval could not be read. Start again.")
	}
	if keyPass == "" {
		// A session whose keys stay shut is useless to a server nobody can ask for
		// a password.
		return l.abandon(a, approved, "The approving app did not share the account keys. Approve the code from a Proton app that is signed in, and start again.")
	}
	if existing, err := session.Load(a.subject); err != nil || existing != nil {
		return l.abandon(a, approved, "Could not save the sign-in. Start again.")
	}
	if _, err := app.AdoptFork(ctx, a.client, a.subject, keyPass, approved); err != nil {
		l.cfg.Logger.Debug("the approved session did not settle", "error", err.Error())
		_ = session.Clear(a.subject)
		return l.abandon(a, approved, "Proton signed in but the account could not be opened. Start again.")
	}
	l.cfg.Logger.Debug("sign-in approved", "subject", a.subject.String())
	return mcpauth.Status{State: mcpauth.Approved, Subject: a.subject.String()}
}

// abandon fails an attempt whose session was already issued. The client takes the
// issued session up, so ending the attempt revokes it and Proton is not left
// holding a session nothing here will ever use.
func (l *Login) abandon(a *attempt, approved *proton.ForkedSession, msg string) mcpauth.Status {
	a.client.AdoptSession(approved.UID, approved.AccessToken, approved.RefreshToken)
	return failed(msg)
}

// Forget revokes the subject's session at Proton and removes everything this
// machine holds for it. Revoking fails open only for the answers that mean the
// session is already gone. Any other failure is returned with the files
// untouched, since they are the only way left to revoke the session, and the
// caller's retry converges: Forget is idempotent. A revoke that keeps failing is
// still retried, and every forgetWarnEvery failures in a row the operator is told
// to revoke the session by hand.
func (l *Login) Forget(ctx context.Context, subject string) error {
	name, err := subjectName(subject)
	if err != nil {
		return fmt.Errorf("protonlogin: forget: %w", err)
	}
	sess, err := session.Load(name)
	if err != nil {
		return fmt.Errorf("protonlogin: forget: %w", err)
	}
	if sess != nil {
		c := l.newClient(name)
		c.SetTokens(sess.UID, sess.AccessToken, sess.RefreshToken)
		if err := c.RevokeSession(ctx, sess.UID); err != nil && !gone(err) {
			l.revokeFailed(name, err)
			return fmt.Errorf("protonlogin: revoke the session at Proton: %w", err)
		}
	}
	l.mu.Lock()
	delete(l.forgetFailures, name.String())
	l.mu.Unlock()
	return app.Forget(name)
}

// revokeFailed counts a failed revoke of the subject's session and, every
// forgetWarnEvery in a row, says so where the operator will see it.
func (l *Login) revokeFailed(name profile.Name, err error) {
	l.mu.Lock()
	l.forgetFailures[name.String()]++
	n := l.forgetFailures[name.String()]
	l.mu.Unlock()
	if n%forgetWarnEvery != 0 {
		return
	}
	attrs := []any{"subject", name.String(), "failures", n}
	var apiErr *proton.APIError
	if errors.As(err, &apiErr) {
		attrs = append(attrs, "status", apiErr.HTTPStatus, "code", apiErr.Code)
	}
	l.cfg.Logger.Warn("the Proton session of a signed-out subject could not be revoked. Its saved session is kept and revoking is retried, but until it succeeds the session is live: revoke it by hand from the session list in the Proton account's security settings", attrs...)
}

// gone says whether a failed revoke means the session no longer exists at
// Proton, so there is nothing left to revoke: ErrUnauthorized (the session was
// refused and could not be refreshed: revoked, expired or never there) or a 404.
// Every other answer - another 4xx, a 5xx, no answer at all - says nothing about
// the session being gone.
func gone(err error) bool {
	if errors.Is(err, proton.ErrUnauthorized) {
		return true
	}
	var apiErr *proton.APIError
	return errors.As(err, &apiErr) && apiErr.HTTPStatus == 404
}
