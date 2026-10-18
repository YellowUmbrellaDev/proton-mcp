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
	"log/slog"
	"sync"
	"time"

	"github.com/roman-16/proton-cli/internal/account/fork"
	"github.com/roman-16/proton-cli/internal/account/session"
	"github.com/roman-16/proton-cli/internal/app"
	"github.com/roman-16/proton-cli/internal/mcpauth"
	"github.com/roman-16/proton-cli/internal/profile"
	"github.com/roman-16/proton-cli/internal/proton"
)

var _ mcpauth.Login = (*Login)(nil)

const (
	// defaultTTL is how long Proton's own sign-in screen keeps a code.
	defaultTTL = 9 * time.Minute
	// maxAttempts bounds what a caller that never finishes can make this hold.
	maxAttempts = 200
	// retention is how long a finished or expired attempt is still answered, so a
	// page that polls once more after the end learns the end rather than "unknown".
	retention = 10 * time.Minute
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
}

// Login implements mcpauth.Login against Proton.
type Login struct {
	cfg Config

	mu       sync.Mutex
	attempts map[string]*attempt
}

// attempt is one code on screen. Its own mutex serialises the polls of one
// attempt, so two tabs asking at once cannot finish the same fork twice.
type attempt struct {
	mu       sync.Mutex
	client   *proton.Client
	selector string
	code     fork.Code
	subject  profile.Name
	expires  time.Time
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
	return &Login{cfg: cfg, attempts: map[string]*attempt{}}, nil
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
func (l *Login) Start(ctx context.Context) (mcpauth.Attempt, error) {
	subject, err := subjectName(l.cfg.NewSubject())
	if err != nil {
		return mcpauth.Attempt{}, fmt.Errorf("protonlogin: new subject: %w", err)
	}
	// Refused before anything reaches Proton: a fork opened and then dropped is a
	// session Proton keeps until it reaps it.
	if err := l.room(); err != nil {
		return mcpauth.Attempt{}, err
	}
	c := l.newClient(subject)
	if err := c.AnonymousSession(ctx); err != nil {
		return mcpauth.Attempt{}, fmt.Errorf("protonlogin: open a session: %w", err)
	}
	opened, err := c.NewFork(ctx)
	if err != nil {
		return mcpauth.Attempt{}, fmt.Errorf("protonlogin: open a fork: %w", err)
	}
	code, err := fork.New(opened.UserCode, c.AppVersion())
	if err != nil {
		return mcpauth.Attempt{}, err
	}
	a := &attempt{
		client: c, selector: opened.Selector, code: code, subject: subject,
		expires: l.cfg.Now().Add(l.cfg.TTL),
	}
	id := randomHex(16)

	l.mu.Lock()
	defer l.mu.Unlock()
	l.purgeLocked()
	if len(l.attempts) >= maxAttempts {
		return mcpauth.Attempt{}, errors.New("protonlogin: too many sign-ins in progress")
	}
	l.attempts[id] = a
	l.cfg.Logger.Debug("sign-in started", "attempt", id)
	return mcpauth.Attempt{ID: id, Code: code.String(), ExpiresAt: a.expires}, nil
}

// room reports whether another attempt fits, after letting go of old ones.
func (l *Login) room() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.purgeLocked()
	if len(l.attempts) >= maxAttempts {
		return errors.New("protonlogin: too many sign-ins in progress")
	}
	return nil
}

func (l *Login) purgeLocked() {
	now := l.cfg.Now()
	for id, a := range l.attempts {
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
		return l.end(a, failed("The code expired. Start again.")), nil
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

// end records the final answer and lets go of what the attempt held.
func (l *Login) end(a *attempt, s mcpauth.Status) mcpauth.Status {
	a.status = &s
	a.client = nil
	a.code = fork.Code{}
	return s
}

// finish turns an approved fork into a saved, unlocked session of the subject.
func (l *Login) finish(ctx context.Context, a *attempt, approved *proton.ForkedSession) mcpauth.Status {
	keyPass, err := a.code.Open(approved.Payload)
	if err != nil {
		l.cfg.Logger.Debug("the approval could not be opened", "error", err.Error())
		return l.abandon(ctx, a, approved, "The approval could not be read. Start again.")
	}
	if keyPass == "" {
		// A session whose keys stay shut is useless to a server nobody can ask for
		// a password.
		return l.abandon(ctx, a, approved, "The approving app did not share the account keys. Approve the code from a Proton app that is signed in, and start again.")
	}
	if existing, err := session.Load(a.subject); err != nil || existing != nil {
		return l.abandon(ctx, a, approved, "Could not save the sign-in. Start again.")
	}
	if _, err := app.AdoptFork(ctx, a.client, a.subject, keyPass, approved); err != nil {
		l.cfg.Logger.Debug("the approved session did not settle", "error", err.Error())
		_ = session.Clear(a.subject)
		return l.abandon(ctx, a, approved, "Proton signed in but the account could not be opened. Start again.")
	}
	l.cfg.Logger.Debug("sign-in approved", "subject", a.subject.String())
	return mcpauth.Status{State: mcpauth.Approved, Subject: a.subject.String()}
}

// abandon fails an attempt whose session was already issued, revoking it so Proton
// is not left holding a session nothing here will ever use.
func (l *Login) abandon(ctx context.Context, a *attempt, approved *proton.ForkedSession, msg string) mcpauth.Status {
	a.client.AdoptSession(approved.UID, approved.AccessToken, approved.RefreshToken)
	if err := a.client.RevokeSession(ctx, approved.UID); err != nil {
		l.cfg.Logger.Debug("the abandoned session could not be revoked", "error", err.Error())
	}
	return failed(msg)
}

// Forget revokes the subject's session at Proton and removes everything this
// machine holds for it. Revoking fails open only for the answers that mean it is
// already gone; a failure that says nothing about the session (no connection, a
// busy server) is returned with the files untouched, so retrying converges.
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
			return fmt.Errorf("protonlogin: revoke the session at Proton: %w", err)
		}
	}
	return app.Forget(name)
}

// gone says whether a failed revoke means the session no longer exists at
// Proton: already revoked, expired beyond refreshing, or never there.
func gone(err error) bool {
	if errors.Is(err, proton.ErrUnauthorized) {
		return true
	}
	var apiErr *proton.APIError
	return errors.As(err, &apiErr) && apiErr.HTTPStatus >= 400 && apiErr.HTTPStatus < 500 &&
		apiErr.HTTPStatus != 429
}
