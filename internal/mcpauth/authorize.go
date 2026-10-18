package mcpauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// A sign-in in flight, from /authorize to consent. It lives in memory only: a
// restart sends the person back to the client to start over.
type pending struct {
	id          string
	clientID    string
	redirectURI string
	state       string
	challenge   string
	resource    string
	scopes      []string // what the client asked for; nil when it named none
	csrf        string   // also the value of the browser's cookie
	attempt     Attempt
	expires     time.Time

	mu        sync.Mutex // guards what follows; held while calling Login.Check
	lastCheck time.Time
	status    Status
	done      bool // consent given or refused; the sign-in is over

	// approved is the subject once the sign-in is approved. It is guarded by
	// Server.mu, not mu, so the server can look at it without waiting for a
	// Login.Check in progress.
	approved string
}

// checkEvery is the most often a sign-in is checked with Login.Check, however
// often its page polls.
const checkEvery = time.Second

// authorize validates an authorization request (RFC 6749 §4.1.1 with PKCE),
// starts a sign-in and sends the browser to its page. Until the client and its
// redirect URI are known good, errors are shown here and never redirected.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for name, vals := range q {
		if len(vals) > 1 && name != "" {
			s.errorPage(w, http.StatusBadRequest, "The request repeats the parameter "+name+".", "")
			return
		}
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	s.mu.Lock()
	c := s.st.Clients[clientID]
	var registered bool
	if c != nil {
		registered = slices.Contains(c.RedirectURIs, redirectURI)
	}
	s.mu.Unlock()
	switch {
	case clientID == "" || c == nil:
		s.errorPage(w, http.StatusBadRequest, "The app that sent you here is not registered with this server. Go back to it and connect again.", "")
		return
	case redirectURI == "" || !registered:
		s.errorPage(w, http.StatusBadRequest, "The app that sent you here gave a return address it did not register. Go back to it and connect again.", "")
		return
	}

	state := q.Get("state")
	fail := func(code, desc string) {
		s.redirectError(w, r, redirectURI, state, code, desc)
	}
	if rt := q.Get("response_type"); rt != "code" {
		fail("unsupported_response_type", "only the code response type is supported")
		return
	}
	challenge := q.Get("code_challenge")
	switch method := q.Get("code_challenge_method"); {
	case challenge == "":
		fail("invalid_request", "code_challenge is required (PKCE)")
		return
	case method != "S256":
		fail("invalid_request", "code_challenge_method must be S256")
		return
	case !validChallenge(challenge):
		fail("invalid_request", "code_challenge is not a base64url SHA-256")
		return
	}
	if res, ok := q["resource"]; ok && res[0] != s.resource {
		fail("invalid_target", "this server only issues tokens for "+s.resource)
		return
	}
	var scopes []string
	if _, ok := q["scope"]; ok {
		scopes = parseScope(q.Get("scope"))
		if !subset(scopes, s.cfg.Scopes) {
			fail("invalid_scope", "unknown scope")
			return
		}
	}

	now := s.now()
	s.mu.Lock()
	if s.maybePurge(now) {
		_ = s.commit()
	}
	busy := len(s.pending) >= maxPending
	s.mu.Unlock()
	s.drainIfQueued()
	if busy {
		fail("temporarily_unavailable", "too many sign-ins in progress")
		return
	}
	attempt, err := s.cfg.Login.Start(r.Context())
	if err != nil {
		fail("temporarily_unavailable", "the sign-in could not be started")
		return
	}
	p := &pending{
		id:          newID(),
		clientID:    clientID,
		redirectURI: redirectURI,
		state:       state,
		challenge:   challenge,
		resource:    s.resource,
		scopes:      scopes,
		csrf:        newID(),
		attempt:     attempt,
		expires:     now.Add(loginTTL),
	}
	s.mu.Lock()
	s.pending[p.id] = p
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName(p.id),
		Value:    p.csrf,
		Path:     "/",
		MaxAge:   int(loginTTL / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, s.endpoint("/login")+"?id="+url.QueryEscape(p.id), http.StatusSeeOther)
}

// The cookie that ties a sign-in to the browser that started it; its value is
// the CSRF token the consent form must repeat. The __Host- prefix makes the
// browser refuse it unless it is Secure, host-only and for the whole site.
func cookieName(id string) string { return "__Host-mcpauth-" + id }

// fromBrowser finds the sign-in a request names and checks that it comes from
// the browser that started it.
func (s *Server) fromBrowser(r *http.Request, id string) *pending {
	s.mu.Lock()
	p := s.pending[id]
	if p != nil && s.now().After(p.expires) {
		delete(s.pending, id)
		p = nil
	}
	s.mu.Unlock()
	if p == nil {
		return nil
	}
	ck, err := r.Cookie(cookieName(id))
	if err != nil || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(p.csrf)) != 1 {
		return nil
	}
	return p
}

// check asks Login where a sign-in stands, at most once every checkEvery, and
// records an approval so the subject is not left behind if nobody consents.
func (s *Server) check(ctx context.Context, p *pending) Status {
	p.mu.Lock()
	if p.status.State != Waiting {
		defer p.mu.Unlock()
		return p.status
	}
	now := s.now()
	if !p.lastCheck.IsZero() && now.Sub(p.lastCheck) < checkEvery {
		defer p.mu.Unlock()
		return p.status
	}
	p.lastCheck = now
	st, err := s.cfg.Login.Check(ctx, p.attempt.ID)
	switch {
	case err != nil:
		// Transient: keep waiting and ask again on the next poll.
		st = p.status
	case st.State == Approved && st.Subject == "":
		st = Status{State: Failed, Message: "The sign-in finished without an account."}
	case st.State == Failed && st.Message == "":
		st.Message = "The sign-in did not complete."
	case st.State != Approved && st.State != Failed:
		st = Status{State: Waiting}
	}
	p.status = st
	p.mu.Unlock()

	if st.State == Approved {
		s.mu.Lock()
		p.approved = st.Subject
		s.holdUnbound(st.Subject, p.expires)
		_ = s.commit()
		s.mu.Unlock()
	}
	return st
}

// holdUnbound keeps a subject's session alive until deadline while it has no
// grant yet; the caller holds s.mu.
func (s *Server) holdUnbound(subject string, deadline time.Time) {
	if cur, ok := s.st.Unbound[subject]; !ok || deadline.After(cur) {
		s.st.Unbound[subject] = deadline
	}
}

// loginPage shows the code to approve, then the consent form, or why the
// sign-in failed. Without JavaScript it reloads itself while waiting.
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	p := s.fromBrowser(r, id)
	if p == nil {
		s.errorPage(w, http.StatusBadRequest, "This sign-in has expired or was started in another browser. Go back to the app and connect again.", "")
		return
	}
	p.mu.Lock()
	done := p.done
	p.mu.Unlock()
	if done {
		s.errorPage(w, http.StatusBadRequest, "This sign-in is already finished. Go back to the app.", "")
		return
	}
	st := s.check(r.Context(), p)
	switch st.State {
	case Approved:
		s.consentPage(w, p)
	case Failed:
		s.errorPage(w, http.StatusOK, st.Message, s.retryURL(p))
	default:
		s.render(w, http.StatusOK, "waiting", pageData{
			Title:     "Sign in to Proton",
			ID:        p.id,
			Code:      p.attempt.Code,
			QR:        qrDataURL(p.attempt.Code),
			StatusURL: s.endpoint("/login/status") + "?id=" + url.QueryEscape(p.id),
		}, "")
	}
}

// loginStatus answers the page's poll: waiting, approved or failed.
func (s *Server) loginStatus(w http.ResponseWriter, r *http.Request) {
	p := s.fromBrowser(r, r.URL.Query().Get("id"))
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"state": "gone"})
		return
	}
	name := "waiting"
	switch s.check(r.Context(), p).State {
	case Approved:
		name = "approved"
	case Failed:
		name = "failed"
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": name})
}

// retryURL starts the same authorization request again.
func (s *Server) retryURL(p *pending) string {
	v := url.Values{
		"client_id":             {p.clientID},
		"redirect_uri":          {p.redirectURI},
		"response_type":         {"code"},
		"code_challenge":        {p.challenge},
		"code_challenge_method": {"S256"},
		"resource":              {p.resource},
	}
	if p.state != "" {
		v.Set("state", p.state)
	}
	if p.scopes != nil {
		v.Set("scope", strings.Join(p.scopes, " "))
	}
	return s.endpoint("/authorize") + "?" + v.Encode()
}

// offer is what the consent form shows: the scopes the client may get, each
// with whether the person may untick it and whether it starts ticked. Read
// access is what every tool needs, so it is fixed; any other scope (write) is a
// checkbox, ticked only when the client asked for it by name.
func (s *Server) offer(p *pending) []scopeView {
	want := p.scopes
	if want == nil {
		want = s.cfg.Scopes
	}
	var out []scopeView
	for _, sc := range s.cfg.Scopes {
		required := sc == ScopeRead
		if !required && !slices.Contains(want, sc) {
			continue
		}
		out = append(out, scopeView{
			Name:     sc,
			Text:     scopeText(sc),
			Optional: !required,
			Checked:  required || slices.Contains(p.scopes, sc),
		})
	}
	return out
}

func (s *Server) consentPage(w http.ResponseWriter, p *pending) {
	s.mu.Lock()
	c := s.st.Clients[p.clientID]
	name := ""
	if c != nil {
		name = c.Name
	}
	s.mu.Unlock()
	if name == "" {
		name = "An app that did not give its name"
	}
	host := p.redirectURI
	if u, err := url.Parse(p.redirectURI); err == nil {
		host = u.Host
	}
	s.render(w, http.StatusOK, "consent", pageData{
		Title:        "Allow access?",
		ID:           p.id,
		ClientName:   name,
		RedirectHost: host,
		Scopes:       s.offer(p),
		ConsentURL:   s.endpoint("/login/consent"),
		CSRF:         p.csrf,
	}, redirectOrigin(p.redirectURI))
}

// redirectOrigin is the origin the consent form's redirect lands on, for its
// form-action.
func redirectOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// consent takes the person's answer. It must come from the browser that
// started the sign-in (cookie) and from this server's own form (the same token
// in a hidden field, and the Origin when the browser sends one).
func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, http.StatusBadRequest, "The form could not be read.", "")
		return
	}
	if o := r.Header.Get("Origin"); o != "" && o != s.origin {
		s.errorPage(w, http.StatusForbidden, "The answer did not come from this page.", "")
		return
	}
	id := r.PostForm.Get("id")
	p := s.fromBrowser(r, id)
	if p == nil || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(p.csrf)) != 1 {
		s.errorPage(w, http.StatusForbidden, "This sign-in has expired or the answer did not come from its page. Go back to the app and connect again.", "")
		return
	}
	p.mu.Lock()
	if p.done || p.status.State != Approved {
		p.mu.Unlock()
		s.errorPage(w, http.StatusBadRequest, "This sign-in is not waiting for an answer.", "")
		return
	}
	p.done = true
	subject := p.status.Subject
	p.mu.Unlock()

	now := s.now()
	s.mu.Lock()
	delete(s.pending, p.id)
	s.mu.Unlock()
	clearCookie(w, p.id)

	if r.PostForm.Get("action") != "allow" {
		s.mu.Lock()
		s.releaseUnbound(subject)
		_ = s.commit()
		s.mu.Unlock()
		s.drainIfQueued()
		s.redirectError(w, r, p.redirectURI, p.state, "access_denied", "the person refused")
		return
	}

	var scopes []string
	chosen := r.PostForm["scope"]
	for _, v := range s.offer(p) {
		if !v.Optional || slices.Contains(chosen, v.Name) {
			scopes = append(scopes, v.Name)
		}
	}
	text, hash := newSecret()
	s.mu.Lock()
	s.st.Codes[hash] = &authCode{
		ClientID:    p.clientID,
		RedirectURI: p.redirectURI,
		Challenge:   p.challenge,
		Resource:    p.resource,
		Scopes:      scopes,
		Subject:     subject,
		Expires:     now.Add(s.cfg.CodeTTL),
	}
	// The session must outlive the code, whenever in the sign-in consent came.
	s.holdUnbound(subject, now.Add(s.cfg.CodeTTL+purgeEvery))
	err := s.commit()
	s.mu.Unlock()
	if err != nil {
		s.redirectError(w, r, p.redirectURI, p.state, "server_error", "")
		return
	}
	s.redirect(w, r, p.redirectURI, url.Values{"code": {text}}, p.state)
}

// releaseUnbound lets go of a subject held for a sign-in once nothing pending
// refers to it any more; the caller holds s.mu.
func (s *Server) releaseUnbound(subject string) {
	for _, c := range s.st.Codes {
		if !c.Used && c.Subject == subject {
			return
		}
	}
	for _, p := range s.pending {
		if p.approved == subject {
			return
		}
	}
	delete(s.st.Unbound, subject)
	s.queueForget(subject)
}

func clearCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(id), Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// redirect sends the browser back to the client with the response parameters,
// the state and the issuer (RFC 9207).
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, redirectURI string, params url.Values, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.errorPage(w, http.StatusInternalServerError, "The return address is broken.", "")
		return
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.cfg.Issuer)
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	v := url.Values{"error": {code}}
	if desc != "" {
		v.Set("error_description", desc)
	}
	s.redirect(w, r, redirectURI, v, state)
}

// validChallenge: an S256 challenge is the unpadded base64url of 32 bytes.
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil && len(b) == 32
}

// qrDataURL draws text as a QR code in an inline PNG.
func qrDataURL(text string) template.URL {
	png, err := qrcode.Encode(text, qrcode.Medium, 256)
	if err != nil {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}
