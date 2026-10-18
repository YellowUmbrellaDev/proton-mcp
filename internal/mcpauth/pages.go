package mcpauth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
)

// Every HTML page carries the same headers. The policy allows no network
// access but fetches to the server itself (the status poll), only inline styles,
// only images inlined as data: URIs (the QR code), and only the script that
// carries this response's nonce. formAction widens form-action for the consent
// page, whose form ends in a redirect to the client: Chrome checks form-action
// against every hop of the redirect chain.
func pageHeaders(w http.ResponseWriter, nonce, formAction string) {
	h := w.Header()
	fa := "'self'"
	if formAction != "" {
		fa += " " + formAction
	}
	h.Set("Content-Security-Policy",
		"default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'; "+
			"connect-src 'self'; form-action "+fa+"; frame-ancestors 'none'; base-uri 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("Content-Type", "text/html; charset=utf-8")
}

// newNonce is 128 random bits in base64url: CSP accepts that alphabet, and
// html/template leaves it as it is in an attribute ('+' would be escaped and
// no longer match the header).
func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// page data shared by every template.
type pageData struct {
	Nonce   string
	Title   string
	Message string // errors and failures
	Retry   string // where "try again" goes
	// Waiting
	ID        string
	Code      string
	QR        template.URL
	StatusURL string
	// Consent
	ClientName   string
	RedirectHost string
	Scopes       []scopeView
	ConsentURL   string
	CSRF         string
}

type scopeView struct {
	Name     string
	Text     string
	Optional bool // a checkbox
	Checked  bool
}

func (s *Server) render(w http.ResponseWriter, status int, name string, d pageData, formAction string) {
	d.Nonce = newNonce()
	var buf bytes.Buffer
	if err := pages.ExecuteTemplate(&buf, name, d); err != nil {
		http.Error(w, "page failed to render", http.StatusInternalServerError)
		return
	}
	pageHeaders(w, d.Nonce, formAction)
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// errorPage shows an error that cannot be sent back to the client, because no
// redirect URI has been established yet.
func (s *Server) errorPage(w http.ResponseWriter, status int, msg, retry string) {
	s.render(w, status, "error", pageData{Title: "Cannot sign in", Message: msg, Retry: retry}, "")
}

var pages = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem;color:#1b1b1f;background:#fff}
h1{font-size:1.4rem}
.code{font:600 1.6rem/1.3 ui-monospace,monospace;letter-spacing:.08em;user-select:all;-webkit-user-select:all;padding:.6rem .8rem;border:1px solid #ccc;border-radius:6px;display:inline-block;word-break:break-all}
.qr{display:block;margin:1rem 0;width:256px;height:256px;image-rendering:pixelated}
.muted{color:#5c5c66;font-size:.9rem}
.err{color:#a1001b}
button{font:inherit;padding:.5rem 1.2rem;margin-right:.5rem;border-radius:6px;border:1px solid #6d4aff;background:#6d4aff;color:#fff;cursor:pointer}
button.secondary{background:#fff;color:#1b1b1f;border-color:#ccc}
ul{padding-left:1.2rem}
@media (prefers-color-scheme: dark){body{background:#16141c;color:#eee}.muted{color:#aaa}.code{border-color:#444}button.secondary{background:#16141c;color:#eee;border-color:#444}}
</style>{{end}}

{{define "error"}}{{template "head" .}}</head><body>
<h1>{{.Title}}</h1>
<p class="err">{{.Message}}</p>
{{if .Retry}}<p><a href="{{.Retry}}">Try again</a></p>{{end}}
</body></html>{{end}}

{{define "waiting"}}{{template "head" .}}
<noscript><meta http-equiv="refresh" content="5"></noscript>
</head><body>
<h1>Sign in to Proton</h1>
<p>Open a Proton app where you are already signed in, choose to sign in another device, and enter this code or scan it.</p>
<p class="code">{{.Code}}</p>
{{if .QR}}<img class="qr" alt="QR code of the sign-in code" src="{{.QR}}">{{end}}
<p class="muted" id="status">Waiting for approval...</p>
<noscript><p class="muted">This page reloads itself every few seconds.</p></noscript>
<script nonce="{{.Nonce}}">
(function(){
  var url = {{.StatusURL}};
  function poll(){
    fetch(url, {credentials: "same-origin", cache: "no-store"}).then(function(r){
      if (!r.ok) { location.reload(); return; }
      return r.json().then(function(s){
        if (s.state === "waiting") { setTimeout(poll, 2000); } else { location.reload(); }
      });
    }).catch(function(){ setTimeout(poll, 5000); });
  }
  setTimeout(poll, 2000);
})();
</script>
</body></html>{{end}}

{{define "consent"}}{{template "head" .}}</head><body>
<h1>Allow access to your Proton account?</h1>
<p><strong>{{.ClientName}}</strong> wants to act on your Proton account and will receive access at <strong>{{.RedirectHost}}</strong>.</p>
<form method="post" action="{{.ConsentURL}}">
<input type="hidden" name="id" value="{{.ID}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<ul>
{{range .Scopes}}<li>{{if .Optional}}<label><input type="checkbox" name="scope" value="{{.Name}}"{{if .Checked}} checked{{end}}> {{.Text}}</label>{{else}}{{.Text}}<input type="hidden" name="scope" value="{{.Name}}">{{end}}</li>
{{end}}</ul>
<p class="muted">Only allow this if you started connecting this app yourself. You can revoke the access from the app at any time.</p>
<button type="submit" name="action" value="allow">Allow</button>
<button type="submit" name="action" value="deny" class="secondary">Deny</button>
</form>
</body></html>{{end}}
`))

// scopeText describes a scope to the person approving it.
func scopeText(scope string) string {
	switch scope {
	case ScopeRead:
		return "Read your mail, calendar, contacts, drive and passwords"
	case ScopeWrite:
		return "Change things: send mail, edit events, contacts, files and passwords"
	}
	return "Scope " + scope
}
