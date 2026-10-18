package mcpauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// What the server remembers between restarts. Every secret handed to a client
// (code, access token, refresh token) is kept only as the SHA-256 of its text,
// so the file cannot be replayed into tokens; the whole document is then sealed
// with AES-256-GCM under Config.Key, which also hides who the grants are for.
type state struct {
	Clients map[string]*client       `json:"clients"`
	Grants  map[string]*grant        `json:"grants"`
	Codes   map[string]*authCode     `json:"codes"`   // by hash
	Access  map[string]*accessToken  `json:"access"`  // by hash
	Refresh map[string]*refreshToken `json:"refresh"` // by hash
	// Unbound holds subjects of sign-ins that were approved but have no grant
	// yet (consent pending, or a code not exchanged), with the time after which
	// they are given up on. It outlives a restart, so such a session is
	// forgotten even if the server stops in between.
	Unbound map[string]time.Time `json:"unbound"`
	// Forget lists subjects whose last grant is gone but whose Login.Forget has
	// not succeeded yet; it is retried until it does.
	Forget []string `json:"forget"`
}

// A registered client (RFC 7591). Every client is public: it proves itself
// with PKCE, never with a secret.
type client struct {
	ID           string    `json:"id"`
	Name         string    `json:"name,omitempty"`
	RedirectURIs []string  `json:"redirect_uris"`
	GrantTypes   []string  `json:"grant_types"`
	Scope        string    `json:"scope,omitempty"`
	Created      time.Time `json:"created"`
	LastUsed     time.Time `json:"last_used"`
}

// A grant is one consent: a client may act as a subject within some scopes, on
// one resource. It lives as long as its newest refresh token.
type grant struct {
	ID       string    `json:"id"`
	ClientID string    `json:"client_id"`
	Subject  string    `json:"subject"`
	Scopes   []string  `json:"scopes"`
	Resource string    `json:"resource"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
}

// An authorization code. A used code is kept while the grant it produced lives,
// so that a replay can revoke that grant.
type authCode struct {
	ClientID    string    `json:"client_id"`
	RedirectURI string    `json:"redirect_uri"`
	Challenge   string    `json:"challenge"`
	Resource    string    `json:"resource"`
	Scopes      []string  `json:"scopes"`
	Subject     string    `json:"subject"`
	Expires     time.Time `json:"expires"`
	Used        bool      `json:"used,omitempty"`
	GrantID     string    `json:"grant_id,omitempty"`
}

type accessToken struct {
	GrantID  string    `json:"grant_id"`
	Scopes   []string  `json:"scopes"`
	Resource string    `json:"resource"`
	Expires  time.Time `json:"expires"`
}

// A refresh token is live until it is used once; then it is superseded, and for
// refreshGrace it may be used one more time (a client racing itself). Any use
// after that is a stolen token being replayed, and ends the grant.
type refreshToken struct {
	GrantID    string    `json:"grant_id"`
	Expires    time.Time `json:"expires"`
	Superseded time.Time `json:"superseded,omitzero"`
	GraceUsed  bool      `json:"grace_used,omitempty"`
}

func newState() *state {
	return &state{
		Clients: map[string]*client{},
		Grants:  map[string]*grant{},
		Codes:   map[string]*authCode{},
		Access:  map[string]*accessToken{},
		Refresh: map[string]*refreshToken{},
		Unbound: map[string]time.Time{},
	}
}

// The file on disk: a version and the sealed JSON of a state.
type envelope struct {
	Version int    `json:"v"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
}

const (
	stateVersion = 1
	stateAAD     = "mcpauth state v1"
)

type store struct {
	path string
	aead cipher.AEAD
}

func newStore(path string, key []byte) (*store, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("mcpauth: key is %d bytes, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &store{path: path, aead: aead}, nil
}

func (st *store) load() (*state, error) {
	raw, err := os.ReadFile(st.path)
	if errors.Is(err, fs.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("mcpauth: read state: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("mcpauth: state file is not an envelope: %w", err)
	}
	if env.Version != stateVersion {
		return nil, fmt.Errorf("mcpauth: state version %d, want %d", env.Version, stateVersion)
	}
	nonce, err1 := base64.StdEncoding.DecodeString(env.Nonce)
	data, err2 := base64.StdEncoding.DecodeString(env.Data)
	if err := errors.Join(err1, err2); err != nil {
		return nil, fmt.Errorf("mcpauth: state file encoding: %w", err)
	}
	if len(nonce) != st.aead.NonceSize() {
		return nil, errors.New("mcpauth: state file nonce has the wrong size")
	}
	plain, err := st.aead.Open(nil, nonce, data, []byte(stateAAD))
	if err != nil {
		return nil, errors.New("mcpauth: state file cannot be opened with this key")
	}
	s := newState()
	if err := json.Unmarshal(plain, s); err != nil {
		return nil, fmt.Errorf("mcpauth: decode state: %w", err)
	}
	// A document written with empty maps may decode them as nil.
	fresh := newState()
	if s.Clients == nil {
		s.Clients = fresh.Clients
	}
	if s.Grants == nil {
		s.Grants = fresh.Grants
	}
	if s.Codes == nil {
		s.Codes = fresh.Codes
	}
	if s.Access == nil {
		s.Access = fresh.Access
	}
	if s.Refresh == nil {
		s.Refresh = fresh.Refresh
	}
	if s.Unbound == nil {
		s.Unbound = fresh.Unbound
	}
	return s, nil
}

// save writes the state atomically: a sealed temporary file next to the real
// one, synced, then renamed over it.
func (st *store) save(s *state) error {
	plain, err := json.Marshal(s)
	if err != nil {
		return err
	}
	nonce := make([]byte, st.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	env, err := json.Marshal(envelope{
		Version: stateVersion,
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Data:    base64.StdEncoding.EncodeToString(st.aead.Seal(nil, nonce, plain, []byte(stateAAD))),
	})
	if err != nil {
		return err
	}
	dir := filepath.Dir(st.path)
	tmp, err := os.CreateTemp(dir, ".mcpauth-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(env); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), st.path)
}

// newSecret returns a random 256-bit value as text, and the hash under which
// it is stored.
func newSecret() (text, hash string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	text = base64.RawURLEncoding.EncodeToString(b)
	return text, hashSecret(text)
}

func hashSecret(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// newID is a random identifier that is not a secret.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
