package mcpserver

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// InlineLimit is the largest download handed back inside the tool result.
	// Base64 inflates it by a third, and a gateway between the model and this
	// server may refuse a response well under what the transport would carry, so
	// anything bigger is kept here and read in pieces through resources/read.
	InlineLimit = 512 << 10
	// ChunkLimit is the most one resources/read returns.
	ChunkLimit = 512 << 10

	storeBudget = 256 << 20
	storeTTL    = 30 * time.Minute
)

// fileInfo describes a download, as the tool result's structuredContent.
type fileInfo struct {
	Name     string `json:"name"`
	Size     int    `json:"size"`
	MIMEType string `json:"mimeType"`
	URI      string `json:"uri"`
	// Inline says the content is in this result; otherwise it is read from URI
	// with resources/read, ChunkLimit bytes at a time.
	Inline    bool   `json:"inline"`
	ChunkSize int    `json:"chunkSize,omitempty"`
	ReadWith  string `json:"readWith,omitempty"`
}

type heldFile struct {
	owner, uri string
	mime       string
	data       []byte
	at         time.Time
}

// Store keeps the downloads too big to return inline, for their owner alone: a
// multi-user server must never serve one person's file under another's session.
type Store struct {
	mu    sync.Mutex
	files []*heldFile
	now   func() time.Time
}

func NewStore() *Store { return &Store{now: time.Now} }

// Put keeps data for owner under uri, replacing what that owner had there.
func (s *Store) Put(owner, uri, mime string, data []byte) error {
	if len(data) > storeBudget {
		return fmt.Errorf("the download is %d bytes, more than the %d this server keeps for reading back", len(data), storeBudget)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	kept := s.files[:0]
	for _, f := range s.files {
		if f.owner != owner || f.uri != uri {
			kept = append(kept, f)
		}
	}
	s.files = append(kept, &heldFile{owner: owner, uri: uri, mime: mime, data: data, at: s.now()})
	for total(s.files) > storeBudget && len(s.files) > 1 {
		s.files = s.files[1:] // oldest first
	}
	return nil
}

func total(fs []*heldFile) (n int) {
	for _, f := range fs {
		n += len(f.data)
	}
	return n
}

func (s *Store) expire() {
	kept := s.files[:0]
	for _, f := range s.files {
		if s.now().Sub(f.at) < storeTTL {
			kept = append(kept, f)
		}
	}
	s.files = kept
}

// Get returns a held file, or false when the owner has none by that uri.
func (s *Store) Get(owner, uri string) (data []byte, mime string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	for _, f := range s.files {
		if f.owner == owner && f.uri == uri {
			return f.data, f.mime, true
		}
	}
	return nil, "", false
}

// readRange is what resources/read answers for uri, which may end in
// ?offset=N&length=M. A file larger than ChunkLimit cannot be read whole.
func (s *Store) readRange(owner, raw string) (*mcp.ReadResourceResult, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", raw, err)
	}
	q := u.Query()
	u.RawQuery = ""
	base := u.String()
	data, mime, ok := s.Get(owner, base)
	if !ok {
		return nil, mcp.ResourceNotFoundError(raw)
	}
	offset, length := 0, ChunkLimit
	if v := q.Get("offset"); v != "" {
		if offset, err = strconv.Atoi(v); err != nil || offset < 0 || offset > len(data) {
			return nil, fmt.Errorf("offset must be between 0 and %d", len(data))
		}
	}
	if v := q.Get("length"); v != "" {
		if length, err = strconv.Atoi(v); err != nil || length < 1 {
			return nil, fmt.Errorf("length must be a positive whole number")
		}
	}
	if length > ChunkLimit {
		length = ChunkLimit
	}
	if q.Get("offset") == "" && q.Get("length") == "" && len(data) > ChunkLimit {
		return nil, fmt.Errorf("the file is %d bytes: read it in pieces with %s?offset=0&length=%d, then offset=%d, and so on", len(data), base, ChunkLimit, ChunkLimit)
	}
	end := min(offset+length, len(data))
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
		URI: raw, MIMEType: mime, Blob: data[offset:end],
	}}}, nil
}

// addFileResources lets a client read what the store holds. The template covers
// every uri a download can have; what a caller may read is decided by the store.
func addFileResources(s *mcp.Server, store *Store, who func(context.Context) (Runner, error)) {
	s.AddResourceTemplate(&mcp.ResourceTemplate{
		Name:        "download",
		Description: "A file returned by a download tool, too large to come inline. Read it with ?offset=N&length=M, at most 524288 bytes at a time.",
		URITemplate: "proton://{+path}",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		run, err := who(ctx)
		if err != nil {
			return nil, err
		}
		return store.readRange(run.Profile, req.Params.URI)
	})
}

// downloadURI names a download after what it was asked for: the command's path
// without its verb, then the references it was given, then the file name.
func downloadURI(t Tool, input map[string]any, name string) string {
	var segs []string
	for _, p := range t.Path[:len(t.Path)-1] {
		segs = append(segs, url.PathEscape(p))
	}
	for _, p := range t.Params {
		if s, ok := input[p.Prop].(string); ok && p.Positional {
			segs = append(segs, url.PathEscape(s))
		}
	}
	for _, p := range strings.Split(name, "/") {
		segs = append(segs, url.PathEscape(p))
	}
	return "proton://" + strings.Join(segs, "/")
}
