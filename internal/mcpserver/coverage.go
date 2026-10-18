package mcpserver

import (
	"encoding/json"
	"os"
	"sync"
)

// Outcome is how a call ended, for the coverage log.
type Outcome string

const (
	// Executed means the tool ran and succeeded, changing or reading for real.
	Executed Outcome = "executed"
	// Previewed means it only reported what it would do (dry run, or held until confirm).
	Previewed Outcome = "previewed"
	// Failed means the tool ran and returned an error.
	Failed Outcome = "failed"
)

// OutcomeOf classifies a result.
func OutcomeOf(r Result) Outcome {
	switch {
	case r.IsError:
		return Failed
	case r.Held || r.DryRun:
		return Previewed
	}
	return Executed
}

// CoverageLog appends one JSON line per call to a file, safe for concurrent use.
type CoverageLog struct {
	mu sync.Mutex
	f  *os.File
}

// OpenCoverageLog opens (creating) the file for appending.
func OpenCoverageLog(path string) (*CoverageLog, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &CoverageLog{f: f}, nil
}

// Record writes one call.
func (l *CoverageLog) Record(t Tool, r Result) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"tool": t.Name, "outcome": OutcomeOf(r), "mutating": t.Mutating})
	_, _ = l.f.Write(append(b, '\n'))
}
