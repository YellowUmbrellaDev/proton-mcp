package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/roman-16/proton-cli/internal/app"
)

func TestRunReturnsExitCodeAndWritesToStreams(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var out, errw bytes.Buffer
	code, err := Run(context.Background(), []string{"mail", "nonsense"}, app.Streams{Out: &out, Err: &errw, In: bytes.NewReader(nil)})
	if err == nil || code == 0 {
		t.Fatalf("want a failure, got code=%d err=%v", code, err)
	}
	if errw.Len() == 0 {
		t.Fatalf("want the failure written to the Err stream")
	}
}
