package cli

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/roman-16/proton-cli/internal/app"
)

// A server runs many commands at once in one process, all pinned to the same
// zone. Each run adopts that zone as the process's time.Local, so once the zone
// is already in place concurrent runs must not write it, or they race with every
// reader of it. Without the guard in adoptZone the race detector flags this test.
func TestConcurrentRunsInOneZoneDoNotRace(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Cleanup(func(old *time.Location) func() { return func() { time.Local = old } }(time.Local))
	// What a server does once at startup, before it serves anything: the first
	// write of the process cannot be made safe against unrelated readers.
	time.Local = time.UTC

	stop := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() { // anything in the process that reads the local zone meanwhile
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = time.Now().Local().Format(time.RFC3339)
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out, errw bytes.Buffer
			code, err := Run(context.Background(), []string{"--zone", "UTC", "--no-log", "--no-input", "version"},
				app.Streams{Out: &out, Err: &errw, In: bytes.NewReader(nil)})
			if err != nil || code != 0 || out.Len() == 0 {
				t.Errorf("version: code=%d err=%v out=%q err=%q", code, err, out.String(), errw.String())
			}
		}()
	}
	wg.Wait()
	close(stop)
	readers.Wait()
	if time.Local.String() != "UTC" {
		t.Fatalf("time.Local = %s, want UTC", time.Local)
	}
}
