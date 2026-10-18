package mcpserver

import (
	"context"
	"testing"
	"time"
)

func TestNoLimitNeverWaits(t *testing.T) {
	start := time.Now()
	for i := 0; i < 50; i++ {
		if err := NewLimiter(0, 5).Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("a disabled limiter waited %s", time.Since(start))
	}
}

func TestPacerSpacesCalls(t *testing.T) {
	l := NewPacer(80 * time.Millisecond)
	start := time.Now()
	for i := 0; i < 4; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// The first call goes through at once; the other three each wait one gap.
	if got := time.Since(start); got < 220*time.Millisecond {
		t.Fatalf("four calls took %s, want at least 3 gaps of 80ms", got)
	}
}

func TestBurstGoesThroughThenWaits(t *testing.T) {
	l := NewLimiter(60, 3) // one a second after the first three
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("the burst of 3 waited %s", time.Since(start))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx); err == nil {
		t.Fatal("the fourth call should have had to wait past the deadline")
	}
}
