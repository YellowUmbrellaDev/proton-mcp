package mcpserver

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/time/rate"
)

// Limiter spaces tool calls so a burst of them cannot look like abuse to Proton.
//
// It counts tool calls, not the API requests behind them: one tool can make
// several requests (listing contacts reads 27 pages), so the real request rate is
// a multiple of this one. It is a brake on the caller, not a guarantee about
// Proton's own limits.
type Limiter struct {
	r *rate.Limiter
}

// NewLimiter allows perMinute calls a minute on average, with up to burst back to
// back. perMinute <= 0 means no limit.
func NewLimiter(perMinute float64, burst int) *Limiter {
	if perMinute <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{r: rate.NewLimiter(rate.Limit(perMinute/60), burst)}
}

// NewPacer allows one call per gap, with no burst. It is what a long test run
// uses to spread its calls over time.
func NewPacer(gap time.Duration) *Limiter {
	if gap <= 0 {
		return nil
	}
	return &Limiter{r: rate.NewLimiter(rate.Every(gap), 1)}
}

// Wait blocks until the call may go ahead, or the context ends.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if err := l.r.Wait(ctx); err != nil {
		return fmt.Errorf("rate limit: %w", err)
	}
	return nil
}
