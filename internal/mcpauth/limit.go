package mcpauth

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultPerMinute = 20
	defaultBurst     = 10
	limiterIdle      = 10 * time.Minute
	limiterSweepAt   = 1024 // entries before idle ones are swept
)

// limiter is a token bucket per (endpoint, client IP). It reads the server's
// clock, so tests are deterministic.
type limiter struct {
	off   bool
	every rate.Limit
	burst int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	r    *rate.Limiter
	seen time.Time
}

func newLimiter(cfg RateLimit) *limiter {
	l := &limiter{every: rate.Limit(float64(defaultPerMinute) / 60), burst: defaultBurst, buckets: map[string]*bucket{}}
	switch {
	case cfg.PerMinute < 0:
		l.off = true
	case cfg.PerMinute > 0:
		l.every = rate.Limit(cfg.PerMinute / 60)
	}
	if cfg.Burst > 0 {
		l.burst = cfg.Burst
	}
	return l
}

// allow takes a token for key at now; when there is none it says how long to
// wait for the next.
func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	if l.off {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) >= limiterSweepAt {
		for k, b := range l.buckets {
			if now.Sub(b.seen) > limiterIdle {
				delete(l.buckets, k)
			}
		}
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{r: rate.NewLimiter(l.every, l.burst)}
		l.buckets[key] = b
	}
	b.seen = now
	res := b.r.ReserveN(now, 1)
	if delay := res.DelayFrom(now); delay > 0 {
		res.CancelAt(now)
		return false, delay
	}
	return true, 0
}

// limited wraps an endpoint in the per-IP limit of its bucket.
func (s *Server) limited(name string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok, wait := s.limits.allow(name+"|"+s.cfg.ClientIP(r), s.now())
		if !ok {
			secs := int(wait/time.Second) + 1
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h(w, r)
	}
}
