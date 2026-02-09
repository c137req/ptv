package api

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"sync"
	"time"
)

// _build_chain wraps a handler with all middleware in correct order.
// outermost (first to run on request) listed first.
func (s *_server) _build_chain(h http.Handler) http.Handler {
	h = s._mw_log(h)
	h = s._mw_timeout(h)
	h = s._mw_auth(h)
	h = s._mw_body_limit(h)
	h = s._mw_rate_limit(h)
	h = s._mw_cors(h)
	h = s._mw_internal_ip(h)
	h = s._mw_security_headers(h)
	h = s._mw_recover(h)
	return h
}

// --- recovery ---

func (s *_server) _mw_recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rv := recover(); rv != nil {
				s.cfg.log_fn("panic recovered: %v", rv)
				_write_error(w, http.StatusInternalServerError,
					"internal_error", "an internal error occurred")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// --- security headers ---

func (s *_server) _mw_security_headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// --- internal ip gate ---

func (s *_server) _mw_internal_ip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := _parse_ip(r.RemoteAddr)
		if ip == nil || (!ip.IsLoopback() && !ip.IsPrivate()) {
			_write_error(w, http.StatusForbidden,
				"forbidden", "access denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func _parse_ip(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.ParseIP(host)
}

// --- cors ---

func (s *_server) _mw_cors(next http.Handler) http.Handler {
	if s.cfg.cors == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", s.cfg.cors)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- rate limiting ---

type _rate_entry struct {
	tokens []int64
}

type _rate_limiter struct {
	mu      sync.Mutex
	entries map[string]*_rate_entry
	rpm     int
	window  int64 // milliseconds
}

func _new_rate_limiter(rpm int) *_rate_limiter {
	rl := &_rate_limiter{
		entries: make(map[string]*_rate_entry),
		rpm:     rpm,
		window:  60_000,
	}
	go rl._cleanup_loop()
	return rl
}

func (rl *_rate_limiter) _allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UnixMilli()
	cutoff := now - rl.window

	entry, ok := rl.entries[ip]
	if !ok {
		entry = &_rate_entry{}
		rl.entries[ip] = entry
	}

	valid := entry.tokens[:0]
	for _, ts := range entry.tokens {
		if ts > cutoff {
			valid = append(valid, ts)
		}
	}
	entry.tokens = valid

	if len(entry.tokens) >= rl.rpm {
		return false
	}
	entry.tokens = append(entry.tokens, now)
	return true
}

func (rl *_rate_limiter) _cleanup_loop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now().UnixMilli()
		cutoff := now - rl.window
		for ip, entry := range rl.entries {
			recent := false
			for _, ts := range entry.tokens {
				if ts > cutoff {
					recent = true
					break
				}
			}
			if !recent {
				delete(rl.entries, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (s *_server) _mw_rate_limit(next http.Handler) http.Handler {
	if s.limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := _parse_ip(r.RemoteAddr)
		if ip == nil || !s.limiter._allow(ip.String()) {
			s.stats.rate_limited.Add(1)
			w.Header().Set("Retry-After", "60")
			_write_error(w, http.StatusTooManyRequests,
				"rate_limited", "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- body size limit ---

func (s *_server) _mw_body_limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.max_body)
		}
		next.ServeHTTP(w, r)
	})
}

// --- authentication ---

func (s *_server) _mw_auth(next http.Handler) http.Handler {
	if len(s.cfg.api_key) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// health is unauthenticated
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		provided := []byte(r.Header.Get("X-API-Key"))
		expected := s.cfg.api_key

		// constant-time compare with length padding
		match := subtle.ConstantTimeCompare(
			_pad_to(provided, len(expected)),
			expected,
		)
		if match != 1 || len(provided) != len(expected) {
			s.stats.auth_failures.Add(1)
			_write_error(w, http.StatusUnauthorized,
				"unauthorised", "invalid or missing api key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func _pad_to(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	p := make([]byte, n)
	copy(p, b)
	return p
}

// --- timeout ---

func (s *_server) _mw_timeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- logging ---

type _status_writer struct {
	http.ResponseWriter
	code int
}

func (sw *_status_writer) WriteHeader(code int) {
	sw.code = code
	sw.ResponseWriter.WriteHeader(code)
}

func (s *_server) _mw_log(next http.Handler) http.Handler {
	if !s.cfg.verbose {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &_status_writer{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		dur := time.Since(start).Round(time.Microsecond)
		ip := _parse_ip(r.RemoteAddr)
		s.cfg.log_fn("%s %s %d %s %s", r.Method, r.URL.Path, sw.code, dur, ip)
	})
}
