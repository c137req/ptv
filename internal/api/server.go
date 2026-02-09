package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/c137req/ptv/internal/module"
)

type _config struct {
	bind     string
	api_key  []byte
	max_body int64
	rate_rpm int
	cors     string
	tls_cert string
	tls_key  string
	timeout  time.Duration
	verbose  bool
	log_fn   func(string, ...any)
}

type _metrics struct {
	total_requests   atomic.Int64
	ok_requests      atomic.Int64
	fail_requests    atomic.Int64
	rate_limited     atomic.Int64
	auth_failures    atomic.Int64
	total_latency_ns atomic.Int64
	mu               sync.Mutex
	format_from      map[string]int
	format_to        map[string]int
}

type _server struct {
	cfg     _config
	srv     *http.Server
	ln      net.Listener
	started time.Time
	limiter *_rate_limiter
	stats   _metrics
}

// --- json types ---

type _convert_req struct {
	Data string `json:"data"`
}

type _api_resp struct {
	OK      bool           `json:"ok"`
	Data    string         `json:"data,omitempty"`
	Meta    *_resp_meta    `json:"meta,omitempty"`
	Formats []string       `json:"formats,omitempty"`
	Count   int            `json:"count,omitempty"`
	Uptime  float64        `json:"uptime_seconds,omitempty"`
	Stats   *_metrics_resp `json:"stats,omitempty"`
	Error   *_api_err      `json:"error,omitempty"`
}

type _resp_meta struct {
	SourceFormat string `json:"source_format"`
	TargetFormat string `json:"target_format"`
	RecordCount  int    `json:"record_count"`
	ParsedAt     string `json:"parsed_at"`
}

type _metrics_resp struct {
	Total       int64              `json:"total"`
	Successful  int64              `json:"successful"`
	Failed      int64              `json:"failed"`
	RateLimited int64              `json:"rate_limited"`
	AuthFails   int64              `json:"auth_failures"`
	AvgLatMs    float64            `json:"avg_latency_ms"`
	Conversions map[string]_fmt_ct `json:"conversions"`
}

type _fmt_ct struct {
	From int `json:"from"`
	To   int `json:"to"`
}

type _api_err struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewServer creates a configured server. does not start listening.
func NewServer(
	bind string,
	api_key string,
	max_body int64,
	rate_rpm int,
	cors string,
	tls_cert string,
	tls_key string,
	timeout time.Duration,
	verbose bool,
	log_fn func(string, ...any),
) *_server {
	s := &_server{
		cfg: _config{
			bind:     bind,
			api_key:  []byte(api_key),
			max_body: max_body,
			cors:     cors,
			tls_cert: tls_cert,
			tls_key:  tls_key,
			timeout:  timeout,
			verbose:  verbose,
			log_fn:   log_fn,
		},
		stats: _metrics{
			format_from: make(map[string]int),
			format_to:   make(map[string]int),
		},
	}

	if rate_rpm > 0 {
		s.limiter = _new_rate_limiter(rate_rpm)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /convert/{from}/{to}", s._handle_convert)
	mux.HandleFunc("GET /formats", s._handle_formats)
	mux.HandleFunc("GET /health", s._handle_health)
	mux.HandleFunc("GET /metrics", s._handle_metrics)

	s.srv = &http.Server{
		Handler:           s._build_chain(mux),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      timeout + 5*time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	return s
}

// Listen creates the listener. call before ListenAndServe for random-port support.
func (s *_server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.bind)
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Addr returns the listener address (useful for random port).
func (s *_server) Addr() string {
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.cfg.bind
}

// Serve starts serving on the existing listener. blocks until shutdown.
func (s *_server) Serve() error {
	s.started = time.Now()
	if s.cfg.tls_cert != "" && s.cfg.tls_key != "" {
		return s.srv.ServeTLS(s.ln, s.cfg.tls_cert, s.cfg.tls_key)
	}
	return s.srv.Serve(s.ln)
}

// Shutdown gracefully stops the server.
func (s *_server) Shutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// --- handlers ---

var _format_re = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (s *_server) _handle_convert(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s.stats.total_requests.Add(1)

	from_name := r.PathValue("from")
	to_name := r.PathValue("to")

	if !_format_re.MatchString(from_name) || !_format_re.MatchString(to_name) {
		s.stats.fail_requests.Add(1)
		_write_error(w, http.StatusBadRequest, "invalid_format", "conversion failed")
		return
	}

	var req _convert_req
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.stats.fail_requests.Add(1)
		_write_error(w, http.StatusBadRequest, "bad_request", "invalid request body")
		return
	}

	raw, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		s.stats.fail_requests.Add(1)
		_write_error(w, http.StatusBadRequest, "bad_data", "data must be valid base64")
		return
	}
	if len(raw) == 0 {
		s.stats.fail_requests.Add(1)
		_write_error(w, http.StatusBadRequest, "empty_data", "data must not be empty")
		return
	}

	// anti-enumeration: always look up both before checking either
	from_mod, from_ok := module.Get(from_name)
	to_mod, to_ok := module.Get(to_name)
	if !from_ok || !to_ok {
		s.stats.fail_requests.Add(1)
		_write_error(w, http.StatusBadRequest, "invalid_format", "conversion failed")
		return
	}

	ds, err := from_mod.Parse(raw)
	if err != nil {
		s.cfg.log_fn("parse error (%s): %v", from_name, err)
		s.stats.fail_requests.Add(1)
		_write_error(w, http.StatusUnprocessableEntity, "parse_error", "conversion failed")
		return
	}

	out, err := to_mod.Render(ds)
	if err != nil {
		s.cfg.log_fn("render error (%s): %v", to_name, err)
		s.stats.fail_requests.Add(1)
		_write_error(w, http.StatusUnprocessableEntity, "render_error", "conversion failed")
		return
	}

	s.stats.ok_requests.Add(1)
	s.stats.total_latency_ns.Add(time.Since(start).Nanoseconds())
	s.stats.mu.Lock()
	s.stats.format_from[from_name]++
	s.stats.format_to[to_name]++
	s.stats.mu.Unlock()

	_write_json(w, http.StatusOK, _api_resp{
		OK:   true,
		Data: base64.StdEncoding.EncodeToString(out),
		Meta: &_resp_meta{
			SourceFormat: from_name,
			TargetFormat: to_name,
			RecordCount:  ds.Meta.RecordCount,
			ParsedAt:     ds.Meta.ParsedAt,
		},
	})
}

func (s *_server) _handle_formats(w http.ResponseWriter, r *http.Request) {
	fmts := module.List()
	_write_json(w, http.StatusOK, _api_resp{
		OK:      true,
		Formats: fmts,
		Count:   len(fmts),
	})
}

func (s *_server) _handle_health(w http.ResponseWriter, r *http.Request) {
	_write_json(w, http.StatusOK, _api_resp{
		OK:     true,
		Count:  len(module.List()),
		Uptime: time.Since(s.started).Seconds(),
	})
}

func (s *_server) _handle_metrics(w http.ResponseWriter, r *http.Request) {
	total := s.stats.total_requests.Load()
	ok := s.stats.ok_requests.Load()
	fail := s.stats.fail_requests.Load()
	lat_ns := s.stats.total_latency_ns.Load()

	avg_ms := float64(0)
	if ok > 0 {
		avg_ms = float64(lat_ns) / float64(ok) / 1e6
	}

	s.stats.mu.Lock()
	convs := make(map[string]_fmt_ct)
	for name, ct := range s.stats.format_from {
		e := convs[name]
		e.From = ct
		convs[name] = e
	}
	for name, ct := range s.stats.format_to {
		e := convs[name]
		e.To = ct
		convs[name] = e
	}
	s.stats.mu.Unlock()

	_write_json(w, http.StatusOK, _api_resp{
		OK:     true,
		Uptime: time.Since(s.started).Seconds(),
		Stats: &_metrics_resp{
			Total:       total,
			Successful:  ok,
			Failed:      fail,
			RateLimited: s.stats.rate_limited.Load(),
			AuthFails:   s.stats.auth_failures.Load(),
			AvgLatMs:    avg_ms,
			Conversions: convs,
		},
	})
}

// --- helpers ---

func _write_json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func _write_error(w http.ResponseWriter, status int, code string, msg string) {
	_write_json(w, status, _api_resp{
		OK:    false,
		Error: &_api_err{Code: code, Message: msg},
	})
}

// --- api key generation ---

// charset: latin lowercase + digits + cyrillic lowercase
var _key_charset = []rune("abcdefghijklmnopqrstuvwxyz0123456789абвгдежзиклмнопрстуфхцчшщэюя")

// GenerateKey creates a random 16-character api key.
func GenerateKey() (string, error) {
	max := big.NewInt(int64(len(_key_charset)))
	key := make([]rune, 16)
	for i := range key {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("key generation failed: %w", err)
		}
		key[i] = _key_charset[n.Int64()]
	}
	return string(key), nil
}
