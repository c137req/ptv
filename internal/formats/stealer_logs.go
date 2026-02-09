package formats

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _stealer_logs struct{}

func init() { module.Register(&_stealer_logs{}) }

func (s *_stealer_logs) Name() string { return "stealer_logs" }

func (s *_stealer_logs) Parse(raw []byte) (*ir.Dataset, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")

	// split on redline separator first, then split remaining blocks on double newline
	var blocks []string
	parts := strings.Split(text, "===============\n")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// within each redline section, further split on double newline (racoon style)
		subs := strings.Split(part, "\n\n")
		for _, sub := range subs {
			sub = strings.TrimSpace(sub)
			if sub != "" {
				blocks = append(blocks, sub)
			}
		}
	}

	var records []ir.Record
	for _, block := range blocks {
		r := ir.Record{PTVID: ir.NewPTVID()}
		lines := strings.Split(block, "\n")
		matched := 0

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || line == "===============" {
				continue
			}

			lower := strings.ToLower(line)

			switch {
			case _stealer_has_prefix(lower, "url:", "host:", "hostname:"):
				val := _stealer_after_colon(line)
				if val != "" {
					r.URL = val
					if u, err := url.Parse(val); err == nil && u.Host != "" {
						r.Domain = u.Hostname()
					}
					matched++
				}

			case _stealer_has_prefix(lower, "username:", "user:", "login:", "user login:"):
				val := _stealer_after_colon(line)
				if val != "" {
					_classify_identity(&r, val)
					matched++
				}

			case _stealer_has_prefix(lower, "password:", "pass:", "user password:"):
				val := _stealer_after_colon(line)
				if val != "" {
					r.Password = val
					matched++
				}
			}
		}

		if matched > 0 {
			records = append(records, r)
		}
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.9
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "stealer_logs",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (s *_stealer_logs) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for i, r := range ds.Records {
		if i > 0 {
			b.WriteByte('\n')
		}
		u := r.URL
		if u == "" && r.Domain != "" {
			u = "https://" + r.Domain
		}
		b.WriteString(fmt.Sprintf("URL: %s\n", u))

		identity := r.Email
		if identity == "" {
			identity = r.Username
		}
		b.WriteString(fmt.Sprintf("Username: %s\n", identity))
		b.WriteString(fmt.Sprintf("Password: %s\n", r.Password))
	}
	return []byte(b.String()), nil
}

func _stealer_has_prefix(lower string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func _stealer_after_colon(line string) string {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}
