package formats

import (
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _env struct{}

func init() { module.Register(&_env{}) }

func (e *_env) Name() string { return "env" }

// credential-like key patterns
var _cred_keys = map[string]string{
	"password": "password", "passwd": "password", "pass": "password", "pwd": "password",
	"secret": "password", "secret_key": "password", "secret_token": "password",
	"token": "password", "api_key": "password", "apikey": "password",
	"access_key": "password", "private_key": "password",
}

func (e *_env) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))

	// env files are one record per file (a single config context), not one per line
	r := ir.Record{
		PTVID: ir.NewPTVID(),
		Extra: map[string]any{},
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// strip surrounding quotes
		val = strings.Trim(val, "\"'")

		lower_key := strings.ToLower(key)

		// check for credential-like keys
		matched := false
		for pattern, field := range _cred_keys {
			if strings.Contains(lower_key, pattern) {
				if field == "password" && r.Password == "" {
					r.Password = val
					matched = true
				} else if field == "password" {
					// already have a password, put additional secrets in extra
					r.Extra[key] = val
					matched = true
				}
				break
			}
		}

		if !matched {
			// check for other known fields
			switch {
			case strings.Contains(lower_key, "user") || lower_key == "login":
				if r.Username == "" {
					r.Username = val
				} else {
					r.Extra[key] = val
				}
			case strings.Contains(lower_key, "email") || strings.Contains(lower_key, "mail"):
				if r.Email == "" {
					r.Email = val
				} else {
					r.Extra[key] = val
				}
			case strings.Contains(lower_key, "host") || strings.Contains(lower_key, "ip"):
				if r.IP == "" {
					r.IP = val
				} else {
					r.Extra[key] = val
				}
			case strings.Contains(lower_key, "port"):
				r.Extra[key] = val
			default:
				r.Extra[key] = val
			}
		}
	}

	cols := []string{}
	conf := map[string]float64{}
	if r.Username != "" {
		cols = append(cols, "username")
		conf["username"] = 0.7
	}
	if r.Password != "" {
		cols = append(cols, "password")
		conf["password"] = 0.6
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "env",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     1,
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: []ir.Record{r},
	}, nil
}

func (e *_env) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		if r.Username != "" {
			b.WriteString(fmt.Sprintf("USER=%s\n", r.Username))
		}
		if r.Email != "" {
			b.WriteString(fmt.Sprintf("EMAIL=%s\n", r.Email))
		}
		if r.Password != "" {
			b.WriteString(fmt.Sprintf("PASSWORD=%s\n", r.Password))
		}
		if r.IP != "" {
			b.WriteString(fmt.Sprintf("HOST=%s\n", r.IP))
		}
		for k, v := range r.Extra {
			b.WriteString(fmt.Sprintf("%s=%v\n", k, v))
		}
	}
	return []byte(b.String()), nil
}
