package formats

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _base64_creds struct{}

func init() { module.Register(&_base64_creds{}) }

func (b *_base64_creds) Name() string { return "base64_creds" }

func (b *_base64_creds) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))

	for _, line := range lines {
		if line == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil {
			// try url-safe
			decoded, err = base64.URLEncoding.DecodeString(strings.TrimSpace(line))
			if err != nil {
				continue
			}
		}
		r := ir.Record{PTVID: ir.NewPTVID()}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) >= 1 {
			_classify_identity(&r, parts[0])
		}
		if len(parts) >= 2 {
			r.Password = parts[1]
		}
		records = append(records, r)
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "base64_creds",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         []string{"email", "username", "password"},
			FieldConfidence: map[string]float64{"email": 0.8, "username": 0.8, "password": 1.0},
		},
		Records: records,
	}, nil
}

func (b *_base64_creds) Render(ds *ir.Dataset) ([]byte, error) {
	var out strings.Builder
	for _, r := range ds.Records {
		ident := r.Email
		if ident == "" {
			ident = r.Username
		}
		plain := ident + ":" + r.Password
		out.WriteString(base64.StdEncoding.EncodeToString([]byte(plain)))
		out.WriteByte('\n')
	}
	return []byte(out.String()), nil
}
