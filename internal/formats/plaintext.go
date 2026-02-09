package formats

import (
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _plaintext struct{}

func init() { module.Register(&_plaintext{}) }

func (p *_plaintext) Name() string { return "plaintext" }

func (p *_plaintext) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))

	for _, line := range lines {
		if line == "" {
			continue
		}
		r := ir.Record{PTVID: ir.NewPTVID()}

		// we can't know what a bare line is without context
		if strings.Contains(line, "@") {
			r.Email = line
		} else {
			r.Unknowns = []ir.UnknownField{{
				Value: line,
				PotentialFields: []ir.PotentialField{
					{Field: "password", Confidence: 0.5},
					{Field: "username", Confidence: 0.4},
				},
			}}
		}
		records = append(records, r)
	}

	cols := []string{"email"}
	conf := map[string]float64{"email": 0.7}
	if len(records) > 0 && len(records[0].Unknowns) > 0 {
		cols = []string{}
		conf = map[string]float64{}
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "plaintext",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (p *_plaintext) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		val := _first_populated(r)
		if val != "" {
			b.WriteString(val)
			b.WriteByte('\n')
		}
	}
	return []byte(b.String()), nil
}

func _first_populated(r ir.Record) string {
	if r.Email != "" {
		return r.Email
	}
	if r.Username != "" {
		return r.Username
	}
	if r.Password != "" {
		return r.Password
	}
	if r.Hash != nil {
		return r.Hash.Value
	}
	if len(r.Unknowns) > 0 {
		return r.Unknowns[0].Value
	}
	return ""
}
