package formats

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _json_flat struct{}

func init() { module.Register(&_json_flat{}) }

func (j *_json_flat) Name() string { return "json_flat" }

func (j *_json_flat) Parse(raw []byte) (*ir.Dataset, error) {
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("failed to parse json: %w", err)
	}

	records := make([]ir.Record, 0, len(rows))
	seen_cols := map[string]bool{}

	for _, row := range rows {
		r := ir.Record{PTVID: ir.NewPTVID()}
		for k, v := range row {
			str := fmt.Sprintf("%v", v)
			if !_map_field_to_record(&r, k, str) {
				if r.Extra == nil {
					r.Extra = map[string]any{}
				}
				r.Extra[k] = v
			}
			seen_cols[k] = true
		}
		records = append(records, r)
	}

	cols := make([]string, 0, len(seen_cols))
	for k := range seen_cols {
		cols = append(cols, k)
	}

	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "json_flat",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (j *_json_flat) Render(ds *ir.Dataset) ([]byte, error) {
	rows := make([]map[string]any, 0, len(ds.Records))
	for _, r := range ds.Records {
		m := map[string]any{}
		if r.Email != "" {
			m["email"] = r.Email
		}
		if r.Username != "" {
			m["username"] = r.Username
		}
		if r.Password != "" {
			m["password"] = r.Password
		}
		if r.URL != "" {
			m["url"] = r.URL
		}
		if r.Domain != "" {
			m["domain"] = r.Domain
		}
		if r.IP != "" {
			m["ip"] = r.IP
		}
		if r.Phone != "" {
			m["phone"] = r.Phone
		}
		if r.Name != "" {
			m["name"] = r.Name
		}
		if r.Hash != nil {
			m["hash"] = r.Hash.Value
			m["hash_type"] = string(r.Hash.Type)
		}
		for k, v := range r.Extra {
			m[k] = v
		}
		if len(r.Unknowns) > 0 {
			unknowns := make([]map[string]any, len(r.Unknowns))
			for i, u := range r.Unknowns {
				unk := map[string]any{"value": u.Value}
				if len(u.PotentialFields) > 0 {
					pf := make([]map[string]any, len(u.PotentialFields))
					for j, p := range u.PotentialFields {
						pf[j] = map[string]any{"field": p.Field, "confidence": p.Confidence}
					}
					unk["potential_fields"] = pf
				}
				unknowns[i] = unk
			}
			m["unknowns"] = unknowns
		}
		rows = append(rows, m)
	}
	return json.MarshalIndent(rows, "", "  ")
}
