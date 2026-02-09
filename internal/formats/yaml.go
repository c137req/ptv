package formats

import (
	"fmt"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"gopkg.in/yaml.v3"
)

type _yaml struct{}

func init() { module.Register(&_yaml{}) }

func (y *_yaml) Name() string { return "yaml" }

func (y *_yaml) Parse(raw []byte) (*ir.Dataset, error) {
	var root any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	var records []ir.Record
	_walk_json(root, &records)

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.8
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "yaml",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (y *_yaml) Render(ds *ir.Dataset) ([]byte, error) {
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
		rows = append(rows, m)
	}
	return yaml.Marshal(rows)
}
