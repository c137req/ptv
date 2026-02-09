package formats

import (
	"fmt"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"howett.net/plist"
)

type _plist struct{}

func init() { module.Register(&_plist{}) }

func (p *_plist) Name() string { return "plist" }

func (pl *_plist) Parse(raw []byte) (*ir.Dataset, error) {
	var root any
	_, err := plist.Unmarshal(raw, &root)
	if err != nil {
		return nil, fmt.Errorf("failed to parse plist: %w", err)
	}

	// plist deserialises to the same Go types as JSON (maps, slices, strings)
	// so we can reuse _walk_json
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
			SourceFormat:    "plist",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (pl *_plist) Render(ds *ir.Dataset) ([]byte, error) {
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
		for k, v := range r.Extra {
			m[k] = v
		}
		rows = append(rows, m)
	}

	root := map[string]any{"records": rows}
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to render plist: %w", err)
	}

	return data, nil
}
