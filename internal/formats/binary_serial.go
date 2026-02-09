package formats

import (
	"fmt"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"github.com/fxamacker/cbor/v2"
	"github.com/vmihailenco/msgpack/v5"
)

type _msgpack struct{}
type _cbor struct{}

func init() {
	module.Register(&_msgpack{})
	module.Register(&_cbor{})
}

func (m *_msgpack) Name() string { return "msgpack" }
func (c *_cbor) Name() string   { return "cbor" }

// --- msgpack ---

func (m *_msgpack) Parse(raw []byte) (*ir.Dataset, error) {
	var rows []map[string]any
	if err := msgpack.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("failed to parse msgpack: %w", err)
	}
	return _parse_kv_rows(rows, "msgpack"), nil
}

func (m *_msgpack) Render(ds *ir.Dataset) ([]byte, error) {
	return msgpack.Marshal(_render_kv_rows(ds))
}

// --- cbor ---

func (c *_cbor) Parse(raw []byte) (*ir.Dataset, error) {
	var rows []map[string]any
	if err := cbor.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("failed to parse cbor: %w", err)
	}
	return _parse_kv_rows(rows, "cbor"), nil
}

func (c *_cbor) Render(ds *ir.Dataset) ([]byte, error) {
	return cbor.Marshal(_render_kv_rows(ds))
}

// shared helpers for binary key-value serialisation formats

func _parse_kv_rows(rows []map[string]any, name string) *ir.Dataset {
	records := make([]ir.Record, 0, len(rows))
	seen := map[string]bool{}

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
			seen[k] = true
		}
		records = append(records, r)
	}

	cols := make([]string, 0, len(seen))
	for k := range seen {
		cols = append(cols, k)
	}
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    name,
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}
}

func _render_kv_rows(ds *ir.Dataset) []map[string]any {
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
	return rows
}
