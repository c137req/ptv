package formats

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"github.com/parquet-go/parquet-go"
)

type _parquet struct{}

func init() { module.Register(&_parquet{}) }

func (p *_parquet) Name() string { return "parquet" }

func (p *_parquet) Parse(raw []byte) (*ir.Dataset, error) {
	file, err := parquet.OpenFile(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("failed to open parquet: %w", err)
	}

	schema := file.Schema()
	fields := schema.Fields()
	col_names := make([]string, len(fields))
	for i, f := range fields {
		col_names[i] = f.Name()
	}

	var records []ir.Record

	for _, rg := range file.RowGroups() {
		rows := rg.Rows()
		buf := make([]parquet.Row, 128)
		for {
			n, err := rows.ReadRows(buf)
			for i := 0; i < n; i++ {
				r := ir.Record{PTVID: ir.NewPTVID()}
				matched := 0

				for _, val := range buf[i] {
					if val.IsNull() {
						continue
					}
					col_idx := val.Column()
					if col_idx < 0 || col_idx >= len(col_names) {
						continue
					}

					str_val := _parquet_value_string(val)
					if str_val == "" {
						continue
					}

					if _map_field_to_record(&r, col_names[col_idx], str_val) {
						matched++
					} else {
						if r.Extra == nil {
							r.Extra = map[string]any{}
						}
						r.Extra[col_names[col_idx]] = str_val
					}
				}

				if matched > 0 {
					records = append(records, r)
				}
			}
			if err != nil {
				break
			}
		}
		rows.Close()
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "parquet",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func _parquet_value_string(v parquet.Value) string {
	switch v.Kind() {
	case parquet.ByteArray, parquet.FixedLenByteArray:
		return string(v.ByteArray())
	case parquet.Boolean:
		if v.Boolean() {
			return "true"
		}
		return "false"
	case parquet.Int32:
		return fmt.Sprintf("%d", v.Int32())
	case parquet.Int64:
		return fmt.Sprintf("%d", v.Int64())
	case parquet.Float:
		return fmt.Sprintf("%g", v.Float())
	case parquet.Double:
		return fmt.Sprintf("%g", v.Double())
	default:
		return ""
	}
}

type _parquet_row struct {
	Email    string `parquet:"email,optional"`
	Username string `parquet:"username,optional"`
	Password string `parquet:"password,optional"`
	URL      string `parquet:"url,optional"`
	Domain   string `parquet:"domain,optional"`
	IP       string `parquet:"ip,optional"`
	Phone    string `parquet:"phone,optional"`
	Name     string `parquet:"name,optional"`
	Hash     string `parquet:"hash,optional"`
}

func (p *_parquet) Render(ds *ir.Dataset) ([]byte, error) {
	tmp, err := os.CreateTemp("", "ptv-parquet-*.parquet")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmp_path := tmp.Name()
	defer os.Remove(tmp_path)

	writer := parquet.NewGenericWriter[_parquet_row](tmp)

	for _, r := range ds.Records {
		m := _record_to_map(r)
		row := _parquet_row{
			Email:    m["email"],
			Username: m["username"],
			Password: m["password"],
			URL:      m["url"],
			Domain:   m["domain"],
			IP:       m["ip"],
			Phone:    m["phone"],
			Name:     m["name"],
			Hash:     m["hash"],
		}
		writer.Write([]_parquet_row{row})
	}

	if err := writer.Close(); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("failed to close parquet writer: %w", err)
	}
	tmp.Close()

	return os.ReadFile(tmp_path)
}
