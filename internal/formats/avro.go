package formats

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"github.com/linkedin/goavro/v2"
)

type _avro struct{}

func init() { module.Register(&_avro{}) }

func (a *_avro) Name() string { return "avro" }

func (a *_avro) Parse(raw []byte) (*ir.Dataset, error) {
	ocf, err := goavro.NewOCFReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to open avro: %w", err)
	}

	var records []ir.Record

	for ocf.Scan() {
		datum, err := ocf.Read()
		if err != nil {
			continue
		}

		m, ok := datum.(map[string]any)
		if !ok {
			continue
		}

		r := ir.Record{PTVID: ir.NewPTVID()}
		matched := 0

		for key, val := range m {
			var str_val string
			switch v := val.(type) {
			case string:
				str_val = v
			case map[string]any:
				// avro union type: {"string": "value"}
				for _, uv := range v {
					str_val = fmt.Sprintf("%v", uv)
					break
				}
			default:
				if val != nil {
					str_val = fmt.Sprintf("%v", val)
				}
			}

			if str_val == "" {
				continue
			}

			if _map_field_to_record(&r, key, str_val) {
				matched++
			} else {
				if r.Extra == nil {
					r.Extra = map[string]any{}
				}
				r.Extra[key] = str_val
			}
		}

		if matched > 0 {
			records = append(records, r)
		}
	}

	if err := ocf.Err(); err != nil {
		return nil, fmt.Errorf("avro read error: %w", err)
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "avro",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (a *_avro) Render(ds *ir.Dataset) ([]byte, error) {
	cols := ds.Meta.Columns
	if len(cols) == 0 {
		cols = _detect_columns(ds.Records)
	}

	var fields []string
	for _, col := range cols {
		fields = append(fields, fmt.Sprintf(`{"name":"%s","type":["null","string"],"default":null}`, col))
	}
	schema := fmt.Sprintf(`{"type":"record","name":"credential","fields":[%s]}`, strings.Join(fields, ","))

	var buf bytes.Buffer
	ocf, err := goavro.NewOCFWriter(goavro.OCFConfig{
		W:      &buf,
		Schema: schema,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create avro writer: %w", err)
	}

	for _, r := range ds.Records {
		m := _record_to_map(r)
		datum := map[string]any{}
		for _, col := range cols {
			val := m[col]
			if val != "" {
				datum[col] = goavro.Union("string", val)
			}
		}
		if err := ocf.Append([]any{datum}); err != nil {
			continue
		}
	}

	return buf.Bytes(), nil
}
