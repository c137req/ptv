package formats

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _csv_mod struct{}
type _tsv_mod struct{}

func init() {
	module.Register(&_csv_mod{})
	module.Register(&_tsv_mod{})
}

func (c *_csv_mod) Name() string { return "csv" }
func (t *_tsv_mod) Name() string { return "tsv" }

func (c *_csv_mod) Parse(raw []byte) (*ir.Dataset, error) { return _parse_delimited(raw, ',', "csv") }
func (t *_tsv_mod) Parse(raw []byte) (*ir.Dataset, error) { return _parse_delimited(raw, '\t', "tsv") }

func (c *_csv_mod) Render(ds *ir.Dataset) ([]byte, error) { return _render_delimited(ds, ',') }
func (t *_tsv_mod) Render(ds *ir.Dataset) ([]byte, error) { return _render_delimited(ds, '\t') }

func _parse_delimited(raw []byte, sep rune, name string) (*ir.Dataset, error) {
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.Comma = sep
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", name, err)
	}
	if len(rows) < 2 {
		return &ir.Dataset{PTVVersion: "1.0", Meta: ir.Meta{SourceFormat: name, ParsedAt: time.Now().UTC().Format(time.RFC3339)}}, nil
	}

	headers := rows[0]
	records := make([]ir.Record, 0, len(rows)-1)

	for _, row := range rows[1:] {
		r := ir.Record{PTVID: ir.NewPTVID()}
		for i, val := range row {
			if i >= len(headers) {
				break
			}
			if !_map_field_to_record(&r, headers[i], val) {
				if r.Extra == nil {
					r.Extra = map[string]any{}
				}
				r.Extra[headers[i]] = val
			}
		}
		records = append(records, r)
	}

	cols := make([]string, len(headers))
	copy(cols, headers)
	conf := map[string]float64{}
	for _, h := range headers {
		conf[strings.ToLower(h)] = 1.0
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
	}, nil
}

func _render_delimited(ds *ir.Dataset, sep rune) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Comma = sep

	cols := ds.Meta.Columns
	if len(cols) == 0 {
		cols = _detect_columns(ds.Records)
	}

	w.Write(cols)
	for _, r := range ds.Records {
		m := _record_to_map(r)
		row := make([]string, len(cols))
		for i, col := range cols {
			row[i] = m[strings.ToLower(col)]
		}
		w.Write(row)
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func _detect_columns(records []ir.Record) []string {
	seen := map[string]bool{}
	var cols []string
	for _, r := range records {
		m := _record_to_map(r)
		for k := range m {
			if !seen[k] {
				seen[k] = true
				cols = append(cols, k)
			}
		}
	}
	return cols
}
