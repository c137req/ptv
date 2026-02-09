package formats

import (
	"bytes"
	"fmt"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"github.com/xuri/excelize/v2"
)

type _excel struct{}

func init() { module.Register(&_excel{}) }

func (e *_excel) Name() string { return "excel" }

func (e *_excel) Parse(raw []byte) (*ir.Dataset, error) {
	f, err := excelize.OpenReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to open xlsx: %w", err)
	}
	defer f.Close()

	sheet := f.GetSheetName(0)
	if sheet == "" {
		return nil, fmt.Errorf("xlsx has no sheets")
	}

	rows, err := f.GetRows(sheet)
	if err != nil {
		return nil, fmt.Errorf("failed to read xlsx rows: %w", err)
	}

	if len(rows) < 2 {
		return &ir.Dataset{
			PTVVersion: "1.0",
			Meta: ir.Meta{
				SourceFormat: "excel",
				ParsedAt:     time.Now().UTC().Format(time.RFC3339),
				RecordCount:  0,
				Columns:      []string{},
				FieldConfidence: map[string]float64{},
			},
			Records: []ir.Record{},
		}, nil
	}

	headers := rows[0]
	var records []ir.Record

	for _, row := range rows[1:] {
		all_empty := true
		for _, cell := range row {
			if cell != "" {
				all_empty = false
				break
			}
		}
		if all_empty {
			continue
		}

		r := ir.Record{PTVID: ir.NewPTVID()}
		matched := 0
		for i, header := range headers {
			if i >= len(row) {
				break
			}
			val := row[i]
			if val == "" {
				continue
			}
			if _map_field_to_record(&r, header, val) {
				matched++
			} else {
				if r.Extra == nil {
					r.Extra = map[string]any{}
				}
				r.Extra[header] = val
			}
		}
		if matched > 0 {
			records = append(records, r)
		}
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "excel",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (e *_excel) Render(ds *ir.Dataset) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()
	sheet := "Sheet1"

	cols := ds.Meta.Columns
	if len(cols) == 0 {
		cols = _detect_columns(ds.Records)
	}

	// write headers
	for i, col := range cols {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheet, cell, col)
	}

	// write data rows
	for row_idx, r := range ds.Records {
		m := _record_to_map(r)
		for col_idx, col := range cols {
			cell, _ := excelize.CoordinatesToCellName(col_idx+1, row_idx+2)
			f.SetCellValue(sheet, cell, m[col])
		}
	}

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("failed to write xlsx: %w", err)
	}

	return buf.Bytes(), nil
}
