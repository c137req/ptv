package formats

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	bencode "github.com/jackpal/bencode-go"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _bencode struct{}

func init() { module.Register(&_bencode{}) }

func (b *_bencode) Name() string { return "bencode" }

func (bc *_bencode) Parse(raw []byte) (*ir.Dataset, error) {
	decoded, err := bencode.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to parse bencode: %w", err)
	}

	var records []ir.Record

	switch val := decoded.(type) {
	case map[string]any:
		r := _parse_bencode_dict(val)
		if r != nil {
			records = append(records, *r)
		}
	case []any:
		for _, item := range val {
			if dict, ok := item.(map[string]any); ok {
				r := _parse_bencode_dict(dict)
				if r != nil {
					records = append(records, *r)
				}
			}
		}
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.8
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "bencode",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func _parse_bencode_dict(dict map[string]any) *ir.Record {
	r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}

	// check if this looks like torrent metainfo
	if announce, ok := dict["announce"].(string); ok {
		r.URL = announce
	}
	if info, ok := dict["info"].(map[string]any); ok {
		if name, ok := info["name"].(string); ok {
			r.Name = name
		}
		if length, ok := info["length"].(int64); ok {
			r.Extra["length"] = length
		}
		if pl, ok := info["piece length"].(int64); ok {
			r.Extra["piece_length"] = pl
		}
	}
	if comment, ok := dict["comment"].(string); ok {
		r.Extra["comment"] = comment
	}
	if created_by, ok := dict["created by"].(string); ok {
		r.Extra["created_by"] = created_by
	}
	if cd, ok := dict["creation date"].(int64); ok {
		r.Extra["creation_date"] = cd
	}

	// if not torrent-shaped, try generic field mapping
	if r.URL == "" && r.Name == "" {
		matched := 0
		for k, v := range dict {
			str := fmt.Sprintf("%v", v)
			if _map_field_to_record(&r, k, str) {
				matched++
			} else {
				r.Extra[k] = v
			}
		}
		if matched == 0 {
			return nil
		}
	}

	return &r
}

func (bc *_bencode) Render(ds *ir.Dataset) ([]byte, error) {
	var results []byte

	for _, r := range ds.Records {
		dict := map[string]any{}
		if r.URL != "" {
			dict["announce"] = r.URL
		}
		info := map[string]any{}
		if r.Name != "" {
			info["name"] = r.Name
		}
		if pl, ok := r.Extra["piece_length"]; ok {
			info["piece length"] = pl
		}
		if length, ok := r.Extra["length"]; ok {
			info["length"] = length
		}
		if len(info) > 0 {
			dict["info"] = info
		}
		if comment := _extra_str(r, "comment"); comment != "" {
			dict["comment"] = comment
		}
		if cb := _extra_str(r, "created_by"); cb != "" {
			dict["created by"] = cb
		}
		if cd, ok := r.Extra["creation_date"]; ok {
			dict["creation date"] = cd
		}

		// add non-standard extra fields
		for k, v := range r.Extra {
			switch k {
			case "comment", "created_by", "creation_date", "piece_length", "length":
				continue
			default:
				dict[k] = v
			}
		}

		var buf bytes.Buffer
		if err := bencode.Marshal(&buf, dict); err != nil {
			return nil, fmt.Errorf("failed to render bencode: %w", err)
		}
		results = append(results, buf.Bytes()...)
	}
	_ = strings.Join // keep import
	return results, nil
}
