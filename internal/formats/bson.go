package formats

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"go.mongodb.org/mongo-driver/bson"
)

type _bson struct{}

func init() { module.Register(&_bson{}) }

func (b *_bson) Name() string { return "bson" }

func (b *_bson) Parse(raw []byte) (*ir.Dataset, error) {
	docs, err := _read_bson_docs(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bson: %w", err)
	}

	records := make([]ir.Record, 0, len(docs))
	seen := map[string]bool{}

	for _, doc := range docs {
		r := ir.Record{PTVID: ir.NewPTVID()}
		for k, v := range doc {
			if k == "_id" {
				continue
			}
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
		if k != "_id" {
			cols = append(cols, k)
		}
	}
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "bson",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (b *_bson) Render(ds *ir.Dataset) ([]byte, error) {
	var out []byte
	for _, r := range ds.Records {
		doc := bson.M{}
		if r.Email != "" {
			doc["email"] = r.Email
		}
		if r.Username != "" {
			doc["username"] = r.Username
		}
		if r.Password != "" {
			doc["password"] = r.Password
		}
		if r.URL != "" {
			doc["url"] = r.URL
		}
		if r.Domain != "" {
			doc["domain"] = r.Domain
		}
		if r.IP != "" {
			doc["ip"] = r.IP
		}
		if r.Phone != "" {
			doc["phone"] = r.Phone
		}
		if r.Name != "" {
			doc["name"] = r.Name
		}
		for k, v := range r.Extra {
			doc[k] = v
		}
		data, err := bson.Marshal(doc)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal bson: %w", err)
		}
		out = append(out, data...)
	}
	return out, nil
}

func _read_bson_docs(raw []byte) ([]bson.M, error) {
	var docs []bson.M
	offset := 0
	for offset < len(raw) {
		if offset+4 > len(raw) {
			break
		}
		doc_len := int(binary.LittleEndian.Uint32(raw[offset : offset+4]))
		if doc_len < 5 || offset+doc_len > len(raw) {
			break
		}
		var doc bson.M
		if err := bson.Unmarshal(raw[offset:offset+doc_len], &doc); err != nil {
			return docs, fmt.Errorf("bson document at offset %d: %w", offset, err)
		}
		docs = append(docs, doc)
		offset += doc_len
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no valid bson documents found")
	}
	return docs, nil
}
