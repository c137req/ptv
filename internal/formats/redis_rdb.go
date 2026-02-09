package formats

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"github.com/hdt3213/rdb/parser"
)

type _redis_rdb struct{}

func init() { module.Register(&_redis_rdb{}) }

func (rdb *_redis_rdb) Name() string { return "redis_rdb" }

func (rdb *_redis_rdb) Parse(raw []byte) (*ir.Dataset, error) {
	decoder := parser.NewDecoder(bytes.NewReader(raw))
	var records []ir.Record

	err := decoder.Parse(func(o parser.RedisObject) bool {
		switch obj := o.(type) {
		case *parser.StringObject:
			r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}
			key := obj.GetKey()
			val := string(obj.Value)
			matched := 0

			if _map_field_to_record(&r, key, val) {
				matched++
			} else if strings.Contains(key, ":") {
				parts := strings.SplitN(key, ":", 2)
				if _map_field_to_record(&r, parts[0], parts[1]) {
					matched++
					if val != "" {
						r.Password = val
						matched++
					}
				}
			}

			if matched == 0 && strings.Contains(val, ":") {
				parts := strings.SplitN(val, ":", 2)
				_classify_identity(&r, parts[0])
				r.Password = parts[1]
				r.Extra["key"] = key
				matched++
			}

			if matched == 0 {
				r.Extra["key"] = key
				r.Extra["value"] = val
			}

			r.Extra["db"] = fmt.Sprintf("%d", obj.GetDBIndex())
			if matched > 0 {
				records = append(records, r)
			}

		case *parser.HashObject:
			r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}
			matched := 0
			for field, val := range obj.Hash {
				v := string(val)
				if _map_field_to_record(&r, field, v) {
					matched++
				} else {
					r.Extra[field] = v
				}
			}
			r.Extra["key"] = obj.GetKey()
			r.Extra["db"] = fmt.Sprintf("%d", obj.GetDBIndex())
			if matched > 0 {
				records = append(records, r)
			}
		}
		return true
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse rdb: %w", err)
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.7
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "redis_rdb",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (rdb *_redis_rdb) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		key := _extra_str(r, "key")
		if key == "" && r.Domain != "" {
			key = r.Domain
		}
		if key == "" && r.Username != "" {
			key = "user:" + r.Username
		}
		if key == "" {
			key = r.PTVID
		}
		val := r.Password
		if val == "" {
			val = r.Email
		}
		b.WriteString(fmt.Sprintf("*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
			len(key), key, len(val), val))
	}
	return []byte(b.String()), nil
}
