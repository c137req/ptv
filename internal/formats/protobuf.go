package formats

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"google.golang.org/protobuf/encoding/protowire"
)

type _protobuf struct{}

func init() { module.Register(&_protobuf{}) }

func (p *_protobuf) Name() string { return "protobuf" }

func (p *_protobuf) Parse(raw []byte) (*ir.Dataset, error) {
	// try as a wrapper message where each field 1 is a length-delimited sub-message
	records := _pb_parse_wrapper(raw)
	if len(records) == 0 {
		// try as a single message
		if r, ok := _pb_parse_message(raw); ok {
			records = append(records, r)
		}
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("protobuf: no parseable records found")
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.3
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "protobuf",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

// _pb_parse_wrapper tries to parse raw as repeated field-1 length-delimited messages
func _pb_parse_wrapper(raw []byte) []ir.Record {
	var records []ir.Record
	buf := raw
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			break
		}
		if typ != protowire.BytesType {
			break
		}
		buf = buf[n:]
		data, n := protowire.ConsumeBytes(buf)
		if n < 0 {
			break
		}
		buf = buf[n:]

		if num == 1 {
			if r, ok := _pb_parse_message(data); ok {
				records = append(records, r)
			}
		}
	}
	return records
}

// _pb_parse_message parses a single protobuf message into an IR record
func _pb_parse_message(data []byte) (ir.Record, bool) {
	r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}
	matched := 0
	buf := data

	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			break
		}
		buf = buf[n:]

		switch typ {
		case protowire.BytesType:
			val, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return r, false
			}
			buf = buf[n:]

			if utf8.Valid(val) {
				s := string(val)
				fieldName := fmt.Sprintf("field_%d", num)
				if _map_field_to_record(&r, fieldName, s) {
					matched++
				} else if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
					if r.URL == "" {
						r.URL = s
						matched++
					} else {
						r.Extra[fieldName] = s
					}
				} else if strings.Contains(s, "@") && strings.Contains(s, ".") {
					if r.Email == "" {
						r.Email = s
						matched++
					} else {
						r.Extra[fieldName] = s
					}
				} else {
					r.Extra[fieldName] = s
				}
			} else {
				// try recursive parse
				if sub, ok := _pb_parse_message(val); ok {
					// merge sub-record fields
					if sub.Email != "" && r.Email == "" {
						r.Email = sub.Email
						matched++
					}
					if sub.Username != "" && r.Username == "" {
						r.Username = sub.Username
						matched++
					}
					if sub.Password != "" && r.Password == "" {
						r.Password = sub.Password
						matched++
					}
					if sub.URL != "" && r.URL == "" {
						r.URL = sub.URL
						matched++
					}
					if sub.Domain != "" && r.Domain == "" {
						r.Domain = sub.Domain
						matched++
					}
				} else {
					r.Extra[fmt.Sprintf("field_%d", num)] = fmt.Sprintf("%x", val)
				}
			}

		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(buf)
			if n < 0 {
				return r, false
			}
			buf = buf[n:]
			r.Extra[fmt.Sprintf("field_%d", num)] = v

		case protowire.Fixed32Type:
			v, n := protowire.ConsumeFixed32(buf)
			if n < 0 {
				return r, false
			}
			buf = buf[n:]
			r.Extra[fmt.Sprintf("field_%d", num)] = v

		case protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(buf)
			if n < 0 {
				return r, false
			}
			buf = buf[n:]
			r.Extra[fmt.Sprintf("field_%d", num)] = v

		default:
			// unknown wire type, bail
			return r, matched > 0
		}
	}

	if len(r.Extra) == 0 {
		r.Extra = nil
	}
	return r, matched > 0
}

func (p *_protobuf) Render(ds *ir.Dataset) ([]byte, error) {
	var out []byte
	for _, r := range ds.Records {
		var msg []byte
		fieldNum := protowire.Number(1)

		m := _record_to_map(r)
		for _, key := range []string{"email", "username", "password", "url", "domain", "ip", "phone", "name", "hash"} {
			if val, ok := m[key]; ok {
				msg = protowire.AppendTag(msg, fieldNum, protowire.BytesType)
				msg = protowire.AppendString(msg, val)
			}
			fieldNum++
		}

		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, msg)
	}
	return out, nil
}
