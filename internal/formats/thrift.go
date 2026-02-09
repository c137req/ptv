package formats

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _thrift struct{}

func init() { module.Register(&_thrift{}) }

func (t *_thrift) Name() string { return "thrift" }

// thrift binary protocol types
const (
	_thrift_stop   = 0
	_thrift_bool   = 2
	_thrift_byte   = 3
	_thrift_i16    = 6
	_thrift_i32    = 8
	_thrift_i64    = 10
	_thrift_string = 11
	_thrift_struct = 12
	_thrift_map    = 13
	_thrift_set    = 14
	_thrift_list   = 15
)

func (t *_thrift) Parse(raw []byte) (*ir.Dataset, error) {
	var records []ir.Record
	buf := bytes.NewReader(raw)

	for buf.Len() > 0 {
		r, err := _thrift_parse_struct(buf)
		if err != nil {
			break
		}
		if r.Email != "" || r.Username != "" || r.Password != "" ||
			r.URL != "" || r.Domain != "" || r.IP != "" {
			records = append(records, r)
		}
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("thrift: no parseable records found")
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.3
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "thrift",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func _thrift_parse_struct(buf *bytes.Reader) (ir.Record, error) {
	r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}

	for {
		typByte, err := buf.ReadByte()
		if err != nil {
			return r, err
		}
		if typByte == _thrift_stop {
			break
		}

		var fieldID uint16
		if err := binary.Read(buf, binary.BigEndian, &fieldID); err != nil {
			return r, err
		}

		switch typByte {
		case _thrift_string:
			s, err := _thrift_read_string(buf)
			if err != nil {
				return r, err
			}
			fieldName := fmt.Sprintf("field_%d", fieldID)
			if !_map_field_to_record(&r, fieldName, s) {
				if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
					if r.URL == "" {
						r.URL = s
					} else {
						r.Extra[fieldName] = s
					}
				} else if strings.Contains(s, "@") && strings.Contains(s, ".") {
					if r.Email == "" {
						r.Email = s
					} else {
						r.Extra[fieldName] = s
					}
				} else {
					r.Extra[fieldName] = s
				}
			}

		case _thrift_bool:
			v, err := buf.ReadByte()
			if err != nil {
				return r, err
			}
			r.Extra[fmt.Sprintf("field_%d", fieldID)] = v != 0

		case _thrift_byte:
			v, err := buf.ReadByte()
			if err != nil {
				return r, err
			}
			r.Extra[fmt.Sprintf("field_%d", fieldID)] = v

		case _thrift_i16:
			var v int16
			if err := binary.Read(buf, binary.BigEndian, &v); err != nil {
				return r, err
			}
			r.Extra[fmt.Sprintf("field_%d", fieldID)] = v

		case _thrift_i32:
			var v int32
			if err := binary.Read(buf, binary.BigEndian, &v); err != nil {
				return r, err
			}
			r.Extra[fmt.Sprintf("field_%d", fieldID)] = v

		case _thrift_i64:
			var v int64
			if err := binary.Read(buf, binary.BigEndian, &v); err != nil {
				return r, err
			}
			r.Extra[fmt.Sprintf("field_%d", fieldID)] = v

		case _thrift_struct:
			sub, err := _thrift_parse_struct(buf)
			if err != nil {
				return r, err
			}
			// merge fields from nested struct
			if sub.Email != "" && r.Email == "" {
				r.Email = sub.Email
			}
			if sub.Username != "" && r.Username == "" {
				r.Username = sub.Username
			}
			if sub.Password != "" && r.Password == "" {
				r.Password = sub.Password
			}
			if sub.URL != "" && r.URL == "" {
				r.URL = sub.URL
			}
			if sub.Domain != "" && r.Domain == "" {
				r.Domain = sub.Domain
			}

		default:
			// skip unknown types
			return r, fmt.Errorf("thrift: unsupported field type %d", typByte)
		}
	}

	if len(r.Extra) == 0 {
		r.Extra = nil
	}
	return r, nil
}

func _thrift_read_string(buf *bytes.Reader) (string, error) {
	var length int32
	if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
		return "", err
	}
	if length < 0 || length > 10*1024*1024 {
		return "", fmt.Errorf("thrift: string length %d out of range", length)
	}
	data := make([]byte, length)
	if _, err := buf.Read(data); err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return fmt.Sprintf("%x", data), nil
	}
	return string(data), nil
}

func (t *_thrift) Render(ds *ir.Dataset) ([]byte, error) {
	var out bytes.Buffer
	for _, r := range ds.Records {
		fieldID := uint16(1)
		m := _record_to_map(r)
		for _, key := range []string{"email", "username", "password", "url", "domain", "ip", "phone", "name", "hash"} {
			if val, ok := m[key]; ok {
				out.WriteByte(_thrift_string)
				binary.Write(&out, binary.BigEndian, fieldID)
				binary.Write(&out, binary.BigEndian, int32(len(val)))
				out.WriteString(val)
			}
			fieldID++
		}
		out.WriteByte(_thrift_stop)
	}
	return out.Bytes(), nil
}
