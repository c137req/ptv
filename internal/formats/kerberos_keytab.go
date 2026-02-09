package formats

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _kerberos_keytab struct{}

func init() { module.Register(&_kerberos_keytab{}) }

func (k *_kerberos_keytab) Name() string { return "kerberos_keytab" }

func (k *_kerberos_keytab) Parse(raw []byte) (*ir.Dataset, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("keytab too short")
	}

	version := binary.BigEndian.Uint16(raw[:2])
	if version != 0x0502 && version != 0x0501 {
		return nil, fmt.Errorf("unsupported keytab version: 0x%04x", version)
	}

	var records []ir.Record
	pos := 2

	for pos < len(raw) {
		if pos+4 > len(raw) {
			break
		}

		entry_size := int32(binary.BigEndian.Uint32(raw[pos : pos+4]))
		pos += 4

		if entry_size <= 0 {
			pos += int(-entry_size)
			continue
		}

		entry_end := pos + int(entry_size)
		if entry_end > len(raw) {
			break
		}

		buf := raw[pos:entry_end]
		offset := 0

		if offset+2 > len(buf) {
			pos = entry_end
			continue
		}
		num_components := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2

		if version == 0x0501 {
			num_components++
		}

		// realm
		if offset+2 > len(buf) {
			pos = entry_end
			continue
		}
		realm_len := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
		if offset+realm_len > len(buf) {
			pos = entry_end
			continue
		}
		realm := string(buf[offset : offset+realm_len])
		offset += realm_len

		// principal components
		var components []string
		for i := 0; i < num_components; i++ {
			if offset+2 > len(buf) {
				break
			}
			comp_len := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
			offset += 2
			if offset+comp_len > len(buf) {
				break
			}
			components = append(components, string(buf[offset:offset+comp_len]))
			offset += comp_len
		}

		// name type (only in v2)
		var name_type uint32
		if version == 0x0502 {
			if offset+4 > len(buf) {
				pos = entry_end
				continue
			}
			name_type = binary.BigEndian.Uint32(buf[offset : offset+4])
			offset += 4
		}

		// timestamp
		if offset+4 > len(buf) {
			pos = entry_end
			continue
		}
		timestamp := binary.BigEndian.Uint32(buf[offset : offset+4])
		offset += 4

		// kvno (8-bit)
		if offset+1 > len(buf) {
			pos = entry_end
			continue
		}
		kvno := buf[offset]
		offset++

		// keyblock type
		if offset+2 > len(buf) {
			pos = entry_end
			continue
		}
		key_type := binary.BigEndian.Uint16(buf[offset : offset+2])
		offset += 2

		// keyblock data
		if offset+2 > len(buf) {
			pos = entry_end
			continue
		}
		key_len := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
		var key_data []byte
		if offset+key_len <= len(buf) {
			key_data = buf[offset : offset+key_len]
		}

		// 32-bit kvno at end if space remains
		if offset+key_len+4 <= int(entry_size) {
			kvno32 := binary.BigEndian.Uint32(buf[offset+key_len : offset+key_len+4])
			if kvno32 != 0 {
				kvno = byte(kvno32)
			}
		}

		principal := strings.Join(components, "/")
		r := ir.Record{
			PTVID:    ir.NewPTVID(),
			Username: principal,
			Domain:   realm,
			Extra: map[string]any{
				"key_type":  fmt.Sprintf("%d", key_type),
				"kvno":      fmt.Sprintf("%d", kvno),
				"timestamp": fmt.Sprintf("%d", timestamp),
				"name_type": fmt.Sprintf("%d", name_type),
			},
		}

		if len(key_data) > 0 {
			r.Extra["key_data"] = fmt.Sprintf("%x", key_data)
		}

		records = append(records, r)
		pos = entry_end
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "kerberos_keytab",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (k *_kerberos_keytab) Render(ds *ir.Dataset) ([]byte, error) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(0x0502))

	for _, r := range ds.Records {
		var entry bytes.Buffer

		principal := r.Username
		realm := r.Domain
		components := strings.Split(principal, "/")

		binary.Write(&entry, binary.BigEndian, uint16(len(components)))

		binary.Write(&entry, binary.BigEndian, uint16(len(realm)))
		entry.WriteString(realm)

		for _, comp := range components {
			binary.Write(&entry, binary.BigEndian, uint16(len(comp)))
			entry.WriteString(comp)
		}

		var name_type uint32
		if nt := _extra_str(r, "name_type"); nt != "" {
			if n, err := strconv.ParseUint(nt, 10, 32); err == nil {
				name_type = uint32(n)
			}
		}
		binary.Write(&entry, binary.BigEndian, name_type)

		var timestamp uint32
		if ts := _extra_str(r, "timestamp"); ts != "" {
			if n, err := strconv.ParseUint(ts, 10, 32); err == nil {
				timestamp = uint32(n)
			}
		}
		binary.Write(&entry, binary.BigEndian, timestamp)

		var kvno uint8
		if kv := _extra_str(r, "kvno"); kv != "" {
			if n, err := strconv.ParseUint(kv, 10, 8); err == nil {
				kvno = uint8(n)
			}
		}
		entry.WriteByte(kvno)

		var key_type uint16
		if kt := _extra_str(r, "key_type"); kt != "" {
			if n, err := strconv.ParseUint(kt, 10, 16); err == nil {
				key_type = uint16(n)
			}
		}
		binary.Write(&entry, binary.BigEndian, key_type)

		var key_data []byte
		if kd := _extra_str(r, "key_data"); kd != "" {
			key_data, _ = hex.DecodeString(kd)
		}
		binary.Write(&entry, binary.BigEndian, uint16(len(key_data)))
		entry.Write(key_data)

		binary.Write(&buf, binary.BigEndian, int32(entry.Len()))
		buf.Write(entry.Bytes())
	}

	return buf.Bytes(), nil
}
