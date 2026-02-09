package formats

import (
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _ldif struct{}

func init() { module.Register(&_ldif{}) }

func (l *_ldif) Name() string { return "ldif" }

func (l *_ldif) Parse(raw []byte) (*ir.Dataset, error) {
	entries := _parse_ldif_entries(string(raw))
	var records []ir.Record

	for _, entry := range entries {
		r := _ldif_entry_to_record(entry)
		if r != nil {
			records = append(records, *r)
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
			SourceFormat:    "ldif",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func _parse_ldif_entries(content string) []map[string][]string {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var entries []map[string][]string
	current := map[string][]string{}

	for _, line := range lines {
		// blank line separates entries
		if strings.TrimSpace(line) == "" {
			if len(current) > 0 {
				entries = append(entries, current)
				current = map[string][]string{}
			}
			continue
		}

		// skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		// continuation line (starts with single space)
		if strings.HasPrefix(line, " ") && len(current) > 0 {
			// append to last attribute's last value
			for k, v := range current {
				if len(v) > 0 {
					current[k][len(v)-1] += strings.TrimPrefix(line, " ")
					break
				}
			}
			continue
		}

		// attribute: value
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}

		attr := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// handle base64 encoded values (attr:: value)
		if strings.HasPrefix(val, ":") {
			val = strings.TrimSpace(val[1:])
			// leave base64 as-is for now
		}

		current[attr] = append(current[attr], val)
	}

	if len(current) > 0 {
		entries = append(entries, current)
	}

	return entries
}

func _ldif_entry_to_record(entry map[string][]string) *ir.Record {
	r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}
	matched := 0

	for attr, vals := range entry {
		if len(vals) == 0 {
			continue
		}
		val := vals[0]

		switch strings.ToLower(attr) {
		case "mail", "email":
			r.Email = val
			matched++
		case "uid", "samaccountname":
			r.Username = val
			matched++
		case "cn", "displayname":
			r.Name = val
			matched++
		case "userpassword":
			r.Password = val
			matched++
		case "telephonenumber":
			r.Phone = ir.NormalizePhone(val)
			matched++
		case "dn":
			r.Extra["dn"] = val
		case "objectclass":
			if len(vals) > 1 {
				r.Extra["objectclass"] = vals
			} else {
				r.Extra["objectclass"] = val
			}
		default:
			if len(vals) == 1 {
				r.Extra[attr] = val
			} else {
				r.Extra[attr] = vals
			}
		}
	}

	if matched == 0 {
		return nil
	}

	if len(r.Extra) == 0 {
		r.Extra = nil
	}

	return &r
}

func (l *_ldif) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder

	for i, r := range ds.Records {
		if i > 0 {
			b.WriteByte('\n')
		}

		// dn line
		dn := _extra_str(r, "dn")
		if dn == "" {
			// synthesise from available fields
			parts := []string{}
			if r.Name != "" {
				parts = append(parts, fmt.Sprintf("cn=%s", r.Name))
			} else if r.Username != "" {
				parts = append(parts, fmt.Sprintf("uid=%s", r.Username))
			}
			parts = append(parts, "dc=example,dc=com")
			dn = strings.Join(parts, ",")
		}
		b.WriteString(fmt.Sprintf("dn: %s\n", dn))
		b.WriteString("objectClass: inetOrgPerson\n")

		if r.Name != "" {
			b.WriteString(fmt.Sprintf("cn: %s\n", r.Name))
		}
		if r.Username != "" {
			b.WriteString(fmt.Sprintf("uid: %s\n", r.Username))
		}
		if r.Email != "" {
			b.WriteString(fmt.Sprintf("mail: %s\n", r.Email))
		}
		if r.Password != "" {
			b.WriteString(fmt.Sprintf("userPassword: %s\n", r.Password))
		}
		if r.Phone != "" {
			b.WriteString(fmt.Sprintf("telephoneNumber: %s\n", r.Phone))
		}
		if r.Name != "" {
			b.WriteString(fmt.Sprintf("displayName: %s\n", r.Name))
		}
	}

	return []byte(b.String()), nil
}
