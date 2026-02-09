package formats

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _keepass_xml struct{}

func init() { module.Register(&_keepass_xml{}) }

func (k *_keepass_xml) Name() string { return "keepass_xml" }

func (k *_keepass_xml) Parse(raw []byte) (*ir.Dataset, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	var records []ir.Record

	var in_entry bool
	var in_string bool
	var current_key string
	var current_value string
	var collecting_key bool
	var collecting_value bool
	var current_group string
	var collecting_group_name bool
	entry_fields := map[string]string{}

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "Entry":
				in_entry = true
				entry_fields = map[string]string{}
			case "String":
				if in_entry {
					in_string = true
					current_key = ""
					current_value = ""
				}
			case "Key":
				if in_string {
					collecting_key = true
				}
			case "Value":
				if in_string {
					collecting_value = true
				}
			case "Name":
				// could be group name
				if !in_entry {
					collecting_group_name = true
				}
			}

		case xml.CharData:
			text := string(t)
			if collecting_key {
				current_key += text
			} else if collecting_value {
				current_value += text
			} else if collecting_group_name {
				current_group = strings.TrimSpace(text)
			}

		case xml.EndElement:
			switch t.Name.Local {
			case "Entry":
				if in_entry {
					r := _keepass_fields_to_record(entry_fields, current_group)
					if r != nil {
						records = append(records, *r)
					}
					in_entry = false
				}
			case "String":
				if in_string {
					entry_fields[strings.TrimSpace(current_key)] = strings.TrimSpace(current_value)
					in_string = false
				}
			case "Key":
				collecting_key = false
			case "Value":
				collecting_value = false
			case "Name":
				collecting_group_name = false
			}
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
			SourceFormat:    "keepass_xml",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func _keepass_fields_to_record(fields map[string]string, group string) *ir.Record {
	r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}

	for key, val := range fields {
		if val == "" {
			continue
		}
		switch key {
		case "UserName":
			if strings.Contains(val, "@") {
				r.Email = val
			} else {
				r.Username = val
			}
		case "Password":
			r.Password = val
		case "URL":
			r.URL = val
		case "Title":
			r.Name = val
		case "Notes":
			r.Extra["notes"] = val
		default:
			r.Extra[key] = val
		}
	}

	if group != "" && group != "Root" {
		r.Extra["group"] = group
	}

	if r.Email == "" && r.Username == "" && r.Password == "" && r.URL == "" {
		return nil
	}

	if len(r.Extra) == 0 {
		r.Extra = nil
	}

	return &r
}

func (k *_keepass_xml) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	b.WriteString("<KeePassFile>\n\t<Root>\n\t\t<Group>\n\t\t\t<Name>Root</Name>\n")

	for _, r := range ds.Records {
		b.WriteString("\t\t\t<Entry>\n")
		if r.Name != "" {
			_keepass_write_string(&b, "Title", r.Name)
		}
		if r.Email != "" {
			_keepass_write_string(&b, "UserName", r.Email)
		} else if r.Username != "" {
			_keepass_write_string(&b, "UserName", r.Username)
		}
		if r.Password != "" {
			_keepass_write_string(&b, "Password", r.Password)
		}
		if r.URL != "" {
			_keepass_write_string(&b, "URL", r.URL)
		}
		if notes := _extra_str(r, "notes"); notes != "" {
			_keepass_write_string(&b, "Notes", notes)
		}
		b.WriteString("\t\t\t</Entry>\n")
	}

	b.WriteString("\t\t</Group>\n\t</Root>\n</KeePassFile>\n")
	return []byte(b.String()), nil
}

func _keepass_write_string(b *strings.Builder, key, value string) {
	b.WriteString(fmt.Sprintf("\t\t\t\t<String>\n\t\t\t\t\t<Key>%s</Key>\n\t\t\t\t\t<Value>%s</Value>\n\t\t\t\t</String>\n",
		_xml_escape(key), _xml_escape(value)))
}
