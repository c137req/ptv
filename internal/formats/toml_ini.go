package formats

import (
	"fmt"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"gopkg.in/ini.v1"
)

type _toml struct{}
type _ini struct{}

func init() {
	module.Register(&_toml{})
	module.Register(&_ini{})
}

func (t *_toml) Name() string { return "toml" }
func (i *_ini) Name() string  { return "ini" }

// --- toml ---

func (t *_toml) Parse(raw []byte) (*ir.Dataset, error) {
	var root map[string]any
	if err := toml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("failed to parse toml: %w", err)
	}

	var records []ir.Record
	for section, val := range root {
		obj, ok := val.(map[string]any)
		if !ok {
			continue
		}
		r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{"section": section}}
		matched := 0
		for k, v := range obj {
			str := fmt.Sprintf("%v", v)
			if _map_field_to_record(&r, k, str) {
				matched++
			} else {
				r.Extra[k] = str
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
			SourceFormat:    "toml",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (t *_toml) Render(ds *ir.Dataset) ([]byte, error) {
	sections := map[string]map[string]any{}
	for i, r := range ds.Records {
		section := _extra_str(r, "section")
		if section == "" {
			section = fmt.Sprintf("record_%d", i)
		}
		m := map[string]any{}
		if r.Email != "" {
			m["email"] = r.Email
		}
		if r.Username != "" {
			m["username"] = r.Username
		}
		if r.Password != "" {
			m["password"] = r.Password
		}
		if r.URL != "" {
			m["url"] = r.URL
		}
		if r.Domain != "" {
			m["domain"] = r.Domain
		}
		if r.IP != "" {
			m["ip"] = r.IP
		}
		if r.Phone != "" {
			m["phone"] = r.Phone
		}
		if r.Name != "" {
			m["name"] = r.Name
		}
		for k, v := range r.Extra {
			if k == "section" {
				continue
			}
			m[k] = v
		}
		sections[section] = m
	}
	var buf strings.Builder
	if err := toml.NewEncoder(&buf).Encode(sections); err != nil {
		return nil, fmt.Errorf("failed to render toml: %w", err)
	}
	return []byte(buf.String()), nil
}

// --- ini ---

func (i *_ini) Parse(raw []byte) (*ir.Dataset, error) {
	cfg, err := ini.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ini: %w", err)
	}

	var records []ir.Record
	for _, section := range cfg.Sections() {
		name := section.Name()
		if name == "DEFAULT" && len(section.Keys()) == 0 {
			continue
		}
		r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}
		if name != "DEFAULT" {
			r.Extra["section"] = name
		}
		matched := 0
		for _, key := range section.Keys() {
			if _map_field_to_record(&r, key.Name(), key.String()) {
				matched++
			} else {
				r.Extra[key.Name()] = key.String()
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
			SourceFormat:    "ini",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (i *_ini) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		section := _extra_str(r, "section")
		if section != "" {
			b.WriteString(fmt.Sprintf("[%s]\n", section))
		}
		if r.Email != "" {
			b.WriteString(fmt.Sprintf("email = %s\n", r.Email))
		}
		if r.Username != "" {
			b.WriteString(fmt.Sprintf("username = %s\n", r.Username))
		}
		if r.Password != "" {
			b.WriteString(fmt.Sprintf("password = %s\n", r.Password))
		}
		if r.URL != "" {
			b.WriteString(fmt.Sprintf("url = %s\n", r.URL))
		}
		if r.Domain != "" {
			b.WriteString(fmt.Sprintf("domain = %s\n", r.Domain))
		}
		if r.IP != "" {
			b.WriteString(fmt.Sprintf("ip = %s\n", r.IP))
		}
		if r.Phone != "" {
			b.WriteString(fmt.Sprintf("phone = %s\n", r.Phone))
		}
		if r.Name != "" {
			b.WriteString(fmt.Sprintf("name = %s\n", r.Name))
		}
		for k, v := range r.Extra {
			if k == "section" {
				continue
			}
			b.WriteString(fmt.Sprintf("%s = %v\n", k, v))
		}
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}
