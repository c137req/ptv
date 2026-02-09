package formats

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _json_nested struct{}

func init() { module.Register(&_json_nested{}) }

func (j *_json_nested) Name() string { return "json_nested" }

func (j *_json_nested) Parse(raw []byte) (*ir.Dataset, error) {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("failed to parse json: %w", err)
	}

	var records []ir.Record
	_walk_json(root, &records)

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.8
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "json_nested",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (j *_json_nested) Render(ds *ir.Dataset) ([]byte, error) {
	rows := make([]map[string]any, 0, len(ds.Records))
	for _, r := range ds.Records {
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
		if r.Hash != nil {
			m["hash"] = r.Hash.Value
			m["hash_type"] = string(r.Hash.Type)
		}
		for k, v := range r.Extra {
			m[k] = v
		}
		rows = append(rows, m)
	}
	wrapper := map[string]any{"records": rows}
	return json.MarshalIndent(wrapper, "", "  ")
}

// _walk_json recursively walks a json value, collecting records from objects
// that contain at least one credential-like field.
func _walk_json(v any, records *[]ir.Record) {
	switch val := v.(type) {
	case map[string]any:
		r := ir.Record{PTVID: ir.NewPTVID()}
		matched := 0
		for k, child := range val {
			str, ok := child.(string)
			if !ok {
				continue
			}
			if _map_field_to_record(&r, k, str) {
				matched++
			}
		}
		if matched > 0 {
			// also grab unmatched string fields as extra
			for k, child := range val {
				str, ok := child.(string)
				if !ok {
					continue
				}
				if !_is_known_field(k) {
					if r.Extra == nil {
						r.Extra = map[string]any{}
					}
					r.Extra[k] = str
				}
			}
			*records = append(*records, r)
		}
		// recurse into non-string children
		for _, child := range val {
			switch child.(type) {
			case map[string]any, []any:
				_walk_json(child, records)
			}
		}
	case []any:
		for _, item := range val {
			_walk_json(item, records)
		}
	}
}

func _is_known_field(name string) bool {
	switch strings.ToLower(name) {
	case "email", "e-mail", "mail", "email_address",
		"username", "user", "login", "account", "user_name", "userid",
		"password", "pass", "passwd", "pwd", "secret",
		"url", "uri", "link", "website", "site",
		"domain", "host", "hostname",
		"ip", "ip_address", "ipaddress", "ip_addr",
		"phone", "telephone", "tel", "mobile", "phone_number",
		"name", "full_name", "fullname", "display_name", "displayname":
		return true
	}
	return false
}
