package formats

import (
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

// combolist_user_pass — user:pass (or email:pass, auto-detected)
type _combo_user_pass struct{}

func init() {
	module.Register(&_combo_user_pass{})
	module.Register(&_combo_email_pass{})
	module.Register(&_combo_user_pass_url{})
	module.Register(&_combo_extended{})
}

func (c *_combo_user_pass) Name() string { return "combolist_user_pass" }

func (c *_combo_user_pass) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		r := ir.Record{PTVID: ir.NewPTVID()}
		if len(parts) >= 1 {
			_classify_identity(&r, parts[0])
		}
		if len(parts) >= 2 {
			r.Password = parts[1]
		}
		records = append(records, r)
	}
	return _combo_dataset("combolist_user_pass", []string{"email", "username", "password"},
		map[string]float64{"email": 0.8, "username": 0.8, "password": 1.0}, records), nil
}

func (c *_combo_user_pass) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		ident := r.Email
		if ident == "" {
			ident = r.Username
		}
		if ident == "" && len(r.Unknowns) > 0 {
			ident = r.Unknowns[0].Value
		}
		b.WriteString(ident)
		b.WriteByte(':')
		b.WriteString(r.Password)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// combolist_email_pass — email:pass (email expected)
type _combo_email_pass struct{}

func (c *_combo_email_pass) Name() string { return "combolist_email_pass" }

func (c *_combo_email_pass) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		r := ir.Record{PTVID: ir.NewPTVID()}
		if len(parts) >= 1 {
			r.Email = parts[0]
		}
		if len(parts) >= 2 {
			r.Password = parts[1]
		}
		records = append(records, r)
	}
	return _combo_dataset("combolist_email_pass", []string{"email", "password"},
		map[string]float64{"email": 1.0, "password": 1.0}, records), nil
}

func (c *_combo_email_pass) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		email := r.Email
		if email == "" {
			email = r.Username
		}
		b.WriteString(email)
		b.WriteByte(':')
		b.WriteString(r.Password)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// combolist_user_pass_url — user:pass:url
type _combo_user_pass_url struct{}

func (c *_combo_user_pass_url) Name() string { return "combolist_user_pass_url" }

func (c *_combo_user_pass_url) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		r := ir.Record{PTVID: ir.NewPTVID()}
		if len(parts) >= 1 {
			_classify_identity(&r, parts[0])
		}
		if len(parts) >= 2 {
			r.Password = parts[1]
		}
		if len(parts) >= 3 {
			r.URL = parts[2]
		}
		records = append(records, r)
	}
	return _combo_dataset("combolist_user_pass_url", []string{"email", "username", "password", "url"},
		map[string]float64{"email": 0.8, "username": 0.8, "password": 1.0, "url": 1.0}, records), nil
}

func (c *_combo_user_pass_url) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		ident := r.Email
		if ident == "" {
			ident = r.Username
		}
		b.WriteString(ident)
		b.WriteByte(':')
		b.WriteString(r.Password)
		b.WriteByte(':')
		b.WriteString(r.URL)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// combolist_extended — user:pass:url:... (variable fields, extras go to unknowns)
type _combo_extended struct{}

func (c *_combo_extended) Name() string { return "combolist_extended" }

func (c *_combo_extended) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := _split_combo_fields(line)
		r := ir.Record{PTVID: ir.NewPTVID()}
		if len(parts) >= 1 {
			_classify_identity(&r, parts[0])
		}
		if len(parts) >= 2 {
			r.Password = parts[1]
		}
		if len(parts) >= 3 {
			r.URL = parts[2]
		}
		if len(parts) >= 4 {
			r.IP = parts[3]
		}
		for i := 4; i < len(parts); i++ {
			r.Unknowns = append(r.Unknowns, ir.UnknownField{Value: parts[i]})
		}
		records = append(records, r)
	}
	return _combo_dataset("combolist_extended", []string{"email", "username", "password", "url", "ip"},
		map[string]float64{"email": 0.7, "username": 0.7, "password": 1.0, "url": 0.8, "ip": 0.6}, records), nil
}

func (c *_combo_extended) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		ident := r.Email
		if ident == "" {
			ident = r.Username
		}
		b.WriteString(ident)
		b.WriteByte(':')
		b.WriteString(r.Password)
		if r.URL != "" || r.IP != "" || len(r.Unknowns) > 0 {
			b.WriteByte(':')
			b.WriteString(r.URL)
		}
		if r.IP != "" || len(r.Unknowns) > 0 {
			b.WriteByte(':')
			b.WriteString(r.IP)
		}
		for _, u := range r.Unknowns {
			b.WriteByte(':')
			b.WriteString(u.Value)
		}
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

func _classify_identity(r *ir.Record, val string) {
	if strings.Contains(val, "@") {
		r.Email = val
	} else {
		r.Username = val
	}
}

func _combo_dataset(name string, cols []string, conf map[string]float64, records []ir.Record) *ir.Dataset {
	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    name,
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}
}
