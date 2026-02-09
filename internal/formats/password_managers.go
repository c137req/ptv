package formats

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _lastpass_csv struct{}
type _onepassword_csv struct{}
type _bitwarden_csv struct{}
type _bitwarden_json struct{}
type _chrome_csv struct{}
type _safari_csv struct{}

func init() {
	module.Register(&_lastpass_csv{})
	module.Register(&_onepassword_csv{})
	module.Register(&_bitwarden_csv{})
	module.Register(&_bitwarden_json{})
	module.Register(&_chrome_csv{})
	module.Register(&_safari_csv{})
}

func (l *_lastpass_csv) Name() string    { return "lastpass_csv" }
func (o *_onepassword_csv) Name() string { return "onepassword_csv" }
func (b *_bitwarden_csv) Name() string   { return "bitwarden_csv" }
func (b *_bitwarden_json) Name() string  { return "bitwarden_json" }
func (c *_chrome_csv) Name() string      { return "chrome_csv" }
func (s *_safari_csv) Name() string      { return "safari_csv" }

// --- lastpass csv ---

func (l *_lastpass_csv) Parse(raw []byte) (*ir.Dataset, error) {
	return _parse_pm_csv(raw, "lastpass_csv", map[string]string{
		"url": "url", "username": "username", "password": "password",
		"name": "name",
	}, []string{"totp", "extra", "grouping", "fav"})
}

func (l *_lastpass_csv) Render(ds *ir.Dataset) ([]byte, error) {
	headers := []string{"url", "username", "password", "totp", "extra", "name", "grouping", "fav"}
	return _render_pm_csv(ds, headers, func(r ir.Record) []string {
		return []string{
			r.URL, _pm_ident(r), r.Password,
			_extra_str(r, "totp"), _extra_str(r, "extra"),
			r.Name, _extra_str(r, "grouping"), _extra_str(r, "fav"),
		}
	})
}

// --- 1password csv ---

func (o *_onepassword_csv) Parse(raw []byte) (*ir.Dataset, error) {
	return _parse_pm_csv(raw, "onepassword_csv", map[string]string{
		"title": "name", "url": "url", "username": "username", "password": "password",
	}, []string{"notes", "type"})
}

func (o *_onepassword_csv) Render(ds *ir.Dataset) ([]byte, error) {
	headers := []string{"Title", "Url", "Username", "Password", "Notes", "Type"}
	return _render_pm_csv(ds, headers, func(r ir.Record) []string {
		return []string{
			r.Name, r.URL, _pm_ident(r), r.Password,
			_extra_str(r, "notes"), _extra_str(r, "type"),
		}
	})
}

// --- bitwarden csv ---

func (b *_bitwarden_csv) Parse(raw []byte) (*ir.Dataset, error) {
	return _parse_pm_csv(raw, "bitwarden_csv", map[string]string{
		"login_uri": "url", "login_username": "username", "login_password": "password",
		"name": "name",
	}, []string{"folder", "favorite", "type", "notes", "fields", "reprompt", "login_totp"})
}

func (b *_bitwarden_csv) Render(ds *ir.Dataset) ([]byte, error) {
	headers := []string{"folder", "favorite", "type", "name", "notes", "fields", "reprompt",
		"login_uri", "login_username", "login_password", "login_totp"}
	return _render_pm_csv(ds, headers, func(r ir.Record) []string {
		return []string{
			_extra_str(r, "folder"), _extra_str(r, "favorite"), _extra_str(r, "type"),
			r.Name, _extra_str(r, "notes"), _extra_str(r, "fields"), _extra_str(r, "reprompt"),
			r.URL, _pm_ident(r), r.Password, _extra_str(r, "login_totp"),
		}
	})
}

// --- bitwarden json ---

func (b *_bitwarden_json) Parse(raw []byte) (*ir.Dataset, error) {
	var export struct {
		Encrypted bool `json:"encrypted"`
		Folders   []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"folders"`
		Items []struct {
			ID       string  `json:"id"`
			FolderID *string `json:"folderId"`
			Type     int     `json:"type"`
			Name     string  `json:"name"`
			Notes    *string `json:"notes"`
			Login    *struct {
				URIs     []struct{ URI string `json:"uri"` } `json:"uris"`
				Username string                              `json:"username"`
				Password string                              `json:"password"`
				TOTP     *string                             `json:"totp"`
			} `json:"login"`
		} `json:"items"`
	}

	if err := json.Unmarshal(raw, &export); err != nil {
		return nil, fmt.Errorf("failed to parse bitwarden json: %w", err)
	}

	// build folder lookup
	folders := map[string]string{}
	for _, f := range export.Folders {
		folders[f.ID] = f.Name
	}

	records := make([]ir.Record, 0, len(export.Items))
	for _, item := range export.Items {
		r := ir.Record{
			PTVID: ir.NewPTVID(),
			Name:  item.Name,
			Extra: map[string]any{},
		}
		if item.Login != nil {
			if len(item.Login.URIs) > 0 {
				r.URL = item.Login.URIs[0].URI
			}
			_classify_identity(&r, item.Login.Username)
			r.Password = item.Login.Password
			if item.Login.TOTP != nil && *item.Login.TOTP != "" {
				r.Extra["totp"] = *item.Login.TOTP
			}
		}
		if item.Notes != nil && *item.Notes != "" {
			r.Extra["notes"] = *item.Notes
		}
		if item.FolderID != nil {
			if fname, ok := folders[*item.FolderID]; ok {
				r.Extra["folder"] = fname
			}
		}
		records = append(records, r)
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "bitwarden_json",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         []string{"email", "username", "password", "url", "name"},
			FieldConfidence: map[string]float64{"email": 0.9, "username": 0.9, "password": 1.0, "url": 1.0, "name": 1.0},
		},
		Records: records,
	}, nil
}

func (b *_bitwarden_json) Render(ds *ir.Dataset) ([]byte, error) {
	type bw_uri struct {
		URI string `json:"uri"`
	}
	type bw_login struct {
		URIs     []bw_uri `json:"uris"`
		Username string   `json:"username"`
		Password string   `json:"password"`
		TOTP     *string  `json:"totp"`
	}
	type bw_item struct {
		ID       string   `json:"id"`
		FolderID *string  `json:"folderId"`
		Type     int      `json:"type"`
		Name     string   `json:"name"`
		Notes    *string  `json:"notes"`
		Login    bw_login `json:"login"`
	}

	items := make([]bw_item, 0, len(ds.Records))
	for _, r := range ds.Records {
		ident := r.Email
		if ident == "" {
			ident = r.Username
		}
		item := bw_item{
			ID:   r.PTVID,
			Type: 1,
			Name: r.Name,
			Login: bw_login{
				URIs:     []bw_uri{{URI: r.URL}},
				Username: ident,
				Password: r.Password,
			},
		}
		if totp := _extra_str(r, "totp"); totp != "" {
			item.Login.TOTP = &totp
		}
		if notes := _extra_str(r, "notes"); notes != "" {
			item.Notes = &notes
		}
		items = append(items, item)
	}

	export := map[string]any{
		"encrypted": false,
		"folders":   []any{},
		"items":     items,
	}
	return json.MarshalIndent(export, "", "  ")
}

// --- chrome csv ---

func (c *_chrome_csv) Parse(raw []byte) (*ir.Dataset, error) {
	return _parse_pm_csv(raw, "chrome_csv", map[string]string{
		"name": "name", "url": "url", "username": "username", "password": "password",
	}, []string{"note"})
}

func (c *_chrome_csv) Render(ds *ir.Dataset) ([]byte, error) {
	headers := []string{"name", "url", "username", "password", "note"}
	return _render_pm_csv(ds, headers, func(r ir.Record) []string {
		return []string{r.Name, r.URL, _pm_ident(r), r.Password, _extra_str(r, "note")}
	})
}

// --- safari csv ---

func (s *_safari_csv) Parse(raw []byte) (*ir.Dataset, error) {
	return _parse_pm_csv(raw, "safari_csv", map[string]string{
		"title": "name", "url": "url", "username": "username", "password": "password",
	}, []string{"notes", "otpauth"})
}

func (s *_safari_csv) Render(ds *ir.Dataset) ([]byte, error) {
	headers := []string{"Title", "URL", "Username", "Password", "Notes", "OTPAuth"}
	return _render_pm_csv(ds, headers, func(r ir.Record) []string {
		return []string{r.Name, r.URL, _pm_ident(r), r.Password, _extra_str(r, "notes"), _extra_str(r, "otpauth")}
	})
}

// shared helpers for password manager csv parsing

func _parse_pm_csv(raw []byte, name string, field_map map[string]string, extra_fields []string) (*ir.Dataset, error) {
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", name, err)
	}
	if len(rows) < 2 {
		return &ir.Dataset{PTVVersion: "1.0", Meta: ir.Meta{SourceFormat: name, ParsedAt: time.Now().UTC().Format(time.RFC3339)}}, nil
	}

	headers := rows[0]
	// build extra fields set
	extra_set := map[string]bool{}
	for _, ef := range extra_fields {
		extra_set[strings.ToLower(ef)] = true
	}

	records := make([]ir.Record, 0, len(rows)-1)
	for _, row := range rows[1:] {
		r := ir.Record{PTVID: ir.NewPTVID()}
		for i, val := range row {
			if i >= len(headers) {
				break
			}
			h := strings.ToLower(headers[i])
			if mapped, ok := field_map[h]; ok {
				_map_field_to_record(&r, mapped, val)
			} else if extra_set[h] {
				if val != "" {
					if r.Extra == nil {
						r.Extra = map[string]any{}
					}
					r.Extra[h] = val
				}
			} else {
				if !_map_field_to_record(&r, h, val) && val != "" {
					if r.Extra == nil {
						r.Extra = map[string]any{}
					}
					r.Extra[h] = val
				}
			}
		}
		records = append(records, r)
	}

	cols := []string{"email", "username", "password", "url", "name"}
	conf := map[string]float64{"email": 0.9, "username": 0.9, "password": 1.0, "url": 1.0, "name": 1.0}

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
	}, nil
}

func _render_pm_csv(ds *ir.Dataset, headers []string, row_fn func(ir.Record) []string) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write(headers)
	for _, r := range ds.Records {
		w.Write(row_fn(r))
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func _pm_ident(r ir.Record) string {
	if r.Email != "" {
		return r.Email
	}
	return r.Username
}

func _extra_str(r ir.Record, key string) string {
	if r.Extra == nil {
		return ""
	}
	v, ok := r.Extra[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}
