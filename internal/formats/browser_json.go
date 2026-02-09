package formats

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _firefox_json struct{}
type _netscape_cookie struct{}

func init() {
	module.Register(&_firefox_json{})
	module.Register(&_netscape_cookie{})
}

func (f *_firefox_json) Name() string   { return "firefox_json" }
func (n *_netscape_cookie) Name() string { return "netscape_cookie" }

// --- firefox json ---

func (f *_firefox_json) Parse(raw []byte) (*ir.Dataset, error) {
	var export struct {
		Logins []struct {
			ID                any     `json:"id"`
			Hostname          string  `json:"hostname"`
			HTTPRealm         *string `json:"httpRealm"`
			FormSubmitURL     string  `json:"formSubmitURL"`
			UsernameField     string  `json:"usernameField"`
			PasswordField     string  `json:"passwordField"`
			Username          string  `json:"username"`
			Password          string  `json:"password"`
			EncryptedUsername  string  `json:"encryptedUsername"`
			EncryptedPassword string  `json:"encryptedPassword"`
			GUID              string  `json:"guid"`
			TimeCreated       int64   `json:"timeCreated"`
			TimeLastUsed      int64   `json:"timeLastUsed"`
			TimesUsed         int     `json:"timesUsed"`
		} `json:"logins"`
	}

	if err := json.Unmarshal(raw, &export); err != nil {
		return nil, fmt.Errorf("failed to parse firefox json: %w", err)
	}

	records := make([]ir.Record, 0, len(export.Logins))
	for _, login := range export.Logins {
		r := ir.Record{
			PTVID: ir.NewPTVID(),
			URL:   login.Hostname,
			Extra: map[string]any{},
		}

		// prefer plaintext username/password if available
		if login.Username != "" {
			_classify_identity(&r, login.Username)
		} else if login.EncryptedUsername != "" {
			r.Unknowns = append(r.Unknowns, ir.UnknownField{
				Value:           login.EncryptedUsername,
				PotentialFields: []ir.PotentialField{{Field: "username", Confidence: 0.9}},
			})
		}

		if login.Password != "" {
			r.Password = login.Password
		} else if login.EncryptedPassword != "" {
			r.Unknowns = append(r.Unknowns, ir.UnknownField{
				Value:           login.EncryptedPassword,
				PotentialFields: []ir.PotentialField{{Field: "password", Confidence: 0.9}},
			})
		}

		if login.FormSubmitURL != "" {
			r.Extra["form_submit_url"] = login.FormSubmitURL
		}
		if login.GUID != "" {
			r.Extra["guid"] = login.GUID
		}
		if login.HTTPRealm != nil {
			r.Extra["http_realm"] = *login.HTTPRealm
		}
		if login.TimesUsed > 0 {
			r.Extra["times_used"] = login.TimesUsed
		}

		records = append(records, r)
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "firefox_json",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         []string{"email", "username", "password", "url"},
			FieldConfidence: map[string]float64{"email": 0.9, "username": 0.9, "password": 1.0, "url": 1.0},
		},
		Records: records,
	}, nil
}

func (f *_firefox_json) Render(ds *ir.Dataset) ([]byte, error) {
	type ff_login struct {
		Hostname      string `json:"hostname"`
		FormSubmitURL string `json:"formSubmitURL"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		GUID          string `json:"guid"`
	}

	logins := make([]ff_login, 0, len(ds.Records))
	for _, r := range ds.Records {
		ident := r.Email
		if ident == "" {
			ident = r.Username
		}
		form_url := r.URL
		if v := _extra_str(r, "form_submit_url"); v != "" {
			form_url = v
		}
		guid := r.PTVID
		if v := _extra_str(r, "guid"); v != "" {
			guid = v
		}
		logins = append(logins, ff_login{
			Hostname:      r.URL,
			FormSubmitURL: form_url,
			Username:      ident,
			Password:      r.Password,
			GUID:          guid,
		})
	}

	export := map[string]any{"logins": logins}
	return json.MarshalIndent(export, "", "  ")
}

// --- netscape cookie ---

func (n *_netscape_cookie) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))

	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 7 {
			continue
		}

		r := ir.Record{
			PTVID:  ir.NewPTVID(),
			Domain: parts[0],
			Extra: map[string]any{
				"subdomain_flag": parts[1],
				"path":           parts[2],
				"secure":         parts[3],
				"expiry":         parts[4],
				"cookie_name":    parts[5],
				"cookie_value":   parts[6],
			},
		}
		records = append(records, r)
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "netscape_cookie",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         []string{"domain"},
			FieldConfidence: map[string]float64{"domain": 1.0},
		},
		Records: records,
	}, nil
}

func (n *_netscape_cookie) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n")
	b.WriteString("# https://curl.se/docs/http-cookies.html\n")

	for _, r := range ds.Records {
		domain := r.Domain
		if domain == "" {
			domain = ".unknown"
		}
		sub := _extra_str(r, "subdomain_flag")
		if sub == "" {
			sub = "TRUE"
		}
		path := _extra_str(r, "path")
		if path == "" {
			path = "/"
		}
		secure := _extra_str(r, "secure")
		if secure == "" {
			secure = "FALSE"
		}
		expiry := _extra_str(r, "expiry")
		if expiry == "" {
			expiry = "0"
		}
		name := _extra_str(r, "cookie_name")
		if name == "" {
			name = "session"
		}
		value := _extra_str(r, "cookie_value")

		b.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			domain, sub, path, secure, expiry, name, value))
	}
	return []byte(b.String()), nil
}
