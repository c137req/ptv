package formats

import (
	"strings"

	"github.com/c137req/ptv/internal/ir"
)

func _split_lines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	// trim trailing empty
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// _split_combo_fields splits a colon-delimited line but rejoins url schemes (https://, ftp://, etc.)
func _split_combo_fields(line string) []string {
	raw := strings.Split(line, ":")
	var fields []string
	for i := 0; i < len(raw); i++ {
		// if next part starts with // this is a url scheme, rejoin
		if i+1 < len(raw) && strings.HasPrefix(raw[i+1], "//") {
			rejoined := raw[i] + ":" + raw[i+1]
			// also grab port or path segments that got split
			// e.g. https://example.com:8080/path → parts: https, //example.com, 8080/path
			// only rejoin if next-next part looks like a port/path (contains / or is numeric-ish)
			i++
			fields = append(fields, rejoined)
		} else {
			fields = append(fields, raw[i])
		}
	}
	return fields
}

// _map_field_to_record sets a record field by name, returns true if it matched a known field.
func _map_field_to_record(r *ir.Record, field string, value string) bool {
	switch strings.ToLower(field) {
	case "email", "e-mail", "mail", "email_address":
		r.Email = value
	case "username", "user", "login", "account", "user_name", "userid":
		r.Username = value
	case "password", "pass", "passwd", "pwd", "secret":
		r.Password = value
	case "url", "uri", "link", "website", "site":
		r.URL = value
	case "domain", "host", "hostname":
		r.Domain = value
	case "ip", "ip_address", "ipaddress", "ip_addr":
		r.IP = value
	case "phone", "telephone", "tel", "mobile", "phone_number":
		r.Phone = ir.NormalizePhone(value)
	case "name", "full_name", "fullname", "display_name", "displayname":
		r.Name = value
	default:
		return false
	}
	return true
}

// _record_to_map extracts populated fields into a string map.
func _record_to_map(r ir.Record) map[string]string {
	m := map[string]string{}
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
	}
	return m
}
