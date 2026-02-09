package formats

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _openvpn struct{}
type _wireguard struct{}
type _telegram_json struct{}
type _discord_json struct{}
type _docker_config struct{}
type _aws_credentials struct{}

func init() {
	module.Register(&_openvpn{})
	module.Register(&_wireguard{})
	module.Register(&_telegram_json{})
	module.Register(&_discord_json{})
	module.Register(&_docker_config{})
	module.Register(&_aws_credentials{})
}

func (o *_openvpn) Name() string        { return "openvpn" }
func (w *_wireguard) Name() string      { return "wireguard" }
func (t *_telegram_json) Name() string  { return "telegram_json" }
func (d *_discord_json) Name() string   { return "discord_json" }
func (d *_docker_config) Name() string  { return "docker_config" }
func (a *_aws_credentials) Name() string { return "aws_credentials" }

// --- openvpn ---

func (o *_openvpn) Parse(raw []byte) (*ir.Dataset, error) {
	content := string(raw)
	r := ir.Record{
		PTVID: ir.NewPTVID(),
		Extra: map[string]any{},
	}

	lines := _split_lines(content)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "remote ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				r.Domain = parts[1]
			}
			if len(parts) >= 3 {
				if port, err := strconv.Atoi(parts[2]); err == nil {
					r.Port = port
				}
			}
		} else if strings.HasPrefix(line, "proto ") {
			r.Extra["protocol"] = strings.TrimPrefix(line, "proto ")
		} else if strings.HasPrefix(line, "cipher ") {
			r.Extra["cipher"] = strings.TrimPrefix(line, "cipher ")
		} else if strings.HasPrefix(line, "auth ") {
			r.Extra["auth"] = strings.TrimPrefix(line, "auth ")
		} else if line == "auth-user-pass" {
			r.Extra["auth_user_pass"] = true
		}
	}

	// extract inline blocks
	for _, tag := range []string{"ca", "cert", "key", "tls-auth"} {
		if block := _extract_inline_block(content, tag); block != "" {
			r.Extra[tag] = block
		}
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "openvpn",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     1,
			Columns:         []string{"domain"},
			FieldConfidence: map[string]float64{"domain": 1.0},
		},
		Records: []ir.Record{r},
	}, nil
}

func (o *_openvpn) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		b.WriteString("client\ndev tun\n")
		proto := _extra_str(r, "protocol")
		if proto == "" {
			proto = "udp"
		}
		b.WriteString(fmt.Sprintf("proto %s\n", proto))
		host := r.Domain
		if host == "" {
			host = r.IP
		}
		port := r.Port
		if port == 0 {
			port = 1194
		}
		b.WriteString(fmt.Sprintf("remote %s %d\n", host, port))
		b.WriteString("resolv-retry infinite\nnobind\npersist-key\npersist-tun\n")
		if cipher := _extra_str(r, "cipher"); cipher != "" {
			b.WriteString(fmt.Sprintf("cipher %s\n", cipher))
		}
		if auth := _extra_str(r, "auth"); auth != "" {
			b.WriteString(fmt.Sprintf("auth %s\n", auth))
		}
		if v, ok := r.Extra["auth_user_pass"]; ok && v == true {
			b.WriteString("auth-user-pass\n")
		}
		b.WriteString("verb 3\n")

		for _, tag := range []string{"ca", "cert", "key", "tls-auth"} {
			if block := _extra_str(r, tag); block != "" {
				b.WriteString(fmt.Sprintf("\n<%s>\n%s\n</%s>\n", tag, block, tag))
			}
		}
	}
	return []byte(b.String()), nil
}

func _extract_inline_block(content, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	start := strings.Index(content, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(content[start:], close)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(content[start : start+end])
}

// --- wireguard ---

func (w *_wireguard) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	var records []ir.Record
	var current *ir.Record
	var section string

	_flush := func() {
		if current != nil {
			records = append(records, *current)
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[Interface]" || line == "[Peer]" {
			_flush()
			current = &ir.Record{
				PTVID: ir.NewPTVID(),
				Extra: map[string]any{"section": line},
			}
			section = line
			continue
		}

		if current == nil {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "PrivateKey":
			current.Extra["private_key"] = val
		case "PublicKey":
			current.Extra["public_key"] = val
		case "PresharedKey":
			current.Extra["preshared_key"] = val
		case "Address":
			current.IP = strings.Split(val, "/")[0]
		case "DNS":
			current.Extra["dns"] = val
		case "ListenPort":
			if port, err := strconv.Atoi(val); err == nil {
				current.Port = port
			}
		case "Endpoint":
			ep_parts := strings.SplitN(val, ":", 2)
			current.Domain = ep_parts[0]
			if len(ep_parts) == 2 {
				if port, err := strconv.Atoi(ep_parts[1]); err == nil {
					current.Port = port
				}
			}
		case "AllowedIPs":
			current.Extra["allowed_ips"] = val
		case "PersistentKeepalive":
			current.Extra["persistent_keepalive"] = val
		default:
			current.Extra[key] = val
		}
		_ = section
	}
	_flush()

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "wireguard",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (w *_wireguard) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		section := _extra_str(r, "section")
		if section == "" {
			if _extra_str(r, "private_key") != "" {
				section = "[Interface]"
			} else {
				section = "[Peer]"
			}
		}
		b.WriteString(section)
		b.WriteByte('\n')

		if section == "[Interface]" {
			if pk := _extra_str(r, "private_key"); pk != "" {
				b.WriteString(fmt.Sprintf("PrivateKey = %s\n", pk))
			}
			if r.IP != "" {
				b.WriteString(fmt.Sprintf("Address = %s/32\n", r.IP))
			}
			if dns := _extra_str(r, "dns"); dns != "" {
				b.WriteString(fmt.Sprintf("DNS = %s\n", dns))
			}
			if r.Port > 0 {
				b.WriteString(fmt.Sprintf("ListenPort = %d\n", r.Port))
			}
		} else {
			if pk := _extra_str(r, "public_key"); pk != "" {
				b.WriteString(fmt.Sprintf("PublicKey = %s\n", pk))
			}
			if psk := _extra_str(r, "preshared_key"); psk != "" {
				b.WriteString(fmt.Sprintf("PresharedKey = %s\n", psk))
			}
			if aip := _extra_str(r, "allowed_ips"); aip != "" {
				b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", aip))
			}
			endpoint := r.Domain
			if endpoint != "" && r.Port > 0 {
				endpoint = fmt.Sprintf("%s:%d", endpoint, r.Port)
			}
			if endpoint != "" {
				b.WriteString(fmt.Sprintf("Endpoint = %s\n", endpoint))
			}
			if ka := _extra_str(r, "persistent_keepalive"); ka != "" {
				b.WriteString(fmt.Sprintf("PersistentKeepalive = %s\n", ka))
			}
		}
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// --- telegram json ---

func (t *_telegram_json) Parse(raw []byte) (*ir.Dataset, error) {
	var export struct {
		Chats struct {
			List []struct {
				Name     string `json:"name"`
				Messages []struct {
					From   string `json:"from"`
					FromID string `json:"from_id"`
					Text   any    `json:"text"`
				} `json:"messages"`
			} `json:"list"`
		} `json:"chats"`
		Contacts struct {
			List []struct {
				FirstName   string `json:"first_name"`
				LastName    string `json:"last_name"`
				PhoneNumber string `json:"phone_number"`
				UserID      string `json:"user_id"`
			} `json:"list"`
		} `json:"contacts"`
	}

	if err := json.Unmarshal(raw, &export); err != nil {
		return nil, fmt.Errorf("failed to parse telegram json: %w", err)
	}

	// build contact lookup
	contacts := map[string]struct {
		name  string
		phone string
	}{}
	for _, c := range export.Contacts.List {
		name := strings.TrimSpace(c.FirstName + " " + c.LastName)
		contacts[c.UserID] = struct {
			name  string
			phone string
		}{name, c.PhoneNumber}
	}

	// collect unique users from messages
	seen := map[string]bool{}
	var records []ir.Record

	for _, chat := range export.Chats.List {
		for _, msg := range chat.Messages {
			if msg.FromID == "" || seen[msg.FromID] {
				continue
			}
			seen[msg.FromID] = true

			r := ir.Record{
				PTVID: ir.NewPTVID(),
				Extra: map[string]any{"chat": chat.Name},
			}

			if msg.From != "" {
				r.Name = msg.From
			}
			r.Username = msg.FromID

			if contact, ok := contacts[msg.FromID]; ok {
				if contact.name != "" {
					r.Name = contact.name
				}
				if contact.phone != "" {
					r.Phone = ir.NormalizePhone(contact.phone)
				}
			}

			records = append(records, r)
		}
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.8
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "telegram_json",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (t *_telegram_json) Render(ds *ir.Dataset) ([]byte, error) {
	type tg_msg struct {
		From   string `json:"from"`
		FromID string `json:"from_id"`
		Text   string `json:"text"`
	}
	type tg_chat struct {
		Name     string   `json:"name"`
		Messages []tg_msg `json:"messages"`
	}

	msgs := make([]tg_msg, 0, len(ds.Records))
	for _, r := range ds.Records {
		from := r.Name
		if from == "" {
			from = r.Username
		}
		msgs = append(msgs, tg_msg{
			From:   from,
			FromID: r.Username,
			Text:   r.Password,
		})
	}

	export := map[string]any{
		"chats": map[string]any{
			"list": []tg_chat{{Name: "export", Messages: msgs}},
		},
	}
	return json.MarshalIndent(export, "", "  ")
}

// --- discord json ---

func (d *_discord_json) Parse(raw []byte) (*ir.Dataset, error) {
	var export struct {
		Channel struct {
			Name string `json:"name"`
		} `json:"channel"`
		Messages []struct {
			Content string `json:"content"`
			Author  struct {
				ID       string `json:"id"`
				Username string `json:"username"`
				Email    string `json:"email"`
			} `json:"author"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(raw, &export); err != nil {
		return nil, fmt.Errorf("failed to parse discord json: %w", err)
	}

	// collect unique authors
	seen := map[string]bool{}
	var records []ir.Record

	for _, msg := range export.Messages {
		if msg.Author.ID == "" || seen[msg.Author.ID] {
			continue
		}
		seen[msg.Author.ID] = true

		r := ir.Record{
			PTVID:    ir.NewPTVID(),
			Username: msg.Author.Username,
			Extra: map[string]any{
				"discord_id": msg.Author.ID,
				"channel":    export.Channel.Name,
			},
		}
		if msg.Author.Email != "" {
			r.Email = msg.Author.Email
		}

		records = append(records, r)
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "discord_json",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (d *_discord_json) Render(ds *ir.Dataset) ([]byte, error) {
	type dc_author struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email,omitempty"`
	}
	type dc_msg struct {
		Content string    `json:"content"`
		Author  dc_author `json:"author"`
	}

	msgs := make([]dc_msg, 0, len(ds.Records))
	for _, r := range ds.Records {
		did := _extra_str(r, "discord_id")
		if did == "" {
			did = r.PTVID
		}
		msgs = append(msgs, dc_msg{
			Content: r.Password,
			Author: dc_author{
				ID:       did,
				Username: r.Username,
				Email:    r.Email,
			},
		})
	}

	export := map[string]any{
		"channel":  map[string]any{"name": "export"},
		"messages": msgs,
	}
	return json.MarshalIndent(export, "", "  ")
}

// --- docker config ---

func (d *_docker_config) Parse(raw []byte) (*ir.Dataset, error) {
	var config struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}

	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("failed to parse docker config: %w", err)
	}

	var records []ir.Record
	for registry, auth := range config.Auths {
		r := ir.Record{
			PTVID:  ir.NewPTVID(),
			Domain: registry,
		}

		decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) >= 1 {
				_classify_identity(&r, parts[0])
			}
			if len(parts) >= 2 {
				r.Password = parts[1]
			}
		}

		records = append(records, r)
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "docker_config",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         []string{"domain", "username", "email", "password"},
			FieldConfidence: map[string]float64{"domain": 1.0, "username": 1.0, "email": 1.0, "password": 1.0},
		},
		Records: records,
	}, nil
}

func (d *_docker_config) Render(ds *ir.Dataset) ([]byte, error) {
	auths := map[string]map[string]string{}
	for _, r := range ds.Records {
		registry := r.Domain
		if registry == "" {
			registry = "https://index.docker.io/v1/"
		}
		ident := r.Email
		if ident == "" {
			ident = r.Username
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(ident + ":" + r.Password))
		auths[registry] = map[string]string{"auth": encoded}
	}
	config := map[string]any{"auths": auths}
	return json.MarshalIndent(config, "", "  ")
}

// --- aws credentials ---

func (a *_aws_credentials) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	var records []ir.Record
	var current *ir.Record

	_flush := func() {
		if current != nil {
			records = append(records, *current)
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			_flush()
			profile := line[1 : len(line)-1]
			current = &ir.Record{
				PTVID: ir.NewPTVID(),
				Extra: map[string]any{"profile": profile},
			}
			continue
		}

		if current == nil {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "aws_access_key_id":
			current.Username = val
		case "aws_secret_access_key":
			current.Password = val
		case "region":
			current.Extra["region"] = val
		case "aws_session_token":
			current.Extra["session_token"] = val
		default:
			current.Extra[key] = val
		}
	}
	_flush()

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "aws_credentials",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         []string{"username", "password"},
			FieldConfidence: map[string]float64{"username": 1.0, "password": 1.0},
		},
		Records: records,
	}, nil
}

func (a *_aws_credentials) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		profile := _extra_str(r, "profile")
		if profile == "" {
			profile = "default"
		}
		b.WriteString(fmt.Sprintf("[%s]\n", profile))
		if r.Username != "" {
			b.WriteString(fmt.Sprintf("aws_access_key_id = %s\n", r.Username))
		}
		if r.Password != "" {
			b.WriteString(fmt.Sprintf("aws_secret_access_key = %s\n", r.Password))
		}
		if region := _extra_str(r, "region"); region != "" {
			b.WriteString(fmt.Sprintf("region = %s\n", region))
		}
		if token := _extra_str(r, "session_token"); token != "" {
			b.WriteString(fmt.Sprintf("aws_session_token = %s\n", token))
		}
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}
