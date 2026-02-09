package formats

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _xml_generic struct{}
type _windows_wifi struct{}

func init() {
	module.Register(&_xml_generic{})
	module.Register(&_windows_wifi{})
}

func (x *_xml_generic) Name() string  { return "xml_generic" }
func (w *_windows_wifi) Name() string { return "windows_wifi_xml" }

func (x *_xml_generic) Parse(raw []byte) (*ir.Dataset, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	var records []ir.Record
	var current ir.Record
	has_fields := false
	current.PTVID = ir.NewPTVID()
	var elem_name string

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			elem_name = t.Name.Local
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text == "" || elem_name == "" {
				continue
			}
			if _map_field_to_record(&current, elem_name, text) {
				has_fields = true
			} else if _is_known_field(elem_name) {
				has_fields = true
			}
		case xml.EndElement:
			// when we close a container element that had credential children, save it
			if t.Name.Local != elem_name && has_fields {
				records = append(records, current)
				current = ir.Record{PTVID: ir.NewPTVID()}
				has_fields = false
			}
			elem_name = ""
		}
	}
	if has_fields {
		records = append(records, current)
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.9
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "xml_generic",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (x *_xml_generic) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<records>\n")
	for _, r := range ds.Records {
		b.WriteString("  <record>\n")
		m := _record_to_map(r)
		for k, v := range m {
			b.WriteString(fmt.Sprintf("    <%s>%s</%s>\n", k, _xml_escape(v), k))
		}
		for k, v := range r.Extra {
			b.WriteString(fmt.Sprintf("    <%s>%v</%s>\n", k, v, k))
		}
		b.WriteString("  </record>\n")
	}
	b.WriteString("</records>\n")
	return []byte(b.String()), nil
}

func _xml_escape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// windows wifi xml parser
func (w *_windows_wifi) Parse(raw []byte) (*ir.Dataset, error) {
	content := string(raw)
	r := ir.Record{
		PTVID: ir.NewPTVID(),
		Extra: map[string]any{},
	}

	// extract SSID name
	if ssid := _xml_extract_tag(content, "name"); ssid != "" {
		r.Domain = ssid
	}

	// extract key material (wifi password)
	if key := _xml_extract_tag(content, "keyMaterial"); key != "" {
		r.Password = key
	}

	// extract auth/encryption type
	if auth := _xml_extract_tag(content, "authentication"); auth != "" {
		r.Extra["authentication"] = auth
	}
	if enc := _xml_extract_tag(content, "encryption"); enc != "" {
		r.Extra["encryption"] = enc
	}
	if kt := _xml_extract_tag(content, "keyType"); kt != "" {
		r.Extra["key_type"] = kt
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "windows_wifi_xml",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     1,
			Columns:         []string{"domain", "password"},
			FieldConfidence: map[string]float64{"domain": 1.0, "password": 1.0},
		},
		Records: []ir.Record{r},
	}, nil
}

func (w *_windows_wifi) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		ssid := r.Domain
		if ssid == "" {
			ssid = "Unknown"
		}
		auth := "WPA2PSK"
		enc := "AES"
		if r.Extra != nil {
			if v, ok := r.Extra["authentication"].(string); ok {
				auth = v
			}
			if v, ok := r.Extra["encryption"].(string); ok {
				enc = v
			}
		}
		b.WriteString("<?xml version=\"1.0\"?>\n")
		b.WriteString("<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n")
		b.WriteString(fmt.Sprintf("  <name>%s</name>\n", _xml_escape(ssid)))
		b.WriteString("  <SSIDConfig><SSID>\n")
		b.WriteString(fmt.Sprintf("    <name>%s</name>\n", _xml_escape(ssid)))
		b.WriteString("  </SSID></SSIDConfig>\n")
		b.WriteString("  <connectionType>ESS</connectionType>\n")
		b.WriteString("  <connectionMode>auto</connectionMode>\n")
		b.WriteString("  <MSM><security>\n")
		b.WriteString("    <authEncryption>\n")
		b.WriteString(fmt.Sprintf("      <authentication>%s</authentication>\n", auth))
		b.WriteString(fmt.Sprintf("      <encryption>%s</encryption>\n", enc))
		b.WriteString("    </authEncryption>\n")
		b.WriteString("    <sharedKey>\n")
		b.WriteString("      <keyType>passPhrase</keyType>\n")
		b.WriteString("      <protected>false</protected>\n")
		b.WriteString(fmt.Sprintf("      <keyMaterial>%s</keyMaterial>\n", _xml_escape(r.Password)))
		b.WriteString("    </sharedKey>\n")
		b.WriteString("  </security></MSM>\n")
		b.WriteString("</WLANProfile>\n")
	}
	return []byte(b.String()), nil
}

// _xml_extract_tag finds the first occurrence of <tag>value</tag> and returns value.
func _xml_extract_tag(content, tag string) string {
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
