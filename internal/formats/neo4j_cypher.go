package formats

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _neo4j_cypher struct{}

func init() { module.Register(&_neo4j_cypher{}) }

func (n *_neo4j_cypher) Name() string { return "neo4j_cypher" }

// matches CREATE/MERGE (var:Label {props}) or CREATE/MERGE (var {props})
var _cypher_node_re = regexp.MustCompile(`(?i)(?:CREATE|MERGE)\s+\(\w+(?::(\w+))?\s*\{([^}]+)\}\s*\)`)

func (n *_neo4j_cypher) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	var records []ir.Record

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		matches := _cypher_node_re.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			label := match[1]
			props := match[2]

			r := ir.Record{PTVID: ir.NewPTVID()}
			matched := 0

			pairs := _parse_cypher_props(props)
			for k, v := range pairs {
				if _map_field_to_record(&r, k, v) {
					matched++
				} else {
					if r.Extra == nil {
						r.Extra = map[string]any{}
					}
					r.Extra[k] = v
				}
			}

			if label != "" {
				if r.Extra == nil {
					r.Extra = map[string]any{}
				}
				r.Extra["label"] = label
			}

			if matched > 0 {
				records = append(records, r)
			}
		}
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.9
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "neo4j_cypher",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func _parse_cypher_props(s string) map[string]string {
	result := map[string]string{}
	i := 0
	for i < len(s) {
		// skip whitespace and commas
		for i < len(s) && (s[i] == ' ' || s[i] == ',' || s[i] == '\t' || s[i] == '\n') {
			i++
		}
		if i >= len(s) {
			break
		}

		// read key
		start := i
		for i < len(s) && s[i] != ':' && s[i] != ' ' {
			i++
		}
		key := strings.TrimSpace(s[start:i])

		// skip colon and whitespace
		for i < len(s) && (s[i] == ':' || s[i] == ' ') {
			i++
		}
		if i >= len(s) {
			break
		}

		var val string
		if s[i] == '\'' {
			i++
			var b strings.Builder
			for i < len(s) {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						b.WriteByte('\'')
						i += 2
						continue
					}
					break
				}
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++
			}
			val = b.String()
		} else if s[i] == '"' {
			i++
			var b strings.Builder
			for i < len(s) {
				if s[i] == '"' {
					break
				}
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++
			}
			val = b.String()
		} else {
			start = i
			for i < len(s) && s[i] != ',' && s[i] != '}' {
				i++
			}
			val = strings.TrimSpace(s[start:i])
		}

		if key != "" {
			result[key] = val
		}
	}
	return result
}

func (n *_neo4j_cypher) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		m := _record_to_map(r)
		label := "Record"
		if r.Extra != nil {
			if l, ok := r.Extra["label"].(string); ok && l != "" {
				label = l
			}
		}

		var props []string
		for k, v := range m {
			props = append(props, fmt.Sprintf("%s: '%s'", k, strings.ReplaceAll(v, "'", "\\'")))
		}
		if r.Extra != nil {
			for k, v := range r.Extra {
				if k == "label" {
					continue
				}
				if sv, ok := v.(string); ok {
					props = append(props, fmt.Sprintf("%s: '%s'", k, strings.ReplaceAll(sv, "'", "\\'")))
				}
			}
		}

		b.WriteString(fmt.Sprintf("CREATE (n:%s {%s})\n", label, strings.Join(props, ", ")))
	}
	return []byte(b.String()), nil
}
