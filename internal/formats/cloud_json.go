package formats

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _firebase_json struct{}
type _firestore_json struct{}
type _couchdb_json struct{}

func init() {
	module.Register(&_firebase_json{})
	module.Register(&_firestore_json{})
	module.Register(&_couchdb_json{})
}

func (f *_firebase_json) Name() string  { return "firebase_json" }
func (f *_firestore_json) Name() string { return "firestore_json" }
func (c *_couchdb_json) Name() string   { return "couchdb_json" }

// --- firebase json ---

func (f *_firebase_json) Parse(raw []byte) (*ir.Dataset, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("failed to parse firebase json: %w", err)
	}

	var records []ir.Record

	// walk top-level collections (typically "users", "accounts", etc.)
	for _, collection := range root {
		coll, ok := collection.(map[string]any)
		if !ok {
			continue
		}
		for _, doc := range coll {
			obj, ok := doc.(map[string]any)
			if !ok {
				continue
			}
			r := ir.Record{PTVID: ir.NewPTVID()}
			matched := 0
			for k, v := range obj {
				str := fmt.Sprintf("%v", v)
				if _map_field_to_record(&r, k, str) {
					matched++
				} else {
					if r.Extra == nil {
						r.Extra = map[string]any{}
					}
					r.Extra[k] = v
				}
			}
			if matched > 0 {
				records = append(records, r)
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
			SourceFormat:    "firebase_json",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (f *_firebase_json) Render(ds *ir.Dataset) ([]byte, error) {
	users := map[string]map[string]any{}
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
		if r.Name != "" {
			m["name"] = r.Name
		}
		if r.Phone != "" {
			m["phone"] = r.Phone
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
		for k, v := range r.Extra {
			m[k] = v
		}
		users[r.PTVID] = m
	}
	root := map[string]any{"users": users}
	return json.MarshalIndent(root, "", "  ")
}

// --- firestore json ---

func (f *_firestore_json) Parse(raw []byte) (*ir.Dataset, error) {
	var records []ir.Record

	// try JSONL first (one doc per line)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	parsed_lines := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			break
		}
		parsed_lines++
		r := _parse_firestore_doc(doc)
		if r != nil {
			records = append(records, *r)
		}
	}

	// if no lines parsed as JSONL, try as JSON array
	if parsed_lines == 0 {
		var docs []map[string]any
		if err := json.Unmarshal(raw, &docs); err != nil {
			return nil, fmt.Errorf("failed to parse firestore json: %w", err)
		}
		for _, doc := range docs {
			r := _parse_firestore_doc(doc)
			if r != nil {
				records = append(records, *r)
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
			SourceFormat:    "firestore_json",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func _parse_firestore_doc(doc map[string]any) *ir.Record {
	fields, ok := doc["fields"].(map[string]any)
	if !ok {
		return nil
	}

	r := ir.Record{PTVID: ir.NewPTVID()}
	matched := 0

	for k, v := range fields {
		// firestore typed values: {"stringValue": "..."}, {"integerValue": "..."}, etc.
		typed, ok := v.(map[string]any)
		if !ok {
			continue
		}
		val := _firestore_unwrap(typed)
		if _map_field_to_record(&r, k, val) {
			matched++
		} else {
			if r.Extra == nil {
				r.Extra = map[string]any{}
			}
			r.Extra[k] = val
		}
	}

	if matched == 0 {
		return nil
	}
	return &r
}

func _firestore_unwrap(typed map[string]any) string {
	for _, key := range []string{"stringValue", "integerValue", "doubleValue", "booleanValue"} {
		if v, ok := typed[key]; ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return fmt.Sprintf("%v", typed)
}

func (f *_firestore_json) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		fields := map[string]any{}
		if r.Email != "" {
			fields["email"] = map[string]string{"stringValue": r.Email}
		}
		if r.Username != "" {
			fields["username"] = map[string]string{"stringValue": r.Username}
		}
		if r.Password != "" {
			fields["password"] = map[string]string{"stringValue": r.Password}
		}
		if r.URL != "" {
			fields["url"] = map[string]string{"stringValue": r.URL}
		}
		if r.Name != "" {
			fields["name"] = map[string]string{"stringValue": r.Name}
		}
		if r.Phone != "" {
			fields["phone"] = map[string]string{"stringValue": r.Phone}
		}
		if r.Domain != "" {
			fields["domain"] = map[string]string{"stringValue": r.Domain}
		}
		if r.IP != "" {
			fields["ip"] = map[string]string{"stringValue": r.IP}
		}
		for k, v := range r.Extra {
			fields[k] = map[string]string{"stringValue": fmt.Sprintf("%v", v)}
		}
		doc := map[string]any{"fields": fields}
		line, _ := json.Marshal(doc)
		b.Write(line)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// --- couchdb json ---

func (c *_couchdb_json) Parse(raw []byte) (*ir.Dataset, error) {
	var wrapper map[string]any
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse couchdb json: %w", err)
	}

	var docs []map[string]any

	// try {"rows": [{"doc": {...}}, ...]} format
	if rows, ok := wrapper["rows"].([]any); ok {
		for _, row := range rows {
			rm, ok := row.(map[string]any)
			if !ok {
				continue
			}
			if doc, ok := rm["doc"].(map[string]any); ok {
				docs = append(docs, doc)
			}
		}
	}

	// try {"docs": [...]} format
	if len(docs) == 0 {
		if d, ok := wrapper["docs"].([]any); ok {
			for _, item := range d {
				if doc, ok := item.(map[string]any); ok {
					docs = append(docs, doc)
				}
			}
		}
	}

	records := make([]ir.Record, 0, len(docs))
	for _, doc := range docs {
		r := ir.Record{PTVID: ir.NewPTVID()}
		matched := 0
		for k, v := range doc {
			if k == "_id" || k == "_rev" {
				continue
			}
			str := fmt.Sprintf("%v", v)
			if _map_field_to_record(&r, k, str) {
				matched++
			} else {
				if r.Extra == nil {
					r.Extra = map[string]any{}
				}
				r.Extra[k] = v
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
			SourceFormat:    "couchdb_json",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (c *_couchdb_json) Render(ds *ir.Dataset) ([]byte, error) {
	docs := make([]map[string]any, 0, len(ds.Records))
	for _, r := range ds.Records {
		m := map[string]any{"_id": r.PTVID}
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
		if r.Name != "" {
			m["name"] = r.Name
		}
		if r.Phone != "" {
			m["phone"] = r.Phone
		}
		if r.Domain != "" {
			m["domain"] = r.Domain
		}
		if r.IP != "" {
			m["ip"] = r.IP
		}
		for k, v := range r.Extra {
			m[k] = v
		}
		docs = append(docs, m)
	}
	root := map[string]any{"docs": docs}
	return json.MarshalIndent(root, "", "  ")
}
