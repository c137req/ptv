package formats

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	_ "modernc.org/sqlite"
)

type _sqlite struct{}
type _browser_sqlite struct{}

func init() {
	module.Register(&_sqlite{})
	module.Register(&_browser_sqlite{})
}

func (s *_sqlite) Name() string         { return "sqlite" }
func (b *_browser_sqlite) Name() string { return "browser_sqlite" }

// --- shared helper ---

func _open_sqlite_db(raw []byte) (*sql.DB, string, error) {
	tmp, err := os.CreateTemp("", "ptv-sqlite-*.db")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp file: %w", err)
	}
	path := tmp.Name()
	tmp.Close()

	if err := os.WriteFile(path, raw, 0600); err != nil {
		os.Remove(path)
		return nil, "", fmt.Errorf("failed to write temp file: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		os.Remove(path)
		return nil, "", fmt.Errorf("failed to open sqlite db: %w", err)
	}

	return db, path, nil
}

func _sqlite_has_cred_columns(columns []string) bool {
	for _, col := range columns {
		switch strings.ToLower(col) {
		case "email", "e-mail", "mail", "email_address",
			"username", "user", "login", "account", "user_name", "userid",
			"password", "pass", "passwd", "pwd", "secret",
			"url", "uri", "link", "website",
			"domain", "host", "hostname",
			"ip", "ip_address",
			"phone", "telephone", "tel":
			return true
		}
	}
	return false
}

// --- generic sqlite ---

func (s *_sqlite) Parse(raw []byte) (*ir.Dataset, error) {
	db, path, err := _open_sqlite_db(raw)
	if err != nil {
		return nil, err
	}
	defer os.Remove(path)
	defer db.Close()

	tables, err := _sqlite_list_tables(db)
	if err != nil {
		return nil, err
	}

	var records []ir.Record
	for _, table := range tables {
		cols, err := _sqlite_table_columns(db, table)
		if err != nil {
			continue
		}
		if !_sqlite_has_cred_columns(cols) {
			continue
		}

		rows, err := db.Query(fmt.Sprintf("SELECT * FROM %q", table))
		if err != nil {
			continue
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				continue
			}

			r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{"table": table}}
			for i, col := range cols {
				str := _sqlite_val_to_string(vals[i])
				if str == "" {
					continue
				}
				if !_map_field_to_record(&r, col, str) {
					r.Extra[col] = str
				}
			}
			records = append(records, r)
		}
		rows.Close()
	}

	detected := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range detected {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "sqlite",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         detected,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (s *_sqlite) Render(ds *ir.Dataset) ([]byte, error) {
	cols := ds.Meta.Columns
	if len(cols) == 0 {
		cols = _detect_columns(ds.Records)
	}

	var b strings.Builder
	table := "credentials"

	// create table
	col_defs := make([]string, len(cols))
	for i, c := range cols {
		col_defs[i] = fmt.Sprintf("%s TEXT", c)
	}
	b.WriteString(fmt.Sprintf("CREATE TABLE %s (%s);\n", table, strings.Join(col_defs, ", ")))

	// insert rows
	for _, r := range ds.Records {
		m := _record_to_map(r)
		vals := make([]string, len(cols))
		for i, col := range cols {
			vals[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(m[strings.ToLower(col)], "'", "''"))
		}
		b.WriteString(fmt.Sprintf("INSERT INTO %s VALUES (%s);\n", table, strings.Join(vals, ", ")))
	}

	return []byte(b.String()), nil
}

// --- browser sqlite ---

var _browser_table_schemas = []struct {
	table   string
	columns map[string]string // db column → ir field name
}{
	{
		table: "logins", // chrome
		columns: map[string]string{
			"origin_url":     "url",
			"username_value": "username",
			"password_value": "password",
			"signon_realm":   "domain",
		},
	},
	{
		table: "moz_logins", // firefox
		columns: map[string]string{
			"hostname":          "url",
			"encryptedUsername":  "username",
			"encryptedPassword": "password",
			"formSubmitURL":     "url",
		},
	},
}

func (bs *_browser_sqlite) Parse(raw []byte) (*ir.Dataset, error) {
	db, path, err := _open_sqlite_db(raw)
	if err != nil {
		return nil, err
	}
	defer os.Remove(path)
	defer db.Close()

	tables, err := _sqlite_list_tables(db)
	if err != nil {
		return nil, err
	}

	table_set := map[string]bool{}
	for _, t := range tables {
		table_set[t] = true
	}

	var records []ir.Record

	for _, schema := range _browser_table_schemas {
		if !table_set[schema.table] {
			continue
		}

		cols, err := _sqlite_table_columns(db, schema.table)
		if err != nil {
			continue
		}

		rows, err := db.Query(fmt.Sprintf("SELECT * FROM %q", schema.table))
		if err != nil {
			continue
		}

		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				continue
			}

			r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{"table": schema.table}}

			for i, col := range cols {
				ir_field, known := schema.columns[col]
				if !known {
					str := _sqlite_val_to_string(vals[i])
					if str != "" {
						r.Extra[col] = str
					}
					continue
				}

				// handle potentially encrypted blob values
				if ir_field == "password" || ir_field == "username" {
					str := _sqlite_val_to_string(vals[i])
					if str == "" {
						continue
					}
					// check if value looks like encrypted data (non-utf8 or too short binary)
					if blob, ok := vals[i].([]byte); ok && !utf8.Valid(blob) {
						r.Unknowns = append(r.Unknowns, ir.UnknownField{
							Value: fmt.Sprintf("[encrypted:%d bytes]", len(blob)),
							PotentialFields: []ir.PotentialField{
								{Field: ir_field, Confidence: 0.9},
							},
						})
						continue
					}
					_map_field_to_record(&r, ir_field, str)
				} else {
					str := _sqlite_val_to_string(vals[i])
					if str != "" {
						_map_field_to_record(&r, ir_field, str)
					}
				}
			}
			records = append(records, r)
		}
		rows.Close()

		if len(records) > 0 {
			break // found a matching browser table
		}
	}

	// fall back to generic sqlite scan if no browser table matched
	if len(records) == 0 {
		return (&_sqlite{}).Parse(raw)
	}

	detected := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range detected {
		conf[c] = 0.9
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "browser_sqlite",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         detected,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (bs *_browser_sqlite) Render(ds *ir.Dataset) ([]byte, error) {
	return (&_sqlite{}).Render(ds)
}

// --- sqlite utilities ---

func _sqlite_list_tables(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		tables = append(tables, name)
	}
	return tables, nil
}

func _sqlite_table_columns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%q)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt_value any
		var pk int
		rows.Scan(&cid, &name, &typ, &notnull, &dflt_value, &pk)
		cols = append(cols, name)
	}
	return cols, nil
}

func _sqlite_val_to_string(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		if utf8.Valid(val) {
			return string(val)
		}
		return fmt.Sprintf("%x", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}
