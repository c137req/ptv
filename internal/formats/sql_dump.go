package formats

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _sql_dump_mysql struct{}
type _sql_dump_postgres struct{}
type _sql_dump_mssql struct{}
type _sql_dump_oracle struct{}

func init() {
	module.Register(&_sql_dump_mysql{})
	module.Register(&_sql_dump_postgres{})
	module.Register(&_sql_dump_mssql{})
	module.Register(&_sql_dump_oracle{})
}

func (s *_sql_dump_mysql) Name() string    { return "sql_dump_mysql" }
func (s *_sql_dump_postgres) Name() string { return "sql_dump_postgres" }
func (s *_sql_dump_mssql) Name() string    { return "sql_dump_mssql" }
func (s *_sql_dump_oracle) Name() string   { return "sql_dump_oracle" }

// --- shared sql parsing ---

var (
	// matches INSERT [INTO] [schema.]table (col1, col2) VALUES
	// handles backtick, double-quote, and bracket quoting, including [schema].[table]
	_insert_re = regexp.MustCompile(`(?i)INSERT\s+(?:INTO\s+)?` +
		`(?:[\x60"\w]+\.|\[\w+\]\.)?` + // optional schema prefix (backtick/dquote/bracket)
		`([\x60"\w]+|\[\w+\])\s*` + // table name
		`\(([^)]+)\)\s*VALUES?\s*`)

	// matches CREATE TABLE [schema.]table (
	_create_re = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` +
		`(?:[\x60"\w]+\.|\[\w+\]\.)?` +
		`([\x60"\w]+|\[\w+\])\s*\(`)

	// matches COPY table (cols) FROM stdin
	_copy_re = regexp.MustCompile(`(?i)COPY\s+([\w"]+)\s*\(([^)]+)\)\s*FROM\s+stdin`)
)

func _parse_sql_dump(raw []byte, format string) (*ir.Dataset, error) {
	content := string(raw)
	lines := _split_lines(content)

	var records []ir.Record

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// detect INSERT line and join until semicolon or GO
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "INSERT") {
			stmt := line
			// join lines until we find a terminator
			for !_sql_stmt_complete(stmt, format) && i+1 < len(lines) {
				i++
				next := lines[i]
				next_trimmed := strings.TrimSpace(next)
				if next_trimmed == "" || strings.HasPrefix(next_trimmed, "--") {
					continue
				}
				stmt = stmt + "\n" + next
				if _sql_stmt_complete(stmt, format) {
					break
				}
			}

			loc := _insert_re.FindStringIndex(stmt)
			if loc != nil {
				match := _insert_re.FindStringSubmatch(stmt)
				if match != nil {
					cols := _parse_sql_col_list(match[2], format)
					values_part := stmt[loc[1]:]
					value_sets := _extract_value_sets(values_part)
					for _, vals := range value_sets {
						r := _sql_values_to_record(cols, vals)
						if r != nil {
							records = append(records, *r)
						}
					}
				}
			}
			continue
		}

		// try COPY (postgres)
		if format == "sql_dump_postgres" {
			copy_match := _copy_re.FindStringSubmatch(line)
			if copy_match != nil {
				cols := _parse_sql_col_list(copy_match[2], format)
				for i+1 < len(lines) {
					i++
					data_line := lines[i]
					if strings.TrimSpace(data_line) == `\.` {
						break
					}
					vals := strings.Split(data_line, "\t")
					r := _sql_values_to_record(cols, vals)
					if r != nil {
						records = append(records, *r)
					}
				}
			}
		}
	}

	detected := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range detected {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    format,
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         detected,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func _sql_stmt_complete(stmt string, format string) bool {
	trimmed := strings.TrimSpace(stmt)
	if strings.HasSuffix(trimmed, ";") {
		return true
	}
	// mssql uses GO as batch separator — check if next line after values is GO
	if format == "sql_dump_mssql" {
		lines := strings.Split(trimmed, "\n")
		last := strings.TrimSpace(lines[len(lines)-1])
		if strings.EqualFold(last, "GO") || strings.HasSuffix(last, ")") {
			return true
		}
	}
	return false
}

func _extract_sql_columns(content string, format string) []string {
	match := _create_re.FindStringIndex(content)
	if match == nil {
		return nil
	}
	// extract column definitions between ( and matching )
	rest := content[match[1]:]
	depth := 1
	end := 0
	for i, c := range rest {
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth == 0 {
				end = i
				break
			}
		}
	}
	if end == 0 {
		return nil
	}
	body := rest[:end]
	var cols []string
	for _, line := range strings.Split(body, ",") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// skip constraints
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "PRIMARY") || strings.HasPrefix(upper, "UNIQUE") ||
			strings.HasPrefix(upper, "KEY") || strings.HasPrefix(upper, "INDEX") ||
			strings.HasPrefix(upper, "CONSTRAINT") || strings.HasPrefix(upper, "CHECK") ||
			strings.HasPrefix(upper, "FOREIGN") {
			continue
		}
		col := strings.Fields(line)[0]
		col = _strip_sql_quotes(col, format)
		cols = append(cols, col)
	}
	return cols
}

func _parse_sql_col_list(list string, format string) []string {
	parts := strings.Split(list, ",")
	cols := make([]string, 0, len(parts))
	for _, p := range parts {
		col := strings.TrimSpace(p)
		col = _strip_sql_quotes(col, format)
		cols = append(cols, col)
	}
	return cols
}

func _strip_sql_quotes(s string, format string) string {
	s = strings.TrimSpace(s)
	// backticks (mysql)
	s = strings.Trim(s, "`")
	// double quotes (postgres, oracle)
	s = strings.Trim(s, `"`)
	// brackets (mssql)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	// N prefix (mssql unicode)
	_ = format
	return s
}

func _extract_value_sets(s string) [][]string {
	var sets [][]string
	i := 0
	for i < len(s) {
		// find opening (
		start := strings.IndexByte(s[i:], '(')
		if start < 0 {
			break
		}
		i += start + 1
		vals, end := _parse_value_tuple(s[i:])
		if vals != nil {
			sets = append(sets, vals)
		}
		i += end
	}
	return sets
}

func _parse_value_tuple(s string) ([]string, int) {
	var vals []string
	i := 0
	for i < len(s) {
		// skip whitespace
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == ')' {
			return vals, i + 1
		}

		// skip N prefix for MSSQL unicode strings
		if i+1 < len(s) && s[i] == 'N' && s[i+1] == '\'' {
			i++
		}

		if s[i] == '\'' {
			// quoted string
			i++
			var val strings.Builder
			for i < len(s) {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						val.WriteByte('\'')
						i += 2
						continue
					}
					break
				}
				if s[i] == '\\' && i+1 < len(s) {
					val.WriteByte(s[i+1])
					i += 2
					continue
				}
				val.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++ // skip closing quote
			}
			vals = append(vals, val.String())
		} else if s[i] == ',' {
			i++
			continue
		} else {
			// unquoted value (number, NULL, etc.)
			start := i
			for i < len(s) && s[i] != ',' && s[i] != ')' {
				i++
			}
			val := strings.TrimSpace(s[start:i])
			if strings.EqualFold(val, "NULL") {
				vals = append(vals, "")
			} else {
				vals = append(vals, val)
			}
		}

		// skip comma between values
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}
		if i < len(s) && s[i] == ',' {
			i++
		}
	}
	return vals, i
}

func _sql_values_to_record(cols []string, vals []string) *ir.Record {
	r := ir.Record{PTVID: ir.NewPTVID()}
	matched := 0
	for i, col := range cols {
		if i >= len(vals) {
			break
		}
		val := strings.TrimSpace(vals[i])
		if val == "" {
			continue
		}
		if _map_field_to_record(&r, col, val) {
			matched++
		} else {
			if r.Extra == nil {
				r.Extra = map[string]any{}
			}
			r.Extra[col] = val
		}
	}
	if matched == 0 {
		return nil
	}
	return &r
}

// --- mysql ---

func (s *_sql_dump_mysql) Parse(raw []byte) (*ir.Dataset, error) {
	return _parse_sql_dump(raw, "sql_dump_mysql")
}

func (s *_sql_dump_mysql) Render(ds *ir.Dataset) ([]byte, error) {
	return _render_sql_dump(ds, "sql_dump_mysql")
}

// --- postgres ---

func (s *_sql_dump_postgres) Parse(raw []byte) (*ir.Dataset, error) {
	return _parse_sql_dump(raw, "sql_dump_postgres")
}

func (s *_sql_dump_postgres) Render(ds *ir.Dataset) ([]byte, error) {
	return _render_sql_dump(ds, "sql_dump_postgres")
}

// --- mssql ---

func (s *_sql_dump_mssql) Parse(raw []byte) (*ir.Dataset, error) {
	return _parse_sql_dump(raw, "sql_dump_mssql")
}

func (s *_sql_dump_mssql) Render(ds *ir.Dataset) ([]byte, error) {
	return _render_sql_dump(ds, "sql_dump_mssql")
}

// --- oracle ---

func (s *_sql_dump_oracle) Parse(raw []byte) (*ir.Dataset, error) {
	return _parse_sql_dump(raw, "sql_dump_oracle")
}

func (s *_sql_dump_oracle) Render(ds *ir.Dataset) ([]byte, error) {
	return _render_sql_dump(ds, "sql_dump_oracle")
}

func _render_sql_dump(ds *ir.Dataset, format string) ([]byte, error) {
	cols := ds.Meta.Columns
	if len(cols) == 0 {
		cols = _detect_columns(ds.Records)
	}

	var b strings.Builder
	table := "credentials"
	quote_fn := _sql_quote_id(format)

	// create table
	col_defs := make([]string, len(cols))
	for i, c := range cols {
		col_defs[i] = fmt.Sprintf("%s TEXT", quote_fn(c))
	}
	b.WriteString(fmt.Sprintf("CREATE TABLE %s (\n  %s\n);\n\n", quote_fn(table), strings.Join(col_defs, ",\n  ")))

	// insert rows
	for _, r := range ds.Records {
		m := _record_to_map(r)
		vals := make([]string, len(cols))
		for i, col := range cols {
			v := m[strings.ToLower(col)]
			v = strings.ReplaceAll(v, "'", "''")
			if format == "sql_dump_mssql" {
				vals[i] = fmt.Sprintf("N'%s'", v)
			} else {
				vals[i] = fmt.Sprintf("'%s'", v)
			}
		}
		quoted_cols := make([]string, len(cols))
		for i, c := range cols {
			quoted_cols[i] = quote_fn(c)
		}
		b.WriteString(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s);\n",
			quote_fn(table), strings.Join(quoted_cols, ", "), strings.Join(vals, ", ")))
		if format == "sql_dump_mssql" {
			b.WriteString("GO\n")
		}
	}

	return []byte(b.String()), nil
}

func _sql_quote_id(format string) func(string) string {
	switch format {
	case "sql_dump_mysql":
		return func(s string) string { return "`" + s + "`" }
	case "sql_dump_mssql":
		return func(s string) string { return "[" + s + "]" }
	case "sql_dump_postgres", "sql_dump_oracle":
		return func(s string) string { return `"` + s + `"` }
	default:
		return func(s string) string { return s }
	}
}
