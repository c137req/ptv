package formats

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _redis_aof struct{}
type _influxdb_lp struct{}
type _cassandra_cql struct{}

func init() {
	module.Register(&_redis_aof{})
	module.Register(&_influxdb_lp{})
	module.Register(&_cassandra_cql{})
}

func (r *_redis_aof) Name() string     { return "redis_aof" }
func (i *_influxdb_lp) Name() string   { return "influxdb_lp" }
func (c *_cassandra_cql) Name() string { return "cassandra_cql" }

// --- redis aof ---

func (ra *_redis_aof) Parse(raw []byte) (*ir.Dataset, error) {
	lines := strings.Split(string(raw), "\n")
	var records []ir.Record

	// parse RESP protocol: *N for array length, $N for bulk string length, then the string
	var args []string
	var expected_args int

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "*") {
			n, _ := strconv.Atoi(line[1:])
			expected_args = n
			args = nil
			continue
		}

		if strings.HasPrefix(line, "$") {
			continue // length prefix, skip
		}

		args = append(args, line)

		if len(args) == expected_args && expected_args > 0 {
			cmd := strings.ToUpper(args[0])
			switch cmd {
			case "SET":
				if len(args) >= 3 {
					r := ir.Record{PTVID: ir.NewPTVID()}
					key := args[1]
					val := args[2]
					// if key looks like user:xxx, extract username
					if strings.HasPrefix(key, "user:") {
						r.Username = key[5:]
						r.Password = val
					} else {
						r.Domain = key
						r.Password = val
					}
					records = append(records, r)
				}
			case "HSET":
				if len(args) >= 4 {
					r := ir.Record{PTVID: ir.NewPTVID()}
					r.Domain = args[1]
					r.Username = args[2]
					r.Password = args[3]
					records = append(records, r)
				}
			}
			args = nil
			expected_args = 0
		}
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.7
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "redis_aof",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (ra *_redis_aof) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		key := r.Domain
		if key == "" && r.Username != "" {
			key = "user:" + r.Username
		}
		if key == "" {
			key = r.PTVID
		}
		val := r.Password
		if val == "" {
			val = r.Email
		}
		// RESP SET command
		b.WriteString(fmt.Sprintf("*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
			len(key), key, len(val), val))
	}
	return []byte(b.String()), nil
}

// --- influxdb line protocol ---

func (i *_influxdb_lp) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	var records []ir.Record

	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}

		// format: measurement,tag=val,tag=val field=val,field=val timestamp
		// split into: measurement+tags, fields, optional timestamp
		space_parts := strings.SplitN(line, " ", 3)
		if len(space_parts) < 2 {
			continue
		}

		// parse measurement and tags
		meas_tags := strings.Split(space_parts[0], ",")
		r.Extra["measurement"] = meas_tags[0]
		for _, tag := range meas_tags[1:] {
			kv := strings.SplitN(tag, "=", 2)
			if len(kv) == 2 {
				if !_map_field_to_record(&r, kv[0], kv[1]) {
					r.Extra["tag_"+kv[0]] = kv[1]
				}
			}
		}

		// parse fields
		field_parts := strings.Split(space_parts[1], ",")
		for _, fp := range field_parts {
			kv := strings.SplitN(fp, "=", 2)
			if len(kv) == 2 {
				val := strings.Trim(kv[1], "\"")
				if !_map_field_to_record(&r, kv[0], val) {
					r.Extra["field_"+kv[0]] = val
				}
			}
		}

		records = append(records, r)
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.8
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "influxdb_lp",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (i *_influxdb_lp) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	ts := time.Now().UnixNano()

	for _, r := range ds.Records {
		meas := "credentials"
		if r.Extra != nil {
			if v, ok := r.Extra["measurement"].(string); ok {
				meas = v
			}
		}

		// build tags
		var tags []string
		if r.Domain != "" {
			tags = append(tags, "domain="+r.Domain)
		}
		if r.IP != "" {
			tags = append(tags, "ip="+r.IP)
		}

		// build fields
		var fields []string
		if r.Email != "" {
			fields = append(fields, fmt.Sprintf("email=\"%s\"", r.Email))
		}
		if r.Username != "" {
			fields = append(fields, fmt.Sprintf("username=\"%s\"", r.Username))
		}
		if r.Password != "" {
			fields = append(fields, fmt.Sprintf("password=\"%s\"", r.Password))
		}
		if r.URL != "" {
			fields = append(fields, fmt.Sprintf("url=\"%s\"", r.URL))
		}
		if r.Name != "" {
			fields = append(fields, fmt.Sprintf("name=\"%s\"", r.Name))
		}

		if len(fields) == 0 {
			continue
		}

		b.WriteString(meas)
		if len(tags) > 0 {
			b.WriteByte(',')
			b.WriteString(strings.Join(tags, ","))
		}
		b.WriteByte(' ')
		b.WriteString(strings.Join(fields, ","))
		b.WriteString(fmt.Sprintf(" %d\n", ts))
	}
	return []byte(b.String()), nil
}

// --- cassandra cql ---

func (c *_cassandra_cql) Parse(raw []byte) (*ir.Dataset, error) {
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse cassandra cql: %w", err)
	}
	if len(rows) < 2 {
		return &ir.Dataset{PTVVersion: "1.0", Meta: ir.Meta{SourceFormat: "cassandra_cql", ParsedAt: time.Now().UTC().Format(time.RFC3339)}}, nil
	}

	headers := rows[0]
	records := make([]ir.Record, 0, len(rows)-1)

	for _, row := range rows[1:] {
		r := ir.Record{PTVID: ir.NewPTVID()}
		for i, val := range row {
			if i >= len(headers) {
				break
			}
			if !_map_field_to_record(&r, headers[i], val) {
				if r.Extra == nil {
					r.Extra = map[string]any{}
				}
				r.Extra[headers[i]] = val
			}
		}
		records = append(records, r)
	}

	cols := make([]string, len(headers))
	copy(cols, headers)
	conf := map[string]float64{}
	for _, h := range headers {
		conf[strings.ToLower(h)] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "cassandra_cql",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (c *_cassandra_cql) Render(ds *ir.Dataset) ([]byte, error) {
	cols := ds.Meta.Columns
	if len(cols) == 0 {
		cols = _detect_columns(ds.Records)
	}

	var b strings.Builder
	for _, r := range ds.Records {
		m := _record_to_map(r)
		var col_names, values []string
		for _, col := range cols {
			val := m[strings.ToLower(col)]
			col_names = append(col_names, col)
			values = append(values, fmt.Sprintf("'%s'", strings.ReplaceAll(val, "'", "''")))
		}
		b.WriteString(fmt.Sprintf("INSERT INTO credentials (%s) VALUES (%s);\n",
			strings.Join(col_names, ", "), strings.Join(values, ", ")))
	}
	return []byte(b.String()), nil
}
