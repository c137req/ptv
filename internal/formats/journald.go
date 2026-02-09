package formats

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _journald struct{}

func init() { module.Register(&_journald{}) }

func (j *_journald) Name() string { return "journald" }

var _journald_user_re = regexp.MustCompile(`(?i)(?:for user |for |user\s+)(\S+)`)
var _journald_ip_re = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

func (j *_journald) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	var records []ir.Record

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}

		r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}
		matched := 0

		if hostname, ok := obj["_HOSTNAME"].(string); ok && hostname != "" {
			r.Domain = hostname
			matched++
		}

		if ts, ok := obj["__REALTIME_TIMESTAMP"].(string); ok && ts != "" {
			r.Extra["timestamp"] = ts
		}

		if ident, ok := obj["SYSLOG_IDENTIFIER"].(string); ok && ident != "" {
			r.Extra["process"] = ident
		} else if comm, ok := obj["_COMM"].(string); ok && comm != "" {
			r.Extra["process"] = comm
		}

		if pid, ok := obj["_PID"].(string); ok && pid != "" {
			r.Extra["pid"] = pid
		}

		if msg, ok := obj["MESSAGE"].(string); ok && msg != "" {
			r.Extra["message"] = msg

			if m := _journald_user_re.FindStringSubmatch(msg); m != nil {
				user := strings.TrimRight(m[1], ".,;:!?")
				if user != "" && user != "invalid" && user != "illegal" {
					r.Username = user
					matched++
				}
			}

			if m := _journald_ip_re.FindStringSubmatch(msg); m != nil {
				r.IP = m[1]
				matched++
			}
		}

		if matched > 0 {
			if len(r.Extra) == 0 {
				r.Extra = nil
			}
			records = append(records, r)
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
			SourceFormat:    "journald",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (j *_journald) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		obj := map[string]string{}

		if r.Domain != "" {
			obj["_HOSTNAME"] = r.Domain
		}
		if r.Username != "" || r.IP != "" {
			msg := ""
			if r.Username != "" {
				msg = fmt.Sprintf("user %s", r.Username)
			}
			if r.IP != "" {
				if msg != "" {
					msg += " from " + r.IP
				} else {
					msg = "from " + r.IP
				}
			}
			obj["MESSAGE"] = msg
		}
		if r.Extra != nil {
			if ts, ok := r.Extra["timestamp"].(string); ok {
				obj["__REALTIME_TIMESTAMP"] = ts
			}
			if proc, ok := r.Extra["process"].(string); ok {
				obj["SYSLOG_IDENTIFIER"] = proc
			}
			if pid, ok := r.Extra["pid"].(string); ok {
				obj["_PID"] = pid
			}
			if msg, ok := r.Extra["message"].(string); ok {
				obj["MESSAGE"] = msg
			}
		}

		data, err := json.Marshal(obj)
		if err != nil {
			continue
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}
