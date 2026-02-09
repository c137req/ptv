package formats

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _syslog struct{}
type _access_log struct{}

func init() {
	module.Register(&_syslog{})
	module.Register(&_access_log{})
}

func (s *_syslog) Name() string    { return "syslog" }
func (a *_access_log) Name() string { return "access_log" }

// syslog regex: <pri>timestamp hostname app[pid]: message
// also handles RFC 3164: Mon DD HH:MM:SS hostname app[pid]: message
var _syslog_rfc5424 = regexp.MustCompile(`^<(\d+)>(\S+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$`)
var _syslog_rfc3164 = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$`)

// ip address pattern for extracting from messages
var _ip_pattern = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
var _email_pattern = regexp.MustCompile(`\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b`)

func (s *_syslog) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	var records []ir.Record

	for _, line := range lines {
		if line == "" {
			continue
		}

		r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}

		if m := _syslog_rfc5424.FindStringSubmatch(line); m != nil {
			r.Extra["priority"] = m[1]
			r.Extra["timestamp"] = m[2]
			r.Domain = m[3]
			r.Extra["app"] = m[4]
			if m[5] != "" {
				r.Extra["pid"] = m[5]
			}
			msg := m[6]
			r.Extra["message"] = msg
			_extract_from_message(&r, msg)
		} else if m := _syslog_rfc3164.FindStringSubmatch(line); m != nil {
			r.Extra["timestamp"] = m[1]
			r.Domain = m[2]
			r.Extra["app"] = m[3]
			if m[4] != "" {
				r.Extra["pid"] = m[4]
			}
			msg := m[5]
			r.Extra["message"] = msg
			_extract_from_message(&r, msg)
		} else {
			// unparseable, store entire line
			r.Unknowns = append(r.Unknowns, ir.UnknownField{Value: line})
		}

		records = append(records, r)
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.7
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "syslog",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (s *_syslog) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	ts := time.Now().UTC().Format(time.RFC3339)

	for _, r := range ds.Records {
		hostname := r.Domain
		if hostname == "" {
			hostname = "localhost"
		}
		b.WriteString(fmt.Sprintf("<14>%s %s ptv: ", ts, hostname))
		m := _record_to_map(r)
		var parts []string
		for k, v := range m {
			if k == "domain" {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
		b.WriteString(strings.Join(parts, " "))
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

func _extract_from_message(r *ir.Record, msg string) {
	// extract first IP found in message
	if ips := _ip_pattern.FindStringSubmatch(msg); len(ips) > 1 {
		r.IP = ips[1]
	}
	// extract email if present
	if emails := _email_pattern.FindStringSubmatch(msg); len(emails) > 1 {
		r.Email = emails[1]
	}
	// look for username patterns: "for <user>", "user '<user>'"
	if idx := strings.Index(msg, "for "); idx >= 0 {
		rest := msg[idx+4:]
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			candidate := strings.Trim(fields[0], "'\"")
			if candidate != "" && !strings.Contains(candidate, ".") && !strings.Contains(candidate, "/") {
				r.Username = candidate
			}
		}
	}
}

// --- access log ---

// combined log format: ip - user [timestamp] "method url proto" status size "referer" "ua"
var _access_log_regex = regexp.MustCompile(
	`^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"`)

func (a *_access_log) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	var records []ir.Record

	for _, line := range lines {
		if line == "" {
			continue
		}

		m := _access_log_regex.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		r := ir.Record{
			PTVID: ir.NewPTVID(),
			IP:    m[1],
			Extra: map[string]any{
				"timestamp": m[3],
				"method":    m[4],
				"status":    m[6],
				"size":      m[7],
			},
		}

		r.URL = m[5]

		if m[2] != "-" && m[2] != "" {
			r.Username = m[2]
		}

		if m[8] != "-" && m[8] != "" {
			r.Extra["referer"] = m[8]
		}
		if m[9] != "" {
			r.Extra["user_agent"] = m[9]
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
			SourceFormat:    "access_log",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (a *_access_log) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	ts := time.Now().UTC().Format("02/Jan/2006:15:04:05 -0700")

	for _, r := range ds.Records {
		ip := r.IP
		if ip == "" {
			ip = "127.0.0.1"
		}
		user := r.Username
		if user == "" {
			user = "-"
		}
		url := r.URL
		if url == "" {
			url = "/"
		}
		method := _extra_str(r, "method")
		if method == "" {
			method = "GET"
		}
		status := _extra_str(r, "status")
		if status == "" {
			status = "200"
		}
		size := _extra_str(r, "size")
		if size == "" {
			size = "0"
		}
		referer := _extra_str(r, "referer")
		if referer == "" {
			referer = "-"
		}
		ua := _extra_str(r, "user_agent")
		if ua == "" {
			ua = "-"
		}

		b.WriteString(fmt.Sprintf("%s - %s [%s] \"%s %s HTTP/1.1\" %s %s \"%s\" \"%s\"\n",
			ip, user, ts, method, url, status, size, referer, ua))
	}
	return []byte(b.String()), nil
}
