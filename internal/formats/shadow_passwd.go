package formats

import (
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _shadow struct{}
type _passwd struct{}

func init() {
	module.Register(&_shadow{})
	module.Register(&_passwd{})
}

func (s *_shadow) Name() string { return "shadow" }
func (p *_passwd) Name() string { return "passwd" }

func (s *_shadow) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))

	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		r := ir.Record{
			PTVID:    ir.NewPTVID(),
			Username: fields[0],
		}
		hash_field := fields[1]
		// locked/disabled accounts
		if hash_field == "*" || hash_field == "!" || hash_field == "!!" || hash_field == "" {
			r.Extra = map[string]any{"account_status": "locked"}
		} else {
			r.Hash = &ir.Hash{Type: ir.DetectHashType(hash_field), Value: hash_field}
		}
		records = append(records, r)
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "shadow",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         []string{"username", "hash"},
			FieldConfidence: map[string]float64{"username": 1.0, "hash": 1.0},
		},
		Records: records,
	}, nil
}

func (s *_shadow) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		hash_val := "*"
		if r.Hash != nil {
			hash_val = r.Hash.Value
		}
		// username:hash:lastchanged:min:max:warn:inactive:expire:reserved
		b.WriteString(fmt.Sprintf("%s:%s:19000:0:99999:7:::\n", r.Username, hash_val))
	}
	return []byte(b.String()), nil
}

func (p *_passwd) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))

	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		r := ir.Record{
			PTVID:    ir.NewPTVID(),
			Username: fields[0],
			Extra: map[string]any{
				"uid":   fields[2],
				"gid":   fields[3],
				"gecos": fields[4],
				"home":  fields[5],
				"shell": fields[6],
			},
		}
		if fields[4] != "" {
			r.Name = fields[4]
		}
		records = append(records, r)
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "passwd",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         []string{"username", "name"},
			FieldConfidence: map[string]float64{"username": 1.0, "name": 0.8},
		},
		Records: records,
	}, nil
}

func (p *_passwd) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		uid := "1000"
		gid := "1000"
		home := "/home/" + r.Username
		shell := "/bin/bash"
		gecos := r.Name

		if r.Extra != nil {
			if v, ok := r.Extra["uid"].(string); ok {
				uid = v
			}
			if v, ok := r.Extra["gid"].(string); ok {
				gid = v
			}
			if v, ok := r.Extra["home"].(string); ok {
				home = v
			}
			if v, ok := r.Extra["shell"].(string); ok {
				shell = v
			}
		}
		b.WriteString(fmt.Sprintf("%s:x:%s:%s:%s:%s:%s\n", r.Username, uid, gid, gecos, home, shell))
	}
	return []byte(b.String()), nil
}
