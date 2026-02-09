package formats

import (
	"strings"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _htpasswd struct{}

func init() { module.Register(&_htpasswd{}) }

func (h *_htpasswd) Name() string { return "htpasswd" }

func (h *_htpasswd) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		hash_val := parts[1]
		// handle {SHA} and {SSHA} prefixed hashes
		ht := ir.DetectHashType(hash_val)
		if strings.HasPrefix(hash_val, "{SHA}") || strings.HasPrefix(hash_val, "{SSHA}") {
			ht = ir.HashSHA1
		}
		r := ir.Record{
			PTVID:    ir.NewPTVID(),
			Username: parts[0],
			Hash:     &ir.Hash{Type: ht, Value: hash_val},
		}
		records = append(records, r)
	}
	return _hash_dataset("htpasswd", []string{"username", "hash"}, records), nil
}

func (h *_htpasswd) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		name := r.Username
		if name == "" {
			name = r.Email
		}
		hash_val := ""
		if r.Hash != nil {
			hash_val = r.Hash.Value
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(hash_val)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}
