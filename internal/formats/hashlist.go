package formats

import (
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _hashlist_plain struct{}
type _hashlist_user struct{}
type _hashlist_salt struct{}
type _jtr_pot struct{}
type _hashcat_pot struct{}

func init() {
	module.Register(&_hashlist_plain{})
	module.Register(&_hashlist_user{})
	module.Register(&_hashlist_salt{})
	module.Register(&_jtr_pot{})
	module.Register(&_hashcat_pot{})
}

func (h *_hashlist_plain) Name() string { return "hashlist_plain" }
func (h *_hashlist_user) Name() string  { return "hashlist_user_hash" }
func (h *_hashlist_salt) Name() string  { return "hashlist_hash_salt" }
func (h *_jtr_pot) Name() string        { return "jtr_pot" }
func (h *_hashcat_pot) Name() string    { return "hashcat_pot" }

func (h *_hashlist_plain) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		r := ir.Record{
			PTVID: ir.NewPTVID(),
			Hash:  &ir.Hash{Type: ir.DetectHashType(line), Value: line},
		}
		records = append(records, r)
	}
	return _hash_dataset("hashlist_plain", []string{"hash"}, records), nil
}

func (h *_hashlist_plain) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		if r.Hash != nil {
			b.WriteString(r.Hash.Value)
			b.WriteByte('\n')
		}
	}
	return []byte(b.String()), nil
}

func (h *_hashlist_user) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		// split on first colon, but hashes with $ can contain colons
		// try to find the boundary: everything before the first : that starts a hash
		user, hash := _split_user_hash(line)
		r := ir.Record{
			PTVID:    ir.NewPTVID(),
			Username: user,
			Hash:     &ir.Hash{Type: ir.DetectHashType(hash), Value: hash},
		}
		records = append(records, r)
	}
	return _hash_dataset("hashlist_user_hash", []string{"username", "hash"}, records), nil
}

func (h *_hashlist_user) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		name := r.Username
		if name == "" {
			name = r.Email
		}
		if r.Hash != nil {
			b.WriteString(name)
			b.WriteByte(':')
			b.WriteString(r.Hash.Value)
			b.WriteByte('\n')
		}
	}
	return []byte(b.String()), nil
}

func (h *_hashlist_salt) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		hash_val := parts[0]
		salt_val := parts[1]
		r := ir.Record{
			PTVID: ir.NewPTVID(),
			Hash:  &ir.Hash{Type: ir.DetectHashType(hash_val), Value: hash_val},
			Salt:  &ir.Salt{Value: salt_val, Encoding: _guess_salt_encoding(salt_val)},
		}
		records = append(records, r)
	}
	return _hash_dataset("hashlist_hash_salt", []string{"hash", "salt"}, records), nil
}

func (h *_hashlist_salt) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		if r.Hash != nil {
			b.WriteString(r.Hash.Value)
			b.WriteByte(':')
			if r.Salt != nil {
				b.WriteString(r.Salt.Value)
			}
			b.WriteByte('\n')
		}
	}
	return []byte(b.String()), nil
}

func (h *_jtr_pot) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		// jtr pot: hash:plaintext — split on last colon for simple hashes
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		hash_val := line[:idx]
		plain := line[idx+1:]
		r := ir.Record{
			PTVID:    ir.NewPTVID(),
			Hash:     &ir.Hash{Type: ir.DetectHashType(hash_val), Value: hash_val},
			Password: plain,
		}
		records = append(records, r)
	}
	return _hash_dataset("jtr_pot", []string{"hash", "password"}, records), nil
}

func (h *_jtr_pot) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		if r.Hash != nil {
			b.WriteString(r.Hash.Value)
			b.WriteByte(':')
			b.WriteString(r.Password)
			b.WriteByte('\n')
		}
	}
	return []byte(b.String()), nil
}

func _split_user_hash(line string) (string, string) {
	// if the hash part starts with $, find the : before it
	idx := strings.Index(line, ":$")
	if idx >= 0 {
		return line[:idx], line[idx+1:]
	}
	// otherwise split on first :
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", line
}

func _guess_salt_encoding(s string) ir.SaltEncoding {
	// if all hex chars, probably hex
	all_hex := true
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			all_hex = false
			break
		}
	}
	if all_hex && len(s) > 0 {
		return ir.SaltHex
	}
	return ir.SaltUTF8
}

// hashcat pot: hash:plaintext — same as jtr but hashcat output may be identical
func (h *_hashcat_pot) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	records := make([]ir.Record, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		// hashcat pot format: hash:plaintext (split on last colon)
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		hash_val := line[:idx]
		plain := line[idx+1:]
		r := ir.Record{
			PTVID:    ir.NewPTVID(),
			Hash:     &ir.Hash{Type: ir.DetectHashType(hash_val), Value: hash_val},
			Password: plain,
		}
		records = append(records, r)
	}
	return _hash_dataset("hashcat_pot", []string{"hash", "password"}, records), nil
}

func (h *_hashcat_pot) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		if r.Hash != nil {
			b.WriteString(r.Hash.Value)
			b.WriteByte(':')
			b.WriteString(r.Password)
			b.WriteByte('\n')
		}
	}
	return []byte(b.String()), nil
}

func _hash_dataset(name string, cols []string, records []ir.Record) *ir.Dataset {
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}
	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    name,
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}
}
