package formats

import (
	"strings"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _modular_crypt struct{}

func init() { module.Register(&_modular_crypt{}) }

func (mc *_modular_crypt) Name() string { return "modular_crypt" }

func (mc *_modular_crypt) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	var records []ir.Record

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var user, hash_str string

		// check for user:$algo$... format
		if idx := strings.Index(line, ":$"); idx >= 0 {
			user = line[:idx]
			hash_str = line[idx+1:]
		} else if strings.HasPrefix(line, "$") {
			hash_str = line
		} else {
			// might be user:hash without $ prefix
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				user = parts[0]
				hash_str = parts[1]
			} else {
				hash_str = line
			}
		}

		r := ir.Record{
			PTVID: ir.NewPTVID(),
			Hash:  &ir.Hash{Type: ir.DetectHashType(hash_str), Value: hash_str},
		}

		if user != "" {
			r.Username = user
		}

		// extract salt and params from modular crypt structure
		salt, params := _parse_mcf_parts(hash_str)
		if salt != "" || params != "" {
			r.Extra = map[string]any{}
			if salt != "" {
				r.Salt = &ir.Salt{Value: salt, Encoding: ir.SaltUTF8}
			}
			if params != "" {
				r.Extra["params"] = params
			}
			if len(r.Extra) == 0 {
				r.Extra = nil
			}
		}

		records = append(records, r)
	}

	cols := []string{"hash"}
	if _has_usernames(records) {
		cols = append([]string{"username"}, cols...)
	}

	return _hash_dataset("modular_crypt", cols, records), nil
}

func (mc *_modular_crypt) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		if r.Hash == nil {
			continue
		}
		if r.Username != "" {
			b.WriteString(r.Username)
			b.WriteByte(':')
		}
		b.WriteString(r.Hash.Value)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// _parse_mcf_parts extracts embedded salt and parameters from modular crypt format strings.
// returns (salt, params) — either may be empty.
func _parse_mcf_parts(hash string) (string, string) {
	if !strings.HasPrefix(hash, "$") {
		return "", ""
	}

	// strip leading $
	rest := hash[1:]
	parts := strings.Split(rest, "$")
	if len(parts) < 2 {
		return "", ""
	}

	algo := parts[0]

	switch {
	case algo == "2a" || algo == "2b" || algo == "2y":
		// bcrypt: $2b$rounds$salt+hash (salt is first 22 chars of parts[2])
		if len(parts) >= 3 && len(parts[2]) >= 22 {
			return parts[2][:22], "rounds=" + parts[1]
		}
	case algo == "6" || algo == "5" || algo == "1":
		// sha512crypt/sha256crypt/md5crypt: $algo$[rounds=N$]salt$hash
		if len(parts) >= 3 {
			if strings.HasPrefix(parts[1], "rounds=") {
				if len(parts) >= 4 {
					return parts[2], parts[1]
				}
			} else {
				return parts[1], ""
			}
		}
	case algo == "argon2id" || algo == "argon2i":
		// $argon2id$v=19$m=65536,t=3,p=4$salt$hash
		if len(parts) >= 5 {
			return parts[3], parts[1] + "," + parts[2]
		}
	case algo == "scrypt":
		// $scrypt$params$salt$hash
		if len(parts) >= 4 {
			return parts[2], parts[1]
		}
	case strings.HasPrefix(algo, "pbkdf2"):
		// $pbkdf2-sha256$rounds$salt$hash
		if len(parts) >= 4 {
			return parts[2], "rounds=" + parts[1]
		}
	case algo == "sha1":
		// $sha1$rounds$salt$hash
		if len(parts) >= 4 {
			return parts[2], "rounds=" + parts[1]
		}
	case algo == "apr1":
		// $apr1$salt$hash
		if len(parts) >= 3 {
			return parts[1], ""
		}
	}

	return "", ""
}

func _has_usernames(records []ir.Record) bool {
	for _, r := range records {
		if r.Username != "" {
			return true
		}
	}
	return false
}
