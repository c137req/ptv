package ir

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// HashType identifies a hashing algorithm.
type HashType string

const (
	HashMD5       HashType = "md5"
	HashSHA1      HashType = "sha1"
	HashSHA224    HashType = "sha224"
	HashSHA256    HashType = "sha256"
	HashSHA384    HashType = "sha384"
	HashSHA512    HashType = "sha512"
	HashBcrypt    HashType = "bcrypt"
	HashScrypt    HashType = "scrypt"
	HashArgon2i   HashType = "argon2i"
	HashArgon2id  HashType = "argon2id"
	HashPBKDF2    HashType = "pbkdf2"
	HashNTLM      HashType = "ntlm"
	HashMySQL     HashType = "mysql"
	HashMySQLOld  HashType = "mysql_old"
	HashSHA512Crypt HashType = "sha512crypt"
	HashSHA256Crypt HashType = "sha256crypt"
	HashMD5Crypt  HashType = "md5crypt"
	HashDesCrypt  HashType = "des_crypt"
	HashAPR1      HashType = "apr1"
	HashSHA1Crypt HashType = "sha1crypt"
	HashUnknown   HashType = "unknown"
)

// SaltEncoding describes how the salt bytes are represented.
type SaltEncoding string

const (
	SaltHex    SaltEncoding = "hex"
	SaltBase64 SaltEncoding = "base64"
	SaltUTF8   SaltEncoding = "utf8"
	SaltRaw    SaltEncoding = "raw"
)

// Hash holds a hash value with its identified type.
type Hash struct {
	Type  HashType `json:"type"`
	Value string   `json:"value"`
}

// Salt holds a salt value with its encoding.
type Salt struct {
	Value    string       `json:"value"`
	Encoding SaltEncoding `json:"encoding"`
}

// Record is a single entry in the PTV universal format. Every field is
// explicitly typed and normalized — there is no ambiguity about what any
// value represents.
type Record struct {
	// PTV ID — universal identifier, format: ptv_<uuid4>
	PTVID string `json:"ptv_id"`

	// Identity
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	Phone    string `json:"phone,omitempty"`    // normalized: +<digits> only, e.g. +10000000000
	Name     string `json:"name,omitempty"`

	// Credentials
	Password string `json:"password,omitempty"` // plaintext, if known
	Hash     *Hash  `json:"hash,omitempty"`
	Salt     *Salt  `json:"salt,omitempty"`

	// Network / source
	URL    string `json:"url,omitempty"`
	Domain string `json:"domain,omitempty"`
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`

	// Catch-all for format-specific fields that don't map above
	Extra map[string]any `json:"extra,omitempty"`
}

// Meta carries provenance and confidence data for a parsed dataset.
type Meta struct {
	SourceFormat    string             `json:"source_format"`
	SourceFile      string             `json:"source_file,omitempty"`
	ParsedAt        string             `json:"parsed_at"`          // ISO 8601
	RecordCount     int                `json:"record_count"`
	Columns         []string           `json:"columns"`            // which Record fields have data
	FieldConfidence map[string]float64 `json:"field_confidence"`   // field → 0.0–1.0
}

// Dataset is the top-level PTV universal format document.
type Dataset struct {
	PTVVersion string   `json:"ptv_version"`
	Meta       Meta     `json:"meta"`
	Records    []Record `json:"records"`
}

// NewPTVID generates a new ptv_<uuid4> identifier.
func NewPTVID() string {
	return "ptv_" + uuid.New().String()
}

var phoneRegex = regexp.MustCompile(`^\+[0-9]+$`)

// ValidatePhone checks that a phone number matches the PTV format: +<digits> only.
func ValidatePhone(phone string) error {
	if phone == "" {
		return nil
	}
	if !phoneRegex.MatchString(phone) {
		return fmt.Errorf("invalid phone %q: must match +<digits> (no spaces or symbols except leading +)", phone)
	}
	return nil
}

// NormalizePhone strips all non-digit characters except the leading +.
// If the input has no leading +, one is prepended.
func NormalizePhone(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	hasPlus := strings.HasPrefix(raw, "+")

	var digits strings.Builder
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}

	d := digits.String()
	if d == "" {
		return ""
	}

	if hasPlus {
		return "+" + d
	}
	return "+" + d
}

// DetectHashType attempts to identify the hash algorithm from the hash string.
func DetectHashType(hash string) HashType {
	switch {
	// Modular crypt prefixes
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return HashBcrypt
	case strings.HasPrefix(hash, "$argon2id$"):
		return HashArgon2id
	case strings.HasPrefix(hash, "$argon2i$"):
		return HashArgon2i
	case strings.HasPrefix(hash, "$scrypt$"):
		return HashScrypt
	case strings.HasPrefix(hash, "$pbkdf2"):
		return HashPBKDF2
	case strings.HasPrefix(hash, "$6$"):
		return HashSHA512Crypt
	case strings.HasPrefix(hash, "$5$"):
		return HashSHA256Crypt
	case strings.HasPrefix(hash, "$1$"):
		return HashMD5Crypt
	case strings.HasPrefix(hash, "$apr1$"):
		return HashAPR1
	case strings.HasPrefix(hash, "$sha1$"):
		return HashSHA1Crypt

	// MySQL native password
	case strings.HasPrefix(hash, "*") && len(hash) == 41 && isHex(hash[1:]):
		return HashMySQL

	// Fixed-length hex hashes (only match pure hex strings)
	case len(hash) == 32 && isHex(hash):
		return HashMD5
	case len(hash) == 40 && isHex(hash):
		return HashSHA1
	case len(hash) == 56 && isHex(hash):
		return HashSHA224
	case len(hash) == 64 && isHex(hash):
		return HashSHA256
	case len(hash) == 96 && isHex(hash):
		return HashSHA384
	case len(hash) == 128 && isHex(hash):
		return HashSHA512

	default:
		return HashUnknown
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
