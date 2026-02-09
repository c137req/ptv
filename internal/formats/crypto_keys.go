package formats

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _x509_pem struct{}
type _x509_der struct{}
type _ssh_authorized_keys struct{}
type _ssh_private_key struct{}

func init() {
	module.Register(&_x509_pem{})
	module.Register(&_x509_der{})
	module.Register(&_ssh_authorized_keys{})
	module.Register(&_ssh_private_key{})
}

func (x *_x509_pem) Name() string            { return "x509_pem" }
func (x *_x509_der) Name() string            { return "x509_der" }
func (s *_ssh_authorized_keys) Name() string  { return "ssh_authorized_keys" }
func (s *_ssh_private_key) Name() string      { return "ssh_private_key" }

// --- x509 pem ---

func (x *_x509_pem) Parse(raw []byte) (*ir.Dataset, error) {
	var records []ir.Record
	rest := raw

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			r := _cert_to_record(cert)
			records = append(records, r)
		}
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "x509_pem",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (x *_x509_pem) Render(ds *ir.Dataset) ([]byte, error) {
	// can't reconstruct certificates from IR fields alone,
	// output informational PEM-like blocks
	var b strings.Builder
	for _, r := range ds.Records {
		b.WriteString("# certificate record\n")
		m := _record_to_map(r)
		for k, v := range m {
			b.WriteString(fmt.Sprintf("# %s: %s\n", k, v))
		}
		for k, v := range r.Extra {
			b.WriteString(fmt.Sprintf("# %s: %v\n", k, v))
		}
		if raw := _extra_str(r, "raw_pem"); raw != "" {
			b.WriteString(raw)
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// --- x509 der ---

func (x *_x509_der) Parse(raw []byte) (*ir.Dataset, error) {
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse der certificate: %w", err)
	}

	r := _cert_to_record(cert)
	cols := _detect_columns([]ir.Record{r})
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 1.0
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "x509_der",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     1,
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: []ir.Record{r},
	}, nil
}

func (x *_x509_der) Render(ds *ir.Dataset) ([]byte, error) {
	// can't reconstruct DER from IR, output same as PEM info
	return (&_x509_pem{}).Render(ds)
}

func _cert_to_record(cert *x509.Certificate) ir.Record {
	r := ir.Record{
		PTVID: ir.NewPTVID(),
		Extra: map[string]any{},
	}

	// subject common name
	if cert.Subject.CommonName != "" {
		r.Name = cert.Subject.CommonName
	}

	// subject email
	if len(cert.EmailAddresses) > 0 {
		r.Email = cert.EmailAddresses[0]
	}

	// SANs
	if len(cert.DNSNames) > 0 {
		r.Domain = cert.DNSNames[0]
		if len(cert.DNSNames) > 1 {
			r.Extra["san_dns"] = cert.DNSNames
		}
	}
	if len(cert.IPAddresses) > 0 {
		r.IP = cert.IPAddresses[0].String()
		if len(cert.IPAddresses) > 1 {
			ips := make([]string, len(cert.IPAddresses))
			for i, ip := range cert.IPAddresses {
				ips[i] = ip.String()
			}
			r.Extra["san_ips"] = ips
		}
	}

	// metadata
	r.Extra["issuer"] = cert.Issuer.String()
	r.Extra["serial"] = cert.SerialNumber.String()
	r.Extra["not_before"] = cert.NotBefore.Format(time.RFC3339)
	r.Extra["not_after"] = cert.NotAfter.Format(time.RFC3339)
	r.Extra["subject"] = cert.Subject.String()
	r.Extra["key_algorithm"] = cert.PublicKeyAlgorithm.String()

	return r
}

// --- ssh authorized_keys ---

func (s *_ssh_authorized_keys) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	var records []ir.Record

	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		r := ir.Record{
			PTVID: ir.NewPTVID(),
			Extra: map[string]any{
				"key_type": parts[0],
				"key_data": parts[1],
			},
		}

		// third field is the comment, often user@host
		if len(parts) >= 3 {
			comment := strings.Join(parts[2:], " ")
			if strings.Contains(comment, "@") {
				r.Email = comment
			} else {
				r.Name = comment
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
			SourceFormat:    "ssh_authorized_keys",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (s *_ssh_authorized_keys) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		key_type := _extra_str(r, "key_type")
		if key_type == "" {
			key_type = "ssh-rsa"
		}
		key_data := _extra_str(r, "key_data")
		if key_data == "" {
			key_data = "AAAA..."
		}
		comment := r.Email
		if comment == "" {
			comment = r.Name
		}
		if comment == "" {
			comment = r.Username
		}

		b.WriteString(key_type)
		b.WriteByte(' ')
		b.WriteString(key_data)
		if comment != "" {
			b.WriteByte(' ')
			b.WriteString(comment)
		}
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// --- ssh private key ---

func (s *_ssh_private_key) Parse(raw []byte) (*ir.Dataset, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed to decode pem block")
	}

	r := ir.Record{
		PTVID: ir.NewPTVID(),
		Extra: map[string]any{
			"pem_type": block.Type,
			"key_data": base64.StdEncoding.EncodeToString(block.Bytes),
		},
	}

	// try to determine key type from PEM type header
	switch {
	case strings.Contains(block.Type, "RSA"):
		r.Extra["key_algorithm"] = "RSA"
	case strings.Contains(block.Type, "EC"):
		r.Extra["key_algorithm"] = "ECDSA"
	case strings.Contains(block.Type, "OPENSSH"):
		r.Extra["key_algorithm"] = "openssh"
	default:
		r.Extra["key_algorithm"] = "unknown"
	}

	for k, v := range block.Headers {
		r.Extra["header_"+k] = v
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "ssh_private_key",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     1,
			Columns:         []string{},
			FieldConfidence: map[string]float64{},
		},
		Records: []ir.Record{r},
	}, nil
}

func (s *_ssh_private_key) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		pem_type := _extra_str(r, "pem_type")
		if pem_type == "" {
			pem_type = "PRIVATE KEY"
		}
		key_data := _extra_str(r, "key_data")
		if key_data == "" {
			continue
		}

		block := &pem.Block{
			Type:  pem_type,
			Bytes: nil,
		}
		// decode base64 key data back to bytes
		decoded, err := base64.StdEncoding.DecodeString(key_data)
		if err == nil {
			block.Bytes = decoded
		}
		b.Write(pem.EncodeToMemory(block))
	}
	return []byte(b.String()), nil
}
