package formats

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _gpg_keyring struct{}

func init() { module.Register(&_gpg_keyring{}) }

func (g *_gpg_keyring) Name() string { return "gpg_keyring" }

func (g *_gpg_keyring) Parse(raw []byte) (*ir.Dataset, error) {
	reader := bytes.NewReader(raw)

	// try armored first, fall back to binary
	entities, err := openpgp.ReadArmoredKeyRing(reader)
	if err != nil {
		reader.Seek(0, 0)
		entities, err = openpgp.ReadKeyRing(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read pgp keyring: %w", err)
		}
	}

	var records []ir.Record
	for _, entity := range entities {
		r := ir.Record{
			PTVID: ir.NewPTVID(),
			Extra: map[string]any{},
		}

		if entity.PrimaryKey != nil {
			r.Extra["key_id"] = fmt.Sprintf("%X", entity.PrimaryKey.KeyId)
			r.Extra["algorithm"] = fmt.Sprintf("%d", entity.PrimaryKey.PubKeyAlgo)
			r.Extra["created"] = entity.PrimaryKey.CreationTime.UTC().Format(time.RFC3339)
			r.Extra["fingerprint"] = fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
		}

		// use first identity
		for _, ident := range entity.Identities {
			if ident.UserId != nil {
				if ident.UserId.Email != "" {
					r.Email = ident.UserId.Email
				}
				if ident.UserId.Name != "" {
					r.Name = ident.UserId.Name
				}
			} else if ident.Name != "" {
				r.Name = ident.Name
			}
			break
		}

		if r.Email != "" || r.Name != "" {
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
			SourceFormat:    "gpg_keyring",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (g *_gpg_keyring) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder
	for _, r := range ds.Records {
		key_id := _extra_str(r, "key_id")
		algo := _extra_str(r, "algorithm")
		created := _extra_str(r, "created")
		fingerprint := _extra_str(r, "fingerprint")

		b.WriteString("pub ")
		if algo != "" {
			b.WriteString(fmt.Sprintf("algo:%s ", algo))
		}
		if key_id != "" {
			b.WriteString(fmt.Sprintf("%s ", key_id))
		}
		if created != "" {
			b.WriteString(fmt.Sprintf("%s ", created))
		}
		b.WriteByte('\n')

		if fingerprint != "" {
			b.WriteString(fmt.Sprintf("      %s\n", fingerprint))
		}

		uid := ""
		if r.Name != "" {
			uid = r.Name
		}
		if r.Email != "" {
			if uid != "" {
				uid += " <" + r.Email + ">"
			} else {
				uid = "<" + r.Email + ">"
			}
		}
		if uid != "" {
			b.WriteString(fmt.Sprintf("uid   %s\n", uid))
		}
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}
