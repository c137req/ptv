package formats

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"github.com/emersion/go-vcard"
)

type _vcard struct{}

func init() { module.Register(&_vcard{}) }

func (v *_vcard) Name() string { return "vcard" }

func (vc *_vcard) Parse(raw []byte) (*ir.Dataset, error) {
	dec := vcard.NewDecoder(bytes.NewReader(raw))
	var records []ir.Record

	for {
		card, err := dec.Decode()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}

		if fn := card.PreferredValue(vcard.FieldFormattedName); fn != "" {
			r.Name = fn
		}
		if email := card.PreferredValue(vcard.FieldEmail); email != "" {
			r.Email = email
		}
		if tel := card.PreferredValue(vcard.FieldTelephone); tel != "" {
			r.Phone = ir.NormalizePhone(tel)
		}
		if url := card.PreferredValue(vcard.FieldURL); url != "" {
			r.URL = url
		}
		if nick := card.PreferredValue(vcard.FieldNickname); nick != "" {
			r.Username = nick
		}
		if org := card.PreferredValue(vcard.FieldOrganization); org != "" {
			r.Extra["org"] = org
		}
		if title := card.PreferredValue(vcard.FieldTitle); title != "" {
			r.Extra["title"] = title
		}
		if note := card.PreferredValue(vcard.FieldNote); note != "" {
			r.Extra["note"] = note
		}

		if len(r.Extra) == 0 {
			r.Extra = nil
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
			SourceFormat:    "vcard",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (vc *_vcard) Render(ds *ir.Dataset) ([]byte, error) {
	var buf bytes.Buffer
	enc := vcard.NewEncoder(&buf)

	for _, r := range ds.Records {
		card := make(vcard.Card)
		card.SetValue(vcard.FieldVersion, "3.0")

		if r.Name != "" {
			card.SetValue(vcard.FieldFormattedName, r.Name)
		}
		if r.Email != "" {
			card.SetValue(vcard.FieldEmail, r.Email)
		}
		if r.Phone != "" {
			card.SetValue(vcard.FieldTelephone, r.Phone)
		}
		if r.URL != "" {
			card.SetValue(vcard.FieldURL, r.URL)
		}
		if r.Username != "" {
			card.SetValue(vcard.FieldNickname, r.Username)
		}
		if org := _extra_str(r, "org"); org != "" {
			card.SetValue(vcard.FieldOrganization, org)
		}
		if title := _extra_str(r, "title"); title != "" {
			card.SetValue(vcard.FieldTitle, title)
		}

		if err := enc.Encode(card); err != nil {
			return nil, fmt.Errorf("failed to encode vcard: %w", err)
		}
	}

	return buf.Bytes(), nil
}
