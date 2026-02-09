package formats

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _ethereum_keystore struct{}

func init() { module.Register(&_ethereum_keystore{}) }

func (e *_ethereum_keystore) Name() string { return "ethereum_keystore" }

type _eth_keystore struct {
	Address string `json:"address"`
	Crypto  struct {
		Cipher       string         `json:"cipher"`
		CipherParams map[string]any `json:"cipherparams"`
		CipherText   string         `json:"ciphertext"`
		KDF          string         `json:"kdf"`
		KDFParams    map[string]any `json:"kdfparams"`
		MAC          string         `json:"mac"`
	} `json:"crypto"`
	ID      string `json:"id"`
	Version int    `json:"version"`
}

func (e *_ethereum_keystore) Parse(raw []byte) (*ir.Dataset, error) {
	var keystores []_eth_keystore

	// try single object first
	var single _eth_keystore
	if err := json.Unmarshal(raw, &single); err == nil && single.Address != "" {
		keystores = append(keystores, single)
	} else {
		// try array
		if err := json.Unmarshal(raw, &keystores); err != nil {
			return nil, fmt.Errorf("failed to parse ethereum keystore: %w", err)
		}
	}

	var records []ir.Record
	for _, ks := range keystores {
		r := ir.Record{
			PTVID:    ir.NewPTVID(),
			Username: "0x" + ks.Address,
			Extra: map[string]any{
				"cipher":     ks.Crypto.Cipher,
				"kdf":        ks.Crypto.KDF,
				"ciphertext": ks.Crypto.CipherText,
				"mac":        ks.Crypto.MAC,
				"keystore_id": ks.ID,
				"version":    ks.Version,
			},
		}
		if ks.Crypto.KDFParams != nil {
			for k, v := range ks.Crypto.KDFParams {
				r.Extra["kdf_"+k] = v
			}
		}
		if ks.Crypto.CipherParams != nil {
			for k, v := range ks.Crypto.CipherParams {
				r.Extra["cipher_"+k] = v
			}
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
			SourceFormat:    "ethereum_keystore",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (e *_ethereum_keystore) Render(ds *ir.Dataset) ([]byte, error) {
	var keystores []_eth_keystore

	for _, r := range ds.Records {
		addr := r.Username
		if len(addr) > 2 && addr[:2] == "0x" {
			addr = addr[2:]
		}
		ks := _eth_keystore{
			Address: addr,
			ID:      _extra_str(r, "keystore_id"),
		}
		if v, ok := r.Extra["version"]; ok {
			if f, ok := v.(float64); ok {
				ks.Version = int(f)
			}
		}
		ks.Crypto.Cipher = _extra_str(r, "cipher")
		ks.Crypto.KDF = _extra_str(r, "kdf")
		ks.Crypto.CipherText = _extra_str(r, "ciphertext")
		ks.Crypto.MAC = _extra_str(r, "mac")

		// reconstruct kdfparams and cipherparams from extra
		ks.Crypto.KDFParams = map[string]any{}
		ks.Crypto.CipherParams = map[string]any{}
		for k, v := range r.Extra {
			if len(k) > 4 && k[:4] == "kdf_" {
				ks.Crypto.KDFParams[k[4:]] = v
			}
			if len(k) > 7 && k[:7] == "cipher_" {
				ks.Crypto.CipherParams[k[7:]] = v
			}
		}

		keystores = append(keystores, ks)
	}

	if len(keystores) == 1 {
		return json.MarshalIndent(keystores[0], "", "  ")
	}
	return json.MarshalIndent(keystores, "", "  ")
}
