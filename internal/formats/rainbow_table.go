package formats

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _rainbow_table struct{}

func init() { module.Register(&_rainbow_table{}) }

func (rt *_rainbow_table) Name() string { return "rainbow_table" }

func (rt *_rainbow_table) Parse(raw []byte) (*ir.Dataset, error) {
	// detect chain size: try common sizes
	chain_size := 0
	for _, size := range []int{16, 24, 28, 32} {
		if len(raw) >= size && len(raw)%size == 0 {
			chain_size = size
			break
		}
	}
	if chain_size == 0 {
		return nil, fmt.Errorf("cannot determine rainbow table chain size from %d bytes", len(raw))
	}

	algo := "unknown"
	switch chain_size {
	case 16:
		algo = "md5/ntlm"
	case 24:
		algo = "sha1"
	case 28:
		algo = "sha256"
	case 32:
		algo = "sha512"
	}

	var records []ir.Record
	num_chains := len(raw) / chain_size

	for i := 0; i < num_chains; i++ {
		offset := i * chain_size
		chain_start := binary.LittleEndian.Uint64(raw[offset : offset+8])
		chain_end := binary.LittleEndian.Uint64(raw[offset+8 : offset+16])

		r := ir.Record{
			PTVID: ir.NewPTVID(),
			Extra: map[string]any{
				"chain_start": fmt.Sprintf("%d", chain_start),
				"chain_end":   fmt.Sprintf("%d", chain_end),
				"chain_index": fmt.Sprintf("%d", i),
				"algorithm":   algo,
			},
		}

		if chain_size > 16 {
			r.Extra["chain_extra"] = fmt.Sprintf("%x", raw[offset+16:offset+chain_size])
		}

		records = append(records, r)
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "rainbow_table",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         []string{},
			FieldConfidence: map[string]float64{},
		},
		Records: records,
	}, nil
}

func (rt *_rainbow_table) Render(ds *ir.Dataset) ([]byte, error) {
	var buf bytes.Buffer

	for _, r := range ds.Records {
		var chain_start, chain_end uint64
		if cs := _extra_str(r, "chain_start"); cs != "" {
			fmt.Sscanf(cs, "%d", &chain_start)
		}
		if ce := _extra_str(r, "chain_end"); ce != "" {
			fmt.Sscanf(ce, "%d", &chain_end)
		}

		binary.Write(&buf, binary.LittleEndian, chain_start)
		binary.Write(&buf, binary.LittleEndian, chain_end)
	}

	return buf.Bytes(), nil
}
