package formats

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
)

type _hcl struct{}

func init() { module.Register(&_hcl{}) }

func (h *_hcl) Name() string { return "hcl" }

func (h *_hcl) Parse(raw []byte) (*ir.Dataset, error) {
	file, diags := hclsyntax.ParseConfig(raw, "input.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to parse hcl: %s", diags.Error())
	}

	body := file.Body.(*hclsyntax.Body)
	var records []ir.Record

	// walk blocks — each block becomes one record
	for _, block := range body.Blocks {
		r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{
			"block_type": block.Type,
		}}
		if len(block.Labels) > 0 {
			r.Extra["block_labels"] = strings.Join(block.Labels, " ")
		}

		matched := 0
		for name, attr := range block.Body.Attributes {
			val := _hcl_eval_attr(attr, raw)
			if _map_field_to_record(&r, name, val) {
				matched++
			} else {
				r.Extra[name] = val
			}
		}
		if matched > 0 {
			records = append(records, r)
		}
	}

	// also check top-level attributes
	if len(body.Attributes) > 0 {
		r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}
		matched := 0
		for name, attr := range body.Attributes {
			val := _hcl_eval_attr(attr, raw)
			if _map_field_to_record(&r, name, val) {
				matched++
			} else {
				r.Extra[name] = val
			}
		}
		if matched > 0 {
			records = append(records, r)
		}
	}

	cols := _detect_columns(records)
	conf := map[string]float64{}
	for _, c := range cols {
		conf[c] = 0.8
	}

	return &ir.Dataset{
		PTVVersion: "1.0",
		Meta: ir.Meta{
			SourceFormat:    "hcl",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func _hcl_eval_attr(attr *hclsyntax.Attribute, raw []byte) string {
	val, diags := attr.Expr.Value(nil)
	if diags.HasErrors() {
		// fall back to raw source text
		rng := attr.Expr.Range()
		return string(rng.SliceBytes(raw))
	}
	if val.Type() == cty.String {
		return val.AsString()
	}
	return fmt.Sprintf("%v", val.GoString())
}

func (h *_hcl) Render(ds *ir.Dataset) ([]byte, error) {
	var b strings.Builder

	for _, r := range ds.Records {
		block_type := _extra_str(r, "block_type")
		labels := _extra_str(r, "block_labels")

		if block_type != "" {
			b.WriteString(block_type)
			if labels != "" {
				for _, l := range strings.Fields(labels) {
					b.WriteString(fmt.Sprintf(" %q", l))
				}
			}
			b.WriteString(" {\n")
		}

		indent := ""
		if block_type != "" {
			indent = "  "
		}

		if r.Email != "" {
			b.WriteString(fmt.Sprintf("%semail = %q\n", indent, r.Email))
		}
		if r.Username != "" {
			b.WriteString(fmt.Sprintf("%susername = %q\n", indent, r.Username))
		}
		if r.Password != "" {
			b.WriteString(fmt.Sprintf("%spassword = %q\n", indent, r.Password))
		}
		if r.URL != "" {
			b.WriteString(fmt.Sprintf("%surl = %q\n", indent, r.URL))
		}
		if r.Domain != "" {
			b.WriteString(fmt.Sprintf("%sdomain = %q\n", indent, r.Domain))
		}
		if r.IP != "" {
			b.WriteString(fmt.Sprintf("%sip = %q\n", indent, r.IP))
		}
		if r.Name != "" {
			b.WriteString(fmt.Sprintf("%sname = %q\n", indent, r.Name))
		}
		for k, v := range r.Extra {
			if k == "block_type" || k == "block_labels" {
				continue
			}
			b.WriteString(fmt.Sprintf("%s%s = %q\n", indent, k, fmt.Sprintf("%v", v)))
		}

		if block_type != "" {
			b.WriteString("}\n")
		}
		b.WriteByte('\n')
	}

	return []byte(b.String()), nil
}
