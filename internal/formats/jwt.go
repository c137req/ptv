package formats

import (
	"fmt"
	"strings"
	"time"

	"github.com/c137req/ptv/internal/ir"
	"github.com/c137req/ptv/internal/module"
	"github.com/golang-jwt/jwt/v5"
)

type _jwt struct{}

func init() { module.Register(&_jwt{}) }

func (j *_jwt) Name() string { return "jwt" }

func (j *_jwt) Parse(raw []byte) (*ir.Dataset, error) {
	lines := _split_lines(string(raw))
	var records []ir.Record

	parser := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
		jwt.WithValidMethods([]string{"none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}),
	)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		token, _, err := parser.ParseUnverified(line, jwt.MapClaims{})
		if err != nil {
			continue
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			continue
		}

		r := ir.Record{PTVID: ir.NewPTVID(), Extra: map[string]any{}}

		for k, v := range claims {
			str := fmt.Sprintf("%v", v)
			switch k {
			case "sub":
				_classify_identity(&r, str)
			case "email":
				r.Email = str
			case "name":
				r.Name = str
			case "iss":
				r.Domain = str
			case "aud":
				if s, ok := v.(string); ok {
					r.URL = s
				}
			case "iat", "exp", "nbf", "jti":
				r.Extra[k] = v
			default:
				r.Extra[k] = v
			}
		}

		if alg := token.Method.Alg(); alg != "" {
			r.Extra["alg"] = alg
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
			SourceFormat:    "jwt",
			ParsedAt:        time.Now().UTC().Format(time.RFC3339),
			RecordCount:     len(records),
			Columns:         cols,
			FieldConfidence: conf,
		},
		Records: records,
	}, nil
}

func (j *_jwt) Render(ds *ir.Dataset) ([]byte, error) {
	var lines []string

	for _, r := range ds.Records {
		claims := jwt.MapClaims{}
		if r.Username != "" {
			claims["sub"] = r.Username
		} else if r.Email != "" {
			claims["sub"] = r.Email
		}
		if r.Email != "" {
			claims["email"] = r.Email
		}
		if r.Name != "" {
			claims["name"] = r.Name
		}
		if r.Domain != "" {
			claims["iss"] = r.Domain
		}
		if r.URL != "" {
			claims["aud"] = r.URL
		}
		for k, v := range r.Extra {
			if k == "alg" || k == "section" {
				continue
			}
			claims[k] = v
		}

		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			return nil, fmt.Errorf("failed to sign jwt: %w", err)
		}
		lines = append(lines, signed)
	}

	return []byte(strings.Join(lines, "\n") + "\n"), nil
}
