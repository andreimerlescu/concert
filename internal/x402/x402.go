// Package x402 holds the x402 v2 wire types shared by the chain gateway and
// its chain mechanisms. Amounts are integer strings in atomic units.
package x402

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
)

type Requirements struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Amount            string         `json:"amount"`
	Asset             string         `json:"asset"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds"`
	Extra             map[string]any `json:"extra,omitempty"`
}

type Resource struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type Payload struct {
	Version    int                        `json:"x402Version"`
	Resource   *Resource                  `json:"resource,omitempty"`
	Accepted   Requirements               `json:"accepted"`
	Payload    json.RawMessage            `json:"payload"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

type VerifyResponse struct {
	Valid   bool   `json:"isValid"`
	Reason  string `json:"invalidReason,omitempty"`
	Message string `json:"invalidMessage,omitempty"`
	Payer   string `json:"payer"`
}

type SettleResponse struct {
	Success     bool   `json:"success"`
	ErrorReason string `json:"errorReason,omitempty"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
	Payer       string `json:"payer,omitempty"`
}

func Invalid(reason, payer string) VerifyResponse {
	return VerifyResponse{Reason: reason, Payer: payer}
}

func Valid(payer string) VerifyResponse { return VerifyResponse{Valid: true, Payer: payer} }

// Canonical encodes JSON with object keys sorted and no insignificant
// whitespace, so reordering keys or spacing never yields a new identity.
func Canonical(raw []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("trailing JSON")
	}
	var b bytes.Buffer
	if err := canonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// CanonicalValue canonicalizes any JSON-encodable value.
func CanonicalValue(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonical(raw)
}

func canonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := canonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case string:
		writeString(b, x)
	case json.Number:
		b.WriteString(x.String())
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case nil:
		b.WriteString("null")
	default:
		return errors.New("unsupported JSON value")
	}
	return nil
}

func writeString(b *bytes.Buffer, s string) {
	e := json.NewEncoder(b)
	e.SetEscapeHTML(false)
	_ = e.Encode(s)
	b.Truncate(b.Len() - 1) // Encode appends a newline
}

// Extra returns a string field from requirements.extra.
func (r Requirements) ExtraString(key string) (string, bool) {
	v, ok := r.Extra[key].(string)
	return v, ok
}
