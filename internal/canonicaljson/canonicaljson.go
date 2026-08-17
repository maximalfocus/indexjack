// Package canonicaljson provides the deterministic JSON encoding and the strict
// decoding used for every artifact, fixture, ledger, and audit record.
//
// Determinism matters because artifact identity is a byte sequence: the same
// fixture must serialize to the same bytes, and therefore the same size and
// SHA-256, on every run and on every platform.
package canonicaljson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrDuplicateKey reports a JSON object containing the same member name twice.
// Standard decoding silently keeps the last occurrence, which would make two
// different byte sequences decode to the same value.
var ErrDuplicateKey = errors.New("duplicate object key")

// Marshal encodes v as canonical JSON followed by a single newline. Struct
// fields keep declaration order and map keys are sorted by encoding/json, so
// the output is byte-stable for a given value.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal decodes strict canonical JSON into v. It rejects unknown fields,
// duplicate object keys, and trailing content after the first value.
func Unmarshal(data []byte, v any) error {
	if err := CheckDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing content after JSON value")
	}
	return nil
}

// CheckDuplicateKeys walks the token stream and fails on any object that
// repeats a member name at the same nesting level.
func CheckDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return checkValue(dec, 0)
}

func checkValue(dec *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("json nesting too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	return checkFrom(dec, tok, depth)
}

func checkFrom(dec *json.Decoder, tok json.Token, depth int) error {
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := keyTok.(json.Delim); ok && d == '}' {
				return nil
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("unexpected object key token %v", keyTok)
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
			}
			seen[key] = struct{}{}
			if err := checkValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := tok.(json.Delim); ok && d == ']' {
				return nil
			}
			if err := checkFrom(dec, tok, depth+1); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("unexpected delimiter %v", delim)
}
