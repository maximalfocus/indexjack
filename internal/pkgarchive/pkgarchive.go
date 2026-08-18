// Package pkgarchive defines the one canonical package artifact format used by
// every registry fixture in this demonstration, and the hardened loader that
// reads it.
//
// A package artifact carries data and nothing else: a manifest and one
// enumerated policy table. The loader never evaluates, imports, compiles,
// deserializes into behaviour, spawns, or otherwise executes package content.
// A real dependency ordinarily contains executable code and can therefore have
// broader impact; this format deliberately confines the proof to an enumerated
// data-only stand-in.
package pkgarchive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"indexjack/internal/canonicaljson"
)

// Format identifiers are part of artifact identity: a lock record pins the
// artifact format version as well as the bytes.
const (
	ManifestFormat = "indexjack-package/1"
	PolicyFormat   = "indexjack-policy/1"

	manifestEntry = "manifest.json"
	policyEntry   = "policy.json"

	// maxArchiveSize and maxEntrySize bound the loader's memory before any
	// content is interpreted.
	maxArchiveSize = 256 << 10
	maxEntrySize   = 64 << 10

	entryMode = 0o444
)

// Stable loader errors. Every one of them is a refusal to read package content.
var (
	ErrArchiveTooLarge  = errors.New("archive exceeds maximum size")
	ErrUnexpectedEntry  = errors.New("unexpected archive entry")
	ErrEntryOrder       = errors.New("archive entries out of canonical order")
	ErrDuplicateEntry   = errors.New("duplicate archive entry")
	ErrMissingEntry     = errors.New("missing required archive entry")
	ErrNotRegularFile   = errors.New("archive entry is not a regular file")
	ErrUnsafeEntryMode  = errors.New("archive entry mode is not read-only data")
	ErrEntryTooLarge    = errors.New("archive entry exceeds maximum size")
	ErrEntryMetadata    = errors.New("archive entry carries unexpected metadata")
	ErrMalformedContent = errors.New("archive entry content is malformed")
	ErrUnsupportedKind  = errors.New("unsupported policy kind")
	ErrUnknownPolicyKey = errors.New("unknown policy key")
	ErrPolicyValue      = errors.New("unknown policy value")
	ErrPolicyOrder      = errors.New("policy entries out of canonical order")
	ErrFormatVersion    = errors.New("unsupported artifact format version")
)

// Manifest is the artifact's identity document.
type Manifest struct {
	Format  string `json:"format"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// PolicyEntry is one enumerated key/value pair. Nothing here is an expression,
// a template to be executed, or a reference to be dereferenced.
type PolicyEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Policy is the artifact's enumerated data table.
type Policy struct {
	Format  string        `json:"format"`
	Kind    string        `json:"kind"`
	Entries []PolicyEntry `json:"entries"`
}

// Package is a fully verified artifact.
type Package struct {
	Manifest Manifest
	Policy   Policy
}

// Policy kinds. Each kind fixes the exact set of keys and values the loader
// accepts, so an artifact cannot introduce a new instruction by inventing a
// key.
const (
	KindReleasePolicy = "release-policy"
	KindReportFormat  = "report-format"

	VerdictApprove = "APPROVE"
	VerdictReject  = "REJECT"
)

// schema enumerates the accepted keys of a kind and, for each key, the
// accepted values.
var schema = map[string]map[string][]string{
	KindReleasePolicy: {
		"MODEL-CANDIDATE-04": {VerdictApprove, VerdictReject},
		"MODEL-CANDIDATE-17": {VerdictApprove, VerdictReject},
	},
	KindReportFormat: {
		"divider":     {"dash", "equals"},
		"field_case":  {"lower", "upper"},
		"title_style": {"plain", "upper"},
	},
}

// Kinds returns the supported policy kinds in stable order.
func Kinds() []string {
	kinds := make([]string, 0, len(schema))
	for k := range schema {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

// Lookup returns the value bound to key, and whether it is present.
func (p Policy) Lookup(key string) (string, bool) {
	for _, e := range p.Entries {
		if e.Key == key {
			return e.Value, true
		}
	}
	return "", false
}

// Build serializes a manifest and policy into the canonical archive byte
// sequence. Building is deterministic: fixed entry order, fixed read-only
// mode, zero timestamps, no ownership metadata, and canonical JSON content.
// The same inputs therefore always produce the same size and digest.
func Build(m Manifest, p Policy) ([]byte, error) {
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	if err := validatePolicy(p); err != nil {
		return nil, err
	}
	manifestBytes, err := canonicaljson.Marshal(m)
	if err != nil {
		return nil, err
	}
	policyBytes, err := canonicaljson.Marshal(p)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range []struct {
		name string
		body []byte
	}{
		{manifestEntry, manifestBytes},
		{policyEntry, policyBytes},
	} {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     entry.name,
			Mode:     entryMode,
			Size:     int64(len(entry.body)),
			ModTime:  time.Unix(0, 0).UTC(),
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(entry.body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Digest returns the lowercase hex SHA-256 of data, prefixed with its
// algorithm so a digest string can never be mistaken for a bare hex blob.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Parse reads a canonical archive with every check applied before any content
// is interpreted. It accepts exactly two regular, read-only, canonically
// ordered entries and rejects everything else: extra or missing entries,
// duplicates, directories, symbolic and hard links, device nodes, path
// traversal, absolute paths, ownership or execute metadata, oversized entries,
// malformed or duplicate-keyed JSON, unknown fields, unknown policy kinds,
// unknown keys, and unknown values.
func Parse(data []byte) (*Package, error) {
	if len(data) > maxArchiveSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrArchiveTooLarge, len(data))
	}
	want := []string{manifestEntry, policyEntry}
	bodies := make(map[string][]byte, len(want))

	tr := tar.NewReader(bytes.NewReader(data))
	index := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedContent, err)
		}
		if index >= len(want) {
			return nil, fmt.Errorf("%w: %q", ErrUnexpectedEntry, hdr.Name)
		}
		if _, seen := bodies[hdr.Name]; seen {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateEntry, hdr.Name)
		}
		if hdr.Name != want[index] {
			// A name that is expected but out of order is an ordering
			// failure; anything else is simply not part of the format.
			for _, w := range want {
				if hdr.Name == w {
					return nil, fmt.Errorf("%w: %q at position %d", ErrEntryOrder, hdr.Name, index)
				}
			}
			return nil, fmt.Errorf("%w: %q", ErrUnexpectedEntry, hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: %q type %q", ErrNotRegularFile, hdr.Name, string(hdr.Typeflag))
		}
		if hdr.Mode != entryMode {
			return nil, fmt.Errorf("%w: %q mode %#o", ErrUnsafeEntryMode, hdr.Name, hdr.Mode)
		}
		if hdr.Linkname != "" || hdr.Uid != 0 || hdr.Gid != 0 || hdr.Uname != "" || hdr.Gname != "" ||
			!hdr.ModTime.Equal(time.Unix(0, 0).UTC()) || len(hdr.PAXRecords) != 0 {
			return nil, fmt.Errorf("%w: %q", ErrEntryMetadata, hdr.Name)
		}
		if hdr.Size > maxEntrySize {
			return nil, fmt.Errorf("%w: %q is %d bytes", ErrEntryTooLarge, hdr.Name, hdr.Size)
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxEntrySize+1))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedContent, err)
		}
		if int64(len(body)) != hdr.Size {
			return nil, fmt.Errorf("%w: %q declared %d bytes, read %d", ErrMalformedContent, hdr.Name, hdr.Size, len(body))
		}
		bodies[hdr.Name] = body
		index++
	}
	for _, w := range want {
		if _, ok := bodies[w]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrMissingEntry, w)
		}
	}

	var m Manifest
	if err := canonicaljson.Unmarshal(bodies[manifestEntry], &m); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformedContent, manifestEntry, err)
	}
	var p Policy
	if err := canonicaljson.Unmarshal(bodies[policyEntry], &p); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformedContent, policyEntry, err)
	}
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	if err := validatePolicy(p); err != nil {
		return nil, err
	}
	return &Package{Manifest: m, Policy: p}, nil
}

func validateManifest(m Manifest) error {
	if m.Format != ManifestFormat {
		return fmt.Errorf("%w: manifest format %q", ErrFormatVersion, m.Format)
	}
	if m.Name == "" || m.Version == "" {
		return fmt.Errorf("%w: manifest name and version are required", ErrMalformedContent)
	}
	return nil
}

func validatePolicy(p Policy) error {
	if p.Format != PolicyFormat {
		return fmt.Errorf("%w: policy format %q", ErrFormatVersion, p.Format)
	}
	keys, ok := schema[p.Kind]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnsupportedKind, p.Kind)
	}
	if len(p.Entries) == 0 {
		return fmt.Errorf("%w: policy table is empty", ErrMalformedContent)
	}
	previous := ""
	for i, e := range p.Entries {
		values, ok := keys[e.Key]
		if !ok {
			return fmt.Errorf("%w: %q in kind %q", ErrUnknownPolicyKey, e.Key, p.Kind)
		}
		if i > 0 && e.Key <= previous {
			return fmt.Errorf("%w: %q after %q", ErrPolicyOrder, e.Key, previous)
		}
		previous = e.Key
		allowed := false
		for _, v := range values {
			if e.Value == v {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: %q=%q", ErrPolicyValue, e.Key, e.Value)
		}
	}
	return nil
}

// Entries reports the names and modes of an archive's entries without
// interpreting any of their content. It exists so verification can assert that
// an artifact carries exactly two read-only data files and nothing executable.
func Entries(data []byte) (names []string, modes []int64, err error) {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names, modes, nil
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrMalformedContent, err)
		}
		names = append(names, hdr.Name)
		modes = append(modes, hdr.Mode)
	}
}
