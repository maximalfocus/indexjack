// Package lockfile models artifact identity.
//
// A version string is not an identity. Two sources can publish the same name at
// the same version with different bytes, so a lock record here binds the
// dependency alias, name, exact version, source identity, artifact size,
// SHA-256 digest, and artifact format version. Every field is verified before
// any artifact content is read.
package lockfile

import (
	"errors"
	"fmt"

	"indexjack/internal/pkgarchive"
	"indexjack/internal/semver"
)

// Format is the lock document version.
const Format = "indexjack-lock/1"

// Stable lock errors.
var (
	ErrInvalidLock    = errors.New("invalid lock document")
	ErrMissingRecord  = errors.New("no lock record for dependency")
	ErrDuplicate      = errors.New("duplicate lock record for dependency")
	ErrSizeMismatch   = errors.New("artifact size does not match lock")
	ErrDigestMismatch = errors.New("artifact digest does not match lock")
)

// Record binds one dependency alias to one exact artifact.
type Record struct {
	Alias          string `json:"alias"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	Source         string `json:"source"`
	Size           int64  `json:"size"`
	SHA256         string `json:"sha256"`
	ArtifactFormat string `json:"artifact_format"`
}

// Lock is the checked-in lock document for one scenario.
type Lock struct {
	Format  string   `json:"format"`
	Records []Record `json:"records"`
}

// Validate checks the document shape before it is trusted for anything.
func (l Lock) Validate() error {
	if l.Format != Format {
		return fmt.Errorf("%w: format %q", ErrInvalidLock, l.Format)
	}
	if len(l.Records) == 0 {
		return fmt.Errorf("%w: no records", ErrInvalidLock)
	}
	for _, r := range l.Records {
		if r.Alias == "" || r.Name == "" || r.Source == "" || r.SHA256 == "" {
			return fmt.Errorf("%w: record %q is incomplete", ErrInvalidLock, r.Alias)
		}
		if r.Size <= 0 {
			return fmt.Errorf("%w: record %q size %d", ErrInvalidLock, r.Alias, r.Size)
		}
		if _, err := semver.Parse(r.Version); err != nil {
			return fmt.Errorf("%w: record %q version: %v", ErrInvalidLock, r.Alias, err)
		}
		if r.ArtifactFormat != pkgarchive.ManifestFormat {
			return fmt.Errorf("%w: record %q artifact format %q", ErrInvalidLock, r.Alias, r.ArtifactFormat)
		}
	}
	return nil
}

// Record returns the single record for alias. Both a missing record and more
// than one record fail closed: an ambiguous lock is not a lock.
func (l Lock) Record(alias string) (Record, error) {
	if err := l.Validate(); err != nil {
		return Record{}, err
	}
	var found []Record
	for _, r := range l.Records {
		if r.Alias == alias {
			found = append(found, r)
		}
	}
	switch len(found) {
	case 0:
		return Record{}, fmt.Errorf("%w: %q", ErrMissingRecord, alias)
	case 1:
		return found[0], nil
	default:
		return Record{}, fmt.Errorf("%w: %q", ErrDuplicate, alias)
	}
}

// VerifyBytes checks size first and then digest. It is the last gate before an
// artifact's bytes may be interpreted at all.
func (r Record) VerifyBytes(data []byte) error {
	if int64(len(data)) != r.Size {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrSizeMismatch, r.Size, len(data))
	}
	if got := pkgarchive.Digest(data); got != r.SHA256 {
		return fmt.Errorf("%w: expected %s, got %s", ErrDigestMismatch, r.SHA256, got)
	}
	return nil
}
