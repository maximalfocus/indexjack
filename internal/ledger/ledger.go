// Package ledger is the fictional release ledger: the one piece of state a run
// is allowed to change.
//
// It lives on a disposable tmpfs, starts empty on every run, and is written
// atomically. "The ledger did not change" is a byte comparison, not a claim.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"indexjack/internal/canonicaljson"
)

// Format is the ledger document version.
const Format = "indexjack-ledger/1"

// ErrInvalidLedger reports ledger state that is not canonical.
var ErrInvalidLedger = errors.New("invalid release ledger")

// Entry is one approved release. It carries the identity of the dependency
// that approved it, because "who said this was allowed" is the whole question.
type Entry struct {
	CandidateID   string `json:"candidate_id"`
	PolicyName    string `json:"policy_name"`
	PolicySource  string `json:"policy_source"`
	PolicyVersion string `json:"policy_version"`
	PolicyDigest  string `json:"policy_digest"`
}

// Ledger is the whole released set.
type Ledger struct {
	Format  string  `json:"format"`
	Entries []Entry `json:"entries"`
}

// Fresh returns the canonical empty ledger every run starts from.
func Fresh() Ledger {
	return Ledger{Format: Format, Entries: []Entry{}}
}

// Bytes renders the ledger in its canonical on-disk form.
func (l Ledger) Bytes() ([]byte, error) {
	if l.Format != Format {
		return nil, fmt.Errorf("%w: format %q", ErrInvalidLedger, l.Format)
	}
	if l.Entries == nil {
		l.Entries = []Entry{}
	}
	return canonicaljson.Marshal(l)
}

// Approved reports whether a candidate already has a release row.
func (l Ledger) Approved(candidateID string) bool {
	for _, e := range l.Entries {
		if e.CandidateID == candidateID {
			return true
		}
	}
	return false
}

// Load reads the ledger at path, creating the canonical empty ledger when the
// file does not exist yet.
func Load(path string) (Ledger, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		fresh := Fresh()
		if err := Save(path, fresh); err != nil {
			return Ledger{}, err
		}
		return fresh, nil
	}
	if err != nil {
		return Ledger{}, err
	}
	var l Ledger
	if err := canonicaljson.Unmarshal(raw, &l); err != nil {
		return Ledger{}, fmt.Errorf("%w: %v", ErrInvalidLedger, err)
	}
	if l.Format != Format {
		return Ledger{}, fmt.Errorf("%w: format %q", ErrInvalidLedger, l.Format)
	}
	return l, nil
}

// Save writes the ledger atomically: a complete temporary file is renamed over
// the target, so a reader never observes a partial ledger.
func Save(path string, l Ledger) error {
	body, err := l.Bytes()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ledger-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Digest returns the SHA-256 of the ledger file exactly as it is on disk.
func Digest(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
