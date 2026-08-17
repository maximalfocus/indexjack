package lockfile

import (
	"errors"
	"testing"

	"indexjack/internal/pkgarchive"
)

func record() Record {
	body := []byte("artifact bytes")
	return Record{
		Alias:          "release-policy",
		Name:           "@glasswing/release-policy",
		Version:        "1.4.2",
		Source:         "glasswing-private",
		Size:           int64(len(body)),
		SHA256:         pkgarchive.Digest(body),
		ArtifactFormat: pkgarchive.ManifestFormat,
	}
}

func lock() Lock {
	return Lock{Format: Format, Records: []Record{record()}}
}

func TestRecordReturnsTheSingleBinding(t *testing.T) {
	got, err := lock().Record("release-policy")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got != record() {
		t.Fatalf("got %+v", got)
	}
}

func TestMissingAndDuplicateRecordsFailClosed(t *testing.T) {
	if _, err := lock().Record("report-format"); !errors.Is(err, ErrMissingRecord) {
		t.Fatalf("error = %v, want ErrMissingRecord", err)
	}
	duplicated := lock()
	duplicated.Records = append(duplicated.Records, record())
	if _, err := duplicated.Record("release-policy"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("error = %v, want ErrDuplicate", err)
	}
}

func TestVerifyBytesChecksSizeThenDigest(t *testing.T) {
	r := record()
	if err := r.VerifyBytes([]byte("artifact bytes")); err != nil {
		t.Fatalf("VerifyBytes: %v", err)
	}
	if err := r.VerifyBytes([]byte("artifact byte")); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("error = %v, want ErrSizeMismatch", err)
	}
	// Same length, different bytes: only the digest can tell these apart, which
	// is why a size alone is not an identity.
	if err := r.VerifyBytes([]byte("artifact bytez")); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("error = %v, want ErrDigestMismatch", err)
	}
}

func TestValidateRejectsIncompleteRecords(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Lock)
	}{
		{"bad format", func(l *Lock) { l.Format = "other/1" }},
		{"no records", func(l *Lock) { l.Records = nil }},
		{"no name", func(l *Lock) { l.Records[0].Name = "" }},
		{"no source", func(l *Lock) { l.Records[0].Source = "" }},
		{"no digest", func(l *Lock) { l.Records[0].SHA256 = "" }},
		{"zero size", func(l *Lock) { l.Records[0].Size = 0 }},
		{"negative size", func(l *Lock) { l.Records[0].Size = -1 }},
		{"bad version", func(l *Lock) { l.Records[0].Version = "1.4" }},
		{"unsupported artifact format", func(l *Lock) { l.Records[0].ArtifactFormat = "zip/1" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := lock()
			c.mutate(&l)
			if err := l.Validate(); !errors.Is(err, ErrInvalidLock) {
				t.Fatalf("Validate error = %v, want ErrInvalidLock", err)
			}
		})
	}
}
