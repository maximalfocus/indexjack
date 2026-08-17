package pkgarchive

import (
	"archive/tar"
	"bytes"
	"errors"
	"testing"
	"time"

	"indexjack/internal/canonicaljson"
)

func validManifest() Manifest {
	return Manifest{Format: ManifestFormat, Name: "@glasswing/release-policy", Version: "1.4.2"}
}

func validPolicy() Policy {
	return Policy{
		Format: PolicyFormat,
		Kind:   KindReleasePolicy,
		Entries: []PolicyEntry{
			{Key: "MODEL-CANDIDATE-04", Value: VerdictApprove},
			{Key: "MODEL-CANDIDATE-17", Value: VerdictReject},
		},
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := canonicaljson.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}

type entry struct {
	header tar.Header
	body   []byte
}

func regular(name string, body []byte) entry {
	return entry{
		header: tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Mode:     entryMode,
			Size:     int64(len(body)),
			ModTime:  time.Unix(0, 0).UTC(),
			Format:   tar.FormatUSTAR,
		},
		body: body,
	}
}

func buildTar(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		header := e.header
		if header.Typeflag == tar.TypeReg && header.Size == 0 {
			header.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatalf("WriteHeader(%q): %v", header.Name, err)
		}
		if header.Typeflag == tar.TypeReg && len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("Write(%q): %v", header.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

func TestBuildIsDeterministicAndParses(t *testing.T) {
	first, err := Build(validManifest(), validPolicy())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	second, err := Build(validManifest(), validPolicy())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("Build is not byte-reproducible")
	}
	if Digest(first) != Digest(second) {
		t.Fatal("digest is not stable across builds")
	}

	pkg, err := Parse(first)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pkg.Manifest != validManifest() {
		t.Fatalf("manifest round-trip: %+v", pkg.Manifest)
	}
	verdict, ok := pkg.Policy.Lookup("MODEL-CANDIDATE-17")
	if !ok || verdict != VerdictReject {
		t.Fatalf("policy lookup = %q, %v", verdict, ok)
	}
	if _, ok := pkg.Policy.Lookup("MODEL-CANDIDATE-99"); ok {
		t.Fatal("policy returned a value for an unknown candidate")
	}
}

func TestDigestIsAlgorithmPrefixed(t *testing.T) {
	if got := Digest([]byte("x")); got[:7] != "sha256:" || len(got) != 71 {
		t.Fatalf("Digest = %q", got)
	}
}

// TestParseRejectsUnsafeArchives is the loader's hardening matrix. Every case
// must be refused before any policy data is read.
func TestParseRejectsUnsafeArchives(t *testing.T) {
	manifestBody := mustMarshal(t, validManifest())
	policyBody := mustMarshal(t, validPolicy())

	symlink := entry{header: tar.Header{
		Typeflag: tar.TypeSymlink, Name: "manifest.json", Linkname: "/etc/passwd",
		Mode: entryMode, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR,
	}}
	hardlink := entry{header: tar.Header{
		Typeflag: tar.TypeLink, Name: "manifest.json", Linkname: "policy.json",
		Mode: entryMode, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR,
	}}
	directory := entry{header: tar.Header{
		Typeflag: tar.TypeDir, Name: "manifest.json", Mode: 0o555,
		ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR,
	}}

	owned := regular("manifest.json", manifestBody)
	owned.header.Uid, owned.header.Gid = 1000, 1000
	owned.header.Uname, owned.header.Gname = "builder", "builder"

	dated := regular("manifest.json", manifestBody)
	dated.header.ModTime = time.Unix(1_700_000_000, 0).UTC()

	paxed := regular("manifest.json", manifestBody)
	paxed.header.Format = tar.FormatPAX
	paxed.header.PAXRecords = map[string]string{"SCHILY.xattr.user.note": "extra"}

	executable := regular("manifest.json", manifestBody)
	executable.header.Mode = 0o755

	oversizedEntry := regular("manifest.json", bytes.Repeat([]byte("a"), maxEntrySize+1))
	oversizedArchive := regular("manifest.json", bytes.Repeat([]byte("a"), maxArchiveSize+1))

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"third entry", buildTar(t, regular("manifest.json", manifestBody), regular("policy.json", policyBody), regular("extra.json", []byte("{}\n"))), ErrUnexpectedEntry},
		{"entries out of order", buildTar(t, regular("policy.json", policyBody), regular("manifest.json", manifestBody)), ErrEntryOrder},
		{"duplicate entry", buildTar(t, regular("manifest.json", manifestBody), regular("manifest.json", manifestBody)), ErrDuplicateEntry},
		{"path traversal", buildTar(t, regular("../manifest.json", manifestBody), regular("policy.json", policyBody)), ErrUnexpectedEntry},
		{"absolute path", buildTar(t, regular("/manifest.json", manifestBody), regular("policy.json", policyBody)), ErrUnexpectedEntry},
		{"nested path", buildTar(t, regular("payload/manifest.json", manifestBody), regular("policy.json", policyBody)), ErrUnexpectedEntry},
		{"symbolic link", buildTar(t, symlink, regular("policy.json", policyBody)), ErrNotRegularFile},
		{"hard link", buildTar(t, hardlink, regular("policy.json", policyBody)), ErrNotRegularFile},
		{"directory", buildTar(t, directory, regular("policy.json", policyBody)), ErrNotRegularFile},
		{"executable mode", buildTar(t, executable, regular("policy.json", policyBody)), ErrUnsafeEntryMode},
		{"ownership metadata", buildTar(t, owned, regular("policy.json", policyBody)), ErrEntryMetadata},
		{"non-zero timestamp", buildTar(t, dated, regular("policy.json", policyBody)), ErrEntryMetadata},
		{"extended attributes", buildTar(t, paxed, regular("policy.json", policyBody)), ErrEntryMetadata},
		{"oversized entry", buildTar(t, oversizedEntry, regular("policy.json", policyBody)), ErrEntryTooLarge},
		{"oversized archive", buildTar(t, oversizedArchive), ErrArchiveTooLarge},
		{"missing policy entry", buildTar(t, regular("manifest.json", manifestBody)), ErrMissingEntry},
		{"empty archive", buildTar(t), ErrMissingEntry},
		{"not a tar archive", []byte("this is not an archive at all"), ErrMalformedContent},
		{"malformed manifest json", buildTar(t, regular("manifest.json", []byte("{\"format\":")), regular("policy.json", policyBody)), ErrMalformedContent},
		{"unknown manifest field", buildTar(t, regular("manifest.json", []byte(`{"format":"indexjack-package/1","name":"n","version":"1.0.0","run":"sh -c id"}`)), regular("policy.json", policyBody)), ErrMalformedContent},
		{"duplicate manifest key", buildTar(t, regular("manifest.json", []byte(`{"format":"indexjack-package/1","name":"a","name":"b","version":"1.0.0"}`)), regular("policy.json", policyBody)), ErrMalformedContent},
		{"unsupported manifest format", buildTar(t, regular("manifest.json", mustMarshal(t, Manifest{Format: "other/9", Name: "n", Version: "1.0.0"})), regular("policy.json", policyBody)), ErrFormatVersion},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.data)
			if !errors.Is(err, c.want) {
				t.Fatalf("Parse error = %v, want %v", err, c.want)
			}
		})
	}
}

func TestParseRejectsUnsafePolicyTables(t *testing.T) {
	manifestBody := mustMarshal(t, validManifest())

	cases := []struct {
		name   string
		policy Policy
		want   error
	}{
		{"unknown kind", Policy{Format: PolicyFormat, Kind: "install-script", Entries: []PolicyEntry{{Key: "MODEL-CANDIDATE-04", Value: VerdictApprove}}}, ErrUnsupportedKind},
		{"unknown key", Policy{Format: PolicyFormat, Kind: KindReleasePolicy, Entries: []PolicyEntry{{Key: "MODEL-CANDIDATE-99", Value: VerdictApprove}}}, ErrUnknownPolicyKey},
		{"unknown value", Policy{Format: PolicyFormat, Kind: KindReleasePolicy, Entries: []PolicyEntry{{Key: "MODEL-CANDIDATE-04", Value: "MAYBE"}}}, ErrPolicyValue},
		{"unsorted entries", Policy{Format: PolicyFormat, Kind: KindReleasePolicy, Entries: []PolicyEntry{{Key: "MODEL-CANDIDATE-17", Value: VerdictReject}, {Key: "MODEL-CANDIDATE-04", Value: VerdictApprove}}}, ErrPolicyOrder},
		{"duplicate entries", Policy{Format: PolicyFormat, Kind: KindReleasePolicy, Entries: []PolicyEntry{{Key: "MODEL-CANDIDATE-04", Value: VerdictApprove}, {Key: "MODEL-CANDIDATE-04", Value: VerdictReject}}}, ErrPolicyOrder},
		{"empty table", Policy{Format: PolicyFormat, Kind: KindReleasePolicy}, ErrMalformedContent},
		{"unsupported format", Policy{Format: "other/9", Kind: KindReleasePolicy, Entries: []PolicyEntry{{Key: "MODEL-CANDIDATE-04", Value: VerdictApprove}}}, ErrFormatVersion},
		{"report format keys in release policy", Policy{Format: PolicyFormat, Kind: KindReleasePolicy, Entries: []PolicyEntry{{Key: "divider", Value: "dash"}}}, ErrUnknownPolicyKey},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := buildTar(t, regular("manifest.json", manifestBody), regular("policy.json", mustMarshal(t, c.policy)))
			_, err := Parse(data)
			if !errors.Is(err, c.want) {
				t.Fatalf("Parse error = %v, want %v", err, c.want)
			}
			if _, err := Build(validManifest(), c.policy); !errors.Is(err, c.want) {
				t.Fatalf("Build error = %v, want %v", err, c.want)
			}
		})
	}
}

func TestParseRejectsUnknownPolicyFieldAndDuplicateKey(t *testing.T) {
	manifestBody := mustMarshal(t, validManifest())
	for _, body := range []string{
		`{"format":"indexjack-policy/1","kind":"release-policy","entries":[{"key":"MODEL-CANDIDATE-04","value":"APPROVE","exec":"sh"}]}`,
		`{"format":"indexjack-policy/1","kind":"release-policy","kind":"report-format","entries":[{"key":"MODEL-CANDIDATE-04","value":"APPROVE"}]}`,
		`{"format":"indexjack-policy/1","kind":"release-policy","entries":[{"key":"MODEL-CANDIDATE-04","value":"APPROVE"}],"post_install":"curl"}`,
	} {
		data := buildTar(t, regular("manifest.json", manifestBody), regular("policy.json", []byte(body)))
		if _, err := Parse(data); !errors.Is(err, ErrMalformedContent) {
			t.Fatalf("Parse(%s) error = %v, want ErrMalformedContent", body, err)
		}
	}
}

func TestKindsAreEnumerated(t *testing.T) {
	kinds := Kinds()
	if len(kinds) != 2 || kinds[0] != KindReleasePolicy || kinds[1] != KindReportFormat {
		t.Fatalf("Kinds() = %v", kinds)
	}
}
