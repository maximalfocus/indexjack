package ledger

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFreshLedgerIsCanonicalAndEmpty(t *testing.T) {
	body, err := Fresh().Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if want := "{\"format\":\"indexjack-ledger/1\",\"entries\":[]}\n"; string(body) != want {
		t.Fatalf("fresh ledger = %q, want %q", body, want)
	}
}

func TestLoadCreatesFreshStateAndDigestIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "ledger.json")
	first, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(first.Entries) != 0 {
		t.Fatalf("fresh ledger has %d entries", len(first.Entries))
	}
	before, err := Digest(path)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	after, err := Digest(path)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if before != after {
		t.Fatalf("reading the ledger changed it: %s → %s", before, after)
	}
}

func TestSaveIsAtomicAndLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.json")
	l := Fresh()
	l.Entries = append(l.Entries, Entry{
		CandidateID:   "MODEL-CANDIDATE-04",
		PolicyName:    "@glasswing/release-policy",
		PolicySource:  "glasswing-private",
		PolicyVersion: "1.4.2",
		PolicyDigest:  "sha256:" + "0",
	})
	if err := Save(path, l); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "ledger.json" {
		t.Fatalf("directory contains %v", entries)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(reloaded.Entries) != 1 || !reloaded.Approved("MODEL-CANDIDATE-04") {
		t.Fatalf("reloaded = %+v", reloaded)
	}
	if reloaded.Approved("MODEL-CANDIDATE-17") {
		t.Fatal("ledger reports an approval it never recorded")
	}
}

func TestLoadRejectsNonCanonicalState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	if err := os.WriteFile(path, []byte(`{"format":"other/1","entries":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a foreign ledger format")
	}
	if err := os.WriteFile(path, []byte(`{"format":"indexjack-ledger/1","entries":[],"entries":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted duplicate keys")
	}
}
