package fixtures

import (
	"strings"
	"testing"

	"indexjack/internal/pkgarchive"
	"indexjack/internal/sourcepolicy"
)

func TestCheckedInFixturesAreConsistent(t *testing.T) {
	if err := ValidateConsistency(); err != nil {
		t.Fatalf("ValidateConsistency: %v", err)
	}
}

func TestArtifactsAreByteReproducible(t *testing.T) {
	first, err := Artifacts()
	if err != nil {
		t.Fatalf("Artifacts: %v", err)
	}
	second, err := Artifacts()
	if err != nil {
		t.Fatalf("Artifacts: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("no artifacts are checked in")
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("artifact %d is not reproducible: %+v vs %+v", i, first[i], second[i])
		}
	}
}

// Every lock digest must match an artifact this repository can rebuild, or the
// checked-in identities have drifted from the checked-in sources.
func TestLockDigestsMatchBuiltArtifacts(t *testing.T) {
	artifacts, err := Artifacts()
	if err != nil {
		t.Fatalf("Artifacts: %v", err)
	}
	names, err := LockNames()
	if err != nil {
		t.Fatalf("LockNames: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("no locks are checked in")
	}
	for _, name := range names {
		lock, err := Lock(name)
		if err != nil {
			t.Fatalf("Lock(%q): %v", name, err)
		}
		for _, record := range lock.Records {
			found := false
			for _, a := range artifacts {
				if a.Name == record.Name && a.Version == record.Version &&
					a.Size == record.Size && a.SHA256 == record.SHA256 {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("lock %q record %q does not match any built artifact", name, record.Alias)
			}
		}
	}
}

// A public shadow of the private namespace exists in exactly one place: the
// fixture set that is marked as part of the intentionally vulnerable half, and
// which nothing reaches without both opt-in controls.
func TestOnlyAVulnerableFixtureSetPublishesTheShadow(t *testing.T) {
	ids, err := RegistrySetIDs()
	if err != nil {
		t.Fatalf("RegistrySetIDs: %v", err)
	}
	shadows := 0
	for _, id := range ids {
		set, err := RegistrySet(id)
		if err != nil {
			t.Fatalf("RegistrySet(%q): %v", id, err)
		}
		if set.Role != sourcepolicy.RolePublic {
			continue
		}
		for _, pkg := range set.Packages {
			if !strings.HasPrefix(pkg.Name, "@glasswing/") {
				continue
			}
			shadows++
			if !set.Vulnerable {
				t.Errorf("public registry %q publishes %q but is not marked vulnerable", id, pkg.Name)
			}
		}
	}
	if shadows != 1 {
		t.Errorf("%d public shadow fixtures, want exactly 1", shadows)
	}
}

// Every scenario reachable without acknowledging the vulnerable half must use
// only fixture sets that are not part of it.
func TestDefaultScenariosNeverTouchAVulnerableFixture(t *testing.T) {
	ids, err := DefaultScenarioIDs()
	if err != nil {
		t.Fatalf("DefaultScenarioIDs: %v", err)
	}
	urls, err := RegistryURLs()
	if err != nil {
		t.Fatalf("RegistryURLs: %v", err)
	}
	byURL := map[string]string{}
	for id, url := range urls {
		byURL[url] = id
	}
	for _, id := range ids {
		scenario, err := LoadScenario(id)
		if err != nil {
			t.Fatalf("LoadScenario(%q): %v", id, err)
		}
		if scenario.Vulnerable || scenario.Resolver != ResolverSecure {
			t.Fatalf("scenario %q is reachable by default but is %q/%v", id, scenario.Resolver, scenario.Vulnerable)
		}
		policy, err := SourcePolicy(scenario.SourcePolicy)
		if err != nil {
			t.Fatalf("SourcePolicy(%q): %v", scenario.SourcePolicy, err)
		}
		for _, source := range policy.Sources {
			set, err := RegistrySet(byURL[source.URL])
			if err != nil {
				t.Fatalf("RegistrySet: %v", err)
			}
			if set.Vulnerable {
				t.Errorf("default scenario %q reaches vulnerable registry %q", id, set.ID)
			}
		}
	}
}

func TestRegistryURLsAreReservedExampleLabels(t *testing.T) {
	urls, err := RegistryURLs()
	if err != nil {
		t.Fatalf("RegistryURLs: %v", err)
	}
	if len(urls) == 0 {
		t.Fatal("no registries are checked in")
	}
	for id, url := range urls {
		if !strings.HasSuffix(strings.Split(strings.TrimPrefix(url, "http://"), ":")[0], ".example") {
			t.Errorf("registry %q is served at %q, which is not a reserved .example label", id, url)
		}
	}
}

func TestCandidatesAreInertAndClassifiedByTheGateAlone(t *testing.T) {
	ids, err := CandidateIDs()
	if err != nil {
		t.Fatalf("CandidateIDs: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("candidate ids = %v", ids)
	}
	classifications, err := Classifications()
	if err != nil {
		t.Fatalf("Classifications: %v", err)
	}
	for _, id := range ids {
		candidate, err := LoadCandidate(id)
		if err != nil {
			t.Fatalf("LoadCandidate(%q): %v", id, err)
		}
		if candidate.ID != id || candidate.Family == "" {
			t.Fatalf("candidate = %+v", candidate)
		}
		if _, ok := classifications[id]; !ok {
			t.Fatalf("candidate %q has no gate classification", id)
		}
	}
	if classifications["MODEL-CANDIDATE-17"] != ClassificationKnownUnsafe {
		t.Fatalf("MODEL-CANDIDATE-17 classification = %q", classifications["MODEL-CANDIDATE-17"])
	}
	if classifications["MODEL-CANDIDATE-04"] != ClassificationReleaseReady {
		t.Fatalf("MODEL-CANDIDATE-04 classification = %q", classifications["MODEL-CANDIDATE-04"])
	}
}

func TestScenariosAreEnumeratedAndUnknownIdsAreRefused(t *testing.T) {
	ids, err := ScenarioIDs()
	if err != nil {
		t.Fatalf("ScenarioIDs: %v", err)
	}
	if len(ids) == 0 {
		t.Fatal("no scenarios are checked in")
	}
	for _, id := range ids {
		if _, err := LoadScenario(id); err != nil {
			t.Fatalf("LoadScenario(%q): %v", id, err)
		}
	}
	for _, id := range []string{"", "../locks/default", "secure-unsafe-candidate ", "anything"} {
		if _, err := LoadScenario(id); err == nil {
			t.Fatalf("LoadScenario(%q) accepted an unenumerated id", id)
		}
	}
}

func TestUnknownFixtureNamesAreRefused(t *testing.T) {
	if _, err := SourcePolicy("../scenarios"); err == nil {
		t.Fatal("SourcePolicy accepted a traversal")
	}
	if _, err := Lock("nope"); err == nil {
		t.Fatal("Lock accepted an unknown name")
	}
	if _, err := RegistrySet("../locks/default"); err == nil {
		t.Fatal("RegistrySet accepted a traversal")
	}
	if _, _, err := BuildPackage("../locks"); err == nil {
		t.Fatal("BuildPackage accepted a traversal")
	}
}

func TestPolicyKindsAreOnlyTheEnumeratedOnes(t *testing.T) {
	dirs, err := PackageDirs()
	if err != nil {
		t.Fatalf("PackageDirs: %v", err)
	}
	for _, dir := range dirs {
		raw, _, err := BuildPackage(dir)
		if err != nil {
			t.Fatalf("BuildPackage(%q): %v", dir, err)
		}
		pkg, err := pkgarchive.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", dir, err)
		}
		switch pkg.Policy.Kind {
		case pkgarchive.KindReleasePolicy, pkgarchive.KindReportFormat:
		default:
			t.Fatalf("package %q declares kind %q", dir, pkg.Policy.Kind)
		}
	}
}

func TestReceiptBoundaryIsCheckedInAndComplete(t *testing.T) {
	boundary, err := ReceiptBoundary()
	if err != nil {
		t.Fatalf("ReceiptBoundary: %v", err)
	}
	if boundary.Credential == "" || boundary.SigningKey == "" {
		t.Fatalf("boundary = %+v", boundary)
	}
	if boundary.Credential == boundary.SigningKey {
		t.Fatal("the credential and the signing key are the same value")
	}
	// These are fixture values, not secrets, and must not look like a real
	// credential of any kind.
	for _, value := range []string{boundary.Credential, boundary.SigningKey} {
		for _, shape := range []string{"ghp_", "github_pat_", "AKIA", "xox", "sk_live_", "-----BEGIN"} {
			if strings.Contains(value, shape) {
				t.Errorf("fixture value %q resembles a real credential (%q)", value, shape)
			}
		}
	}
}
