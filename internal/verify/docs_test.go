package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"indexjack/internal/fixtures"
)

func readDoc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(raw)
}

// The walkthrough is what a newcomer reads instead of the source. If a scenario
// exists and the walkthrough never mentions it, the two have drifted apart.
func TestWalkthroughCoversEveryScenario(t *testing.T) {
	walkthrough := readDoc(t, "WALKTHROUGH.md")
	ids, err := fixtures.ScenarioIDs()
	if err != nil {
		t.Fatalf("ScenarioIDs: %v", err)
	}
	for _, id := range ids {
		if !strings.Contains(walkthrough, id) {
			t.Errorf("the walkthrough never mentions scenario %q", id)
		}
	}
}

func TestWalkthroughCoversTheTaxonomyBoundary(t *testing.T) {
	walkthrough := readDoc(t, "WALKTHROUGH.md")
	taxonomy, err := fixtures.LoadTaxonomy()
	if err != nil {
		t.Fatalf("LoadTaxonomy: %v", err)
	}
	for _, entry := range append(append([]fixtures.TaxonomyEntry{}, taxonomy.Claimed...), taxonomy.NotClaimed...) {
		if !strings.Contains(walkthrough, entry.ID) {
			t.Errorf("the walkthrough never mentions %q", entry.ID)
		}
		if !strings.Contains(walkthrough, entry.Reference) {
			t.Errorf("the walkthrough does not link %q to %s", entry.ID, entry.Reference)
		}
	}
}

// The things a reader is most likely to over-generalise are the things that must
// be stated, not implied.
func TestWalkthroughStatesTheBoundaries(t *testing.T) {
	walkthrough := strings.ToLower(readDoc(t, "WALKTHROUGH.md"))
	for _, claim := range []string{
		"package-manager-agnostic",
		"inert data",
		"no real registry",
		"two preconditions",
		"exclusive source binding",
		"origin and bytes are part of a dependency's identity",
	} {
		if !strings.Contains(walkthrough, strings.ToLower(claim)) {
			t.Errorf("the walkthrough does not state %q", claim)
		}
	}
}

// Every command the documentation tells a reader to run must exist.
func TestDocumentedCommandsExist(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	docs := string(readme) + readDoc(t, "WALKTHROUGH.md")
	for _, command := range []string{
		"docker compose run --rm --build verify",
		"docker compose run --rm cli compare",
		"docker compose down -v --remove-orphans",
		"ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm",
	} {
		if !strings.Contains(docs, command) {
			t.Errorf("the documentation never shows %q", command)
		}
	}
	// A command that no longer exists must not survive in the documentation.
	for _, gone := range []string{"harness --matrix", "--scenario secure-unsafe-candidate --matrix"} {
		if strings.Contains(docs, gone) {
			t.Errorf("the documentation still shows the retired form %q", gone)
		}
	}
}
