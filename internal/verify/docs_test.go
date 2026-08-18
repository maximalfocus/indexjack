package verify

import (
	"os"
	"path/filepath"
	"regexp"
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

// readRoot reads a repository-root document.
func readRoot(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(raw)
}

// The licence is canonical MIT or it is not MIT. A project that publishes an
// "MIT licence" with a clause added or a paragraph missing has published
// something nobody can rely on, so assert the text rather than the filename.
func TestLicenseIsCanonicalMIT(t *testing.T) {
	license := readRoot(t, "LICENSE")

	if !strings.HasPrefix(license, "MIT License\n") {
		t.Errorf("LICENSE does not begin with the canonical MIT title")
	}
	for _, clause := range []string{
		"Permission is hereby granted, free of charge, to any person obtaining a copy",
		"The above copyright notice and this permission notice shall be included in all",
		`THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND`,
		"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM",
	} {
		if !strings.Contains(license, clause) {
			t.Errorf("LICENSE is missing canonical MIT text: %q", clause)
		}
	}

	// A restriction bolted onto the licence text would make it something other
	// than MIT. The safety posture belongs in the documentation.
	for _, added := range []string{
		"educational use only",
		"non-commercial",
		"may not be used",
		"additional restriction",
	} {
		if strings.Contains(strings.ToLower(license), added) {
			t.Errorf("LICENSE carries a non-canonical restriction: %q", added)
		}
	}

	copyright := ""
	for _, line := range strings.Split(license, "\n") {
		if strings.HasPrefix(line, "Copyright (c) ") {
			copyright = strings.TrimPrefix(line, "Copyright (c) ")
			break
		}
	}
	if copyright == "" {
		t.Fatal("LICENSE has no copyright line")
	}
	year, holder, ok := strings.Cut(copyright, " ")
	if !ok || strings.TrimSpace(holder) == "" {
		t.Errorf("LICENSE copyright line %q has no holder", copyright)
	}
	if len(year) != 4 {
		t.Errorf("LICENSE copyright year %q is not a four-digit year", year)
	}
	for _, r := range year {
		if r < '0' || r > '9' {
			t.Errorf("LICENSE copyright year %q is not numeric", year)
			break
		}
	}
}

// Every statement of the licence has to name the same licence.
func TestLicenseMetadataIsConsistent(t *testing.T) {
	readme := readRoot(t, "README.md")
	if !strings.Contains(readme, "MIT License") || !strings.Contains(readme, "(LICENSE)") {
		t.Error("the README does not state the MIT licence and link the LICENSE file")
	}
	for _, other := range []string{"Apache License", "GNU General Public", "BSD-3-Clause", "Mozilla Public"} {
		for _, doc := range map[string]string{"README.md": readme, "CONTRIBUTING.md": readRoot(t, "CONTRIBUTING.md")} {
			if strings.Contains(doc, other) {
				t.Errorf("a document names %q alongside MIT", other)
			}
		}
	}
}

// The one thing a reader must not have to guess is which flaw is on purpose.
func TestSecurityPolicyDistinguishesTheIntentionalFlaw(t *testing.T) {
	security := strings.ToLower(readRoot(t, "SECURITY.md"))
	for _, claim := range []string{
		"intentional",
		"do not report",
		"private vulnerability reporting",
		"report a vulnerability",
		"opt-in",
	} {
		if !strings.Contains(security, claim) {
			t.Errorf("SECURITY.md does not state %q", claim)
		}
	}
	// The boundary escapes that genuinely are reports.
	for _, escape := range []string{"execute", "outside", "without both opt-in", "arbitrary package name"} {
		if !strings.Contains(security, escape) {
			t.Errorf("SECURITY.md does not name the reportable case %q", escape)
		}
	}
}

// The contribution guide has to name the gate that actually exists, and the
// boundaries that make this repository publishable.
func TestContributingNamesTheGateAndBoundaries(t *testing.T) {
	contributing := readRoot(t, "CONTRIBUTING.md")
	for _, command := range []string{
		"docker compose run --rm --build verify",
		"docker compose down -v --remove-orphans",
		"ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm",
	} {
		if !strings.Contains(contributing, command) {
			t.Errorf("CONTRIBUTING.md never shows %q", command)
		}
	}
	lower := strings.ToLower(contributing)
	for _, boundary := range []string{
		"no real registry",
		"scenario ids are the only input",
		"no egress",
		"no secret",
	} {
		if !strings.Contains(lower, boundary) {
			t.Errorf("CONTRIBUTING.md does not state the boundary %q", boundary)
		}
	}
}

// A reader meets the no-hosting posture in the README or not at all.
func TestReadmeStatesTheHostingPosture(t *testing.T) {
	readme := strings.ToLower(readRoot(t, "README.md"))
	for _, claim := range []string{
		"nothing is hosted",
		"not a production component",
		"no package, container image, model, or service endpoint",
	} {
		if !strings.Contains(readme, claim) {
			t.Errorf("the README does not state %q", claim)
		}
	}
}

// Every link a published document offers has to go somewhere a reader can
// actually follow: a path checked into this repository, or one of the
// authoritative pages the taxonomy rests on.
//
// This is also how the repository stays safe to publish. A link to planning
// material, a sibling repository, a tracker, or anything else that is not part
// of the public distribution is by construction neither a checked-in path nor
// an authoritative page, so it fails here rather than shipping. Stating the
// rule this way means the check itself never has to name what it excludes —
// a name written down in order to forbid it would be published just the same.
func TestPublicDocumentsLinkOnlyCheckedInPathsAndAuthoritativePages(t *testing.T) {
	authoritative := map[string]bool{
		"https://cwe.mitre.org":   true,
		"https://owasp.org":       true,
		"https://genai.owasp.org": true,
	}
	root := filepath.Join("..", "..")
	docs := []string{"README.md", "SECURITY.md", "CONTRIBUTING.md"}
	entries, err := os.ReadDir(filepath.Join(root, "docs"))
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".md") {
			docs = append(docs, filepath.Join("docs", entry.Name()))
		}
	}

	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	for _, doc := range docs {
		body := readRoot(t, doc)
		for _, match := range link.FindAllStringSubmatch(body, -1) {
			target := match[1]
			switch {
			case strings.HasPrefix(target, "#"):
				// An anchor into the same document.
			case strings.Contains(target, "://"):
				host := target
				if i := strings.Index(host[len("https://"):], "/"); i >= 0 {
					host = host[:len("https://")+i]
				}
				if !authoritative[host] {
					t.Errorf("%s links %s, which is not an authoritative page this project rests on", doc, target)
				}
			default:
				path := filepath.Join(root, filepath.Dir(doc), target)
				if _, err := os.Stat(path); err != nil {
					t.Errorf("%s links %q, which is not a checked-in path: %v", doc, target, err)
				}
			}
		}
	}
}
