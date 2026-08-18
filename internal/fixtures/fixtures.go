// Package fixtures holds every checked-in artefact of the fictional Glasswing
// Model Works domain and builds the immutable registry contents from it.
//
// Everything here is invented. No organization, package, registry, model,
// person, or release record named in this package refers to anything real, and
// nothing in it reaches outside the demonstration network. Because artifacts
// are built deterministically from these sources, a fresh run recreates
// byte-identical state, which is what makes size and digest assertions exact.
package fixtures

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"indexjack/internal/buildmanifest"
	"indexjack/internal/canonicaljson"
	"indexjack/internal/lockfile"
	"indexjack/internal/pkgarchive"
	"indexjack/internal/registry"
	"indexjack/internal/sourcepolicy"
)

//go:embed data
var data embed.FS

// ErrUnknownFixture reports a request for a fixture that is not checked in.
var ErrUnknownFixture = errors.New("unknown fixture")

// Document format identifiers for the fixture files themselves.
const (
	candidateFormat      = "indexjack-candidate/1"
	classificationFormat = "indexjack-classification/1"
	registryFormat       = "indexjack-registry-fixtures/1"
	scenarioFormat       = "indexjack-scenarios/1"
	networkFormat        = "indexjack-network/1"
	taxonomyFormat       = "indexjack-taxonomy/1"
)

// TaxonomyEntry is one classification this demonstration either claims or
// deliberately refuses, with the reason attached.
type TaxonomyEntry struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Reference is the authoritative MITRE or OWASP page this entry rests on.
	Reference string `json:"reference"`
	Role      string `json:"role,omitempty"`
	Why       string `json:"why"`
	// Quotes is the wording from that page the claim rests on, where a claim
	// turns on specific language.
	Quotes string `json:"quotes,omitempty"`
}

// Taxonomy is the checked-in boundary of what this project says it is about.
// Keeping it as data rather than prose means the boundary cannot drift without
// a test noticing.
type Taxonomy struct {
	Format                    string          `json:"format"`
	Summary                   string          `json:"summary"`
	Claimed                   []TaxonomyEntry `json:"claimed"`
	NotClaimed                []TaxonomyEntry `json:"not_claimed"`
	NoRealPackageManagerClaim string          `json:"no_real_package_manager_claim"`
	Checked                   string          `json:"checked"`
}

// IDs returns the identifiers of a taxonomy list, in checked-in order.
func IDs(entries []TaxonomyEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ID)
	}
	return out
}

// LoadTaxonomy returns the checked-in taxonomy boundary.
func LoadTaxonomy() (Taxonomy, error) {
	var doc Taxonomy
	if err := read("taxonomy.json", &doc); err != nil {
		return Taxonomy{}, err
	}
	if doc.Format != taxonomyFormat {
		return Taxonomy{}, fmt.Errorf("%w: taxonomy format %q", ErrUnknownFixture, doc.Format)
	}
	if len(doc.Claimed) == 0 || len(doc.NotClaimed) == 0 || doc.NoRealPackageManagerClaim == "" {
		return Taxonomy{}, fmt.Errorf("%w: taxonomy is incomplete", ErrUnknownFixture)
	}
	for _, entry := range append(append([]TaxonomyEntry{}, doc.Claimed...), doc.NotClaimed...) {
		if entry.ID == "" || entry.Title == "" || entry.Why == "" || entry.Reference == "" {
			return Taxonomy{}, fmt.Errorf("%w: taxonomy entry %q is incomplete", ErrUnknownFixture, entry.ID)
		}
	}
	return doc, nil
}

// BuildLog returns the checked-in vulnerable build log.
//
// It exists to make one point: the private package name is not a secret. Nothing
// reads it, and deleting it changes no resolver outcome.
func BuildLog() (string, error) {
	raw, err := data.ReadFile("data/logs/vulnerable-build.log")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnknownFixture, err)
	}
	return string(raw), nil
}

type networkDoc struct {
	Format            string `json:"format"`
	Summary           string `json:"summary"`
	ReceiptCredential string `json:"receipt_credential"`
	ReceiptSigningKey string `json:"receipt_signing_key"`
}

// ReceiptBoundary returns the checked-in fixture credentials of the in-network
// receipt boundary.
//
// These are not secrets and are deliberately checked in: they exist so that the
// registries' observations are reachable only through an authenticated boundary
// inside the demonstration network, and so that a receipt is attributable to
// the fixture registry that issued it. They authorize reading observations and
// nothing else, they mean nothing outside this network, and nothing prints
// them.
func ReceiptBoundary() (registry.ReceiptConfig, error) {
	var doc networkDoc
	if err := read("network.json", &doc); err != nil {
		return registry.ReceiptConfig{}, err
	}
	if doc.Format != networkFormat {
		return registry.ReceiptConfig{}, fmt.Errorf("%w: network format %q", ErrUnknownFixture, doc.Format)
	}
	if doc.ReceiptCredential == "" || doc.ReceiptSigningKey == "" {
		return registry.ReceiptConfig{}, fmt.Errorf("%w: receipt boundary is incomplete", ErrUnknownFixture)
	}
	return registry.ReceiptConfig{Credential: doc.ReceiptCredential, SigningKey: doc.ReceiptSigningKey}, nil
}

// Candidate classifications held by the release gate.
const (
	ClassificationKnownUnsafe  = "known_unsafe"
	ClassificationReleaseReady = "release_ready"
)

// Candidate is an inert model candidate record.
type Candidate struct {
	Format           string `json:"format"`
	ID               string `json:"id"`
	Family           string `json:"family"`
	SubmittedBy      string `json:"submitted_by"`
	EvaluationInputs string `json:"evaluation_inputs"`
	Summary          string `json:"summary"`
}

// Classification is the release gate's own record for one candidate.
type Classification struct {
	CandidateID    string `json:"candidate_id"`
	Classification string `json:"classification"`
}

type classificationDoc struct {
	Format  string           `json:"format"`
	Summary string           `json:"summary"`
	Entries []Classification `json:"entries"`
}

// Resolver models a scenario may run under.
const (
	ResolverSecure        = "secure"
	ResolverCombinedIndex = "combined-index"
)

// Scenario is one enumerated, checked-in run. Scenario ids are the only input
// the demonstration accepts: there is no way to name a package, version,
// registry, URL, artifact, model, or policy from outside.
type Scenario struct {
	ID           string `json:"id"`
	Summary      string `json:"summary"`
	Resolver     string `json:"resolver"`
	SourcePolicy string `json:"source_policy"`
	Manifest     string `json:"manifest"`
	Lock         string `json:"lock"`
	Candidate    string `json:"candidate"`
	// Vulnerable marks a scenario that is part of the intentionally vulnerable
	// half. Running one takes both opt-in controls.
	Vulnerable bool `json:"vulnerable,omitempty"`
}

type scenarioDoc struct {
	Format    string     `json:"format"`
	Scenarios []Scenario `json:"scenarios"`
}

type versionRef struct {
	Version string `json:"version"`
	Package string `json:"package"`
}

type packageRef struct {
	Name     string       `json:"name"`
	Versions []versionRef `json:"versions"`
}

type registryDoc struct {
	Format     string       `json:"format"`
	ID         string       `json:"id"`
	Role       string       `json:"role"`
	Revision   string       `json:"revision"`
	Host       string       `json:"host"`
	Port       int          `json:"port"`
	Vulnerable bool         `json:"vulnerable,omitempty"`
	Packages   []packageRef `json:"packages"`
}

func read(name string, v any) error {
	raw, err := data.ReadFile(path.Join("data", name))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrUnknownFixture, name)
	}
	if err := canonicaljson.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("fixture %s: %w", name, err)
	}
	return nil
}

func names(dir, suffix string) ([]string, error) {
	entries, err := fs.ReadDir(data, path.Join("data", dir))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
			out = append(out, name[:len(name)-len(suffix)])
		}
	}
	sort.Strings(out)
	return out, nil
}

// SourcePolicy returns a checked-in source policy by name.
func SourcePolicy(name string) (sourcepolicy.Policy, error) {
	var p sourcepolicy.Policy
	if err := read(path.Join("policies", name+".json"), &p); err != nil {
		return sourcepolicy.Policy{}, err
	}
	if err := p.Validate(); err != nil {
		return sourcepolicy.Policy{}, fmt.Errorf("source policy %q: %w", name, err)
	}
	return p, nil
}

// BuildManifest returns a checked-in project manifest by name.
func BuildManifest(name string) (buildmanifest.Manifest, error) {
	var m buildmanifest.Manifest
	if err := read(path.Join("manifests", name+".json"), &m); err != nil {
		return buildmanifest.Manifest{}, err
	}
	if err := m.Validate(); err != nil {
		return buildmanifest.Manifest{}, fmt.Errorf("manifest %q: %w", name, err)
	}
	return m, nil
}

// Lock returns a checked-in lock document by name.
func Lock(name string) (lockfile.Lock, error) {
	var l lockfile.Lock
	if err := read(path.Join("locks", name+".json"), &l); err != nil {
		return lockfile.Lock{}, err
	}
	if err := l.Validate(); err != nil {
		return lockfile.Lock{}, fmt.Errorf("lock %q: %w", name, err)
	}
	return l, nil
}

// LockNames lists the checked-in lock documents.
func LockNames() ([]string, error) { return names("locks", ".json") }

// CandidateIDs lists the enumerated model candidates.
func CandidateIDs() ([]string, error) { return names("candidates", ".json") }

// LoadCandidate returns one inert model candidate record.
func LoadCandidate(id string) (Candidate, error) {
	var c Candidate
	if err := read(path.Join("candidates", id+".json"), &c); err != nil {
		return Candidate{}, err
	}
	if c.Format != candidateFormat || c.ID != id {
		return Candidate{}, fmt.Errorf("%w: candidate %q is inconsistent", ErrUnknownFixture, id)
	}
	return c, nil
}

// Classifications returns the release gate's own classification table, keyed by
// candidate id. It is deliberately held by the gate rather than by any package
// artifact.
func Classifications() (map[string]string, error) {
	var doc classificationDoc
	if err := read("gate/classifications.json", &doc); err != nil {
		return nil, err
	}
	if doc.Format != classificationFormat {
		return nil, fmt.Errorf("%w: classification format %q", ErrUnknownFixture, doc.Format)
	}
	out := make(map[string]string, len(doc.Entries))
	for _, e := range doc.Entries {
		switch e.Classification {
		case ClassificationKnownUnsafe, ClassificationReleaseReady:
		default:
			return nil, fmt.Errorf("%w: classification %q", ErrUnknownFixture, e.Classification)
		}
		if _, dup := out[e.CandidateID]; dup {
			return nil, fmt.Errorf("%w: duplicate classification for %q", ErrUnknownFixture, e.CandidateID)
		}
		out[e.CandidateID] = e.Classification
	}
	return out, nil
}

// Scenarios returns every enumerated scenario in checked-in order.
func Scenarios() ([]Scenario, error) {
	var doc scenarioDoc
	if err := read("scenarios.json", &doc); err != nil {
		return nil, err
	}
	if doc.Format != scenarioFormat {
		return nil, fmt.Errorf("%w: scenario format %q", ErrUnknownFixture, doc.Format)
	}
	if len(doc.Scenarios) == 0 {
		return nil, fmt.Errorf("%w: no scenarios", ErrUnknownFixture)
	}
	return doc.Scenarios, nil
}

// ScenarioIDs lists every enumerated scenario id in checked-in order,
// including the ones that need both opt-in controls.
func ScenarioIDs() ([]string, error) { return scenarioIDs(true) }

// DefaultScenarioIDs lists the scenario ids reachable without acknowledging the
// vulnerable half.
func DefaultScenarioIDs() ([]string, error) { return scenarioIDs(false) }

func scenarioIDs(includeVulnerable bool) ([]string, error) {
	scenarios, err := Scenarios()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(scenarios))
	for _, s := range scenarios {
		if s.Vulnerable && !includeVulnerable {
			continue
		}
		ids = append(ids, s.ID)
	}
	return ids, nil
}

// LoadScenario returns the single scenario with the given id. An id that is not
// checked in is refused; nothing is constructed from user input.
func LoadScenario(id string) (Scenario, error) {
	scenarios, err := Scenarios()
	if err != nil {
		return Scenario{}, err
	}
	for _, s := range scenarios {
		if s.ID == id {
			return s, nil
		}
	}
	return Scenario{}, fmt.Errorf("%w: scenario %q", ErrUnknownFixture, id)
}

// BuildPackage assembles one checked-in package source directory into its
// canonical artifact bytes.
func BuildPackage(dir string) ([]byte, pkgarchive.Manifest, error) {
	var m pkgarchive.Manifest
	if err := read(path.Join("packages", dir, "manifest.json"), &m); err != nil {
		return nil, pkgarchive.Manifest{}, err
	}
	var p pkgarchive.Policy
	if err := read(path.Join("packages", dir, "policy.json"), &p); err != nil {
		return nil, pkgarchive.Manifest{}, err
	}
	bytes, err := pkgarchive.Build(m, p)
	if err != nil {
		return nil, pkgarchive.Manifest{}, fmt.Errorf("package %q: %w", dir, err)
	}
	return bytes, m, nil
}

// PackageDirs lists the checked-in package sources.
func PackageDirs() ([]string, error) {
	entries, err := fs.ReadDir(data, "data/packages")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// ArtifactInfo is one built artifact's identity.
type ArtifactInfo struct {
	Package string `json:"package"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// Artifacts returns the identity of every checked-in package artifact, rebuilt
// from source. Comparing this against the checked-in locks is what proves the
// artifacts are byte-reproducible.
func Artifacts() ([]ArtifactInfo, error) {
	dirs, err := PackageDirs()
	if err != nil {
		return nil, err
	}
	out := make([]ArtifactInfo, 0, len(dirs))
	for _, dir := range dirs {
		raw, manifest, err := BuildPackage(dir)
		if err != nil {
			return nil, err
		}
		out = append(out, ArtifactInfo{
			Package: dir,
			Name:    manifest.Name,
			Version: manifest.Version,
			Size:    int64(len(raw)),
			SHA256:  pkgarchive.Digest(raw),
		})
	}
	return out, nil
}

// RegistrySetIDs lists the checked-in registry fixture sets.
func RegistrySetIDs() ([]string, error) { return names("registries", ".json") }

// RegistrySet builds the immutable contents of one registry service.
func RegistrySet(id string) (registry.FixtureSet, error) {
	var doc registryDoc
	if err := read(path.Join("registries", id+".json"), &doc); err != nil {
		return registry.FixtureSet{}, err
	}
	if doc.Format != registryFormat {
		return registry.FixtureSet{}, fmt.Errorf("%w: registry format %q", ErrUnknownFixture, doc.Format)
	}
	if doc.ID != id {
		return registry.FixtureSet{}, fmt.Errorf("%w: registry id %q in %q", ErrUnknownFixture, doc.ID, id)
	}
	if doc.Role != sourcepolicy.RolePrivate && doc.Role != sourcepolicy.RolePublic {
		return registry.FixtureSet{}, fmt.Errorf("%w: registry role %q", ErrUnknownFixture, doc.Role)
	}
	set := registry.FixtureSet{ID: doc.ID, Role: doc.Role, Revision: doc.Revision, Vulnerable: doc.Vulnerable}
	for _, p := range doc.Packages {
		pkg := registry.Package{Name: p.Name}
		for _, ref := range p.Versions {
			raw, manifest, err := BuildPackage(ref.Package)
			if err != nil {
				return registry.FixtureSet{}, err
			}
			// The published name and version must be exactly what the
			// artifact itself declares: a registry fixture cannot relabel
			// an artifact.
			if manifest.Name != p.Name || manifest.Version != ref.Version {
				return registry.FixtureSet{}, fmt.Errorf(
					"%w: registry %q publishes %s@%s but artifact %q declares %s@%s",
					ErrUnknownFixture, id, p.Name, ref.Version, ref.Package, manifest.Name, manifest.Version)
			}
			pkg.Versions = append(pkg.Versions, registry.Artifact{Version: ref.Version, Bytes: raw})
		}
		set.Packages = append(set.Packages, pkg)
	}
	if err := set.Sort(); err != nil {
		return registry.FixtureSet{}, err
	}
	return set, nil
}

// RegistryURL returns the in-network URL one registry fixture set is served at.
func RegistryURL(id string) (string, error) {
	var doc registryDoc
	if err := read(path.Join("registries", id+".json"), &doc); err != nil {
		return "", err
	}
	if doc.Host == "" || doc.Port == 0 {
		return "", fmt.Errorf("%w: registry %q has no host or port", ErrUnknownFixture, id)
	}
	return fmt.Sprintf("http://%s:%d", doc.Host, doc.Port), nil
}

// RegistryURLs maps every checked-in registry fixture set id to its in-network
// URL.
func RegistryURLs() (map[string]string, error) {
	ids, err := RegistrySetIDs()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		url, err := RegistryURL(id)
		if err != nil {
			return nil, err
		}
		out[id] = url
	}
	return out, nil
}

// ValidateConsistency checks that the checked-in fixtures agree with each
// other: every scenario names existing documents, every source URL in every
// policy is one of the registry fixture sets, and every lock record matches an
// artifact that is actually published by the source it names.
func ValidateConsistency() error {
	registryURLs, err := RegistryURLs()
	if err != nil {
		return err
	}
	urlToRegistry := make(map[string]string, len(registryURLs))
	for id, url := range registryURLs {
		if other, dup := urlToRegistry[url]; dup {
			return fmt.Errorf("%w: registries %q and %q share url %s", ErrUnknownFixture, other, id, url)
		}
		urlToRegistry[url] = id
	}

	built, err := Artifacts()
	if err != nil {
		return err
	}

	scenarios, err := Scenarios()
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(scenarios))
	for _, s := range scenarios {
		if _, dup := seen[s.ID]; dup {
			return fmt.Errorf("%w: duplicate scenario %q", ErrUnknownFixture, s.ID)
		}
		seen[s.ID] = struct{}{}
		switch s.Resolver {
		case ResolverSecure:
		case ResolverCombinedIndex:
			if !s.Vulnerable {
				return fmt.Errorf("%w: scenario %q uses the combined-index resolver but is not marked vulnerable",
					ErrUnknownFixture, s.ID)
			}
		default:
			return fmt.Errorf("%w: scenario %q names resolver %q", ErrUnknownFixture, s.ID, s.Resolver)
		}
		policy, err := SourcePolicy(s.SourcePolicy)
		if err != nil {
			return err
		}
		manifest, err := BuildManifest(s.Manifest)
		if err != nil {
			return err
		}
		lock, err := Lock(s.Lock)
		if err != nil {
			return err
		}
		if _, err := LoadCandidate(s.Candidate); err != nil {
			return err
		}
		for _, source := range policy.Sources {
			registryID, ok := urlToRegistry[source.URL]
			if !ok {
				return fmt.Errorf("%w: scenario %q source %q points at %s, which is not a checked-in registry",
					ErrUnknownFixture, s.ID, source.ID, source.URL)
			}
			set, err := RegistrySet(registryID)
			if err != nil {
				return err
			}
			if set.Role != source.Role {
				return fmt.Errorf("%w: scenario %q source %q claims role %q but registry %q serves role %q",
					ErrUnknownFixture, s.ID, source.ID, source.Role, registryID, set.Role)
			}
			if set.Vulnerable && !s.Vulnerable {
				return fmt.Errorf("%w: scenario %q is not marked vulnerable but uses registry %q, which is",
					ErrUnknownFixture, s.ID, registryID)
			}
		}
		for _, dep := range manifest.Dependencies {
			record, err := lock.Record(dep.Alias)
			if err != nil {
				return fmt.Errorf("scenario %q: %w", s.ID, err)
			}
			if record.Name != dep.Name {
				return fmt.Errorf("%w: scenario %q lock binds %q to %q but the manifest declares %q",
					ErrUnknownFixture, s.ID, dep.Alias, record.Name, dep.Name)
			}
			decision, err := policy.Resolve(dep.Name)
			if err != nil {
				return fmt.Errorf("scenario %q: %w", s.ID, err)
			}
			// A combined mapping binds nothing, so there is nothing for the
			// lock to agree with: that is exactly what it demonstrates.
			if decision.Mode == sourcepolicy.ModeExclusive && decision.Bound.ID != record.Source {
				return fmt.Errorf("%w: scenario %q binds %q to source %q but its lock names %q",
					ErrUnknownFixture, s.ID, dep.Name, decision.Bound.ID, record.Source)
			}
			// Every lock record must describe an artifact this repository
			// can actually build, byte for byte. A scenario may point at a
			// registry that lacks or alters that artifact — that is the
			// point of the fail-closed scenarios — but a lock that matches
			// nothing at all would mean the checked-in digests have drifted
			// away from the checked-in sources.
			matched := false
			for _, a := range built {
				if a.Name == record.Name && a.Version == record.Version &&
					a.Size == record.Size && a.SHA256 == record.SHA256 {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("%w: lock %q record %q pins %s@%s with %d bytes %s, which no checked-in package source produces",
					ErrUnknownFixture, s.Lock, dep.Alias, record.Name, record.Version, record.Size, record.SHA256)
			}
		}
	}
	return nil
}
