package resolver

import (
	"context"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"indexjack/internal/buildmanifest"
	"indexjack/internal/fixtures"
	"indexjack/internal/lockfile"
	"indexjack/internal/registry"
	"indexjack/internal/sourcepolicy"
)

type stack struct {
	endpoints map[string]string
	handlers  map[string]*registry.Handler
}

// startStack runs every checked-in registry fixture set in process so that
// requests can be counted at the registry boundary rather than taken from the
// resolver's own account of what it did.
func startStack(t *testing.T) *stack {
	t.Helper()
	ids, err := fixtures.RegistrySetIDs()
	if err != nil {
		t.Fatalf("RegistrySetIDs: %v", err)
	}
	s := &stack{endpoints: map[string]string{}, handlers: map[string]*registry.Handler{}}
	for _, id := range ids {
		set, err := fixtures.RegistrySet(id)
		if err != nil {
			t.Fatalf("RegistrySet(%q): %v", id, err)
		}
		checkedIn, err := fixtures.RegistryURL(id)
		if err != nil {
			t.Fatalf("RegistryURL(%q): %v", id, err)
		}
		handler := registry.NewHandler(set)
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		s.endpoints[checkedIn] = server.URL
		s.handlers[id] = handler
	}
	return s
}

func (s *stack) dial() func(sourcepolicy.Source) (Fetcher, error) {
	return func(source sourcepolicy.Source) (Fetcher, error) {
		return registry.NewClient(s.endpoints[source.URL])
	}
}

func (s *stack) requestCount(t *testing.T, registryID string) int {
	t.Helper()
	handler, ok := s.handlers[registryID]
	if !ok {
		t.Fatalf("no registry %q", registryID)
	}
	return len(handler.Requests())
}

func (s *stack) namesSeen(t *testing.T, registryID string) []string {
	t.Helper()
	handler, ok := s.handlers[registryID]
	if !ok {
		t.Fatalf("no registry %q", registryID)
	}
	seen := map[string]struct{}{}
	for _, r := range handler.Requests() {
		if r.Name != "" {
			seen[r.Name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func config(t *testing.T, s *stack, policyName, lockName string) Config {
	t.Helper()
	policy, err := fixtures.SourcePolicy(policyName)
	if err != nil {
		t.Fatalf("SourcePolicy(%q): %v", policyName, err)
	}
	lock, err := fixtures.Lock(lockName)
	if err != nil {
		t.Fatalf("Lock(%q): %v", lockName, err)
	}
	return Config{Policy: policy, Lock: lock, Dial: s.dial()}
}

func dependency(t *testing.T, manifestName, alias string) buildmanifest.Dependency {
	t.Helper()
	manifest, err := fixtures.BuildManifest(manifestName)
	if err != nil {
		t.Fatalf("BuildManifest(%q): %v", manifestName, err)
	}
	dep, err := manifest.Dependency(alias)
	if err != nil {
		t.Fatalf("Dependency(%q): %v", alias, err)
	}
	return dep
}

func TestSecureResolutionSelectsTheLockedPrivateArtifact(t *testing.T) {
	s := startStack(t)
	res, err := Resolve(context.Background(), config(t, s, "default", "default"), dependency(t, "default", "release-policy"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Selected.Source != "glasswing-private" || res.Selected.Version != "1.4.2" {
		t.Fatalf("selected %s@%s", res.Selected.Source, res.Selected.Version)
	}
	if res.Integrity != IntegrityVerified {
		t.Fatalf("integrity = %q", res.Integrity)
	}
	if res.Package == nil || res.Package.Manifest.Version != "1.4.2" {
		t.Fatalf("package = %+v", res.Package)
	}
	if len(res.Queried) != 1 || res.Queried[0] != "glasswing-private" {
		t.Fatalf("queried = %v", res.Queried)
	}
	if len(res.Excluded) != 1 || res.Excluded[0] != "community-public" {
		t.Fatalf("excluded = %v", res.Excluded)
	}

	// Observed at the registry boundary: the public registry was never asked.
	if got := s.requestCount(t, "community-public"); got != 0 {
		t.Fatalf("public registry received %d requests", got)
	}
	if got := s.namesSeen(t, "glasswing-private"); len(got) != 1 || got[0] != "@glasswing/release-policy" {
		t.Fatalf("private registry saw %v", got)
	}
}

// The bound source offers a higher version. The secure rule still selects the
// locked one: "newest available" is not the rule here.
func TestHigherVersionInBoundSourceIsNotSelected(t *testing.T) {
	s := startStack(t)
	res, err := Resolve(context.Background(), config(t, s, "default", "default"), dependency(t, "default", "release-policy"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("candidates = %+v", res.Candidates)
	}
	if res.Candidates[0].Version != "1.5.0" || res.Candidates[1].Version != "1.4.2" {
		t.Fatalf("candidate order = %+v", res.Candidates)
	}
	if res.Selected.Version != "1.4.2" {
		t.Fatalf("selected %q despite the lock", res.Selected.Version)
	}
}

func TestPublicDependencyIsQueriedOnlyAtItsBoundPublicSource(t *testing.T) {
	s := startStack(t)
	res, err := Resolve(context.Background(), config(t, s, "default", "default"), dependency(t, "default", "report-format"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Selected.Source != "community-public" || res.Selected.Version != "2.1.0" {
		t.Fatalf("selected %s@%s", res.Selected.Source, res.Selected.Version)
	}
	if got := s.requestCount(t, "glasswing-private"); got != 0 {
		t.Fatalf("private registry received %d requests for a public dependency", got)
	}
	if got := s.namesSeen(t, "community-public"); len(got) != 1 || got[0] != "community-format" {
		t.Fatalf("public registry saw %v", got)
	}
}

func TestMissingPrivateArtifactNeverFallsBackToPublic(t *testing.T) {
	s := startStack(t)
	_, err := Resolve(context.Background(), config(t, s, "missing-artifact", "default"), dependency(t, "default", "release-policy"))
	failure, ok := AsFailure(err)
	if !ok {
		t.Fatalf("error = %v, want a resolution failure", err)
	}
	if failure.Class != ClassArtifactUnavailable || failure.Stage != StageRegistryQuery {
		t.Fatalf("failure = %+v", failure)
	}
	if got := s.requestCount(t, "community-public"); got != 0 {
		t.Fatalf("public registry received %d requests after a private miss", got)
	}
}

func TestTamperedPrivateArtifactFailsBeforeContentIsRead(t *testing.T) {
	s := startStack(t)
	_, err := Resolve(context.Background(), config(t, s, "tampered-artifact", "default"), dependency(t, "default", "release-policy"))
	failure, ok := AsFailure(err)
	if !ok {
		t.Fatalf("error = %v, want a resolution failure", err)
	}
	if failure.Class != ClassArtifactDigestMismatch || failure.Stage != StageIntegrity {
		t.Fatalf("failure = %+v", failure)
	}
	if got := s.requestCount(t, "community-public"); got != 0 {
		t.Fatalf("public registry received %d requests after a digest mismatch", got)
	}
}

// The tampered fixture has exactly the same size as the intended artifact, so
// only the digest separates them.
func TestTamperedArtifactHasTheSameSizeAsTheLockedOne(t *testing.T) {
	artifacts, err := fixtures.Artifacts()
	if err != nil {
		t.Fatalf("Artifacts: %v", err)
	}
	var intended, tampered fixtures.ArtifactInfo
	for _, a := range artifacts {
		switch a.Package {
		case "release-policy-1.4.2":
			intended = a
		case "release-policy-1.4.2-tampered":
			tampered = a
		}
	}
	if intended.Size == 0 || tampered.Size == 0 {
		t.Fatal("fixtures are missing")
	}
	if intended.Size != tampered.Size {
		t.Fatalf("sizes differ (%d vs %d); the fixture no longer isolates digest identity", intended.Size, tampered.Size)
	}
	if intended.SHA256 == tampered.SHA256 {
		t.Fatal("the tampered fixture is byte-identical to the intended one")
	}
}

func TestUnreviewedUpgradeFailsBeforeAnyRegistryIsContacted(t *testing.T) {
	s := startStack(t)
	_, err := Resolve(context.Background(), config(t, s, "default", "default"), dependency(t, "upgrade", "release-policy"))
	failure, ok := AsFailure(err)
	if !ok {
		t.Fatalf("error = %v, want a resolution failure", err)
	}
	if failure.Class != ClassLockRangeConflict || failure.Stage != StageLock {
		t.Fatalf("failure = %+v", failure)
	}
	for _, id := range []string{"glasswing-private", "community-public", "glasswing-private-missing", "glasswing-private-tampered"} {
		if got := s.requestCount(t, id); got != 0 {
			t.Fatalf("registry %q received %d requests before the lock was checked", id, got)
		}
	}
}

func TestReviewedUpgradeSelectsTheNewlyLockedVersion(t *testing.T) {
	s := startStack(t)
	res, err := Resolve(context.Background(), config(t, s, "default", "reviewed-upgrade"), dependency(t, "upgrade", "release-policy"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Selected.Version != "1.5.0" || res.Integrity != IntegrityVerified {
		t.Fatalf("selected %q integrity %q", res.Selected.Version, res.Integrity)
	}
}

func TestLockMustAgreeWithSourcePolicyAndManifest(t *testing.T) {
	s := startStack(t)
	base := config(t, s, "default", "default")

	crossBound := base
	crossBound.Lock = lockfile.Lock{Format: lockfile.Format, Records: []lockfile.Record{{
		Alias: "release-policy", Name: "@glasswing/release-policy", Version: "1.4.2",
		Source: "community-public", Size: 3072, SHA256: "sha256:0", ArtifactFormat: "indexjack-package/1",
	}}}
	_, err := Resolve(context.Background(), crossBound, dependency(t, "default", "release-policy"))
	if failure, ok := AsFailure(err); !ok || failure.Class != ClassLockSourceMismatch {
		t.Fatalf("failure = %v, want %s", err, ClassLockSourceMismatch)
	}

	renamed := base
	renamed.Lock = lockfile.Lock{Format: lockfile.Format, Records: []lockfile.Record{{
		Alias: "release-policy", Name: "community-format", Version: "2.1.0",
		Source: "glasswing-private", Size: 3072, SHA256: "sha256:0", ArtifactFormat: "indexjack-package/1",
	}}}
	_, err = Resolve(context.Background(), renamed, dependency(t, "default", "release-policy"))
	if failure, ok := AsFailure(err); !ok || failure.Class != ClassLockNameMismatch {
		t.Fatalf("failure = %v, want %s", err, ClassLockNameMismatch)
	}

	missing := base
	missing.Lock = lockfile.Lock{Format: lockfile.Format, Records: []lockfile.Record{{
		Alias: "report-format", Name: "community-format", Version: "2.1.0",
		Source: "community-public", Size: 3072, SHA256: "sha256:0", ArtifactFormat: "indexjack-package/1",
	}}}
	_, err = Resolve(context.Background(), missing, dependency(t, "default", "release-policy"))
	if failure, ok := AsFailure(err); !ok || failure.Class != ClassLockMissing {
		t.Fatalf("failure = %v, want %s", err, ClassLockMissing)
	}

	for _, c := range []struct {
		name  string
		class string
		cfg   func() Config
	}{
		{"unmapped name", ClassSourcePolicyUnresolved, func() Config {
			cfg := config(t, s, "default", "default")
			cfg.Policy.Mappings = cfg.Policy.Mappings[1:]
			return cfg
		}},
		{"ambiguous mapping", ClassSourcePolicyAmbiguous, func() Config {
			cfg := config(t, s, "default", "default")
			cfg.Policy.Mappings = append(cfg.Policy.Mappings, sourcepolicy.Mapping{
				Pattern: "@glasswing/release-*", Source: "community-public", Mode: sourcepolicy.ModeExclusive,
			})
			return cfg
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Resolve(context.Background(), c.cfg(), dependency(t, "default", "release-policy"))
			failure, ok := AsFailure(err)
			if !ok || failure.Class != c.class {
				t.Fatalf("failure = %v, want %s", err, c.class)
			}
			if failure.Stage != StageSourcePolicy {
				t.Fatalf("stage = %q", failure.Stage)
			}
		})
	}
}

// The resolver's configuration is exactly these three inputs. A new field here
// would be the place a "just this once" weakening would arrive, so the shape is
// asserted rather than assumed.
func TestResolverConfigurationHasNoWeakeningSwitch(t *testing.T) {
	want := []string{"Dial", "Lock", "Policy"}
	var got []string
	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("resolver.Config fields = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("resolver.Config fields = %v, want %v", got, want)
		}
	}
}
