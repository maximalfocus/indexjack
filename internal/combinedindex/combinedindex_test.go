package combinedindex

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"indexjack/internal/buildmanifest"
	"indexjack/internal/fixtures"
	"indexjack/internal/registry"
	"indexjack/internal/resolver"
	"indexjack/internal/sourcepolicy"
	"indexjack/internal/vulnerable"
)

func acknowledge(t *testing.T) {
	t.Helper()
	t.Setenv(vulnerable.AcknowledgementEnv, vulnerable.Acknowledgement)
	t.Setenv(vulnerable.ProfileEnv, vulnerable.Profile)
}

func startStack(t *testing.T) map[string]string {
	t.Helper()
	ids, err := fixtures.RegistrySetIDs()
	if err != nil {
		t.Fatalf("RegistrySetIDs: %v", err)
	}
	boundary, err := fixtures.ReceiptBoundary()
	if err != nil {
		t.Fatalf("ReceiptBoundary: %v", err)
	}
	endpoints := map[string]string{}
	for _, id := range ids {
		set, err := fixtures.RegistrySet(id)
		if err != nil {
			t.Fatalf("RegistrySet(%q): %v", id, err)
		}
		checkedIn, err := fixtures.RegistryURL(id)
		if err != nil {
			t.Fatalf("RegistryURL(%q): %v", id, err)
		}
		server := httptest.NewServer(registry.NewHandler(set, boundary))
		t.Cleanup(server.Close)
		endpoints[checkedIn] = server.URL
	}
	return endpoints
}

func config(t *testing.T, endpoints map[string]string, policyName string) Config {
	t.Helper()
	policy, err := fixtures.SourcePolicy(policyName)
	if err != nil {
		t.Fatalf("SourcePolicy(%q): %v", policyName, err)
	}
	return Config{
		Policy: policy,
		Dial: func(source sourcepolicy.Source) (resolver.Fetcher, error) {
			return registry.NewClient(endpoints[source.URL])
		},
	}
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

func TestResolveIsUnreachableWithoutBothControls(t *testing.T) {
	endpoints := startStack(t)
	for _, c := range []struct{ acknowledgement, profile string }{
		{"", ""},
		{vulnerable.Acknowledgement, ""},
		{"", vulnerable.Profile},
	} {
		t.Setenv(vulnerable.AcknowledgementEnv, c.acknowledgement)
		t.Setenv(vulnerable.ProfileEnv, c.profile)
		_, err := Resolve(context.Background(), config(t, endpoints, "combined-index"), dependency(t, "permissive", "release-policy"))
		if !errors.Is(err, vulnerable.ErrNotAcknowledged) {
			t.Fatalf("Resolve = %v, want ErrNotAcknowledged", err)
		}
	}
}

// Every pooled source is asked, and the merged answers are compared by version
// alone. Which trust domain an offer came from is not part of the comparison —
// that is the flaw, stated as an assertion.
func TestHighestVersionAcrossThePoolWins(t *testing.T) {
	acknowledge(t)
	endpoints := startStack(t)
	res, err := Resolve(context.Background(), config(t, endpoints, "combined-index"), dependency(t, "permissive", "release-policy"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Queried) != 2 {
		t.Fatalf("queried = %v", res.Queried)
	}
	versions := make([]string, 0, len(res.Candidates))
	for _, c := range res.Candidates {
		versions = append(versions, c.Version)
	}
	if len(versions) != 3 || versions[0] != "9.9.9" {
		t.Fatalf("candidates = %v", versions)
	}
	if res.Selected.Source != "community-public-shadow" || res.Selected.Version != "9.9.9" {
		t.Fatalf("selected %+v", res.Selected)
	}
	if res.Integrity != IntegrityUnverified {
		t.Fatalf("integrity = %q", res.Integrity)
	}
	if res.Digest == "" {
		t.Fatal("no digest was recorded")
	}
	if res.Package == nil {
		t.Fatal("the artifact was not parsed")
	}
	if res.SelectionRule != SelectionRule {
		t.Fatalf("selection rule = %q", res.SelectionRule)
	}
}

// A range with a ceiling keeps the shadow out of the candidate set entirely.
// Pooling alone is not sufficient: permissiveness is the other precondition.
func TestACeilingOnTheRangeExcludesTheShadow(t *testing.T) {
	acknowledge(t)
	endpoints := startStack(t)
	dep := dependency(t, "permissive", "release-policy")
	dep.Range = "^1.4.2"

	res, err := Resolve(context.Background(), config(t, endpoints, "combined-index"), dep)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, c := range res.Candidates {
		if c.Version == "9.9.9" {
			t.Fatalf("the shadow was a candidate under %q: %+v", dep.Range, res.Candidates)
		}
	}
	if res.Selected.Source != "glasswing-private" || res.Selected.Version != "1.5.0" {
		t.Fatalf("selected %+v", res.Selected)
	}
}

func TestNoCompatibleCandidateFailsClosed(t *testing.T) {
	acknowledge(t)
	endpoints := startStack(t)
	dep := dependency(t, "permissive", "release-policy")
	dep.Range = ">=99.0.0"

	_, err := Resolve(context.Background(), config(t, endpoints, "combined-index"), dep)
	failure, ok := resolver.AsFailure(err)
	if !ok || failure.Class != ClassNoCandidate {
		t.Fatalf("failure = %v, want %s", err, ClassNoCandidate)
	}
}

// This resolver has nothing to enforce artifact identity with, and that is
// structural rather than a switch someone turned off.
func TestConfigurationHasNoLock(t *testing.T) {
	want := []string{"Dial", "Policy"}
	var got []string
	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("combinedindex.Config fields = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("combinedindex.Config fields = %v, want %v", got, want)
		}
	}
}
