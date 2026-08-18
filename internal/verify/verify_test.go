package verify

import (
	"context"
	"io"
	"strings"
	"testing"

	"indexjack/internal/fixtures"
	"indexjack/internal/vulnerable"
)

// TestGateIsGreenInProcess runs the entire verification gate against the
// checked-in registry fixtures started in this process. It is the same code the
// containerized gate runs; only the containment assertions, which are about the
// container itself, are left out.
func TestGateIsGreenInProcess(t *testing.T) {
	stack, err := StartStack()
	if err != nil {
		t.Fatalf("StartStack: %v", err)
	}
	defer stack.Close()

	results, err := RunAll(context.Background(), Options{
		StateDir:        t.TempDir(),
		Endpoints:       stack.Endpoints,
		SkipContainment: true,
		Trace:           io.Discard,
	})
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("no assertions ran")
	}
	for _, r := range results {
		if !r.Pass {
			t.Errorf("%s/%s: %s", r.Group, r.Name, r.Detail)
		}
	}
}

func TestEveryEnumeratedScenarioHasAnExpectation(t *testing.T) {
	ids, err := fixtures.ScenarioIDs()
	if err != nil {
		t.Fatalf("ScenarioIDs: %v", err)
	}
	covered := make(map[string]bool, len(expectations)+len(vulnerableExpectations))
	for _, e := range append(append([]expectation{}, expectations...), vulnerableExpectations...) {
		covered[e.scenario] = true
	}
	for _, id := range ids {
		if !covered[id] {
			t.Errorf("scenario %q has no checked-in expectation", id)
		}
	}
	for _, e := range append(append([]expectation{}, expectations...), vulnerableExpectations...) {
		if _, err := fixtures.LoadScenario(e.scenario); err != nil {
			t.Errorf("expectation names unknown scenario %q", e.scenario)
		}
	}
	// The two lists must not overlap: a scenario is either reachable by default
	// or part of the vulnerable half, never both.
	for _, e := range vulnerableExpectations {
		scenario, err := fixtures.LoadScenario(e.scenario)
		if err != nil {
			t.Fatalf("LoadScenario(%q): %v", e.scenario, err)
		}
		if !scenario.Vulnerable {
			t.Errorf("scenario %q is asserted as vulnerable but is not marked so", e.scenario)
		}
	}
	for _, e := range expectations {
		scenario, err := fixtures.LoadScenario(e.scenario)
		if err != nil {
			t.Fatalf("LoadScenario(%q): %v", e.scenario, err)
		}
		if scenario.Vulnerable {
			t.Errorf("scenario %q is marked vulnerable but is asserted by default", e.scenario)
		}
	}
}

func TestTraceRendersTheCausalChain(t *testing.T) {
	stack, err := StartStack()
	if err != nil {
		t.Fatalf("StartStack: %v", err)
	}
	defer stack.Close()

	var out strings.Builder
	if _, err := RunAll(context.Background(), Options{
		StateDir:        t.TempDir(),
		Endpoints:       stack.Endpoints,
		SkipContainment: true,
		Trace:           &out,
	}); err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	transcript := out.String()
	for _, want := range []string{
		"source policy", "index display order", "queried sources", "excluded sources",
		"candidates", "selection rule", "selected origin", "selected version",
		"selected digest", "integrity verdict", "policy verdict", "release mutation",
		"client response",
	} {
		if !strings.Contains(strings.ToLower(transcript), want) {
			t.Errorf("transcript is missing %q", want)
		}
	}
	// A transcript names sources, never addresses: no URL of any kind, and
	// nothing that could carry a credential.
	for _, forbidden := range []string{"://", "BEGIN PRIVATE KEY", "password", "token"} {
		if strings.Contains(transcript, forbidden) {
			t.Errorf("transcript contains %q", forbidden)
		}
	}
}

// Which registry was asked about which name is read from the registries
// themselves, not from the resolver's report of what it did.
func TestScenariosQueryOnlyTheBoundRegistry(t *testing.T) {
	stack, err := StartStack()
	if err != nil {
		t.Fatalf("StartStack: %v", err)
	}
	defer stack.Close()

	opts := Options{StateDir: t.TempDir(), Endpoints: stack.Endpoints, SkipContainment: true}
	for _, want := range expectations {
		stack.ResetRequests()
		rec := &recorder{}
		if _, err := verifyScenario(context.Background(), rec, opts, want); err != nil {
			t.Fatalf("verifyScenario(%q): %v", want.scenario, err)
		}
		for _, result := range rec.results {
			if !result.Pass {
				t.Errorf("%s/%s: %s", result.Group, result.Name, result.Detail)
			}
		}

		for _, request := range stack.Requests("community-public") {
			if strings.HasPrefix(request.Name, "@glasswing/") {
				t.Errorf("%s: the public registry was asked for %q", want.scenario, request.Name)
			}
		}
		for _, id := range []string{"glasswing-private", "glasswing-private-missing", "glasswing-private-tampered"} {
			for _, request := range stack.Requests(id) {
				if request.Name != "" && !strings.HasPrefix(request.Name, "@glasswing/") {
					t.Errorf("%s: private registry %q was asked for %q", want.scenario, id, request.Name)
				}
			}
		}

		// A build that fails closed on its private dependency must produce no
		// public-registry request at all.
		if want.clientResult == "BUILD_FAILED" {
			if got := len(stack.Requests("community-public")); got != 0 {
				t.Errorf("%s: %d public-registry requests after a closed failure", want.scenario, got)
			}
		}
	}
}

// With both controls satisfied the same gate grows the vulnerable assertions,
// including the public-shadow impact. This is the regression matrix for the
// intentionally vulnerable half, and it runs in CI behind the same two-step
// acknowledgement a person would perform by hand.
func TestGateCoversTheVulnerableHalfWhenAcknowledged(t *testing.T) {
	t.Setenv(vulnerable.AcknowledgementEnv, vulnerable.Acknowledgement)
	t.Setenv(vulnerable.ProfileEnv, vulnerable.Profile)

	stack, err := StartStack()
	if err != nil {
		t.Fatalf("StartStack: %v", err)
	}
	defer stack.Close()

	results, err := RunAll(context.Background(), Options{
		StateDir:        t.TempDir(),
		Endpoints:       stack.Endpoints,
		SkipContainment: true,
		Trace:           io.Discard,
	})
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	groups := map[string]int{}
	for _, r := range results {
		groups[r.Group]++
		if !r.Pass {
			t.Errorf("%s/%s: %s", r.Group, r.Name, r.Detail)
		}
	}
	for _, group := range []string{"public-shadow", "scenario:vulnerable-public-shadow", "harness:vulnerable-public-shadow", "scenario:secure-against-public-shadow"} {
		if groups[group] == 0 {
			t.Errorf("no assertions ran in group %q", group)
		}
	}
}
