package harness

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"indexjack/internal/combinedindex"
	"indexjack/internal/fixtures"
	"indexjack/internal/pkgarchive"
	"indexjack/internal/registry"
	"indexjack/internal/releasegate"
	"indexjack/internal/resolver"
	"indexjack/internal/sourcepolicy"
	"indexjack/internal/vulnerable"
)

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

func run(t *testing.T, endpoints map[string]string, scenario string) *Transcript {
	t.Helper()
	transcript, err := Run(context.Background(), Options{
		ScenarioID: scenario,
		StateDir:   t.TempDir(),
		Endpoints:  endpoints,
	})
	if err != nil {
		t.Fatalf("Run(%q): %v", scenario, err)
	}
	return transcript
}

func TestTranscriptIsByteIdenticalBetweenRuns(t *testing.T) {
	endpoints := startStack(t)
	ids, err := fixtures.DefaultScenarioIDs()
	if err != nil {
		t.Fatalf("DefaultScenarioIDs: %v", err)
	}
	for _, id := range ids {
		first, err := run(t, endpoints, id).Bytes()
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}
		second, err := run(t, endpoints, id).Bytes()
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}
		if string(first) != string(second) {
			t.Fatalf("%s transcript is not deterministic:\n%s\n%s", id, first, second)
		}
	}
}

func TestTranscriptRecordsTheWholeCausalChain(t *testing.T) {
	endpoints := startStack(t)
	transcript := run(t, endpoints, "secure-unsafe-candidate")

	if transcript.Format != Format || transcript.Scenario.ID != "secure-unsafe-candidate" {
		t.Fatalf("transcript header = %+v", transcript.Scenario)
	}
	if len(transcript.Dependencies) != 2 {
		t.Fatalf("%d dependencies recorded", len(transcript.Dependencies))
	}
	dep := transcript.Dependencies[0]
	switch {
	case dep.Alias != "release-policy":
		t.Fatalf("first dependency = %q", dep.Alias)
	case dep.Request.Name != "@glasswing/release-policy" || dep.Request.Range != "^1.4.2":
		t.Fatalf("request = %+v", dep.Request)
	case dep.SourcePolicy.Bound != "glasswing-private" || dep.SourcePolicy.Mode != "exclusive":
		t.Fatalf("source policy = %+v", dep.SourcePolicy)
	case len(dep.SourcePolicy.Excluded) != 1 || dep.SourcePolicy.Excluded[0] != "community-public":
		t.Fatalf("excluded = %v", dep.SourcePolicy.Excluded)
	case len(dep.IndexDisplayOrder) != 2:
		t.Fatalf("display order = %v", dep.IndexDisplayOrder)
	case len(dep.Candidates) != 2:
		t.Fatalf("candidates = %+v", dep.Candidates)
	case dep.Selected.Version != "1.4.2" || dep.Selected.Source != "glasswing-private":
		t.Fatalf("selected = %+v", dep.Selected)
	case dep.Integrity != resolver.IntegrityVerified:
		t.Fatalf("integrity = %q", dep.Integrity)
	case dep.SelectionRule != resolver.SelectionRule:
		t.Fatalf("selection rule = %q", dep.SelectionRule)
	}
	if transcript.Release.PolicyVerdict != pkgarchive.VerdictReject {
		t.Fatalf("verdict = %q", transcript.Release.PolicyVerdict)
	}
	if transcript.Release.GateClassification != fixtures.ClassificationKnownUnsafe {
		t.Fatalf("classification = %q", transcript.Release.GateClassification)
	}
	if transcript.Ledger.Changed || transcript.Ledger.Before != transcript.Ledger.After {
		t.Fatalf("ledger = %+v", transcript.Ledger)
	}
	if transcript.Reconciliation.Result != ReconcilePass {
		t.Fatalf("reconciliation = %+v", transcript.Reconciliation)
	}
	if transcript.Reconciliation.Digest != dep.Selected.SHA256 {
		t.Fatalf("reconciliation names digest %q, selection was %q", transcript.Reconciliation.Digest, dep.Selected.SHA256)
	}
}

// The evidence for "the public registry was never asked" comes from the public
// registry, and a registry that heard nothing still has to say so.
func TestReceiptsAreSignedAndCoverEveryRegistry(t *testing.T) {
	endpoints := startStack(t)
	// Every registry that exists in this workflow has to answer. The ones from
	// the vulnerable half are not running here, so there is nothing to ask.
	ids, err := fixtures.RegistrySetIDs()
	if err != nil {
		t.Fatalf("RegistrySetIDs: %v", err)
	}
	running := 0
	for _, id := range ids {
		set, err := fixtures.RegistrySet(id)
		if err != nil {
			t.Fatalf("RegistrySet(%q): %v", id, err)
		}
		if !set.Vulnerable {
			running++
		}
	}

	for _, scenario := range []string{"secure-missing-artifact", "secure-tampered-artifact", "upgrade-unreviewed"} {
		transcript := run(t, endpoints, scenario)
		if len(transcript.Receipts) != running {
			t.Fatalf("%s: %d receipts for %d running registries", scenario, len(transcript.Receipts), running)
		}
		for _, receipt := range transcript.Receipts {
			if !receipt.SignatureVerified {
				t.Errorf("%s: receipt from %q is not signed by the fixture boundary", scenario, receipt.Source)
			}
			if receipt.Role == "public" && receipt.RequestCount != 0 {
				t.Errorf("%s: public registry %q reports %d requests", scenario, receipt.Source, receipt.RequestCount)
			}
		}
	}
}

func TestSecureRunsNeverAskThePublicRegistryAboutThePrivateNamespace(t *testing.T) {
	endpoints := startStack(t)
	ids, err := fixtures.DefaultScenarioIDs()
	if err != nil {
		t.Fatalf("DefaultScenarioIDs: %v", err)
	}
	for _, id := range ids {
		for _, receipt := range run(t, endpoints, id).Receipts {
			if receipt.Role != "public" {
				continue
			}
			for _, request := range receipt.Requests {
				if strings.HasPrefix(request.Name, "@glasswing/") {
					t.Errorf("%s: %q was asked for %q", id, receipt.Source, request.Name)
				}
			}
		}
	}
}

func TestRunRefusesAnythingButAnEnumeratedScenario(t *testing.T) {
	endpoints := startStack(t)
	for _, id := range []string{
		"", "anything", "../locks/default", "secure-unsafe-candidate ",
		"http://packages.public.example:8080", "@glasswing/release-policy@9.9.9",
	} {
		_, err := Run(context.Background(), Options{ScenarioID: id, StateDir: t.TempDir(), Endpoints: endpoints})
		if err == nil {
			t.Fatalf("Run(%q) was accepted", id)
		}
	}
}

func TestTranscriptCarriesNoCredentialOrAddress(t *testing.T) {
	endpoints := startStack(t)
	boundary, err := fixtures.ReceiptBoundary()
	if err != nil {
		t.Fatalf("ReceiptBoundary: %v", err)
	}
	body, err := run(t, endpoints, "secure-safe-candidate").Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	for _, forbidden := range []string{"://", boundary.Credential, boundary.SigningKey, "password", "BEGIN PRIVATE KEY"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("transcript contains %q", forbidden)
		}
	}
	// The per-execution run id is deliberately absent, which is part of why two
	// runs of one scenario are byte-identical.
	if strings.Contains(string(body), "\"run\"") {
		t.Error("transcript records a per-execution run id")
	}
}

func TestMatrixRunsEveryScenarioAndRenders(t *testing.T) {
	endpoints := startStack(t)
	transcripts, err := Matrix(context.Background(), Options{StateDir: t.TempDir(), Endpoints: endpoints})
	if err != nil {
		t.Fatalf("Matrix: %v", err)
	}
	ids, err := fixtures.DefaultScenarioIDs()
	if err != nil {
		t.Fatalf("DefaultScenarioIDs: %v", err)
	}
	if len(transcripts) != len(ids) {
		t.Fatalf("%d transcripts for %d scenarios", len(transcripts), len(ids))
	}
	for i, id := range ids {
		if transcripts[i].Scenario.ID != id {
			t.Fatalf("matrix row %d = %q, want %q", i, transcripts[i].Scenario.ID, id)
		}
	}

	var table strings.Builder
	if err := RenderMatrix(&table, transcripts); err != nil {
		t.Fatalf("RenderMatrix: %v", err)
	}
	rendered := table.String()
	for _, want := range []string{
		"scenario", "source policy", "queried (observed)", "selected origin", "digest",
		"integrity", "verdict", "mutation", "ledger", "reconciliation",
		"secure-unsafe-candidate", "glasswing-private(2)", "community-public(2)", "PASS",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("matrix table is missing %q:\n%s", want, rendered)
		}
	}

	var human strings.Builder
	if err := Render(&human, transcripts[0]); err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"source policy", "index display order", "queried sources", "excluded sources",
		"candidates", "selection rule", "selected origin", "selected digest",
		"integrity verdict", "REGISTRY-OBSERVED REQUESTS", "signature verified",
		"policy verdict", "ledger before", "RECONCILIATION",
	} {
		if !strings.Contains(human.String(), want) {
			t.Errorf("human transcript is missing %q:\n%s", want, human.String())
		}
	}
}

// reconcile is the judgement the whole demonstration turns on, so each branch is
// exercised directly rather than only through the scenarios that reach it today.
func TestReconcileComparesArtifactVerdictGateRecordAndLedger(t *testing.T) {
	approvedByPrivate := &releasegate.Outcome{
		ClientResult:   releasegate.ResultBuildOK,
		Classification: fixtures.ClassificationReleaseReady,
		Verdict:        pkgarchive.VerdictApprove,
		Mutation:       releasegate.MutationApproved,
		LedgerBefore:   "sha256:before",
		LedgerAfter:    "sha256:after",
		ReleasePolicy:  &resolver.Resolution{Digest: "sha256:policy"},
	}
	approvedByPrivate.ReleasePolicy.Selected.Source = "glasswing-private"

	cases := []struct {
		name    string
		outcome *releasegate.Outcome
		result  string
		says    string
	}{
		{
			name:    "unsafe candidate rejected and ledger untouched",
			outcome: &releasegate.Outcome{ClientResult: releasegate.ResultBuildOK, Classification: fixtures.ClassificationKnownUnsafe, Verdict: pkgarchive.VerdictReject, Mutation: releasegate.MutationNone, LedgerBefore: "sha256:x", LedgerAfter: "sha256:x"},
			result:  ReconcilePass,
			says:    "unsafe candidate not released",
		},
		{
			name:    "release-ready candidate approved once",
			outcome: approvedByPrivate,
			result:  ReconcilePass,
			says:    "released exactly once",
		},
		{
			name:    "unsafe candidate approved",
			outcome: &releasegate.Outcome{ClientResult: releasegate.ResultBuildOK, Classification: fixtures.ClassificationKnownUnsafe, Verdict: pkgarchive.VerdictApprove, Mutation: releasegate.MutationApproved, LedgerBefore: "sha256:x", LedgerAfter: "sha256:y"},
			result:  ReconcileFail,
			says:    "untrusted origin influenced release approval",
		},
		{
			name:    "build failed closed",
			outcome: &releasegate.Outcome{ClientResult: releasegate.ResultBuildFailed, Classification: fixtures.ClassificationKnownUnsafe, Mutation: releasegate.MutationNone, LedgerBefore: "sha256:x", LedgerAfter: "sha256:x"},
			result:  ReconcilePass,
			says:    "build failed closed",
		},
		{
			name:    "build failed but the ledger moved",
			outcome: &releasegate.Outcome{ClientResult: releasegate.ResultBuildFailed, Classification: fixtures.ClassificationKnownUnsafe, Mutation: releasegate.MutationNone, LedgerBefore: "sha256:x", LedgerAfter: "sha256:y"},
			result:  ReconcileFail,
			says:    "release ledger changed",
		},
		{
			name:    "rejection with a ledger write",
			outcome: &releasegate.Outcome{ClientResult: releasegate.ResultBuildOK, Classification: fixtures.ClassificationKnownUnsafe, Verdict: pkgarchive.VerdictReject, Mutation: releasegate.MutationNone, LedgerBefore: "sha256:x", LedgerAfter: "sha256:y"},
			result:  ReconcileFail,
			says:    "release ledger changed",
		},
		{
			name:    "release-ready candidate rejected",
			outcome: &releasegate.Outcome{ClientResult: releasegate.ResultBuildOK, Classification: fixtures.ClassificationReleaseReady, Verdict: pkgarchive.VerdictReject, Mutation: releasegate.MutationNone, LedgerBefore: "sha256:x", LedgerAfter: "sha256:x"},
			result:  ReconcileFail,
			says:    "release-ready candidate was rejected",
		},
		{
			name:    "no verdict at all",
			outcome: &releasegate.Outcome{ClientResult: releasegate.ResultBuildOK, Classification: fixtures.ClassificationKnownUnsafe, Mutation: releasegate.MutationNone, LedgerBefore: "sha256:x", LedgerAfter: "sha256:x"},
			result:  ReconcileFail,
			says:    "no policy verdict",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := reconcile(c.outcome)
			if got.Result != c.result || !strings.Contains(got.Statement, c.says) {
				t.Fatalf("reconcile = %+v, want %s containing %q", got, c.result, c.says)
			}
		})
	}
}

// A failure is not a blank spot in the trace. The dependency the build stopped
// on still has to say what it asked, what policy decided, and who was contacted.
func TestFailedRunStillRecordsPolicyAndQuerySet(t *testing.T) {
	endpoints := startStack(t)
	cases := map[string]struct {
		bound     string
		queried   []string
		integrity string
		selected  string
	}{
		// Nothing was ever offered, so nothing was selected.
		"secure-missing-artifact": {bound: "glasswing-private", queried: []string{"glasswing-private"}, integrity: IntegrityNotReached},
		// A candidate was selected and then its bytes were refused, which is a
		// different fact from never getting that far.
		"secure-tampered-artifact": {bound: "glasswing-private", queried: []string{"glasswing-private"}, integrity: IntegrityRejected, selected: "glasswing-private"},
		// The lock conflict was found before any registry was contacted.
		"upgrade-unreviewed": {bound: "glasswing-private", queried: []string{}, integrity: IntegrityNotReached},
	}
	for scenario, want := range cases {
		transcript := run(t, endpoints, scenario)
		if len(transcript.Dependencies) != 1 {
			t.Fatalf("%s recorded %d dependencies", scenario, len(transcript.Dependencies))
		}
		dep := transcript.Dependencies[0]
		if dep.Alias != "release-policy" || dep.Request.Name != "@glasswing/release-policy" {
			t.Fatalf("%s recorded %+v", scenario, dep)
		}
		if dep.SourcePolicy.Bound != want.bound {
			t.Errorf("%s bound to %q, want %q", scenario, dep.SourcePolicy.Bound, want.bound)
		}
		if strings.Join(dep.QueriedSources, ",") != strings.Join(want.queried, ",") {
			t.Errorf("%s queried %v, want %v", scenario, dep.QueriedSources, want.queried)
		}
		if dep.Integrity != want.integrity {
			t.Errorf("%s integrity = %q, want %q", scenario, dep.Integrity, want.integrity)
		}
		if dep.Selected.Source != want.selected {
			t.Errorf("%s selected source = %q, want %q", scenario, dep.Selected.Source, want.selected)
		}
		// No digest is ever recorded for content that was not accepted.
		if dep.Selected.SHA256 != "" {
			t.Errorf("%s recorded a verified digest despite failing: %+v", scenario, dep.Selected)
		}
		if transcript.Failure == nil {
			t.Errorf("%s recorded no failure", scenario)
		}
	}
}

// acknowledge satisfies both opt-in controls for the duration of one test. It
// is the deliberate, explicit act the demonstration asks for; nothing in the
// default path does this.
func acknowledge(t *testing.T) {
	t.Helper()
	t.Setenv(vulnerable.AcknowledgementEnv, vulnerable.Acknowledgement)
	t.Setenv(vulnerable.ProfileEnv, vulnerable.Profile)
}

func TestVulnerableScenariosAreUnreachableWithoutBothControls(t *testing.T) {
	endpoints := startStack(t)
	cases := []struct {
		name            string
		acknowledgement string
		profile         string
	}{
		{"neither control", "", ""},
		{"acknowledgement alone", vulnerable.Acknowledgement, ""},
		{"profile alone", "", vulnerable.Profile},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(vulnerable.AcknowledgementEnv, c.acknowledgement)
			t.Setenv(vulnerable.ProfileEnv, c.profile)
			for _, id := range []string{"vulnerable-public-shadow", "secure-against-public-shadow"} {
				_, err := Run(context.Background(), Options{ScenarioID: id, StateDir: t.TempDir(), Endpoints: endpoints})
				if !errors.Is(err, vulnerable.ErrNotAcknowledged) {
					t.Fatalf("Run(%q) = %v, want ErrNotAcknowledged", id, err)
				}
			}
			// The scenarios are not merely refused; by default they are not
			// even listed.
			transcripts, err := Matrix(context.Background(), Options{StateDir: t.TempDir(), Endpoints: endpoints})
			if err != nil {
				t.Fatalf("Matrix: %v", err)
			}
			for _, transcript := range transcripts {
				if transcript.Scenario.Vulnerable {
					t.Fatalf("the default matrix ran %q", transcript.Scenario.ID)
				}
			}
		})
	}
}

// The whole demonstration in one test: the same build, the same candidate, the
// same public registry — and the answer changes because one name was resolved
// across two trust domains at once.
func TestPublicShadowWinsUnderTheCombinedIndexResolver(t *testing.T) {
	acknowledge(t)
	endpoints := startStack(t)
	transcript := run(t, endpoints, "vulnerable-public-shadow")

	if transcript.Resolver != fixtures.ResolverCombinedIndex {
		t.Fatalf("resolver = %q", transcript.Resolver)
	}
	if transcript.LockEnforcement != LockUnenforced {
		t.Fatalf("lock enforcement = %q", transcript.LockEnforcement)
	}
	if transcript.Warning != vulnerable.Label {
		t.Fatalf("warning = %q", transcript.Warning)
	}

	dep := transcript.Dependencies[0]
	if dep.SourcePolicy.Mode != sourcepolicy.ModeCombined {
		t.Fatalf("source policy = %+v", dep.SourcePolicy)
	}
	// Both trust domains offered the same name, and both offers are recorded.
	offers := map[string]string{}
	for _, c := range dep.Candidates {
		offers[c.Source] = c.Version
	}
	if offers["glasswing-private"] != "1.4.2" || offers["community-public-shadow"] != "9.9.9" {
		t.Fatalf("candidates = %+v", dep.Candidates)
	}
	if dep.Candidates[0].Version != "9.9.9" {
		t.Fatalf("the highest version is not ordered first: %+v", dep.Candidates)
	}
	if dep.Selected.Source != "community-public-shadow" || dep.Selected.Version != "9.9.9" {
		t.Fatalf("selected %+v", dep.Selected)
	}
	if dep.Selected.Role != "public" {
		t.Fatalf("selected role = %q", dep.Selected.Role)
	}
	if dep.Integrity != combinedindex.IntegrityUnverified {
		t.Fatalf("integrity = %q", dep.Integrity)
	}

	// The selected bytes are the public fixture's bytes.
	shadow := artifactDigest(t, "release-policy-9.9.9-public-shadow")
	if dep.Selected.SHA256 != shadow {
		t.Fatalf("selected digest %q, public shadow digest %q", dep.Selected.SHA256, shadow)
	}

	if transcript.Release.PolicyVerdict != pkgarchive.VerdictApprove {
		t.Fatalf("verdict = %q", transcript.Release.PolicyVerdict)
	}
	if transcript.Release.GateClassification != fixtures.ClassificationKnownUnsafe {
		t.Fatalf("classification = %q", transcript.Release.GateClassification)
	}
	if !transcript.Ledger.Changed || transcript.Ledger.Entries != 1 {
		t.Fatalf("ledger = %+v", transcript.Ledger)
	}
	if transcript.Reconciliation.Result != ReconcileFail {
		t.Fatalf("reconciliation = %+v", transcript.Reconciliation)
	}
	if transcript.Reconciliation.Statement != "untrusted origin influenced release approval" {
		t.Fatalf("reconciliation statement = %q", transcript.Reconciliation.Statement)
	}
	if transcript.Reconciliation.Origin != "community-public-shadow" || transcript.Reconciliation.Digest != shadow {
		t.Fatalf("reconciliation does not name the origin and digest: %+v", transcript.Reconciliation)
	}

	// Both registries say they were asked, in their own signed words.
	observed := map[string]int{}
	askedShadowAbout := map[string]bool{}
	for _, receipt := range transcript.Receipts {
		observed[receipt.Source] = receipt.RequestCount
		if !receipt.SignatureVerified {
			t.Errorf("receipt from %q is not signed", receipt.Source)
		}
		if receipt.Source == "community-public-shadow" {
			for _, request := range receipt.Requests {
				askedShadowAbout[request.Name+"@"+request.Version] = true
			}
		}
	}
	if observed["glasswing-private"] == 0 || observed["community-public-shadow"] == 0 {
		t.Fatalf("observed requests = %+v", observed)
	}
	if !askedShadowAbout["@glasswing/release-policy@9.9.9"] {
		t.Fatalf("the public fixture was never asked for the selected artifact: %+v", askedShadowAbout)
	}
}

// The same shadow, the same registry, the same candidate — and the secure
// resolver is unmoved. Without this pair the run above proves nothing.
func TestSecureResolverIsUnmovedByTheSameShadow(t *testing.T) {
	acknowledge(t)
	endpoints := startStack(t)
	transcript := run(t, endpoints, "secure-against-public-shadow")

	if transcript.Resolver != fixtures.ResolverSecure || transcript.LockEnforcement != LockEnforced {
		t.Fatalf("resolver %q lock %q", transcript.Resolver, transcript.LockEnforcement)
	}
	dep := transcript.Dependencies[0]
	if dep.SourcePolicy.Mode != sourcepolicy.ModeExclusive || dep.SourcePolicy.Bound != "glasswing-private" {
		t.Fatalf("source policy = %+v", dep.SourcePolicy)
	}
	if dep.Selected.Source != "glasswing-private" || dep.Selected.Version != "1.4.2" {
		t.Fatalf("selected %+v", dep.Selected)
	}
	if dep.Integrity != resolver.IntegrityVerified {
		t.Fatalf("integrity = %q", dep.Integrity)
	}
	if transcript.Release.PolicyVerdict != pkgarchive.VerdictReject {
		t.Fatalf("verdict = %q", transcript.Release.PolicyVerdict)
	}
	if transcript.Ledger.Changed {
		t.Fatalf("ledger = %+v", transcript.Ledger)
	}
	if transcript.Reconciliation.Result != ReconcilePass {
		t.Fatalf("reconciliation = %+v", transcript.Reconciliation)
	}

	// The shadow-bearing registry exists, is running, carries the shadow — and
	// was never asked about the private namespace.
	for _, receipt := range transcript.Receipts {
		if receipt.Source != "community-public-shadow" {
			continue
		}
		for _, request := range receipt.Requests {
			if strings.HasPrefix(request.Name, "@glasswing/") {
				t.Fatalf("the shadow registry was asked for %q", request.Name)
			}
		}
	}
}

func TestVulnerableTranscriptsAreDeterministicToo(t *testing.T) {
	acknowledge(t)
	endpoints := startStack(t)
	for _, id := range []string{"vulnerable-public-shadow", "secure-against-public-shadow"} {
		first, err := run(t, endpoints, id).Bytes()
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}
		second, err := run(t, endpoints, id).Bytes()
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}
		if string(first) != string(second) {
			t.Fatalf("%s transcript is not deterministic", id)
		}
	}
}

func TestAcknowledgedMatrixIncludesBothHalves(t *testing.T) {
	acknowledge(t)
	endpoints := startStack(t)
	transcripts, err := Matrix(context.Background(), Options{StateDir: t.TempDir(), Endpoints: endpoints})
	if err != nil {
		t.Fatalf("Matrix: %v", err)
	}
	ids, err := fixtures.ScenarioIDs()
	if err != nil {
		t.Fatalf("ScenarioIDs: %v", err)
	}
	if len(transcripts) != len(ids) {
		t.Fatalf("%d transcripts for %d scenarios", len(transcripts), len(ids))
	}

	var table strings.Builder
	if err := RenderMatrix(&table, transcripts); err != nil {
		t.Fatalf("RenderMatrix: %v", err)
	}
	for _, want := range []string{"vulnerable-public-shadow", "community-public-shadow", "9.9.9", "FAIL", "unverified"} {
		if !strings.Contains(table.String(), want) {
			t.Errorf("matrix is missing %q:\n%s", want, table.String())
		}
	}
}

func artifactDigest(t *testing.T, packageDir string) string {
	t.Helper()
	artifacts, err := fixtures.Artifacts()
	if err != nil {
		t.Fatalf("Artifacts: %v", err)
	}
	for _, a := range artifacts {
		if a.Package == packageDir {
			return a.SHA256
		}
	}
	t.Fatalf("no artifact built from %q", packageDir)
	return ""
}
