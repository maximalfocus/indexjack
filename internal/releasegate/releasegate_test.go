package releasegate

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"indexjack/internal/audit"
	"indexjack/internal/fixtures"
	"indexjack/internal/ledger"
	"indexjack/internal/pkgarchive"
	"indexjack/internal/registry"
	"indexjack/internal/resolver"
	"indexjack/internal/sourcepolicy"
)

type stack struct {
	endpoints map[string]string
	handlers  map[string]*registry.Handler
}

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
		handler := registry.NewHandler(set, receiptBoundary(t))
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		s.endpoints[checkedIn] = server.URL
		s.handlers[id] = handler
	}
	return s
}

func receiptBoundary(t *testing.T) registry.ReceiptConfig {
	t.Helper()
	boundary, err := fixtures.ReceiptBoundary()
	if err != nil {
		t.Fatalf("ReceiptBoundary: %v", err)
	}
	return boundary
}

func (s *stack) dial() func(sourcepolicy.Source) (resolver.Fetcher, error) {
	return func(source sourcepolicy.Source) (resolver.Fetcher, error) {
		return registry.NewClient(s.endpoints[source.URL])
	}
}

func (s *stack) requests(registryID string) int { return len(s.handlers[registryID].Requests()) }

func execute(t *testing.T, s *stack, scenarioID, stateDir string) *Outcome {
	t.Helper()
	scenario, err := fixtures.LoadScenario(scenarioID)
	if err != nil {
		t.Fatalf("LoadScenario(%q): %v", scenarioID, err)
	}
	out, err := Execute(context.Background(), Options{Scenario: scenario, StateDir: stateDir, Dial: s.dial()})
	if err != nil {
		t.Fatalf("Execute(%q): %v", scenarioID, err)
	}
	return out
}

func eventNames(events []audit.Event) []string {
	names := make([]string, 0, len(events))
	for _, e := range events {
		names = append(names, e.Event)
	}
	return names
}

func freshLedgerBytes(t *testing.T) []byte {
	t.Helper()
	body, err := ledger.Fresh().Bytes()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	return body
}

func TestUnsafeCandidateIsRejectedAndTheLedgerDoesNotChange(t *testing.T) {
	s := startStack(t)
	dir := t.TempDir()
	out := execute(t, s, "secure-unsafe-candidate", dir)

	if out.ClientResult != ResultBuildOK {
		t.Fatalf("client result = %q", out.ClientResult)
	}
	if out.Verdict != pkgarchive.VerdictReject {
		t.Fatalf("verdict = %q", out.Verdict)
	}
	if out.Classification != fixtures.ClassificationKnownUnsafe {
		t.Fatalf("classification = %q", out.Classification)
	}
	if out.Mutation != MutationNone {
		t.Fatalf("mutation = %q", out.Mutation)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, LedgerFile))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(onDisk) != string(freshLedgerBytes(t)) {
		t.Fatalf("ledger changed: %q", onDisk)
	}
	if names := eventNames(out.AuditEvents); len(names) != 1 || names[0] != audit.EventReleaseRejected {
		t.Fatalf("audit events = %v", names)
	}
}

func TestSafeCandidateIsApprovedExactlyOnce(t *testing.T) {
	s := startStack(t)
	dir := t.TempDir()
	out := execute(t, s, "secure-safe-candidate", dir)

	if out.Verdict != pkgarchive.VerdictApprove || out.Mutation != MutationApproved {
		t.Fatalf("verdict %q mutation %q", out.Verdict, out.Mutation)
	}
	current, err := ledger.Load(filepath.Join(dir, LedgerFile))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(current.Entries) != 1 {
		t.Fatalf("ledger has %d entries", len(current.Entries))
	}
	entry := current.Entries[0]
	if entry.CandidateID != "MODEL-CANDIDATE-04" || entry.PolicySource != "glasswing-private" || entry.PolicyVersion != "1.4.2" {
		t.Fatalf("entry = %+v", entry)
	}
	if entry.PolicyDigest != out.ReleasePolicy.Digest {
		t.Fatalf("entry digest %q, resolved digest %q", entry.PolicyDigest, out.ReleasePolicy.Digest)
	}

	// A second run against the same ledger must not release the candidate
	// twice.
	before, err := ledger.Digest(filepath.Join(dir, LedgerFile))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	second := execute(t, s, "secure-safe-candidate", dir)
	if second.Mutation != MutationSuppressed {
		t.Fatalf("second mutation = %q", second.Mutation)
	}
	after, err := ledger.Digest(filepath.Join(dir, LedgerFile))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if before != after {
		t.Fatalf("duplicate release changed the ledger: %s → %s", before, after)
	}
	if names := eventNames(second.AuditEvents); len(names) != 1 || names[0] != audit.EventReleaseDuplicate {
		t.Fatalf("audit events = %v", names)
	}
}

func TestMissingAndTamperedArtifactsFailIdentically(t *testing.T) {
	s := startStack(t)
	responses := map[string]string{}
	for _, scenario := range []string{"secure-missing-artifact", "secure-tampered-artifact"} {
		dir := t.TempDir()
		out := execute(t, s, scenario, dir)

		if out.ClientResult != ResultBuildFailed {
			t.Fatalf("%s client result = %q", scenario, out.ClientResult)
		}
		if out.ReleasePolicy != nil {
			t.Fatalf("%s read package policy despite failing", scenario)
		}
		if out.Verdict != "" || out.Mutation != MutationNone {
			t.Fatalf("%s verdict %q mutation %q", scenario, out.Verdict, out.Mutation)
		}
		onDisk, err := os.ReadFile(filepath.Join(dir, LedgerFile))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if string(onDisk) != string(freshLedgerBytes(t)) {
			t.Fatalf("%s changed the ledger", scenario)
		}
		if names := eventNames(out.AuditEvents); len(names) != 1 || names[0] != audit.EventBuildFailed {
			t.Fatalf("%s audit events = %v", scenario, names)
		}
		if got := s.requests("community-public"); got != 0 {
			t.Fatalf("%s produced %d public-registry requests", scenario, got)
		}
		response, err := out.ClientResponse()
		if err != nil {
			t.Fatalf("ClientResponse: %v", err)
		}
		responses[scenario] = string(response)
	}
	if responses["secure-missing-artifact"] != responses["secure-tampered-artifact"] {
		t.Fatalf("failures are distinguishable: %q vs %q",
			responses["secure-missing-artifact"], responses["secure-tampered-artifact"])
	}
}

func TestClientResponseCarriesNothingButTheResult(t *testing.T) {
	s := startStack(t)
	out := execute(t, s, "secure-missing-artifact", t.TempDir())
	response, err := out.ClientResponse()
	if err != nil {
		t.Fatalf("ClientResponse: %v", err)
	}
	want := "{\"format\":\"indexjack-build-result/1\",\"result\":\"BUILD_FAILED\"}\n"
	if string(response) != want {
		t.Fatalf("client response = %q, want %q", response, want)
	}
}

func TestUnreviewedUpgradeFailsClosedAndReviewedUpgradeSucceeds(t *testing.T) {
	s := startStack(t)

	unreviewed := execute(t, s, "upgrade-unreviewed", t.TempDir())
	if unreviewed.ClientResult != ResultBuildFailed {
		t.Fatalf("client result = %q", unreviewed.ClientResult)
	}
	if unreviewed.Failure == nil || unreviewed.Failure.Class != resolver.ClassLockRangeConflict {
		t.Fatalf("failure = %+v", unreviewed.Failure)
	}

	dir := t.TempDir()
	reviewed := execute(t, s, "reviewed-upgrade", dir)
	if reviewed.ClientResult != ResultBuildOK || reviewed.Mutation != MutationApproved {
		t.Fatalf("result %q mutation %q", reviewed.ClientResult, reviewed.Mutation)
	}
	if reviewed.ReleasePolicy.Selected.Version != "1.5.0" {
		t.Fatalf("selected version = %q", reviewed.ReleasePolicy.Selected.Version)
	}
	current, err := ledger.Load(filepath.Join(dir, LedgerFile))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(current.Entries) != 1 || current.Entries[0].PolicyVersion != "1.5.0" {
		t.Fatalf("entries = %+v", current.Entries)
	}
}

func TestLegitimatePublicDependencyResolvesUnderBothCandidates(t *testing.T) {
	s := startStack(t)
	for _, scenario := range []string{"secure-unsafe-candidate", "secure-safe-candidate"} {
		out := execute(t, s, scenario, t.TempDir())
		if out.ReportFormat == nil {
			t.Fatalf("%s did not resolve the public dependency", scenario)
		}
		if out.ReportFormat.Selected.Source != "community-public" || out.ReportFormat.Selected.Version != "2.1.0" {
			t.Fatalf("%s resolved %s@%s", scenario, out.ReportFormat.Selected.Source, out.ReportFormat.Selected.Version)
		}
		if out.ReportFormat.Package.Policy.Kind != pkgarchive.KindReportFormat {
			t.Fatalf("%s public dependency kind = %q", scenario, out.ReportFormat.Package.Policy.Kind)
		}
	}
}

func TestAuditRecordsArePersistedWithADeterministicCorrelationID(t *testing.T) {
	s := startStack(t)
	dir := t.TempDir()
	out := execute(t, s, "secure-unsafe-candidate", dir)

	records, err := audit.Read(filepath.Join(dir, AuditFile))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(records) != len(out.AuditEvents) || len(records) != 1 {
		t.Fatalf("%d records on disk, %d in memory", len(records), len(out.AuditEvents))
	}
	if records[0].CorrelationID != audit.CorrelationID("secure-unsafe-candidate") {
		t.Fatalf("correlation id = %q", records[0].CorrelationID)
	}
	if records[0].CandidateID != "MODEL-CANDIDATE-17" {
		t.Fatalf("candidate = %q", records[0].CandidateID)
	}
}

func TestEveryScenarioRunsFromFreshStateDeterministically(t *testing.T) {
	s := startStack(t)
	ids, err := fixtures.DefaultScenarioIDs()
	if err != nil {
		t.Fatalf("DefaultScenarioIDs: %v", err)
	}
	for _, id := range ids {
		first := execute(t, s, id, t.TempDir())
		second := execute(t, s, id, t.TempDir())
		if first.ClientResult != second.ClientResult || first.Verdict != second.Verdict ||
			first.Mutation != second.Mutation || first.LedgerAfter != second.LedgerAfter {
			t.Fatalf("%s is not deterministic:\n%+v\n%+v", id, first, second)
		}
	}
}
