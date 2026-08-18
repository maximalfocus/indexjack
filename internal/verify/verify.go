// Package verify is the demonstration's own gate.
//
// It asserts the runtime containment claims, the byte-reproducibility of every
// checked-in artifact, the read-only surface of every registry, and the exact
// outcome of every enumerated scenario. It is the same code locally and in CI,
// run through the same container boundary.
package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"indexjack/internal/audit"
	"indexjack/internal/combinedindex"
	"indexjack/internal/containment"
	"indexjack/internal/fixtures"
	"indexjack/internal/harness"
	"indexjack/internal/ledger"
	"indexjack/internal/pkgarchive"
	"indexjack/internal/registry"
	"indexjack/internal/releasegate"
	"indexjack/internal/resolver"
	"indexjack/internal/sourcepolicy"
	"indexjack/internal/trace"
	"indexjack/internal/vulnerable"
)

// Options configures a verification run.
type Options struct {
	// StateDir is the run's disposable writable directory. Each scenario gets
	// a fresh subdirectory of it.
	StateDir string
	// Endpoints replaces checked-in registry URLs, keyed by the checked-in
	// URL. In-process verification uses it to reach loopback fixtures.
	Endpoints map[string]string
	// SkipContainment omits the runtime container assertions, which only
	// apply inside the demonstration's own containers.
	SkipContainment bool
	// Trace receives each scenario transcript.
	Trace io.Writer
	// Progress receives one line per assertion.
	Progress io.Writer
}

// Result is one assertion.
type Result struct {
	Group  string
	Name   string
	Detail string
	Pass   bool
}

// expectation is the exact outcome one scenario must produce.
type expectation struct {
	scenario        string
	clientResult    string
	selectedSource  string
	selectedVersion string
	verdict         string
	mutation        string
	ledgerChanged   bool
	ledgerEntries   int
	auditEvents     []string
	failureClass    string
	failureStage    string
	reportResolved  bool
	reconciliation  string
	// integrity defaults to a verified verdict; the vulnerable resolver never
	// verifies anything, so it names its own.
	integrity string
	// queried defaults to the selected source; a combined pool names every
	// source it asked, in order.
	queried string
	// receipts is the exact number of requests each registry must report
	// having received, from its own signed account of the run.
	receipts map[string]int
}

func (e expectation) wantIntegrity() string {
	if e.integrity != "" {
		return e.integrity
	}
	return resolver.IntegrityVerified
}

func (e expectation) wantQueried() string {
	if e.queried != "" {
		return e.queried
	}
	return e.selectedSource
}

// vulnerableExpectations are the outcomes of the intentionally vulnerable half.
// They are asserted only when both opt-in controls are satisfied; otherwise the
// gate asserts that they are refused instead.
var vulnerableExpectations = []expectation{
	{
		scenario:        "vulnerable-public-shadow",
		clientResult:    releasegate.ResultBuildOK,
		selectedSource:  "community-public-shadow",
		selectedVersion: "9.9.9",
		integrity:       combinedindex.IntegrityUnverified,
		queried:         "glasswing-private,community-public-shadow",
		verdict:         pkgarchive.VerdictApprove,
		mutation:        releasegate.MutationApproved,
		ledgerChanged:   true,
		ledgerEntries:   1,
		auditEvents:     []string{audit.EventReleaseApproved},
		reportResolved:  true,
		reconciliation:  harness.ReconcileFail,
		receipts: map[string]int{
			"glasswing-private": 1, "community-public-shadow": 4,
			"community-public": 0, "glasswing-private-missing": 0, "glasswing-private-tampered": 0,
		},
	},
	{
		scenario:        "secure-against-public-shadow",
		clientResult:    releasegate.ResultBuildOK,
		selectedSource:  "glasswing-private",
		selectedVersion: "1.4.2",
		verdict:         pkgarchive.VerdictReject,
		mutation:        releasegate.MutationNone,
		ledgerChanged:   false,
		ledgerEntries:   0,
		auditEvents:     []string{audit.EventReleaseRejected},
		reportResolved:  true,
		reconciliation:  harness.ReconcilePass,
		receipts: map[string]int{
			"glasswing-private": 2, "community-public-shadow": 2,
			"community-public": 0, "glasswing-private-missing": 0, "glasswing-private-tampered": 0,
		},
	},
}

// expectations is the checked-in outcome of every enumerated scenario. Values
// are exact: no timing tolerance, no probability, no "contains".
var expectations = []expectation{
	{
		scenario:        "secure-unsafe-candidate",
		clientResult:    releasegate.ResultBuildOK,
		selectedSource:  "glasswing-private",
		selectedVersion: "1.4.2",
		verdict:         pkgarchive.VerdictReject,
		mutation:        releasegate.MutationNone,
		ledgerChanged:   false,
		ledgerEntries:   0,
		auditEvents:     []string{audit.EventReleaseRejected},
		reportResolved:  true,
		reconciliation:  harness.ReconcilePass,
		receipts:        map[string]int{"glasswing-private": 2, "community-public": 2, "glasswing-private-missing": 0, "glasswing-private-tampered": 0},
	},
	{
		scenario:        "secure-safe-candidate",
		clientResult:    releasegate.ResultBuildOK,
		selectedSource:  "glasswing-private",
		selectedVersion: "1.4.2",
		verdict:         pkgarchive.VerdictApprove,
		mutation:        releasegate.MutationApproved,
		ledgerChanged:   true,
		ledgerEntries:   1,
		auditEvents:     []string{audit.EventReleaseApproved},
		reportResolved:  true,
		reconciliation:  harness.ReconcilePass,
		receipts:        map[string]int{"glasswing-private": 2, "community-public": 2, "glasswing-private-missing": 0, "glasswing-private-tampered": 0},
	},
	{
		scenario:       "secure-missing-artifact",
		clientResult:   releasegate.ResultBuildFailed,
		mutation:       releasegate.MutationNone,
		ledgerChanged:  false,
		ledgerEntries:  0,
		auditEvents:    []string{audit.EventBuildFailed},
		failureClass:   resolver.ClassArtifactUnavailable,
		failureStage:   resolver.StageRegistryQuery,
		reconciliation: harness.ReconcilePass,
		receipts:       map[string]int{"glasswing-private": 0, "community-public": 0, "glasswing-private-missing": 1, "glasswing-private-tampered": 0},
	},
	{
		scenario:       "secure-tampered-artifact",
		clientResult:   releasegate.ResultBuildFailed,
		mutation:       releasegate.MutationNone,
		ledgerChanged:  false,
		ledgerEntries:  0,
		auditEvents:    []string{audit.EventBuildFailed},
		failureClass:   resolver.ClassArtifactDigestMismatch,
		failureStage:   resolver.StageIntegrity,
		reconciliation: harness.ReconcilePass,
		receipts:       map[string]int{"glasswing-private": 0, "community-public": 0, "glasswing-private-missing": 0, "glasswing-private-tampered": 2},
	},
	{
		scenario:       "upgrade-unreviewed",
		clientResult:   releasegate.ResultBuildFailed,
		mutation:       releasegate.MutationNone,
		ledgerChanged:  false,
		ledgerEntries:  0,
		auditEvents:    []string{audit.EventBuildFailed},
		failureClass:   resolver.ClassLockRangeConflict,
		failureStage:   resolver.StageLock,
		reconciliation: harness.ReconcilePass,
		receipts:       map[string]int{"glasswing-private": 0, "community-public": 0, "glasswing-private-missing": 0, "glasswing-private-tampered": 0},
	},
	{
		scenario:        "reviewed-upgrade",
		clientResult:    releasegate.ResultBuildOK,
		selectedSource:  "glasswing-private",
		selectedVersion: "1.5.0",
		verdict:         pkgarchive.VerdictApprove,
		mutation:        releasegate.MutationApproved,
		ledgerChanged:   true,
		ledgerEntries:   1,
		auditEvents:     []string{audit.EventReleaseApproved},
		reportResolved:  true,
		reconciliation:  harness.ReconcilePass,
		receipts:        map[string]int{"glasswing-private": 2, "community-public": 2, "glasswing-private-missing": 0, "glasswing-private-tampered": 0},
	},
}

type recorder struct {
	results  []Result
	progress io.Writer
}

func (r *recorder) add(group, name string, pass bool, format string, args ...any) {
	result := Result{Group: group, Name: name, Detail: fmt.Sprintf(format, args...), Pass: pass}
	r.results = append(r.results, result)
	if r.progress != nil {
		status := "FAIL"
		if pass {
			status = "ok"
		}
		fmt.Fprintf(r.progress, "%-4s %s/%s: %s\n", status, group, name, result.Detail)
	}
}

func (r *recorder) expectString(group, name, got, want string) {
	r.add(group, name, got == want, "%q (expected %q)", got, want)
}

// AllPassed reports whether every assertion passed.
func AllPassed(results []Result) bool {
	for _, r := range results {
		if !r.Pass {
			return false
		}
	}
	return true
}

// RunAll executes every assertion and returns them in order.
func RunAll(ctx context.Context, opts Options) ([]Result, error) {
	if opts.StateDir == "" {
		return nil, errors.New("verification requires a state directory")
	}
	rec := &recorder{progress: opts.Progress}

	if !opts.SkipContainment {
		if !containment.Supported() {
			rec.add("containment", "supported", false, "containment assertions require the demonstration's Linux containers")
		} else {
			for _, check := range containment.Run(filepath.Join(opts.StateDir, "containment")) {
				rec.add("containment", check.Name, check.Pass, "%s", check.Detail)
			}
		}
	}

	verifyFixtures(rec)
	if err := verifyRegistrySurface(ctx, rec, opts); err != nil {
		return rec.results, err
	}

	responses := make(map[string]string)
	for _, want := range expectations {
		response, err := verifyScenario(ctx, rec, opts, want)
		if err != nil {
			return rec.results, err
		}
		responses[want.scenario] = response

		if err := verifyHarness(ctx, rec, opts, want); err != nil {
			return rec.results, err
		}
	}
	if err := verifyHarnessSurface(ctx, rec, opts); err != nil {
		return rec.results, err
	}
	if err := verifyOptIn(ctx, rec, opts); err != nil {
		return rec.results, err
	}
	if vulnerable.Acknowledged() {
		for _, want := range vulnerableExpectations {
			if _, err := verifyScenario(ctx, rec, opts, want); err != nil {
				return rec.results, err
			}
			if err := verifyHarness(ctx, rec, opts, want); err != nil {
				return rec.results, err
			}
		}
		if err := verifyPublicShadowImpact(ctx, rec, opts); err != nil {
			return rec.results, err
		}
	}

	// Two different failure causes must be indistinguishable to the build's
	// consumer: one is "there is no such artifact", the other is "its bytes
	// were wrong", and telling them apart would leak what a private registry
	// contains.
	missing, tampered := responses["secure-missing-artifact"], responses["secure-tampered-artifact"]
	rec.add("cross-scenario", "identical_generic_failure", missing == tampered && missing != "",
		"missing=%s tampered=%s", strings.TrimSpace(missing), strings.TrimSpace(tampered))

	return rec.results, nil
}

func verifyFixtures(rec *recorder) {
	const group = "fixtures"

	if err := fixtures.ValidateConsistency(); err != nil {
		rec.add(group, "consistent", false, "%v", err)
	} else {
		rec.add(group, "consistent", true, "scenarios, policies, manifests, locks and registries agree")
	}

	first, err := fixtures.Artifacts()
	if err != nil {
		rec.add(group, "artifacts_build", false, "%v", err)
		return
	}
	second, err := fixtures.Artifacts()
	if err != nil {
		rec.add(group, "artifacts_build", false, "%v", err)
		return
	}
	reproducible := len(first) == len(second) && len(first) > 0
	for i := range first {
		if reproducible && first[i] != second[i] {
			reproducible = false
		}
	}
	rec.add(group, "artifacts_byte_reproducible", reproducible, "%d artifacts rebuilt to identical size and digest", len(first))

	// Every published version must equal the artifact built from its checked-in
	// source, so a registry cannot serve anything this repository cannot
	// reproduce.
	setIDs, err := fixtures.RegistrySetIDs()
	if err != nil {
		rec.add(group, "registry_sets", false, "%v", err)
		return
	}
	byIdentity := make(map[string]fixtures.ArtifactInfo, len(first))
	for _, a := range first {
		byIdentity[a.Name+"@"+a.Version+"#"+a.SHA256] = a
	}
	publishedOK, unmarkedShadow, shadows := true, "", 0
	for _, id := range setIDs {
		set, err := fixtures.RegistrySet(id)
		if err != nil {
			rec.add(group, "registry_sets", false, "%v", err)
			return
		}
		for _, pkg := range set.Packages {
			if set.Role == sourcepolicy.RolePublic && strings.HasPrefix(pkg.Name, "@glasswing/") {
				shadows++
				if !set.Vulnerable {
					unmarkedShadow = fmt.Sprintf("%s publishes %s", id, pkg.Name)
				}
			}
			for _, a := range pkg.Versions {
				key := pkg.Name + "@" + a.Version + "#" + pkgarchive.Digest(a.Bytes)
				if _, ok := byIdentity[key]; !ok {
					publishedOK = false
				}
			}
		}
	}
	rec.add(group, "published_artifacts_are_built_from_source", publishedOK,
		"every published version matches an artifact built from checked-in sources")
	rec.add(group, "public_shadow_exists_only_in_a_vulnerable_fixture_set", unmarkedShadow == "" && shadows == 1,
		"%s", valueOr(unmarkedShadow, fmt.Sprintf("%d public shadow fixture(s), all marked vulnerable", shadows)))
}

// verifyRegistrySurface probes each running registry at its own boundary. It
// asserts what the service refuses, which is the part that matters: no write,
// no search, no arbitrary name, no second parameter.
func verifyRegistrySurface(ctx context.Context, rec *recorder, opts Options) error {
	const group = "registry-surface"
	urls, err := fixtures.RegistryURLs()
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(urls))
	for id := range urls {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	client := &http.Client{Timeout: 10 * time.Second}
	for _, id := range ids {
		base := endpoint(opts, urls[id])
		set, err := fixtures.RegistrySet(id)
		if err != nil {
			return err
		}

		// A registry belonging to the intentionally vulnerable half is not
		// merely refused in a run that has not acknowledged it: it is not
		// running, and its name does not resolve.
		if set.Vulnerable && !vulnerable.Acknowledged() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+registry.MetadataPath+"?name=community-format", nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
			}
			rec.add(group, id+"/not_running_without_the_opt_in", err != nil, "%s", valueOr(errText(err), "the vulnerable registry answered"))
			continue
		}
		if set.Vulnerable {
			rec.add(group, id+"/labels_itself_as_vulnerable", true, "checked below with every other response header")
		}

		probes := []struct {
			name   string
			method string
			target string
			want   int
		}{
			{"rejects_write_methods", http.MethodPost, base + registry.MetadataPath + "?name=community-format", http.StatusMethodNotAllowed},
			{"rejects_delete", http.MethodDelete, base + registry.ArtifactPath + "?name=community-format&version=2.1.0", http.StatusMethodNotAllowed},
			{"has_no_listing_or_search", http.MethodGet, base + "/v1/packages", http.StatusNotFound},
			{"refuses_arbitrary_name", http.MethodGet, base + registry.MetadataPath + "?name=@example/anything-at-all", http.StatusNotFound},
			{"refuses_repeated_parameter", http.MethodGet, base + registry.MetadataPath + "?name=community-format&name=@glasswing/release-policy", http.StatusBadRequest},
			{"refuses_unknown_parameter", http.MethodGet, base + registry.MetadataPath + "?name=community-format&mirror=1", http.StatusBadRequest},
		}
		for _, probe := range probes {
			req, err := http.NewRequestWithContext(ctx, probe.method, probe.target, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				rec.add(group, id+"/"+probe.name, false, "%v", err)
				continue
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			rec.add(group, id+"/"+probe.name, resp.StatusCode == probe.want,
				"%s %s → %d (expected %d)", probe.method, redactBase(probe.target, base), resp.StatusCode, probe.want)

			if probe.name == "rejects_write_methods" {
				rec.add(group, id+"/identifies_role_and_revision",
					resp.Header.Get(registry.HeaderRole) == set.Role && resp.Header.Get(registry.HeaderRevision) == set.Revision,
					"role=%q revision=%q", resp.Header.Get(registry.HeaderRole), resp.Header.Get(registry.HeaderRevision))
				label := resp.Header.Get(vulnerable.LabelHeader)
				if set.Vulnerable {
					rec.expectString(group, id+"/every_response_is_labelled", label, vulnerable.Label)
				} else {
					rec.expectString(group, id+"/carries_no_vulnerable_label", label, "")
				}
			}
		}
	}
	return nil
}

func verifyScenario(ctx context.Context, rec *recorder, opts Options, want expectation) (string, error) {
	group := "scenario:" + want.scenario
	scenario, err := fixtures.LoadScenario(want.scenario)
	if err != nil {
		return "", err
	}
	stateDir := filepath.Join(opts.StateDir, "scenarios", want.scenario)
	if err := os.RemoveAll(stateDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}

	out, err := releasegate.Execute(ctx, releasegate.Options{
		Scenario: scenario,
		StateDir: stateDir,
		Dial:     dialer(opts),
	})
	if err != nil {
		return "", err
	}
	if opts.Trace != nil {
		if err := trace.Render(opts.Trace, out); err != nil {
			return "", err
		}
		fmt.Fprintln(opts.Trace)
	}

	rec.expectString(group, "client_result", out.ClientResult, want.clientResult)
	rec.expectString(group, "release_mutation", out.Mutation, want.mutation)
	rec.expectString(group, "policy_verdict", out.Verdict, want.verdict)

	if want.failureClass != "" {
		class, stage := "", ""
		if out.Failure != nil {
			class, stage = out.Failure.Class, out.Failure.Stage
		}
		rec.expectString(group, "failure_class", class, want.failureClass)
		rec.expectString(group, "failure_stage", stage, want.failureStage)
	} else {
		rec.add(group, "no_failure", out.Failure == nil, "%v", out.Failure)
	}

	if want.selectedVersion != "" {
		source, version, integrity := "", "", ""
		if out.ReleasePolicy != nil {
			source = out.ReleasePolicy.Selected.Source
			version = out.ReleasePolicy.Selected.Version
			integrity = out.ReleasePolicy.Integrity
		}
		rec.expectString(group, "selected_source", source, want.selectedSource)
		rec.expectString(group, "selected_version", version, want.selectedVersion)
		rec.expectString(group, "integrity_verdict", integrity, want.wantIntegrity())

		queried := ""
		if out.ReleasePolicy != nil {
			queried = strings.Join(out.ReleasePolicy.Queried, ",")
		}
		rec.expectString(group, "queried_sources", queried, want.wantQueried())
	}

	rec.add(group, "report_format_resolved", (out.ReportFormat != nil) == want.reportResolved,
		"resolved=%v (expected %v)", out.ReportFormat != nil, want.reportResolved)
	if want.reportResolved && out.ReportFormat != nil {
		rec.add(group, "report_format_from_a_public_source",
			out.ReportFormat.Policy.Bound.Role == sourcepolicy.RolePublic,
			"%s (%s)", out.ReportFormat.Selected.Source, out.ReportFormat.Policy.Bound.Role)
	}

	changed := out.LedgerBefore != out.LedgerAfter
	rec.add(group, "ledger_changed", changed == want.ledgerChanged, "changed=%v (expected %v)", changed, want.ledgerChanged)

	current, err := ledger.Load(out.LedgerPath)
	if err != nil {
		return "", err
	}
	rec.add(group, "ledger_entries", len(current.Entries) == want.ledgerEntries,
		"%d entries (expected %d)", len(current.Entries), want.ledgerEntries)
	if want.ledgerEntries == 1 && len(current.Entries) == 1 {
		entry := current.Entries[0]
		rec.expectString(group, "ledger_entry_candidate", entry.CandidateID, scenario.Candidate)
		rec.expectString(group, "ledger_entry_source", entry.PolicySource, want.selectedSource)
		rec.expectString(group, "ledger_entry_version", entry.PolicyVersion, want.selectedVersion)
	}
	if !want.ledgerChanged {
		fresh, err := ledger.Fresh().Bytes()
		if err != nil {
			return "", err
		}
		onDisk, err := os.ReadFile(out.LedgerPath)
		if err != nil {
			return "", err
		}
		rec.add(group, "ledger_byte_identical_to_fresh", string(fresh) == string(onDisk),
			"%d bytes on disk", len(onDisk))
	}

	events := make([]string, 0, len(out.AuditEvents))
	for _, e := range out.AuditEvents {
		events = append(events, e.Event)
	}
	rec.add(group, "audit_events", strings.Join(events, ",") == strings.Join(want.auditEvents, ","),
		"[%s] (expected [%s])", strings.Join(events, ","), strings.Join(want.auditEvents, ","))

	persisted, err := audit.Read(filepath.Join(stateDir, releasegate.AuditFile))
	if err != nil {
		return "", err
	}
	rec.add(group, "audit_records_persisted", len(persisted) == len(want.auditEvents),
		"%d records on disk (expected %d)", len(persisted), len(want.auditEvents))
	for _, e := range persisted {
		if e.CorrelationID != audit.CorrelationID(scenario.ID) {
			rec.add(group, "audit_correlation_id", false, "%q", e.CorrelationID)
		}
	}

	response, err := out.ClientResponse()
	if err != nil {
		return "", err
	}
	return string(response), nil
}

// verifyHarness runs one scenario through the harness and checks the whole
// transcript: that it is byte-identical when the scenario is run again, that
// each registry's own signed receipt matches the expected request count, and
// that the run reconciles the way it should.
func verifyHarness(ctx context.Context, rec *recorder, opts Options, want expectation) error {
	group := "harness:" + want.scenario

	first, err := harness.Run(ctx, harness.Options{
		ScenarioID: want.scenario,
		StateDir:   filepath.Join(opts.StateDir, "harness", want.scenario, "first"),
		Endpoints:  opts.Endpoints,
	})
	if err != nil {
		return err
	}
	second, err := harness.Run(ctx, harness.Options{
		ScenarioID: want.scenario,
		StateDir:   filepath.Join(opts.StateDir, "harness", want.scenario, "second"),
		Endpoints:  opts.Endpoints,
	})
	if err != nil {
		return err
	}

	firstBody, err := first.Bytes()
	if err != nil {
		return err
	}
	secondBody, err := second.Bytes()
	if err != nil {
		return err
	}
	rec.add(group, "transcript_byte_identical_between_runs", string(firstBody) == string(secondBody),
		"%d bytes", len(firstBody))

	transcriptPath := filepath.Join(opts.StateDir, "harness", want.scenario, "first", harness.TranscriptFile)
	onDisk, err := os.ReadFile(transcriptPath)
	if err != nil {
		return err
	}
	rec.add(group, "transcript_artifact_written", string(onDisk) == string(firstBody), "%d bytes on disk", len(onDisk))

	rec.expectString(group, "reconciliation", first.Reconciliation.Result, want.reconciliation)
	rec.expectString(group, "client_result", first.ClientResponse.Result, want.clientResult)
	rec.expectString(group, "policy_verdict", first.Release.PolicyVerdict, want.verdict)
	rec.add(group, "ledger_changed", first.Ledger.Changed == want.ledgerChanged,
		"changed=%v (expected %v)", first.Ledger.Changed, want.ledgerChanged)

	// Each registry's own account of the run, including the ones that were
	// meant to hear nothing at all.
	observed := make(map[string]int, len(first.Receipts))
	for _, receipt := range first.Receipts {
		observed[receipt.Source] = receipt.RequestCount
		rec.add(group, "receipt_signed/"+receipt.Source, receipt.SignatureVerified,
			"signature verified=%v", receipt.SignatureVerified)
		if receipt.Role == sourcepolicy.RolePublic {
			for _, request := range receipt.Requests {
				if !strings.HasPrefix(request.Name, "@glasswing/") {
					continue
				}
				// A public source being asked about the private namespace is
				// the flaw itself: forbidden everywhere except in the run that
				// exists to demonstrate it.
				rec.add(group, "public_registry_asked_about_private_namespace", first.Scenario.Vulnerable,
					"%s was asked for %q", receipt.Source, request.Name)
			}
		}
	}
	for source, count := range want.receipts {
		got, ok := observed[source]
		rec.add(group, "observed_requests/"+source, ok && got == count,
			"%d request(s) (expected %d)", got, count)
	}
	publicTotal := 0
	for _, receipt := range first.Receipts {
		if receipt.Role == sourcepolicy.RolePublic {
			publicTotal += receipt.RequestCount
		}
	}
	if want.clientResult == releasegate.ResultBuildFailed {
		rec.add(group, "no_public_request_after_failing_closed", publicTotal == 0,
			"%d public request(s)", publicTotal)
	}
	if !first.Scenario.Vulnerable {
		privateNamespaceAtPublic := 0
		for _, receipt := range first.Receipts {
			if receipt.Role != sourcepolicy.RolePublic {
				continue
			}
			for _, request := range receipt.Requests {
				if strings.HasPrefix(request.Name, "@glasswing/") {
					privateNamespaceAtPublic++
				}
			}
		}
		rec.add(group, "private_namespace_never_reaches_a_public_source", privateNamespaceAtPublic == 0,
			"%d such request(s)", privateNamespaceAtPublic)
	}

	// A transcript is evidence a learner reads and a reviewer publishes. It must
	// carry no credential, no address, and no package content.
	boundary, err := fixtures.ReceiptBoundary()
	if err != nil {
		return err
	}
	leaks := []string{"://", boundary.Credential, boundary.SigningKey, "BEGIN PRIVATE KEY", "password"}
	leaked := ""
	for _, needle := range leaks {
		if needle != "" && strings.Contains(string(firstBody), needle) {
			leaked = needle
		}
	}
	rec.add(group, "transcript_carries_no_credential_or_address", leaked == "",
		"%s", valueOr(leaked, "no credential, address, or package content in the transcript"))
	return nil
}

// verifyHarnessSurface checks what the harness refuses and that its matrix
// covers every enumerated scenario.
func verifyHarnessSurface(ctx context.Context, rec *recorder, opts Options) error {
	const group = "harness-surface"

	for _, id := range []string{"", "anything", "../locks/default", "secure-unsafe-candidate "} {
		_, err := harness.Run(ctx, harness.Options{
			ScenarioID: id,
			StateDir:   filepath.Join(opts.StateDir, "harness", "refused"),
			Endpoints:  opts.Endpoints,
		})
		rec.add(group, "refuses_unenumerated_scenario", errors.Is(err, harness.ErrUnknownScenario),
			"%q → %v", id, err)
	}

	transcripts, err := harness.Matrix(ctx, harness.Options{
		StateDir:  filepath.Join(opts.StateDir, "harness", "matrix"),
		Endpoints: opts.Endpoints,
	})
	if err != nil {
		return err
	}
	ids, err := fixtures.DefaultScenarioIDs()
	if vulnerable.Acknowledged() {
		ids, err = fixtures.ScenarioIDs()
	}
	if err != nil {
		return err
	}
	covered := make([]string, 0, len(transcripts))
	for _, t := range transcripts {
		covered = append(covered, t.Scenario.ID)
	}
	rec.add(group, "matrix_covers_every_reachable_scenario", strings.Join(covered, ",") == strings.Join(ids, ","),
		"[%s]", strings.Join(covered, ","))

	if opts.Trace != nil {
		if err := harness.RenderMatrix(opts.Trace, transcripts); err != nil {
			return err
		}
		fmt.Fprintln(opts.Trace)
	}
	return nil
}

// verifyOptIn asserts the two controls themselves: each one alone refuses, both
// together admit, and in a run that has not acknowledged anything the
// vulnerable half is not merely refused but absent.
func verifyOptIn(ctx context.Context, rec *recorder, opts Options) error {
	const group = "opt-in"

	for _, c := range []struct {
		name            string
		acknowledgement string
		profile         string
		wantErr         bool
	}{
		{"neither_control", "", "", true},
		{"acknowledgement_alone", vulnerable.Acknowledgement, "", true},
		{"profile_alone", "", vulnerable.Profile, true},
		{"both_controls", vulnerable.Acknowledgement, vulnerable.Profile, false},
	} {
		err := vulnerable.Check(c.acknowledgement, c.profile)
		rec.add(group, c.name, (err != nil) == c.wantErr, "%v", valueOr(errText(err), "admitted"))
	}

	acknowledged := vulnerable.Acknowledged()
	rec.add(group, "acknowledged_in_this_run", true, "%t", acknowledged)

	defaults, err := fixtures.DefaultScenarioIDs()
	if err != nil {
		return err
	}
	all, err := fixtures.ScenarioIDs()
	if err != nil {
		return err
	}
	rec.add(group, "vulnerable_scenarios_are_separate", len(all) > len(defaults),
		"%d reachable by default, %d in total", len(defaults), len(all))

	for _, scenario := range all {
		loaded, err := fixtures.LoadScenario(scenario)
		if err != nil {
			return err
		}
		if !loaded.Vulnerable {
			continue
		}
		if acknowledged {
			continue
		}
		_, err = harness.Run(ctx, harness.Options{
			ScenarioID: scenario,
			StateDir:   filepath.Join(opts.StateDir, "opt-in", scenario),
			Endpoints:  opts.Endpoints,
		})
		rec.add(group, "refused/"+scenario, errors.Is(err, vulnerable.ErrNotAcknowledged), "%v", err)
	}
	return nil
}

// verifyPublicShadowImpact asserts the demonstration's central claim: under the
// combined-index resolver the public shadow decides the release, and the bytes
// that decided it are the public fixture's.
func verifyPublicShadowImpact(ctx context.Context, rec *recorder, opts Options) error {
	const group = "public-shadow"

	transcript, err := harness.Run(ctx, harness.Options{
		ScenarioID: "vulnerable-public-shadow",
		StateDir:   filepath.Join(opts.StateDir, "public-shadow"),
		Endpoints:  opts.Endpoints,
	})
	if err != nil {
		return err
	}
	artifacts, err := fixtures.Artifacts()
	if err != nil {
		return err
	}
	shadowDigest, privateDigest := "", ""
	for _, a := range artifacts {
		switch a.Package {
		case "release-policy-9.9.9-public-shadow":
			shadowDigest = a.SHA256
		case "release-policy-1.4.2":
			privateDigest = a.SHA256
		}
	}

	if len(transcript.Dependencies) == 0 {
		rec.add(group, "resolved_the_policy_dependency", false, "no dependency recorded")
		return nil
	}
	dep := transcript.Dependencies[0]

	offered := map[string]string{}
	for _, c := range dep.Candidates {
		offered[c.Source] = c.Version
	}
	rec.add(group, "both_trust_domains_offered_the_same_name",
		offered["glasswing-private"] != "" && offered["community-public-shadow"] == "9.9.9",
		"private %s, public %s", valueOr(offered["glasswing-private"], "none"), valueOr(offered["community-public-shadow"], "none"))
	rec.expectString(group, "highest_version_wins", dep.Selected.Version, "9.9.9")
	rec.expectString(group, "selected_origin_is_public", dep.Selected.Role, sourcepolicy.RolePublic)
	rec.expectString(group, "selected_bytes_are_the_public_fixture", dep.Selected.SHA256, shadowDigest)
	rec.add(group, "selected_bytes_are_not_the_private_artifact", dep.Selected.SHA256 != privateDigest,
		"%s", dep.Selected.SHA256)
	rec.expectString(group, "no_lock_was_enforced", transcript.LockEnforcement, harness.LockUnenforced)
	rec.expectString(group, "transcript_is_labelled", transcript.Warning, vulnerable.Label)
	rec.expectString(group, "unsafe_candidate_approved", transcript.Release.PolicyVerdict, pkgarchive.VerdictApprove)
	rec.add(group, "exactly_one_unexpected_release_row",
		transcript.Ledger.Changed && transcript.Ledger.Entries == 1,
		"changed=%v entries=%d", transcript.Ledger.Changed, transcript.Ledger.Entries)
	rec.expectString(group, "reconciliation_fails", transcript.Reconciliation.Result, harness.ReconcileFail)
	rec.expectString(group, "reconciliation_names_the_origin", transcript.Reconciliation.Origin, "community-public-shadow")
	rec.expectString(group, "reconciliation_names_the_digest", transcript.Reconciliation.Digest, shadowDigest)

	askedForShadow := false
	for _, receipt := range transcript.Receipts {
		if receipt.Source != "community-public-shadow" {
			continue
		}
		for _, request := range receipt.Requests {
			if request.Name == "@glasswing/release-policy" && request.Version == "9.9.9" {
				askedForShadow = true
			}
		}
	}
	rec.add(group, "receipts_prove_the_public_fixture_served_it", askedForShadow,
		"the public fixture reports serving @glasswing/release-policy@9.9.9")
	return nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func dialer(opts Options) func(sourcepolicy.Source) (resolver.Fetcher, error) {
	if len(opts.Endpoints) == 0 {
		return nil
	}
	return func(source sourcepolicy.Source) (resolver.Fetcher, error) {
		return registry.NewClient(endpoint(opts, source.URL))
	}
}

func endpoint(opts Options, checkedIn string) string {
	if replacement, ok := opts.Endpoints[checkedIn]; ok {
		return replacement
	}
	return checkedIn
}

func redactBase(target, base string) string { return strings.TrimPrefix(target, base) }

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
