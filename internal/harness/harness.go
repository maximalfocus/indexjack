// Package harness runs one enumerated scenario and records the whole causal
// chain behind its outcome.
//
// The transcript is the teaching artifact. It answers, in one place and in a
// fixed order: what was requested, what policy said about where it could come
// from, which registries were actually asked — according to those registries —
// what they offered, what was selected, whether the bytes matched the lock,
// what the selected artifact then said about a release, and what actually
// changed as a result.
//
// Two properties make it evidence rather than narration. It is deterministic:
// the same scenario produces byte-identical transcripts, so assertions can be
// exact. And its query set is observed at the registry boundary rather than
// self-reported, so "the public registry was never asked" is something the
// public registry says about itself.
package harness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"indexjack/internal/audit"
	"indexjack/internal/canonicaljson"
	"indexjack/internal/fixtures"
	"indexjack/internal/pkgarchive"
	"indexjack/internal/registry"
	"indexjack/internal/releasegate"
	"indexjack/internal/resolver"
	"indexjack/internal/sourcepolicy"
	"indexjack/internal/vulnerable"
)

// Format is the transcript document version.
const Format = "indexjack-transcript/1"

// Reconciliation results.
const (
	ReconcilePass = "PASS"
	ReconcileFail = "FAIL"
)

// TranscriptFile is where a run's machine-readable transcript is written inside
// the run's disposable state directory.
const TranscriptFile = "transcript.json"

// ErrUnknownScenario reports a scenario id that is not checked in.
var ErrUnknownScenario = errors.New("unknown scenario")

// Request is what the project asked for.
type Request struct {
	Name  string `json:"name"`
	Range string `json:"range"`
}

// SourcePolicy is what policy decided about where it may come from.
type SourcePolicy struct {
	Pattern string `json:"pattern"`
	Mode    string `json:"mode"`
	// Bound is the single source of an exclusive mapping, and empty under a
	// combined one — where nothing is bound, which is the point.
	Bound string `json:"bound"`
	// Pool is every source the mapping considers.
	Pool     []string `json:"pool"`
	Excluded []string `json:"excluded"`
}

// Candidate is one version a queried source offered.
type Candidate struct {
	Source  string `json:"source"`
	Version string `json:"version"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// Selected is the artifact that was chosen and verified.
type Selected struct {
	Source  string `json:"source"`
	Role    string `json:"role"`
	Version string `json:"version"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// Dependency is one dependency's complete resolution record.
type Dependency struct {
	Alias             string       `json:"alias"`
	Request           Request      `json:"request"`
	SourcePolicy      SourcePolicy `json:"source_policy"`
	IndexDisplayOrder []string     `json:"index_display_order"`
	QueriedSources    []string     `json:"queried_sources"`
	Candidates        []Candidate  `json:"candidates"`
	SelectionRule     string       `json:"selection_rule"`
	Selected          Selected     `json:"selected"`
	Integrity         string       `json:"integrity_verdict"`
}

// Failure is a build failure's local operator evidence. It is never what the
// build's consumer is told.
type Failure struct {
	Class string `json:"class"`
	Stage string `json:"stage"`
}

// Release is what the selected artifact decided, and what the gate already knew.
type Release struct {
	Candidate          string `json:"candidate"`
	GateClassification string `json:"gate_classification"`
	PolicyVerdict      string `json:"policy_verdict"`
	Mutation           string `json:"mutation"`
}

// Ledger is the release ledger before and after the run.
type Ledger struct {
	Before  string `json:"before"`
	After   string `json:"after"`
	Changed bool   `json:"changed"`
	Entries int    `json:"entries"`
}

// AuditRecord is one structured audit event, without its per-run correlation
// noise: the correlation id is recorded once for the whole run.
type AuditRecord struct {
	Event        string `json:"event"`
	Stage        string `json:"stage"`
	FailureClass string `json:"failure_class,omitempty"`
	Candidate    string `json:"candidate_id,omitempty"`
	Alias        string `json:"dependency_alias,omitempty"`
}

// RegistryReceipt is one registry's own account of what this run asked it.
//
// The receipt's signature and run id are verified when it is collected but are
// deliberately not recorded here: both are per-execution values, and a
// transcript that carried them could not be byte-identical between runs.
type RegistryReceipt struct {
	Source            string             `json:"source"`
	Role              string             `json:"role"`
	Revision          string             `json:"revision"`
	RequestCount      int                `json:"request_count"`
	Requests          []registry.Request `json:"requests"`
	SignatureVerified bool               `json:"signature_verified"`
}

// Reconciliation is the run's final verdict: does what happened match what
// should have happened?
type Reconciliation struct {
	Result    string `json:"result"`
	Statement string `json:"statement"`
	Origin    string `json:"origin,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

// ClientResponse is what the build returned to its consumer.
type ClientResponse struct {
	Format string `json:"format"`
	Result string `json:"result"`
}

// Scenario is the enumerated scenario a transcript describes.
type Scenario struct {
	ID           string `json:"id"`
	Summary      string `json:"summary"`
	SourcePolicy string `json:"source_policy"`
	Manifest     string `json:"manifest"`
	Lock         string `json:"lock"`
	Candidate    string `json:"candidate"`
	Vulnerable   bool   `json:"vulnerable"`
}

// Lock enforcement, as recorded in a transcript.
const (
	LockEnforced   = "exact source, version, size and digest"
	LockUnenforced = "none"
)

// Transcript is one run, in full.
type Transcript struct {
	Format   string   `json:"format"`
	Scenario Scenario `json:"scenario"`
	// Resolver names the resolution model, LockEnforcement says whether
	// artifact identity was checked at all, and Warning is set on everything
	// the intentionally vulnerable half produces.
	Resolver        string            `json:"resolver"`
	LockEnforcement string            `json:"lock_enforcement"`
	Warning         string            `json:"warning,omitempty"`
	Project         string            `json:"project"`
	CorrelationID   string            `json:"correlation_id"`
	Dependencies    []Dependency      `json:"dependencies"`
	Failure         *Failure          `json:"failure"`
	Release         Release           `json:"release"`
	Ledger          Ledger            `json:"ledger"`
	Audit           []AuditRecord     `json:"audit"`
	Receipts        []RegistryReceipt `json:"registry_receipts"`
	ClientResponse  ClientResponse    `json:"client_response"`
	Reconciliation  Reconciliation    `json:"reconciliation"`
}

// Bytes renders the transcript in its canonical machine-readable form.
func (t *Transcript) Bytes() ([]byte, error) { return canonicaljson.Marshal(t) }

// Options configures one harness run.
type Options struct {
	// ScenarioID is the only input the harness accepts. It must be one of the
	// checked-in enumerated ids.
	ScenarioID string
	// StateDir is the run's disposable directory.
	StateDir string
	// Endpoints replaces checked-in registry URLs, keyed by checked-in URL, so
	// in-process verification can reach loopback fixtures. It cannot change
	// which source a name is bound to.
	Endpoints map[string]string
}

// Run executes one enumerated scenario and returns its transcript.
func Run(ctx context.Context, opts Options) (*Transcript, error) {
	scenario, err := fixtures.LoadScenario(opts.ScenarioID)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownScenario, opts.ScenarioID)
	}
	if scenario.Vulnerable {
		if err := vulnerable.Gate(); err != nil {
			return nil, err
		}
	}
	if opts.StateDir == "" {
		return nil, errors.New("the harness requires a state directory")
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, err
	}

	boundary, err := fixtures.ReceiptBoundary()
	if err != nil {
		return nil, err
	}
	// One execution, one run id. It is never printed and never recorded: it
	// exists so a registry can separate this execution's requests from any
	// other's, including a previous execution of the same scenario.
	runID, err := newRunID()
	if err != nil {
		return nil, err
	}

	outcome, err := releasegate.Execute(ctx, releasegate.Options{
		Scenario: scenario,
		StateDir: opts.StateDir,
		Dial: func(source sourcepolicy.Source) (resolver.Fetcher, error) {
			return registry.NewClient(endpoint(opts.Endpoints, source.URL), registry.WithRunID(runID))
		},
	})
	if err != nil {
		return nil, err
	}

	receipts, err := collectReceipts(ctx, opts.Endpoints, runID, boundary)
	if err != nil {
		return nil, err
	}

	transcript := build(scenario, outcome, receipts)
	body, err := transcript.Bytes()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(opts.StateDir, TranscriptFile), body, 0o600); err != nil {
		return nil, err
	}
	return transcript, nil
}

func newRunID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func endpoint(endpoints map[string]string, checkedIn string) string {
	if replacement, ok := endpoints[checkedIn]; ok {
		return replacement
	}
	return checkedIn
}

// collectReceipts asks every checked-in registry — not only the ones this run
// expected to use — what it was asked. A registry that saw nothing has to say
// so, in its own signed words.
func collectReceipts(ctx context.Context, endpoints map[string]string, runID string, boundary registry.ReceiptConfig) ([]RegistryReceipt, error) {
	urls, err := fixtures.RegistryURLs()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(urls))
	for id := range urls {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	acknowledged := vulnerable.Acknowledged()
	out := make([]RegistryReceipt, 0, len(ids))
	for _, id := range ids {
		set, err := fixtures.RegistrySet(id)
		if err != nil {
			return nil, err
		}
		// A registry from the vulnerable half is not running in an
		// unacknowledged workflow, so there is nothing to ask.
		if set.Vulnerable && !acknowledged {
			continue
		}
		client, err := registry.NewClient(endpoint(endpoints, urls[id]))
		if err != nil {
			return nil, err
		}
		receipt, err := client.Receipt(ctx, runID, boundary.Credential)
		if err != nil {
			return nil, fmt.Errorf("registry %q receipt: %w", id, err)
		}
		if receipt.Source != id {
			return nil, fmt.Errorf("registry %q returned a receipt claiming to be from %q", id, receipt.Source)
		}
		out = append(out, RegistryReceipt{
			Source:            receipt.Source,
			Role:              receipt.Role,
			Revision:          receipt.Revision,
			RequestCount:      receipt.RequestCount,
			Requests:          receipt.Requests,
			SignatureVerified: registry.VerifyReceipt(receipt, boundary.SigningKey),
		})
	}
	return out, nil
}

func build(scenario fixtures.Scenario, outcome *releasegate.Outcome, receipts []RegistryReceipt) *Transcript {
	t := &Transcript{
		Format: Format,
		Scenario: Scenario{
			ID:           scenario.ID,
			Summary:      scenario.Summary,
			SourcePolicy: scenario.SourcePolicy,
			Manifest:     scenario.Manifest,
			Lock:         scenario.Lock,
			Candidate:    scenario.Candidate,
			Vulnerable:   scenario.Vulnerable,
		},
		Resolver:        outcome.Resolver,
		LockEnforcement: lockEnforcement(outcome),
		Warning:         warning(scenario),
		Project:         outcome.Project,
		CorrelationID:   audit.CorrelationID(scenario.ID),
		Dependencies:    []Dependency{},
		Release: Release{
			Candidate:          scenario.Candidate,
			GateClassification: outcome.Classification,
			PolicyVerdict:      outcome.Verdict,
			Mutation:           outcome.Mutation,
		},
		Ledger: Ledger{
			Before:  outcome.LedgerBefore,
			After:   outcome.LedgerAfter,
			Changed: outcome.LedgerBefore != outcome.LedgerAfter,
		},
		Audit:          []AuditRecord{},
		Receipts:       receipts,
		ClientResponse: ClientResponse{Format: releasegate.ClientResponseFormat, Result: outcome.ClientResult},
	}

	for _, res := range outcome.Resolutions {
		t.Dependencies = append(t.Dependencies, dependencyRecord(res, nil))
	}
	// The dependency a failed build stopped on is part of the trace: it is the
	// one whose policy, query set and candidates explain the failure.
	if outcome.Attempted != nil {
		t.Dependencies = append(t.Dependencies, dependencyRecord(outcome.Attempted, outcome.Failure))
	}

	if outcome.Failure != nil {
		t.Failure = &Failure{Class: outcome.Failure.Class, Stage: outcome.Failure.Stage}
	}
	for _, e := range outcome.AuditEvents {
		t.Audit = append(t.Audit, AuditRecord{
			Event:        e.Event,
			Stage:        e.Stage,
			FailureClass: e.FailureClass,
			Candidate:    e.CandidateID,
			Alias:        e.DependencyAlias,
		})
	}
	t.Ledger.Entries = ledgerEntries(outcome)
	t.Reconciliation = reconcile(outcome)
	return t
}

// Integrity verdicts for a dependency whose content was never read: either
// verification was never reached, or it was reached and refused the bytes.
const (
	IntegrityNotReached = "not_reached"
	IntegrityRejected   = "rejected"
)

func dependencyRecord(res *resolver.Resolution, failure *resolver.Failure) Dependency {
	dep := Dependency{
		Alias:   res.Alias,
		Request: Request{Name: res.Name, Range: res.Range},
		SourcePolicy: SourcePolicy{
			Pattern:  res.Policy.Pattern,
			Mode:     res.Policy.Mode,
			Bound:    res.Policy.Bound.ID,
			Pool:     poolOf(res.Policy),
			Excluded: res.Excluded,
		},
		IndexDisplayOrder: res.DisplayOrder,
		QueriedSources:    res.Queried,
		Candidates:        []Candidate{},
		SelectionRule:     res.SelectionRule,
		Selected: Selected{
			Source:  res.Selected.Source,
			Version: res.Selected.Version,
			Size:    res.Size,
			SHA256:  res.Digest,
		},
		Integrity: res.Integrity,
	}
	// The role belongs to the origin that was actually selected, which under a
	// combined mapping is not the same thing as the bound source — there is no
	// bound source.
	if res.Selected.Source != "" {
		dep.Selected.Role = roleOf(res.Policy, res.Selected.Source)
	}
	if dep.Integrity == "" {
		dep.Integrity = IntegrityNotReached
		if failure != nil && failure.Stage == resolver.StageIntegrity {
			// The bytes were fetched and compared against the lock, and lost.
			// That is a different fact from never getting that far.
			dep.Integrity = IntegrityRejected
		}
	}
	if dep.SourcePolicy.Excluded == nil {
		dep.SourcePolicy.Excluded = []string{}
	}
	if dep.IndexDisplayOrder == nil {
		dep.IndexDisplayOrder = []string{}
	}
	if dep.QueriedSources == nil {
		dep.QueriedSources = []string{}
	}
	for _, c := range res.Candidates {
		dep.Candidates = append(dep.Candidates, Candidate{
			Source:  c.Source,
			Version: c.Version,
			Size:    c.Size,
			SHA256:  c.SHA256,
		})
	}
	return dep
}

func poolOf(decision sourcepolicy.Decision) []string {
	out := make([]string, 0, len(decision.Pool))
	for _, s := range decision.Pool {
		out = append(out, s.ID)
	}
	return out
}

func roleOf(decision sourcepolicy.Decision, sourceID string) string {
	for _, s := range decision.Pool {
		if s.ID == sourceID {
			return s.Role
		}
	}
	if decision.Bound.ID == sourceID {
		return decision.Bound.Role
	}
	return ""
}

func lockEnforcement(outcome *releasegate.Outcome) string {
	if outcome.LockEnforced {
		return LockEnforced
	}
	return LockUnenforced
}

func warning(scenario fixtures.Scenario) string {
	if scenario.Vulnerable {
		return vulnerable.Label
	}
	return ""
}

func ledgerEntries(outcome *releasegate.Outcome) int {
	switch outcome.Mutation {
	case releasegate.MutationApproved, releasegate.MutationSuppressed:
		return 1
	default:
		return 0
	}
}

// reconcile compares three things that are allowed to disagree: what the
// resolved dependency said, what the release gate already knew, and what
// actually changed on disk. Agreement is the only pass.
func reconcile(outcome *releasegate.Outcome) Reconciliation {
	origin, digest := "", ""
	if outcome.ReleasePolicy != nil {
		origin = outcome.ReleasePolicy.Selected.Source
		digest = outcome.ReleasePolicy.Digest
	}
	changed := outcome.LedgerBefore != outcome.LedgerAfter

	if outcome.Failed() {
		if changed {
			return Reconciliation{
				Result:    ReconcileFail,
				Statement: "the build failed but the release ledger changed",
				Origin:    origin, Digest: digest,
			}
		}
		return Reconciliation{
			Result:    ReconcilePass,
			Statement: "build failed closed; no package policy was read and no release was recorded",
		}
	}

	unsafe := outcome.Classification == fixtures.ClassificationKnownUnsafe
	switch {
	case outcome.Verdict == pkgarchive.VerdictApprove && unsafe:
		// The selected dependency approved something the gate itself knows is
		// unsafe. Whatever else is true, the artifact that decided this was not
		// the one the project meant to trust.
		return Reconciliation{
			Result:    ReconcileFail,
			Statement: "untrusted origin influenced release approval",
			Origin:    origin, Digest: digest,
		}
	case outcome.Verdict == pkgarchive.VerdictReject && unsafe:
		if changed {
			return Reconciliation{
				Result:    ReconcileFail,
				Statement: "the candidate was rejected but the release ledger changed",
				Origin:    origin, Digest: digest,
			}
		}
		return Reconciliation{
			Result:    ReconcilePass,
			Statement: "intended private artifact selected; unsafe candidate not released",
			Origin:    origin, Digest: digest,
		}
	case outcome.Verdict == pkgarchive.VerdictApprove && !unsafe:
		if !changed && outcome.Mutation != releasegate.MutationSuppressed {
			return Reconciliation{
				Result:    ReconcileFail,
				Statement: "the candidate was approved but no release was recorded",
				Origin:    origin, Digest: digest,
			}
		}
		return Reconciliation{
			Result:    ReconcilePass,
			Statement: "intended private artifact selected; release-ready candidate released exactly once",
			Origin:    origin, Digest: digest,
		}
	case outcome.Verdict == pkgarchive.VerdictReject && !unsafe:
		return Reconciliation{
			Result:    ReconcileFail,
			Statement: "a release-ready candidate was rejected by the selected policy artifact",
			Origin:    origin, Digest: digest,
		}
	}
	return Reconciliation{
		Result:    ReconcileFail,
		Statement: "the run produced no policy verdict to reconcile",
		Origin:    origin, Digest: digest,
	}
}
