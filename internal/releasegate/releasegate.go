// Package releasegate runs one enumerated scenario end to end: resolve the
// project's dependencies, ask the selected release-policy artifact about one
// enumerated candidate, and change the release ledger only when that artifact
// says APPROVE.
//
// The gate's own classification of a candidate is deliberately kept out of the
// approval decision. The gate does what its dependency tells it, which is
// precisely why which artifact it resolved matters.
package releasegate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"indexjack/internal/audit"
	"indexjack/internal/canonicaljson"
	"indexjack/internal/fixtures"
	"indexjack/internal/ledger"
	"indexjack/internal/pkgarchive"
	"indexjack/internal/resolver"
	"indexjack/internal/sourcepolicy"
)

// Dependency aliases the gate expects a scenario manifest to declare.
const (
	AliasReleasePolicy = "release-policy"
	AliasReportFormat  = "report-format"
)

// Client-visible results. A failure is always exactly this, with no detail:
// a build must not become an oracle for what exists in a private registry.
const (
	ResultBuildOK     = "BUILD_OK"
	ResultBuildFailed = "BUILD_FAILED"
)

// Ledger mutations.
const (
	MutationNone       = "none"
	MutationApproved   = "approved"
	MutationSuppressed = "suppressed-duplicate"
)

// Gate-stage failure classes, using the same shape as resolution failures.
const (
	StagePolicyEvaluation       = "policy_evaluation"
	ClassPolicyCandidateUnknown = "POLICY_CANDIDATE_UNKNOWN"
	ClassPolicyKindUnexpected   = "POLICY_KIND_UNEXPECTED"
)

// State file names inside the run's disposable state directory.
const (
	LedgerFile = "ledger.json"
	AuditFile  = "audit.jsonl"
)

// Options configures one run.
type Options struct {
	Scenario fixtures.Scenario
	StateDir string
	// Dial is the resolver's source dialler; nil uses the ordinary read-only
	// registry client.
	Dial func(sourcepolicy.Source) (resolver.Fetcher, error)
	// AuditMirror receives a copy of each audit record, usually stderr.
	AuditMirror io.Writer
}

// Outcome is everything one run observed.
type Outcome struct {
	Scenario      fixtures.Scenario
	ClientResult  string
	Project       string
	Resolutions   []*resolver.Resolution
	ReleasePolicy *resolver.Resolution
	ReportFormat  *resolver.Resolution
	// Attempted is the dependency the build failed on, as far as resolution
	// got. It records what was asked and who was contacted even though nothing
	// was accepted.
	Attempted      *resolver.Resolution
	Verdict        string
	Classification string
	Mutation       string
	LedgerPath     string
	LedgerBefore   string
	LedgerAfter    string
	AuditEvents    []audit.Event
	Failure        *resolver.Failure
}

// Failed reports whether the build failed closed.
func (o *Outcome) Failed() bool { return o.ClientResult == ResultBuildFailed }

// ClientResponseFormat is the version of the response a build's consumer sees.
const ClientResponseFormat = "indexjack-build-result/1"

type clientResponse struct {
	Format string `json:"format"`
	Result string `json:"result"`
}

// ClientResponse is everything the build returns to its consumer: a result and
// nothing else.
//
// Two different failures must produce byte-identical responses. A response that
// distinguished "no such package" from "that package's bytes were wrong" would
// turn every build into an oracle for what a private registry contains.
func (o *Outcome) ClientResponse() ([]byte, error) {
	return canonicaljson.Marshal(clientResponse{Format: ClientResponseFormat, Result: o.ClientResult})
}

// Execute runs one scenario.
func Execute(ctx context.Context, opts Options) (*Outcome, error) {
	if opts.StateDir == "" {
		return nil, errors.New("release gate requires a state directory")
	}
	ledgerPath := filepath.Join(opts.StateDir, LedgerFile)
	auditPath := filepath.Join(opts.StateDir, AuditFile)
	sink := audit.NewSink(auditPath, opts.Scenario.ID, opts.AuditMirror)

	current, err := ledger.Load(ledgerPath)
	if err != nil {
		return nil, err
	}
	before, err := ledger.Digest(ledgerPath)
	if err != nil {
		return nil, err
	}

	out := &Outcome{
		Scenario:     opts.Scenario,
		LedgerPath:   ledgerPath,
		LedgerBefore: before,
		LedgerAfter:  before,
		Mutation:     MutationNone,
	}

	policy, err := fixtures.SourcePolicy(opts.Scenario.SourcePolicy)
	if err != nil {
		return nil, err
	}
	manifest, err := fixtures.BuildManifest(opts.Scenario.Manifest)
	if err != nil {
		return nil, err
	}
	lock, err := fixtures.Lock(opts.Scenario.Lock)
	if err != nil {
		return nil, err
	}
	classifications, err := fixtures.Classifications()
	if err != nil {
		return nil, err
	}
	if _, err := fixtures.LoadCandidate(opts.Scenario.Candidate); err != nil {
		return nil, err
	}
	out.Project = manifest.Project
	out.Classification = classifications[opts.Scenario.Candidate]

	cfg := resolver.Config{Policy: policy, Lock: lock, Dial: opts.Dial}

	// Dependencies resolve in declaration order and the build stops at the
	// first failure. Nothing after the failure is fetched, which is why a
	// failed private resolution reaches no other source at all.
	for _, dep := range manifest.Dependencies {
		resolution, err := resolver.Resolve(ctx, cfg, dep)
		if err != nil {
			failure, ok := resolver.AsFailure(err)
			if !ok {
				return nil, err
			}
			out.ClientResult = ResultBuildFailed
			out.Failure = failure
			out.Attempted = resolution
			if emitErr := sink.Emit(audit.Event{
				Event:           audit.EventBuildFailed,
				Stage:           failure.Stage,
				DependencyAlias: dep.Alias,
				FailureClass:    failure.Class,
			}); emitErr != nil {
				return nil, emitErr
			}
			out.AuditEvents = sink.Emitted()
			return out, nil
		}
		out.Resolutions = append(out.Resolutions, resolution)
		switch dep.Alias {
		case AliasReleasePolicy:
			out.ReleasePolicy = resolution
		case AliasReportFormat:
			out.ReportFormat = resolution
		}
	}

	if out.ReleasePolicy == nil {
		return nil, fmt.Errorf("scenario %q manifest declares no %q dependency", opts.Scenario.ID, AliasReleasePolicy)
	}
	out.ClientResult = ResultBuildOK

	policyPkg := out.ReleasePolicy.Package
	if policyPkg.Policy.Kind != pkgarchive.KindReleasePolicy {
		out.ClientResult = ResultBuildFailed
		out.Failure = &resolver.Failure{
			Class: ClassPolicyKindUnexpected,
			Stage: StagePolicyEvaluation,
			Err:   fmt.Errorf("release policy artifact declares kind %q", policyPkg.Policy.Kind),
		}
		if err := sink.Emit(audit.Event{
			Event:           audit.EventBuildFailed,
			Stage:           StagePolicyEvaluation,
			DependencyAlias: AliasReleasePolicy,
			FailureClass:    ClassPolicyKindUnexpected,
		}); err != nil {
			return nil, err
		}
		out.AuditEvents = sink.Emitted()
		return out, nil
	}

	verdict, ok := policyPkg.Policy.Lookup(opts.Scenario.Candidate)
	if !ok {
		out.ClientResult = ResultBuildFailed
		out.Failure = &resolver.Failure{
			Class: ClassPolicyCandidateUnknown,
			Stage: StagePolicyEvaluation,
			Err:   fmt.Errorf("release policy has no entry for %q", opts.Scenario.Candidate),
		}
		if err := sink.Emit(audit.Event{
			Event:           audit.EventBuildFailed,
			Stage:           StagePolicyEvaluation,
			DependencyAlias: AliasReleasePolicy,
			FailureClass:    ClassPolicyCandidateUnknown,
			CandidateID:     opts.Scenario.Candidate,
		}); err != nil {
			return nil, err
		}
		out.AuditEvents = sink.Emitted()
		return out, nil
	}
	out.Verdict = verdict

	switch verdict {
	case pkgarchive.VerdictReject:
		if err := sink.Emit(audit.Event{
			Event:           audit.EventReleaseRejected,
			Stage:           StagePolicyEvaluation,
			DependencyAlias: AliasReleasePolicy,
			CandidateID:     opts.Scenario.Candidate,
		}); err != nil {
			return nil, err
		}
	case pkgarchive.VerdictApprove:
		if current.Approved(opts.Scenario.Candidate) {
			out.Mutation = MutationSuppressed
			if err := sink.Emit(audit.Event{
				Event:           audit.EventReleaseDuplicate,
				Stage:           StagePolicyEvaluation,
				DependencyAlias: AliasReleasePolicy,
				CandidateID:     opts.Scenario.Candidate,
			}); err != nil {
				return nil, err
			}
			break
		}
		current.Entries = append(current.Entries, ledger.Entry{
			CandidateID:   opts.Scenario.Candidate,
			PolicyName:    out.ReleasePolicy.Name,
			PolicySource:  out.ReleasePolicy.Selected.Source,
			PolicyVersion: out.ReleasePolicy.Selected.Version,
			PolicyDigest:  out.ReleasePolicy.Digest,
		})
		if err := ledger.Save(ledgerPath, current); err != nil {
			return nil, err
		}
		out.Mutation = MutationApproved
		if err := sink.Emit(audit.Event{
			Event:           audit.EventReleaseApproved,
			Stage:           StagePolicyEvaluation,
			DependencyAlias: AliasReleasePolicy,
			CandidateID:     opts.Scenario.Candidate,
		}); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unreachable: unvalidated verdict %q", verdict)
	}

	after, err := ledger.Digest(ledgerPath)
	if err != nil {
		return nil, err
	}
	out.LedgerAfter = after
	out.AuditEvents = sink.Emitted()
	return out, nil
}
