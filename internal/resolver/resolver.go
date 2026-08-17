// Package resolver implements the secure resolution model.
//
// The order of operations is the security property. Source policy is evaluated
// before any registry is contacted, the lock is checked before any artifact is
// fetched, and size and digest are verified before any byte of package content
// is interpreted. There is no flag, environment variable, retry mode, or
// alternate entry point that reorders or skips a step.
//
// This is a documented model of how a resolver can behave, not a
// reimplementation of npm, pip, Maven, NuGet, Go modules, Cargo, or any other
// named tool. Its ordering and tie rules are this project's own.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"indexjack/internal/buildmanifest"
	"indexjack/internal/lockfile"
	"indexjack/internal/pkgarchive"
	"indexjack/internal/registry"
	"indexjack/internal/semver"
	"indexjack/internal/sourcepolicy"
)

// Stages of resolution, in the order they are attempted.
const (
	StageSourcePolicy  = "source_policy"
	StageLock          = "lock"
	StageRegistryQuery = "registry_query"
	StageArtifactFetch = "artifact_fetch"
	StageIntegrity     = "integrity"
	StageArtifactParse = "artifact_parse"
)

// Stable failure classes. These are internal evidence: every one of them is
// reported to the client as the same generic build failure.
const (
	ClassSourcePolicyUnresolved = "SOURCE_POLICY_UNRESOLVED"
	ClassSourcePolicyAmbiguous  = "SOURCE_POLICY_AMBIGUOUS"
	ClassSourcePolicyInvalid    = "SOURCE_POLICY_INVALID"
	ClassLockMissing            = "LOCK_MISSING"
	ClassLockDuplicate          = "LOCK_DUPLICATE"
	ClassLockInvalid            = "LOCK_INVALID"
	ClassLockSourceMismatch     = "LOCK_SOURCE_MISMATCH"
	ClassLockNameMismatch       = "LOCK_NAME_MISMATCH"
	ClassLockRangeConflict      = "LOCK_RANGE_CONFLICT"
	ClassRegistryUnavailable    = "REGISTRY_UNAVAILABLE"
	ClassArtifactUnavailable    = "ARTIFACT_UNAVAILABLE"
	ClassArtifactSizeMismatch   = "ARTIFACT_SIZE_MISMATCH"
	ClassArtifactDigestMismatch = "ARTIFACT_DIGEST_MISMATCH"
	ClassArtifactMalformed      = "ARTIFACT_MALFORMED"
	ClassManifestMismatch       = "MANIFEST_MISMATCH"
)

// SelectionRule is the one rule this resolver applies. It is printed in every
// trace so the reader never has to infer it.
const SelectionRule = "select the locked version from the exclusively bound source; no other source, version, or byte sequence is acceptable"

// Failure is a resolution failure with its stable class and the stage that
// produced it.
type Failure struct {
	Class string
	Stage string
	Err   error
}

func (f *Failure) Error() string {
	return fmt.Sprintf("%s at %s: %v", f.Class, f.Stage, f.Err)
}

func (f *Failure) Unwrap() error { return f.Err }

func fail(class, stage string, err error) *Failure {
	return &Failure{Class: class, Stage: stage, Err: err}
}

// AsFailure extracts the resolution failure from err, if any.
func AsFailure(err error) (*Failure, bool) {
	var f *Failure
	if errors.As(err, &f) {
		return f, true
	}
	return nil, false
}

// Candidate is one version the bound source offers, as the source described it.
type Candidate struct {
	Source  string
	Name    string
	Version string
	Size    int64
	SHA256  string
}

// Resolution is the complete record of one successful dependency resolution.
type Resolution struct {
	Alias        string
	Name         string
	Range        string
	DisplayOrder []string
	Policy       sourcepolicy.Decision
	Queried      []string
	Excluded     []string
	Candidates   []Candidate
	Selected     Candidate
	Locked       lockfile.Record
	Size         int64
	Digest       string
	Integrity    string
	Package      *pkgarchive.Package
}

// Integrity verdict values.
const (
	IntegrityVerified = "verified"
)

// Fetcher is the subset of a registry client the resolver needs.
type Fetcher interface {
	Metadata(ctx context.Context, name string) (registry.Metadata, error)
	Artifact(ctx context.Context, name, version string) ([]byte, error)
}

// Config is everything resolution depends on. All of it is checked-in data.
type Config struct {
	Policy sourcepolicy.Policy
	Lock   lockfile.Lock
	// Dial returns the client for a source. It exists so in-process
	// verification can reach fixture registries on loopback; it cannot change
	// which source a name is bound to.
	Dial func(source sourcepolicy.Source) (Fetcher, error)
}

// DefaultDial builds the ordinary read-only registry client.
func DefaultDial(source sourcepolicy.Source) (Fetcher, error) {
	return registry.NewClient(source.URL)
}

// Resolve resolves one dependency.
func Resolve(ctx context.Context, cfg Config, dep buildmanifest.Dependency) (*Resolution, error) {
	dial := cfg.Dial
	if dial == nil {
		dial = DefaultDial
	}

	// A resolution record exists from the first step, so a failure can still
	// say what was asked, what policy decided, and who was contacted. A trace
	// that goes blank at the moment something goes wrong is not a trace.
	res := &Resolution{Alias: dep.Alias, Name: dep.Name, Range: dep.Range}

	// 1. Source policy, before anything is contacted.
	if err := cfg.Policy.Validate(); err != nil {
		return res, fail(ClassSourcePolicyInvalid, StageSourcePolicy, err)
	}
	res.DisplayOrder = cfg.Policy.DisplayOrder()
	decision, err := cfg.Policy.Resolve(dep.Name)
	if err != nil {
		class := ClassSourcePolicyUnresolved
		if errors.Is(err, sourcepolicy.ErrAmbiguousMapping) {
			class = ClassSourcePolicyAmbiguous
		}
		return res, fail(class, StageSourcePolicy, err)
	}
	res.Policy = decision
	for _, s := range decision.Excluded {
		res.Excluded = append(res.Excluded, s.ID)
	}

	// 2. Lock, before anything is fetched.
	record, err := cfg.Lock.Record(dep.Alias)
	if err != nil {
		class := ClassLockInvalid
		switch {
		case errors.Is(err, lockfile.ErrMissingRecord):
			class = ClassLockMissing
		case errors.Is(err, lockfile.ErrDuplicate):
			class = ClassLockDuplicate
		}
		return res, fail(class, StageLock, err)
	}
	res.Locked = record
	if record.Name != dep.Name {
		return res, fail(ClassLockNameMismatch, StageLock,
			fmt.Errorf("lock binds alias %q to %q, manifest declares %q", dep.Alias, record.Name, dep.Name))
	}
	if record.Source != decision.Bound.ID {
		return res, fail(ClassLockSourceMismatch, StageLock,
			fmt.Errorf("lock binds %q to source %q, policy binds it to %q", dep.Alias, record.Source, decision.Bound.ID))
	}
	depRange, err := semver.ParseRange(dep.Range)
	if err != nil {
		return res, fail(ClassLockRangeConflict, StageLock, err)
	}
	lockedVersion, err := semver.Parse(record.Version)
	if err != nil {
		return res, fail(ClassLockInvalid, StageLock, err)
	}
	if !depRange.Satisfies(lockedVersion) {
		// The declared range moved and the lock did not. Nothing here may
		// silently prefer one over the other: a lock is changed by review.
		return res, fail(ClassLockRangeConflict, StageLock,
			fmt.Errorf("manifest requires %s but the lock pins %s", depRange, lockedVersion))
	}

	// 3. Query exactly one source: the bound one.
	client, err := dial(decision.Bound)
	if err != nil {
		return res, fail(ClassRegistryUnavailable, StageRegistryQuery, err)
	}
	res.Queried = []string{decision.Bound.ID}
	meta, err := client.Metadata(ctx, dep.Name)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return res, fail(ClassArtifactUnavailable, StageRegistryQuery,
				fmt.Errorf("source %q does not carry %q", decision.Bound.ID, dep.Name))
		}
		return res, fail(ClassRegistryUnavailable, StageRegistryQuery, err)
	}
	res.Candidates = orderCandidates(decision.Bound.ID, meta)

	// 4. Select the locked version, and only it.
	var selected *Candidate
	for i := range res.Candidates {
		if res.Candidates[i].Version == record.Version {
			selected = &res.Candidates[i]
			break
		}
	}
	if selected == nil {
		return res, fail(ClassArtifactUnavailable, StageRegistryQuery,
			fmt.Errorf("source %q does not carry %s@%s", decision.Bound.ID, dep.Name, record.Version))
	}
	res.Selected = *selected

	// 5. Fetch, then verify size and digest before reading content.
	raw, err := client.Artifact(ctx, dep.Name, record.Version)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return res, fail(ClassArtifactUnavailable, StageArtifactFetch,
				fmt.Errorf("source %q does not carry %s@%s", decision.Bound.ID, dep.Name, record.Version))
		}
		return res, fail(ClassRegistryUnavailable, StageArtifactFetch, err)
	}
	if err := record.VerifyBytes(raw); err != nil {
		class := ClassArtifactDigestMismatch
		if errors.Is(err, lockfile.ErrSizeMismatch) {
			class = ClassArtifactSizeMismatch
		}
		return res, fail(class, StageIntegrity, err)
	}
	res.Size = int64(len(raw))
	res.Digest = pkgarchive.Digest(raw)
	res.Integrity = IntegrityVerified

	// 6. Only now may the bytes be read, and only as data.
	pkg, err := pkgarchive.Parse(raw)
	if err != nil {
		return res, fail(ClassArtifactMalformed, StageArtifactParse, err)
	}
	if pkg.Manifest.Name != dep.Name || pkg.Manifest.Version != record.Version {
		return res, fail(ClassManifestMismatch, StageArtifactParse,
			fmt.Errorf("artifact declares %s@%s, lock binds %s@%s",
				pkg.Manifest.Name, pkg.Manifest.Version, dep.Name, record.Version))
	}
	res.Package = pkg
	return res, nil
}

// orderCandidates renders the candidate set in the resolver's documented order:
// descending semantic version, ties broken by source id ascending. Ordering is
// presentation and comparison only; it never decides trust.
func orderCandidates(source string, meta registry.Metadata) []Candidate {
	out := make([]Candidate, 0, len(meta.Versions))
	parsed := make(map[string]semver.Version, len(meta.Versions))
	for _, v := range meta.Versions {
		version, err := semver.Parse(v.Version)
		if err != nil {
			// A source that publishes a version outside the model is not a
			// candidate at all.
			continue
		}
		parsed[v.Version] = version
		out = append(out, Candidate{
			Source:  source,
			Name:    meta.Name,
			Version: v.Version,
			Size:    v.Size,
			SHA256:  v.SHA256,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if c := semver.Compare(parsed[out[i].Version], parsed[out[j].Version]); c != 0 {
			return c > 0
		}
		return out[i].Source < out[j].Source
	})
	return out
}
