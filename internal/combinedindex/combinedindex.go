// Package combinedindex implements the intentionally vulnerable resolver.
//
// It exists to be compared against the secure one. The difference between them
// is deliberately small, because the point of the demonstration is that the
// difference in real builds is also small — a configuration choice, not a bug:
//
//   - it asks every source in a combined pool instead of exactly one; and
//   - it selects the highest compatible version across the merged answers,
//     binding neither origin nor bytes.
//
// Everything else is shared with the secure path: the same hardened data-only
// artifact parser, the same release gate, the same fixtures, the same
// transcript. Nothing here executes package content, and this package's
// configuration has no lock field at all — not because enforcement is switched
// off somewhere, but because this resolver has nothing to enforce with.
//
// It is reachable only behind both opt-in controls in package vulnerable.
package combinedindex

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"indexjack/internal/buildmanifest"
	"indexjack/internal/pkgarchive"
	"indexjack/internal/registry"
	"indexjack/internal/resolver"
	"indexjack/internal/semver"
	"indexjack/internal/sourcepolicy"
	"indexjack/internal/vulnerable"
)

// SelectionRule is the rule this resolver applies. It is printed in every
// transcript it produces, next to the origin it chose.
const SelectionRule = "merge the compatible candidates offered by every pooled source and select the highest semantic version; ties are broken by the order the sources are listed in the policy, then by source id"

// IntegrityUnverified is what this resolver records instead of a verdict. It
// never compares bytes against anything, so it has nothing to report.
const IntegrityUnverified = "unverified"

// ClassNoCandidate reports that the pooled sources offered nothing compatible.
const ClassNoCandidate = "NO_COMPATIBLE_CANDIDATE"

// Config is everything this resolver depends on. There is no lock here.
type Config struct {
	Policy sourcepolicy.Policy
	// Dial returns the client for a source.
	Dial func(source sourcepolicy.Source) (resolver.Fetcher, error)
}

// Resolve resolves one dependency across a pooled candidate set.
func Resolve(ctx context.Context, cfg Config, dep buildmanifest.Dependency) (*resolver.Resolution, error) {
	if err := vulnerable.Gate(); err != nil {
		return nil, err
	}
	dial := cfg.Dial
	if dial == nil {
		dial = resolver.DefaultDial
	}

	res := &resolver.Resolution{Alias: dep.Alias, Name: dep.Name, Range: dep.Range, SelectionRule: SelectionRule}
	if err := cfg.Policy.Validate(); err != nil {
		return res, resolver.NewFailure(resolver.ClassSourcePolicyInvalid, resolver.StageSourcePolicy, err)
	}
	res.DisplayOrder = cfg.Policy.DisplayOrder()
	decision, err := cfg.Policy.Resolve(dep.Name)
	if err != nil {
		class := resolver.ClassSourcePolicyUnresolved
		if errors.Is(err, sourcepolicy.ErrAmbiguousMapping) {
			class = resolver.ClassSourcePolicyAmbiguous
		}
		return res, resolver.NewFailure(class, resolver.StageSourcePolicy, err)
	}
	res.Policy = decision
	for _, s := range decision.Excluded {
		res.Excluded = append(res.Excluded, s.ID)
	}

	declared, err := semver.ParseRange(dep.Range)
	if err != nil {
		return res, resolver.NewFailure(resolver.ClassSourcePolicyInvalid, resolver.StageSourcePolicy, err)
	}

	// Ask every pooled source. Listing a trusted source first changes the order
	// of these questions and nothing else.
	type offer struct {
		candidate resolver.Candidate
		version   semver.Version
		rank      int
	}
	var offers []offer
	for rank, source := range decision.Pool {
		client, err := dial(source)
		if err != nil {
			return res, resolver.NewFailure(resolver.ClassRegistryUnavailable, resolver.StageRegistryQuery, err)
		}
		res.Queried = append(res.Queried, source.ID)
		meta, err := client.Metadata(ctx, dep.Name)
		if err != nil {
			if errors.Is(err, registry.ErrNotFound) {
				// A source that does not carry the name simply offers nothing.
				continue
			}
			return res, resolver.NewFailure(resolver.ClassRegistryUnavailable, resolver.StageRegistryQuery, err)
		}
		for _, v := range meta.Versions {
			version, err := semver.Parse(v.Version)
			if err != nil || !declared.Satisfies(version) {
				continue
			}
			offers = append(offers, offer{
				candidate: resolver.Candidate{
					Source:  source.ID,
					Name:    meta.Name,
					Version: v.Version,
					Size:    v.Size,
					SHA256:  v.SHA256,
				},
				version: version,
				rank:    rank,
			})
		}
	}

	// One merged pool, ordered by version alone. Which trust domain an offer
	// came from is not part of this comparison — that is the whole flaw.
	sort.SliceStable(offers, func(i, j int) bool {
		if c := semver.Compare(offers[i].version, offers[j].version); c != 0 {
			return c > 0
		}
		if offers[i].rank != offers[j].rank {
			return offers[i].rank < offers[j].rank
		}
		return offers[i].candidate.Source < offers[j].candidate.Source
	})
	for _, o := range offers {
		res.Candidates = append(res.Candidates, o.candidate)
	}
	if len(offers) == 0 {
		return res, resolver.NewFailure(ClassNoCandidate, resolver.StageRegistryQuery,
			fmt.Errorf("no pooled source offers %s %s", dep.Name, dep.Range))
	}

	selected := offers[0].candidate
	res.Selected = selected

	client, err := dial(sourceByID(decision.Pool, selected.Source))
	if err != nil {
		return res, resolver.NewFailure(resolver.ClassRegistryUnavailable, resolver.StageArtifactFetch, err)
	}
	raw, err := client.Artifact(ctx, dep.Name, selected.Version)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return res, resolver.NewFailure(resolver.ClassArtifactUnavailable, resolver.StageArtifactFetch,
				fmt.Errorf("source %q does not carry %s@%s", selected.Source, dep.Name, selected.Version))
		}
		return res, resolver.NewFailure(resolver.ClassRegistryUnavailable, resolver.StageArtifactFetch, err)
	}

	// The digest is computed and recorded, but nothing is compared against it.
	// A digest you print and do not check is a label, not an identity.
	res.Size = int64(len(raw))
	res.Digest = pkgarchive.Digest(raw)
	res.Integrity = IntegrityUnverified

	// The artifact is still parsed by the same hardened, data-only loader. This
	// resolver demonstrates selecting the wrong thing, not running it.
	pkg, err := pkgarchive.Parse(raw)
	if err != nil {
		return res, resolver.NewFailure(resolver.ClassArtifactMalformed, resolver.StageArtifactParse, err)
	}
	res.Package = pkg
	return res, nil
}

func sourceByID(pool []sourcepolicy.Source, id string) sourcepolicy.Source {
	for _, s := range pool {
		if s.ID == id {
			return s
		}
	}
	return sourcepolicy.Source{}
}
