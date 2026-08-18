// Package sourcepolicy models where a dependency name is allowed to come from.
//
// Source policy is a first-class input, deliberately separate from the order in
// which sources are displayed or would be queried. Listing a trusted source
// first is a display detail; an exclusive mapping is a trust decision. Keeping
// the two apart is the whole point of the model: only the mapping constrains
// resolution.
package sourcepolicy

import (
	"errors"
	"fmt"
	"strings"
)

// Modes a mapping may declare.
const (
	// ModeExclusive binds a name pattern to exactly one source. Every other
	// source is excluded for that pattern: it is neither queried first nor
	// used as a fallback when the bound source has nothing to offer.
	ModeExclusive = "exclusive"
	// ModeCombined pools several sources for one pattern, so a name is resolved
	// across more than one trust domain at once. It is the shape of policy the
	// demonstration exists to argue against, and only the opt-in combined-index
	// resolver will act on it: the secure resolver fails closed when it sees a
	// mapping that is not exclusive.
	ModeCombined = "combined"
)

// Roles a source may declare. The role is a label for output; it grants
// nothing.
const (
	RolePrivate = "private"
	RolePublic  = "public"
)

// Stable policy errors.
var (
	ErrNoMapping        = errors.New("no source mapping matches dependency")
	ErrAmbiguousMapping = errors.New("multiple source mappings match dependency")
	ErrUnknownSource    = errors.New("mapping references unknown source")
	ErrUnsupportedMode  = errors.New("unsupported mapping mode")
	ErrInvalidPolicy    = errors.New("invalid source policy")
)

// Source is one registry the build knows about.
type Source struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	URL  string `json:"url"`
}

// Mapping binds a dependency-name pattern to a source, or — in combined mode —
// to a pool of them.
type Mapping struct {
	Pattern string `json:"pattern"`
	Mode    string `json:"mode"`
	// Source names the single source of an exclusive mapping.
	Source string `json:"source,omitempty"`
	// Sources names the pool of a combined mapping, in the order a build tool
	// would consult them. That order is display only: pooling is what matters,
	// and the order changes nothing about which candidates are considered.
	Sources []string `json:"sources,omitempty"`
}

// Policy is the checked-in source policy for one scenario.
type Policy struct {
	Format string `json:"format"`
	// Sources is display order only. It never decides trust.
	Sources  []Source  `json:"sources"`
	Mappings []Mapping `json:"mappings"`
}

// Format is the policy document version.
const Format = "indexjack-source-policy/1"

// Decision is the result of evaluating a policy for one dependency name.
type Decision struct {
	Name    string
	Pattern string
	Mode    string
	// Bound is the single source of an exclusive mapping. In combined mode it
	// is the zero value: nothing is bound, which is the entire problem.
	Bound Source
	// Pool is every source a combined mapping considers, in declared order.
	// For an exclusive mapping it holds the bound source alone.
	Pool     []Source
	Excluded []Source
}

// DisplayOrder returns the source ids in policy declaration order, which is
// what a build tool would print as its index list.
func (p Policy) DisplayOrder() []string {
	ids := make([]string, 0, len(p.Sources))
	for _, s := range p.Sources {
		ids = append(ids, s.ID)
	}
	return ids
}

// Source returns the declared source with the given id.
func (p Policy) Source(id string) (Source, bool) {
	for _, s := range p.Sources {
		if s.ID == id {
			return s, true
		}
	}
	return Source{}, false
}

// Validate checks the policy document itself, independently of any dependency.
func (p Policy) Validate() error {
	if p.Format != Format {
		return fmt.Errorf("%w: format %q", ErrInvalidPolicy, p.Format)
	}
	if len(p.Sources) == 0 || len(p.Mappings) == 0 {
		return fmt.Errorf("%w: sources and mappings are required", ErrInvalidPolicy)
	}
	seen := make(map[string]struct{}, len(p.Sources))
	for _, s := range p.Sources {
		if s.ID == "" || s.URL == "" {
			return fmt.Errorf("%w: source id and url are required", ErrInvalidPolicy)
		}
		if s.Role != RolePrivate && s.Role != RolePublic {
			return fmt.Errorf("%w: source %q role %q", ErrInvalidPolicy, s.ID, s.Role)
		}
		if _, dup := seen[s.ID]; dup {
			return fmt.Errorf("%w: duplicate source %q", ErrInvalidPolicy, s.ID)
		}
		seen[s.ID] = struct{}{}
	}
	patterns := make(map[string]struct{}, len(p.Mappings))
	for _, m := range p.Mappings {
		if err := validatePattern(m.Pattern); err != nil {
			return err
		}
		if _, dup := patterns[m.Pattern]; dup {
			return fmt.Errorf("%w: duplicate pattern %q", ErrInvalidPolicy, m.Pattern)
		}
		patterns[m.Pattern] = struct{}{}
		switch m.Mode {
		case ModeExclusive:
			if m.Source == "" || len(m.Sources) != 0 {
				return fmt.Errorf("%w: exclusive mapping %q takes one source", ErrInvalidPolicy, m.Pattern)
			}
			if _, ok := p.Source(m.Source); !ok {
				return fmt.Errorf("%w: %q", ErrUnknownSource, m.Source)
			}
		case ModeCombined:
			if m.Source != "" || len(m.Sources) < 2 {
				return fmt.Errorf("%w: combined mapping %q takes two or more sources", ErrInvalidPolicy, m.Pattern)
			}
			seen := make(map[string]struct{}, len(m.Sources))
			for _, id := range m.Sources {
				if _, ok := p.Source(id); !ok {
					return fmt.Errorf("%w: %q", ErrUnknownSource, id)
				}
				if _, dup := seen[id]; dup {
					return fmt.Errorf("%w: combined mapping %q repeats source %q", ErrInvalidPolicy, m.Pattern, id)
				}
				seen[id] = struct{}{}
			}
		default:
			return fmt.Errorf("%w: %q", ErrUnsupportedMode, m.Mode)
		}
	}
	return nil
}

func validatePattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("%w: empty pattern", ErrInvalidPolicy)
	}
	if strings.Count(pattern, "*") > 1 || (strings.Contains(pattern, "*") && !strings.HasSuffix(pattern, "*")) {
		return fmt.Errorf("%w: pattern %q supports at most one trailing '*'", ErrInvalidPolicy, pattern)
	}
	return nil
}

// Resolve evaluates the policy for one dependency name. Exactly one mapping
// must match: no match and multiple matches both fail closed, because a build
// that cannot say where a name comes from must not guess.
func (p Policy) Resolve(name string) (Decision, error) {
	if err := p.Validate(); err != nil {
		return Decision{}, err
	}
	var matched []Mapping
	for _, m := range p.Mappings {
		if matches(m.Pattern, name) {
			matched = append(matched, m)
		}
	}
	switch len(matched) {
	case 0:
		return Decision{}, fmt.Errorf("%w: %q", ErrNoMapping, name)
	case 1:
	default:
		patterns := make([]string, 0, len(matched))
		for _, m := range matched {
			patterns = append(patterns, m.Pattern)
		}
		return Decision{}, fmt.Errorf("%w: %q matches %s", ErrAmbiguousMapping, name, strings.Join(patterns, ", "))
	}

	m := matched[0]
	decision := Decision{Name: name, Pattern: m.Pattern, Mode: m.Mode}
	pooled := make(map[string]struct{})
	if m.Mode == ModeCombined {
		for _, id := range m.Sources {
			source, ok := p.Source(id)
			if !ok {
				return Decision{}, fmt.Errorf("%w: %q", ErrUnknownSource, id)
			}
			decision.Pool = append(decision.Pool, source)
			pooled[id] = struct{}{}
		}
	} else {
		bound, ok := p.Source(m.Source)
		if !ok {
			return Decision{}, fmt.Errorf("%w: %q", ErrUnknownSource, m.Source)
		}
		decision.Bound = bound
		decision.Pool = []Source{bound}
		pooled[bound.ID] = struct{}{}
	}
	for _, s := range p.Sources {
		if _, ok := pooled[s.ID]; !ok {
			decision.Excluded = append(decision.Excluded, s)
		}
	}
	return decision, nil
}

func matches(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}
