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

// Mapping binds a dependency-name pattern to exactly one source.
type Mapping struct {
	Pattern string `json:"pattern"`
	Source  string `json:"source"`
	Mode    string `json:"mode"`
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
	Name     string
	Pattern  string
	Mode     string
	Bound    Source
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
		if m.Mode != ModeExclusive {
			return fmt.Errorf("%w: %q", ErrUnsupportedMode, m.Mode)
		}
		if _, ok := p.Source(m.Source); !ok {
			return fmt.Errorf("%w: %q", ErrUnknownSource, m.Source)
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
	bound, ok := p.Source(m.Source)
	if !ok {
		return Decision{}, fmt.Errorf("%w: %q", ErrUnknownSource, m.Source)
	}
	var excluded []Source
	for _, s := range p.Sources {
		if s.ID != bound.ID {
			excluded = append(excluded, s)
		}
	}
	return Decision{
		Name:     name,
		Pattern:  m.Pattern,
		Mode:     m.Mode,
		Bound:    bound,
		Excluded: excluded,
	}, nil
}

func matches(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}
