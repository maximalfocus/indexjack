package sourcepolicy

import (
	"errors"
	"testing"
)

func policy() Policy {
	return Policy{
		Format: Format,
		Sources: []Source{
			{ID: "glasswing-private", Role: RolePrivate, URL: "http://packages.private.example:8080"},
			{ID: "community-public", Role: RolePublic, URL: "http://packages.public.example:8080"},
		},
		Mappings: []Mapping{
			{Pattern: "@glasswing/*", Source: "glasswing-private", Mode: ModeExclusive},
			{Pattern: "community-*", Source: "community-public", Mode: ModeExclusive},
		},
	}
}

func TestExclusiveMappingBindsAndExcludes(t *testing.T) {
	decision, err := policy().Resolve("@glasswing/release-policy")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if decision.Bound.ID != "glasswing-private" {
		t.Fatalf("bound to %q", decision.Bound.ID)
	}
	if decision.Mode != ModeExclusive {
		t.Fatalf("mode = %q", decision.Mode)
	}
	if len(decision.Excluded) != 1 || decision.Excluded[0].ID != "community-public" {
		t.Fatalf("excluded = %+v", decision.Excluded)
	}
}

func TestPublicNameBindsToPublicSource(t *testing.T) {
	decision, err := policy().Resolve("community-format")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if decision.Bound.ID != "community-public" {
		t.Fatalf("bound to %q", decision.Bound.ID)
	}
}

// Display order is not trust. Reordering the source list must not change any
// binding: that distinction is the entire lesson of this package.
func TestDisplayOrderDoesNotChangeBinding(t *testing.T) {
	reordered := policy()
	reordered.Sources[0], reordered.Sources[1] = reordered.Sources[1], reordered.Sources[0]

	original, err := policy().Resolve("@glasswing/release-policy")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	swapped, err := reordered.Resolve("@glasswing/release-policy")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if original.Bound.ID != swapped.Bound.ID {
		t.Fatalf("binding changed with display order: %q vs %q", original.Bound.ID, swapped.Bound.ID)
	}
	if got := reordered.DisplayOrder(); got[0] != "community-public" {
		t.Fatalf("DisplayOrder did not follow declaration order: %v", got)
	}
}

func TestUnmappedNameFailsClosed(t *testing.T) {
	_, err := policy().Resolve("unmapped-dependency")
	if !errors.Is(err, ErrNoMapping) {
		t.Fatalf("Resolve error = %v, want ErrNoMapping", err)
	}
}

func TestAmbiguousMappingFailsClosed(t *testing.T) {
	p := policy()
	p.Mappings = append(p.Mappings, Mapping{Pattern: "@glasswing/release-*", Source: "community-public", Mode: ModeExclusive})
	_, err := p.Resolve("@glasswing/release-policy")
	if !errors.Is(err, ErrAmbiguousMapping) {
		t.Fatalf("Resolve error = %v, want ErrAmbiguousMapping", err)
	}
}

func TestValidateRejectsMalformedPolicies(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Policy)
		want   error
	}{
		{"bad format", func(p *Policy) { p.Format = "other/1" }, ErrInvalidPolicy},
		{"no sources", func(p *Policy) { p.Sources = nil }, ErrInvalidPolicy},
		{"no mappings", func(p *Policy) { p.Mappings = nil }, ErrInvalidPolicy},
		{"unknown source", func(p *Policy) { p.Mappings[0].Source = "nowhere" }, ErrUnknownSource},
		{"unsupported mode", func(p *Policy) { p.Mappings[0].Mode = "prefer" }, ErrUnsupportedMode},
		{"duplicate source", func(p *Policy) { p.Sources[1].ID = p.Sources[0].ID }, ErrInvalidPolicy},
		{"duplicate pattern", func(p *Policy) { p.Mappings[1].Pattern = p.Mappings[0].Pattern }, ErrInvalidPolicy},
		{"unknown role", func(p *Policy) { p.Sources[0].Role = "trusted" }, ErrInvalidPolicy},
		{"interior wildcard", func(p *Policy) { p.Mappings[0].Pattern = "@glass*/policy" }, ErrInvalidPolicy},
		{"multiple wildcards", func(p *Policy) { p.Mappings[0].Pattern = "@*/*" }, ErrInvalidPolicy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := policy()
			c.mutate(&p)
			if err := p.Validate(); !errors.Is(err, c.want) {
				t.Fatalf("Validate error = %v, want %v", err, c.want)
			}
			if _, err := p.Resolve("@glasswing/release-policy"); err == nil {
				t.Fatal("Resolve accepted an invalid policy")
			}
		})
	}
}

func TestExactPatternMatchesOnlyItself(t *testing.T) {
	p := policy()
	p.Mappings = []Mapping{{Pattern: "community-format", Source: "community-public", Mode: ModeExclusive}}
	if _, err := p.Resolve("community-format"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := p.Resolve("community-formatting"); !errors.Is(err, ErrNoMapping) {
		t.Fatalf("Resolve error = %v, want ErrNoMapping", err)
	}
}

func combinedPolicy() Policy {
	p := policy()
	p.Mappings[0] = Mapping{
		Pattern: "@glasswing/*",
		Mode:    ModeCombined,
		Sources: []string{"glasswing-private", "community-public"},
	}
	return p
}

// A combined mapping binds nothing. Everything it pools may answer, and that is
// the shape of policy this project exists to argue against.
func TestCombinedMappingPoolsAndBindsNothing(t *testing.T) {
	decision, err := combinedPolicy().Resolve("@glasswing/release-policy")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if decision.Mode != ModeCombined {
		t.Fatalf("mode = %q", decision.Mode)
	}
	if decision.Bound.ID != "" {
		t.Fatalf("a combined mapping bound %q", decision.Bound.ID)
	}
	if len(decision.Pool) != 2 || decision.Pool[0].ID != "glasswing-private" || decision.Pool[1].ID != "community-public" {
		t.Fatalf("pool = %+v", decision.Pool)
	}
	if len(decision.Excluded) != 0 {
		t.Fatalf("excluded = %+v", decision.Excluded)
	}
}

func TestExclusiveMappingPoolsExactlyItsBoundSource(t *testing.T) {
	decision, err := policy().Resolve("@glasswing/release-policy")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(decision.Pool) != 1 || decision.Pool[0].ID != decision.Bound.ID {
		t.Fatalf("pool = %+v, bound = %q", decision.Pool, decision.Bound.ID)
	}
}

func TestValidateRejectsMalformedCombinedMappings(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Policy)
	}{
		{"one source", func(p *Policy) { p.Mappings[0].Sources = []string{"glasswing-private"} }},
		{"no sources", func(p *Policy) { p.Mappings[0].Sources = nil }},
		{"unknown source", func(p *Policy) { p.Mappings[0].Sources = []string{"glasswing-private", "nowhere"} }},
		{"repeated source", func(p *Policy) {
			p.Mappings[0].Sources = []string{"glasswing-private", "glasswing-private"}
		}},
		{"both source and sources", func(p *Policy) { p.Mappings[0].Source = "glasswing-private" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := combinedPolicy()
			c.mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("Validate accepted a malformed combined mapping")
			}
		})
	}
}

func TestExclusiveMappingMustNotCarryAPool(t *testing.T) {
	p := policy()
	p.Mappings[0].Sources = []string{"glasswing-private", "community-public"}
	if err := p.Validate(); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("Validate error = %v, want ErrInvalidPolicy", err)
	}
}
