package buildmanifest

import (
	"errors"
	"testing"
)

func manifest() Manifest {
	return Manifest{
		Format:  Format,
		Project: "glasswing-release-gate",
		Dependencies: []Dependency{
			{Alias: "release-policy", Name: "@glasswing/release-policy", Range: "^1.4.2"},
			{Alias: "report-format", Name: "community-format", Range: "2.1.0"},
		},
	}
}

func TestDependencyLookupFollowsDeclarationOrder(t *testing.T) {
	m := manifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if m.Dependencies[0].Alias != "release-policy" {
		t.Fatalf("declaration order changed: %+v", m.Dependencies)
	}
	dep, err := m.Dependency("report-format")
	if err != nil {
		t.Fatalf("Dependency: %v", err)
	}
	if dep.Name != "community-format" || dep.Range != "2.1.0" {
		t.Fatalf("dependency = %+v", dep)
	}
	if _, err := m.Dependency("nothing"); err == nil {
		t.Fatal("Dependency accepted an unknown alias")
	}
}

func TestValidateRejectsMalformedManifests(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"bad format", func(m *Manifest) { m.Format = "other/1" }},
		{"no project", func(m *Manifest) { m.Project = "" }},
		{"no dependencies", func(m *Manifest) { m.Dependencies = nil }},
		{"no alias", func(m *Manifest) { m.Dependencies[0].Alias = "" }},
		{"no name", func(m *Manifest) { m.Dependencies[0].Name = "" }},
		{"duplicate alias", func(m *Manifest) { m.Dependencies[1].Alias = m.Dependencies[0].Alias }},
		{"unsupported range", func(m *Manifest) { m.Dependencies[0].Range = "~1.4.2" }},
		{"empty range", func(m *Manifest) { m.Dependencies[0].Range = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := manifest()
			c.mutate(&m)
			if err := m.Validate(); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Validate error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}
