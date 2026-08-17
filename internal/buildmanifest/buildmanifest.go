// Package buildmanifest models what a project declares it depends on.
//
// A manifest states names and ranges only. It never states where a name comes
// from: that is source policy, and never states which bytes are acceptable:
// that is the lock.
package buildmanifest

import (
	"errors"
	"fmt"

	"indexjack/internal/semver"
)

// Format is the manifest document version.
const Format = "indexjack-manifest/1"

// ErrInvalidManifest reports a malformed manifest document.
var ErrInvalidManifest = errors.New("invalid manifest")

// Dependency is one declared dependency.
type Dependency struct {
	Alias string `json:"alias"`
	Name  string `json:"name"`
	Range string `json:"range"`
}

// Manifest is the project's declared dependency set, in declaration order.
// Resolution follows that order and stops at the first failure, so a build that
// fails closed on its first dependency never reaches the next one.
type Manifest struct {
	Format       string       `json:"format"`
	Project      string       `json:"project"`
	Dependencies []Dependency `json:"dependencies"`
}

// Validate checks the document shape.
func (m Manifest) Validate() error {
	if m.Format != Format {
		return fmt.Errorf("%w: format %q", ErrInvalidManifest, m.Format)
	}
	if m.Project == "" || len(m.Dependencies) == 0 {
		return fmt.Errorf("%w: project and dependencies are required", ErrInvalidManifest)
	}
	seen := make(map[string]struct{}, len(m.Dependencies))
	for _, d := range m.Dependencies {
		if d.Alias == "" || d.Name == "" {
			return fmt.Errorf("%w: dependency alias and name are required", ErrInvalidManifest)
		}
		if _, dup := seen[d.Alias]; dup {
			return fmt.Errorf("%w: duplicate dependency alias %q", ErrInvalidManifest, d.Alias)
		}
		seen[d.Alias] = struct{}{}
		if _, err := semver.ParseRange(d.Range); err != nil {
			return fmt.Errorf("%w: dependency %q: %v", ErrInvalidManifest, d.Alias, err)
		}
	}
	return nil
}

// Dependency returns the single dependency with the given alias.
func (m Manifest) Dependency(alias string) (Dependency, error) {
	for _, d := range m.Dependencies {
		if d.Alias == alias {
			return d, nil
		}
	}
	return Dependency{}, fmt.Errorf("%w: no dependency %q", ErrInvalidManifest, alias)
}
