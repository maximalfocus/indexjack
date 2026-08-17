// Package semver implements the exact, deliberately small version model this
// demonstration resolves with.
//
// It is a documented model, not a reimplementation of any real package
// manager's version algebra: three numeric components, no prerelease, no build
// metadata, and two range forms.
package semver

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidVersion reports a version string outside the supported model.
var ErrInvalidVersion = errors.New("invalid version")

// ErrInvalidRange reports a range string outside the supported model.
var ErrInvalidRange = errors.New("invalid version range")

// Version is a strict MAJOR.MINOR.PATCH triple.
type Version struct {
	Major, Minor, Patch uint64
}

// Parse reads a strict MAJOR.MINOR.PATCH version. Leading zeros, signs,
// whitespace, prerelease and build metadata are rejected so that one version
// value has exactly one spelling.
func Parse(s string) (Version, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("%w: %q", ErrInvalidVersion, s)
	}
	var out [3]uint64
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return Version{}, fmt.Errorf("%w: %q", ErrInvalidVersion, s)
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return Version{}, fmt.Errorf("%w: %q", ErrInvalidVersion, s)
			}
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("%w: %q", ErrInvalidVersion, s)
		}
		out[i] = n
	}
	return Version{Major: out[0], Minor: out[1], Patch: out[2]}, nil
}

// MustParse is Parse for checked-in constants; it panics on malformed input.
func MustParse(s string) Version {
	v, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

// String renders the canonical spelling of v.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare orders two versions: -1 if a < b, 0 if equal, 1 if a > b.
func Compare(a, b Version) int {
	switch {
	case a.Major != b.Major:
		return cmpUint(a.Major, b.Major)
	case a.Minor != b.Minor:
		return cmpUint(a.Minor, b.Minor)
	case a.Patch != b.Patch:
		return cmpUint(a.Patch, b.Patch)
	}
	return 0
}

func cmpUint(a, b uint64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// RangeKind enumerates the two supported range forms.
type RangeKind string

const (
	// KindExact matches one version only: "1.4.2".
	KindExact RangeKind = "exact"
	// KindCaret matches versions at or above the base within the same major
	// component: "^1.4.2".
	KindCaret RangeKind = "caret"
)

// Range is a parsed dependency range.
type Range struct {
	Kind RangeKind
	Base Version
}

// ParseRange reads "1.4.2" (exact) or "^1.4.2" (caret).
func ParseRange(s string) (Range, error) {
	kind := KindExact
	body := s
	if strings.HasPrefix(s, "^") {
		kind = KindCaret
		body = strings.TrimPrefix(s, "^")
	}
	v, err := Parse(body)
	if err != nil {
		return Range{}, fmt.Errorf("%w: %q", ErrInvalidRange, s)
	}
	return Range{Kind: kind, Base: v}, nil
}

// String renders the canonical spelling of r.
func (r Range) String() string {
	if r.Kind == KindCaret {
		return "^" + r.Base.String()
	}
	return r.Base.String()
}

// Satisfies reports whether v is inside r.
func (r Range) Satisfies(v Version) bool {
	switch r.Kind {
	case KindExact:
		return Compare(v, r.Base) == 0
	case KindCaret:
		return v.Major == r.Base.Major && Compare(v, r.Base) >= 0
	}
	return false
}
