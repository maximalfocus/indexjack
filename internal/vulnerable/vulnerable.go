// Package vulnerable holds the two deliberate opt-in controls that stand
// between an ordinary run of this demonstration and its intentionally
// vulnerable half.
//
// Neither control is a security boundary, and neither is pretending to be one:
// anything with a shell can set an environment variable. They are an
// acknowledgement. Reaching the vulnerable resolver, the public shadow artifact
// or the vulnerable registry service takes two separate, deliberate acts — a
// non-default container profile and an explicit acknowledgement — so that
// nobody arrives there by running the documented command, copying a snippet, or
// letting a default carry them.
package vulnerable

import (
	"errors"
	"fmt"
	"os"
)

// The two controls.
const (
	// AcknowledgementEnv must be set to Acknowledgement by the person running
	// the demonstration.
	AcknowledgementEnv = "ALLOW_VULNERABLE_DEMO"
	Acknowledgement    = "true"

	// ProfileEnv is set only by the container services that exist under the
	// non-default profile named by Profile. Nothing in the default workflow
	// sets it.
	ProfileEnv = "INDEXJACK_COMPOSE_PROFILE"
	Profile    = "vulnerable"
)

// Label marks everything the vulnerable half produces.
const Label = "intentionally vulnerable local educational material"

// LabelHeader carries Label on every response from a vulnerable registry
// fixture.
const LabelHeader = "X-Indexjack-Intentionally-Vulnerable"

// ErrNotAcknowledged reports that at least one opt-in control is unsatisfied.
var ErrNotAcknowledged = errors.New("the vulnerable demonstration was not acknowledged")

// Check reports whether both controls are satisfied by the given values. It is
// a pure function so the exact behaviour of each combination can be asserted
// without touching the environment.
func Check(acknowledgement, profile string) error {
	missingProfile := profile != Profile
	missingAck := acknowledgement != Acknowledgement

	switch {
	case missingProfile && missingAck:
		return fmt.Errorf("%w: this is %s, and reaching it needs both the %q container profile and %s=%s",
			ErrNotAcknowledged, Label, Profile, AcknowledgementEnv, Acknowledgement)
	case missingProfile:
		return fmt.Errorf("%w: %s=%s is set, but this is not running under the %q container profile; the acknowledgement alone is not enough",
			ErrNotAcknowledged, AcknowledgementEnv, Acknowledgement, Profile)
	case missingAck:
		return fmt.Errorf("%w: the %q container profile is active, but %s=%s is not set; the profile alone is not enough",
			ErrNotAcknowledged, Profile, AcknowledgementEnv, Acknowledgement)
	}
	return nil
}

// Gate applies Check to the current environment.
func Gate() error { return Check(os.Getenv(AcknowledgementEnv), os.Getenv(ProfileEnv)) }

// Acknowledged reports whether the vulnerable half is currently reachable.
func Acknowledged() bool { return Gate() == nil }
