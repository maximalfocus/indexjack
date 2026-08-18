package vulnerable

import (
	"errors"
	"strings"
	"testing"
)

// Either control alone must fail, and each refusal has to say which
// acknowledgement is missing: a gate that only says "no" teaches nothing.
func TestBothControlsAreRequired(t *testing.T) {
	cases := []struct {
		name            string
		acknowledgement string
		profile         string
		wantErr         bool
		says            string
	}{
		{"neither", "", "", true, "both"},
		{"acknowledgement alone", Acknowledgement, "", true, "not running under"},
		{"profile alone", "", Profile, true, "is not set"},
		{"wrong acknowledgement value", "yes", Profile, true, "is not set"},
		{"wrong profile value", Acknowledgement, "default", true, "not running under"},
		{"both", Acknowledgement, Profile, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Check(c.acknowledgement, c.profile)
			if c.wantErr {
				if !errors.Is(err, ErrNotAcknowledged) {
					t.Fatalf("Check(%q,%q) = %v, want ErrNotAcknowledged", c.acknowledgement, c.profile, err)
				}
				if !strings.Contains(err.Error(), c.says) {
					t.Fatalf("refusal %q does not say %q", err, c.says)
				}
				return
			}
			if err != nil {
				t.Fatalf("Check(%q,%q) = %v, want nil", c.acknowledgement, c.profile, err)
			}
		})
	}
}

func TestGateReadsTheEnvironment(t *testing.T) {
	t.Setenv(AcknowledgementEnv, "")
	t.Setenv(ProfileEnv, "")
	if Acknowledged() {
		t.Fatal("the vulnerable half is reachable with neither control set")
	}
	t.Setenv(AcknowledgementEnv, Acknowledgement)
	if Acknowledged() {
		t.Fatal("the acknowledgement alone opened the gate")
	}
	t.Setenv(ProfileEnv, Profile)
	if err := Gate(); err != nil {
		t.Fatalf("Gate with both controls set: %v", err)
	}
}
