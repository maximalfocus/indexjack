package containment

import (
	"runtime"
	"testing"
)

func TestSupportedFollowsTheRuntime(t *testing.T) {
	if got, want := Supported(), runtime.GOOS == "linux"; got != want {
		t.Fatalf("Supported() = %v on %s", got, runtime.GOOS)
	}
}

func TestRunReportsEveryClaimedBoundary(t *testing.T) {
	checks := Run(t.TempDir())
	want := []string{
		"non_root_user",
		"no_new_privileges",
		"capabilities_dropped",
		"read_only_root_filesystem",
		"no_interpreter_in_image",
		"disposable_state_writable",
		"no_default_route",
		"external_connection_refused",
		"external_name_unresolvable",
	}
	if len(checks) != len(want) {
		t.Fatalf("Run returned %d checks, want %d", len(checks), len(want))
	}
	for i, name := range want {
		if checks[i].Name != name {
			t.Fatalf("check %d = %q, want %q", i, checks[i].Name, name)
		}
		if checks[i].Detail == "" {
			t.Fatalf("check %q reported no detail", name)
		}
	}
}

// The demonstration's own runtime image must pass every check. Anywhere else —
// a developer workstation, or the toolchain container that compiles this test
// and necessarily has a compiler and a shell — these assertions are about a
// different environment, so only their shape is asserted above.
func TestContainerBoundaryHolds(t *testing.T) {
	if !Supported() {
		t.Skipf("containment assertions apply to the demonstration's Linux containers, not %s", runtime.GOOS)
	}
	if !InRuntimeImage() {
		t.Skipf("not running in the demonstration's runtime image (%s unset)", RuntimeImageEnv)
	}
	checks := Run(t.TempDir())
	if !AllPassed(checks) {
		for _, c := range checks {
			if !c.Pass {
				t.Errorf("%s: %s", c.Name, c.Detail)
			}
		}
	}
}
