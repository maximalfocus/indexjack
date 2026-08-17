// Package containment asserts the runtime boundary this demonstration claims.
//
// Every claim here is checked at run time rather than described in prose: the
// process is unprivileged, its root filesystem is read-only, its only writable
// place is the disposable state directory, and it has no way out of the
// container network.
package containment

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Check is one containment assertion.
type Check struct {
	Name   string
	Detail string
	Pass   bool
}

// Supported reports whether the runtime exposes what these checks read. They
// are Linux container assertions; on a developer workstation they are simply
// not the environment being asserted.
func Supported() bool { return runtime.GOOS == "linux" }

// externalProbe is a routable public address the demonstration must not be able
// to reach. Nothing is sent to it: the connection attempt is expected to fail
// before any packet leaves the container network, and the check fails if it
// ever succeeds.
const externalProbe = "1.1.1.1:443"

// externalName is looked up only to prove that name resolution for anything
// outside the container network does not work. It is the domain reserved for
// documentation, chosen precisely because it does resolve in the public DNS:
// a name that could never resolve anywhere would make this assertion empty.
const externalName = "example.com"

// Run executes every containment check. stateDir is the run's disposable
// writable directory.
func Run(stateDir string) []Check {
	return []Check{
		nonRootUser(),
		noNewPrivileges(),
		capabilitiesDropped(),
		readOnlyRootFilesystem(),
		stateDirWritable(stateDir),
		noDefaultRoute(),
		externalConnectionRefused(),
		externalNameUnresolvable(),
	}
}

// AllPassed reports whether every check passed.
func AllPassed(checks []Check) bool {
	for _, c := range checks {
		if !c.Pass {
			return false
		}
	}
	return true
}

func nonRootUser() Check {
	uid, gid := os.Geteuid(), os.Getegid()
	return Check{
		Name:   "non_root_user",
		Detail: fmt.Sprintf("euid=%d egid=%d", uid, gid),
		Pass:   uid > 0 && gid > 0,
	}
}

func procStatusValue(key string) (string, error) {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		name, value, found := strings.Cut(line, ":")
		if found && name == key {
			return strings.TrimSpace(value), nil
		}
	}
	return "", fmt.Errorf("%q not present in /proc/self/status", key)
}

func noNewPrivileges() Check {
	value, err := procStatusValue("NoNewPrivs")
	if err != nil {
		return Check{Name: "no_new_privileges", Detail: err.Error()}
	}
	return Check{
		Name:   "no_new_privileges",
		Detail: "NoNewPrivs=" + value,
		Pass:   value == "1",
	}
}

func capabilitiesDropped() Check {
	value, err := procStatusValue("CapEff")
	if err != nil {
		return Check{Name: "capabilities_dropped", Detail: err.Error()}
	}
	return Check{
		Name:   "capabilities_dropped",
		Detail: "CapEff=" + value,
		Pass:   strings.Trim(value, "0") == "",
	}
}

func readOnlyRootFilesystem() Check {
	probe := "/indexjack-containment-probe"
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_ = f.Close()
		_ = os.Remove(probe)
		return Check{Name: "read_only_root_filesystem", Detail: "root filesystem accepted a write", Pass: false}
	}
	return Check{Name: "read_only_root_filesystem", Detail: err.Error(), Pass: true}
}

func stateDirWritable(stateDir string) Check {
	if stateDir == "" {
		return Check{Name: "disposable_state_writable", Detail: "no state directory given"}
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return Check{Name: "disposable_state_writable", Detail: err.Error()}
	}
	probe := filepath.Join(stateDir, ".containment-probe")
	if err := os.WriteFile(probe, []byte("probe\n"), 0o600); err != nil {
		return Check{Name: "disposable_state_writable", Detail: err.Error()}
	}
	if err := os.Remove(probe); err != nil {
		return Check{Name: "disposable_state_writable", Detail: err.Error()}
	}
	return Check{Name: "disposable_state_writable", Detail: stateDir + " is writable", Pass: true}
}

// noDefaultRoute reads the kernel routing table directly. A container attached
// only to an internal network has routes to that network and no default route,
// so there is nowhere for traffic to leave through.
func noDefaultRoute() Check {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return Check{Name: "no_default_route", Detail: err.Error()}
	}
	for i, line := range strings.Split(string(raw), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			return Check{Name: "no_default_route", Detail: "default route via " + fields[0], Pass: false}
		}
	}
	return Check{Name: "no_default_route", Detail: "no default route in /proc/net/route", Pass: true}
}

func externalConnectionRefused() Check {
	conn, err := net.DialTimeout("tcp", externalProbe, 3*time.Second)
	if err == nil {
		_ = conn.Close()
		return Check{Name: "external_connection_refused", Detail: "connected to " + externalProbe, Pass: false}
	}
	return Check{Name: "external_connection_refused", Detail: err.Error(), Pass: true}
}

func externalNameUnresolvable() Check {
	addrs, err := net.LookupHost(externalName)
	if err == nil {
		return Check{
			Name:   "external_name_unresolvable",
			Detail: fmt.Sprintf("%s resolved to %s", externalName, strings.Join(addrs, ", ")),
			Pass:   false,
		}
	}
	return Check{Name: "external_name_unresolvable", Detail: err.Error(), Pass: true}
}
