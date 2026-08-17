// Command indexjack runs every part of this local, self-contained
// demonstration: the immutable fixture registries, one enumerated release
// scenario, and the verification gate.
//
// Nothing it does reaches outside the container network, and nothing it accepts
// is free-form: scenarios and fixture sets are named, checked-in, enumerated
// values.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"indexjack/internal/canonicaljson"
	"indexjack/internal/fixtures"
	"indexjack/internal/harness"
	"indexjack/internal/registry"
	"indexjack/internal/releasegate"
	"indexjack/internal/trace"
	"indexjack/internal/verify"
)

// defaultStateDir is the disposable tmpfs the containers mount. It is the only
// writable path the demonstration uses.
const defaultStateDir = "/run/indexjack"

const usage = `indexjack — local dependency-confusion demonstration

usage:
  indexjack registry --fixtures ID [--listen ADDR]   serve one immutable registry fixture set
  indexjack release --scenario ID [--state-dir DIR]  run one enumerated scenario
  indexjack harness --scenario ID | --matrix         run scenarios and record the full provenance trace
  indexjack verify [--state-dir DIR]                 run the full verification gate
  indexjack scenarios                                list the enumerated scenarios
  indexjack fixtures                                 list the built artifacts and their digests
  indexjack healthcheck [--address ADDR]             report whether a registry is accepting connections

Everything is fictional and local. No real registry, package, organization, or
model is contacted, named, or described.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "indexjack: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("a command is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "registry":
		return runRegistry(ctx, args[1:])
	case "release":
		return runRelease(ctx, args[1:])
	case "harness":
		return runHarness(ctx, args[1:])
	case "verify":
		return runVerify(ctx, args[1:])
	case "healthcheck":
		return runHealthcheck(args[1:])
	case "scenarios":
		return listScenarios()
	case "fixtures":
		return listFixtures()
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runRegistry(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("registry", flag.ContinueOnError)
	fixtureSet := fs.String("fixtures", "", "checked-in registry fixture set to serve")
	listen := fs.String("listen", ":8080", "address to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ids, err := fixtures.RegistrySetIDs()
	if err != nil {
		return err
	}
	if !contains(ids, *fixtureSet) {
		return fmt.Errorf("--fixtures must be one of: %s", strings.Join(ids, ", "))
	}
	set, err := fixtures.RegistrySet(*fixtureSet)
	if err != nil {
		return err
	}
	boundary, err := fixtures.ReceiptBoundary()
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              *listen,
		Handler:           registry.NewHandler(set, boundary),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		// The service holds no state beyond its fixtures, so a small
		// header budget is all it ever needs.
		MaxHeaderBytes: 8 << 10,
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "registry %s (role=%s revision=%s) serving %d package(s) on %s\n",
		set.ID, set.Role, set.Revision, len(set.Packages), listener.Addr())

	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func runRelease(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	scenarioID := fs.String("scenario", "", "enumerated scenario to run")
	stateDir := fs.String("state-dir", defaultStateDir, "disposable directory for the release ledger and audit records")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ids, err := fixtures.ScenarioIDs()
	if err != nil {
		return err
	}
	if !contains(ids, *scenarioID) {
		return fmt.Errorf("--scenario must be one of: %s", strings.Join(ids, ", "))
	}
	scenario, err := fixtures.LoadScenario(*scenarioID)
	if err != nil {
		return err
	}

	out, err := releasegate.Execute(ctx, releasegate.Options{
		Scenario:    scenario,
		StateDir:    *stateDir,
		AuditMirror: os.Stderr,
	})
	if err != nil {
		return err
	}
	if err := trace.Render(os.Stdout, out); err != nil {
		return err
	}
	if out.Failed() {
		// A build that failed closed exits non-zero, exactly as a real build
		// would. In the fail-closed scenarios that is the intended result.
		return errors.New("build failed closed; see the transcript above")
	}
	return nil
}

func runHarness(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("harness", flag.ContinueOnError)
	scenarioID := fs.String("scenario", "", "enumerated scenario to run")
	matrix := fs.Bool("matrix", false, "run every enumerated scenario and print one row each")
	format := fs.String("format", "human", "transcript form: human or json")
	stateDir := fs.String("state-dir", defaultStateDir, "disposable directory for run state and transcripts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "human" && *format != "json" {
		return fmt.Errorf("--format must be human or json")
	}
	if *matrix == (*scenarioID != "") {
		return errors.New("pass exactly one of --scenario or --matrix")
	}

	if *matrix {
		transcripts, err := harness.Matrix(ctx, harness.Options{StateDir: *stateDir})
		if err != nil {
			return err
		}
		if *format == "json" {
			body, err := canonicaljson.Marshal(transcripts)
			if err != nil {
				return err
			}
			fmt.Print(string(body))
			return nil
		}
		return harness.RenderMatrix(os.Stdout, transcripts)
	}

	ids, err := fixtures.ScenarioIDs()
	if err != nil {
		return err
	}
	if !contains(ids, *scenarioID) {
		return fmt.Errorf("--scenario must be one of: %s", strings.Join(ids, ", "))
	}
	transcript, err := harness.Run(ctx, harness.Options{
		ScenarioID: *scenarioID,
		StateDir:   filepath.Join(*stateDir, "scenarios", *scenarioID),
	})
	if err != nil {
		return err
	}
	if *format == "json" {
		body, err := transcript.Bytes()
		if err != nil {
			return err
		}
		fmt.Print(string(body))
		return nil
	}
	return harness.Render(os.Stdout, transcript)
}

func runVerify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir, "disposable directory for verification state")
	skipContainment := fs.Bool("skip-containment", false, "skip the container runtime assertions")
	if err := fs.Parse(args); err != nil {
		return err
	}

	results, err := verify.RunAll(ctx, verify.Options{
		StateDir:        *stateDir,
		SkipContainment: *skipContainment,
		Trace:           os.Stdout,
		Progress:        os.Stderr,
	})
	if err != nil {
		return err
	}
	passed := 0
	var failures []string
	for _, r := range results {
		if r.Pass {
			passed++
			continue
		}
		failures = append(failures, fmt.Sprintf("%s/%s: %s", r.Group, r.Name, r.Detail))
	}
	fmt.Fprintf(os.Stderr, "\n%d/%d assertions passed\n", passed, len(results))
	if len(failures) > 0 {
		return fmt.Errorf("verification failed:\n  %s", strings.Join(failures, "\n  "))
	}
	return nil
}

// runHealthcheck reports whether a registry in this container is accepting
// connections. It opens a socket and closes it: the readiness probe adds no
// HTTP surface to the registry itself.
func runHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	address := fs.String("address", "127.0.0.1:8080", "address to probe")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", *address, 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

func listScenarios() error {
	scenarios, err := fixtures.Scenarios()
	if err != nil {
		return err
	}
	for _, s := range scenarios {
		fmt.Printf("%-26s %s\n", s.ID, s.Summary)
	}
	return nil
}

func listFixtures() error {
	artifacts, err := fixtures.Artifacts()
	if err != nil {
		return err
	}
	body, err := canonicaljson.Marshal(artifacts)
	if err != nil {
		return err
	}
	fmt.Print(string(body))
	return nil
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
