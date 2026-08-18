package harness

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"indexjack/internal/fixtures"
	"indexjack/internal/vulnerable"
)

const labelWidth = 24

// digestPrefix shortens a digest for a table while keeping enough of it to be
// compared by eye. Full digests stay in the transcript.
func digestPrefix(digest string) string {
	body := strings.TrimPrefix(digest, "sha256:")
	if body == "" {
		return "—"
	}
	if len(body) > 12 {
		body = body[:12]
	}
	return body
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

type printer struct {
	w   io.Writer
	err error
}

func (p *printer) line(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format+"\n", args...)
}

func (p *printer) field(label, format string, args ...any) {
	p.line("%-*s %s", labelWidth, label+":", fmt.Sprintf(format, args...))
}

// Render writes the human-readable transcript. It carries exactly what the
// machine-readable form carries, in the same order.
func Render(w io.Writer, t *Transcript) error {
	p := &printer{w: w}
	p.line("%s", strings.Repeat("=", 78))
	p.line("SCENARIO %s", strings.ToUpper(t.Scenario.ID))
	if t.Warning != "" {
		p.line("!! %s", strings.ToUpper(t.Warning))
	}
	p.line("%s", strings.Repeat("=", 78))
	p.field("summary", "%s", t.Scenario.Summary)
	p.field("resolver", "%s", t.Resolver)
	p.field("lock enforcement", "%s", t.LockEnforcement)
	p.field("project", "%s", t.Project)
	p.field("fixtures", "policy=%s manifest=%s lock=%s", t.Scenario.SourcePolicy, t.Scenario.Manifest, t.Scenario.Lock)
	p.field("correlation", "%s", t.CorrelationID)
	p.line("")

	if len(t.Dependencies) == 0 {
		p.line("DEPENDENCY RESOLUTION")
		p.field("resolved", "none — the build failed closed on its first dependency")
		p.line("")
	}
	for _, dep := range t.Dependencies {
		p.line("DEPENDENCY %q", dep.Alias)
		p.field("request", "%s %s", dep.Request.Name, dep.Request.Range)
		p.field("source policy", "%s → %s (%s)", dep.SourcePolicy.Pattern, policyTarget(dep.SourcePolicy), dep.SourcePolicy.Mode)
		p.field("index display order", "%s", strings.Join(dep.IndexDisplayOrder, ", "))
		p.field("queried sources", "%s", valueOr(strings.Join(dep.QueriedSources, ", "), "none"))
		p.field("excluded sources", "%s", valueOr(strings.Join(dep.SourcePolicy.Excluded, ", "), "none"))
		for i, c := range dep.Candidates {
			label := "candidates"
			if i > 0 {
				label = ""
			}
			p.line("%-*s %s %s (source-reported %d bytes, %s)",
				labelWidth, labelOrPad(label), c.Source, c.Version, c.Size, c.SHA256)
		}
		p.field("selection rule", "%s", dep.SelectionRule)
		p.field("selected origin", "%s (%s)", dep.Selected.Source, dep.Selected.Role)
		p.field("selected version", "%s", dep.Selected.Version)
		p.field("selected size", "%d bytes", dep.Selected.Size)
		p.field("selected digest", "%s", dep.Selected.SHA256)
		p.field("integrity verdict", "%s", dep.Integrity)
		p.line("")
	}

	p.line("REGISTRY-OBSERVED REQUESTS (each registry's own signed account)")
	for _, r := range t.Receipts {
		p.field(r.Source, "%d request(s), role=%s revision=%s, signature %s",
			r.RequestCount, r.Role, r.Revision, verified(r.SignatureVerified))
		for _, request := range r.Requests {
			p.line("%-*s %s %s → %d", labelWidth, "", request.Path, valueOr(request.Name+atVersion(request.Version), "—"), request.Status)
		}
	}
	p.line("")

	p.line("RELEASE DECISION")
	p.field("policy verdict", "%s", valueOr(t.Release.PolicyVerdict, "not reached"))
	p.field("gate classification", "%s is %s", t.Release.Candidate, valueOr(t.Release.GateClassification, "unclassified"))
	p.field("release mutation", "%s", t.Release.Mutation)
	p.field("ledger before", "%s", t.Ledger.Before)
	p.field("ledger after", "%s", t.Ledger.After)
	p.field("ledger changed", "%t (%d entr%s)", t.Ledger.Changed, t.Ledger.Entries, plural(t.Ledger.Entries))
	p.line("")

	p.line("LOCAL OPERATOR EVIDENCE (never returned to the build's consumer)")
	if t.Failure != nil {
		p.field("failure", "%s at stage %s", t.Failure.Class, t.Failure.Stage)
	}
	for _, record := range t.Audit {
		p.field("audit event", "%s%s", record.Event, bracket(record.FailureClass))
	}
	p.line("")

	p.line("RECONCILIATION")
	p.field("result", "%s — %s", t.Reconciliation.Result, t.Reconciliation.Statement)
	if t.Reconciliation.Origin != "" {
		p.field("selected origin", "%s", t.Reconciliation.Origin)
		p.field("selected digest", "%s", t.Reconciliation.Digest)
	}
	p.field("client response", "{\"format\":%q,\"result\":%q}", t.ClientResponse.Format, t.ClientResponse.Result)
	p.line("%s", strings.Repeat("=", 78))
	return p.err
}

func labelOrPad(label string) string {
	if label == "" {
		return ""
	}
	return label + ":"
}

func atVersion(version string) string {
	if version == "" {
		return ""
	}
	return "@" + version
}

func verified(ok bool) string {
	if ok {
		return "verified"
	}
	return "NOT VERIFIED"
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func bracket(value string) string {
	if value == "" {
		return ""
	}
	return " (" + value + ")"
}

// Matrix runs every reachable scenario from fresh state, in checked-in order.
// The intentionally vulnerable scenarios are included only when both opt-in
// controls are satisfied; otherwise they are simply not there.
func Matrix(ctx context.Context, opts Options) ([]*Transcript, error) {
	ids, err := fixtures.DefaultScenarioIDs()
	if vulnerable.Acknowledged() {
		ids, err = fixtures.ScenarioIDs()
	}
	if err != nil {
		return nil, err
	}
	out := make([]*Transcript, 0, len(ids))
	for _, id := range ids {
		stateDir := filepath.Join(opts.StateDir, "scenarios", id)
		if err := os.RemoveAll(stateDir); err != nil {
			return nil, err
		}
		transcript, err := Run(ctx, Options{ScenarioID: id, StateDir: stateDir, Endpoints: opts.Endpoints})
		if err != nil {
			return nil, err
		}
		out = append(out, transcript)
	}
	return out, nil
}

// RenderMatrix prints one row per scenario. Every column is a fact the run
// observed, and the queried-sources column comes from the registries' own
// receipts rather than from the resolver.
func RenderMatrix(w io.Writer, transcripts []*Transcript) error {
	columns := []string{
		"scenario", "source policy", "queried (observed)", "selected origin",
		"version", "digest", "integrity", "verdict", "mutation", "ledger", "reconciliation",
	}
	rows := make([][]string, 0, len(transcripts))
	for _, t := range transcripts {
		rows = append(rows, []string{
			t.Scenario.ID,
			policyColumn(t),
			queriedColumn(t),
			valueOr(selectedOf(t).Source, "—"),
			valueOr(selectedOf(t).Version, "—"),
			digestPrefix(selectedOf(t).SHA256),
			valueOr(integrityOf(t), "—"),
			valueOr(t.Release.PolicyVerdict, "—"),
			t.Release.Mutation,
			fmt.Sprintf("%s→%s", digestPrefix(t.Ledger.Before), digestPrefix(t.Ledger.After)),
			t.Reconciliation.Result,
		})
	}

	widths := make([]int, len(columns))
	for i, c := range columns {
		widths[i] = len(c)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	p := &printer{w: w}
	p.line("%s", renderRow(columns, widths))
	separators := make([]string, len(columns))
	for i := range separators {
		separators[i] = strings.Repeat("-", widths[i])
	}
	p.line("%s", renderRow(separators, widths))
	for _, row := range rows {
		p.line("%s", renderRow(row, widths))
	}
	return p.err
}

func renderRow(cells []string, widths []int) string {
	parts := make([]string, len(cells))
	for i, cell := range cells {
		parts[i] = fmt.Sprintf("%-*s", widths[i], cell)
	}
	return strings.TrimRight(strings.Join(parts, "  "), " ")
}

func releasePolicyDependency(t *Transcript) *Dependency {
	for i := range t.Dependencies {
		if t.Dependencies[i].Alias == "release-policy" {
			return &t.Dependencies[i]
		}
	}
	return nil
}

// policyTarget renders what a mapping points at: one bound source, or the pool
// a combined mapping considers instead of binding anything.
func policyTarget(policy SourcePolicy) string {
	if policy.Bound != "" {
		return policy.Bound
	}
	if len(policy.Pool) > 0 {
		return strings.Join(policy.Pool, " + ")
	}
	return "nothing"
}

func policyColumn(t *Transcript) string {
	if dep := releasePolicyDependency(t); dep != nil {
		return dep.SourcePolicy.Pattern + "→" + policyTarget(dep.SourcePolicy)
	}
	return "—"
}

func selectedOf(t *Transcript) Selected {
	if dep := releasePolicyDependency(t); dep != nil {
		return dep.Selected
	}
	return Selected{}
}

func integrityOf(t *Transcript) string {
	if dep := releasePolicyDependency(t); dep != nil {
		return dep.Integrity
	}
	return ""
}

func queriedColumn(t *Transcript) string {
	parts := make([]string, 0, len(t.Receipts))
	for _, r := range t.Receipts {
		if r.RequestCount == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%d)", r.Source, r.RequestCount))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}
