// Package trace renders the run transcript a learner reads.
//
// The transcript always has the same shape — request, source policy, queried
// sources, candidates, selection rule, selected origin, version, size, digest,
// integrity verdict, policy verdict, release mutation — because the point is
// that every one of those is visible without reading source code.
//
// Query order and trust policy are always rendered as separate fields. A build
// tool that lists a trusted index first has told you about display, not trust.
package trace

import (
	"fmt"
	"io"
	"strings"

	"indexjack/internal/pkgarchive"
	"indexjack/internal/releasegate"
	"indexjack/internal/resolver"
)

const labelWidth = 22

// Style is the presentation the resolved report-format dependency asks for.
// It is data read out of a package artifact and nothing else: no template is
// executed, and an unknown value can never reach here because the loader only
// accepts enumerated ones.
type Style struct {
	Title     string
	Divider   string
	FieldCase string
	Source    string
}

// fallbackStyle is used when the report-format dependency was not resolved,
// which happens whenever the build failed closed before reaching it.
func fallbackStyle() Style {
	return Style{Title: "plain", Divider: "dash", FieldCase: "lower", Source: "built-in fallback"}
}

// StyleFrom reads the enumerated presentation values out of a resolved
// report-format package.
func StyleFrom(res *resolver.Resolution) Style {
	if res == nil || res.Package == nil || res.Package.Policy.Kind != pkgarchive.KindReportFormat {
		return fallbackStyle()
	}
	style := Style{Title: "plain", Divider: "dash", FieldCase: "lower"}
	style.Source = fmt.Sprintf("%s@%s from %s", res.Name, res.Selected.Version, res.Selected.Source)
	if v, ok := res.Package.Policy.Lookup("title_style"); ok {
		style.Title = v
	}
	if v, ok := res.Package.Policy.Lookup("divider"); ok {
		style.Divider = v
	}
	if v, ok := res.Package.Policy.Lookup("field_case"); ok {
		style.FieldCase = v
	}
	return style
}

func (s Style) dividerRune() string {
	if s.Divider == "equals" {
		return "="
	}
	return "-"
}

func (s Style) title(text string) string {
	if s.Title == "upper" {
		return strings.ToUpper(text)
	}
	return text
}

func (s Style) field(label string) string {
	if s.FieldCase == "upper" {
		return strings.ToUpper(label)
	}
	return strings.ToLower(label)
}

type printer struct {
	w     io.Writer
	style Style
	err   error
}

func (p *printer) line(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format+"\n", args...)
}

func (p *printer) field(label, format string, args ...any) {
	p.line("%-*s %s", labelWidth, p.style.field(label)+":", fmt.Sprintf(format, args...))
}

func (p *printer) rule() {
	p.line("%s", strings.Repeat(p.style.dividerRune(), 72))
}

// Render writes the transcript for one outcome.
func Render(w io.Writer, out *releasegate.Outcome) error {
	style := StyleFrom(out.ReportFormat)
	p := &printer{w: w, style: style}

	p.rule()
	p.line("%s", style.title("indexjack — local dependency-confusion demonstration"))
	p.rule()
	p.field("scenario", "%s", out.Scenario.ID)
	p.field("summary", "%s", out.Scenario.Summary)
	p.field("project", "%s", out.Project)
	p.field("report format", "%s", style.Source)
	p.line("")

	for _, res := range out.Resolutions {
		renderResolution(p, res)
	}
	// The dependency the build stopped on is shown too: its policy, query set
	// and candidates are what explain the failure.
	if out.Attempted != nil {
		renderResolution(p, out.Attempted)
	}

	p.line("%s", style.title("release decision"))
	if out.Verdict != "" {
		p.field("policy verdict", "%s for %s", out.Verdict, out.Scenario.Candidate)
	} else {
		p.field("policy verdict", "not reached")
	}
	p.field("gate classification", "%s is %s in the gate's own record", out.Scenario.Candidate, valueOr(out.Classification, "unclassified"))
	switch out.Mutation {
	case releasegate.MutationApproved:
		p.field("release mutation", "one release row added for %s", out.Scenario.Candidate)
	case releasegate.MutationSuppressed:
		p.field("release mutation", "none — %s was already released exactly once", out.Scenario.Candidate)
	default:
		p.field("release mutation", "none")
	}
	if out.LedgerBefore == out.LedgerAfter {
		p.field("release ledger", "byte-for-byte unchanged")
	} else {
		p.field("release ledger", "changed")
	}
	p.line("")

	p.line("%s", style.title("local operator evidence (never returned to the build's consumer)"))
	if out.Failure != nil {
		p.field("failure class", "%s at stage %s", out.Failure.Class, out.Failure.Stage)
		p.field("failure detail", "%v", out.Failure.Err)
	}
	for _, e := range out.AuditEvents {
		if e.FailureClass != "" {
			p.field("audit event", "%s (%s) correlation %s", e.Event, e.FailureClass, e.CorrelationID)
			continue
		}
		p.field("audit event", "%s correlation %s", e.Event, e.CorrelationID)
	}
	p.line("")

	response, err := out.ClientResponse()
	if err != nil {
		return err
	}
	p.line("%s", style.title("returned to the build's consumer"))
	p.field("client response", "%s", strings.TrimSpace(string(response)))
	p.rule()
	return p.err
}

func renderResolution(p *printer, res *resolver.Resolution) {
	p.line("%s", p.style.title(fmt.Sprintf("dependency %q", res.Alias)))
	p.field("request", "%s %s", res.Name, res.Range)
	p.field("source policy", "%s → %s (%s)", res.Policy.Pattern, res.Policy.Bound.ID, res.Policy.Mode)
	p.field("index display order", "%s", strings.Join(res.DisplayOrder, ", "))
	p.field("queried sources", "%s", strings.Join(res.Queried, ", "))
	p.field("excluded sources", "%s", valueOr(strings.Join(res.Excluded, ", "), "none"))
	p.field("lock record", "%s@%s from %s, %d bytes, %s",
		res.Locked.Name, res.Locked.Version, res.Locked.Source, res.Locked.Size, res.Locked.SHA256)
	if len(res.Candidates) == 0 {
		p.field("candidates", "none")
	}
	for i, c := range res.Candidates {
		label := "candidates"
		if i > 0 {
			label = ""
		}
		p.line("%-*s %s %s (source-reported %d bytes, %s)",
			labelWidth, p.style.field(label)+colonIf(label), c.Source, c.Version, c.Size, c.SHA256)
	}
	p.field("selection rule", "%s", resolver.SelectionRule)
	if res.Selected.Source == "" {
		p.field("selected origin", "none — nothing was accepted")
		p.field("integrity verdict", "not reached — no artifact content was read")
		p.line("")
		return
	}
	p.field("selected origin", "%s (%s)", res.Selected.Source, res.Policy.Bound.Role)
	p.field("selected version", "%s", res.Selected.Version)
	p.field("selected size", "%d bytes", res.Size)
	p.field("selected digest", "%s", res.Digest)
	p.field("integrity verdict", "%s — locked size and digest matched before any content was read", res.Integrity)
	p.line("")
}

func colonIf(label string) string {
	if label == "" {
		return " "
	}
	return ":"
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
