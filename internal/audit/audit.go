// Package audit emits the demonstration's structured evidence.
//
// An audit record says what class of thing happened and which enumerated
// scenario it happened in. It deliberately carries no registry credential, no
// package bytes, no model content, and no URL: an audit trail that leaks the
// thing it is auditing is not a control.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"indexjack/internal/canonicaljson"
)

// Format is the audit record version.
const Format = "indexjack-audit/1"

// Stable event names.
const (
	EventBuildFailed      = "BUILD_FAILED"
	EventReleaseRejected  = "RELEASE_REJECTED"
	EventReleaseApproved  = "RELEASE_APPROVED"
	EventReleaseDuplicate = "RELEASE_DUPLICATE"
)

// Event is one structured audit record.
type Event struct {
	Format          string `json:"format"`
	Event           string `json:"event"`
	CorrelationID   string `json:"correlation_id"`
	ScenarioID      string `json:"scenario_id"`
	Stage           string `json:"stage"`
	DependencyAlias string `json:"dependency_alias,omitempty"`
	FailureClass    string `json:"failure_class,omitempty"`
	CandidateID     string `json:"candidate_id,omitempty"`
}

// CorrelationID derives a stable correlation id from the scenario id. It is
// deterministic on purpose: it correlates records within a run and across
// reruns, and it identifies nobody.
func CorrelationID(scenarioID string) string {
	sum := sha256.Sum256([]byte("indexjack-correlation:" + scenarioID))
	return hex.EncodeToString(sum[:])[:16]
}

// Sink appends audit records to a file and mirrors them to a writer so a
// learner sees the same evidence the tests assert on.
type Sink struct {
	path     string
	mirror   io.Writer
	emitted  []Event
	scenario string
}

// NewSink returns a sink writing to path and mirroring to mirror, which may be
// nil.
func NewSink(path, scenarioID string, mirror io.Writer) *Sink {
	return &Sink{path: path, scenario: scenarioID, mirror: mirror}
}

// Emit writes exactly one record.
func (s *Sink) Emit(e Event) error {
	e.Format = Format
	e.ScenarioID = s.scenario
	e.CorrelationID = CorrelationID(s.scenario)
	if err := validate(e); err != nil {
		return err
	}
	line, err := canonicaljson.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	s.emitted = append(s.emitted, e)
	if s.mirror != nil {
		if _, err := fmt.Fprintf(s.mirror, "audit: %s", line); err != nil {
			return err
		}
	}
	return nil
}

// Emitted returns the records this sink wrote, in order.
func (s *Sink) Emitted() []Event {
	out := make([]Event, len(s.emitted))
	copy(out, s.emitted)
	return out
}

// Read parses an audit file.
func Read(path string) ([]Event, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e Event
		if err := canonicaljson.Unmarshal([]byte(line), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// forbidden are substrings an audit record must never contain. Checking is
// cheap and turns "we would never log that" into something enforced.
var forbidden = []string{"http://", "https://", "-----BEGIN", "password", "token", "secret"}

func validate(e Event) error {
	if e.Event == "" || e.Stage == "" || e.ScenarioID == "" || e.CorrelationID == "" {
		return fmt.Errorf("audit record is incomplete: %+v", e)
	}
	for _, field := range []string{e.Event, e.ScenarioID, e.Stage, e.DependencyAlias, e.FailureClass, e.CandidateID} {
		lowered := strings.ToLower(field)
		for _, bad := range forbidden {
			if strings.Contains(lowered, strings.ToLower(bad)) {
				return fmt.Errorf("audit record field %q contains disallowed content", field)
			}
		}
	}
	return nil
}
