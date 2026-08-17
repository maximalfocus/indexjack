package audit

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestCorrelationIDIsDeterministicPerScenario(t *testing.T) {
	first := CorrelationID("secure-unsafe-candidate")
	second := CorrelationID("secure-unsafe-candidate")
	other := CorrelationID("secure-safe-candidate")
	if first != second {
		t.Fatalf("correlation id is not deterministic: %q vs %q", first, second)
	}
	if first == other {
		t.Fatal("two scenarios share a correlation id")
	}
	if len(first) != 16 {
		t.Fatalf("correlation id = %q", first)
	}
}

func TestEmitWritesExactlyOneRecordAndMirrorsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var mirror bytes.Buffer
	sink := NewSink(path, "secure-missing-artifact", &mirror)

	if err := sink.Emit(Event{Event: EventBuildFailed, Stage: "registry_query", DependencyAlias: "release-policy", FailureClass: "ARTIFACT_UNAVAILABLE"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	records, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("%d records written", len(records))
	}
	got := records[0]
	if got.Format != Format || got.Event != EventBuildFailed || got.ScenarioID != "secure-missing-artifact" {
		t.Fatalf("record = %+v", got)
	}
	if got.CorrelationID != CorrelationID("secure-missing-artifact") {
		t.Fatalf("correlation id = %q", got.CorrelationID)
	}
	if len(sink.Emitted()) != 1 {
		t.Fatalf("sink recorded %d events", len(sink.Emitted()))
	}
	if !strings.HasPrefix(mirror.String(), "audit: {") {
		t.Fatalf("mirror = %q", mirror.String())
	}
}

func TestEmitRefusesRecordsThatWouldLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := NewSink(path, "secure-unsafe-candidate", nil)
	for _, bad := range []Event{
		{Event: EventBuildFailed, Stage: "registry_query", DependencyAlias: "http://packages.public.example:8080"},
		{Event: EventBuildFailed, Stage: "registry_query", FailureClass: "TOKEN_REJECTED"},
		{Event: "", Stage: "registry_query"},
		{Event: EventBuildFailed, Stage: ""},
	} {
		if err := sink.Emit(bad); err == nil {
			t.Fatalf("Emit accepted %+v", bad)
		}
	}
	if len(sink.Emitted()) != 0 {
		t.Fatalf("sink recorded %d events", len(sink.Emitted()))
	}
}

func TestReadReturnsRecordsInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := NewSink(path, "secure-safe-candidate", nil)
	for _, name := range []string{EventReleaseApproved, EventReleaseDuplicate} {
		if err := sink.Emit(Event{Event: name, Stage: "policy_evaluation", CandidateID: "MODEL-CANDIDATE-04"}); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	records, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(records) != 2 || records[0].Event != EventReleaseApproved || records[1].Event != EventReleaseDuplicate {
		t.Fatalf("records = %+v", records)
	}
}
