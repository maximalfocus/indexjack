package canonicaljson

import (
	"errors"
	"strings"
	"testing"
)

type doc struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestMarshalIsStableAndNewlineTerminated(t *testing.T) {
	first, err := Marshal(doc{Name: "glasswing", Count: 2})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	second, err := Marshal(doc{Name: "glasswing", Count: 2})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("Marshal is not deterministic: %q vs %q", first, second)
	}
	if want := "{\"name\":\"glasswing\",\"count\":2}\n"; string(first) != want {
		t.Fatalf("Marshal = %q, want %q", first, want)
	}
}

func TestMarshalDoesNotEscapeHTML(t *testing.T) {
	out, err := Marshal(doc{Name: "a<b&c>d"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(out), "a<b&c>d") {
		t.Fatalf("Marshal escaped HTML: %q", out)
	}
}

func TestUnmarshalRejectsDuplicateKeys(t *testing.T) {
	var got doc
	err := Unmarshal([]byte(`{"name":"a","name":"b"}`), &got)
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("Unmarshal error = %v, want ErrDuplicateKey", err)
	}
}

func TestUnmarshalRejectsNestedDuplicateKeys(t *testing.T) {
	var got map[string]any
	err := Unmarshal([]byte(`{"outer":[{"k":1,"k":2}]}`), &got)
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("Unmarshal error = %v, want ErrDuplicateKey", err)
	}
}

func TestUnmarshalRejectsUnknownFields(t *testing.T) {
	var got doc
	if err := Unmarshal([]byte(`{"name":"a","extra":1}`), &got); err == nil {
		t.Fatal("Unmarshal accepted an unknown field")
	}
}

func TestUnmarshalRejectsTrailingContent(t *testing.T) {
	var got doc
	if err := Unmarshal([]byte(`{"name":"a"} {"name":"b"}`), &got); err == nil {
		t.Fatal("Unmarshal accepted trailing content")
	}
}

func TestUnmarshalAcceptsCanonicalDocument(t *testing.T) {
	var got doc
	if err := Unmarshal([]byte(`{"name":"a","count":3}`), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Name != "a" || got.Count != 3 {
		t.Fatalf("got %+v", got)
	}
}

func TestCheckDuplicateKeysRejectsDeepNesting(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40)
	if err := CheckDuplicateKeys([]byte(deep)); err == nil {
		t.Fatal("CheckDuplicateKeys accepted excessive nesting")
	}
}
