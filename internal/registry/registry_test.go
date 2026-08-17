package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"indexjack/internal/pkgarchive"
)

func fixtureSet() FixtureSet {
	return FixtureSet{
		ID:       "glasswing-private",
		Role:     "private",
		Revision: "glasswing-private/1",
		Packages: []Package{{
			Name: "@glasswing/release-policy",
			Versions: []Artifact{
				{Version: "1.4.2", Bytes: []byte("one-four-two")},
				{Version: "1.5.0", Bytes: []byte("one-five-zero")},
			},
		}},
	}
}

func newServer(t *testing.T) (*httptest.Server, *Handler) {
	t.Helper()
	handler := NewHandler(fixtureSet())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, handler
}

func TestMetadataListsOnlyCheckedInVersions(t *testing.T) {
	server, handler := newServer(t)
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	meta, err := client.Metadata(context.Background(), "@glasswing/release-policy")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if meta.Source != "glasswing-private" || meta.Role != "private" {
		t.Fatalf("metadata = %+v", meta)
	}
	if len(meta.Versions) != 2 || meta.Versions[0].Version != "1.4.2" || meta.Versions[1].Version != "1.5.0" {
		t.Fatalf("versions = %+v", meta.Versions)
	}
	if meta.Versions[0].SHA256 != pkgarchive.Digest([]byte("one-four-two")) {
		t.Fatalf("digest = %q", meta.Versions[0].SHA256)
	}
	// Every request is observable at the boundary, with the name it asked for.
	requests := handler.Requests()
	if len(requests) != 1 || requests[0].Name != "@glasswing/release-policy" || requests[0].Status != http.StatusOK {
		t.Fatalf("requests = %+v", requests)
	}
}

func TestArtifactReturnsExactBytes(t *testing.T) {
	server, _ := newServer(t)
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	raw, err := client.Artifact(context.Background(), "@glasswing/release-policy", "1.5.0")
	if err != nil {
		t.Fatalf("Artifact: %v", err)
	}
	if string(raw) != "one-five-zero" {
		t.Fatalf("artifact = %q", raw)
	}
	if _, err := client.Artifact(context.Background(), "@glasswing/release-policy", "9.9.9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// The registry's refusals are the security surface: no write, no listing, no
// search, no arbitrary name, and no second parameter to smuggle one in.
func TestServiceSurfaceIsReadOnlyAndEnumerated(t *testing.T) {
	server, _ := newServer(t)
	cases := []struct {
		name   string
		method string
		target string
		want   int
	}{
		{"post metadata", http.MethodPost, MetadataPath + "?name=@glasswing/release-policy", http.StatusMethodNotAllowed},
		{"put artifact", http.MethodPut, ArtifactPath + "?name=@glasswing/release-policy&version=1.4.2", http.StatusMethodNotAllowed},
		{"delete artifact", http.MethodDelete, ArtifactPath + "?name=@glasswing/release-policy&version=1.4.2", http.StatusMethodNotAllowed},
		{"patch metadata", http.MethodPatch, MetadataPath + "?name=@glasswing/release-policy", http.StatusMethodNotAllowed},
		{"upload endpoint", http.MethodGet, "/v1/upload", http.StatusNotFound},
		{"search endpoint", http.MethodGet, "/v1/search?q=glasswing", http.StatusNotFound},
		{"listing endpoint", http.MethodGet, "/v1/packages", http.StatusNotFound},
		{"root", http.MethodGet, "/", http.StatusNotFound},
		{"unknown name", http.MethodGet, MetadataPath + "?name=@attacker/anything", http.StatusNotFound},
		{"missing name", http.MethodGet, MetadataPath, http.StatusBadRequest},
		{"empty name", http.MethodGet, MetadataPath + "?name=", http.StatusBadRequest},
		{"repeated name", http.MethodGet, MetadataPath + "?name=@glasswing/release-policy&name=@attacker/x", http.StatusBadRequest},
		{"extra parameter", http.MethodGet, MetadataPath + "?name=@glasswing/release-policy&mirror=1", http.StatusBadRequest},
		{"artifact missing version", http.MethodGet, ArtifactPath + "?name=@glasswing/release-policy", http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequest(c.method, server.URL+c.target, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, c.want)
			}
			if got := resp.Header.Get(HeaderRole); got != "private" {
				t.Fatalf("role header = %q", got)
			}
			if got := resp.Header.Get(HeaderRevision); got != "glasswing-private/1" {
				t.Fatalf("revision header = %q", got)
			}
		})
	}
}

// An absent name and an absent version are reported identically, so a probe
// cannot use the registry to discover what a private namespace contains.
func TestAbsenceIsReportedIdentically(t *testing.T) {
	server, _ := newServer(t)
	unknownName, err := http.Get(server.URL + MetadataPath + "?name=@attacker/anything")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer unknownName.Body.Close()
	unknownVersion, err := http.Get(server.URL + ArtifactPath + "?name=@glasswing/release-policy&version=9.9.9")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer unknownVersion.Body.Close()
	if unknownName.StatusCode != unknownVersion.StatusCode {
		t.Fatalf("statuses differ: %d vs %d", unknownName.StatusCode, unknownVersion.StatusCode)
	}
}

func TestClientRefusesHostsOutsideTheDemonstration(t *testing.T) {
	for _, base := range []string{
		"http://packages.private.example.test",
		"http://packages.private.example.attacker.test",
		"http://packages.private.exampleattacker",
		"https://packages.private.example:8080",
		"file:///etc/passwd",
		"http://169.254.169.254",
	} {
		if _, err := NewClient(base); !errors.Is(err, ErrDisallowed) {
			t.Fatalf("NewClient(%q) error = %v, want ErrDisallowed", base, err)
		}
	}
	for _, base := range []string{
		"http://packages.private.example:8080",
		"http://packages.public.example:8080",
		"http://127.0.0.1:1234",
	} {
		if _, err := NewClient(base); err != nil {
			t.Fatalf("NewClient(%q): %v", base, err)
		}
	}
}

func TestClientRefusesRedirects(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/somewhere", http.StatusFound)
	}))
	defer elsewhere.Close()

	client, err := NewClient(elsewhere.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Metadata(context.Background(), "@glasswing/release-policy"); err == nil {
		t.Fatal("client followed a redirect")
	}
}

func TestResetClearsObservationsButNotContent(t *testing.T) {
	server, handler := newServer(t)
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Metadata(context.Background(), "@glasswing/release-policy"); err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	handler.Reset()
	if len(handler.Requests()) != 0 {
		t.Fatal("Reset did not clear observations")
	}
	if _, err := client.Metadata(context.Background(), "@glasswing/release-policy"); err != nil {
		t.Fatalf("Metadata after reset: %v", err)
	}
}
