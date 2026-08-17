// Package registry is the immutable fixture registry: both the read-only
// service and the client the resolver uses to talk to it.
//
// The service is deliberately tiny. It exposes two read-only endpoints, serves
// only the enumerated artifacts checked into this repository, and has no
// upload, write, delete, search, listing, or arbitrary-name surface. A name it
// does not carry is simply absent, and absence is reported the same way for
// every name so that a probe learns nothing.
package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"indexjack/internal/canonicaljson"
	"indexjack/internal/pkgarchive"
	"indexjack/internal/semver"
)

// Wire formats and headers.
const (
	MetadataFormat = "indexjack-registry-metadata/1"

	HeaderRole     = "X-Indexjack-Registry-Role"
	HeaderRevision = "X-Indexjack-Fixture-Revision"
	HeaderSource   = "X-Indexjack-Source-Id"

	MetadataPath = "/v1/metadata"
	ArtifactPath = "/v1/artifact"

	maxMetadataBytes = 64 << 10
	maxArtifactBytes = 256 << 10
)

// Stable client errors.
var (
	ErrNotFound    = errors.New("registry has no such artifact")
	ErrUnavailable = errors.New("registry unavailable")
	ErrProtocol    = errors.New("registry response is not valid fixture protocol")
	ErrDisallowed  = errors.New("registry host is outside the demonstration network")
)

// VersionInfo is one published version.
//
// Size and SHA256 here are what the registry *says*. They are shown in the
// trace as candidate metadata and are never used as proof: the lock, not the
// source, decides which bytes are acceptable.
type VersionInfo struct {
	Version string `json:"version"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// Metadata is the response of the metadata endpoint.
type Metadata struct {
	Format   string        `json:"format"`
	Source   string        `json:"source"`
	Role     string        `json:"role"`
	Name     string        `json:"name"`
	Versions []VersionInfo `json:"versions"`
}

// Artifact is one immutable published artifact.
type Artifact struct {
	Version string
	Bytes   []byte
}

// Package is one published name with its versions.
type Package struct {
	Name     string
	Versions []Artifact
}

// FixtureSet is everything one registry service serves. It is built once at
// start-up from checked-in fixtures and never mutated afterwards.
type FixtureSet struct {
	ID       string
	Role     string
	Revision string
	Packages []Package
}

// Request is one observation at the registry boundary. Counting requests here,
// rather than trusting a client's own account of what it did, is what makes
// "the public registry was never asked" an observed fact.
type Request struct {
	Method  string
	Path    string
	Name    string
	Version string
	Status  int
}

// Handler serves one immutable fixture set.
type Handler struct {
	set FixtureSet

	mu       sync.Mutex
	requests []Request
}

// NewHandler returns a read-only handler for set.
func NewHandler(set FixtureSet) *Handler {
	return &Handler{set: set}
}

// Requests returns the requests observed so far, oldest first.
func (h *Handler) Requests() []Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Request, len(h.requests))
	copy(out, h.requests)
	return out
}

// Reset clears the observed requests. It never changes what is served.
func (h *Handler) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests = nil
}

func (h *Handler) record(r Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests = append(h.requests, r)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(HeaderRole, h.set.Role)
	w.Header().Set(HeaderRevision, h.set.Revision)
	w.Header().Set(HeaderSource, h.set.ID)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	req := Request{Method: r.Method, Path: r.URL.Path}
	defer func() { h.record(req) }()

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		req.Status = http.StatusMethodNotAllowed
		writeStatus(w, req.Status, "method_not_allowed")
		return
	}

	query := r.URL.Query()
	switch r.URL.Path {
	case MetadataPath:
		name, ok := single(query, "name")
		if !ok || len(query) != 1 {
			req.Status = http.StatusBadRequest
			writeStatus(w, req.Status, "bad_request")
			return
		}
		req.Name = name
		pkg, ok := h.pkg(name)
		if !ok {
			req.Status = http.StatusNotFound
			writeStatus(w, req.Status, "not_found")
			return
		}
		meta := Metadata{
			Format:   MetadataFormat,
			Source:   h.set.ID,
			Role:     h.set.Role,
			Name:     pkg.Name,
			Versions: make([]VersionInfo, 0, len(pkg.Versions)),
		}
		for _, a := range pkg.Versions {
			meta.Versions = append(meta.Versions, VersionInfo{
				Version: a.Version,
				Size:    int64(len(a.Bytes)),
				SHA256:  pkgarchive.Digest(a.Bytes),
			})
		}
		body, err := canonicaljson.Marshal(meta)
		if err != nil {
			req.Status = http.StatusInternalServerError
			writeStatus(w, req.Status, "internal_error")
			return
		}
		req.Status = http.StatusOK
		w.WriteHeader(req.Status)
		_, _ = w.Write(body)

	case ArtifactPath:
		name, okName := single(query, "name")
		version, okVersion := single(query, "version")
		if !okName || !okVersion || len(query) != 2 {
			req.Status = http.StatusBadRequest
			writeStatus(w, req.Status, "bad_request")
			return
		}
		req.Name, req.Version = name, version
		artifact, ok := h.artifact(name, version)
		if !ok {
			req.Status = http.StatusNotFound
			writeStatus(w, req.Status, "not_found")
			return
		}
		req.Status = http.StatusOK
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(req.Status)
		_, _ = w.Write(artifact.Bytes)

	default:
		req.Status = http.StatusNotFound
		writeStatus(w, req.Status, "not_found")
	}
}

// single returns the sole value of key, refusing repeated parameters so a
// request cannot smuggle a second name past the first check.
func single(q url.Values, key string) (string, bool) {
	values, ok := q[key]
	if !ok || len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func writeStatus(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	// Every refusal looks the same from outside: a probe cannot tell an
	// unknown name from a known name at an unknown version.
	_, _ = fmt.Fprintf(w, "{\"error\":%q}\n", code)
}

func (h *Handler) pkg(name string) (Package, bool) {
	for _, p := range h.set.Packages {
		if p.Name == name {
			return p, true
		}
	}
	return Package{}, false
}

func (h *Handler) artifact(name, version string) (Artifact, bool) {
	pkg, ok := h.pkg(name)
	if !ok {
		return Artifact{}, false
	}
	for _, a := range pkg.Versions {
		if a.Version == version {
			return a, true
		}
	}
	return Artifact{}, false
}

// Sort orders a fixture set deterministically: packages by name, versions
// ascending by semantic version.
func (s *FixtureSet) Sort() error {
	sort.Slice(s.Packages, func(i, j int) bool { return s.Packages[i].Name < s.Packages[j].Name })
	for _, p := range s.Packages {
		parsed := make(map[string]semver.Version, len(p.Versions))
		for _, a := range p.Versions {
			v, err := semver.Parse(a.Version)
			if err != nil {
				return fmt.Errorf("fixture set %q package %q: %w", s.ID, p.Name, err)
			}
			parsed[a.Version] = v
		}
		sort.SliceStable(p.Versions, func(i, j int) bool {
			return semver.Compare(parsed[p.Versions[i].Version], parsed[p.Versions[j].Version]) < 0
		})
	}
	return nil
}

// Client is the resolver's view of one registry.
type Client struct {
	base *url.URL
	http *http.Client
}

// NewClient returns a client for base.
//
// The host must be one of the demonstration's reserved .example fixture labels
// or loopback. There is no way to point this client at an arbitrary host, and
// redirects are refused because following one would silently change the source
// an artifact came from.
func NewClient(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDisallowed, err)
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("%w: scheme %q", ErrDisallowed, u.Scheme)
	}
	if !allowedHost(u.Hostname()) {
		return nil, fmt.Errorf("%w: host %q", ErrDisallowed, u.Hostname())
	}
	return &Client{
		base: u,
		http: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirects are refused: a redirect would change the source")
			},
			Transport: &http.Transport{
				Proxy:               nil,
				DisableCompression:  true,
				MaxIdleConnsPerHost: 2,
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
		},
	}, nil
}

// allowedHost accepts only in-network fixture labels and loopback. `.example`
// is reserved by RFC 2606 and, inside this demonstration, resolves only through
// the container network's own aliases.
func allowedHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.HasSuffix(host, ".private.example") || strings.HasSuffix(host, ".public.example")
}

// Metadata asks the registry which versions of name it carries.
func (c *Client) Metadata(ctx context.Context, name string) (Metadata, error) {
	body, err := c.get(ctx, MetadataPath, url.Values{"name": {name}}, maxMetadataBytes)
	if err != nil {
		return Metadata{}, err
	}
	var meta Metadata
	if err := canonicaljson.Unmarshal(body, &meta); err != nil {
		return Metadata{}, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if meta.Format != MetadataFormat || meta.Name != name {
		return Metadata{}, fmt.Errorf("%w: unexpected metadata for %q", ErrProtocol, name)
	}
	return meta, nil
}

// Artifact fetches the exact bytes of one published version.
func (c *Client) Artifact(ctx context.Context, name, version string) ([]byte, error) {
	return c.get(ctx, ArtifactPath, url.Values{"name": {name}, "version": {version}}, maxArtifactBytes)
}

func (c *Client) get(ctx context.Context, path string, query url.Values, limit int64) ([]byte, error) {
	target := *c.base
	target.Path = path
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrProtocol, limit)
	}
	return body, nil
}
