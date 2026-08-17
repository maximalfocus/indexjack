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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
	ReceiptFormat  = "indexjack-registry-receipt/1"

	HeaderRole     = "X-Indexjack-Registry-Role"
	HeaderRevision = "X-Indexjack-Fixture-Revision"
	HeaderSource   = "X-Indexjack-Source-Id"
	HeaderRunID    = "X-Indexjack-Run-Id"

	MetadataPath = "/v1/metadata"
	ArtifactPath = "/v1/artifact"
	ReceiptPath  = "/v1/receipts"

	// receiptScheme is the authorization scheme of the in-network fixture
	// boundary. The credential it carries is a checked-in fixture value, not a
	// secret.
	receiptScheme = "Fixture"

	maxMetadataBytes = 64 << 10
	maxArtifactBytes = 256 << 10
	maxReceiptBytes  = 256 << 10
)

// Stable client errors.
var (
	ErrNotFound     = errors.New("registry has no such artifact")
	ErrUnavailable  = errors.New("registry unavailable")
	ErrProtocol     = errors.New("registry response is not valid fixture protocol")
	ErrDisallowed   = errors.New("registry host is outside the demonstration network")
	ErrUnauthorized = errors.New("registry refused the fixture credential")
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
	Method  string `json:"method"`
	Path    string `json:"path"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Status  int    `json:"status"`
}

// Receipt is a registry's own signed statement of what one run asked it.
//
// It is the answer to "who did you talk to?" given by the party that was
// talked to. A run that queried nothing gets a signed receipt saying exactly
// that, which is what makes a zero count evidence rather than an absence of
// evidence.
type Receipt struct {
	Format       string    `json:"format"`
	Source       string    `json:"source"`
	Role         string    `json:"role"`
	Revision     string    `json:"revision"`
	Run          string    `json:"run"`
	RequestCount int       `json:"request_count"`
	Requests     []Request `json:"requests"`
	Signature    string    `json:"signature"`
}

// ReceiptConfig holds the checked-in fixture credentials of the in-network
// receipt boundary. Neither value is a secret: they exist so the boundary is
// authenticated and so a receipt is attributable to the registry that issued
// it.
type ReceiptConfig struct {
	Credential string
	SigningKey string
}

// Handler serves one immutable fixture set.
type Handler struct {
	set      FixtureSet
	receipts ReceiptConfig

	mu       sync.Mutex
	requests []Request
	byRun    map[string][]Request
}

// NewHandler returns a read-only handler for set.
func NewHandler(set FixtureSet, receipts ReceiptConfig) *Handler {
	return &Handler{set: set, receipts: receipts, byRun: map[string][]Request{}}
}

// Requests returns the requests observed so far, oldest first.
func (h *Handler) Requests() []Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Request, len(h.requests))
	copy(out, h.requests)
	return out
}

// RunRequests returns the requests one run made, oldest first.
func (h *Handler) RunRequests(run string) []Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Request, len(h.byRun[run]))
	copy(out, h.byRun[run])
	return out
}

// Reset clears the observed requests. It never changes what is served.
func (h *Handler) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests = nil
	h.byRun = map[string][]Request{}
}

func (h *Handler) record(r Request, run string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests = append(h.requests, r)
	if run != "" {
		h.byRun[run] = append(h.byRun[run], r)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(HeaderRole, h.set.Role)
	w.Header().Set(HeaderRevision, h.set.Revision)
	w.Header().Set(HeaderSource, h.set.ID)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	run := r.Header.Get(HeaderRunID)
	req := Request{Method: r.Method, Path: r.URL.Path}
	// Reading a receipt is not a query about a package, and recording it would
	// make observing a run change what the run observed.
	if r.URL.Path != ReceiptPath {
		defer func() { h.record(req, run) }()
	}

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

	case ReceiptPath:
		h.serveReceipt(w, r, query)

	default:
		req.Status = http.StatusNotFound
		writeStatus(w, req.Status, "not_found")
	}
}

// serveReceipt answers, over an authenticated in-network boundary, what one run
// asked this registry. It is read-only in the strongest sense: it reports
// observations and changes nothing, including its own observations.
func (h *Handler) serveReceipt(w http.ResponseWriter, r *http.Request, query url.Values) {
	if h.receipts.Credential == "" || h.receipts.SigningKey == "" {
		writeStatus(w, http.StatusNotFound, "not_found")
		return
	}
	if !credentialMatches(r.Header.Get("Authorization"), h.receipts.Credential) {
		writeStatus(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	run, ok := single(query, "run")
	if !ok || len(query) != 1 {
		writeStatus(w, http.StatusBadRequest, "bad_request")
		return
	}

	// A run this registry never heard from gets a signed receipt saying so.
	// "Nothing was asked" has to be a statement, not a missing answer.
	requests := h.RunRequests(run)
	if requests == nil {
		requests = []Request{}
	}
	receipt := Receipt{
		Format:       ReceiptFormat,
		Source:       h.set.ID,
		Role:         h.set.Role,
		Revision:     h.set.Revision,
		Run:          run,
		RequestCount: len(requests),
		Requests:     requests,
	}
	signature, err := SignReceipt(receipt, h.receipts.SigningKey)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError, "internal_error")
		return
	}
	receipt.Signature = signature
	body, err := canonicaljson.Marshal(receipt)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// credentialMatches compares the presented credential in constant time. The
// value is a checked-in fixture, but comparing it sloppily would teach the
// wrong habit.
func credentialMatches(header, expected string) bool {
	scheme, presented, found := strings.Cut(header, " ")
	if !found || scheme != receiptScheme {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(presented)), []byte(expected)) == 1
}

// SignReceipt derives a receipt's signature. The key is bound to the issuing
// registry's own id, so a receipt from one registry cannot be presented as a
// receipt from another.
func SignReceipt(receipt Receipt, signingKey string) (string, error) {
	receipt.Signature = ""
	body, err := canonicaljson.Marshal(receipt)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(signingKey+":"+receipt.Source))
	mac.Write(body)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyReceipt reports whether a receipt carries this fixture boundary's
// signature for the registry it claims to come from.
func VerifyReceipt(receipt Receipt, signingKey string) bool {
	presented := receipt.Signature
	expected, err := SignReceipt(receipt, signingKey)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
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
	base  *url.URL
	http  *http.Client
	runID string
}

// Option adjusts a client.
type Option func(*Client)

// WithRunID labels every request with a run id so the registry can report,
// per run, exactly what it was asked. The id identifies one execution and
// nothing else; it names no person and appears in no transcript.
func WithRunID(runID string) Option {
	return func(c *Client) { c.runID = runID }
}

// NewClient returns a client for base.
//
// The host must be one of the demonstration's reserved .example fixture labels
// or loopback. There is no way to point this client at an arbitrary host, and
// redirects are refused because following one would silently change the source
// an artifact came from.
func NewClient(base string, opts ...Option) (*Client, error) {
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
	client := &Client{
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
	}
	for _, opt := range opts {
		opt(client)
	}
	return client, nil
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

// Receipt asks the registry what the given run asked it. The credential is the
// checked-in in-network fixture value; it authorizes reading observations and
// nothing else.
func (c *Client) Receipt(ctx context.Context, run, credential string) (Receipt, error) {
	body, err := c.get(ctx, ReceiptPath, url.Values{"run": {run}}, maxReceiptBytes,
		header{"Authorization", receiptScheme + " " + credential})
	if err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	if err := canonicaljson.Unmarshal(body, &receipt); err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if receipt.Format != ReceiptFormat || receipt.Run != run {
		return Receipt{}, fmt.Errorf("%w: unexpected receipt for run", ErrProtocol)
	}
	if receipt.Requests == nil {
		receipt.Requests = []Request{}
	}
	if receipt.RequestCount != len(receipt.Requests) {
		return Receipt{}, fmt.Errorf("%w: receipt count %d does not match %d listed requests",
			ErrProtocol, receipt.RequestCount, len(receipt.Requests))
	}
	return receipt, nil
}

type header struct{ key, value string }

func (c *Client) get(ctx context.Context, path string, query url.Values, limit int64, headers ...header) ([]byte, error) {
	target := *c.base
	target.Path = path
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if c.runID != "" {
		req.Header.Set(HeaderRunID, c.runID)
	}
	for _, h := range headers {
		req.Header.Set(h.key, h.value)
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
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
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
