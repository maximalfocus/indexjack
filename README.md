# indexjack

A small, local, container-only demonstration of **dependency confusion** — also called package
substitution, namespace confusion, or dependency hijacking — and of the two controls that actually
prevent it: binding a dependency name to exactly one source, and pinning the exact bytes that source
must return.

Everything here is fictional and self-contained. The registries are local fixture services on a
network with no route out, the packages are inert data files, and the "release gate" is an invented
workflow for an invented organization. No real registry, package, organization, or model is contacted,
named, probed, or described, and nothing is ever published.

> **The intentionally vulnerable half is behind two deliberate opt-in controls.** Nothing you run by
> following the commands below reaches it: the vulnerable resolver, the public shadow package, and the
> registry that serves it require both a non-default container profile and an explicit
> acknowledgement, and either one alone fails. See [Opt in to the flaw](#opt-in-to-the-flaw).

**New here? Read [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md).** It is a five-minute tour that teaches
the flaw, the three half-fixes that do not fix it, the six things it is *not*, and the two-part control
that does — without asking you to open a single source file.

## What it shows

A build asks for `@glasswing/release-policy`. That package decides whether a candidate model may be
released. The demonstration makes every step of *how a build decides which artifact that is* visible
in one transcript:

```
request → source policy → queried sources → candidates → selection rule →
selected origin → version → size → digest → integrity verdict →
policy verdict → release mutation
```

Two ideas do the work:

- **Source policy is not source order.** Listing a trusted index first is a display detail. Binding
  `@glasswing/*` exclusively to the private source is a trust decision, and only the second one
  constrains resolution.
- **A version is not an identity.** The same name and version can exist in more than one source with
  different bytes. Only an origin plus an exact size and digest identifies an artifact.

## Requirements

Docker, and nothing else. No Go toolchain, no package manager, and no network access at runtime.

## Run it

```sh
docker compose run --rm --build verify   # build, start the registries, run the whole gate
docker compose down -v --remove-orphans  # tear everything down, including the opt-in services
```

The gate takes seconds and asserts, in one pass:

- **containment** — the containers run non-root, capability-dropped, `no-new-privileges`, with a
  read-only root filesystem, no default route, no reachable external host, and no external name
  resolution;
- **fixtures** — every package artifact rebuilds to byte-identical size and digest, every published
  version matches an artifact built from checked-in sources, and no public registry fixture carries a
  name from the private namespace;
- **registry surface** — each registry refuses writes, deletes, listing, search, unknown names,
  repeated parameters, and unknown parameters, and identifies its role and fixture revision;
- **scenarios** — every enumerated scenario produces its exact expected origin, version, digest,
  integrity verdict, policy verdict, ledger bytes, and audit records;
- **transcripts** — each scenario's transcript is byte-identical between runs, each registry's signed
  receipt matches the exact expected request count, and no transcript carries a credential, address,
  or package content;
- **the opt-in controls** — each control alone refuses, both together admit, and in a default run the
  vulnerable scenarios are not merely refused but absent, with their registry not even running;
- **the taxonomy boundary** — the claimed and deliberately refused classifications are exactly the
  checked-in sets, each refusal with its reason;
- **no execution path** — every artifact is exactly two read-only data entries, and the runtime image
  contains no shell or interpreter to run anything with;
- **formatting, vetting and the full test suite**, in a pinned toolchain image through the same
  Compose boundary that CI uses.

## Explore it by hand

One row per scenario, every column a fact the run observed:

```sh
docker compose run --rm cli compare
```

```
scenario                  source policy                   queried (observed)                        selected origin    version  digest        integrity    verdict  mutation  ledger                     reconciliation
------------------------  ------------------------------  ----------------------------------------  -----------------  -------  ------------  -----------  -------  --------  -------------------------  --------------
secure-unsafe-candidate   @glasswing/*→glasswing-private  glasswing-private(2) community-public(2)  glasswing-private  1.4.2    590ff7b9ff81  verified     REJECT   none      704b56de923e→704b56de923e  PASS
secure-safe-candidate     @glasswing/*→glasswing-private  glasswing-private(2) community-public(2)  glasswing-private  1.4.2    590ff7b9ff81  verified     APPROVE  approved  704b56de923e→60caa8cb929b  PASS
secure-missing-artifact   @glasswing/*→glasswing-private  glasswing-private-missing(1)              —                  —        —             not_reached  —        none      704b56de923e→704b56de923e  PASS
secure-tampered-artifact  @glasswing/*→glasswing-private  glasswing-private-tampered(2)             glasswing-private  1.4.2    —             rejected     —        none      704b56de923e→704b56de923e  PASS
upgrade-unreviewed        @glasswing/*→glasswing-private  none                                      —                  —        —             not_reached  —        none      704b56de923e→704b56de923e  PASS
reviewed-upgrade          @glasswing/*→glasswing-private  glasswing-private(2) community-public(2)  glasswing-private  1.5.0    388952376306  verified     APPROVE  approved  704b56de923e→5018fda7bddf  PASS
```

The **queried** column is not the resolver's account of itself: it is what each registry says it was
asked, signed and collected through an authenticated in-network boundary. A registry that was asked
nothing still has to say so.

The full trace of one scenario, or its machine-readable form:

```sh
docker compose run --rm cli harness --scenario secure-tampered-artifact
docker compose run --rm cli harness --scenario secure-tampered-artifact --format json
docker compose run --rm cli release --scenario secure-safe-candidate   # the direct build path
```

| Scenario | What it demonstrates |
|---|---|
| `secure-unsafe-candidate` | The locked private policy rejects the known-unsafe candidate; the release ledger stays byte-for-byte unchanged. |
| `secure-safe-candidate` | The same policy approves the release-ready candidate, exactly once. |
| `secure-missing-artifact` | The bound private source no longer carries the locked artifact. The build fails closed and never asks the public registry. |
| `secure-tampered-artifact` | The bound private source returns different bytes. The mismatch is caught before any package content is read. |
| `upgrade-unreviewed` | The project asks for a newer version while the lock still pins the old one. No flag relaxes a lock. |
| `reviewed-upgrade` | The same upgrade succeeds once the checked-in lock carries the new version, size, and digest. |
| `vulnerable-public-shadow` | *Opt-in only.* One name resolved across two trust domains: a public package with the same name and a higher version wins, and approves the known-unsafe candidate. |
| `secure-against-public-shadow` | *Opt-in only.* The identical shadow exists and is running, and exclusive binding still selects the private artifact and still rejects the candidate. |
| `half-fix-private-first` | *Opt-in only.* Half-fix: the trusted source is listed and queried first. One pool is still one pool. |
| `half-fix-version-only` | *Opt-in only.* Half-fix: an exact version is pinned, and both sources publish it with different bytes. |

Scenario ids are the only input the demonstration accepts. There is no way to pass a package name,
version, registry, URL, artifact, model, or policy from outside. The harness reports on a run, so it
succeeds whatever the build did; `release` is the build itself, so its three fail-closed scenarios
exit non-zero on purpose.

`docker compose run --rm cli scenarios` lists the ids; `docker compose run --rm cli fixtures` prints
every artifact's identity.

## Opt in to the flaw

The vulnerable half needs two separate deliberate acts — a non-default container profile and an
explicit acknowledgement:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm verify-vulnerable
```

Either one alone fails, and says which acknowledgement is missing. The profile without the
acknowledgement will not even start the registry that serves the shadow.

Tear the opt-in services down with `docker compose down -v --remove-orphans` when you are finished. A
plain `down` leaves them running, and the default gate will then correctly report that the vulnerable
registry is up when it should not be.

That run is the same gate as `verify` plus the vulnerable-path assertions, and afterwards the matrix
shows both halves side by side:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm vulnerable compare
```

```
scenario                      source policy                                             queried (observed)                               selected origin          version  digest        integrity    verdict  mutation  ledger                     reconciliation
----------------------------  --------------------------------------------------------  -----------------------------------------------  -----------------------  -------  ------------  -----------  -------  --------  -------------------------  --------------
vulnerable-public-shadow      @glasswing/*→community-public-shadow + glasswing-private  community-public-shadow(4) glasswing-private(1)  community-public-shadow  9.9.9    43a700bfe56e  unverified   APPROVE  approved  704b56de923e→8c7eedd3cdba  FAIL
secure-against-public-shadow  @glasswing/*→glasswing-private                            glasswing-private(2) community-public-shadow(2)  glasswing-private        1.4.2    590ff7b9ff81  verified     REJECT   none      704b56de923e→704b56de923e  PASS
```

Same build, same candidate, same public registry — running, reachable, and carrying the shadow. The
only differences are that one run pools two sources for a single name instead of binding it to one,
and does not check what bytes it got. That is the entire flaw.

### Three mitigations that are not one

| Half-fix | Why it fails |
|---|---|
| **Private index listed first** | The query order really does change. The trust statement does not, and neither does the selection: one pool is still one pool. |
| **Exact version only** | Both sources publish the pinned version, with different bytes. Pinning a version says nothing about which bytes arrive. |
| **Lifecycle scripts disabled** | There is no hook here to disable. The public artifact is consumed as ordinary data, and that was always enough to flip the verdict. |

### And six things this is *not*

No outdated or unmaintained component is a variable; the private registry is never compromised or
intercepted; the model candidates and their classifications are byte-identical between runs, so the
only differing input is the resolved software artifact; the private package name is already in a
checked-in build log and exclusive binding holds anyway; a legitimate public dependency still
resolves; and a reviewed private upgrade still succeeds. Each is an assertion group in the gate.

Neither control is a security boundary and neither pretends to be one; anything with a shell can set
an environment variable. They are an acknowledgement, so that nobody arrives at the vulnerable half by
running the documented command or copying a snippet.

## Safety boundary

- **Local only.** The runtime network is internal: no default gateway, no route to an external host,
  and no published port. The `.example` hostnames are reserved documentation labels that resolve only
  through this network's own aliases.
- **Nothing is executed, on either path.** A package artifact contains a manifest and one enumerated
  key/value table.
  The loader parses those as data and never evaluates, imports, compiles, deserializes into
  behaviour, spawns, or otherwise runs package content. There are no install hooks and no lifecycle
  scripts anywhere in the project. Real dependencies usually *do* contain executable code and can
  therefore have far broader impact; this project deliberately confines its proof to inert data.
- **Nothing is published, and nothing is hosted.** The registries are read-only fixtures with no
  upload, write, delete, search, or listing endpoint, and they accept no name that is not checked in.
  This project publishes no package, container image, model, or service endpoint, and there is no
  deployed or hosted instance of it anywhere. The only supported form is a local clone run through
  Docker Compose.
- **Not a production component.** This is a teaching artefact, not a library, tool, or reference
  implementation to depend on. The vulnerable half is deliberately vulnerable, and even the secure half
  is a small documented model built to be read — not to resolve real dependencies.
- **Nothing real is involved.** Every organization, package, version, digest, model candidate, policy,
  and release record is invented for this demonstration.
- **The only writable state** is a disposable tmpfs release ledger that starts empty on every run.

## How it is put together

| Path | What lives there |
|---|---|
| `cmd/indexjack` | one binary: registry service, release run, verification gate |
| `internal/pkgarchive` | the canonical data-only package format and its hardened loader |
| `internal/sourcepolicy` | exclusive name-to-source binding, kept apart from display order |
| `internal/lockfile` | artifact identity: name, version, source, size, digest, format |
| `internal/resolver` | the secure resolution model, in a fixed order that cannot be reordered |
| `internal/registry` | the immutable fixture registry service and its client |
| `internal/releasegate` | the release decision and the atomic ledger |
| `internal/harness` | the named-scenario harness, its transcript, and reconciliation |
| `internal/combinedindex` | the opt-in vulnerable resolver, and nothing else |
| `internal/vulnerable` | the two opt-in controls |
| `internal/verify` | the gate every assertion above comes from |
| `internal/fixtures` | every checked-in fixture, and the deterministic build of each artifact |

[`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md) is the guided tour, and the place to start.
[`docs/RESOLVER.md`](docs/RESOLVER.md) documents both resolver models in full: the ordering rule, the
tie rule, the lock fields, the stable error classes, and the three half-fixes.
[`docs/TRANSCRIPT.md`](docs/TRANSCRIPT.md) documents the transcript, the registry receipt boundary,
and how a run reconciles. [`docs/TAXONOMY.md`](docs/TAXONOMY.md) states exactly what this project
claims and what it deliberately does not — including why the pairing a reader might expect,
A06:2021 with CWE-1104, is not claimed here.

The resolver is a deliberately small, documented model of how dependency resolution can work. It is
**not** a reimplementation of npm, pip, Maven, NuGet, Go modules, Cargo, or any other tool, and this
project makes no claim about how any of them behaves.

## Contributing, security, and licence

[`CONTRIBUTING.md`](CONTRIBUTING.md) describes the one supported way to verify a change — the same
`docker compose run --rm --build verify` gate every landed change has passed — and the boundaries a
change may not cross.

[`SECURITY.md`](SECURITY.md) draws the line that matters here: the dependency confusion this project
demonstrates is intentional and is not a vulnerability report, while anything that escapes the boundary
above — package content executing, a container reaching outside its internal network, a registry fixture
accepting a write, the vulnerable path reachable without both opt-in acts — is worth reporting, and
should be reported privately rather than opened as a public issue.

Licensed under the [MIT License](LICENSE).
