# indexjack

A small, local, container-only demonstration of **dependency confusion** — also called package
substitution, namespace confusion, or dependency hijacking — and of the two controls that actually
prevent it: binding a dependency name to exactly one source, and pinning the exact bytes that source
must return.

Everything here is fictional and self-contained. The registries are local fixture services on a
network with no route out, the packages are inert data files, and the "release gate" is an invented
workflow for an invented organization. No real registry, package, organization, or model is contacted,
named, probed, or described, and nothing is ever published.

> **This stage of the project delivers the secure half only.** There is no vulnerable resolver and no
> public shadow package anywhere in this repository yet. What you can run today is the correct
> behaviour — source binding, lock verification, fail-closed errors — plus the fixtures and evidence
> the later comparison is built on.

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
docker compose down -v                   # tear everything down
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
- **formatting, vetting and the full test suite**, in a pinned toolchain image through the same
  Compose boundary that CI uses.

## Explore one scenario by hand

```sh
docker compose run --rm cli release --scenario secure-safe-candidate
```

| Scenario | What it demonstrates |
|---|---|
| `secure-unsafe-candidate` | The locked private policy rejects the known-unsafe candidate; the release ledger stays byte-for-byte unchanged. |
| `secure-safe-candidate` | The same policy approves the release-ready candidate, exactly once. |
| `secure-missing-artifact` | The bound private source no longer carries the locked artifact. The build fails closed and never asks the public registry. |
| `secure-tampered-artifact` | The bound private source returns different bytes. The mismatch is caught before any package content is read. |
| `upgrade-unreviewed` | The project asks for a newer version while the lock still pins the old one. No flag relaxes a lock. |
| `reviewed-upgrade` | The same upgrade succeeds once the checked-in lock carries the new version, size, and digest. |

Scenario ids are the only input the demonstration accepts. There is no way to pass a package name,
version, registry, URL, artifact, model, or policy from outside, and the two fail-closed scenarios
exit non-zero on purpose.

`docker compose run --rm cli scenarios` lists the ids; `docker compose run --rm cli fixtures` prints
every artifact's identity.

## Safety boundary

- **Local only.** The runtime network is internal: no default gateway, no route to an external host,
  and no published port. The `.example` hostnames are reserved documentation labels that resolve only
  through this network's own aliases.
- **Nothing is executed.** A package artifact contains a manifest and one enumerated key/value table.
  The loader parses those as data and never evaluates, imports, compiles, deserializes into
  behaviour, spawns, or otherwise runs package content. There are no install hooks and no lifecycle
  scripts anywhere in the project. Real dependencies usually *do* contain executable code and can
  therefore have far broader impact; this project deliberately confines its proof to inert data.
- **Nothing is published.** The registries are read-only fixtures with no upload, write, delete,
  search, or listing endpoint, and they accept no name that is not checked in.
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
| `internal/verify` | the gate every assertion above comes from |
| `internal/fixtures` | every checked-in fixture, and the deterministic build of each artifact |

[`docs/RESOLVER.md`](docs/RESOLVER.md) documents the resolver model in full: the ordering rule, the
tie rule, the lock fields, and the stable error classes.

The resolver is a deliberately small, documented model of how dependency resolution can work. It is
**not** a reimplementation of npm, pip, Maven, NuGet, Go modules, Cargo, or any other tool, and this
project makes no claim about how any of them behaves.
