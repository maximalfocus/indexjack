# The resolver model

This project resolves dependencies with a small, fixed, documented model. It exists to make one
mechanism legible — how a build decides *which artifact* a name refers to — and it is written so that
every step of that decision is printed rather than inferred.

**It is a model, not a reimplementation.** Nothing here claims to reproduce the behaviour of npm, pip,
Maven, NuGet, Go modules, Cargo, RubyGems, or any other tool. Those tools differ from each other and
change over time, and several of them ship mitigations for exactly the problem demonstrated here.
Treat every rule below as *this project's rule*. What transfers between ecosystems is not a
precedence table; it is the invariant: **origin and bytes are part of a dependency's identity.**

## The three inputs

| Input | What it states | What it must never state |
|---|---|---|
| Manifest | which names the project depends on, and an acceptable range for each | where a name comes from |
| Source policy | which single source each name pattern is bound to | which bytes are acceptable |
| Lock | the exact artifact: name, version, source, size, SHA-256, artifact format | which names the project needs |

Keeping them apart is the point. A manifest that also decided origin would make "add a dependency"
and "trust a publisher" the same action. A source policy that also decided bytes would make a
compromised-looking artifact indistinguishable from an intended one.

### Versions and ranges

A version is exactly `MAJOR.MINOR.PATCH`. Leading zeros, prereleases, build metadata, and any other
spelling are rejected, so one version has one representation. Two range forms exist:

| Form | Meaning |
|---|---|
| `1.4.2` | exactly that version |
| `^1.4.2` | that version or later, within the same major component |
| `>=1.4.2` | that version or later, with no upper bound at all |

The last form is the permissive one, and permissiveness is half of what makes a
name resolvable to something nobody chose: a range with no ceiling will accept
`9.9.9` from anywhere that is allowed to answer.

### Source policy

A mapping binds a pattern — a literal name, or a literal prefix with one trailing `*` — to a source.
There are two modes.

**`exclusive`** binds the pattern to exactly one source. It means both of the things people usually
mean separately:

- the other sources are **not queried** for a matching name; and
- the other sources are **not a fallback** when the bound source has nothing to offer.

The policy also lists its sources in a display order. That order is what a build tool would print as
its index list. It decides nothing. A trace always renders `index display order` and `source policy`
as separate fields, because "the private index is listed first" and "the private index is the only
one allowed to answer" are different claims, and only the second one is a control.

**`combined`** pools two or more sources for one pattern, so a name is resolved across more than one
trust domain at once. Nothing is bound; every pooled source may answer. This is the shape of policy
the demonstration exists to argue against, and the secure resolver refuses it outright — a mapping
that is not exclusive fails closed as `SOURCE_POLICY_NOT_EXCLUSIVE`. Only the opt-in combined-index
resolver acts on it.

Exactly one mapping must match a name. No match and more than one match both fail closed: a build
that cannot say where a name comes from must not guess.

### Lock records

One record per dependency alias, binding:

`alias`, `name`, `version`, `source`, `size`, `sha256`, `artifact_format`

Every field is checked. A record whose source disagrees with the policy, whose name disagrees with
the manifest, or whose version falls outside the manifest's range is a conflict, not a preference —
there is no rule for resolving it, and no flag that relaxes it. A lock changes when a person changes
it and the change is reviewed.

## Resolution order

Order is the security property. Each step happens only after the one before it has succeeded.

1. **Source policy** — evaluate the policy for the dependency name. Nothing has been contacted yet.
2. **Lock** — find the single record for the alias, and require it to agree with the policy's source,
   the manifest's name, the manifest's range, and a supported artifact format. Nothing has been
   fetched yet.
3. **Registry query** — ask the bound source, and only the bound source, which versions it carries.
4. **Selection** — take the locked version from that source's candidate set. If it is not there,
   fail; do not substitute a neighbour, and do not look elsewhere.
5. **Integrity** — fetch the artifact and verify size, then digest, against the lock. No package byte
   has been interpreted yet.
6. **Parse** — only now read the artifact, and only as data, through the hardened loader. Finally,
   require the artifact's own manifest to declare the name and version the lock pinned.

Dependencies are resolved in manifest declaration order and the build stops at the first failure.
That is why a build that fails closed on its private dependency produces no request to any other
source at all.

There is no option, environment variable, retry mode, or alternate entry point that reorders, skips,
or weakens any of these steps.

### Candidate ordering and the tie rule

Candidates are rendered in descending semantic version. Where two candidates compare equal, the tie is
broken by source id in ascending lexicographic order. Ordering is presentation and comparison only —
this resolver selects the locked version, not the first or highest one — but the rule is fixed and
documented so that later comparisons have something exact to point at.

Registry-reported sizes and digests are shown in the candidate list as *what the source said*. They
are never used as proof. The lock is the only authority on which bytes are acceptable.

## Stable failure classes

Every failure below returns exactly one generic result to the build's consumer:

```json
{"format":"indexjack-build-result/1","result":"BUILD_FAILED"}
```

Two different causes must be indistinguishable from outside, or a build becomes an oracle for what a
private registry contains. The class and stage below are *local operator evidence*: they appear in the
transcript and in exactly one structured audit record, and they never reach the consumer.

| Class | Stage | Cause |
|---|---|---|
| `SOURCE_POLICY_INVALID` | `source_policy` | the policy document itself is malformed |
| `SOURCE_POLICY_UNRESOLVED` | `source_policy` | no mapping matches the name |
| `SOURCE_POLICY_AMBIGUOUS` | `source_policy` | more than one mapping matches the name |
| `SOURCE_POLICY_NOT_EXCLUSIVE` | `source_policy` | the mapping pools sources instead of binding one |
| `LOCK_INVALID` | `lock` | the lock document itself is malformed |
| `LOCK_MISSING` | `lock` | no record for the alias |
| `LOCK_DUPLICATE` | `lock` | more than one record for the alias |
| `LOCK_NAME_MISMATCH` | `lock` | the record's name disagrees with the manifest |
| `LOCK_SOURCE_MISMATCH` | `lock` | the record's source disagrees with the policy |
| `LOCK_RANGE_CONFLICT` | `lock` | the locked version is outside the manifest's range |
| `REGISTRY_UNAVAILABLE` | `registry_query`, `artifact_fetch` | the bound source could not be reached |
| `ARTIFACT_UNAVAILABLE` | `registry_query`, `artifact_fetch` | the bound source does not carry the locked artifact |
| `ARTIFACT_SIZE_MISMATCH` | `integrity` | the fetched bytes are not the locked length |
| `ARTIFACT_DIGEST_MISMATCH` | `integrity` | the fetched bytes are the locked length but not the locked bytes |
| `ARTIFACT_MALFORMED` | `artifact_parse` | the artifact is not a valid data-only package |
| `MANIFEST_MISMATCH` | `artifact_parse` | the artifact declares a different name or version |

## The artifact format

One archive containing exactly two regular, read-only files in a fixed order: `manifest.json` and
`policy.json`. Building is deterministic — fixed order, fixed mode, zero timestamps, no ownership
metadata, canonical JSON — so an artifact's size and digest are reproducible from its source.

The loader refuses, before reading any policy data: extra, missing, duplicate, or out-of-order
entries; directories, symbolic links, hard links, and device nodes; path traversal, absolute, and
nested names; execute bits, ownership, timestamps, and extended attributes; oversized entries and
oversized archives; malformed JSON, unknown fields, and duplicate keys; unknown policy kinds, keys,
and values; and unsorted or duplicated policy entries.

`policy.json` is an enumerated key/value table whose accepted keys and values are fixed per kind:

| Kind | Keys | Values |
|---|---|---|
| `release-policy` | `MODEL-CANDIDATE-04`, `MODEL-CANDIDATE-17` | `APPROVE`, `REJECT` |
| `report-format` | `divider`, `field_case`, `title_style` | `dash`/`equals`, `lower`/`upper`, `plain`/`upper` |

Because both kinds are enumerated, a package cannot introduce a new instruction by inventing a key,
and nothing in an artifact is ever evaluated, imported, compiled, deserialized into behaviour, or
executed. A real dependency ordinarily *does* contain executable code; this project deliberately
stops at the trust decision and proves the consequence with inert data instead.

## The other resolver

The demonstration ships a second, intentionally vulnerable resolver. It is reachable only behind two
deliberate opt-in controls (see the README), and it exists to be compared against the one above.

The difference between them is deliberately small, because in real builds the difference is also
small — a configuration choice, not a bug:

| | secure | combined-index |
|---|---|---|
| sources asked | exactly the one bound to the name | every source in the pool |
| selection | the locked version from the bound source | the highest compatible version across the merged answers |
| lock | name, version, source, size and digest, all verified before content is read | none; its configuration has no lock field at all |
| integrity verdict | `verified` | `unverified` — it computes a digest and compares it to nothing |

Its rule, printed in every transcript it produces:

> merge the compatible candidates offered by every pooled source and select the highest semantic
> version; ties are broken by the order the sources are listed in the policy, then by source id

Everything else is shared: the same hardened data-only artifact parser, the same release gate, the
same fixtures, the same transcript schema. The vulnerable resolver selects the wrong artifact; it
does not run it, and no artifact in this project is executable by anything.

Two consequences are worth stating plainly, because they are the lesson rather than the mechanism:

- **Listing the private source first would not help.** Pool order is a display detail; the merged set
  is compared by version alone, so a higher public version wins wherever it was listed.
- **Printing a digest is not checking one.** The vulnerable transcript shows the selected digest in
  full, and that digest was never compared against anything. A digest you display and do not verify
  is a label.
