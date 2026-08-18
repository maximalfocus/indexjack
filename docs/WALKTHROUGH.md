# A five-minute walkthrough

This is a local, self-contained demonstration of **dependency confusion**: how a build that asks more
than one package index about a supposedly private dependency can end up installing a package somebody
else published, and what actually prevents it.

Everything in it is invented. The registries are fixture services on a container network with no route
out, the packages are inert data files, and the organization, models and release records are made up.
No real registry, package, organization or model is contacted, named or described anywhere, and
nothing is ever published.

**Before anything else, three boundaries that shape everything below:**

- The resolver here is a **deterministic, package-manager-agnostic model**. It is not npm, pip, Maven,
  NuGet, Go modules, Cargo or RubyGems, and this project makes **no claim about how any of them
  resolves or breaks ties**.
- A package artifact here is **inert data**: a manifest and one enumerated key/value table. Nothing is
  ever evaluated, imported, compiled, spawned or executed — there is no hook mechanism at all, and the
  runtime image contains no shell to run one with. Real dependencies usually *do* contain executable
  code and can therefore have much broader impact; this project deliberately stops at the trust
  decision and proves the consequence with data.
- The intentionally vulnerable half is behind **two deliberate opt-in controls**. You will not reach it
  by following the first section of this document.

---

## 1. The story

Glasswing Model Works evaluates model candidates before letting them into its release catalogue. The
build that runs that gate depends on a private package, `@glasswing/release-policy`, which says which
candidates may be released.

`MODEL-CANDIDATE-17` is recorded in the gate's own files as **known-unsafe**. The intended private
package agrees: it says `REJECT`.

Somebody else has published a package with the **same name** to the public registry, at a **higher
version**, saying `APPROVE`.

Nothing is hacked. No registry is broken into, no traffic is intercepted, no credential is stolen. The
only question is which package the build resolves — and that question turns out to be enough.

## 2. Run it

```sh
docker compose run --rm --build verify        # the gate: containment, fixtures, registries, scenarios
docker compose run --rm cli compare           # one row per scenario
docker compose down -v --remove-orphans       # tear it all down
```

The comparison prints, for every scenario: the source policy, which registries were actually asked, the
selected origin, version and digest, whether integrity was verified, what the package said, whether the
release ledger changed, and whether the run reconciles.

To follow one run in full:

```sh
docker compose run --rm cli harness --scenario secure-unsafe-candidate
```

These are all the scenarios. Only the first six are reachable until you opt in:

| Scenario | What it is |
|---|---|
| `secure-unsafe-candidate` | the intended private policy rejects the known-unsafe candidate; the ledger does not move |
| `secure-safe-candidate` | the same policy approves the release-ready candidate, exactly once |
| `secure-missing-artifact` | the bound private source no longer has the locked artifact — fails closed, asks nobody else |
| `secure-tampered-artifact` | the bound private source returns different bytes — caught before any content is read |
| `upgrade-unreviewed` | the project asks for a newer version while the lock still pins the old one — no flag relaxes a lock |
| `reviewed-upgrade` | the same upgrade, accepted, once the lock is deliberately updated |
| `vulnerable-public-shadow` | *opt-in:* one name pooled across two trust domains; the public package wins |
| `secure-against-public-shadow` | *opt-in:* the identical shadow, running and reachable, and binding still holds |
| `half-fix-private-first` | *opt-in:* the trusted source queried first, and it changes nothing |
| `half-fix-version-only` | *opt-in:* an exact version pinned, published by both sources with different bytes |

## 3. The two preconditions

Dependency confusion needs exactly two things to be true at once:

1. **A dependency name is resolved across more than one trust domain.** The build asks both a private
   source and a public one about the same name, and treats their answers as one pool of candidates.
2. **At least one of those sources is writable by someone you do not trust.** A public registry is, by
   design — that is what makes it public.

Neither alone is enough, and the demonstration shows that. Pooling with a range that has a ceiling
never sees the higher public version. A permissive range against a single bound source resolves
perfectly safely. Both together are the flaw.

## 4. Reading the trace

Every run prints the same fields in the same order. This is the whole causal chain:

| Field | The question it answers |
|---|---|
| `request` | what name and range did the project ask for? |
| `source policy` | which source, or sources, is that name allowed to come from? |
| `trust` | what does that policy actually *constrain*? |
| `index display order` | in what order are the sources listed? |
| `query order (actual)` | in what order were they really asked? |
| `candidates` | what did each source offer, with the size and digest it claims? |
| `selection rule` | by what rule was one of those chosen? |
| `selected origin` / `version` / `size` / `digest` | which artifact won, from where, and which exact bytes? |
| `integrity verdict` | were those bytes checked against anything before being read? |
| registry receipts | which registry was asked what — *according to that registry*, signed |
| `policy verdict` | what did the selected artifact say about the candidate? |
| `gate classification` | what did the release gate already know about that candidate? |
| `release mutation` / `ledger before`/`after` | what actually changed on disk? |
| `reconciliation` | do those three agree? |

Two of those deserve emphasis.

**`trust` is not `query order`.** They are printed as separate fields precisely because people conflate
them. "We list our private index first" describes display. "This name may only come from our private
index" is a control. Only the second one constrains anything.

**Receipts come from the registries.** A resolver reporting its own behaviour is the weakest possible
evidence for "the public registry was never asked". So each registry keeps a per-run log and hands it
over signed, and a registry that was asked nothing still has to say so. A zero is a statement, not a
silence.

## 5. The vulnerable run

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm vulnerable compare
```

The comparison now has four more rows. Two of them are the point:

```
scenario                      source policy                                             queried (observed)                               selected origin          version  digest        integrity    verdict  mutation  ledger                     reconciliation
----------------------------  --------------------------------------------------------  -----------------------------------------------  -----------------------  -------  ------------  -----------  -------  --------  -------------------------  --------------
vulnerable-public-shadow      @glasswing/*→community-public-shadow + glasswing-private  community-public-shadow(4) glasswing-private(1)  community-public-shadow  9.9.9    43a700bfe56e  unverified   APPROVE  approved  704b56de923e→8c7eedd3cdba  FAIL
secure-against-public-shadow  @glasswing/*→glasswing-private                            glasswing-private(2) community-public-shadow(2)  glasswing-private        1.4.2    590ff7b9ff81  verified     REJECT   none      704b56de923e→704b56de923e  PASS
```

Same build. Same candidate. The same public registry — running, reachable, and carrying the same
package in both rows. What differs:

- the first run **pools** two sources for one name instead of **binding** it to one; and
- the first run never checks **which bytes** it got.

The consequences follow in one line each: the public `9.9.9` wins on version, the release gate asks
*that* artifact about `MODEL-CANDIDATE-17`, it answers `APPROVE`, one release row appears for a
candidate the gate's own records call known-unsafe, and reconciliation fails naming the public origin
and the digest that decided it.

## 6. Three half-fixes

Each of these is a real mitigation someone reaches for. Each is applied honestly here, and each still
ends in the same place.

| Half-fix | Scenario | Why it fails |
|---|---|---|
| **List the private index first** | `half-fix-private-first` | The query order really does change — you can see it in the trace. The trust field still says nothing is bound, the pool is still compared by version alone, and the same public package still wins. |
| **Pin an exact version** | `half-fix-version-only` | Both sources publish that exact version, with different digests, printed side by side. The pin is honoured and decides nothing about which bytes arrive. |
| **Disable lifecycle scripts** | any vulnerable run | There is no hook here to disable, and the verdict flips anyway. The public artifact is consumed as ordinary data on the ordinary path — which was always all it needed. |

Both are in the comparison, and both rows say the same thing in the end:

```
scenario                      source policy                                             queried (observed)                               selected origin          version  digest        integrity    verdict  mutation  ledger                     reconciliation
----------------------------  --------------------------------------------------------  -----------------------------------------------  -----------------------  -------  ------------  -----------  -------  --------  -------------------------  --------------
half-fix-private-first        @glasswing/*→glasswing-private + community-public-shadow  glasswing-private(1) community-public-shadow(4)  community-public-shadow  9.9.9    43a700bfe56e  unverified   APPROVE  approved  704b56de923e→8c7eedd3cdba  FAIL
half-fix-version-only         @glasswing/*→community-public-shadow + glasswing-private  community-public-shadow(4) glasswing-private(1)  community-public-shadow  1.4.2    07b99f62b95d  unverified   APPROVE  approved  704b56de923e→f030d3010fe6  FAIL
```

Look at the first row's query order: the private source really was asked first, and answered. It made
no difference, because the pool is compared by version and nothing in it was ever bound.

The version-only case carries a caveat worth stating twice: the tie goes to the public artifact under
*this project's* documented tie rule. Under a different rule it might go the other way. That is exactly
the lesson rather than a limitation — **a version string alone does not tell you which bytes you will
get**, and a build that pins only a version has not said which bytes it will accept.

## 7. Six things this is *not*

Each is an automated assertion group, not a claim in prose:

1. **Not an outdated-component problem.** Nothing here is vulnerable, deprecated or unmaintained, and
   no maintenance state affects selection. No fixture even has a field for one.
2. **Not a compromised registry, and not interception.** The private source always serves exactly the
   bytes this repository builds. Nobody breaks in, and no TLS, signature or credential is a variable.
3. **Not model or data poisoning.** The candidate documents and the gate's classification of them are
   byte-identical across the two runs that disagree. The only input that differs is the resolved
   software artifact.
4. **Not a secret-name problem.** A checked-in build log already contains the private package name.
   Names live in manifests, lock files, logs, errors and caches; secrecy was never the control, and
   exclusive binding holds with the name fully public.
5. **Not "public dependencies are bad".** An ordinary public dependency resolves from its explicitly
   trusted public source in every secure scenario, under both candidates — `secure-unsafe-candidate`
   and `secure-safe-candidate` alike.
6. **Not "freeze everything forever".** `upgrade-unreviewed` shows the old lock refusing a newer
   version, and `reviewed-upgrade` shows that same upgrade succeeding once the lock is deliberately
   updated. That is what review means.

## 8. The fix, in two parts

Neither part is sufficient alone. Together they are the whole thing:

1. **Exclusive source binding.** The `@glasswing/*` namespace maps to the private source and nothing
   else. Other sources are not queried for those names, and are not a fallback when the bound source
   has nothing to offer. Absence fails the build; it does not widen the search.
2. **Artifact identity verified before any content is read.** The lock binds name, exact version,
   source identity, byte size, SHA-256 and artifact format. All of it is checked before a single byte
   of package content is interpreted.

You can watch both parts working. `secure-against-public-shadow` runs against the shadow-bearing
registry and never asks it about the private namespace. `secure-missing-artifact` and
`secure-tampered-artifact` fail closed — the first because the bound source no longer has the
artifact, the second because the bytes do not match — and both return the *same* generic build failure,
because a build that distinguished them would be an oracle for what a private registry contains.

## 9. Why an LLM release gate

The consumer here is an LLM release pipeline, and that is a **context**, not a claim about models.

A third-party software dependency decides whether a model candidate is approved. That is an ordinary
software supply-chain failure whose blast radius happens to be a model release. Nothing about the
models themselves is poisoned, backdoored or even touched: the candidate files, their classifications
and every evaluation input are byte-identical between the runs that disagree, and the demonstration
asserts it.

## 10. What this is classified as, and what it is not

| Claimed | Why |
|---|---|
| [CWE-427 — Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html) | The precise weakness. Its own entry says: *"Dependency confusion: As of February 2021, this term is used to describe CWE-427 in the context of managing installation of software package dependencies."* Its `ALLOWED-WITH-REVIEW` mapping note is preserved here rather than hidden. |
| [CWE-829 — Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) | The design-level companion: the vulnerable build incorporates functionality from an untrusted control sphere. It complements CWE-427 rather than replacing it. |
| [A08:2021 — Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) | OWASP's description names it: *"an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs)"*, and its prevention guidance says to ensure dependencies *"are consuming trusted repositories"*. |
| [LLM03:2025 — Supply Chain](https://genai.owasp.org/llmrisk/llm032025-supply-chain/) | The affected consumer is an LLM release pipeline whose third-party software dependency changes whether a candidate is approved. |

| Deliberately **not** claimed | Why not |
|---|---|
| [A06:2021 — Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) | Nothing here is vulnerable, unsupported or out of date. OWASP's own A06 prevention guidance sends this problem elsewhere: *"Only obtain components from official sources over secure links. Prefer signed packages to reduce the chance of including a modified, malicious component (see A08:2021-Software and Data Integrity Failures)."* |
| [CWE-1104 — Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html) | Reliance on an unmaintained component is simply not what happens here. |
| [LLM04:2025 — Data and Model Poisoning](https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/) | The models and their data never change. Only the software artifact does. |

The A06/CWE-1104 pairing is the one a reader might expect, so it is worth being blunt: this project
**does not** cover that ground, and saying it did would fill a category while teaching a different root
cause.

And once more, because it is the claim most easily overstated: **no assertion here describes the
behaviour of any real package manager.** What transfers between ecosystems is not a precedence table.
It is the invariant:

> **origin and bytes are part of a dependency's identity.**

## 11. Where to go next

- [`RESOLVER.md`](RESOLVER.md) — both resolver models in full: inputs, ordering, the tie rule, lock
  fields, and the stable error classes.
- [`TRANSCRIPT.md`](TRANSCRIPT.md) — the transcript's shape, the registry receipt boundary, and how a
  run reconciles.
- [`TAXONOMY.md`](TAXONOMY.md) — the classification boundary on its own, as checked-in data.
