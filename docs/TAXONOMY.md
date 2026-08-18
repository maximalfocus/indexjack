# What this demonstrates, and what it does not

The boundary below is checked into `internal/fixtures/data/taxonomy.json` as data, and the
verification gate asserts the claimed and refused sets are exactly these. It cannot drift without a
test noticing.

## Claimed

| Identifier | Role | Why |
|---|---|---|
| **CWE-427** — Uncontrolled Search Path Element | the precise weakness | A fixed search path contains an element an untrusted publisher can write to. The entry names package-manager dependency confusion directly; its `ALLOWED-WITH-REVIEW` mapping note is preserved here rather than hidden. |
| **CWE-829** — Inclusion of Functionality from Untrusted Control Sphere | design-level companion | The vulnerable build incorporates functionality from an untrusted control sphere. It complements CWE-427 rather than replacing the more precise mapping. |
| **A08:2021** — Software and Data Integrity Failures | OWASP Top 10 (2021) category | OWASP describes applications consuming libraries or modules from untrusted repositories, and tells package managers to consume trusted repositories. |
| **LLM03:2025** — Supply Chain | LLM-system context | The affected consumer is an LLM release pipeline, and a third-party software dependency changes whether a model candidate is approved. |

## Deliberately not claimed

| Identifier | Why not |
|---|---|
| **A06:2021** — Vulnerable and Outdated Components | Nothing here is vulnerable, outdated, deprecated or unmaintained, and no maintenance state affects selection. OWASP's own A06 guidance sends modified or malicious package provenance to A08. |
| **CWE-1104** — Use of Unmaintained Third Party Components | Reliance on an unmaintained component is not the behaviour demonstrated. Claiming it would fill a coverage square while teaching a different root cause. |
| **LLM04** — Data and Model Poisoning | Model candidates, their classifications, and every evaluation input are byte-identical between runs. Only the resolved software artifact changes, and the gate asserts exactly that. |

The A06/CWE-1104 pairing is the one a reader might expect, so it is worth stating plainly: this
demonstration does **not** close that gap. Every component in it is current and supported inside its
own fictional domain. What changes the outcome is *where a name resolved from*, not *how old
something is*.

## No claim about any real package manager

The resolver here is a documented, deliberately small model. Nothing in this project asserts that npm,
pip, Maven, NuGet, Go modules, Cargo, RubyGems, or any other named tool follows its precedence or tie
rule — those tools differ from one another, change over time, and several ship mitigations for exactly
this problem.

What transfers between ecosystems is not a precedence table. It is the invariant:

> **origin and bytes are part of a dependency's identity.**

That is why the version-only half-fix is presented the way it is. Under this model's documented tie
rule the public artifact wins a same-version tie; under a different rule the private one might. The
lesson is not which way the tie goes — it is that a version string alone does not tell you, and a
build that pins only a version has not said which bytes it will accept.
