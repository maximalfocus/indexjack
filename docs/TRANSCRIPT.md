# The transcript and its evidence

Every run of the harness produces one transcript: a fixed-shape account of how a build decided which
artifact a dependency name referred to, and what followed from that decision.

```
request → source policy → queried sources → candidates → selection rule → selected origin →
version → size → digest → integrity verdict → policy verdict → release mutation →
ledger before/after → reconciliation
```

Two properties are what make it evidence rather than narration.

## It is byte-identical between runs

Running the same scenario twice produces the same transcript, byte for byte, in both the
human-readable and the machine-readable form. Nothing in it is a timestamp, a duration, a random id,
or a count of anything that varies with the machine. That is what lets a test assert an exact value
instead of searching for a substring, and it is why a change in behaviour shows up as a diff.

Two values are deliberately *not* recorded, precisely to keep that true:

- the **run id**, a fresh identifier per execution that lets a registry separate this run's requests
  from any other's; and
- the **receipt signature**, which is derived from that run id.

Both are checked while the transcript is being assembled — the signature is verified before a receipt
is accepted — and what the transcript records is the conclusion: `signature_verified`.

## Its query set comes from the registries, not from the resolver

A resolver reporting its own behaviour is the weakest possible evidence for a claim like "the public
registry was never asked". So each registry keeps a per-run log of the requests it received and will
hand it over, signed, through an authenticated in-network boundary:

```
GET /v1/receipts?run=<run id>
Authorization: Fixture <checked-in fixture credential>
```

The response is a signed statement from that registry:

```json
{
  "format": "indexjack-registry-receipt/1",
  "source": "community-public",
  "role": "public",
  "revision": "community-public/1",
  "run": "…",
  "request_count": 0,
  "requests": [],
  "signature": "hmac-sha256:…"
}
```

Details that matter:

- **A run that asked nothing still gets a receipt.** A zero count is a statement the registry makes,
  not an answer that failed to arrive. That is the whole basis of the "zero public-registry requests"
  claim.
- **The harness asks every registry**, including the ones a scenario had no reason to contact, so the
  transcript covers the full set rather than the expected subset.
- **A receipt is bound to its issuer.** The signature is derived from the fixture signing key *and*
  the registry's own id, so a private registry's receipt does not verify as a public registry's, and
  altering a receipt's contents invalidates it.
- **Reading a receipt is not itself recorded.** Observing a run must not change what the run observed.
- **The boundary is authenticated but nothing is secret.** The credential and signing key are
  checked-in fixture values. They exist so the request log is reachable only through an authenticated
  boundary and so receipts are attributable — not to protect anything. They mean nothing outside the
  demonstration network, they authorize no write, and no transcript ever prints them.

## What the integrity verdict distinguishes

| Verdict | Meaning |
|---|---|
| `verified` | the fetched bytes matched the locked size and digest, and only then were read |
| `rejected` | a candidate was selected, its bytes were fetched and compared, and they lost |
| `not_reached` | the run never got as far as comparing bytes |

A failed run still records its request, its source policy, the sources it queried, and the candidates
it saw. A trace that went blank at the moment something went wrong would be no use at all.

## Reconciliation

The last line of every run compares three things that are each allowed to disagree:

1. what the **resolved dependency** said about a candidate;
2. what the **release gate's own record** already said about that candidate; and
3. what actually **changed in the release ledger**.

Agreement is the only pass. In particular, a run where the selected artifact approves a candidate the
gate itself classifies as unsafe reconciles as
`FAIL — untrusted origin influenced release approval`, and names the origin and digest that decided
it. No secure scenario reaches that branch today; the rule is written and tested now so that when a
run does reach it, the transcript says so on its own.

## Reading it

```sh
docker compose run --rm cli harness --matrix                                      # one row per scenario
docker compose run --rm cli harness --scenario secure-tampered-artifact           # the full trace
docker compose run --rm cli harness --scenario secure-tampered-artifact --format json
```

The machine-readable transcript is also written to `transcript.json` in the run's disposable state
directory. Scenario ids are the only input accepted: there is no way to pass a package name, version,
registry, URL, artifact, model, or policy from outside.
