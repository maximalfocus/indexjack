# Contributing

This is a small teaching artefact with a fixed subject, so the useful contributions are narrow: making
the explanation clearer, making the gate stricter, or fixing something that is simply wrong. Corrections
to the documentation are as welcome as corrections to the code.

## Verify a change the way the gate does

Docker is the only requirement, and Docker Compose is the only supported workflow. From a clean
checkout:

```sh
docker compose run --rm --build verify   # build, start the registries, run the whole gate
docker compose down -v --remove-orphans  # tear everything down, including the opt-in services
```

That single command is the review contract. It runs formatting, vetting and the full test suite in a
pinned toolchain image, then asserts containment, fixture reproducibility, the registries' read-only
surface, every enumerated scenario, transcript determinism, the opt-in controls, the taxonomy boundary
and the no-execution path. If it is red, the change is not ready; if it is green, it has met the same
bar every landed change has met.

If your change touches the intentionally vulnerable half in any way, run that half too:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm verify-vulnerable
```

Always finish with `docker compose down -v --remove-orphans`. A plain `down` leaves the opt-in services
running, and the next default gate will then correctly report that the vulnerable registry is up when it
should not be.

A change to a fixture will move a digest, a ledger hash, or an expected transcript. That is fine when it
is deliberate — say so, and say which. It is not fine when it is a surprise.

## Boundaries a change may not cross

These are not style preferences. They are the reason this repository can exist in the open, and a change
that crosses one will be declined however good it otherwise is.

- **No real target.** No real registry, package, organisation, product, or model may be named, contacted,
  probed, described, or characterised. Every name here is invented, and the resolver is a documented
  package-manager-agnostic model — not a claim about how any real tool behaves.
- **No arbitrary input.** Scenario ids are the only input the demonstration accepts. Do not add a way to
  pass a package name, version, source, URL, artifact, model, or policy in from outside.
- **No publication or execution capability.** No upload, write, delete, or search endpoint on a registry
  fixture; no code path that evaluates, imports, compiles, deserializes into behaviour, spawns, or
  shells out to package content; no install hook or lifecycle script; nothing that publishes a package,
  image, or service.
- **No egress.** The runtime network stays internal, with no default gateway, no route to an external
  host, and no published port.
- **The opt-in controls stay two, and stay off.** The vulnerable half exists on purpose and must remain
  behind both a non-default profile and an explicit acknowledgement. Do not weaken either, do not default
  either on, do not add a third way in, and do not make either one alone sufficient.
- **No secret, credential, personal datum, or private link** in source, fixtures, commit messages,
  branch names, issues, or pull requests. Those surfaces are permanent.
- **The gate only gets stricter.** Do not delete or loosen an assertion to make a change pass. If an
  assertion is wrong, fix the assertion and say why in the pull request.

## Documentation is part of the product

`README.md`, `docs/WALKTHROUGH.md`, `docs/RESOLVER.md`, `docs/TRANSCRIPT.md` and `docs/TAXONOMY.md` are
tested, not decorative: the gate asserts that they cover every scenario and every taxonomy identifier,
link the authoritative pages, state the boundaries a reader is most likely to over-generalise, and show
no retired command. Add a scenario and the walkthrough must mention it. Retire a command and it must
disappear from the docs. This is deliberate — documentation drift is a test failure here.

## Pull requests

Keep the diff to one coherent outcome, describe what you ran and what it printed, and name any digest,
ledger hash, or transcript that moved and why. If a change alters what the project claims about itself,
say which claim and against which authoritative source.

## Reporting something unsafe

If you think you have found a way out of the boundary above — rather than the dependency confusion this
project demonstrates on purpose — read [`SECURITY.md`](SECURITY.md) and report it privately instead of
opening a pull request.
