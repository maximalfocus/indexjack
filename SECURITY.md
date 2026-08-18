# Security policy

## The flaw in this repository is the subject, not a bug

This project exists to demonstrate **dependency confusion**. The vulnerable resolver, the public shadow
package that outranks the private one, and the registry that serves it are all intentional, documented,
and the entire point. The dependency confusion here is a deliberate teaching exhibit, not a defect. They are described in [`README.md`](README.md) and taught step by step in
[`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md).

Please do not report any of the following as a vulnerability:

- the combined-index resolver selecting the public `9.9.9` shadow over the private `1.4.2`;
- a resolver that merges two sources into one candidate pool and does not verify the bytes it got;
- either half-fix behaving exactly as documented and still failing to prevent the substitution;
- the two opt-in controls not being a security boundary. They are not, and the README says so: anything
  that can set an environment variable can set that one. They are an acknowledgement, so that nobody
  arrives at the vulnerable half by running a documented command or copying a snippet.

Nothing here is reachable by accident: the vulnerable half requires both a non-default container profile
and an explicit acknowledgement, and either one alone refuses by name.

## What is worth reporting

Anything that escapes the boundary this project claims to hold. Concretely:

- a way to make any package artifact **execute** — evaluated, imported, compiled, deserialized into
  behaviour, spawned, or passed to a shell — on either the secure or the vulnerable path;
- a way to reach a host, name, or network **outside** the internal Compose network from any container
  the project starts, or to make an external request of any kind;
- a way to write outside the disposable tmpfs release ledger, or to make a write survive
  `docker compose down -v --remove-orphans`;
- a way to make a registry fixture accept an upload, write, delete, or a package name that is not
  checked in;
- a way to reach the vulnerable path without both opt-in acts, or to make a default
  `docker compose run --rm --build verify` run vulnerable code;
- a way to pass an arbitrary package name, version, source, URL, artifact, model, or policy into the
  demonstration from outside. Scenario ids are the only accepted input;
- a credential, token, personal datum, or real-world target that has appeared anywhere in this
  repository. The fixture receipt credential and signing key in
  `internal/fixtures/data/network.json` are checked in on purpose, protect nothing, authorize no write,
  and are meaningless outside the demonstration network — those two are not a finding.

If you are unsure which category something falls into, treat it as reportable and say why.

## How to report privately

Use GitHub's **private vulnerability reporting** on this repository: open the **Security** tab and choose
**Report a vulnerability**. That opens a private advisory visible only to the maintainer.

Please do not open a public issue for a suspected boundary escape before it has been looked at. For
anything that is clearly not a boundary escape — a documentation error, a broken command, a confusing
explanation — a normal public issue is the right place and is welcome.

There is no bounty, and no service-level commitment.

## Supported versions

There is no supported-versions matrix, because there is nothing deployed to support. The only supported
form of this project is a local clone of the default branch, run through Docker Compose as documented.
No package, container image, model, or service endpoint is published anywhere, and no hosted instance
exists — so there is no running deployment to report a vulnerability against.
