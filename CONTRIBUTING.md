# Contributing to ElectionGuard C#

Thanks for your interest in contributing. This project is a C# implementation of the
[ElectionGuard](https://www.electionguard.vote/) end-to-end verifiable voting protocol, so
correctness against the spec matters more than in most projects — please read this whole
document before opening a PR.

## Before you start

- For anything beyond a small fix (typos, obvious bugs), open an issue first to discuss the
  approach. This avoids wasted work on changes that don't fit the spec or the project's direction.
- If you're changing cryptographic behavior, identify the spec section(s) involved
  (`v2.1.0`, see `CryptographicParameters.VERSION_DEFAULT`) before writing code. Comments
  throughout the codebase reference spec sections (e.g. `§3.1.1`, `Verification 1`-`9`) —
  when in doubt about *why* something is shaped a certain way, the spec section is the source
  of truth, not the surrounding variable/method names.
- Security-sensitive issues (anything that could compromise ballot secrecy, election integrity,
  or key material) should **not** be filed as public issues — see [SECURITY.md](SECURITY.md).

## Development setup

TBD

## Working with the crypto types

TBD

## Pull requests

- Keep PRs focused — one logical change per PR is much easier to review against the spec than a
  bundle of unrelated fixes.
- Reference the spec section(s) your change implements or fixes, and the verification number(s)
  affected, if any.
- Add or update tests. If your change affects protobuf-serialized types, confirm both the JSON
  and protobuf serializer paths still round-trip.
- Fill out the PR template — it exists mainly to make sure spec references and serialization
  impact aren't forgotten.

## Code style

- Match the existing style in the file you're editing rather than introducing a new convention.
- Prefer clarity that maps back to the spec (naming, structure) over cleverness.
- Follow idiomatic C# as defined by style guides published by Microsoft.

## Questions

Open a [Discussion](../../discussions) for design questions or anything that isn't a concrete bug
or feature request.
