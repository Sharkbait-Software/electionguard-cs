# electionguard-cs

A C# implementation of the [ElectionGuard](https://www.electionguard.vote/) end-to-end verifiable voting protocol,
spec version 2.1.0, and of the ElectionGuard Record Format (EGRF) v2, a streaming, multi-representation election
record (draft specification: [`docs/spec-compliance/egrf-v2-spec.md`](docs/spec-compliance/egrf-v2-spec.md)).

## Projects

| Project | What it is |
|---|---|
| `src/ElectionGuard.Core` | The library: the cryptography and the protocol (key generation, ballot encryption, tally, verifiable decryption, pre-encryption primitives, Verifications 1-19) and the election record format (`RecordFormat`: writer, reader, verify-everything). |
| `src/ElectionGuard.Verifier` | `egrecord`, the command line over a record: `verify`, `digest`, `convert`, `diff`, `prove`, `show`. |
| `src/ElectionGuard.InMemory.Console` | The canonical end-to-end pipeline: key ceremony, encryption, the record written phase by phase, the guardians' preliminary verification and decryption, and the full verification of the record. |
| `perf/ElectionGuard.Perf.Cli` | `egperf`, scenario runs with per-phase timing, allocation and a correctness check; see [`perf/README.md`](perf/README.md). |
| `perf/ElectionGuard.Benchmarks` | BenchmarkDotNet function-level benchmarks. |
| `test/ElectionGuard.Core.UnitTests`, `test/ElectionGuard.Verifier.UnitTests`, `test/ElectionGuard.Perf.UnitTests` | Unit tests, including the known-answer tests against `test/kat/vectors.json` and the record format's conformance tests. |
| `test/ElectionGuard.Testing.Common` | Shared fixture code: election builders, the ballot generator, the expected-tally accumulator. |
| `test/ElectionGuard.Testing.Cli` | Generates random manifests, plaintext ballots and expected tallies. |
| `test/kat`, `test/egrf` | The known-answer vectors and their Python oracle; the record format's schema table, vectors, golden records and Python reference reader. |
| `proto/electionguard/egrf/v2/egrf.proto` | The record format's normative schema, shared by every implementation. |

Build and test with the standard `dotnet build` and `dotnet test` commands. The spec-compliance work and its
decisions are tracked in [`docs/spec-compliance/`](docs/spec-compliance/).
