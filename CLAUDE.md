# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a C# implementation of the [ElectionGuard](https://www.electionguard.vote/) end-to-end verifiable voting protocol (spec version `v2.1.0` — see `CryptographicParameters.VERSION_DEFAULT`). Code comments throughout reference spec section numbers (e.g. `§3.1.1`, `Verification 1`-`9`) — when in doubt about *why* a computation is shaped a certain way, the section number in the nearby comment is the source of truth, not the variable names. The spec serves as the source of truth for all operations contained within, so always verify changes against the spec.

## Build & Test

All projects are buildable and testable using the dotnet cli standard commands.

## Architecture

The following projects either currently are or will exist in this repository:

1. ElectionGuard.Core - This is the core cryptographic primitives used by everything else. This needs high test coverage, high reliability, and is the core purpose for the project. It will be used by other projects to build the end to end workflows, but all of the cryptography and math lives here.
2. ElectionGuard.Administration - This project will be focused on adminstering an election guard election. Allowing guardians to communicate with each other, generating the encryption record, collecting encrypted ballots, and orchestrating the decryption before finally creating an Election Record (the final output of ElectionGuard).
3. ElectionGuard.Verifier - This will be a verifier project whose purpose is to take a completed Election Record and to run all verifications against it to verify that the math checks out as it's supposed to.
4. `perf/` - Performance testing. `ElectionGuard.Perf.Cli` (`egperf`) runs a scenario end to end -
   generate, encrypt, aggregate, decrypt - with per-phase timing, allocation and GC metrics, checks
   the decrypted tally against a known expected tally, and appends one JSON line per run to
   `perf/results/<machine>.jsonl`. `ElectionGuard.Benchmarks` is a BenchmarkDotNet project for
   function-level numbers. See `perf/README.md`. The harness streams in chunks because encrypted
   ballots are ~50 KB each and cannot be held in memory at scale; scenario JSON under
   `perf/scenarios/` controls which phases run and their time budgets, so a phase that is
   impractical today becomes practical by editing configuration rather than code.

Other related projects that will eventually exist that we need to prepare for:

1. Ballot encryptors - Encrypted ballots in reality may be generated in different languages and runtimes since they may come from different sources. Devices could run C#, C++, Rust, or any other language, or it could even be a browser running something like Javascript. Because of that, the project must be prepared to handle ballots encrypted in any language, and therefore we will implement encryptors in multiple languages. These encryptors will be benchmarked and be testable against a unified testing system.
2. Election Record Publish - The final election record must be distributable online. We will probably take some opinions on how that should be done, and may show an example or provide a platform for this purpose.

For the current stuff so far we have:

Two projects matter: `src/ElectionGuard.Core` is the library; everything else (`ElectionGuard.InMemory.Console`, `ElectionGuard.Testing.Cli`, the unit test project) is a consumer or fixture generator. There is no persistence layer, network layer, or UI — this is a pure crypto/protocol library operated by driving it from a `Program.cs` (see `src/ElectionGuard.InMemory.Console/Program.cs` for the canonical full pipeline).

The library models the ElectionGuard protocol as a straight-line pipeline, and the folders under `ElectionGuard.Core` mirror its phases:

1. **`Crypto`** — the math primitives everything else is built on: `IntegerModP` / `IntegerModQ` (structs wrapping `BigInteger`, auto-reducing mod the election's `P`/`Q`), `EGHash` (the spec's HMAC-SHA256-based hash, §5.2), and `ElectionGuardRandom`. Alongside these sits the Note 3.5 acceleration — `MontgomeryContext` (CIOS Montgomery multiply over `ulong` limbs), `MontgomeryModP` (Z_p in Montgomery form), `PowRadix` (a fixed-base comb table of powers of one base) and `PowRadixRegistry` (the opt-in store of those tables). Table-free exponentiation (`MontgomeryModP`'s table-free path and `SubgroupMembership`'s batch test) runs on `Avx512Montgomery` when `Avx512F.IsSupported` and p is at most 4096 bits: an "almost Montgomery" multiply over 144 29-bit digits held in 18 `Vector512` registers, with values kept redundant in [0, 2p) until converted out, so compare with `IsOne`, never digit-for-digit with `One`. Otherwise it falls back to the scalar `MontgomeryContext`; set `DOTNET_EnableAVX512F=0` to test that path, and `[Avx512Fact]` tests skip there. Its multiply is generated: edit `tools/generate_avx512_montgomery_kernel.py` and rerun it, never `Avx512Montgomery.Kernel.g.cs`. `PowRadix` picks its representation at build time: on AVX-512 its entries are the engine's 29-bit digits packed one per `uint` (576 bytes, widened to `ulong` lanes on read at negligible cost), otherwise scalar limbs (512 bytes); `PowRadix.Build(..., allowAvx512: false)` forces the scalar table in tests. `IntegerModP.PowModP` deliberately does **not** consult any of it and must stay that way; the acceleration is reached only through `MontgomeryModP`. `EGParameters` is a process-wide static holder for the active `CryptographicParameters` + `GuardianParameters` + `ParameterBaseHash`, defaulting to the spec's v2.1.0 parameters with no setup required — `EGParameters.Init(...)`/`EGParameters.OverrideScope(...)` exist only to swap in a different parameter set (e.g. to test that `ParameterVerification` rejects a record claiming different parameters). Arithmetic throughout Core reads parameters from `EGParameters` (`EGParameters.P`/`.Q`/`.G`), never from an `EncryptionRecord`/`GuardianRecord`'s own `CryptographicParameters` — that value is only a claim the record makes about its parameters, meaningful solely as the thing `ParameterVerification` (Verification 1) checks against `EGParameters`.
2. **`KeyGeneration`** — `Guardian` runs distributed key generation: each guardian generates Schnorr-proved key pairs, encrypts key shares to every other guardian (`EncryptShares`), decrypts the shares it receives (`DecryptShares`), and verifies the resulting `GuardianRecord` against the other guardians' public commitments (`Verify`). This is a threshold scheme (`GuardianParameters.N`/`K`, defaulting to 3-of-2 and settable via `new GuardianParameters(n, k)`) — no single guardian's secret key can decrypt anything alone.
3. **`BallotEncryption`** — `BallotEncryptor.Encrypt` takes a plaintext `Ballot` + the election's `EncryptionRecord` and produces an `EncryptedBallot`: ElGamal-encrypts every selection plus overvote/nullvote/undervote/write-in counters, generates the disjunctive Chaum-Pedersen proofs that each ciphertext encrypts a value in its valid range, and threads a per-ballot confirmation-code chain (`ChainingField`/`ConfirmationCode`) so ballots can be provably ordered/chained on a device.
4. **`Tally`** — `EncryptedTally.AddBallot` homomorphically accumulates encrypted ballots per contest/choice (ElGamal ciphertexts multiply to add plaintexts); `AddBallots` does the same for a batch across threads. `TallyGuardian.Decrypt` produces each guardian's partial decryption share; `TallyAdmin.Decrypt` combines the threshold-many partial decryptions via Lagrange interpolation into the final `DecryptedTally`, recovering each plaintext vote count with a baby-step giant-step discrete log over `[0, BallotsCast]`.
5. **`Verify`** — one class per protocol verification, mirroring the spec's numbered verification list (`ParameterVerification` = Verification 1, `GuardianPublicKeyVerification` = 2, `ElectionPublicKeyVerification` = 3, `ExtendedBaseHashVerification` = 4, `SelectionEncryptionIdentifierVerification` = 5, `SelectionEncryptionsWellFormedVerification` = 6, `AdherenceToVoteLimitsVerification` = 7, `ConfirmationCodeVerification` = 8, `BallotAggregationVerification` = 9). Failures throw `VerificationFailedException`, which carries a `SubSection` (e.g. `"1.B"`) matching the spec's lettered sub-checks — tests assert on this field, not just on the exception type.
6. **`Models`** — plain data types plus a family of hash-derived value types (`ParameterBaseHash`, `ElectionBaseHash`, `ExtendedBaseHash`, `ContestHash`, `ConfirmationCode`, etc.) whose constructors *compute* the hash from their inputs (per the spec's hash chain) rather than being simple property bags — treat these constructors as the spec formula, not boilerplate.
7. **`Serialization`** — `JsonEncryptedBallotSerializer` and `ProtobufEncryptedBallotSerializer` both implement `IEncryptedBallotSerializer`. The protobuf path hand-maps every field to a parallel `Protobuf*` DTO tree (protobuf-net doesn't understand the domain's `IntegerModP`/`IntegerModQ` structs directly) — when adding a field to an encrypted-ballot type, it must be added in both the domain type *and* its protobuf DTO counterpart, or protobuf round-tripping will silently drop it.

## Working in this codebase

- `IntegerModP`/`IntegerModQ` read `P`/`Q` from `EGParameters`, which defaults to the spec's v2.1.0 parameters — no initialization is required to use them. Only call `EGParameters.Init(...)`/`EGParameters.OverrideScope(...)` when a test deliberately needs a non-default parameter set.
- When encrypting or verifying, always use `EGParameters.P`/`.Q`/`.G`, never `encryptionRecord.CryptographicParameters.*` or `guardianRecord.CryptographicParameters.*` — those are untrusted claims from the record, only meant to be checked against `EGParameters` inside `ParameterVerification`.
- `GuardianParameters` defaults to N=3, K=2; pass `new GuardianParameters(n, k)` for other thresholds. `ElectionFixtureBuilder.CreateGuardianSet(n, k)` builds a matching guardian set.
- Ballot/contest/tally data round-trips through JSON in `test/data/*` fixtures (see `test/data/famous-names/`) — `ElectionGuard.Testing.Cli` generates equivalent fixtures programmatically via Bogus for larger test scenarios.
- `BallotEncryptor.EncryptContest` MUTATES the plaintext ballot it is given: on an overvote it sets
  every `BallotChoice.SelectionValue` to 0. Anything computing an expected tally must do so *before*
  encrypting, and must apply the same rule (a contest whose selection total exceeds
  `SelectionLimit * OptionSelectionLimit` contributes nothing).
- Use `MontgomeryModP.PowModP` for exponents that are full-width elements of Z_q — nonces,
  challenges, responses, secret keys. It is ~2.5x `IntegerModP.PowModP` on its own (~10x with AVX-512) and ~26x once
  `BallotEncryptor.PrecomputePowerTables` has been called, because the bases are g, K and K-hat.
  Do **not** use it for small public exponents (a ballot weight, a guardian index, a loop counter):
  it walks the full width of Z_q regardless of the exponent's value, deliberately, so that the work
  never varies with a secret. `BigInteger.ModPow` scales with the exponent's magnitude and wins
  there, as does a narrow-window Montgomery exponentiation over just the exponent's own bytes, which
  is how `ModPProduct.MultiplyPower` raises a ballot weight.
- The tables are opt-in and caller-owned. Nothing is built until someone calls
  `BallotEncryptor.PrecomputePowerTables`, and they are keyed by base, so a process that moves
  between elections should `PowRadixRegistry.Clear()` rather than accumulate a set per election.
  Exponents that are not in Z_q (the `x^q mod p` subgroup checks in Verifications 2, 6 and 7) must
  use the `BigInteger` exponent overload: reducing q into `IntegerModQ` makes it zero and turns
  those checks into `x^0 = 1`, which passes for everything.
- Verifications 6.A and 7.A check a whole ballot's ciphertext components at once through
  `SubgroupMembership.IndexOfFirstNonMember`: an exact Jacobi-symbol pass, then a probabilistic
  batch test (random 128-bit exponents, one multi-exponentiation, one `^q`). Its soundness rests on
  p - 1 = 2·q·r' with r' a large prime, which holds for the spec's parameters only, so it falls back
  to exact per-value checks under any other parameter set. A unit test pins that factorization.
- `MontgomeryModP.PowModPVariableTime` raises one base to several exponents over one shared
  squaring chain (Yao/BGMW, w = 4), ~38% fewer Montgomery ops per base at two exponents. It is
  **variable-time and verifier-only**: its work depends on the exponents' digits, so it is safe only
  for public values such as the proof challenges c_j of Verifications 6 and 7. Never call it from
  `BallotEncryption`, `KeyGeneration` or `Tally`, or with a nonce or secret key.
- Verifications 6 and 7 compute their commitments through `RangeProofChallenge`, which multiplies
  g^v by alpha^c (and K^w by beta^c) in one engine representation and writes the bytes straight into
  the hash input. Its helpers (`PowRadix.PowMontgomeryInto`, `MontgomeryModP.PowVariableTimeMontgomery`)
  return values in the active engine's own form -- AVX-512 digits or scalar limbs -- so only combine
  them with values in that same form.
- `EncryptedAggregateChoice.A`/`B` are backed by `ModPProduct`, a running product in the active
  Montgomery engine's form. Each factor is multiplied in without being converted into Montgomery
  form, so the accumulator carries an extra R^-1 per factor (its "drift"), corrected once when the
  value is read; R differs between the AVX-512 and scalar engines, so never combine products from
  different engines. `EncryptedTally.AddBallots` and `BallotAggregationVerification.Verify` take a
  `maxDegreeOfParallelism`, as do `TallyGuardian.Decrypt` and `TallyAdmin.Decrypt`; pass it through
  so that `egperf --parallelism 1` stays a true single-threaded baseline.
- `TallyAdmin.Decrypt` recovers each plaintext count with `BoundedDiscreteLog`, baby-step
  giant-step over `[0, BallotsCast]` with one table shared by every choice: about
  2·sqrt(choices x BallotsCast) multiplies for the whole tally. It and the batched inverse
  (`ModInverseVariableTime`, a binary extended GCD over stack limbs: the division-based form
  allocated 2 MB per call, which `compare`'s allocation gate flags) are **variable-time**, which
  is safe only because the counts and the combined partial decryptions are published; never use
  either on a secret. The bound is
  `BallotsCast`, so a ballot weight above 1 or an `OptionSelectionLimit` above 1 can push a true
  count out of range, and decryption then throws.
- Non-shipping fixture code lives in `test/ElectionGuard.Testing.Common` (`ElectionFixtureBuilder`,
  `BallotGenerator`, `ExpectedTallyAccumulator`), shared by the unit tests, the perf harness and the
  benchmarks.