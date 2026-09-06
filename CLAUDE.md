# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a C# implementation of the [ElectionGuard](https://www.electionguard.vote/) end-to-end verifiable voting protocol (spec version `v2.1.0` — see `CryptographicParameters.VERSION_DEFAULT`). Code comments throughout reference spec section numbers (e.g. `§3.1.1`, `Verification 1`-`9`) — when in doubt about *why* a computation is shaped a certain way, the section number in the nearby comment is the source of truth, not the variable names. The spec serves as the source of truth for all operations contained within, so always verify changes against the spec.

## Build & Test

All projects are buildable and testable using the dotnet cli standard commands.

## Architecture

Two projects matter: `src/ElectionGuard.Core` is the library; everything else (`ElectionGuard.InMemory.Console`, `ElectionGuard.Testing.Cli`, the unit test project) is a consumer or fixture generator. There is no persistence layer, network layer, or UI — this is a pure crypto/protocol library operated by driving it from a `Program.cs` (see `src/ElectionGuard.InMemory.Console/Program.cs` for the canonical full pipeline).

The library models the ElectionGuard protocol as a straight-line pipeline, and the folders under `ElectionGuard.Core` mirror its phases:

1. **`Crypto`** — the math primitives everything else is built on: `IntegerModP` / `IntegerModQ` (structs wrapping `BigInteger`, auto-reducing mod the election's `P`/`Q`), `EGHash` (the spec's HMAC-SHA256-based hash, §5.2), and `ElectionGuardRandom`. `EGParameters` is a process-wide static holder for the active `CryptographicParameters` + `GuardianParameters` + `ParameterBaseHash` — it must be initialized once via `EGParameters.Init(...)` before any crypto operation, since `IntegerModP`/`IntegerModQ` read `P`/`Q` from it implicitly.
2. **`KeyGeneration`** — `Guardian` runs distributed key generation: each guardian generates Schnorr-proved key pairs, encrypts key shares to every other guardian (`EncryptShares`), decrypts the shares it receives (`DecryptShares`), and verifies the resulting `GuardianRecord` against the other guardians' public commitments (`Verify`). This is a threshold scheme (`GuardianParameters.N`/`K`, currently hardcoded to 3-of-2) — no single guardian's secret key can decrypt anything alone.
3. **`BallotEncryption`** — `BallotEncryptor.Encrypt` takes a plaintext `Ballot` + the election's `EncryptionRecord` and produces an `EncryptedBallot`: ElGamal-encrypts every selection plus overvote/nullvote/undervote/write-in counters, generates the disjunctive Chaum-Pedersen proofs that each ciphertext encrypts a value in its valid range, and threads a per-ballot confirmation-code chain (`ChainingField`/`ConfirmationCode`) so ballots can be provably ordered/chained on a device.
4. **`Tally`** — `EncryptedTally.AddBallot` homomorphically accumulates encrypted ballots per contest/choice (ElGamal ciphertexts multiply to add plaintexts). `TallyGuardian.Decrypt` produces each guardian's partial decryption share; `TallyAdmin.Decrypt` combines the threshold-many partial decryptions via Lagrange interpolation into the final `DecryptedTally`, brute-forcing the discrete log against `BallotsCast` to recover the plaintext vote count per choice.
5. **`Verify`** — one class per protocol verification, mirroring the spec's numbered verification list (`ParameterVerification` = Verification 1, `GuardianPublicKeyVerification` = 2, `ElectionPublicKeyVerification` = 3, `ExtendedBaseHashVerification` = 4, `SelectionEncryptionIdentifierVerification` = 5, `SelectionEncryptionsWellFormedVerification` = 6, `AdherenceToVoteLimitsVerification` = 7, `ConfirmationCodeVerification` = 8, `BallotAggregationVerification` = 9). Failures throw `VerificationFailedException`, which carries a `SubSection` (e.g. `"1.B"`) matching the spec's lettered sub-checks — tests assert on this field, not just on the exception type.
6. **`Models`** — plain data types plus a family of hash-derived value types (`ParameterBaseHash`, `ElectionBaseHash`, `ExtendedBaseHash`, `ContestHash`, `ConfirmationCode`, etc.) whose constructors *compute* the hash from their inputs (per the spec's hash chain) rather than being simple property bags — treat these constructors as the spec formula, not boilerplate.
7. **`Serialization`** — `JsonEncryptedBallotSerializer` and `ProtobufEncryptedBallotSerializer` both implement `IEncryptedBallotSerializer`. The protobuf path hand-maps every field to a parallel `Protobuf*` DTO tree (protobuf-net doesn't understand the domain's `IntegerModP`/`IntegerModQ` structs directly) — when adding a field to an encrypted-ballot type, it must be added in both the domain type *and* its protobuf DTO counterpart, or protobuf round-tripping will silently drop it.

## Working in this codebase

- Any code touching `IntegerModP`/`IntegerModQ` implicitly depends on `EGParameters` being initialized first (`EGParameters.Init(cryptographicParameters, guardianParameters)`) — unit tests that construct these types call `EGParameters.Init` at the top of the test.
- `GuardianParameters` (N=3, K=2) is currently hardcoded rather than configurable; anything assuming a specific guardian count is tied to that.
- Ballot/contest/tally data round-trips through JSON in `test/data/*` fixtures (see `test/data/famous-names/`) — `ElectionGuard.Testing.Cli` generates equivalent fixtures programmatically via Bogus for larger test scenarios.
