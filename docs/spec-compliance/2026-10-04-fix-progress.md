# Spec v2.1.0 compliance fixes — progress tracker

This is the resume point for fixing the findings of the 2026-10-04 spec audit. The full findings (G1–G40, with spec
quotes, code references, fix sketches and verifier notes) are in
[`2026-10-04-spec-audit.md`](2026-10-04-spec-audit.md) next to this file.

- **Branch:** `worktree-spec-audit-2026-10-04` (worktree `.claude/worktrees/spec-audit-2026-10-04`), based on `846897e`.
- **Spec:** ElectionGuard v2.1.0, `EG_Spec_2_1.pdf` from https://github.com/microsoft/electionguard/releases/tag/v2.1
  (`gh release download v2.1 -R microsoft/electionguard`). To get text: `pypdf`. To get page images, which keep
  overbars, subscripts and hats: PyMuPDF (`pip install pymupdf`, then `page.get_pixmap(dpi=110)`).
- **Rule:** every stage is committed and pushed separately. Each commit message lists the G-IDs it closes.

## How to resume

1. Read **Decisions**, then the **Stages** table. The first stage that is not `done` is the next one to do.
2. For an in-progress stage, read its log entry. "Next step" says where it stopped.
3. Run the **gate** before moving pinned test expectations, and again before marking a stage done.

## Gate (run before re-pinning and before marking a stage done)

1. `dotnet build electionguard-cs.sln -c Release` passes with 0 errors.
2. `dotnet test electionguard-cs.sln -c Release --no-build` passes in full.
3. End-to-end check. `dotnet run -c Release --project perf/ElectionGuard.Perf.Cli -- run --scenario smoke` must
   print `correctness passed`. That is 1,000 ballots encrypted, verified, tallied, the tally verified and decrypted,
   and the result compared against an independently accumulated expected tally.
4. End-to-end check. `dotnet run -c Release --project src/ElectionGuard.InMemory.Console` runs every verification
   and prints the decrypted tally. The trailing `ReadKey` exception under a redirected console is expected.
5. Hash/encoding stages only: the known-answer tests (KAT) pass. KAT vectors come from an independent Python reference
   written from the spec text and page images, not from the C# code: `test/kat/` (added in S1).

Note: egperf's correctness check only shows that the pipeline agrees with itself. It cannot catch a hash computed
consistently wrong. That is the KAT's job. `ExpectedTallyAccumulator` copies the encryptor's overvote rule, so S5
re-derives that rule independently.

Baseline on `846897e`: 945 tests pass (746 Core + 199 Perf); smoke prints `correctness passed`; the console pipeline
completes.

## Decisions

Answers from the user are recorded here word for word, with the date.

Settled from the spec without needing to ask:
- §3.3.10 eq (66): the KDF label is `data_enc_keys` and the context is `contest_data`, with underscores. The p.40
  page image is clear; the pypdf text shows spaces.
- G1: `p`/`q`/`g` are encoded with `BigInteger.ToByteArray(isUnsigned: true, isBigEndian: true)` left-padded to
  512/32/512 bytes. Do **not** go through `IntegerModP`/`IntegerModQ`: they reduce mod p/q, which turns `P` and `Q`
  into 0.
- Progress tracking lives in this file on the branch, not in the gitignored `docs/superpowers/`, so it survives
  losing the worktree and travels with the PR.

User answers (2026-10-04):
- **Q1 Supplemental field model (S5):** "Per-contest manifest". Each `Contest` declares its supplemental fields:
  the kind, its own option index after the selectable options, and a counts-toward-limit flag. Each field is
  encrypted, proved, hashed, aggregated and decrypted as an ordinary option, in manifest order. The election-wide
  `Include*` flags are removed.
- **Q2 Supplemental proofs (S5):** "Range + spec relations".
  - Range proofs: 0..1 for indicators, 0..L for the undervote difference count, 0..(number of write-in fields)
    for the write-in count.
  - The linear relations the spec spells out: the L·overvote term goes into the selection-limit proof
    (sum + L·overvote ≤ L); undervote difference count = L − sum; write-ins count toward the limit where the
    manifest says so.
  - The disjunctive indicator-consistency proofs (undervote indicator ⇔ sum < L, null ⇔ sum = 0) are documented
    as not implemented. The spec says these "are not described in detail".
- **Q3 Null indicator on an overvote (S5):** "0". This follows p.39's explicit "should be set to zero".
- **Q4 Eq (120) (S8):** "Body, no LOCK". B_C = 0x00000001 ∥ H(H_E; 0x44, H_ℓ, B_C,0), so len(B1) = 69. The §5.5.5
  table's `0x4C4F434B` is treated as an erratum.
- **Q5 Eq (99) key (S6):** "H_I", following the body and eq (101). The table row's B0 = H_E is treated as an
  erratum.
- **Q6 KDF counter (S6):** "1-based", following eqs (66) and (104) and Verification 12.4. Verification 13.7's
  0 ≤ l < b_Λ is treated as an erratum.
- **Q7 b_Λ (S6):** "Per-contest + length prefix".
  - Add a per-contest `ContestDataBlocks` (b_Λ) to the manifest and remove the election-wide
    `OptionalContestDataMaxLength`.
  - The library takes exactly 32·b_Λ raw bytes.
  - A helper encodes a string as a 4-byte big-endian length followed by the UTF-8 bytes, zero-padded to 32·b_Λ.
    Data that is too long is rejected.
- **Q8 7.A (S3):** "Per-selection as written". 7.A checks each α_i and β_i. Measure the verify cost and report it.
- **Q9 G39 (S10):** "Skip G39". No constant-time work. G39 is closed as won't-fix by user decision.
- **Cadence:** "Keep going". After each stage: commit, update this tracker, push, start the next stage. Stop only
  for a new spec contradiction or question.

## Stages

| Stage | G-IDs | Blocked on | Status | Commit |
|---|---|---|---|---|
| S1 Hash encodings, indices, canonical order | G1, G6, G7, G35, G26 (1.F compare and constructor reuse), G12, G9 | — | done | see log (S1 commit) |
| S2 Key-generation hardening | G5, G14, G15, G25, G34, G26 (H_B in record and guardian check) | S1 | todo | |
| S3 Ballot verification strictness | G4, G13, G33, G23, G24, G36 | — | todo | |
| S4 Tally soundness | G2, G27, G28, G20, G21, G30, G38, G16 | — | todo | |
| S5 Supplemental fields redesign | G3, G8, G22, G29, G10 | — | todo | |
| S6 Contest data | G11, G32 | after S4 | todo | |
| S7 Ballot nonce and challenged ballots | G17, G18 | after S4 | todo | |
| S8 Chain closing | G19, G37 | — | todo | |
| S9 Pre-encrypted recording tool | G31 | after S5, S7 | todo | |
| S10 Record metadata | G40 (G39 won't fix, per Q9) | — | todo | |

## Pinned-value inventory

Filled in by S1: every test literal or fixture that pins a hash, nonce, ciphertext or confirmation code, and whether
it is now loaded from KAT or regenerated after the gate.

The digests themselves are pinned in exactly one place: `test/kat/vectors.json`, checked by
`test/ElectionGuard.Core.UnitTests/Kat/KnownAnswerTests.cs`. No other test holds a hash literal. Everything else
restates a layout, or compares the library against itself, so it moves with the code:

| Location | What it pinned | S1 action |
|---|---|---|
| `CryptographicParameterTests.cs` `CryptographicParameters_Version_IsCorrect` | left-padded ver | Now asserts `76322E312E30` followed by 26 zero bytes (eq. 4). |
| `Models/ElectionBaseHashTests.cs` `Constructor_HandComputed_MatchesDirectEGHashCall` | H_B with no length prefix | Now asserts `0x01 ‖ b(len,4) ‖ manifest`, and that the unprefixed form differs. Added `Compute_MatchesTheConstructor`. |
| `Models/VotingDeviceInformationHashTests.cs` `Constructor_HandComputed_MatchesDirectEGHashCall` | H_DI without 0x2A | Now asserts `0x2A ‖ b(len,4) ‖ S_device`, and that it differs from the 0x43 form. |
| `VerificationTests.cs` V1 positive and 1.E | compares H_P with itself | Unchanged. It is self-referential; the KAT pins H_P. Added 1.F positive and negative cases. |
| `PreEncryption/BallotPreEncryptorTests.cs` `PreEncrypt_OrdersContestsByContestIndex` | indices 5 and 2 | Redesigned. The manifest now has [1, 2] and the ballot style lists them reversed. |
| `PreEncryption/BallotPreEncryptorTests.cs:250`, `Tally/TallyGuardianTests.cs:382` | 0-based `Index = i` | Changed to `i + 1`. |
| `ElectionFixtureBuilder.CreateMinimalManifest`, `Testing.Cli`, `test/data/single-contest/manifest.json`, Perf `BallotGeneratorTests`/`RunCommandTests` | 0-based fixture indices | Made 1-based. |
| All other layout tests (ExtendedBaseHash, H_I, nonce, ContestHash, ConfirmationCode, ChainingField, pre-encryption, range-proof prefix) | layouts with literal or manifest-derived indices | Unchanged. They pass, and their layouts did not change in S1. |
| `perf/results/*.jsonl` smoke `manifestHash` | SHA-256 of the smoke manifest | Changes because `single-contest/manifest.json` changed. Pre-S1 smoke baselines compare as incomparable. These files are untracked. |

## Log

### 2026-10-04 — S1 orchestrator verification and commit
- I ran the gate again myself on the final tree:
  - Build: 0 warnings, 0 errors.
  - Tests: 811/811 Core, 199/199 Perf.
  - Smoke: `correctness passed` (Encrypt 0.204 ms/ballot, Verify 0.369 ms/ballot).
  - Console: `Done.`, tally `0-0: 3, 0-1: 0`.
- Independent confirmation from outside this repo: Microsoft electionguard-rust (commit e0378a95cf6d,
  `src/eg/src/hashes.rs:275-279`) pins H_P(n=5,k=3) = `944286970EAFDB6F…FB05DDCE`. This repo's spec-only Python
  oracle (`test/kat/eg_kat.py`) and the fixed C# code both reproduce it. No other published v2.1 vectors were found.
- Decided without asking, because the spec answers it: §3.1.3 requires unique **labels** (contest label within the
  election, option label within a contest, ballot style label). In this model the label is `Id`, which
  `Manifest.Validate` enforces. `Name` is display text and does not need to be unique.
- Carry-overs:
  - S3: `BallotEncryptor.Validate(ballot)` throws a bare `Exception`; switch to a typed exception.
  - S3: canonical-order fixtures sort the same way by id and by index; add one where they differ.
  - G35 has no regression test that can fail: an HMAC ≥ q has probability about 2^-248, so H and H_q agree on any
    real vector.

### 2026-10-04 — S1 (hash encodings, indices, canonical order)
- Code changes made (uncommitted at the time of writing; the orchestrator commits):
  - G1: `BigIntegerExtensions.ToBigEndianPadded` (the one fixed-width b(a,m) encoder for unreduced values);
    `ParameterBaseHash` encodes p/q/g as 512/32/512 bytes; `Version`'s byte[] right-pads ("v2.1.0" then 26 zeros);
    1.E calls the `ParameterBaseHash` constructor.
  - G6/G26: `ElectionBaseHash.Compute(H_P, manifest)` = H(H_P; 0x01, b(len,4), manifest), used by the constructor
    and 1.F; 1.F compares with `SequenceEqual`. H_B in records is still S2.
  - G7: regular H_DI hashes 0x2A before the length prefix.
  - G35: `Guardian.ComputeShareSecretKey` (H, not H_q) shared by `EncryptShares` and `DecryptShares`.
  - G12: `Manifest.Validate()` (1-based positional contest/option indices; unique contest ids, option ids within a
    contest, ballot style ids; throws `InvalidManifestException`). Called by `EncryptionRecord.Manifest` init and the
    `BallotEncryptor`/`BallotPreEncryptor` constructors. (V6, V7, V8 and V16 called it per ballot at first; the S1
    review removed that, see "S1 review response" below.) It does **not** check that ballot-style
    contest ids resolve (perf tests rely on that failing later, in `BallotGenerator`).
  - G9: the encryptor walks manifest contests and options in index order, emits them in that order, and so hashes
    them in that order. V8 sorts by manifest index before recomputing chi_l and H_C.
  - Fixtures made 1-based: `ElectionFixtureBuilder`, `Testing.Cli` (and its ballot-style shuffle now uses the seeded
    faker), `test/data/single-contest/manifest.json`, Perf `BallotGeneratorTests`/`RunCommandTests`,
    `TallyGuardianTests:382`, `BallotPreEncryptorTests:250`. `BallotPreEncryptorTests.PreEncrypt_OrdersContestsByContestIndex`
    redesigned (manifest [1,2], ballot style lists them reversed) because indices 5 and 2 are no longer valid.
  - External: `C:\temp\eg\data\1\manifest.json` (console input) indices changed 0/0,1 -> 1/1,2; ids untouched; the
    original is kept next to it as `manifest.json.pre-s1-zero-based.bak`.
  - New tests: `Kat/KnownAnswerTests` (loads `test/kat/vectors.json`), `BallotEncryption/CanonicalOrderTests`,
    `Models/ManifestValidationTests`, 1.F cases in `VerificationTests`.
- Gate before re-pinning: build 0 errors; smoke `correctness passed`; console `Done.` with tally.json
  `0-0: 3, 0-1: 0` (the 3 ballots there each select 0-0; the `expected-tally.json` beside them is stale);
  tests 805/808 Core + 199/199 Perf. The only failures were the three pinned old-layout tests:
  `CryptographicParameterTests.CryptographicParameters_Version_IsCorrect`,
  `ElectionBaseHashTests.Constructor_HandComputed_MatchesDirectEGHashCall`,
  `VotingDeviceInformationHashTests.Constructor_HandComputed_MatchesDirectEGHashCall`. All KAT tests passed.
- Re-pinned those three to the spec layout (see the pinned-value inventory above). Gate after:
  - Build: 0 errors, 0 warnings.
  - Smoke: `correctness passed`.
  - Console: `Done.`, and tally.json is `0-0: 3, 0-1: 0`.
  - Tests: 809/809 Core and 199/199 Perf pass.
- Allocation: the first post-change smoke showed VerifyBallots allocating 9.1 MB, against 5.7 MB before S1.
  The extra came from `Validate`'s HashSets in V6, V7 and V8, plus V8's `OrderBy`.
  - Fixes: duplicate ids are now checked pairwise up to 64 items, with no allocation. V8 sorts only when the
    stored order is not already canonical.
  - Final smoke: VerifyBallots 5.8 MB (pre-S1 5.7 MB), EncryptBallots 134.7 MB (pre-S1 134.5 MB). Wall time
    is unchanged.
- Expected indices in `BallotEncryptorTests` (proof well-formedness) and in `BallotPreEncryptorTests`
  (vector layout, eq. 121 nonces) are now derived from list position, not from `Index`.
- `Testing.Cli`'s `ElectionId` now comes from the seeded faker as well. Two runs with the same `--seed` produce
  byte-identical manifests and ballots. Checked by hand; the generated indices start at 1.
- CLAUDE.md now documents the index rule, canonical order and the KAT.
- S1 is complete once the orchestrator commits it.
- KAT families the library cannot express yet: `contest_hash` (ContestHash always appends the four supplemental
  counters; S5/G8) and `chain_close*` (no API; S8/G19). `KnownAnswerTests` lists them explicitly.

### 2026-10-04 — S1 review response
- Finding: V6, V7 and V8 re-validated the whole manifest on every ballot. That is O(manifest) per ballot, and it
  allocates a HashSet once a list exceeds 64 items, which happens with real ballot-style counts. **Applied.**
  - Removed the per-ballot `Manifest.Validate()` from V6, V7, V8, and also V16
    (`PreEncryptedConfirmationCodeVerification`), which the reviewer did not list but which had the same pattern.
  - The verifiers now trust the validation `EncryptionRecord.Manifest` init does, which also covers
    deserialization.
  - `Validate` still runs in the `BallotEncryptor`/`BallotPreEncryptor` constructors. That is the write path, where
    wrong indices would be baked into ballots.
  - The pairwise duplicate check up to 64 items stays: the perf harness and the console build a `BallotEncryptor`
    per ballot. The comment now says so.
  - Behavior change: if a record's manifest lists are mutated in place after the record is built, verification no
    longer notices. `ManifestValidationTests.Consumers_...` was renamed to
    `Encryptors_ManifestReorderedAfterRecordCreation_Throw` and keeps only the two encryptor assertions. It failed
    as expected (1 of 809) before it was edited.
- Finding: two new encryptor branches had no tests. **Applied.** Two tests added to `CanonicalOrderTests`:
  - `Encrypt_BallotStyleWithSubsetOfContests_EmitsThemInManifestOrderAndVerifies`: manifest A, B, C; style [C, A].
    The output order is [A, C], C is hashed with index 3, the confirmation code is over [H_A, H_C], and V6, V7 and
    V8 pass.
  - `Encrypt_BallotListingAContestTwice_IsRejected`.
- No pinned value moved. Gate: build 0 errors, 0 warnings. Smoke: `correctness passed` (VerifyBallots 5.8 MB,
  EncryptBallots 134.7 MB). Console: `Done.`, tally `0-0: 3, 0-1: 0`. Tests: 811/811 Core, 199/199 Perf.

### 2026-10-04 — setup
- Audit done; tracker created. The baseline gate passes on `846897e`.
- Questions put to the user:
  - Q1: Supplemental field model.
  - Q2: Supplemental field proofs.
  - Q3: Value of the null-vote indicator on an overvoted contest.
  - Q4: Eq (120): use the body or the `0x44‖LOCK` table row.
  - Q5: Eq (99): key with H_I or H_E.
  - Q6: KDF counter: 1-based or 0-based.
  - Q7: Where b_Λ lives and how D_Λ is encoded.
  - Q8: Whether 7.A checks each selection or the aggregates.
  - Q9: Scope of the constant-time work in G39.
