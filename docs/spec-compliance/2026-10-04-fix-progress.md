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
| S1 Hash encodings, indices, canonical order | G1, G6, G7, G35, G26 (1.F compare and constructor reuse), G12, G9 | — | done | 3cec099 |
| S2 Key-generation hardening | G5, G14, G15, G25, G34, G26 (H_B in record and guardian check) | S1 | done | see next commit |
| S3 Ballot verification strictness | G4, G13, G33, G23, G24, G36; plus the push security-review findings on V8 (missing completeness/validation checks: ballot contest set vs ballot style, option set vs manifest, duplicates) | — | todo | |
| S4 Tally soundness | G2, G27, G28, G20, G21, G30, G38, G16 | — | todo | |
| S5 Supplemental fields redesign | G3, G8, G22, G29, G10 | — | todo | |
| S6 Contest data | G11, G32 | after S4 | todo | |
| S7 Ballot nonce and challenged ballots | G17, G18 | after S4 | todo | |
| S8 Chain closing | G19, G37 | — | todo | |
| S9 Pre-encrypted recording tool | G31 | after S5, S7 | todo | |
| S10 Record metadata | G40 (G39 won't fix, per Q9); S2 carry-overs: bind the parsed `Manifest` to `ManifestFile` (S2 review R1), record JSON round trip | — | todo | |

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

S2: no hash, nonce, ciphertext or confirmation code moved. The only digest S2 changes is H_G (eq. 27, now keyed with
H_B), which is local to each guardian and never published; it is pinned by the new `guardian_record_hash` KAT family
(`KnownAnswerTests.GuardianRecordHash_Eq27`), not by a literal. The tests S2 changed are behavior pins, listed in the
S2 log entry.

## Log

### 2026-10-05 — S2 review response (round 2)
Three findings, all fixed. The spec and code findings are the same defect (G14/G15 attribution in step 1).
- **Malformed peer view crashes step 1 (spec minor + code minor): fixed.** The findings were correct. `EncryptShares`
  reads only a peer view's index and communication key, so a view with an empty commitment list reached
  `Guardian.Verify`, where the own-view K = ∏K_{i,0} indexed `[0]` and threw a bare `ArgumentOutOfRangeException`
  naming no one. It ran before Verification 2, so the record-shape checks never got the chance.
  - New `Guardian.RequireOwnViewShape`, run on every held view just before the own-view H_G is formed: exactly k
    `VoteEncryptionCommitments` and k `OtherBallotDataEncryptionCommitments` (eqs. 9, 10, 27). A mismatch throws
    `KeyCeremonyException(1, view.Index, ...)`. A list of k + 1, which did not crash, used to surface as an H_G
    mismatch with no offender; it is now attributed too.
  - API choice (low stakes, decided here): the check is in `Verify`, where the views are consumed, not in
    `EncryptShares`. The views' lists are shared with the caller, so a check at `EncryptShares` time could be
    bypassed by later mutation, and attribution belongs to the step-1 complaint the spec describes. Proofs in the
    held views are not checked here: H_G does not hash them, and the record's proofs are Verification 2's.
  - Test: `Verify_PeerViewWithWrongNumberOfCommitments_FailsStep1_NamingThatGuardian`, a theory over
    {pk_vote, pk_data} × {0, k + 1 = 3} commitments. Guardian 2 is handed the malformed guardian-3 view; the record
    is the real one. It asserts `Step == 1` and `OffendingGuardian == 3`.
- **No test isolates step 2 (tests, minor): fixed.** The finding was correct.
  - Test: `Verify_GuardianWithAnInvalidKeyProof_FailsStep2`, a theory over {pk_vote, pk_data}. Guardian 1's view
    keeps its real commitments and shares, but one response of one proof is incremented. Every guardian is shown
    that view, so H_G agrees, V3 passes (asserted directly), and step 4 passes. It asserts
    `VerificationFailedException` with `SubSection == "2.C"`.
- Mutation check (it ran this time): with the `RequireOwnViewShape` call and the step-2
  `GuardianPublicKeyVerification` call both commented out, exactly the 6 new cases fail and the other 36
  GuardianTests pass. The file was restored from a copy. Note for future mutation runs: `mv` of the backup kept its
  older mtime, so the next incremental build reused the mutant DLL, and the first full test run showed the same 6
  failures. `touch` and rebuild fixed it; every gate line below is from the rebuilt tree.
- CLAUDE.md: the KeyGeneration paragraph now says a held peer view without exactly k commitments of each kind is a
  step-1 `KeyCeremonyException`.
- Gate (no pinned value moved; nothing re-pinned):
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed`. dkg 126 ms. EncryptBallots 0.201 ms/ballot, 134.7 MB. VerifyBallots
    0.362 ms/ballot, 5.8 MB. Tally 6 ms, VerifyTally 3 ms, DecryptTally 20 ms.
  - Console: `Done.`, then the expected ReadKey exception. tally.json
    `{"Contests":{"0":{"Choices":{"0-0":{"VoteCount":3},"0-1":{"VoteCount":0}}}}}`.
  - Tests: Core `Passed: 866, Total: 866` (860 + 6 new cases); Perf `Passed: 199`.
- Perf: the change touches only `Guardian.Verify` (key ceremony, not a ballot path). Smoke is within noise of round 1.

### 2026-10-05 — S2 review response (round 1)
Four findings. Two are fixed with tests. The two manifest-binding findings, which describe the same gap, are tracked
for S10 rather than fixed here.
- **Step 4, eq. (29) untested (tests, major): fixed.** The finding was correct. No test reached the K-hat half of
  §3.2.2 step 4. `Verify_OtherBallotDataPolynomialMismatch_ThrowsException` fails at the H_G comparison (step 1),
  and `..._NamesTheSender` fails at eq. (28) first.
  - New helper `VerifyWithGuardian1CommitmentsReplaced(keyType)`. Every guardian is shown a guardian-1 view
    whose commitments for one key are replaced by commitments to an unrelated polynomial, with a valid proof over
    them; guardian 1 still sends shares of its real polynomials. The helper first asserts that V2 and V3 pass on
    the record, then returns guardian 2's `KeyCeremonyException`.
  - `Verify_BallotDataShareInconsistentWithPublishedCommitments_FailsEq29_NamingTheSender`: replaces "pk_data" and
    asserts `Step == 4`, `OffendingGuardian == 1`, and the eq. (29) message. Only the eq. (29) branch produces
    that message, so deleting the branch fails the test. A direct mutation run was not possible: the session's
    permission classifier refused a build with the check disabled. The temporary edit was reverted at once and
    `git diff` confirms it is gone.
  - `Verify_VoteShareInconsistentWithPublishedCommitments_FailsEq28_NamingTheSender`: the same setup with
    "pk_vote", which isolates eq. (28).
  - Renamed and re-commented, with assertions unchanged:
    - `Verify_OtherBallotDataPolynomialMismatch_ThrowsException` is now
      `Verify_RecordWithReplacedBallotDataCommitments_FailsStep1_BeforeEq29`.
    - `Verify_VoteEncryptionPolynomialMismatch_ThrowsException` is now
      `Verify_RecordFromAnUnrelatedGuardianSet_FailsStep1_BeforeEq28`.
    - The old names claimed the step-4 checks. The stale "plain Exception" comments are gone.
- **V3 failure paths untested (tests, minor): fixed.** New tests:
  - `Verify_GuardianWithNoVoteEncryptionCommitments_Throws_SubSection3A_NotArgumentOutOfRange`.
  - `Verify_GuardianWithNoBallotDataCommitments_Throws_SubSection3B_NotArgumentOutOfRange`.
  - `Verify_GuardianSetWithAnIndexAboveN_Throws_SubSection3A`.
- **Parsed `Manifest` not bound to `ManifestFile`/H_B (spec minor + code minor, same gap): tracked for S10, not
  fixed here.** Both findings are correct, and the gap is real. 1.F checks H_B against `ManifestFile.Bytes`, but
  V6, V7, V8, pre-encryption and the encryptor read the separately supplied `Manifest`.
  - Why not here: the fix needs the library to define its manifest file format. §3.1.3 (p.19) says the canonical
    representation "may be implementation specific", and the callers today produce the bytes three different
    ways:
    - Program.cs reads the file and parses it with its own options.
    - The perf harness uses `PerfJson.LineOptions`.
    - The fixtures use default `System.Text.Json`.
  - Choosing that format belongs with S10's record serialization work: the records' JSON is not a real round trip
    yet either (S2 carry-over).
  - Recommended fix for S10: Core owns one manifest JSON format, and `EncryptionRecord.Manifest` is parsed from
    `ManifestFile.Bytes` rather than supplied separately. The other option is to keep both and have
    `ParameterVerification.Verify(EncryptionRecord)` require that the bytes parse to the supplied `Manifest`,
    reported under 1.F.
  - Done now: the S10 row in Stages lists it. The `EncryptionRecord.ManifestFile` doc comment and CLAUDE.md state
    the gap and say to build both from the same source; Program.cs and the perf harness already do.
- Also fixed: the `KeyCeremonyException` doc comment said "Steps 2 and 3, which are Verifications 1-3". It now
  says Verification 1 runs inside step 1, and steps 2 and 3 are Verifications 2 and 3.
- Gate (no pinned value moved; no test failed at any point, so there was nothing to re-pin):
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed`. dkg 133 ms. EncryptBallots 0.204 ms/ballot, 134.7 MB. VerifyBallots
    0.370 ms/ballot, 5.8 MB. Tally 6 ms, VerifyTally 3 ms, DecryptTally 20 ms.
  - Console: `Done.`, then the expected ReadKey exception. tally.json
    `{"Contests":{"0":{"Choices":{"0-0":{"VoteCount":3},"0-1":{"VoteCount":0}}}}}`.
  - Tests: Core `Passed: 860, Total: 860` (855 + 5 new); Perf `Passed: 199`.
- Perf: no library code path changed, only tests and doc comments. The smoke numbers are within noise of the S2 run.

### 2026-10-05 — S2 (key-generation hardening: G5, G14, G15, G25, G34, G26 remainder)
- Code changes (uncommitted; the orchestrator commits):
  - G5: `GuardianIndex` rejects indices below 1 (`ArgumentOutOfRangeException`); the `Guardian` constructor
    requires 1 <= index <= n (its message said "between 0 and N"). `EncryptShares` requires the peer views to be
    exactly {1..n} \ {self}, each once (`ArgumentException` naming the guardian: self, duplicate, out of range,
    or the missing indices). It also no longer mutates the caller's list: it used to store the list and append
    its own view to it.
  - G15: `DecryptShares` requires every share's `DestinationIndex` to equal this guardian's index, and the
    `SourceIndex` set to be exactly {1..n} \ {self} (`ArgumentException`, naming the guardian). The eq. (16)-(18)
    inputs use `Index` instead of `DestinationIndex`; the bytes are identical once the two are checked equal.
    `Guardian.Verify` step 4 loops i = 1..n over the record (eqs. 28/29, own share included) and throws the new
    `KeyCeremonyException(step, offendingGuardian)`.
  - G14: Verification 2 checks shape before 2.1-2.4 index into the lists. Each commitment list must have exactly
    k entries (2.A), and each proof exactly k+1 responses (2.B). A short list now gives a 2.x failure instead of
    `IndexOutOfRange`. 2.C hashes exactly K_{i,0..k-1}, kappa_i, h_{i,0..k}. The empty 2.B loop is gone; it also
    had an off-by-one bound. The Z_q-range half of 2.B holds by construction (`IntegerModQ` reduces); strict
    parsing stays with G23/S3.
  - G25: Verifications 2 and 3 require exactly G_1..G_n (count n, distinct indices in 1..n), through a shared
    `GuardianSet.RequireComplete`. An empty list gives `VerificationFailedException`, not
    `ArgumentOutOfRange`. `EncryptShares` covers the n-1 side (G5).
  - G34: H_G is keyed with H_B. Both sides go through `Guardian.ComputeGuardianRecordHash(H_B, keys, views)`,
    which sorts by index.
  - G26 remainder:
    - `GuardianRecord` gains `ManifestFile` and `ElectionBaseHash`.
    - `EncryptionRecord` gains `ParameterBaseHash`, `ManifestFile` and `ElectionBaseHash` (§3.7).
    - `ParameterVerification.Verify(EncryptionRecord)` and `Verify(GuardianRecord)` are the one-call full
      Verification 1 (1.A-1.F).
    - `Guardian.Verify` runs it first.
    - Program.cs now runs V1, V2 and V3 on the encryption record before V4. It reads the manifest before the
      ceremony.
    - The perf harness passes the manifest into `CreateGuardianSet` and runs V1-V4 on the record in its untimed
      setup block, after the DKG stopwatch stops.
  - V1 1.E also requires the record's n and k to equal `EGParameters`' n and k. Before, 1.E only recomputed H_P
    from the record's own n and k. Every later count (guardians, commitments, responses) uses `EGParameters`, so a
    record claiming n = 5 would otherwise fail later as a confusing 2.x.
- Gate before re-pinning (code changes complete, no test expectation touched yet; only compile fixes to the two
  `GuardianRecord` and two `EncryptionRecord` initializers in tests, copying the new fields through):
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed` (EncryptBallots 0.201 ms/ballot 134.7 MB; VerifyBallots 0.364 ms/ballot 5.8 MB).
  - Console: `Done.`; tally.json `{"Contests":{"0":{"Choices":{"0-0":{"VoteCount":3},"0-1":{"VoteCount":0}}}}}`.
  - Tests: `Failed: 6, Passed: 805, Total: 811` Core; 199/199 Perf. The failures:
    - `KnownAnswerTests.EveryVectorFamilyIsCheckedOrExplicitlyUnsupported` (new `guardian_record_hash` family)
    - `GuardianTests.Constructor_IndexZero_DoesNotThrow` (the G5 bug pin)
    - `GuardianTests.Verify_MismatchedGuardianRecord_ThrowsOriginalValuesException`, `Verify_VoteEncryptionPolynomialMismatch_ThrowsException`,
      `Verify_OtherBallotDataPolynomialMismatch_ThrowsException` (exact-type `Assert.Throws<Exception>`; now `KeyCeremonyException`)
    - `GuardianTests.EncryptShares_DecryptShares_TamperedShare_ThrowsInvalidOperationException` (used 2 guardians
      under n = 3; now rejected as a missing peer)
- Re-pinned and why (none weakened):
  - `Constructor_IndexZero_DoesNotThrow` was inverted to `Constructor_IndexZero_Throws`. It pinned the G5 bug.
    `Constructor_IndexOneAndN_AreAccepted` was added and keeps the boundary pinned.
  - The three exact-type asserts now name `KeyCeremonyException`, a subclass, and also assert `Step == 1`. That is
    strictly stronger. The message and the `IsNotType<VerificationFailedException>` checks are kept.
  - The tampered-share test now runs the full 3-guardian exchange and passes the tampered share together with the
    other valid share. The tamper and the expected `InvalidOperationException` are unchanged.
  - `guardian_record_hash` was added to `checkedFamilies`, with `GuardianRecordHash_Eq27` (3 vectors). That test
    rebuilds H_B through the library, checks every g^e element and K/K-hat (eqs. 25/26) against the vector, then
    checks H_G in index order and in reversed order.
- New tests:
  - GuardianIndex: below-1 cases.
  - EncryptShares: self, duplicate, missing, index > n, and that the caller's list is untouched.
  - n = 1 completes.
  - DecryptShares: missing, duplicate, wrong destination, self as source, source > n.
  - Step 4 names the sender. The test has guardian 1 send shares of one polynomial and then publish another.
  - 1.F through `Guardian.Verify`: the manifest bytes are tampered, or H_B is computed over another manifest.
  - The guardian's own manifest differs from the record's: step 1 fails.
  - H_G is keyed with what is passed and does not depend on order.
  - V2: k+1 and k-1 commitments give 2.A; k and k+2 responses give 2.B (both proofs); n-1, duplicate, index > n
    and empty sets give 2.A.
  - V3: n-1 guardians with matching keys, a duplicate, or an empty set give 3.A.
  - V1: n/k other than `EGParameters` gives 1.E. The record entry points pass, and give 1.F on a tampered
    manifest, 1.F on H_B over another manifest, and 1.E on a wrong H_P. The `GuardianRecord` entry point is
    covered too.
- Gate after: build 0 warnings, 0 errors. Smoke `correctness passed` (dkg 126 ms; EncryptBallots 0.201 ms/ballot
  134.7 MB; VerifyBallots 0.367 ms/ballot 5.8 MB). Console `Done.`, tally `0-0: 3, 0-1: 0`. Tests 855/855 Core,
  199/199 Perf.
- Perf: no hot path changed. Smoke against S1 (0.204 / 0.369 ms/ballot, 134.7 / 5.8 MB): unchanged within noise.
- Decisions taken (low-stakes API shape; none changes interoperable bytes):
  - H_B reaches the guardians through `GuardianRecord` (`ManifestFile` + `ElectionBaseHash`), not through the
    `Guardian` constructor. Every DKG hash (eqs. 11, 13, 16, 22) keys on H_P, and the spec puts the H_B check in
    record verification. `Guardian.Verify(record, ownManifest = null)`: if the guardian holds its own copy of the
    manifest, its H_B keys the own-view side of H_G, so a record built over another manifest fails step 1.
    Without it, both sides use the record's H_B, which 1.F has just checked.
  - Inside step 1, Verification 1 runs before the H_G comparison, so a bad H_B reports as 1.F.
  - SubSection labels: commitment count 2.A; response count 2.B; V2 guardian-set defects 2.A (the spec letters no
    separate check); V3 guardian-set defects 3.A.
  - Failures of steps 1 and 4 throw `KeyCeremonyException` (`Step`, `OffendingGuardian`). The shape of
    EncryptShares/DecryptShares input throws `ArgumentException`. The share-proof failure in DecryptShares stays
    `InvalidOperationException`.
- Carry-overs:
  - The JSON that Program.cs writes for `EncryptionRecord`/`GuardianRecord` serializes every `HashValue` and
    `IntegerModP` as `{}`. Only `ManifestFile.Bytes` (base64) carries data, so there is no real round trip
    (there was none before S2 either). Serialization still does not throw. For S10/G40 or a serialization stage.
  - `ElectionFixtureBuilder.CreateGuardianSet()` defaults to `CreateMinimalManifest()`'s manifest. Tests that then
    build an encryption record over another manifest get two records that disagree about H_B. Nothing compares
    them, and the perf runner and Program.cs pass the same manifest to both.
  - The Z_q-range half of 2.B, and strict 512/32-byte parsing, are G23 (S3).
- Spec questions: none new.

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
