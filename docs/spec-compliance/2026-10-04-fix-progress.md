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
consistently wrong. That is the KAT's job. Before S5, `ExpectedTallyAccumulator` copied the encryptor's overvote rule;
S5 re-derived it from the spec text (S5b again, from decisions Q11-Q16), and it now also produces the supplemental-field totals that `TallyComparer`
checks.

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
  - *Superseded by Q14 (S5b removed the counts-toward-limit flag). The S5 implementer note follows for the record.*
  - *Implementer note (S5, not part of the user's answer; awaiting the user's acceptance, see S5 review round 2):*
    `Manifest.Validate` narrows the per-field flag. The overvote indicator must count (it enters the limit proof
    L times). The null-vote indicator, the undervote indicator and the undervote difference count must not.
    Only the write-in count's flag is a free choice. Reasons: the two undervote fields are nonzero on an
    overvote, so an honest overvoted ballot would have no limit proof; p.39's optional L·null relation is not
    implemented (Q2).
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
- **Q10 Order of U in eqs (88)/(90) (S4), answered 2026-10-05:** "Ascending index". The participating-guardian set U is
  encoded as b(#U,4) followed by b(j,4) for each j, in ascending guardian index. S4 already does this, and the KAT oracle
  assumes it.
- **S5 follow-up decisions, answered 2026-10-05.** These supersede the parts of the S5 build that conflict with them.
  Notation: s = sum of selections, w = write-in count, L = selection limit.
  - **Q11 Undervote indicator on an overvote:** the user wrote: "The sum of all votes + undervotes + overvotes should
    be less than the selection limit. Therefore, if a contest is an overvote, it is not an undervote. So overvote: 1
    undervote: 0 would sum to a selection limit of 1 in a normal vote by 1 contest." So on an overvote the undervote
    indicator is **0**. The S5 build had 1.
  - **Q12 Write-in count on an overvote:** "Zero it".
  - **Q13 Write-ins that do not count toward the limit:** the user wrote: "What is a write in that does not count
    toward the limit? Any write in should count towards the limit as far as I know." So write-ins **always** count
    toward the limit, exactly like selections. There is no flag. A ballot that uses a write-in is not a null vote, and
    undervote is judged on s + w.
  - **Q14 Counts-toward-limit flags:** the user wrote: "this shouldn't be about whether or not a field counts towards
    the limit as much as whether or not a field is tracked. If a field is tracked, it needs to be counted towards the
    sum of fields being less than or equal to the selection limit. If it is not tracked, then it doesn't matter at all
    and presumably isn't included." So the per-field `CountsTowardLimit` flag is **removed**. Every tracked field is
    checked against L.
  - **Q15 Null-vote and undervote tracked together:** "Null in its own check". Null-vote is a special undervote, so
    putting both in one sum would count the same missing vote twice. The relations are:
    - Limit proof: s + w + L·overvote + undervote-indicator ≤ L.
    - Undervote difference count u, proved exactly: s + w + L·overvote + u = L, so u = 0 on an overvote.
    - Null-vote indicator, its own relation per p.39: s + w + L·null ≤ L.
  - **Q16 Overvote weight:** the user asked to use footnote 42, "exponentiating the ciphertext encrypting the overvote
    field with the contest selection limit". That is the L·overvote term already built in S5 (α_ov^L, β_ov^L).
    Unchanged.
  - Resulting values on an overvote: options 0, write-in count 0, overvote 1, undervote indicator 0, undervote
    difference 0, null 0. On a null vote (s + w = 0, no overvote): undervote indicator 1, difference L, null 1.
- **S5b follow-up decisions, answered 2026-10-05:**
  - **Q17 (S5b question C), null-vote relation and overvote:** "Add overvote term". When the overvote indicator is
    tracked, the null relation becomes s + w + L·overvote + L·null ≤ L. Without the overvote term, overvote = 1 with
    null = 1 would verify. Fixed in S5c.
  - **Q18 (S5b question A), u tracked without an overvote indicator:** the user wrote: "the question says that the
    overvote indicator is not tracked. There is therefore no indication of whether or not something is an overvote, so
    'on an overvote...' doesn't make sense to me." The orchestrator's resolution: without a tracked overvote field
    there is no published notion of an overvote. The neutralized contest (§3.3.5: options zeroed) is indistinguishable
    from a blank contest, so u = L. The S5b behavior is kept, and Validate does not require the overvote indicator
    when u is tracked.
  - **Q19 (S5b question B), write-in fields without a write-in count:** "Reject manifest". Kept as built.
- **S6 design and API choices** (2026-10-05; the first by the orchestrator, the rest low-stakes implementer
  choices; none changes bytes the spec or Q5-Q7 fix):
  - **Every ballot carries the field (orchestrator).** A contest that declares `ContestDataBlocks` > 0 carries
    contest data on every ballot; no text encrypts 32·b_Λ zero bytes (the Q7 encoding of ""). A contest that
    declares 0 carries none. `BallotStructure` enforces both (`"N.structure"`), so the ballot's shape never
    shows whether write-in text was entered, and Verification 8 hashes the field into chi whenever it is
    declared.
  - **The 0x27 proof has no numbered verification.** The spec checks it only where guardians decrypt (§3.6.6
    p.49-50); no Verification 6.x/8.x/12.x covers it. The library checks it in
    `TallyGuardian.CommitContestData` and again in `TallyAdmin.CombineContestData` before publishing, and adds no
    sub-check to Verifications 6-8 (it would cost two full-width exponentiations per ballot on the verify path).
  - **C_0 must be in Z_p^r before anyone decrypts it (S6 review round 1; library hardening, no bytes change).**
    The eq. (69) proof accepts C_0 = 0 (with a = 0) and C_0 = -g^ξ (whenever c is even), and nothing else checks
    C_0. So the guardians and the administrator (`ContestDataStatement.RequireDecryptable`) require
    `SubgroupMembership.IsMember(C_0)` before the proof, refusing with a `TallyDecryptionException` that names no
    guardian. Verification 12 does not add it: the spec states no such check.
  - `BallotContest.ContestData` is `byte[]?` (exactly 32·b_Λ raw bytes, Q7); `ContestDataEncoding` is the Q7
    string helper. A new `EncryptedContestData` type carries C_0 as `IntegerModP` (so both decoders read it
    strictly; its JSON form is unchanged, base64 of 512 bytes); `EncryptedData` stays for the ballot nonce.
  - Guardians, the administrator and Verification 12 recompute H_I = H(H_E; 0x20, id_B) and refuse a ballot whose
    stored H_I differs.
  - One ballot contest per contest data decryption (three rounds); messages name the ballot and contest, and a
    message for another one is refused naming its sender. A guardian holds one session of one kind (tally or
    contest data) at a time.
  - Fixtures: `ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true)` and every committed manifest
    contest that offers write-in fields declare b_Λ = 2. The console decrypts every field of every ballot.
  - No egperf contest data phase (the harness streams and discards ballots; see carry-overs).
- **Q20 (S6) Byte layout of b(C2, 64) in eqs (70), (99) and (101), answered 2026-10-06:** "c then v": b(c,32) ∥ b(v,32).
  The §5.5 tables do not say how the 64 bytes split. S6 already uses this order, and so does the KAT oracle.
- **Cadence:** "Keep going". After each stage: commit, update this tracker, push, start the next stage. Stop only
  for a new spec contradiction or question.

## Stages

| Stage | G-IDs | Blocked on | Status | Commit |
|---|---|---|---|---|
| S1 Hash encodings, indices, canonical order | G1, G6, G7, G35, G26 (1.F compare and constructor reuse), G12, G9 | — | done | 3cec099 |
| S2 Key-generation hardening | G5, G14, G15, G25, G34, G26 (H_B in record and guardian check) | S1 | done | 6fbc25c |
| S3 Ballot verification strictness | G4, G13, G33, G23, G24, G36; plus the push security-review findings on V8 (missing completeness/validation checks: ballot contest set vs ballot style, option set vs manifest, duplicates) | — | done | 7ae4cfc |
| S4 Tally soundness | G2, G27, G28, G20, G21, G30, G38, G16 | — | done | c549325 |
| S5 Supplemental fields redesign (with S5b: user follow-up decisions Q11-Q16) | G3, G8, G22, G29, G10 | — | done | 27e75e2 (+ S5b f8a0699, S5c) |
| S5c Null-vote relation gains the overvote term (Q17) | G22 (Q17 follow-up) | S5b | done | 567e7a6 |
| S6 Contest data | G11, G32 | after S4 | done | see next commit |
| S7 Ballot nonce and challenged ballots | G17, G18 | after S4 | todo | |
| S8 Chain closing | G19, G37 | — | todo | |
| S9 Pre-encrypted recording tool | G31 | after S5, S7 | todo | |
| S10 Record metadata | G40 (G39 won't fix, per Q9); S2 carry-overs: bind the parsed `Manifest` to `ManifestFile` (S2 review R1), record JSON round trip; S4 carry-overs: a `DecryptedTally` record serializer, and a tally loaded from a record must carry or recompute each option's `MaximumCount` (S4 review R1) | — | todo | |

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

S3: no hash, nonce, ciphertext, confirmation code or KAT value moved (every KAT passed before and after; smoke and
console tallies unchanged). The 11 tests S3 re-pinned are behavior pins (exception types and the 0-in-Z_q rule),
listed in the S3 log entry.

S4: no existing hash, nonce, ciphertext, confirmation code or KAT value moved. The two new digests, d_i (eq. 88) and
c (eq. 90), are pinned only by the oracle's new `tally_decryption_commitment_hash` (7) and
`tally_decryption_challenge` (3) families, through `KnownAnswerTests.TallyDecryptionCommitmentHash_Eq88` and
`TallyDecryptionProof_Eq86To93_AndVerification10`; no test holds a literal. The console's `tally.json` changed shape
(it now carries `ContestIndex`, `ChoiceIndex`, `T`, `Challenge`, `Response`); its counts did not. The tests S4
re-pinned are behavior pins (exception types), listed in the S4 log entry.
S4 review response: no pinned value moved. The eq. (88) and (90) hashes now build their input in a pooled buffer;
the bytes are unchanged, which the two oracle families above confirm (they passed before and after).

S5: by design, every contest hash and confirmation code of a ballot whose contest declares supplemental fields moves
(G3: each field has its own nonce xi_{i,j}; G8: only declared fields, in manifest order, are hashed), and a contest
that declares none no longer hashes four counters. No test held a literal for them. The KAT `contest_hash` family (3
vectors), unsupported until now, is checked (`KnownAnswerTests.ContestHash_Eq70`), and
`Encryption_ReproducesTheContestHashAndConfirmationCodeVectors` encrypts the oracle's main-chain ballot (K = g^5,
id_B, xi_B) and gets chi_1, chi_2 and the oracle's confirmation code. No KAT value moved. The undervote difference
proof's challenge and the combined selection-limit ciphertext are not spec-defined, so no oracle vector can pin
them; `SupplementalFieldVerificationTests` pins their documented formats by recomputation. The perf manifests changed
(`manifestHash` of every committed scenario), the console's `tally.json` gains the supplemental fields'
entries, and `expected-tally.json` gains `undervoteDifference` (`undervotes` is now the indicator total). The
tests S5 re-pinned are listed, with reasons, in the S5 log entry.

S5 review round 2: no hash, nonce, ciphertext, confirmation code or KAT value moved, and no existing test was
re-pinned (the gate was green before any test edit). The round only adds tests.

S5 review round 3: no hash, nonce, ciphertext, confirmation code or KAT value moved, and no existing assertion was
re-pinned. The round adds three Manifest.Validate tests and marks the question 4 pins below.

S5 decision-dependent pins (review rounds 1 and 3). These pinned the recommended option (a) of S5 user questions
1, 2 and 4. **Resolved in S5b** by user decisions Q11-Q16: the `DECISION-DEPENDENT PIN` markers are gone from the
source, and the last column says what each pin became. None of the user's answers was option (a) or (b) as asked:
Q13/Q14 removed the "does not count" case the first four rows were about.

| Location | Pinned | Question | S5b |
|---|---|---|---|
| `SupplementalFieldVerificationTests.HonestCases` row `{1, 1, false, 0, 0, 1}` | null indicator 1 when the only marks are uncounted write-ins | 2 | Row removed (no uncounted write-ins, Q13). New row `{1, 1, 0, 0, 1}`: a write-in-only ballot has null indicator 0. |
| `SupplementalFieldVerificationTests.HonestCases` row `{1, 1, false, 1, 1, 2}` | write-in count 0 on an overvote although it does not count | 1 | Row removed (Q13). Write-ins are 0 on every overvote (Q12): rows `{1, 1, 1, 0, 1}`, `{2, 1, 1, 0, 2}`. |
| `ExpectedTallyTests.Add_WriteInsCountTowardTheLimitOnlyWhereTheManifestSaysSo(false, 0, false)` | `Nullvotes` 1 for uncounted write-ins only | 2 | Theory replaced by `Add_WriteInsAlwaysCountTowardTheLimit` (5 rows); a write-in alone gives `Nullvotes` 0. |
| `ExpectedTallyTests.Add_OnAnOvervote_ZeroesWriteInsThatDoNotCountTowardTheLimit` | `WriteIns` 0 on an overvote with uncounted write-ins | 1 | Removed; its case is row (1, 1, 1) of `Add_WriteInsAlwaysCountTowardTheLimit` (`WriteIns` 0, Q12). |
| `ExpectedTallyAccumulator.Add` and `BallotEncryptor.EncryptContest`/`SupplementalValue` | the rules themselves | 1, 2 | Both re-derived for Q11-Q15; the egperf `limits` scenario and `ScenarioRunnerTests` check that they agree. |
| `SupplementalFieldVerificationTests.HonestCases`, every overvoted row | undervote indicator 1 on an overvote | 4 | Undervote indicator 0 and difference 0 on every overvoted row (Q11, Q15). |
| `BallotEncryptorTests.Encrypt_OvervoteCounter_ProofIsWellFormed` | encrypted undervote indicator 1 on an overvote | 4 | Indicator 0, difference 0. |
| `ExpectedTallyTests.GetCounters_CountsAnOvervote`, `GetCounters_OnAnOvervote_ComputesTheUndervoteFieldsOnTheZeroedSelections` | `Undervotes` 1 on an overvote | 4 | `Undervotes` 0 and `UndervoteDifference` 0. The second test is renamed `GetCounters_OnAnOvervote_TheUndervoteFieldsAreZero`. |
| `SupplementalFieldTallyTests.Decrypt_EverySupplementalFieldTotal_MatchesTheIndependentlyAccumulatedTally_AndVerifies` | `Undervotes` 5 (includes the 3 overvotes) | 4 | `[3, 1, 2, 3, 2]`: undervotes 2, difference 3 (0 per overvote). |
| `ExpectedTallyAccumulator.Add` and `BallotEncryptor.SupplementalValue` | the undervote rule | 4 | Both 0 on an overvote. The difference is 0 too, or L where the overvote indicator is not declared (open S5b question A). |

S5b: no KAT value moved, and every KAT family passed before and after, including `ContestHash_Eq70` and
`Encryption_ReproducesTheContestHashAndConfirmationCodeVectors`. What moved, by design:
- The selection-limit proof's ciphertext now includes the undervote indicator, where one is declared.
- The undervote difference relation's ciphertext now always includes the write-in count, and the overvote indicator
  raised to L.
- Every contest that declares the null-vote indicator carries the new `NullVoteProof`.
- On an overvote, the undervote indicator and the difference count encrypt 0 (S5: 1 and L), so those ballots' field
  ciphertexts, contest hashes and confirmation codes differ.

No test holds a literal for any of these. The non-spec formats are pinned by recomputation in
`SupplementalFieldVerificationTests`: `LimitProof_IsEq62...`, `UndervoteDifferenceProof_IsTheDocumentedOneValueProof`,
`NullVoteProof_IsTheDocumentedRangeProof` and `RelationCiphertexts_MatchTheirDefinitions_OnBothEngines`.

The committed manifests lost their `countsTowardSelectionLimit` keys, so every scenario's `manifestHash` changed.
`option-limits` also replaced its third contest. The console's `tally.json` counts are unchanged.

S5b decision-dependent pins (review round 1). These pinned the implemented option (a) of S5b user questions A, B
and C (see the S5b log and the S5b review round 1 entry). **Resolved in S5c** by user decisions Q17-Q19: A (Q18)
and B (Q19) keep option (a), C (Q17) is option (b). The `DECISION-DEPENDENT PIN` markers and the "open question"
wording are gone from the source; the last column says what each pin became.

| Location | Pins | Question | On (b) | S5c |
|---|---|---|---|---|
| `ExpectedTallyAccumulator.Add` and `BallotEncryptor.SupplementalValue` | u = L on an overvote when the overvote indicator is not declared | A | Unreachable (Validate rejects such a contest); the rule may stay or be simplified to u = 0. | Kept (Q18). |
| `test/data/option-limits/manifest.json`, contest `l3-r3-no-overvote` (used only by `perf/scenarios/limits.json`; no unit test loads it) | a contest declaring u without the overvote indicator | A | Validate rejects the manifest and egperf `limits` fails at load: add the overvote indicator to the contest (or drop it), then rebaseline `limits`. | Kept (Q18); perf/README cites Q18. |
| `SupplementalFieldVerificationTests.EveryCombinationOfTrackedFields_HonestBallotsOfEveryKind_Verify`, the `expected = election.L` branch | u = L on an overvote without the overvote indicator | A | The 8 masks that declare u without the overvote indicator throw at Build: skip them (or assert the throw) and drop the branch. | Kept (Q18); the comment cites Q18. |
| `ExpectedTallyTests.GetCounters_OnAnOvervoteWithoutAnOvervoteIndicator_TheUndervoteDifferenceIsL` | `UndervoteDifference` 2 (= L) | A | Would still pass silently (neither `CreateMinimalManifest` nor the accumulator validates): delete it or make it a Validate test. | Kept (Q18); the comment cites Q18. |
| `ManifestValidationTests.Validate_AnyKindDeclaredOnItsOwn_DoesNotThrow(UndervoteDifferenceCount)` | u alone is a valid declaration | A | Throws; move the row to a Throws test. | Kept (Q18); the comment cites Q18. |
| `Manifest.Validate`'s write-in rule | write-in fields offered require a declared write-in count | B | Remove the rule; the encryptor and accumulator must then ignore untracked write-ins in every rule. | Kept (Q19). |
| `ManifestValidationTests.Validate_WriteInFieldsOfferedWithoutAWriteInCount_Throws` (×2) | Validate throws | B | Does not throw. | Kept (Q19); the comment cites Q19. |
| `SupplementalFieldVerificationTests.Build`, `ManifestValidationTests.WithFields`, `SupplementalFieldSerializationTests.Encrypt` defaults (W = 0 unless the count is declared) | not a pin: valid under both options | B | No change required. | Unchanged; the comments cite Q19. |
| `SupplementalFieldVerificationTests.Verification7_InconsistentIndicatorsNoRelationCovers_Verify("null-vote indicator 1 on an overvote")` | that forgery verifies | C | Fails 7.D ("Null-vote proof"): move it to `ForgeryCases`. Also `RangeProofChallenge.RelationCiphertexts`, the encryptor's null-vote `Combine`, `NullVoteProof_IsTheDocumentedRangeProof`, `RelationCiphertexts_MatchTheirDefinitions_OnBothEngines` and the `DeviceProof`/`Forge` null-value formulas gain the L*overvote term. | Done (Q17): the case is `ForgeryCases`' "null-vote indicator set on an overvote" (7.D "Null-vote proof"), plus a new "..., null-vote proof without the overvote term" case. Every listed site gained the term; the both-engines test is split into a scalar theory and an `[Avx512Theory]`. |

S5c: no KAT value moved (every KAT family passed before and after). What moved, by design: the `NullVoteProof` of
every contest that declares both the overvote indicator and the null-vote indicator, whose ciphertext gains the
overvote indicator raised to L (Q17). Its challenge format, the field ciphertexts, contest hashes and confirmation
codes are unchanged; a contest that declares the null-vote indicator without the overvote indicator keeps the S5b
proof bytes. No test holds a literal for it: `NullVoteProof_IsTheDocumentedRangeProof` (now a null vote and an
overvote), the new `NullVoteProof_WithoutAnOvervoteIndicator_HasNoOvervoteTerm` and
`RelationCiphertexts_MatchTheirDefinitions_OnTheScalarEngine`/`_OnTheAvx512Engine` pin it by recomputation. The
console's `tally.json` counts are unchanged.

S6: no existing KAT value moved (every pre-S6 family passed before and after). What moved, by design:
- C_1 of every contest data field (G11: KDF counter 1..b_Λ and constant length field; fixed 32·b_Λ length), and
  so the contest hash and confirmation code of every ballot whose contest declares contest data. Every committed
  manifest now declares b_Λ = 2 on its write-in contests, so every such ballot of `smoke`, `limits`,
  `famous-names` and the console carries the field and its chi and H_C differ from S5c.
- The hash input of eq. (70) with contest data now writes C_0 as b(C_0, 512) (it was the raw byte array, 512 bytes
  from the encryptor anyway).

The new digests are pinned only by the oracle's seven contest data families (`contest_data_nonce` 7,
`contest_data_secret_key` 5, `contest_data_kdf_key` 7, `contest_data_encryption_challenge` 5,
`contest_hash_with_contest_data` 3, `contest_data_decryption_commitment_hash` 7, `contest_data_decryption_challenge`
3) and the appended `confirmation_code` vector, through `KnownAnswerTests.ContestData.cs`; no test holds a literal.
One test literal was re-pinned: `BallotEncryptorTests.Encrypt_WriteInCounter_ProofIsWellFormed` pinned C_1 = 32 bytes
(the pre-S6 "pad to the next block of the text" length) and now pins 32·b_Λ = 64. The committed manifests'
`manifestHash` changed (every scenario); the console's `tally.json` counts are unchanged and it now also writes
`contest-data.json`.

## Log

### 2026-10-05 — S6 review round 2 (G32: administrator zero-share and misaddressed-message tests)
One finding (tests lens, minor), accepted. Tests only; no library code, interoperable byte or pinned value
changed. Nothing staged or committed.

**The administrator's zero-m_j branch on the contest data path was untested.** This is correct. The only zero-share
test, `TallyGuardianTests.Decrypt_ZeroPartialDecryption_ThrowsNamingTheGuardian`, covers the tally path.
The contest-data tamper tests multiply m by g, so they never produce 0. The round-1 C_0 membership fix exists so
that `CombineContestData`'s check (TallyGuardian.cs ~590) blames only a guardian that really sent 0. A regression
removing that check would have gone unnoticed: β = 0 would reach the combined-proof check and Note 3.7's attribution,
which give a different message. New tests in `ContestDataDecryptionTests`:
- `CombineContestData_ZeroPartialDecryption_NamesTheGuardian`. Guardian 3 (second of {1, 3}) sends m_i = 0 via
  `PartialDecryptionTamperForTesting`. The test asserts a `TallyDecryptionException` naming that guardian, a message
  that starts "Contest data did not decrypt successfully" and contains "is 0", and no "Note 3.7".
- `CombineContestData_MessageForAnotherBallotOrContest_NamesTheSender` (6 cases). This is the finding's optional
  suggestion. It first checks that the honest messages combine. Then it re-addresses guardian 2's round-1, round-2
  or round-3 message to ballot-2 or contest-2, and asserts the administrator's `statement.Read` names that sender.
  Before this test, that path was exercised only from the guardian side.

Mutation check: not run. The permission classifier denied building and testing with the zero-share branch disabled,
and the edit was reverted with no trace in the diff. The test still pins the branch by construction. Line 593 is the
only contest-data message containing "is 0", and every other way to reach a `TallyDecryptionException` with β = 0
(the combined-proof failure and Note 3.7) produces a message that lacks "is 0" or contains "Note 3.7".

Gate (Release), after the change; no test failed at any point, so nothing was re-pinned:
- Build: 0 Warning(s), 0 Error(s).
- Smoke: `correctness passed`. dkg 142 ms. EncryptBallots 242 ms, 0.242 ms/ballot, 170.9 MB. VerifyBallots 972 ms,
  0.972 ms/ballot, 12.4 MB. Tally 8, VerifyTally 4, DecryptTally 37, VerifyDecryption 8 ms. These are within run
  noise of round 1 (0.244 / 0.996 ms/ballot), and no hot path changed.
- Console: `Ballot 0, contest 0: contest data "Write-in: Ada Lovelace".`, `Done.`, then the expected
  Console.ReadKey InvalidOperationException. tally.json and contest-data.json were rewritten at 23:08:13;
  "0-0" VoteCount 3 and "0-1" VoteCount 0.
- Tests: Core 1418/1418 (was 1411; +1 zero-share, +6 misaddressed), Perf 226/226.

Carry-overs: unchanged from round 1. These are the C2 byte-order question (pending the user), the S7 nonce-decryption
membership check, and no egperf contest-data phase.

### 2026-10-05 — S6 review round 1 (G32: C_0 subgroup membership; G11/G32 test gaps)
Five findings (two major, three minor), all accepted. Worktree changes only; nothing staged or committed. No
interoperable byte and no pinned value moved.

**C_0 not checked for subgroup membership (spec lens and code lens, major; the same defect).** Confirmed against
§3.6.6 p.49-50: the guardians verify only the eq. (69) proof before computing m_i = C_0^{ẑ_i}, and nothing else
checks C_0 (it is not in Verifications 6-8, `BallotStructure` checks only C_1's length, and
`IntegerModP.FromCanonicalBytes` accepts any value in [0, p)). The proof accepts non-members. With C_0 = 0, a = 0
and any v, every honest m_i is 0, and the administrator's zero-share check blamed `participants[0]`, an honest
guardian. With C_0 = p - g^ξ and an even c (about two draws of u), C_0^c = g^{cξ}, so the proof verifies; then
p ≡ 3 (mod 4) (p - 1 = 2·q·r', with q and r' odd) and m_i = (-1)^{ẑ_i}·g^{ξẑ_i}, so each guardian leaks the parity
of its share. The spec states no membership check, so this is a hardening and not a byte-level deviation, but the
misattribution is a bug in the library's own blame logic. Fix: `ContestDataStatement.RequireEncryptionProof` is
renamed `RequireDecryptable`. It first requires `SubgroupMembership.IsMember(C_0)`, which checks 0 < C_0 < p and
C_0^q = 1 with the `BigInteger` exponent, and then the proof. Both the guardian (`CommitContestData`) and the
administrator (`CombineContestData`) call it, and it throws `TallyDecryptionException(null, ...)` ("... is not in
the order-q subgroup Z_p^r ..."). Cost: one full-width exponentiation per field per guardian and once for the
administrator, off every perf phase. Verification 12 is unchanged. It is a spec verification, and adding the check
would reject records the spec accepts; its class remarks now say so. Doc comments on `CommitContestData`,
`CombineContestData` and CLAUDE.md are updated.

**Tests added (Core 1399 -> 1411):**
- `CommitContestData_C0NotInTheSubgroupWithAValidProof_RefusesNamingNoGuardian` (zero, negated). Each first
  asserts that the forged proof holds and that C_0 is not a member, so the test reaches the new check and not the
  proof check. The guardian refuses with `OffendingGuardian` null and "Z_p^r" in the message.
- `CombineContestData_FieldTheGuardiansWouldRefuse_RefusesNamingNoGuardian` (response + 1 -> "eq. 69"; zero and
  negated -> "Z_p^r"). The test builds valid three-round messages for a good ballot and checks that they combine.
  It then calls `CombineContestData` with the bad field and expects no guardian named and "the administrator" in
  the message. This answers the tests-lens minor finding: deleting the administrator's check now fails all three
  cases. Without it, the "response" case reaches the d_j check, which hashes C_2, and names a guardian.
- `Verification12_StructureFault_Fails12Structure` (unknown contest, b_Λ = 0 in the record's manifest, C_1 one
  block short, H_I replaced by 32 other bytes) -> `"12.structure"`. With the two existing cases, all six branches
  are now covered.
- `CommitContestData_StructureFault_Throws` (unknown contest, C_1 one block short, H_I replaced) ->
  `ArgumentException`. The b_Λ = 0 case was already covered.
- `ContestDataEncryptionTests.Encrypt_FieldDecryptsUnderTheBallotNoncesKey` now also asserts that two
  encryptions under the same ξ have different c and v, and that both proofs hold. A u derived from ξ_B or ξ would
  repeat, and v - v' = (c' - c)·ξ would reveal ξ.
- Mutation checks (run, then reverted): with the membership check disabled, the 4 non-member cases fail. With the
  administrator's `RequireDecryptable` call removed, all 3 `CombineContestData` cases fail.

Gate (no pinned expectation broke, so there was nothing to re-pin):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`. dkg 136 ms. EncryptBallots 0.244 ms/ballot, 170.9 MB. VerifyBallots 0.996 ms/ballot,
  12.4 MB. Tally 7, VerifyTally 4, DecryptTally 34, VerifyDecryption 8 ms. These match the S6 numbers: no smoke
  phase decrypts contest data.
- Console: `Ballot 0, contest 0: contest data "Write-in: Ada Lovelace".`, then `Done.`, then the expected ReadKey
  `InvalidOperationException`. `tally.json` and `contest-data.json` were rewritten at 22:46:05, with 0-0: 3 and
  0-1: 0.
- Tests: Core `Passed: 1411, Total: 1411`; Perf `Passed: 226, Total: 226`.

Carry-over for S7: §3.6.7's decryption of the ballot nonce (Verifications 13.6/13.7) has the same C_0 shape and
the same Schnorr gate, so it needs the same membership check before any guardian exponentiates with its share.

### 2026-10-05 — S6 (contest data: G11, G32)
Worktree changes only; nothing staged or committed. The KAT oracle (`test/kat/*`) was extended by the orchestrator
before this stage with seven contest data families; this stage makes them pass through the library.

**G11 (contest data encryption, §3.3.10 eqs. 63-70):**
- `Contest.ContestDataBlocks` (b_Λ, per contest, Q7) replaces `Manifest.OptionalContestDataMaxLength` (removed;
  it was never read). `Manifest.Validate` requires 0 <= b_Λ < 2^24.
- `ContestDataEncryption` (new, public static) holds every shared derivation: ξ (eq. 64), h (eq. 65), the KDF key
  k_i (eq. 66) with block counter i = 1..b_Λ (Q6) and the constant length field b(b_Λ·256, 4) (unsigned, since
  b_Λ·256 can exceed `int.MaxValue`), Label/Context `data_enc_keys`/`contest_data` ‖ b(ind_c, 4), the XOR, the 0x27
  challenge (eq. 69) and its check (`ProofHolds`), and the decryption of eqs. (104)-(106). The encryptor's private
  `EncryptContestData` is gone. The old one used the byte offset as the counter and i·256 as the length field, and
  padded to the text's own length plus an extra zero block when the text filled one.
- `BallotContest.ContestData` is now `byte[]?`, exactly 32·b_Λ raw bytes (Q7); `ContestDataEncoding` is the Q7
  helper (b(len,4) ‖ UTF-8 ‖ zero padding; rejects, never truncates, text over 32·b_Λ - 4 bytes or invalid
  Unicode; `Decode` rejects a bad prefix, nonzero padding or invalid UTF-8). The encryptor refuses contest data on
  a contest declaring none, or of another length (`InvalidBallotException`), and encrypts 32·b_Λ zero bytes when a
  declaring contest's data is null (orchestrator design: every ballot carries the field).
- `EncryptedContestData` (new) replaces `EncryptedData` on `EncryptedContest.ContestData`; C_0 is an `IntegerModP`.
  `ContestHash` writes b(C_0,512) ‖ C_1 ‖ b(c,32) ‖ b(v,32) (the stale "don't seem like they belong" comment is
  gone). Verification 8 recomputes chi with the field through the same constructor.
- `BallotStructure` (so Verifications 6, 7, 8 and `AddBallot`/9) requires the field exactly where the manifest
  declares it, with C_1 of exactly 32·b_Λ bytes (`"N.structure"`).
- Serialization: JSON reads C_0 through the strict `IntegerModP` converter (same base64 shape as before); protobuf
  decodes C_0 with `IntegerModP.FromCanonicalBytes` and rejects a C_1 that is null or not a nonzero whole number of
  32-byte blocks. No new field, so no DTO member was added.
- Test seam: `BallotEncryptor.ContestDataProofNonceForTesting` fixes u of eq. (69) for the KAT.

**The 0x27 proof.** Searched the spec (text and §5.5/§6.2 pages): eq. (69)'s proof is verified only in §3.6.6
(p.49-50, "before each available guardian ... computes a partial decryption, it verifies that the Schnorr proof is
valid"); Verifications 6, 8 and 12 do not mention it and 12.A-12.C do not include it. So the guardians check it
(`TallyGuardian.CommitContestData`, a `TallyDecryptionException` naming no guardian), the administrator checks it
again before publishing, and no numbered sub-check was invented.

**G32 (contest data decryption, §3.6.6 eqs. 96-106, Verification 12):**
- The S4 machinery is generalized, not duplicated: `VerifiableDecryption` (new, internal) holds round 1 (u_i, the
  partial decryption, (a_i, b_i), d_i), the check of every d_j and the combination into a, b, the combined
  decryption and c, the responses, the proof check and Note 3.7's attribution, over `IDecryptionStatement`s.
  `TallyOption` (now carrying H_E) is the tally's statement (eqs. 88/90), `ContestDataStatement` the contest data's
  (eqs. 99/101 in the new `ContestDataDecryptionHashes`, keyed with H_I per Q5; U ascending per Q10; C_2 as
  b(c,32) ‖ b(v,32)). `TallyDecryptionMessages` keeps only the tally's message mapping. The refactor was
  checkpointed before any contest data wiring: all 276 tally and KAT tests passed unchanged.
- `TallyGuardian.CommitContestData`/`RevealContestData`/`RespondContestData` (m_i = C_0^{ẑ_i} with the ballot data
  key share, a_i = g^{u_i}, b_i = C_0^{u_i}; the existing `NonceSourceForTesting`/`PartialDecryptionTamperForTesting`
  seams are called with ind_o = 0). The guardian session is generic (`Session<T>`), so a tally session cannot be
  revealed or answered with contest data messages or the other way round.
- `TallyAdmin.DecryptContestData`/`CombineContestData`: quorum, one message per participant per round for this
  ballot contest, no zero m_j, d_j checks, β (eq. 97), v (eq. 103), the proof checked against K-hat before
  publishing (Note 3.7 with the guardians' K-hat commitments names a bad share), then h (12.3), the keys (eq. 104)
  and D (eq. 106). Publishes `DecryptedContestData` (ballot, contest, ind_c, β, c, v, D; `DecodeText()`).
- `ContestDataDecryptionVerification` = Verification 12: `"12.structure"` (other ballot, unknown contest or one
  without contest data, wrong published index, malformed ballot, H_I not H(H_E; 0x20, id_B)), then 12.A, 12.B
  (a = g^v·K-hat^c, b = C_0^v·β^c, eq. 101), 12.C (D against C_1 XOR the eq. 104 keys).
- Console: every ballot's contest data is decrypted by all three guardians and checked by Verification 12; ballot 0
  carries "Write-in: Ada Lovelace" (printed), and `contest-data.json` is written. Secret exponents (ξ, u, u_i, ẑ_i)
  all go through `MontgomeryModP.PowModP`.

Fixtures and consumers: the four committed manifests (b_Λ = 2 on every write-in contest; the key
`optionalContestDataMaxLength` removed, which `ManifestLoader` would now reject), `famous-names/ballots/1.json` and
`2.json` (their `contestData` strings re-encoded as base64 of the Q7 encoding), `ElectionFixtureBuilder`
(`contestDataBlocks` parameter, default `DefaultContestDataBlocks` = 2 with write-ins; `CreateBallot` encodes its
string with the helper), `Testing.Cli` (b_Λ = 2 per contest), `BallotGenerator` (text on each contest whose voter
used a write-in, derived from the ballot index so the random stream is untouched), the console. Outside the
worktree: `C:\temp\eg\data\1\manifest.json` (backup `manifest.json.pre-s6.bak`: key removed, `contestDataBlocks: 2`)
and `C:\temp\eg\data\1\ballots\0.json` (backup `C:\temp\eg\data\1\ballot-0.json.pre-s6.bak`, kept out of
`ballots\` because the console reads every file there: `contestData` set to the encoding of "Write-in: Ada
Lovelace"; its selections and `numWriteinsSelected` 0 unchanged, so the tally does not move).

Gate before re-pinning (code, fixtures and the new KAT tests in; no existing expectation edited):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`. dkg 139 ms; EncryptBallots 0.237 ms/ballot, 170.9 MB; VerifyBallots 0.975 ms/ballot,
  12.4 MB; Tally 7; VerifyTally 3; DecryptTally 34; VerifyDecryption 8 ms; `tallyVerification: ran`,
  `decryptionVerification: ran`.
- Console: `Ballot 0, contest 0: contest data "Write-in: Ada Lovelace".`, `Done.`, then the expected ReadKey
  `InvalidOperationException`; `tally.json` rewritten at 22:18 with 0-0: 3, 0-1: 0, every supplemental field 0.
- Tests: Core `Failed: 1, Passed: 1328, Total: 1329` (`BallotEncryptorTests.Encrypt_WriteInCounter_ProofIsWellFormed`:
  C_1 length 64, expected 32); Perf `Failed: 2, Passed: 223, Total: 225`
  (`RunCommandTests.Execute_ReturnsExitCodeOneAndAppendsAnErrorRecordWhenTheRunThrows` and
  `...WhenSetupFails`: exit 2 instead of 1, because their inline manifests still carried the removed
  `optionalContestDataMaxLength` key and failed configuration loading before reaching the failure they test).
  All KAT families, including the seven new ones, passed.

Re-pinned, and why (nothing weakened, skipped or deleted):
- `Encrypt_WriteInCounter_ProofIsWellFormed`: C_1 = 32·b_Λ (= 64), not 32. The old value was the length leak G11
  removes.
- `RunCommandTests` (two inline manifests): the removed key dropped from the fixture JSON; the assertions are
  unchanged and test the same broken-ballot-style failure again.

New tests (Core 1329 -> 1399, Perf 225 -> 226):
- KAT (`KnownAnswerTests.ContestData.cs`, the class is now partial): `ContestDataNonce_Eq64` (7),
  `ContestDataSecretKey_Eq65` (5), `ContestDataKdfKey_Eq66` (7), `ContestDataEncryption_Eq64To69` (5: C_0, C_1, c, v
  through `ContestDataEncryption.Encrypt` with the oracle's u, each k_i, the Q7 D, the proof check and the
  decryption), `ContestDataEncoding_RejectsTheOraclesTooLongStrings`, `ContestHashWithContestData_Eq70` (3),
  `Encryption_WithContestData_ReproducesTheContestHashAndConfirmationCodeVectors` (the oracle's three-contest
  ballot through `BallotEncryptor`: chi_1..3 and H_C, then Verification 8), `ContestDataDecryptionCommitmentHash_Eq99`
  (7, both orders of U), `ContestDataDecryptionProof_Eq96To106_AndVerification12` (3: the whole protocol with the
  oracle's ẑ_i and u_i; every m_i, d_i, a_i, b_i, w_i, v_i, then β, c, v, h, D and the string; Verification 12
  accepts).
- `ContestDataDecryptionTests` (20): any quorum decrypts and V12 accepts; an empty field decrypts to ""; wrong m_i
  named by Note 3.7 (and 12.B when published unchecked); tampered c, v, β -> 12.B; tampered or short D -> 12.C;
  D from a 0-based counter or the old per-block length field -> 12.C; another ballot/index -> 12.structure, another
  ballot's field -> 12.B; an invalid 0x27 proof (v, C_1 or C_0 tampered) refused by the guardian; a contest
  without contest data -> `ArgumentException`; a reveal not matching d_j names the guardian (eq. 99); a message for
  another ballot names its sender; sessions of the other kind are refused and a response ends the session.
- `ContestDataEncryptionTests` (24): the field is always 32·b_Λ bytes (null, "", short, two-block text); none and
  refused where undeclared; wrong lengths refused; determinism from ξ_B and decryption under K-hat^ξ;
  `Manifest.Validate` bounds; the Q7 encoding's round trip, capacity edge, invalid surrogate and four malformed
  decodings.
- `BallotStructureTests`: contest B now declares b_Λ = 1; five new shapes × V6/7/8/9 (field on an undeclared
  contest, missing field, C_1 one block long, one byte short, null).
- `StrictDecodingTests`: JSON `contest data C0 = p`; protobuf C_0 = p, C_0 of 513 bytes, C_1 of 31 bytes, C_1 one byte
  over a block, C_1 missing.
- Perf `BallotGeneratorTests.Generate_WritesWriteInTextIntoTheContestDataOfBallotsThatUseAWriteIn` (text exactly on
  write-in ballots, 32·b_Λ bytes, and the same selections as a manifest without contest data).

Gate after:
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke ×3, each `correctness passed`: dkg 135-138 ms; EncryptBallots 0.242 / 0.243 / 0.246 ms/ballot, 170.9-171.0 MB;
  VerifyBallots 0.996 / 0.994 / 0.965 ms/ballot, 12.3-12.4 MB; Tally 8; VerifyTally 4; DecryptTally 35-41;
  VerifyDecryption 8-9 ms.
- `limits`: `correctness passed`; EncryptBallots 0.898 ms/ballot, 1,329.2 MB; VerifyBallots 3.450 ms/ballot, 93.6 MB;
  DecryptTally 45; VerifyDecryption 13 ms.
- Console: `Ballot 0, contest 0: contest data "Write-in: Ada Lovelace".`, `Done.`, then the expected ReadKey
  exception; `tally.json` and `contest-data.json` rewritten at 22:28:53, counts 0-0: 3, 0-1: 0, fields 0;
  `contest-data.json` has ballots 0 ("Write-in: Ada Lovelace"), 1 and 2 ("").
- Tests: Core `Passed: 1399, Total: 1399`; Perf `Passed: 226, Total: 226`.

Perf against S5c (same machine; S5c: Encrypt 0.236, Verify 1.004 ms/ballot):

| Scenario | Phase | S5c | S6 |
|---|---|---|---|
| smoke | EncryptBallots | 0.236 ms, 168.7 MB | 0.242-0.246 ms, 170.9-171.0 MB |
| smoke | VerifyBallots | 1.004 ms, 12.4 MB | 0.965-0.996 ms, 12.3-12.4 MB |
| limits | EncryptBallots | 0.876 ms, 1,310.7 MB | 0.898 ms, 1,329.2 MB |
| limits | VerifyBallots | 3.455 ms, 93.7 MB | 3.450 ms, 93.6 MB |

Encryption costs about 3% more by design: each contest that declares contest data now encrypts a field on every
ballot (g^ξ, K-hat^ξ and g^u, all three bases tabled). Verification does not move: no ballot verification checks
the field's proof, and the structure check and the extra hash input in chi are cheap. The manifests' hashes
changed, so `compare` treats S5c records as incomparable (perf/README updated).

Carry-overs:
- No egperf contest data phase: the runner streams and discards ballots, so a phase would mean retaining ballots
  with text, plus a new `PhaseSettings` flag, CLI override, result-schema key and report support. Unit tests and the
  console exercise the path; its cost is about 3k + 4 full-width exponentiations per field for k guardians plus
  V12's four.
- §3.6.7 (challenged ballots, S7) will derive ξ of eq. (64) from the decrypted ξ_B and check D against it
  (Verification 13.6/13.7); `ContestDataEncryption.Nonce`/`SecretKey`/`Apply` are public for that.
- A `DecryptedContestData` record serializer (with the S4 `DecryptedTally` carry-over, S10).

### 2026-10-05 — S5c review round 1 (open-question wording left outside the S5c diff)
Both review lenses (spec, code) found the same minor issue. The S5c entry below said every "open S5b question"
phrase was gone, but its grep missed the variant "(open S5b user question)". That variant was in three comments in
files outside the S5c diff, at sites the S5b pin table marks "Kept (Q18)" / "Kept (Q19)". Accepted and fixed
(comments only, no behavior change):
- `BallotEncryptor.SupplementalValue` remarks (u = L on an overvote without an overvote indicator) now cite Q18:
  with no tracked overvote indicator nothing publishes an overvote, so the neutralized contest is a blank one.
- `ExpectedTallyAccumulator` remarks (`test/ElectionGuard.Testing.Common/ExpectedTally.cs`) carry the same Q18
  citation.
- `Manifest.Validate`'s write-in rule now cites user decision Q19, "Reject manifest".
- The S5c log's claim below is annotated. A case-insensitive grep over src, test, perf and the root files
  (`open (S5b |S5 )?(user )?question|pending user|DECISION-DEPENDENT|question [ABC]`, docs excluded) now returns
  nothing.

Gate after (Release; comments only, so there was no before-repin stage): build `0 Warning(s)`, `0 Error(s)`;
smoke `correctness passed` (dkg 137 ms; EncryptBallots 0.230 ms/ballot, 168.7 MB; VerifyBallots 1.003 ms/ballot,
12.4 MB; Tally 8, VerifyTally 4, DecryptTally 34, VerifyDecryption 9 ms; `tallyVerification: ran`,
`decryptionVerification: ran`); console `Done.` then the expected ReadKey `InvalidOperationException`, with
`tally.json` rewritten at 21:39:29 (0-0:3, 0-1:0, every supplemental field 0); tests Core `Passed: 1289, Total:
1289`, Perf `Passed: 225, Total: 225`. No pinned value moved; nothing was re-pinned. The stage stays done (gate
green; awaiting commit).

### 2026-10-05 — S5c (null-vote relation gains the overvote term: G22, user decision Q17)
The user answered the three S5b questions (Q17-Q19 under Decisions). S5c applies Q17 and removes the open-question
wording of Q18 and Q19, which keep the S5b behavior.
- Git state: S5b is staged in the index (its signed commit is being retried by the orchestrator). S5c is unstaged
  working-tree changes on top. Nothing was staged, committed or stashed; no new tracked files.
- Notation as in S5b: s = sum of selections, w = write-in count, L = selection limit.

Code changes (G22, Q17):
- **The null-vote relation (3)** is now s + w + L*overvote + L*null in 0..L when the contest declares the overvote
  indicator, and s + w + L*null in 0..L when it does not (Q17: "When the overvote indicator is tracked").
  - Honest values still give at most L: overvote 0 + L + 0, null vote 0 + 0 + L. Overvote 1 with null 1 gives 2L
    and fails 7.D ("Null-vote proof").
  - With every field declared, the relations now leave two inconsistent values unchecked (both Q2: undervote
    indicator 0 with s + w < L, null 0 with s + w = 0), plus the inherent "null vote reported as an overvote".
    The S5b review round 1 third case (overvote 1 with null 1) is closed.
- **Encryptor (`BallotEncryptor.EncryptContest`).** The null proof's ciphertext is
  `Combine(sum, overvoteField, L, nullVoteField, L)` (`Combine` drops an undeclared term), and its value adds
  L when the contest is overvoted and declares the indicator. One more short-window ov^L per contest that declares
  both fields.
- **Verifier (`RangeProofChallenge.RelationCiphertexts`).** The null-vote ciphertext is now taken after the
  overvote power is folded into the sum, so the existing ov^L is shared by all three relations. The work is the
  same as in S5b, only reordered.
- **Challenge format unchanged:** c = H_q(H_I; 0x24, ind_c, ind_o(null), b(L,4), A, B, a_0, b_0, ..., a_L, b_L).
  Only the definition of (A, B) changes. Docs updated: `ComputeNullVoteChallenge`, the class remarks of
  `AdherenceToVoteLimitsVerification` (relation (3); the gap list drops the third case), its 7.D null-vote message
  (now names the overvote term), `EncryptedContest.NullVoteProof`, `RelationCiphertexts`' doc, the encryptor's
  (3) comment.
- **No serialization change.** No field was added, so the domain type, JSON and protobuf DTO are untouched.

S5b review leftovers:
- **The S5 review round 3 heading** is intact (S5b review round 1, R3 had already restored it); nothing to do.
- **Q18 / Q19 pins (keep).** Every `DECISION-DEPENDENT PIN` marker and "open S5b question" phrase is gone from
  the source (three "(open S5b user question)" comments outside the S5c diff were missed here and fixed in the
  S5c review round 1 entry above). The comments now cite Q18 or Q19:
  - Q18: the `EveryCombinationOfTrackedFields` u = L branch, `GetCounters_OnAnOvervoteWithoutAnOvervoteIndicator_...`
    and the `Validate_AnyKindDeclaredOnItsOwn_DoesNotThrow` theory.
  - Q19: `Validate_WriteInFieldsOfferedWithoutAWriteInCount_Throws`, plus the `Build`, `WithFields` and
    serialization `Encrypt` defaults.
  - Also perf/README (`limits`' third contest) and CLAUDE.md (the overvote bullet).
- **The both-engines test.** `RelationCiphertexts_MatchTheirDefinitions_OnBothEngines` ran the scalar engine twice
  without AVX-512. It is split into `_OnTheScalarEngine` (a theory) and `_OnTheAvx512Engine` (an
  `[Avx512Theory]`, skipped without AVX-512). Each asserts `RangeProofChallenge.UsesAvx512` matches. On this
  machine both ran.

Gate before re-pinning (src changes only; no test edited):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`. dkg 139 ms; EncryptBallots 0.227 ms/ballot, 168.6 MB; VerifyBallots 0.978 ms/ballot,
  12.4 MB; Tally 7; VerifyTally 4; DecryptTally 33; VerifyDecryption 8 ms; `tallyVerification: ran`,
  `decryptionVerification: ran`.
- `limits`: `correctness passed`. EncryptBallots 0.876 ms/ballot, 1,310.7 MB; VerifyBallots 3.455 ms/ballot,
  93.7 MB; DecryptTally 44; VerifyDecryption 14 ms.
- Console: `Done.`, then the expected ReadKey exception. tally.json rewritten at 21:09:35:
  `0-0 (1, 3)`, `0-1 (2, 0)`, fields (3..7, 0).
- Tests: Perf `Passed: 225, Total: 225`. Core `Failed: 8, Passed: 1276, Total: 1284`. The 8 failures:
  - `NullVoteProof_IsTheDocumentedRangeProof`;
  - `RelationCiphertexts_MatchTheirDefinitions_OnBothEngines(1)` and `(3)`;
  - `Verification7_EveryRelationReprovedByTheDeviceOnHonestValues_Passes`;
  - `Verification7_InconsistentIndicatorsNoRelationCovers_Verify` ×4.
- All 8 failures are the test-side formula for (3), which still left out ov^L, so every re-proved null proof was
  over the wrong ciphertext. Of the four `InconsistentIndicators` cases, only "null-vote indicator 1 on an
  overvote" is a closed gap; the other three are expected to keep verifying.
- The 32-mask × 8-kind honest matrix passed: encryptor and verifier agree for every tracked-field subset.

Re-pinned, and why (nothing weakened or skipped):
- **`NullVoteCiphertext`** (the test's definition of (3)) gains `.Times(overvote, L)` where the overvote indicator
  is declared.
- **`Forge` and `Verification7_EveryRelationReproved...`**: the null value adds L*overvote. This fixes the three
  still-unchecked `InconsistentIndicators` cases and the reproved-honest control.
- **`NullVoteProof_IsTheDocumentedRangeProof`** recomputes (A, B) with ov^L. It is now a theory over a null vote
  (0, 0) and an overvote (2, 1), so the overvote term is pinned with a nonzero plaintext.
- **"null-vote indicator 1 on an overvote"** moved from `UncheckedCases` to `ForgeryCases` as "null-vote indicator
  set on an overvote". It is the negative test: both proofs are re-proved by the forging device, and it fails 7.D
  "Null-vote proof".
- **The "null vote reported as an overvote" comment** now gives (3) = L.

New tests (Core 1284 → 1289):
- `ForgeryCases` "null-vote indicator set on an overvote".
- `ForgeryCases` "null-vote indicator set on an overvote, null-vote proof without the overvote term". The new
  helper `WithoutOvervoteTermInNullVoteProof` re-proves only (3), over S5b's s + w + L*null; `Forge`'s `omit`
  would drop the term from (1) too, which then fails first. That proves a true statement (= L), so only a
  verifier that includes the term rejects it.
- `NullVoteProof_IsTheDocumentedRangeProof`'s second row.
- `NullVoteProof_WithoutAnOvervoteIndicator_HasNoOvervoteTerm`: Q17's "when tracked" clause. The S5b format pin,
  plus V6-V8.
- The split engine test: 4 rows where there were 2.
- One `UncheckedCases` row moved out.

Mutation check. Applied from `C:\temp\s5c\mutate.py`, built, run, restored from `C:\temp\s5c` (`cmp` clean):
- The mutation: encryptor and `RelationCiphertexts` both drop the overvote term from (3), i.e. S5b's relation on
  both sides, so honest ballots still verify.
- 11 SupplementalField tests failed, including "... null-vote proof without the overvote term".
- The plain "null-vote indicator set on an overvote" case did *not* fail. Its device proves over the Q17
  ciphertext, which the mutant verifier also rejects. That is why the without-the-term case exists: it is the
  one that catches a verifier missing the term.
- The honest 32-mask matrix passed under the mutant (both sides consistent), as expected.

Gate after:
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke ×3, each `correctness passed`:
  - dkg 137-141 ms;
  - EncryptBallots 0.237 / 0.227 / 0.242 ms/ballot, 168.6-168.7 MB;
  - VerifyBallots 1.012 / 1.020 / 0.995 ms/ballot, 12.4 MB;
  - Tally 8; VerifyTally 4; DecryptTally 33-35; VerifyDecryption 8-9 ms.
- Console: `Done.`, then the expected ReadKey exception. tally.json rewritten at 21:16:50 with the same counts:
  `0-0 (1, 3)`, `0-1 (2, 0)`, fields (3..7, 0).
- Tests: Core `Passed: 1289, Total: 1289` (AVX-512 rows ran, none skipped); Perf `Passed: 225, Total: 225`.
- Final pass, after a wording fix to the 7.D null-vote message ("L times the overvote indicator (where declared)")
  and restoring CRLF on files edited by script: build `0 Warning(s)`, `0 Error(s)`; Core 1289/1289, Perf 225/225;
  smoke `correctness passed`, EncryptBallots 0.230 ms/ballot, 168.6 MB, VerifyBallots 0.997 ms/ballot, 12.4 MB;
  console `Done.`, tally.json rewritten at 21:25:33 with the same counts.

Perf against S5b (same machine; S5b review round 1: Encrypt 0.237, Verify 0.981 ms/ballot, 12.4 MB):

| Scenario | Phase | S5b | S5c |
|---|---|---|---|
| smoke | EncryptBallots | 0.232-0.245 ms/ballot, 169.5-169.7 MB | 0.227-0.242, 168.6-168.7 MB |
| smoke | VerifyBallots | 0.972-0.988 ms/ballot, 12.3-12.4 MB | 0.978-1.020, 12.4 MB |
| limits | EncryptBallots | 0.849-0.864 ms/ballot, 1,310 MB | 0.876, 1,310.7 MB |
| limits | VerifyBallots | 3.389-3.395 ms/ballot, 93.5-93.7 MB | 3.455, 93.7 MB |

- The verifier does the same multiplies in a different order, and allocation is identical. The S5c range of
  0.978-1.020 overlaps S5b's 0.972-0.988, so it is run-to-run noise.
- The encryptor adds one ov^L (a short window over L's bits) per contest that declares both fields; within noise.

Decisions taken (low stakes):
- The null proof's challenge layout is unchanged; only (A, B) gains the term.
- The engine test split uses the existing `[Avx512Theory]`.

Carry-overs: unchanged from S5b. The S5b questions A, B and C are closed (Q18, Q19, Q17). `C:\temp\s5c\` holds the
mutation script, pre-mutation backups and edit scripts, and can be deleted. New files: none.

### 2026-10-05 — S5b review round 1 (G22, G10: a third unchecked indicator case, decision-dependent pins, tracker repair)
Four review findings. All four are right, with one correction to finding 2's evidence. Nothing in `src/` changed except
a doc comment. No assertion moved; the round adds tests and comments only. Everything is still unstaged on top of
S5 (27e75e2); nothing was staged, committed or stashed.
- **R1 (spec, minor), right: V7 accepts overvote 1 with null 1.**
  - Checked by hand with every field declared. Take overvote 1, null 1 and s = w = und = u = 0: (1) gives L,
    (2) gives L and (3) gives L. All pass, and V6 passes too. p.39 (spec text: "When all the selections are set to
    zero as a consequence of an overvote, the null vote indicator should be set to zero") and Q3 say null is 0.
  - The cause: (1) forces the undervote indicator to 0 on an overvote through its L*overvote term, but (3), as
    Q15 states it ("s + w + L·null ≤ L"), has no overvote term.
  - Enumerated the full solution set of (1)-(3) instead of trusting a count. Given the true s + w:
    - with overvote 1, the relations force s + w = 0, und = 0 and u = 0, and leave null free;
    - with overvote 0, they force u = L - s - w, und = 0 at s + w = L and null = 0 at s + w > 0.
    - So the inconsistent values that verify are exactly: und 0 with s + w < L (Q2), null 0 with s + w = 0 (Q2),
      and null 1 on an overvote (new).
    - Separately, and inherent in the spec's design, an encrypted overvote (all zero, overvote 1) cannot be told
      apart from a null vote that a device re-encodes as an overvote. This is now documented too, so that it is
      not counted as a missed gap.
  - `AdherenceToVoteLimitsVerification`'s remarks and CLAUDE.md now list the three cases and the inherent one.
  - New `Verification7_InconsistentIndicatorsNoRelationCovers_Verify` (4 cases) pins all four: a device forges
    the values, re-proves every relation, and V6 and V7 pass. The overvote+null case is marked
    `DECISION-DEPENDENT PIN (open S5b question C, option (a))`.
  - Not implemented: the fix changes the Q15 relation as the user stated it. It is new open question C:
    - (a) keep (3) as s + w + L·null in 0..L (implemented);
    - (b) make (3) s + w + L·overvote + L·null in 0..L.
    - Under (b), honest ballots still give at most L (overvote: 0 + L + 0; null vote: 0 + 0 + L), and overvote 1
      with null 1 gives 2L. The cost is one multiply per contest, since `RelationCiphertexts` already holds the
      overvote indicator's L-th power, plus one `Combine` term in the encryptor.
    - `NullVoteProof` is already a non-spec, non-interoperable format, so (b) has no interop cost. It does change
      that proof's bytes.
    - Recommendation: (b), which matches p.39 and Q3.
- **R2 (code, minor), right, with one correction.** The tracker's "No committed manifest ... hits either case"
  contradicted the next sentence. It now says that `option-limits`' `l3-r3-no-overvote` contest hits case A.
  - Correction to the finding: no unit test loads `option-limits`; only `perf/scenarios/limits.json` does. So
    under A(b) the blast radius is the egperf `limits` run plus the pinned tests, not "every test that loads that
    manifest".
  - The A pins are now marked `DECISION-DEPENDENT PIN (open S5b question A, option (a))`:
    - the `expected = election.L` branch in `EveryCombinationOfTrackedFields_...`;
    - `GetCounters_OnAnOvervoteWithoutAnOvervoteIndicator_TheUndervoteDifferenceIsL`;
    - `Validate_AnyKindDeclaredOnItsOwn_DoesNotThrow`'s `UndervoteDifferenceCount` row, which the finding missed.
  - The `GetCounters_...` pin is the risky one: neither `CreateMinimalManifest` nor the accumulator calls
    Validate, so under A(b) it would keep passing on a manifest that no election can use. Its marker says so.
  - The JSON fixture cannot carry a comment. perf/README's `limits` paragraph and the inventory say what it
    needs under A(b).
- **R3 (tests, minor), right.** Inserting the S5b entry had overwritten the S5 review round 3 heading. The heading
  is restored and the stray fragment removed. Also fixed two stale git-state lines in the S5b entry ("S5 is still
  staged", "S5's new files are staged"): S5 was committed as 27e75e2 before the S5b gate ran.
- **R4 (tests, minor), right in substance.**
  - `Validate_WriteInFieldsOfferedWithoutAWriteInCount_Throws` is marked
    `DECISION-DEPENDENT PIN (open S5b question B, option (a))`.
  - Judgment call: the W = 0 defaults in the `Build`, `WithFields` and `Encrypt` helpers are not pins. A pin
    breaks under option (b), and these manifests are valid under both options. They are not marked; their
    comments name question B and say they hold under either option. The inventory lists them as "no change
    required".
- The pinned-value inventory gains an "S5b decision-dependent pins" table (A, B, C) saying what each entry
  becomes under option (b).

Gate before re-pinning: no assertion changed (this round only adds tests and comments), so the gate run after the
edits is both the before and the after:
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`. dkg 137 ms; EncryptBallots 0.237 ms/ballot, 169.7 MB; VerifyBallots 0.981 ms/ballot,
  12.4 MB; Tally 9; VerifyTally 4; DecryptTally 34; VerifyDecryption 8 ms; `tallyVerification: ran`,
  `decryptionVerification: ran`. Within S5b's range; no hot path changed.
- Console: `Done.`, then the expected ReadKey exception. tally.json rewritten at 20:44:12: `0-0 (1, 3)`,
  `0-1 (2, 0)`, fields (3..7, 0).
- Tests: Core `Passed: 1284, Total: 1284` (1280 + the 4 new cases); Perf `Passed: 225, Total: 225`.

Carry-overs: as in S5b, plus open question C. New files: none.

### 2026-10-05 — S5b (supplemental fields: user follow-up decisions Q11-Q16; G3, G8, G22, G29, G10)
The user answered the four S5 questions plus two follow-ups (Q11-Q16 under Decisions). S5b applies them.
- Git state: S5 is committed (27e75e2). S5b is unstaged working-tree changes on top; no new files. Nothing was
  staged, committed or stashed. (Corrected in S5b review round 1: this line first said S5 was still staged.)
- The S5 questions are answered as follows:
  - Question 1 (write-ins on an overvote): zeroed (Q12).
  - Question 2 (write-in-only null vote): not a null vote (Q13).
  - Question 3 (the `Validate` narrowing): the flag is removed (Q14).
  - Question 4 (undervote indicator on an overvote): 0 (Q11).
- Notation: s = sum of selections, w = write-in count, L = selection limit, u = undervote difference count.

Code changes per G-ID:
- **G10 / G22 model (Q13, Q14).**
  - `SupplementalField.CountsTowardSelectionLimit`, `Contest.SelectionLimitWeight` and `Validate`'s flag rules
    are deleted.
  - New `Validate` rule: a contest that offers write-in fields (`WriteInFieldCount > 0`) must declare the
    write-in count. Q13 says write-ins always count toward the limit, and only the count's ciphertext can carry
    them into a proof. See open question B.
  - The S5 implementer note under Q1 is marked superseded.
- **G10 / G22 values (`BallotEncryptor.SupplementalValue`/`EncryptContest`).**
  - A contest is overvoted when s + w > L or an option > R.
  - On an overvote: options 0, w 0, overvote 1, null 0, undervote indicator 0, and u = 0 when the overvote
    indicator is declared (L when it is not; see open question A).
  - Otherwise: null = (s + w = 0), undervote indicator = (s + w < L), u = L - s - w.
- **Q15 relations (encryptor and `AdherenceToVoteLimitsVerification`).** Each relation is over the ciphertext of
  s + w (the options and the write-in count) and the terms of the declared fields only:
  - (1) The selection-limit proof, eq. (62) format, 0..L, over s + w + L*overvote + undervote indicator.
  - (2) `UndervoteDifferenceProof`: one-value proof that s + w + L*overvote + u = L. Same challenge format as S5,
    with the documented ciphertext updated.
  - (3) New `NullVoteProof`: range proof over 0..L of s + w + L*null, present exactly when the null-vote indicator
    is declared. Challenge: H_q(H_I; 0x24, ind_c, ind_o(null), b(L,4), A, B, a_0, b_0, ..., a_L, b_L).
  - The b(L,4) field makes the null proof's input 13 + 1024(L+2) bytes after H_I. Every other 0x24 input in the
    contest is 5 or 9 mod 1024. Without it, at L = 1 the null proof would share its prefix and length with the
    indicator's own 0..1 proof.
  - (3) is documented as not spec-defined, like (2).
  - Verification 7 checks (1), (2) and (3) in that order. Each proof's Z_q checks are 7.B/C and its challenge
    check is 7.D, with a message naming the proof.
  - A missing, unexpected or wrong-length null-vote proof, or one with a null entry, is `"7"`.
  - 7.A covers every field, as before. V6 is unchanged.
- **Serialization (G22).** `EncryptedContest.NullVoteProof` is in the domain type, in JSON (`nullVoteProof`,
  omitted when null) and in protobuf (member 12; an absent or empty list decodes as null), mirroring
  `UndervoteDifferenceProof`.
- **Montgomery fix (S5 review note).** V7 used to leave and re-enter Montgomery form several times per contest:
  `Aggregate` out, then two `ModPProduct`s back in and out. The new `RangeProofChallenge.RelationCiphertexts`
  computes all three relation ciphertexts in the active engine's representation:
  - each input is converted in once, and the overvote indicator's L-th power is shared by (1) and (2);
  - each output is converted out once;
  - L's power is a short window over L's own bytes (public, small);
  - with no field declared it falls back to `Aggregate`.
  - The encryptor's `Combine` uses `ModPProduct.Multiply`/`MultiplyPower` as before.
- **G29 test infrastructure.**
  - `ExpectedTallyAccumulator` is re-derived from the Q11-Q16 text, which its doc comment quotes, and not from
    the encryptor. `ContestCounters` docs are updated.
  - `ElectionFixtureBuilder.SupplementalFields`/`CreateMinimalManifest` lose `writeInsCountTowardLimit`.
  - Testing.Cli and the `BallotGenerator` comment are updated.
- **Fixtures.**
  - The `countsTowardSelectionLimit` key is stripped from `test/data/{single-contest,famous-names,
    famous-names-large,option-limits}/manifest.json`.
  - `option-limits`' third contest was the S5 "write-ins not counted" contest, which is now identical to the
    second. It is replaced by `l3-r3-no-overvote` (L = R = 3; null, undervote, difference and write-ins; no
    overvote indicator). The `limits` scenario now covers the relations without the overvote term.
  - `C:\temp\eg\data\1\manifest.json` (the console input) lost the key. The previous file is kept as
    `manifest.json.pre-s5b.bak`.
- **Docs.** CLAUDE.md (BallotEncryption supplemental-fields text, the overvote bullet, the Verify and
  Serialization paragraphs, the `Validate` rule list) and perf/README (S5b paragraph, `limits` description).
  The pinned-value inventory is updated above.

Gate before re-pinning (code, fixtures and compile migrations only; no assertion changed):
- Compile migrations: removed the `writeInsCountTowardLimit:` arguments in ManifestValidationTests,
  SupplementalFieldTallyTests, SupplementalFieldVerificationTests, ExpectedTallyTests and ScenarioRunnerTests, and
  `CountsTowardSelectionLimit = counts` in ManifestValidationTests.
- Build: `0 Error(s)`, `1 Warning(s)`. The warning was xUnit1026 on ScenarioRunnerTests' now-unused
  `writeInsCount` theory parameter.
- Smoke: `correctness passed`. dkg 138 ms; EncryptBallots 0.237 ms/ballot, 169.6 MB; VerifyBallots
  1.022 ms/ballot, 12.4 MB; Tally 9; VerifyTally 4; DecryptTally 34; VerifyDecryption 8 ms;
  `tallyVerification: ran`, `decryptionVerification: ran`.
- Console: `Done.`, then the expected ReadKey exception. tally.json `0-0 (1, 3), 0-1 (2, 0)`, fields
  (3..7, 0).
- Tests: Core `Failed: 37, Passed: 1191, Total: 1228`; Perf `Failed: 12, Passed: 213, Total: 225`.

The failures, and what each was:
- **ManifestValidationTests.** `Validate_CountsTowardSelectionLimit_OnlyWhereEveryHonestBallotHasAProof`, all 6
  failing rows. The flag no longer exists.
- **Fixture inputs: new `Validate` rule (W > 0 with no write-in count field).** The test builders defaulted to
  W = 2 while declaring no write-in count:
  - SupplementalFieldSerializationTests `RoundTrip_ContestWithoutAnUndervoteDifferenceCount_HasNoProof` ×2 and
    `RoundTrip_ContestWithoutSupplementalFields_DecodesAnEmptyList` ×2;
  - SupplementalFieldVerificationTests `BallotWithoutExactlyTheDeclaredFields_IsRejectedAsStructure` ×12 and
    `Verification7_UndervoteDifferenceProofWithoutTheField_Fails`.
- **Pins on the S5 rules** (rows where write-ins did not count, or the undervote indicator / u was L on an
  overvote):
  - SupplementalFieldVerificationTests `Encrypt_DerivesEveryFieldFromTheSelections_AndTheBallotVerifies` ×9;
  - `BallotEncryptorTests.Encrypt_OvervoteCounter_ProofIsWellFormed`;
  - `SupplementalFieldTallyTests.Decrypt_EverySupplementalFieldTotal_...` (expected `[3, 1, 5, 9, 2]`, got
    `[3, 1, 2, 3, 2]`);
  - Perf ExpectedTallyTests `Add_OvervoteRule_IsSumAboveLOrAnOptionAboveR` ×4,
    `Add_WriteInsCountTowardTheLimitOnlyWhereTheManifestSaysSo` ×3,
    `Add_OnAnOvervote_ZeroesWriteInsThatDoNotCountTowardTheLimit`, `GetCounters_CountsAnOvervote`,
    `GetCounters_CountsWriteInsFromTheBallotContestRegardlessOfSelections` and
    `GetCounters_OnAnOvervote_ComputesTheUndervoteFieldsOnTheZeroedSelections`;
  - `TallyComparerTests.Compare_ChecksEveryDeclaredSupplementalField`.
- **Format pins, recomputed with the S5 ciphertexts:**
  - `LimitProof_IsEq62OverTheSelectionsTheCountedWriteInsAndTheOvervoteIndicatorToTheL`;
  - `UndervoteDifferenceProof_IsTheDocumentedOneValueProof`;
  - `Verification7_UndervoteDifferenceProofRecomputedByTheDevice_Passes`, whose helper omitted ov^L.

Re-pinned, and why (nothing weakened or skipped):
- **Deleted:**
  - `Validate_CountsTowardSelectionLimit_...`: the flag no longer exists (Q14). It is replaced by
    `Validate_AnyKindDeclaredOnItsOwn_DoesNotThrow` (×5), `Validate_WriteInFieldsOfferedWithoutAWriteInCount_Throws`
    (×2) and `Validate_ALeftoverCountsTowardSelectionLimitKey_IsNotAField`.
  - The `(3, 3, false)` row of ScenarioRunnerTests' R > 1 theory, and the theory's `writeInsCount` parameter. That
    row now duplicates `(3, 3)`.
  - `Add_OnAnOvervote_ZeroesWriteInsThatDoNotCountTowardTheLimit`: uncounted write-ins no longer exist. Its case is
    row (1, 1, 1) of the new `Add_WriteInsAlwaysCountTowardTheLimit`.
- **Fixture inputs:** the builders in ManifestValidationTests, SupplementalFieldVerificationTests and
  SupplementalFieldSerializationTests now default to W = 0 unless the write-in count is declared. Assertions are
  unchanged.
- **Rule pins, moved to Q11-Q15 values** (each test's comment cites the decision):
  - `HonestCases` rewritten: 14 rows, all fields declared. They include a write-in-only ballot (not null), a
    partial undervote with a write-in, write-ins pushing over L, and write-ins filling L.
  - `Encrypt_OvervoteCounter_ProofIsWellFormed`: undervote indicator 0, difference 0.
  - The tally total: `[3, 1, 2, 3, 2]`.
  - ExpectedTallyTests: the overvote theory expects undervote 0 and difference 0 on an overvote.
    `GetCounters_CountsAnOvervote` expects 0/0. `GetCounters_OnAnOvervote_...` is renamed
    `..._TheUndervoteFieldsAreZero`.
  - `GetCounters_CountsWriteInsFromTheBallotContest...` now uses L = 2. With L = 1, a selection plus a write-in is
    now an overvote.
  - The write-ins theory is replaced by `Add_WriteInsAlwaysCountTowardTheLimit` (5 rows).
  - `Compare_ChecksEveryDeclaredSupplementalField`: undervotes 1, difference 1.
- **Format pins** now recompute the Q15 ciphertexts: `LimitProof_IsEq62OverTheSelectionsWriteInsOvervoteToTheLAndUndervoteIndicator`
  (renamed) and `UndervoteDifferenceProof_IsTheDocumentedOneValueProof`. The S5 `RelationProof` helper is replaced
  by `DeviceProof`, a generic prover for the documented formats.

New tests (Core 1228 → 1280, Perf 225 → 225):
- `EveryCombinationOfTrackedFields_HonestBallotsOfEveryKind_Verify`, 32 masks (every subset of the five kinds),
  with L = 3, R = 2, W = 2. Each mask runs 8 ballot kinds: normal, partial undervote, null, write-in only,
  write-ins filling L, overvote by sum, overvote by an option above R, and write-ins pushing over L. Write-in
  ballots are skipped where the count is not declared.
  - Each kind checks every declared field's plaintext, the presence of each proof, and V6-V8.
  - This includes null, undervote indicator and difference tracked together (masks with bits 1-3 set), and the
    no-overvote-indicator case (u = L on an overvote).
- `NullVoteProof_IsTheDocumentedRangeProof` and `RelationCiphertexts_MatchTheirDefinitions_OnBothEngines` (×2;
  AVX-512 and scalar).
- `Verification7_EveryRelationReprovedByTheDeviceOnHonestValues_Passes`: the positive control for `DeviceProof`.
- `Verification7_DeviceThatForgesAFieldAndReprovesEveryRelation_Fails7D` (13 cases). In each, Verification 6
  passes and the device re-proves every relation:
  - overvote = 1 beside real selections;
  - null = 1 beside a selection, or beside a write-in;
  - u ignoring a selection, ignoring the write-ins, or L on an overvote;
  - undervote indicator = 1 with s = L, or with s + w = L;
  - a write-in on a full contest;
  - and four "proved without its term" variants. In those the device proves valid statements that leave the
    forged field out, so only a verifier that includes the term rejects them.
- `Verification7_TamperedNullVoteProof_Fails7D`, `Verification7_NullVoteProofOfTheWrongLength_Fails` (×3) and
  `Verification7_NullVoteProofWithoutTheField_Fails`.
- The JSON null-entry theory gains "null-vote proof entry".
- StrictDecodingTests gains the null-vote proof's challenge = q and response = q sites.
- The serialization round trips check `NullVoteProof`.
- `GetCounters_OnAnOvervoteWithoutAnOvervoteIndicator_TheUndervoteDifferenceIsL`.

Mutation checks. Each was applied from a script, built, run, and restored from `C:\temp\s5b` (`cmp` clean):
- **V7 skips relation (3), plus (1) drops the undervote indicator on both encryptor and verifier** (so honest
  ballots still verify): 12 Core tests failed.
  - These included every null forgery, the tampered null proof, and "undervote indicator ... proved without its
    term".
  - Before that variant was added, the term-dropping mutation went unseen. That is why the "without its term"
    cases exist.
- **Encryptor back to S5's undervote indicator (1 on an overvote), plus accumulator u = L on every overvote:**
  - Core: 16 `EveryCombination` masks, 2 HonestCases rows and the tally total failed.
  - Perf: 20 failed (ExpectedTallyTests, the ScenarioRunner end-to-end runs, TallyComparer).
  - An egperf `limits` run against that stale mutant build failed with `VerificationFailedException: Sum of
    challenge values did not equal c.`, and appended an error record to the gitignored
    `perf/results/sethpc2023.jsonl`. Rebuilt clean, `limits` passes.

Gate after:
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke ×3, each `correctness passed`:
  - dkg 132-135 ms;
  - EncryptBallots 0.236 / 0.245 / 0.232 ms/ballot, 169.5-169.7 MB;
  - VerifyBallots 0.988 / 0.972 / 0.984 ms/ballot, 12.3-12.4 MB;
  - Tally 8; VerifyTally 4; DecryptTally 33-36; VerifyDecryption 8-9 ms.
- `limits`: `correctness passed`. EncryptBallots 0.849 ms/ballot, 1,309.9 MB; VerifyBallots 3.389 ms/ballot,
  93.7 MB; DecryptTally 44; VerifyDecryption 13 ms.
- Console: `Done.`, then the expected ReadKey exception. tally.json was rewritten at 20:18:34:
  `0-0 (1, 3), 0-1 (2, 0)`, fields (3..7, 0).
- Tests: Core `Passed: 1280, Total: 1280`; Perf `Passed: 225, Total: 225`.

Perf against S5 (same machine):

| Scenario | Phase | S5 (round 3) | S5b |
|---|---|---|---|
| smoke | EncryptBallots | 0.220 ms/ballot, 152.2 MB | 0.232-0.245, 169.5-169.7 MB |
| smoke | VerifyBallots | 0.918 ms/ballot, 14.9 MB | 0.972-0.988, 12.3-12.4 MB |
| limits | EncryptBallots | 0.771-0.788 ms/ballot, 1,171 MB (rounds 1-2) | 0.849-0.864, 1,310 MB |
| limits | VerifyBallots | 3.12-3.18 ms/ballot, 112.4 MB | 3.389-3.395, 93.5-93.7 MB |

- The workload grew. Each contest that declares the null-vote indicator gains an (L + 1)-pair range proof:
  - Encryption: 2 more pairs per smoke ballot (L = 1), about +7% time and +11% allocation (the proof, plus one
    more combined ciphertext).
  - Verification: smoke's V6 + V7 pairs go from 21 to 23 (+9.5%), which matches the +6-8% in time.
- Allocation fell by 17% in smoke `VerifyBallots` and 17% in `limits` `VerifyBallots` even with the extra proof.
  That is the Montgomery fix: one engine pass replaces `Aggregate` plus two `ModPProduct`s.
- `limits`' third contest changed, so its figures compare the scenario, not identical work.
- No hot path outside the supplemental fields changed.

Decisions taken (low stakes; recorded here):
- **The null-vote proof's challenge carries b(L,4)** for domain separation by length (above). Its proof list is
  L + 1 long, like the limit proof.
- **The verification order inside V7** is: presence and length of each proof (`"7"`), all 7.B/C, then 7.D for
  (1), (2), (3).
- **`option-limits`' third contest** is repurposed as above.
- **`RelationCiphertexts`** lives on `RangeProofChallenge` next to `Aggregate`, and returns a
  `ContestRelationCiphertexts` record struct.

Open questions (asked in the stage report; implemented as described; they move published totals or reject
manifests, never bytes, for any manifest that declares both fields):
- **A.** What should u be on an overvote when the contest declares the undervote difference count but not the
  overvote indicator? Q15's relation has no overvote term then (Q14: an untracked field "isn't included"), so
  s = w = 0 forces u = L. Options:
  - (a) u = L there (implemented; p.38's relation applied literally);
  - (b) `Validate` requires the overvote indicator wherever the difference count is declared, so that u = 0 on
    every overvote, as the decision text states.
- **B.** Write-in fields offered without a declared write-in count. Options:
  - (a) `Validate` rejects the manifest (implemented; Q13 says write-ins always count, and only the count's
    ciphertext can enter the proofs);
  - (b) allow it, and ignore untracked write-ins in every rule (Q14's "doesn't matter at all"). Then a write-in
    could not overvote such a contest.
- Case A is hit by one committed manifest: `option-limits`' `l3-r3-no-overvote` contest declares u without the
  overvote indicator, so the egperf `limits` scenario exercises A(a). No committed manifest or generator hits
  case B. (Corrected in S5b review round 1: this line first said neither case was hit.) Question C was added
  in S5b review round 1. The pins of A, B and C are listed in the pinned-value inventory.

Carry-overs: unchanged from S5. Known-issue note for memory: the S5 open questions are closed.
New files: none. S5's new files were committed with S5 (27e75e2); S5b only modifies tracked files.

### 2026-10-05 — S5 review round 3 (G22, G10: undervote indicator on an overvote, Manifest guard tests)
Two review findings, both right. Neither changes behavior: one is documentation plus a new user question, the other
adds tests. Everything is still unstaged on top of the staged S3+S4; nothing was staged, committed or stashed.
- **R3-1 (spec, minor), right.** S5 said the spec is silent on the undervote fields of an overvoted contest. It is
  not silent; it contradicts itself on the indicator (checked against pp.18, 38, 39):
  - p.18 and p.38 define the indicator by the voter's sum ("strictly less than the contest selection limit").
    On an overvote that sum exceeds L, so read literally the indicator is 0.
  - p.38's disjunctive proof (indicator 0 and sum = L, or indicator 1 and sum in 0..L-1) can only be satisfied
    with 1 on the neutralized selections, whose sum is 0.
  - p.39 names this mechanism for the null indicator ("Providing such a proof forces setting the null vote
    indicator to one for every overvote ballot as well") and overrides it ("should be set to zero"). There is
    no such override for the undervote indicator.
  - The implementation has no disjunctive proof (Q2), so nothing forces 1: the indicator's only check is its
    0..1 range proof, and 0 would verify too. The difference count, by contrast, really is forced to L.
  - Behavior unchanged (indicator 1, difference L). The `SupplementalValue` doc, CLAUDE.md's overvote bullet,
    the S5 "Undervote fields on an overvote" decision line, the `SupplementalField.CountsTowardSelectionLimit`
    doc, `ExpectedTallyAccumulator`'s doc and the test comments now state the contradiction and cite the pages.
  - New open user question 4 (see the stage report), with its pins marked `DECISION-DEPENDENT PIN` and listed
    in the pinned-value inventory.
- **R3-2 (tests, minor), right.** Two `Manifest.Validate` guards had no test: the null `SupplementalFields`
  list and `WriteInFieldCount < 0` with no write-in count field (the existing -1 case declares one, so the
  later check threw instead). New tests:
  - `ManifestValidationTests.Validate_MalformedSupplementalFieldDeclaration_Throws` (2 cases: "no supplemental
    field list", "cannot be negative");
  - `Validate_JsonManifestWithNullSupplementalFields_ThrowsInvalidManifest`: `"supplementalFields":null` in
    JSON decodes to null (asserted), then `Validate` throws `InvalidManifestException`, not
    `NullReferenceException`.
  - Mutation check: with both guards disabled, exactly these 3 cases failed (`ManifestValidationTests` 38/41);
    `Manifest.cs` was restored from `C:\temp\s5r3` (`cmp` clean).
- Gate before re-pinning (after the doc-comment changes; the round changes no code):
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke ×2: `correctness passed`. EncryptBallots 0.233 ms/ballot, 152.1 MB; VerifyBallots 0.919 ms/ballot,
    14.9 MB; Tally 8; VerifyTally 4; DecryptTally 34; VerifyDecryption 8 ms.
  - Console: `Done.`, then the expected ReadKey exception. tally.json `0-0 (1, 3), 0-1 (2, 0)`, fields (3..7, 0).
  - Tests: Core `Passed: 1228, Total: 1228` (the 3 new cases included); Perf `Passed: 225, Total: 225`. No test
    failed, so nothing was re-pinned.
- Gate after (pin markers and comments added):
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed`. dkg 138 ms; EncryptBallots 0.220 ms/ballot, 152.2 MB; VerifyBallots
    0.918 ms/ballot, 14.9 MB; Tally 8; VerifyTally 4; DecryptTally 34; VerifyDecryption 8 ms.
  - Console: `Done.`, then the expected exception. tally.json rewritten at 15:58:34 with the same counts.
  - Tests: Core `Passed: 1228, Total: 1228`; Perf `Passed: 225, Total: 225`.
- Perf: no hot path changed; smoke is within run-to-run noise of round 2.
- Carry-overs unchanged from round 2. `C:\temp\s5r3\` holds the pre-mutation `Manifest.cs` backup and can be
  deleted.

### 2026-10-05 — S5 review round 2 (G22, G10: proof-list nulls, limit bounds, test gaps)
Five review findings, each judged; all five are right. Two need only tests or docs (F1, F5), one only tests
(F4), and two need code (F2, F3). As before, everything is unstaged working-tree changes on top of the staged
S3+S4; nothing was staged, committed or stashed.
- **F1 (spec, minor), right; no code change.** Q1 gives every field a counts-toward-limit flag, but
  `Validate` requires it for the overvote indicator and forbids it for the null-vote indicator, the undervote
  indicator and the undervote difference count. Only the write-in count's flag is a real choice. The reasons
  are sound (see S5 round 1, R1), but the user has not accepted the narrowing.
  - Added an implementer note under Q1, clearly marked; the user's words are unchanged.
  - New open question 3, asked in the stage report: "Do you accept that `Manifest.Validate` narrows Q1's
    per-field counts-toward-limit flag? Options: (a) accept: the overvote indicator must count (L times), the
    null-vote indicator, undervote indicator and undervote difference count must not, and only the write-in
    count's flag is a free choice (implemented, recommended; changes no bytes); (b) also let the null-vote
    indicator count, which means implementing p.39's optional L·null relation and reopening Q2's list of
    relations (changes the limit proof's ciphertext, so bytes)."
- **F2 (code, minor), right.** The JSON decoder keeps `[null]` in a `ChallengeResponsePair[]` (confirmed by the
  new test, which asserts the decoded null before verifying). `"undervoteDifferenceProof": [null]` passed the
  length check, and V7 then threw `NullReferenceException`. The same was true of a null entry in, or a null
  list for, the contest's `proofs` (V7) and a selection's or field's `proof` (V6, on both the fused pre-check
  and the in-order path).
  - Each now fails like a list of the wrong length: `"7"` or `"6"`, reported after 6.A/7.A as before.
  - These are not `N.structure` failures. Only V6 and V7 read proofs; V8 and the tally do not. Moving them
    into `BallotStructure` would also put them ahead of 6.A/7.A.
  - New theory: `SupplementalFieldVerificationTests.JsonBallotWithANullProofListOrEntry_FailsLikeAProofListOfTheWrongLength`
    (7 cases: the undervote difference proof entry, the contest proof entry and list, the selection proof
    entry and list, and the field proof entry and list). It edits real JSON. Selection and field proofs
    serialize as `"proof"`, contest proofs as `"proofs"`.
  - A null `undervoteDifferenceProof` list was already `"7"` (`?? []`, then the count check).
  - Still a carry-over, because the finding does not name it: a null `contests` or `choices` list, or a null
    entry in either, still throws inside `BallotStructure`.
- **F3 (code, minor), right; cited more narrowly.** `Validate` did not bound L or R. With L = 0, the
  distinctness argument in `ComputeUndervoteDifferenceChallenge` fails: both proofs would be single-commitment
  proofs over the same prefix. With L < 0 the encryptor writes unverifiable ballots.
  - `Validate` now rejects R < 1 on the spec's text (§3.1.3 p.17: R is "a positive integer").
  - It also rejects L < 1. This is a decision recorded here, not spec text: p.17-18 defines L only as "the
    maximal total value for the sum of all selections". With L = 0 every selection overvotes, and the proof
    argument above needs L >= 1.
  - The finding's claim that §3.1.3 defines both limits as positive is true only of R.
  - Rejecting a manifest changes no bytes. The doc comment of `ComputeUndervoteDifferenceChallenge` now names
    the precondition.
  - Every committed manifest and generator uses L, R >= 1 (Testing.Cli draws L from {1, 2, 3}, with R = 1).
  - Tests: `ManifestValidationTests.Validate_SelectionLimitBelowOne_Throws` (4 cases) and
    `Validate_SelectionLimitsOfOne_DoNotThrow`.
- **F4 (tests, major), right.** No test failed when V6's batch membership test lost the supplemental fields
  (`Components`). Two tests added; each forges the null-vote indicator as a non-member with a valid proof
  (`NonMemberRangeProof`, now in a helper):
  - `Verification6_FieldNonMemberOnABallotThatFailsAStructuralCheck_Fails6A`: the in-order path. Choice 1 has
    one proof too few, and the expected result is 6.A, not `"6"`.
  - `Verification6_FieldNonMemberAfterAnEarlierSumFailure_Fails6A`: the fused path. Choice 1 fails 6.D, and
    the expected result is 6.A, not 6.D.
  - Each test first checks each fault on its own.
- **F5 (tests, minor), right.** `Validate_CountsTowardSelectionLimit_OnlyWhereEveryHonestBallotHasAProof`
  now has a reason column:
  - "must count toward the selection limit" for the overvote indicator;
  - "not implemented" for the null-vote indicator;
  - "on an overvoted contest it is nonzero" for the two undervote kinds.
- Gate before re-pinning, run after the code changes (F2 guards, F3 bounds, one doc comment) and before any
  test edit:
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed`. EncryptBallots 0.237 / 0.217 ms/ballot, 152.1 MB; VerifyBallots 0.903 /
    0.914 ms/ballot, 14.9-15.0 MB; Tally 8; VerifyTally 4; DecryptTally 33; VerifyDecryption 8 ms.
  - Console: `Done.`, then the expected ReadKey exception. tally.json `0-0 (1, 3), 0-1 (2, 0)`, fields
    (3..7, 0).
  - Tests: Core `Passed: 1211, Total: 1211`; Perf `Passed: 225, Total: 225`. No test failed, so nothing was
    re-pinned.
- Mutation check. Four mutations were applied together, rebuilt and run, then restored from `C:\temp\s5r2`
  (`cmp` clean):
  - the reviewer's `Components` field loop over `Enumerable.Empty`;
  - the V6/V7 null guards reverted;
  - the two refusal reasons swapped;
  - the L/R bounds removed.
  - Result: exactly the 16 new cases failed (2 F4, 7 F2, 3 F5 rows, 4 F3), and 1209 passed. Both R4 tests
    were among the passes, which confirms the F4 tests cover what R4 did not.
- Gate after:
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke ×3 `correctness passed`: dkg 133-137 ms; EncryptBallots 0.215 / 0.232 / 0.209 ms/ballot,
    152.0-152.1 MB; VerifyBallots 0.898 / 0.902 / 0.896 ms/ballot, 15.0 MB; Tally 8; VerifyTally 4;
    DecryptTally 33-37; VerifyDecryption 8 ms.
  - `limits`: `correctness passed`. EncryptBallots 0.788 ms/ballot, 1,170.9 MB; VerifyBallots
    3.182 ms/ballot, 112.4 MB; DecryptTally 44 ms; VerifyDecryption 13 ms.
  - Console: `Done.`, then the expected exception. tally.json was rewritten at 15:38:56 with the same counts.
  - Tests: Core `Passed: 1225, Total: 1225` (+14 cases: 7 F2, 2 F4, 5 F3; F5 changed existing rows); Perf
    `Passed: 225, Total: 225`.
- After the full gate, the L < 1 exception message was reworded so that it cites §3.1.3 only for what L is,
  not for the L >= 1 rule. Then: build `0 Warning(s)`, `0 Error(s)`; `ManifestValidationTests` 38/38; smoke
  `correctness passed` (EncryptBallots 0.219, VerifyBallots 0.906 ms/ballot).
- Perf: no hot path changed. V6 and V7 gained one null test per proof entry on their existing loops. The
  figures are within run-to-run noise of round 1 (EncryptBallots 0.220-0.222, VerifyBallots 0.903-0.912).
- CLAUDE.md: `Validate`'s rule list now includes R >= 1 and L >= 1, and the V6/V7 paragraph now covers null
  proof lists.
- No egperf mutation runs this round, so `perf/results/sethpc2023.jsonl` gained only clean smoke and `limits`
  records. Nothing outside the worktree was edited except the console's `C:\temp\eg\data` output and the
  mutation backups in `C:\temp\s5r2`.

### 2026-10-05 — S5 review round 1 (G22, G29, G10 test and doc gaps)
Seven review findings, each judged; all applied, finding 1 in corrected form. Still unstaged working-tree changes
on top of the staged S3+S4; nothing staged, committed or stashed.
- **R1 (spec, minor), partly right.** The `Validate` message and the `CountsTowardSelectionLimit` doc gave one
  reason for refusing the flag on the null, undervote and difference fields: nonzero on an overvote while L·ov
  takes the limit. That holds for the undervote indicator (1) and the difference count (L), which are computed
  on the zeroed sum, but not for the null indicator, which is 0 on an overvote (Q3). The null indicator is
  refused because p.39's optional L·null relation ("can be enforced just as the validity of the encrypted
  overvote indicator") is not implemented: Q2 lists only (a)-(c). The message is now per kind, the doc has
  separate bullets, `AdherenceToVoteLimitsVerification` and CLAUDE.md note the unimplemented relation, and the
  S5 decision text and the not-implemented list below are corrected. Behavior is unchanged.
- **R2 (code, minor), right.** `BallotStructure` accepted a null `SupplementalFields` when the manifest declares
  none, and V6, V7, V8 and `AddBallot` then threw `NullReferenceException`. Only JSON can produce null
  (`"supplementalFields": null`; protobuf decodes an absent list as `[]`). A null list, or a null entry, is now
  an `"N.structure"` failure whatever the manifest declares. Normalizing to `[]` in the JSON decoder was the
  alternative; rejecting it fits S3's strict decoding, since the list is `required`. New tests:
  `BallotStructureTests` shapes "null supplemental field list" and "null supplemental field entry" (×6, 7, 8,
  9), and `JsonBallotWithANullSupplementalFieldList_IsRejected_AsStructure` (×4). This one decodes real JSON
  edited through `JsonNode` and asserts that the decoded list is null.
- **R3 (tests, major), right.** No test could fail if V9's A/B loop went back to `contest.Choices`. Added
  `SupplementalFieldTallyTests.Verification9_TamperedSupplementalFieldAggregate_Fails`, with four cases:
  null-votes A → 9.A, undervote-difference B → 9.B, write-ins A → 9.A, overvotes B → 9.B. Each checks that the
  message names the field.
- **R4 (tests, major), right.** Verification 6's fused 6.A on fields was not pinned. Added
  `Verification6_FieldNonMemberWithAValidProof_Fails6A`: the null-vote indicator is forged with
  `NonMemberRangeProof` (-alpha, a 0..1 proof). Its challenge sum is checked against the recomputed c, and the
  test expects 6.A. The p-1 test is renamed `Verification6_FieldTamperedOutsideTheSubgroupWithoutReproving_Fails6A`,
  and its comment now says it shows only that 6.A takes precedence.
- **R5 (tests, minor), right.**
  - Added the HonestCases row `{1, 1, false, 1, 1, 2} → [0, 0, 1, 0, 1, 1, 0]` and
    `ExpectedTallyTests.Add_OnAnOvervote_ZeroesWriteInsThatDoNotCountTowardTheLimit`.
  - `BallotGenerator` now uses write-ins (1..W) on half the overvoted contests that offer them. This changes the
    generated corpus for those ballots only (each ballot has its own `Random`), so smoke is a slightly different
    corpus from S5's first gate. Per-phase figures stayed within run-to-run noise.
- **R6 (tests, minor), right.**
  - New committed manifest `test/data/option-limits/manifest.json`. Its four contests are L/R = 1/2, 3/3,
    3/3 with write-ins not counted, and 2/1. Each declares all five fields and offers W = 2. The L = 1/R = 2 and
    3/3 contests have 2 options, so "mark every choice" and "option at R + 1" both land in (L, L·R].
  - New scenario `perf/scenarios/limits.json`: 2,000 ballots, every verification on.
  - perf/README explains why `smoke` cannot discriminate the overvote rules and `limits` can.
- **R7 (tests, minor), right.**
  - Every test that pins open question 1 or 2 is marked `DECISION-DEPENDENT PIN`: two HonestCases rows, two
    ExpectedTallyTests cases (one new `InlineData(false, 0, false)`), and `ExpectedTallyAccumulator`'s comment.
  - They are listed in the pinned-value inventory with their (b) values.
- Gate before re-pinning, after the code changes to R1, R2 and the generator and before any test edit:
  - Build `0 Warning(s)`, `0 Error(s)`.
  - Smoke `correctness passed` (dkg 132 ms; EncryptBallots 0.222 ms/ballot, 152.1 MB; VerifyBallots
    0.904 ms/ballot, 15.0 MB; Tally 7; VerifyTally 4; DecryptTally 33; VerifyDecryption 8 ms;
    `tallyVerification: ran`, `decryptionVerification: ran`).
  - Console `Done.` plus the expected ReadKey exception. tally.json: `0-0 (1, 3), 0-1 (2, 0)`, every field
    (3..7, 0).
  - Tests: Core `Passed: 1193, Total: 1193`; Perf `Passed: 223, Total: 223`. No failing tests, so nothing was
    re-pinned. Every test change in this round is a new test, a new theory row, a rename or a comment.
- Mutation checks. Each was applied, rebuilt and run, then restored from a copy (`cmp` clean):
  - V9 value loop over `contest.Choices`, V6 field loop without the membership check, and the R2 guard
    reverted to `declared.Count == 0 ? null`, applied together: exactly the 13 new tests failed (4 V9, 1 V6,
    8 structure); 1198 passed, the p-1 test among them.
  - Encryptor keeps an uncounted write-in count on an overvote:
    - Core: only the new HonestCases row failed.
    - Perf: only `ScenarioRunnerTests` (3, 3, not counted) failed. It now sees write-ins on overvotes.
    - egperf `limits`: `correctness failed`, `l3-r3-uncounted/l3-r3-uncounted-write-ins: expected 186, got 188`.
  - Encryptor back to the `sum > L·R` threshold: `limits` failed (`VerificationFailedException: Sum of
    challenge values did not equal c.`), while smoke printed `correctness passed`. This confirms R6.
  - Accumulator keeps uncounted write-ins on an overvote: the new ExpectedTallyTests fact and
    `ScenarioRunnerTests` (3, 3, not counted) failed.
- Gate after:
  - Build `0 Warning(s)`, `0 Error(s)`.
  - Smoke ×3 `correctness passed`: EncryptBallots 0.222 / 0.222 / 0.220 ms/ballot, 152.1-152.2 MB;
    VerifyBallots 0.912 / 0.903 / 0.910 ms/ballot, 14.9-15.0 MB; Tally 8; VerifyTally 4; DecryptTally 33-34;
    VerifyDecryption 8 ms. No hot path changed; the structure check gained a null test per contest and per field.
  - `limits` (2 runs): `correctness passed`. EncryptBallots 0.771 / 0.775 ms/ballot, 1,171 MB; VerifyBallots
    3.119 / 3.171 ms/ballot, 112.5 MB; DecryptTally 43-44 ms; VerifyDecryption 13 ms. The mutation runs also
    appended records to the gitignored `perf/results/sethpc2023.jsonl`: two `limits` records marked
    failed/error, which `compare` refuses, and one smoke record from the L·R mutant. That record is behaviorally
    identical to a correct build on smoke's R = 1. The last `limits` run left `latest/` on a clean record.
  - Console: `Done.`, then the expected exception. tally.json was rewritten at 15:14:30 with the same counts.
  - Tests: Core `Passed: 1211, Total: 1211` (+18); Perf `Passed: 225, Total: 225` (+2).
- Nothing outside the worktree was edited; the mutation backups were in `%TEMP%\s5r1`.
- Untracked (`??`) files to add when committing S5 are now six: this round added `perf/scenarios/limits.json` and
  `test/data/option-limits/manifest.json`, joining S5's four new test files.
- Left as is:
  - A null `Choices` list (or a null entry in it, or a null `Proofs` array) on a JSON ballot still throws
    `NullReferenceException` inside `BallotStructure`/V6. This is the same class of bug as R2, but it is S3's
    structure code for options, so it is a carry-over, not changed here.

### 2026-10-05 — S5 (supplemental fields redesign: G3, G8, G22, G29, G10)
S3 and S4 are staged in the index awaiting signed commits; S5 is unstaged working-tree changes on top (new files show
as `??`). Nothing was staged, committed or stashed. User decisions Q1 (per-contest manifest), Q2 (range + spec
relations) and Q3 (null indicator 0 on an overvote) are implemented as written.
- Code changes (uncommitted; the orchestrator commits):
  - **Model (Q1):**
    - `Contest.SupplementalFields` (`SupplementalField : Choice`: label, name, `Index`, `Kind`,
      `CountsTowardSelectionLimit`) and `Contest.WriteInFieldCount`. `SupplementalFieldKind`: `OvervoteIndicator`,
      `NullVoteIndicator`, `UndervoteIndicator`, `UndervoteDifferenceCount`, `WriteInCount` (the kinds §3.1.3
      pp.18-19 and §3.3.9 pp.38-39 describe; serialized by name). The election-wide `Manifest.Include*` flags are
      gone.
    - `Contest.VerifiableFields()` (options, then fields), `VerifiableFieldCount()`, `SupplementalFieldOfKind`,
      `RangeBound` and `SelectionLimitWeight` are the one place the field rules live.
    - `Manifest.Validate`: a field's index is m + its 1-based position (continuing after the options), at most one
      field per kind, kind defined, label unique among options and fields, `WriteInFieldCount` >= 0 and >= 1 where
      the write-in count is declared, and the counts-toward-limit rule below.
    - `EncryptedContest.SupplementalFields` (`EncryptedSupplementalField`, keyed by `FieldId`, manifest order)
      replaces `OvervoteCount`/`NullvoteCount`/`UndervoteCount`/`WriteInVoteCount`. `UndervoteDifferenceProof`
      (`ChallengeResponsePair[]?`) is present exactly when the contest declares an undervote difference count.
    - JSON: `field_id`; the proof is omitted when null. Protobuf: `SupplementalFields` = member 10
      (`ProtobufEncryptedSupplementalField : ProtobufEncryptedValueWithProofs`, `ProtoInclude` 11, `FieldId` 4),
      `UndervoteDifferenceProof` = member 11; members 4-7 (the old counters) are retired, not reused. Strict
      decoding as S3; an absent field list decodes as empty, an absent or empty proof as null.
    - Plaintext `BallotContest.NumWriteinsSelected` is now optional (default 0); the supplemental values are never
      given by the caller.
  - **G3:** `EncryptionNonce` has no j-less form; every field is encrypted under xi_{i,j} with its own option index
    (eq. 33), and its range proof's challenge hashes that index (eq. 59).
  - **G8:** `ContestHash(H_I, l, verifiableFields, contestData)` takes one ordered list; the encryptor and V8 pass
    the options then the declared fields, in manifest order (V8 sorts each list by manifest index when stored out
    of order). Only declared fields are hashed.
  - **G10 (overvote rule):** the "sum" is the selections plus the write-in count where it counts toward the limit.
    The contest is overvoted when sum > L or any option > R (§3.3.5 p.31, §3.1.3 pp.17-18, §3.3.9 p.38). Then every
    option encrypts 0 (the plaintext ballot is still zeroed in place), the write-in count 0, the overvote indicator
    1, the null indicator 0 (Q3), and the undervote indicator and difference are computed on the zeroed sum
    (1 and L). A value above R is no longer refused; a negative one still is.
  - **G22:** undervote difference u = L - sum; undervote indicator = sum < L; null = not overvoted and sum = 0;
    write-in count validated against `WriteInFieldCount` (`InvalidBallotException` outside [0, it]). Range proofs
    (Q2): 0..1 for the indicators, 0..L for u, 0..`WriteInFieldCount` for the write-in count.
  - **Q2 relations:**
    - (a)+(c) The selection-limit proof (`EncryptedContest.Proofs`, eq. (62) format unchanged:
      H_q(H_I; 0x24, ind_c, A, B, a_0, b_0, ..., a_L, b_L)) is over the combined ciphertext
      A = prod alpha_options * prod alpha_(weight-1 fields) * alpha_ov^L (B likewise), proving a value in 0..L.
      Weight-1 fields are those that count toward the limit, i.e. the write-in count when flagged. With no counted
      field the ciphertext is eq. (62)'s plain aggregate. NOT spec-defined in its combined form (§3.3.9: "not
      described in detail"), though it uses eq. (62)'s format.
    - (b) The undervote difference relation: a one-value range proof (Note 3.4, the set {L}) that
      (prod alpha_options * prod alpha_(weight-1 fields) * alpha_u, ... beta ...) encrypts L. Challenge
      c = H_q(H_I; 0x24, ind_c, ind_o(u), A, B, a_L, b_L) with a_L = g^v A^c, b_L = K^(v - L c) B^c; proof (c, v),
      v = u_r - c * (sum of the nonces). NOT spec-defined, so not interoperable; documented in
      `AdherenceToVoteLimitsVerification.ComputeUndervoteDifferenceChallenge` and `BallotEncryptor`. Its input
      (2057 bytes after H_I) never coincides with u's own range proof (same prefix, but at least 2 commitment
      pairs). `RangeProofChallenge.Compute` gained a `firstValue` (w_j = v_j - (firstValue + j) c_j).
    - Not implemented, as Q2 says: the disjunctive indicator-consistency proofs (undervote indicator iff sum < L,
      null iff sum = 0). Documented on `AdherenceToVoteLimitsVerification`.
    - Also not implemented (optional; Q2's relations (a)-(c) leave it out): p.39 "The validity of the encrypted
      null vote indicator can be enforced just as the validity of the encrypted overvote indicator", i.e. adding
      L·null to the limit proof (sum + L·ov + L·null ≤ L, which every honest ballot satisfies: null vote 0+0+L,
      ordinary sum+0+0, overvote 0+L+0). The null indicator is proved only by its 0..1 range proof, and
      `Validate` refuses it as counting toward the limit. Documented on `AdherenceToVoteLimitsVerification` and
      `SupplementalField.CountsTowardSelectionLimit` (added in review round 1).
    - L * ciphertext is raised with `ModPProduct.MultiplyPower` (small public exponent) on both sides, never
      `MontgomeryModP.PowModP`.
  - **Verifications:**
    - V6 covers every field's range proof with its own bound: 6.A (fused chain and batch paths include the fields),
      6.B/C, 6.D; a wrong proof count is `"6"` (as for options).
    - V7: 7.A over every option's and field's alpha and beta (§3.1.3 p.19 "include all verifiable fields"); 7.B/C
      for both proofs before any exponentiation; 7.D for the combined limit proof, then 7.D (message "Undervote
      difference proof ...") for the relation. A missing relation proof where u is declared, or one present
      where it is not, is `"7"`.
    - `BallotStructure` requires exactly the declared fields, each once, by label (`"N.structure"` for 6, 7, 8 and
      `AddBallot`/9).
  - **G29:** `EncryptedTally` has one aggregate per verifiable field (keyed by label) and `AddBallot` multiplies the
    fields in, weighted, like options. V9's key check and comparison, `TallyOption.ForTally` (decryption), V10's
    label/index lookup and V11's 11.B/11.C all walk `Contest.VerifiableFields()`. `DecryptedTally` carries each
    field under its label with `ChoiceIndex` = the field's option index.
  - **G16/G10 bounds:** `EncryptedAggregateChoice.MaximumValue` per field (`EncryptedTally.MaximumOptionValue`):
    option min(R, L); indicator 1; u L; write-in count `WriteInFieldCount`. `MaximumCount` sums W times it. The
    S4-noted L = 1, R = 2 case is resolved: a 2 is now an overvote, so the option bound min(R, L) = 1 holds for every
    valid ballot (`SupplementalFieldTallyTests.Decrypt_LOneROne_TwoIsAnOvervote_AndTheOptionBoundIsOne`).
  - **Pre-encryption (§4):** §4.1's selection vectors have one entry per selectable option plus L null vectors, no
    supplemental slots (eqs. 112-115); the pre-encryptor is unchanged and documents this.
  - **Test infrastructure:** `ExpectedTallyAccumulator` re-derived from the spec text (quoted in its doc comment),
    not from the encryptor; `ContestCounters` gains `UndervoteDifference` (`Undervotes` is now the indicator
    total) and `Get(kind)`; `ExpectedTally.SupplementalFieldIds`; `TallyComparer` compares every declared field's
    total under its label. `BallotGenerator` generates overvotes and undervotes for every contest, write-ins
    (1..`WriteInFieldCount`) only where offered, values up to R, and (half the overvote band, R > 1) an option at
    R + 1. `ElectionFixtureBuilder.CreateMinimalManifest` declares the overvote, null, undervote indicators and
    the difference count by default (plus the write-in count with `includeWriteIns`), with new
    `supplementalFields`, `writeInFieldCount` and `writeInsCountTowardLimit` parameters; `SupplementalFields(...)`
    and `SupplementalFieldId(kind)` build declarations; `SupplementalFieldExtensions` (`Field`, `WithField`,
    `AsFields`) helps tests. `ExpectedTallyDocument` gains `undervoteDifference`.
  - **Fixtures:** `test/data/single-contest` (smoke) declares all five kinds, write-ins counted, one write-in field;
    `test/data/famous-names` the same; `test/data/famous-names-large` (xsmall..large) declares the four kinds the
    old flags produced (overvote, null, difference, write-in; not counted). The Testing.Cli generator declares all
    kinds. `C:\temp\eg\data\1\manifest.json` (console input) declares all five; the original is kept as
    `manifest.json.pre-s5.bak` next to it.
- Gate before re-pinning (code complete; the only test edits before it were compile migrations, listed below):
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed` (now also comparing the five supplemental totals). dkg 132 ms; EncryptBallots
    0.219 ms/ballot, 152.1 MB; VerifyBallots 0.894 ms/ballot, 14.9 MB; Tally 7 ms; VerifyTally 4 ms; DecryptTally
    33 ms; VerifyDecryption 8 ms; `tallyVerification: ran`, `decryptionVerification: ran`.
  - Console: `Done.`, then the expected ReadKey exception. tally.json: contest index 1,
    `0-0: (1, 3), 0-1: (2, 0), overvotes: (3, 0), null-votes: (4, 0), undervotes: (5, 0), undervote-difference: (6, 0),
    write-ins: (7, 0)` (ChoiceIndex, VoteCount).
  - Tests: Core `Failed: 56, Passed: 1043, Total: 1099`; Perf `Failed: 9, Passed: 195, Total: 204`. The failures:
    - BallotEncryptorTests: `Encrypt_OvervoteCounter_ProofIsWellFormed`, `Encrypt_UndervoteCounter_...`,
      `Encrypt_NullvoteCounter_...`, `Encrypt_WriteInCounter_...` (they rebuilt the challenge without an option
      index, G3), `Encrypt_SelectionValueExceedsOptionSelectionLimit_ThrowsException` (G10).
    - ContestHashTests: `FullCtor_SameInputs_ProducesSameHash`, `FullCtor_DifferentSelectionCiphertexts_...`,
      `EqualityOperator_And_GetHashCode_BehaveConsistently`, `FullCtor_WithoutContestData_HandComputed_...` (the
      default manifest no longer declares a write-in count, which they hashed).
    - AdherenceToVoteLimitsVerificationTests: `Verify_TwoNonMemberSelectionsWhoseProductIsAMember_...`,
      `Verify_TwoQuadraticResidueNonMembers...`, `Verify_ValidProofWithAZeroChallengeAndResponse_Passes` (they
      recompute the plain options aggregate; the default manifest's overvote indicator now enters the proof).
    - `BallotPreEncryptorTests.Constructor_ContestNeedingMoreShortCodesThanTheCodeSpace_Throws` (256 options pushed
      the default fields' indices out of place).
    - Placeholder-ballot fixtures (their counters were labelled as the four legacy kinds, which the default
      manifest does not declare): EncryptedTallyTests (14 cases: `AddBallot_*` ×6, `AddBallots_*` ×8 incl.
      `MatchesAddBallotOneAtATime` ×6, `AggregateSetter_RestartsTheProduct`,
      `Constructor_FromManifest_InitializesOneAggregateContestPerManifestContest`), BallotStatusAndWeightTests
      (`Verification9_*` ×5), TallyDecryptionProtocolTests (`MaximumCount_IsWeightTimesTheSmallerOfTheLimits` ×5,
      `MaximumCount_AfterParallelAddBallots_MatchesOneAtATime` ×2, `Commit_DrawsAFreshSecretForEveryOptionAndGuardian`),
      `TallyGuardianTests.Decrypt_ProducesPartialDecryptionForEachContestChoice`, TallyAdminSearchRangeTests
      (`Decrypt_CountsAcrossTheSearchRange_AreRecovered` ×7, `Decrypt_CountAboveTheBound_Throws` ×3,
      `Decrypt_LimitedParallelism_RecoversTheSameCounts` ×2, `Decrypt_ManyChoices_RecoversEveryCount`,
      `Decrypt_ZeroPartialDecryption_ThrowsNamingTheGuardian`).
    - Perf: TallyComparerTests `Compare_PassesWhenEveryCountMatches`, `Compare_FailsAndNamesTheDivergentChoice`,
      `Compare_PassesOnAnAllZeroTally`, `Compare_ReportsAnAbsentContestAsAMismatch` (the comparer now checks the
      default manifest's fields); RunCommandTests `Execute_ReturnsExitCodeOneAndAppendsAnErrorRecordWhenTheRunThrows`
      and `...WhenSetupFails` (their inline manifests carried the removed `include*` keys, which the perf JSON
      options reject as unmapped: exit 2 instead of 1); ExpectedTallyTests `GetCounters_CountsAnOvervote`,
      `GetCounters_CountsANullvoteAndItsFullUndervote`, `GetCounters_UsesTheOriginalSelectionValuesFromBeforeOvervoteZeroing`.
- Compile migrations before the gate (no assertion changed): `contest.OvervoteCount`/`NullvoteCount`/
  `UndervoteCount`/`WriteInVoteCount` became `contest.Field(kind)` (the old undervote counter maps to
  `UndervoteDifferenceCount`), on the domain and protobuf sides (`DtoField`, StrictDecodingTests' `WithField`);
  `ContestHash` calls pass one ordered list (`Choices.Concat(...)`); `Include*` initializers were deleted
  (CanonicalOrderTests, BallotStructureTests); placeholder ballots got `SupplementalFields = counter.AsFields(...)`.
  `EncryptionNonceTests.Constructor_WithoutChoiceIndex_HandComputed_MatchesDirectHashModQCall` was deleted because
  G3 removes the API it called (it cannot compile); `Constructor_AlwaysTakesAnOptionIndex` replaces it, and
  `Constructor_DifferentContestIndex_ProducesDifferentNonce` passes j = 1.
- Re-pinned and why (none weakened, skipped or deleted beyond the nonce test above):
  - Fixture inputs, assertions unchanged: placeholder ballots carry the default manifest's fields
    (`AsFields(DefaultSupplementalFields)`); TallyAdminSearchRangeTests and the AdherenceToVoteLimitsVerificationTests
    fixture declare no fields (`supplementalFields: []`; the former's tamper hook indexes counts by option index, the
    latter tests eq. (62)'s plain aggregate; the declared-field case is `SupplementalFieldVerificationTests`);
    BallotPreEncryptorTests' 256-option contest declares none (§4.1 has no fields); TallyComparerTests' expected
    tally declares none (fields covered by the new `Compare_ChecksEveryDeclaredSupplementalField`); RunCommandTests'
    inline manifests drop `include*`.
  - Count pins (G29: fields are aggregated and decrypted): `Constructor_FromManifest_...`,
    `Decrypt_ProducesPartialDecryptionForEachContestChoice` now expect 2 + 4 aggregates and assert the field
    labels; `Commit_DrawsAFreshSecret...` expects 3 × 6 commitments.
  - BallotEncryptorTests counter tests: the challenge hashes the field's own option index (G3); bounds are the
    field's (write-in count 0..`WriteInFieldCount`, G22); on the overvote the null indicator is 0, the undervote
    indicator 1 and the difference L (it was L minus the pre-zeroing count of nonzero options, clamped: 0). The
    obsolete "Math.Max clamp" mutation comment went with it. `Encrypt_SelectionValueExceedsOptionSelectionLimit_ThrowsException`
    is now `..._IsNeutralizedAsAnOvervote` (G10: no throw; options 0, overvote 1, null 0).
  - ContestHashTests hash the declared fields in manifest order (G8) rather than four fixed counters.
  - ExpectedTallyTests: `Undervotes` is the indicator total, `UndervoteDifference` the sum; the overvote test
    expects 1/1 (zeroed sum) instead of 0; `GetCounters_UsesTheOriginalSelectionValuesFromBeforeOvervoteZeroing` is
    now `GetCounters_OnAnOvervote_ComputesTheUndervoteFieldsOnTheZeroedSelections` (it pinned the old opposite
    rule).
- New tests (Core 1099 → 1193, Perf 204 → 223):
  - KAT: `ContestHash_Eq70` (3 vectors; family removed from `UnsupportedFamilies`), and
    `Encryption_ReproducesTheContestHashAndConfirmationCodeVectors` (the library encrypts the oracle's main-chain
    ballot and reproduces chi_1, chi_2 and the confirmation-code vector; a declared overvote field changes chi_2,
    leaves the options' ciphertexts alone, and its alpha is g^xi_{2,4}).
  - `Verify/Ballot/SupplementalFieldVerificationTests` (50): the value matrix (15 cases over L/R/write-ins incl.
    the G10 cases L=1,R=2 value 2; L=3,R=3 (2,2); L=3,R=1 value 2) with V6-V8 passing; option above R not
    refused, negatives refused; write-ins outside [0, W] and in a contest offering none refused; only declared
    fields in manifest order; per-field nonces (G3); the limit-proof and relation-proof formats by recomputation;
    V6 6.D/6.A/"6" and range violations (indicator = 2, write-ins above W); V7 7.D for a forged overvote indicator,
    a counted write-in on a full contest, a forged u re-proved by the device (with its positive control), a
    tampered relation proof, `"7"` for a missing or unexpected relation proof, 7.A for a field; 8.A for a field;
    fields out of order still verify; `"N.structure"` (6, 7, 8, 9) for a missing, duplicated or undeclared field.
  - `Tally/SupplementalFieldTallyTests` (6): all fields decrypted through the verifiable protocol and equal to
    `ExpectedTallyAccumulator`'s totals (hand-checked 3/1/5/9/2), V9-V11 pass; the L=1,R=2 bound; per-field
    `MaximumCount` (3 shapes); V9 `"9.structure"`, V10 `"10.structure"`, V11 11.C and 11.B for fields.
  - `Serialization/SupplementalFieldSerializationTests` (6): JSON and protobuf round trips of the field list and
    relation proof, decoded ballots pass V6-V8, no proof stays null (JSON omits it), an empty list decodes empty.
    StrictDecodingTests gains 7 protobuf sites (relation proof challenge/response = q, a field alpha padded, the
    undervote indicator's four components).
  - ManifestValidationTests (+21 cases), EncryptionNonceTests (+1).
  - Perf: ExpectedTallyTests (G10 theory ×8, write-ins counted or not ×3, field ids), TallyComparerTests (+1),
    BallotGeneratorTests (+2: values up to R and R + 1; write-ins only where offered), ScenarioRunnerTests
    `Run_WithEverySupplementalFieldAndOptionLimitsAboveOne_ProducesTheExpectedTally` ((L, R) = (1,2), (3,3) ×2, (2,1);
    600 ballots, ballot and tally verification on).
- Mutation checks (each applied, rebuilt, run, and restored from a copy, `cmp` clean):
  - M1, V7 ignores the L·overvote term: 23 tests fail (every honest V7 with an overvote field, the round trips).
  - M2, encryptor back to the L·R threshold: Core 6 fail (the G10 matrix cases, the limit-proof format, both
    tally tests); Perf, at 120 ballots only (1,2) failed, so the ScenarioRunner theory uses 600 ballots, where
    (1,2), (3,3) and (3,3, not counted) fail ((2,1) cannot: with R = 1 the rules coincide).
  - M3, accumulator back to L·R: Perf 7 fail (the G10 theory ×4, the three R > 1 runs), Core 1 (the decrypted
    totals test).
  - M4 + M5, V6 skips the fields and V7 skips the relation: exactly 7 fail (the five V6 field tests, the two
    relation 7.D tests); 1186 others pass.
- Gate after:
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke (3 runs): `correctness passed`. EncryptBallots 0.214 / 0.209 / 0.218 ms/ballot, 152.1-152.2 MB;
    VerifyBallots 0.898 / 0.905 / 0.902 ms/ballot, 14.9-15.0 MB; Tally 8-9 ms; VerifyTally 4 ms; DecryptTally
    32-33 ms; VerifyDecryption 8 ms.
  - Console: `Done.`, then the expected ReadKey exception. tally.json rewritten at 14:36:17 with the counts above.
  - Tests: Core `Passed: 1193, Total: 1193`; Perf `Passed: 223, Total: 223`.
- Perf (same machine; S4 from its log):

  | Scenario | Phase | S4 | S5 |
  |---|---|---|---|
  | smoke | EncryptBallots | 0.201 ms/ballot, 135.7 MB | 0.209-0.219, 152.1 MB |
  | smoke | VerifyBallots | 0.458 ms/ballot, 6.3 MB | 0.894-0.905, 14.9 MB |
  | smoke | DecryptTally / VerifyDecryption | 33 / 6 ms | 32-33 / 8 ms |
  | smoke corpus, no fields declared | EncryptBallots / VerifyBallots | (S4 always encrypted 4 counters) | 0.108-0.112 / 0.460-0.465 |
  | xsmall (1 run) | EncryptBallots / VerifyBallots | 3.46 / 7.16 ms/ballot | 3.60 / 15.91 |
  | xsmall | DecryptTally / VerifyDecryption | 92 / 30 ms | 186 / 66 ms |

  - The workload grew, not the per-proof cost: smoke's contest went from 4 verified range proofs (the 4 counters
    were encrypted and proved but never verified) to 9 plus the relation proof, and 7.A tests 18 components instead
    of 8. On the same corpus with no fields declared, VerifyBallots is 0.460-0.465 ms/ballot, S4's figure.
  - EncryptBallots: +1 field (5 instead of 4 counters), the relation proof and the combined-ciphertext products;
    about +5% time, +12% allocation.
  - xsmall: 75 options plus 96 fields (24 contests × 4) and 24 relation proofs; decryption covers 171 aggregates
    instead of 75.
- Decisions taken (low stakes; recorded here):
  - **Counts-toward-limit rule:** `Validate` requires the flag on the overvote indicator (Q2 (a) adds L·ov to the
    limit proof unconditionally), allows it on the write-in count, and rejects it on the undervote indicator, the
    difference count and the null indicator. The undervote indicator and difference count are nonzero (1 and L)
    on an overvoted contest while L·ov already takes the whole limit, so an honest overvoted ballot would have no
    limit proof. The null indicator is 0 on an overvote (Q3), so that reason does not apply to it (corrected in
    review round 1): it is refused because p.39's optional L·null term is not implemented (see below).
  - **"Sum"** is the selections plus the write-in count where it counts; overvote, null, undervote and the relation
    all use it.
  - **Undervote fields on an overvote** are computed on the zeroed sum (indicator 1, difference L), as the task
    directed. *Corrected in review round 3:* the spec is not silent here, it contradicts itself. The difference L
    is forced (the relation L − u = sum needs it, and a negative difference cannot be represented). The indicator
    is not: p.18/p.38 define it by the voter's sum (giving 0), while p.38's disjunctive proof can only be satisfied
    with 1 on the neutralized selections. We follow the proof, as p.39 shows for the null indicator before
    overriding it; this is open user question 4 (see the round 3 log entry).
  - **Data model:** a separate `SupplementalFields` list on the manifest contest (`SupplementalField : Choice`)
    and on `EncryptedContest`, not fields mixed into `Choices`, so code that means selectable options
    (pre-encryption, the plaintext ballot) keeps reading `Choices`.
  - **`WriteInFieldCount`** lives on `Contest` (per contest, as the task says), default 0.
  - **Relation proof as a one-value range proof at value L** (Note 3.4), via `RangeProofChallenge`'s new
    `firstValue`, rather than dividing B by K^L (no inverse per contest).
  - **Protobuf:** the field DTO derives from `ProtobufEncryptedValueWithProofs` (`ProtoInclude` 11), as the
    selection DTO does (10).
  - **Sub-sections:** relation-proof failures use the spec's letters for the corresponding checks (7.B/C, 7.D)
    with distinguishing messages; count/presence problems use `"6"`/`"7"` like the existing proof-count checks.
- Questions for the user (implemented as recommended, changes published tallies only, no bytes):
  - Write-ins on an overvoted contest whose write-in count does not count toward the limit: zeroed (implemented;
    p.31 "the votes in the contest become invalid"), or kept? A counted one must be zeroed (else no limit proof).
  - A null vote with uncounted write-ins: the null indicator is 1 when no counted selection was made, even if the
    voter used an uncounted write-in (implemented), or should any write-in clear it?
- Known-issue notes for the orchestrator's memory update: V9-1 (G29, supplemental counters never aggregated) is
  fixed.
- Carry-overs:
  - S9: a recorded pre-encrypted ballot (§4.3) for a contest that declares supplemental fields will lack them and
    fail `BallotStructure`; S9 must decide (derive them at recording, or forbid fields in pre-encrypted elections).
  - S10: a tally loaded from a record must restore each field's `MaximumValue`/`MaximumCount` (S4 R1 extends to
    fields); `DecryptedTally` serializer.
  - S6: contest data is unchanged here (G11/G32); write-in text still goes there.
  - The S3 carry-over about protobuf documents missing nested messages: a missing field list now decodes as empty
    and fails `BallotStructure` where fields are declared; a missing `OvervoteCount` message no longer exists.
- Nothing outside the worktree was edited except the console input `C:\temp\eg\data\1\manifest.json` (original kept
  as `manifest.json.pre-s5.bak`); `tally.json` and `encrypted-json-ballots/` there changed only as console output.
  The no-fields smoke control ran from a temporary scenario and manifest that were deleted afterwards. The S3/S4
  convention of saving each stage's patch under `docs/superpowers/specs/` in the main checkout is outside the
  worktree, so S5's patch is not saved there: capture `git diff` plus the four new (`??`) test files.

### 2026-10-05 — commit signing outage (affects S3 onward), resolved the same day
- Resolved after the user unlocked 1Password. The S3 tree was rebuilt in a temporary index from `6fbc25c` plus the S3
  patch, giving signed commit `7ae4cfc`. S4 was committed from the real index as `c549325`, and the branch ref was
  moved and pushed. S5 is committed normally. The pending patches in `docs/superpowers/specs/` are kept only for
  reference.
- Since S3 finished, 1Password's SSH signer has failed every signing attempt with `failed to fill whole buffer`, including 60
  retries over 30 minutes. Signing is never bypassed. Until it recovers:
  - S3 is staged in the index. Its full patch, relative to `6fbc25c`, is in the main checkout at
    `docs/superpowers/specs/2026-10-05-s3-pending.patch`.
  - S4 is staged on top of S3. Its patch, relative to the S3 state, plus its new files, is in
    `docs/superpowers/specs/2026-10-05-s4-pending/` (`s4-tracked.patch`, `untracked/`).
  - Later stages work on top as unstaged changes and save their patches the same way.
- Once signing works again, build one signed commit per stage:
  - Easy path, while the worktree still holds the work: commit the index, which is S3+S4, as two commits. Unstage
    S4 by resetting to the S3 tree, or build the commits from the patches.
  - Otherwise: start a temporary `GIT_INDEX_FILE` at the parent commit, `git apply --cached` the stage patch, then
    `git commit-tree -S` and `git update-ref`. Repeat for each stage, then push.
- S4 tally-decryption KAT ambiguity: the spec never says what order the participating-guardian set U is encoded in
  for eqs (88) and (90). The code uses ascending guardian index, as the oracle does, and that question has been put
  to the user.

### 2026-10-05 — S4 review response (round 1)
Three minor findings (two code, one tests). All three were correct. F1 is fixed in code and documented, F2 is
recorded for S10 (as suggested), F3 has its test. No pinned value moved, so nothing was re-pinned.
- **F1, `DecryptTally` allocation breaches `compare`'s 2% gate (code): reduced, and documented as deliberate.**
  - `TallyDecryptionHashes.CommitmentHash` (eq. 88) and `Challenge` (eq. 90) now write their 2577 + 4·#U and 2569
    byte inputs into one `ArrayPool` buffer (`IntegerModP.WriteBigEndian`, `BinaryPrimitives.WriteInt32BigEndian`)
    and hash with `EGHash.HashConcatenated`/`HashModQConcatenated`, the `ContestHash`/`RangeProofChallenge`
    pattern. Same bytes: `TallyDecryptionCommitmentHash_Eq88` and `TallyDecryptionProof_Eq86To93_AndVerification10`
    (spec oracle) pass unchanged.
  - Effect: `xsmall` `DecryptTally` 10.2 MB -> 4.2 MB per run (S3: 1.3 MB); `smoke` 0.5 MB -> 0.2 MB (S3: 0.1 MB).
    Wall time is unchanged (xsmall 90 ms, smoke 31 ms).
  - It still cannot meet 2% of a decryption that had no proof. The remaining ~56 KB per option on xsmall was not
    profiled; it is in the proof's exponentiations (`MontgomeryModP.PowModP` outputs and `BigInteger`
    intermediates: Commit's 3 per guardian, M, the administrator's |U| and its proof check). `compare` was run
    against S3 records on this machine:
    - smoke, S4 median of 5 vs S3 `20261005T145238Z-13da7c`: `DecryptTally allocBytesPerBallot 101.112 -> 258.984
      156.14% REGRESSION`, exit 1. Every other phase's allocation is within 2% (the warm in-process repeats lower
      VerifyBallots and Tally).
    - xsmall, `20261005T173819Z-5a1936` vs S3 `20261005T141817Z-49d19e`: `DecryptTally allocBytesPerBallot 1,279.856
      -> 4,361.144 240.75% REGRESSION`, exit 1. Tally +0.61%, VerifyTally +0.61%, Encrypt -0.01%, VerifyBallots
      -0.09%. (Against the other S3 xsmall record, `...141632Z-421da7`, Tally reads +3.85% because that baseline is
      a low outlier at 9.82 MB; the other five S3 xsmall records are 10.14 MB.)
    - Both also warn that `VerifyDecryption` ran only in the candidate.
  - perf/README.md now says this breach is expected at S4 and to rebaseline on a post-S4 record.
- **F2, `MaximumCount` cannot be restored on a tally rebuilt outside Core (code): recorded for S10.** Correct: only
  `AddBallot` and `MergePartials` set it, so a tally rebuilt through the public `A`/`B` setters has 0 and decryption
  fails closed with "not in [0, 0]". No API is added in a review round. The S10 row now lists it: a tally loaded from
  a record must carry `MaximumCount` or recompute it as `AddBallot` does (sum over cast ballots of W·min(R, L)), or
  `TallyAdmin.Combine` needs an overload taking an explicit bound. The `MaximumCount` doc comment says the same.
- **F3, nothing tested that u_i is fresh per option within one Commit (tests): fixed.**
  `TallyDecryptionProtocolTests.Commit_DrawsAFreshSecretForEveryOptionAndGuardian` runs the three rounds for all
  three guardians with no nonce source, and asserts that the 6 a_i, the 6 b_i and the 6 v_i (3 guardians x 2 options)
  are each pairwise distinct, then that `Combine` and V10 accept the proof. The minimal manifest has one contest, so
  cross-contest reuse is covered only through the same per-option draw. Mutation check: one u drawn before the
  `Parallel.For` (nonce seam kept per option) fails only this test; every other Tally and KAT test (231) passed.
  Restored.
- Gate (no pinned value moved, so before and after are the same run):
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed`. dkg 127 ms; EncryptBallots 0.203 ms/ballot 134.7 MB; VerifyBallots 0.461 ms/ballot
    6.2 MB; Tally 6 ms; VerifyTally 3 ms; DecryptTally 31 ms 0.2 MB; VerifyDecryption 7 ms 0.1 MB; notes
    `tallyVerification: ran`, `decryptionVerification: ran`.
  - Console: `Done.`, then the expected ReadKey exception; tally.json contest index 1, 0-0 = 3, 0-1 = 0.
  - Tests: Core `Passed: 1099, Total: 1099` (1098 + 1); Perf `Passed: 204, Total: 204`.

### 2026-10-05 — S4 (tally soundness: G2, G27, G28, G20, G21, G30, G38, G16)
S3 was still staged, awaiting a signed commit, when S4 started. S4's changes are unstaged working-tree changes on
top of it (new files show as `??`); nothing was staged, committed or stashed.
- Code changes (uncommitted; the orchestrator commits):
  - **G2, verifiable decryption (§3.6.5, eqs. 84-93):**
    - The protocol is three explicit rounds on `TallyGuardian`, mediated by `TallyAdmin`. There is no network
      layer: `TallyAdmin.Decrypt(guardians, tally, record, maxDOP)` drives in-process guardians, and
      `TallyAdmin.Combine(tally, record, commitments, reveals, responses, maxDOP)` takes the three rounds'
      messages from anywhere.
      1. `Commit(tally, record, U)`: a fresh u_i per option (`ElectionGuardRandom`), M_i = A^{z_i},
         (a_i, b_i) = (g^{u_i}, A^{u_i}) and d_i (eq. 88), all with the constant-time
         `MontgomeryModP.PowModP`. It sends M_i and d_i (`PartialTallyDecryption`, which gains `CommitmentHash`).
      2. `Reveal(all round-1 messages)` sends (a_i, b_i) (`TallyDecryptionCommitmentReveal`). It refuses until
         exactly U's messages are in, its own echoed unchanged.
      3. `Respond(all round-2 messages)` checks every d_j by eq. (88), over the guardian's own A, B, ind_c, ind_o
         and U. It computes a, b, M and c (eq. 90) itself, never taking c from anyone, and returns
         v_i = u_i - c·w_i·z_i (`TallyDecryptionResponse`). It is single use: u_i is discarded on success or
         failure, and a second call throws.
    - `TallyAdmin.Combine` works in protocol order:
      - It reads rounds 1 and 2, rejects a zero M_j (naming j) and re-checks every d_j.
      - Only then does it read round 3.
      - It forms M = ∏ M_j^{w_j}, a, b, c, v = Σ v_j and T = B·M^-1.
      - It checks g^v·K^c = a and A^v·M^c = b before publishing. On failure, Note 3.7 (eqs. 94, 95) runs per
        guardian, with g^{z_j} rebuilt from the record's commitments, and names the guardian at fault.
      - It then runs the discrete-log search.
    - Every protocol failure throws the new `TallyDecryptionException`, whose `OffendingGuardian` is null when no
      one can be named.
    - Shared pieces, so that guardian, administrator and verifier cannot encode differently:
      - `TallyDecryptionHashes.CommitmentHash` (eq. 88), `.Challenge` (eq. 90) and `.LagrangeCoefficient`
        (eq. 85).
      - `TallyDecryptionMessages`: reading and building messages, and the d_j check and combination.
    - `DecryptedTally` publishes `ContestIndex` (ind_c), and per option `ChoiceIndex` (ind_o), `VoteCount` (t), `T`,
      `Challenge` (c) and `Response` (v). The old unproven `TallyGuardian.Decrypt` and
      `TallyAdmin.Decrypt(partials, tally, keys)` are gone.
    - New `Verify/Tally/TallyDecryptionVerification` (Verification 10):
      - ind_c and ind_o come from the record's manifest, by label. A label not in the manifest, a published index
        that differs, or a missing aggregate is `"10.structure"`.
      - 10.A (v ∈ Z_q) is checked for every option first.
      - Then 10.B (eq. 90 recomputed from (10.1)-(10.3)) and 10.C (T = K^t), reported for the first option in
        manifest order.
      - It is parallel with `maxDegreeOfParallelism`. T is inverted in one variable-time batch, which is safe
        because the values are public.
    - Wired into Program.cs (V10 and V11 after decryption; tally.json is written with the `IntegerModP`/`IntegerModQ`
      converters, so T, c and v are not `{}`). It is also wired into the perf harness: a new `VerifyDecryption`
      phase (`PhaseNames.All`) runs V10 and V11 after a successful decryption when `tallyVerification` is on, and a
      failure there is an `error` run. `DecryptTally` now times the whole protocol.
    - `ElectionFixtureBuilder.DecryptTally` and `.TallyGuardians` give tests, the perf harness and the benchmarks
      one driver. The benchmarks were updated (`TallyBenchmarks.DecryptWithProof`; `PartialDecrypt` now times
      `Commit`).
  - **G27:** new `Verify/Tally/TallyContentsVerification` (Verification 11): 11.A-11.C over the decrypted tally's
    labels against the manifest, and 11.D over the contest labels of every submitted ballot, cast or challenged.
    Overloads take the ballots, or a set of contest ids, which the perf harness collects per chunk instead of
    keeping ballots. Wired into Program.cs and the harness.
  - **G28:** `IEnumerableExtensions.Product(IEnumerable<IntegerModQ>)` is seeded with 1, so w_i = 1 for |U| = 1.
    - The `IntegerModP` overload deliberately stays seedless. An empty product there would be a joint key K = 1,
      and `RangeProofChallengeTests.Aggregate_Empty_ThrowsAsProductDoes` pins the throw.
    - The first gate run caught a version that seeded both overloads, and it was reverted.
  - **G20, G38 (V9):** `BallotAggregationVerifier.Verify` walks the manifest. Every manifest contest and option
    must be in the claimed tally and nothing else may be: a missing or extra key is `"9.structure"`, checked before
    any value. Values are then compared in manifest order as `"9.A"`/`"9.B"`. An extra key used to throw
    `KeyNotFoundException`, and a missing one passed.
  - **G21:** see "Decisions". `EncryptedBallot.Status` (`BallotStatus`: `NotSubmitted` = 0, `Cast` = 1,
    `Challenged` = 2) is recorded once with `RecordStatus`. It is in JSON (as a number) and in protobuf
    (`ProtobufEncryptedBallot.Status`, field 9, not required).
    - `EncryptedTally.AddBallot` skips `Challenged` ballots, so they are not counted in `BallotsCast` either. It
      rejects `NotSubmitted` as `"9.structure"`.
    - V9 reuses `AddBallot`, so it counts only cast ballots. V5-V8 still cover every ballot.
    - Callers record `Cast`: Program.cs before writing each ballot out, and the perf harness after the encrypt
      timing (warmup too). `ElectionFixtureBuilder.CreateEncryptedBallot` takes `status = Cast`, and
      `BenchmarkElection.EncryptBallot` records `Cast`.
  - **G30:** `AddBallot`, and therefore V9, rejects `Weight < 1` as `"9.structure"`.
    - The decoders decode faithfully. A protobuf ballot without a weight reads as 0, and one without a status reads
      as `NotSubmitted`; both are rejected when tallied (tested).
    - Decision: the decoders stay pure decoders, as S3's strict decoding is about canonical value encodings. A
      ballot that decodes but breaks eq. (80) fails Verification 9 with a sub-section.
  - **G16:** each `EncryptedAggregateChoice` tracks `MaximumCount`, the sum over cast ballots of W·min(R, L) for its
    contest (`EncryptedTally.MaximumOptionValue`, the hook where S5's supplemental fields get their own bounds).
    It is summed in `MergePartials`. The discrete-log search runs over [0, the largest `MaximumCount`]; a bound
    above `int.MaxValue` throws `TallyDecryptionException`.
- Gate before re-pinning (code complete; the only test edits before it were compile and fixture migrations:
  `TallyGuardianTests` moved to the round API with every assertion kept, `TallyComparerTests` filled the new
  required members with placeholders, and the ballot-copy sites gained `Status = ballot.Status`, or `Cast` where a
  ballot is built by hand):
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed`. dkg 129 ms; EncryptBallots 0.201 ms/ballot, 135.7 MB; VerifyBallots 0.458 ms/ballot,
    6.3 MB; Tally 6 ms; VerifyTally 3 ms; DecryptTally 33 ms; VerifyDecryption 6 ms. Notes: `tallyVerification: ran`,
    `decryptionVerification: ran`.
  - Console: `Done.`, then the expected ReadKey exception. tally.json now carries indices and the proof; its counts
    are `0-0: 3, 0-1: 0` (ChoiceIndex 1 and 2, ContestIndex 1).
  - Tests: Core `Failed: 27, Passed: 971, Total: 998`; Perf `Failed: 1, Passed: 200, Total: 201`. The failures:
    - `KnownAnswerTests.EveryVectorFamilyIsCheckedOrExplicitlyUnsupported` (the two new families).
    - `RangeProofChallengeTests.Aggregate_Empty_ThrowsAsProductDoes` (allowAvx512 True and False): a code defect
      (the over-broad G28 change). It was fixed in code; the test is unchanged.
    - `BallotStructureTests.ValidBallot_Passes(verification: 9)` and
      `ContestCopiedVerbatim_WithAMatchingConfirmationCode_IsRejectedEverywhere`: the fixture encrypted with
      `BallotEncryptor` directly and never recorded a status.
    - G38 pins of plain `Exception`:
      - `BallotAggregationVerificationTests.Verify_TamperedA_ThrowsPlainException_NotVerificationFailedException`
        and `Verify_TamperedB_...`.
      - `Verify_ManyBallots_ValidTallyPassesAndAMissingBallotIsDetected` (×3).
      - `BallotAggregationVerifierTests` (12 cases, all through `AssertFailsVerification9` or a plain
        `Throws<Exception>`): `AddBallots_ABallotMissingFromAnyChunk_FailsVerification` ×3,
        `BallotAggregationVerification_FromALazySequence_VerifiesInOneCall` ×2,
        `Verify_BeforeAnyBallotIsAdded_FailsAgainstANonEmptyTally`, `Verify_PartWayThrough_LeavesTheVerifierUsable`,
        `AddBallots_FromALazySequenceMissingABallot_FailsVerification` ×3,
        `AddBallot_WeightedBallot_MatchesThatManyUnweightedCopies`, `AddBallots_ABallotAddedTwice_FailsVerification`.
    - Plain-`Exception` pins of tally decryption: `TallyAdminSearchRangeTests.Decrypt_CountAboveBallotsCast_ThrowsPlainException`
      ×3, `Decrypt_ZeroPartialDecryption_ThrowsPlainException`, and
      `TallyAdminTests.Decrypt_NoValidCombinationFound_ThrowsException`.
    - Perf: `HtmlReportTests.Render_IncludesEveryRecordedPhaseAndMetric` (it asserts that every `PhaseNames.All`
      entry renders, and its record had no `VerifyDecryption`).
- Re-pinned and why (none weakened, none skipped or deleted):
  - The G38 pins now assert `VerificationFailedException` with `SubSection` `"9.A"`, or `"9.B"` for the tampered-B
    case. The two tampered tests were renamed `Verify_TamperedA_Throws_SubSection9A` and `..._TamperedB_..._9B`.
    `AssertFailsVerification9` asserts `"9.A"` (every caller changes A of the first option) and keeps the message
    prefix check.
  - `Decrypt_ZeroPartialDecryption_ThrowsPlainException` is now `..._ThrowsNamingTheGuardian`:
    `TallyDecryptionException`, message prefix kept, `OffendingGuardian` = 1. The zero M_1 is planted with the
    tamper seam, hashed consistently into d_1.
  - `Decrypt_CountAboveBallotsCast_ThrowsPlainException` is now `Decrypt_CountAboveTheBound_Throws`:
    `TallyDecryptionException`, message prefix kept, `OffendingGuardian` null.
  - `Decrypt_NoValidCombinationFound_ThrowsException` is now
    `Decrypt_PartialDecryptionAlteredInTransit_IsCaughtByTheOtherGuardiansCommitmentCheck`. Before, the corrupted
    M_1 surfaced only as a failed search. Now guardian 2 rejects d_1 in `Respond` and names guardian 1, and a
    second `Respond` throws. Stronger.
  - `BallotStructureTests`' fixture records `Cast` (fixture input, not an assertion). `HtmlReportTests` adds a
    `VerifyDecryption` phase to its record. The KAT coverage test lists the two families.
- New tests (Core 998 → 1098, Perf 201 → 204):
  - KAT:
    - `TallyDecryptionCommitmentHash_Eq88` (7 vectors). It checks a_i, b_i and M_i through the library, then d_i
      with U as given and with U reversed.
    - `TallyDecryptionProof_Eq86To93_AndVerification10` (3 vectors). The whole protocol runs end to end: guardians
      hold the oracle's z_i, the nonce seam supplies its u_i, and the aggregate is its (A, B). Every w_i, M_i, d_i,
      a_i, b_i, v_i and the published c, v, T, t, ind_c and ind_o must match, and V10 must accept the result.
  - `Tally/TallyDecryptionProtocolTests` (G2, G28, G16):
    - Every quorum, and all three guardians, publish a proof V10 accepts. Indices and T = K^t are published.
    - Repeated runs use fresh commitments. Limited parallelism still verifies.
    - k = 1 with n = 1 and n = 3 (`OverrideScope`). w = 1 for a single participant. Lagrange coefficients
      interpolate at 0.
    - R = L = 2 with one ballot giving 2: count 2, BallotsCast 1. Weight 3 × 2 ballots: count 6.
    - `MaximumCount` = W·min(R, L) for five (L, R) pairs, and is the same after parallel `AddBallots`.
    - The delta-shift attack: the administrator names guardian 1 through Note 3.7. Published without the
      administrator's check, the count really is shifted by δ, and V10 fails 10.B.
    - A reveal altered in transit is named by the receiving guardian and by the administrator.
    - Guardians shown different tallies halt the protocol.
    - Rejected messages: a missing commitment (names the guardian), a commitment from outside U, and the
      guardian's own altered commitment.
    - `Respond` is single use, and rounds called out of order throw.
    - U is validated: below k, without self, above n, and repeated.
    - `Combine` with a missing response, or a wrong response (Note 3.7 names the guardian).
  - `Verify/Tally/TallyDecryptionVerificationTests` (V10):
    - Honest passes.
    - Fails 10.C: a wrong or negative count, or T = 0.
    - Fails 10.B: a count shifted together with T, a tampered c or v, the proof of another option, or another
      aggregate.
    - Failures are reported in manifest order.
    - Fails `"10.structure"`: an option or contest index mismatch, or an unknown option.
    - Limited parallelism gives the same results.
  - `TallyContentsVerificationTests` (V11): honest passes (both overloads); failures 11.A, 11.B, 11.C and 11.D; a
    contest on no submitted ballot may be absent; challenged ballots count for 11.D.
  - `Tally/BallotStatusAndWeightTests` (G21, G30, G20):
    - The encryptor leaves the status unrecorded. `RecordStatus` is final and accepts only cast or challenged.
    - `AddBallot` skips a challenged ballot, and rejects one with no status or with weight 0, -1 or
      `int.MinValue` (`"9.structure"`, nothing added).
    - Decryption counts only cast ballots, in parallel too. V9 leaves challenged ballots out. V9 faults on a
      ballot with no status or with weight 0.
    - JSON and protobuf round-trip status and weight (5 cases each). A protobuf ballot without status or weight
      is rejected when tallied.
    - V9 fails `"9.structure"` on a claimed tally that is missing an option, is empty, or has an extra option or
      contest; the honest pair passes.
  - Perf `ScenarioRunnerTests`: `VerifyDecryption` runs, with 8 ballots and the note `ran`. It is absent without
    decryption, and absent without tally verification.
- Mutation check: the guardians' and administrator's d_j check was disabled (`if (false && ...)` in
  `TallyDecryptionMessages.CheckAndCombine`) and `VerifyBeforePublishing` was defaulted to false. Exactly 5 tests
  failed:
  - `GuardiansShownDifferentTallies_HaltTheProtocol`
  - `RevealAlteredInTransit_IsCaughtByTheOtherGuardians_NamingTheSender`
  - `Decrypt_PartialDecryptionAlteredInTransit_...`
  - `DishonestGuardian_..._IsNamedBeforeAnythingIsPublished`
  - `Combine_WithAWrongResponse_Throws_NamingTheGuardian`

  The other 225 tally and KAT tests passed. Both files were restored from copies (`cmp` clean) and touched before
  rebuilding.
- Gate after:
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed`. dkg 126 ms; EncryptBallots 0.198 ms/ballot, 134.7 MB; VerifyBallots 0.457 ms/ballot,
    6.2 MB; Tally 6 ms; VerifyTally 3 ms; DecryptTally 32 ms; VerifyDecryption 6 ms.
  - Console: `Done.`, then the expected ReadKey exception. tally.json was rewritten at 13:07:39:
    `{"0": {"ContestIndex": 1, "Choices": {"0-0": {"ChoiceIndex": 1, "VoteCount": 3}, "0-1": {"ChoiceIndex": 2, "VoteCount": 0}}}}`.
    T, Challenge and Response are written base64 by the converters.
  - Tests: Core `Passed: 1098, Total: 1098`; Perf `Passed: 204, Total: 204`.
  - After a last one-line change (`Combine` takes distinct round-1 senders, so a guardian that sent two round-1
    messages is a `TallyDecryptionException` naming it rather than an `ArgumentException`; test
    `Combine_WithTwoRound1MessagesFromOneGuardian_Throws_NamingTheGuardian`), the whole gate was run again:
    build 0/0; smoke `correctness passed` (EncryptBallots 0.202 ms/ballot, 134.7 MB; VerifyBallots 0.455 ms/ballot;
    DecryptTally 32 ms; VerifyDecryption 6 ms); console `Done.` with counts `0-0: 3, 0-1: 0`; tests 1098 + 204 pass.
- Perf (same machine; S3's numbers from its log and `perf/results/sethpc2023.jsonl`):

  | Scenario | Phase | S3 | S4 |
  |---|---|---|---|
  | smoke (3 runs) | EncryptBallots | 0.197-0.205 ms/ballot, 134.7 MB | 0.197-0.204, 134.7 MB |
  | smoke | VerifyBallots | 0.454-0.466 ms/ballot, 6.1-6.2 MB | 0.456-0.463, 6.2 MB |
  | smoke | Tally / VerifyTally | 6 / 3 ms | 6 / 3 ms |
  | smoke | DecryptTally | 19-20 ms, 0.5 MB | 30-32 ms, 0.5 MB |
  | smoke | VerifyDecryption | (none) | 6 ms, 0.1 MB |
  | xsmall (24 contests, 75 selections; 1 run) | EncryptBallots / VerifyBallots | 3.44-3.59 / 7.16-7.71 ms/ballot | 3.46 / 7.16 |
  | xsmall | DecryptTally | 49-50 ms, 1.3 MB | 92 ms, 10.2 MB (4.2 MB after the review round pooled the hash inputs) |
  | xsmall | VerifyDecryption | (none) | 30 ms, 2.0 MB |

  - Only decryption changed. The proof costs, per option: per guardian 3 exponentiations in `Commit` and |U| in
    `Respond` (M), plus the administrator's |U| and its 4-exponentiation proof check. The hashes allocate their
    2.5 KB inputs by concatenation (`EGHash.Hash`), which is most of the extra 9 MB on xsmall. (Superseded: the S4
    review round builds them in pooled buffers; xsmall is now 4.2 MB.)
  - This is a one-off cost per election, not per ballot; `DecryptTally`'s ms/ballot column divides it by the
    ballot count. Pooling the hash inputs (`EGHash.HashConcatenated`) is an available optimization, not done.
  - The first smoke run's EncryptBallots 135.7 MB was a cold-run outlier. The next four runs were 134.7 MB, as in
    S3.
- Decisions taken (low stakes; none changes bytes that S3's KATs or any record format already fixed):
  - **G21 status model:** a `BallotStatus Status` on `EncryptedBallot`, recorded once through `RecordStatus` after
    encryption. The init accessor exists for deserializers and copies.
    - It was chosen over a `SubmittedBallot` wrapper. Every consumer (tally, V9, serializers, the harness)
      already takes `EncryptedBallot`, and a wrapper would need a second serializer pair.
    - The encryptor never sets it: the decision follows the confirmation code.
    - `NotSubmitted` = 0, so a ballot that leaves the status out is never read as cast.
    - JSON writes the enum as a number, the same as protobuf. The JSON serializer's options are unchanged.
  - **Tally-structure sub-sections:** a missing or extra tally key is `"9.structure"`, and a V10 label, index or
    aggregate mismatch is `"10.structure"`. This follows S3's `"N.structure"` convention.
  - **T = 0 in V10** fails 10.C (no t has K^t = 0), since (10.1) cannot be computed.
  - **V10 indices:** ind_c and ind_o are taken from the manifest by label, and the published ones must agree. A
    wrong published index cannot slip a proof past.
  - **Note 3.7** is implemented, but runs only after the combined proof fails, to name the guardian. That is what
    the spec says it is for, and it costs nothing on the honest path.
  - **The administrator checks the proof before publishing.** It costs 4 exponentiations per option. The internal
    `VerifyBeforePublishing` seam exists only for tests.
  - **The search bound is the largest per-option maximum**, with one shared table. A count above its own option's
    maximum would still be found if below the largest; the proof (V10) binds T either way.
  - **Seams** follow S3's `EncryptedBallotHookForTesting` precedent: `NonceSourceForTesting`,
    `PartialDecryptionTamperForTesting` and `VerifyBeforePublishing`, all internal.
  - **`VerifyDecryption` budget:** the key is accepted (it is in `PhaseNames.All`) but not enforced. It runs once,
    on a decrypted tally (`perf/README.md`).
- Known-issue notes for the orchestrator's memory update: V9-2 (G20), V9-3 (G21), V9-4 (G30) and V9-5 (G38) are
  fixed. V9-1 (supplemental counters never aggregated, G29) remains for S5.
- Carry-overs:
  - S5: supplemental fields become options with their own `MaximumOptionValue` bounds (hook in `EncryptedTally`),
    and V9, V10 and V11 then cover them unchanged, since they walk the manifest's options.
  - S5 and G10: with L = 1 and R = 2 a value of 2 is an overvote under the spec, but the encryptor's L·R threshold
    lets it through with an invalid contest proof. Such a ballot fails V7, and if tallied anyway its count can
    exceed min(R, L), so decryption fails closed. The R = 2 test therefore uses L = 2.
  - S7: challenged ballots are now marked and left out of the tally. Their §3.6.7 decryption and V13/V14 are S7's.
  - S10: `DecryptedTally` has no record serializer of its own. Program.cs writes it with the `IntegerModP`/`IntegerModQ`
    converters (base64). The d_i, a_i and b_i are protocol messages, not record items (§3.7 publishes T and (c, v)).
  - Optional: pool the eq. (88)/(90) hash inputs if `DecryptTally` matters at scale.
- Known limits, recorded so that review does not rediscover them:
  - `EncryptedTally.AddBallot` returns for a `Challenged` ballot before `BallotStructure.Require`, so the tally path
    never structure-checks a challenged ballot. This is deliberate: it is not aggregated, and V6-V8 still check
    it.
  - The administrator's d_j re-check uses the administrator's own tally. If that differs from what the guardians
    saw, it names a guardian j although the administrator is at fault. This is the same attribution limit as the
    spec's complaint mechanism; the guardians' own checks are what protect them.
  - `ScenarioRunner` records `Cast` before `EncryptedBallotHookForTesting` runs. A future hook that returns a
    freshly built ballot must carry the status itself.
- Nothing outside the worktree was edited by hand. `C:\temp\eg\data\1` changed only as console output
  (`tally.json`, `encrypted-json-ballots/`), so no `.bak` was needed. `test/kat/{README.md,eg_kat.py,vectors.json}`
  are the KAT oracle's earlier unstaged extension (the two new families). S4 did not edit them, and they belong in
  the S4 commit.
- Spec question (implemented as recommended, listed for the user): eq. (88) and the §5.5.4 table encode U as
  b(#U,4) ‖ b(j_1,4) ‖ … ‖ b(j_#U,4) without saying in which order j_1..j_#U go. Ascending order is used, matching
  the KAT oracle. d_i only passes between guardians, so this matters only for interoperability between guardian
  implementations.

### 2026-10-05 — S3 review response (round 1)
Five minor findings (two code, three tests). All five were correct and all are fixed. No production behavior
changes apart from F1, and no pinned value moved.
- **F1, a protobuf ballot without id_B threw `ArgumentNullException` (G23, code): fixed.**
  `SelectionEncryptionIdentifier.FromCanonicalBytes` now takes `ReadOnlySpan<byte>`, like the `IntegerModP` and
  `IntegerModQ` decoders, and copies the bytes. A null array arrives as an empty span and fails the length check
  with `NonCanonicalEncodingException`. Tests: `SelectionEncryptionIdentifier_FromCanonicalBytes_RejectsNull`, and
  the protobuf site "id_B missing", which leaves the field off the wire. That case asserts that protobuf-net reads
  the absent field back as null, not as an empty array, so the old code would have thrown `ArgumentNullException`.
- **F2, no test where only the per-selection ^q test catches a 7.A failure (G36, code): fixed.**
  - The finding's analysis holds. -1 is a non-residue (p = 3 mod 4), so negating alphas is caught by the exact
    Jacobi pass.
  - New `Verify_TwoQuadraticResidueNonMembersWhoseProductIsAMember_Throws_SubSection7A` sets beta_1·x and
    beta_2·x^-1, with x = 2^(2q) mod p, a square of order dividing r'.
  - It asserts that x != 1, that x is not a member, and that both tampered betas pass Euler's criterion but are not
    members. It also asserts that the aggregate equals the honest aggregate and is a member, and that the untouched
    proof's challenge sum checks. V7 must then fail with 7.A.
- **F3, the order of failures was not pinned (tests): fixed.** Three tests in `BallotStructureTests`, which has a
  two-contest fixture:
  - `Verification7_NonMemberInALaterContest_IsReportedBeforeAnEarlierContestsSumFailure`: contest A's contest
    proof fails 7.D and contest B has alpha_i = 2. Expects 7.A. Each fault alone gives 7.D and 7.A.
  - `Verification6_NonMemberInALaterContest_IsReportedBeforeAnEarlierSelectionsSumFailure`: the same for V6 (6.D
    on A's first selection, a non-member in B). Expects 6.A. The ballot is structurally valid, so this takes the
    fused path.
  - `MalformedBallotWithANonMember_IsRejected_AsStructure` (6 and 7): a duplicated option plus a non-member
    alpha. Expects `"N.structure"`. The non-member alone gives `N.A`.
- **F4, the protobuf tests covered 3 of about 22 strict-decode sites (tests): fixed.**
  - `Protobuf_NonCanonicalEncoding_IsRejected` is now table-driven over every mapped site, 28 cases:
    - id_B: 31 bytes, and missing.
    - Padded encodings: one selection alpha, one proof response.
    - Set to p or q: the selection's alpha, beta, proof challenge and response; the contest proof's challenge and
      response; the overvote, nullvote, undervote and write-in alpha, beta, proof challenge and response; the
      ContestData challenge and response.
  - The fixture ballot now carries contest data, because the encryptor only emits `EncryptedData` for a contest
    that has some. Its guardian set is built from its own manifest file.
  - The test asserts that every site exists on the ballot, so no tampering can be a no-op.
  - The JSON test is unchanged: there is one converter per type, applied to every property of that type.
- **F5, 5.A across chunks in the perf harness was untested (G13, tests): fixed.**
  - A `VerifyChunk`-level test could not catch the regression described, a set created per chunk inside `Run`.
  - So `ScenarioRunner` gained an internal test seam, `EncryptedBallotHookForTesting`. It is called per ballot with
    the run-wide index, after the encrypt timing and before verification and tally. It is null outside tests.
  - `Run_FailsVerification5A_WhenALaterChunkRepeatsAnEarlierChunksIdentifier`: 8 ballots in chunks of 4, ballot
    4 replaced by ballot 0. Expects an Error status and a `VerificationFailedException` "Duplicate selection
    encryption identifier" note.
  - `Run_PassesVerification5A_WhenTheHookChangesNothing` is the control. It also checks that the hook sees indices
    0-7.
- Mutation checks (each was applied, the targeted classes were rebuilt and run, and the file was restored from a
  copy, verified with `cmp`):
  - V7's 7.A moved inside the per-contest loop over that contest's components: only the new V7 cross-contest test
    failed. Every other V7 test passed, which confirms the finding.
  - Per-selection Euler criterion plus exact ^q only on the aggregates: the new QR test failed, and so did the V7
    cross-contest test (2 is a QR mod p).
  - Whole-ballot 7.A moved before `BallotStructure.Require`: only `MalformedBallotWithANonMember(7)` failed.
  - V6's fused path without the batch test on a 6.D: the new V6 cross-contest test and the existing
    `Verify_SumMismatchBeforeANonMember` failed.
  - The protobuf overvote beta reverted to `new IntegerModP(bytes)`: only the "overvote beta = p" case failed.
  - The perf harness with a fresh set per ballot: only the new 5.A run test failed.
- Decision taken (low stakes, test-only API): `ScenarioRunner.EncryptedBallotHookForTesting` is an `internal`
  init-only property, reached through the existing `InternalsVisibleTo` for Perf.UnitTests. It is chosen over
  injecting the identifier set, which could not detect a per-chunk set created inside `Run`.
- Carry-over: a protobuf document that leaves out a nested message (`OvervoteCount`, a `Proofs` array,
  `Contests`) still fails with `NullReferenceException`. That is a truncated document, not a non-canonical value
  encoding, so it is outside G23. Record it for S10's deserializer work, or for S5, which redesigns the
  supplemental fields.
- Gate (no pinned value moved, so nothing was re-pinned; the before and after gates are the same run):
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed`, twice.
    - dkg 126 ms.
    - EncryptBallots 0.197 and 0.200 ms/ballot, 134.7 MB.
    - VerifyBallots 0.454 and 0.460 ms/ballot, 6.2 MB.
    - Tally 6 ms, VerifyTally 3 ms, DecryptTally 19 ms.
  - Console: `Done.`, then the expected ReadKey exception. tally.json was rewritten at 10:45:40:
    `{"Contests":{"0":{"Choices":{"0-0":{"VoteCount":3},"0-1":{"VoteCount":0}}}}}`.
  - Tests: Core `Passed: 998, Total: 998` (969 + 29: 23 more protobuf cases, 1 null id_B, 1 V7 QR, 4 ordering);
    Perf `Passed: 201, Total: 201` (199 + 2).
- Perf: no hot path changed. id_B decoding copies 32 bytes per ballot, and the runner does one null check per
  chunk. Smoke VerifyBallots (0.454 and 0.460 ms/ballot, 6.2 MB) matches S3's 0.459-0.466 ms/ballot and 6.1-6.2 MB.

### 2026-10-05 — S3 (ballot verification strictness: G4, G13, G33, G23, G24, G36, V8 review findings, S1 carry-overs)
Resumed from an implementer that died mid-stage (API 529) with uncommitted edits. Those edits were reviewed and kept,
with one change (the `AggressiveOptimization` attributes were measured, then kept with a justifying comment; see
Perf). Its `scratch-s3/` (a HEAD copy used as the perf baseline, a bench script, a `.orig`) is deleted. It had
written no tests and had not touched this tracker.
- Code changes (uncommitted; the orchestrator commits):
  - **G4 + V8 security-review findings** (missing-validation ×2, missing-completeness-check on
    `ConfirmationCodeVerification`): new `Verify/BallotStructure.cs`. `BallotStructure.Require(ballot, manifest, N)`
    requires that the ballot style is in the manifest (and its contest ids resolve, each once); that the ballot lists
    exactly the style's contests, each once; and that each contest lists exactly the manifest's options, each once
    (no missing, extra or duplicated option, and no option of another contest). The per-contest supplemental fields
    are unchanged; S5 redesigns them. It is called first in V6, V7 and V8, and in `EncryptedTally.AddBallot`, which
    V9's `BallotAggregationVerifier` reuses. So a malformed ballot is rejected before any of its ciphertexts are
    multiplied into a tally.
    - The pass path allocates nothing. It uses stack flags up to 256 contests or options, and a hinted linear search
      that costs one comparison per lookup on a canonically ordered ballot.
    - The audit's attack (copy a valid contest verbatim, with the confirmation code hashed over the copies) passed
      V5-V9 and was tallied twice. Now V6, V7, V8 and AddBallot each reject it.
  - **G13:** `SelectionEncryptionIdentifier` implements `IEquatable`, `==`/`!=` and `ToString` by content. The hash is
    over all 32 bytes through `HashCode.AddBytes`, which is per-process seeded, so a crafted record cannot collide
    the 5.A set.
    - New `SelectionEncryptionIdentifierSet`: an incremental 5.A that holds identifiers only. `Verify(...)` takes an
      `IReadOnlyCollection` and uses it.
    - Program.cs runs 5.A once over all submitted ballots before the per-ballot loop; the loop now runs 5.B, which it
      did not before.
    - The perf harness keeps one set across all chunks (32 bytes per ballot) instead of checking within a chunk.
  - **G33:** the `IsInZq` helpers of V6 and V7 are `0 <= x < q`. They used to reject 0. An `IntegerModQ` can hold
    nothing else, so the range half is enforced at decode time (G23).
  - **G23:** new strict decoders, all throwing `NonCanonicalEncodingException` (a `FormatException`):
    - `IntegerModP.FromCanonicalBytes`: exactly 512 bytes, value < p.
    - `IntegerModQ.FromCanonicalBytes`: exactly 32 bytes, value < q.
    - `SelectionEncryptionIdentifier.FromCanonicalBytes`: exactly 32 bytes.
    - The JSON converters (`IntegerModP`, `IntegerModQ`, id_B) and every protobuf mapping of those types use them.
      System.Text.Json lets the exception propagate unwrapped (tested).
    - The reducing byte constructors stay, documented as internal-arithmetic only.
    - The strict paths are public, so the Z_q-range half of 2.B is available to a future record deserializer (none
      exists yet; S10).
  - **G24:** the `PreEncryptedBallot` overload of `BallotStructure.Require` runs first in V16
    (`PreEncryptedConfirmationCodeVerification`). It requires:
    - the ballot style exists, and the ballot lists exactly its contests, each once;
    - each contest's `ContestIndex` equals the manifest's;
    - `Selections.Count == m + L`, and every vector has exactly m entries;
    - each option has exactly one vector, and there are exactly L null vectors (eqs. 113-115, 16.A-16.C p.65).
  - **G36 (Q8 "per-selection as written"):** V7 now runs `SubgroupMembership.IndexOfFirstNonMember` over every
    selection's alpha_i and beta_i, after the structure check and before any other 7.x check.
    - V7's fused chain path and its structural pre-pass are removed. Its chains are the aggregates', so they cannot
      decide per-selection membership. The aggregates need no separate test: Z_p^r is closed under multiplication.
    - V6 keeps its fused exact path.
  - **S1 carry-over:** `BallotEncryptor.Validate` throws the new `InvalidBallotException : ArgumentException` (in
    `Ballot.cs`) instead of a bare `Exception`.
- Gate before re-pinning (code complete, no test expectation touched):
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke: `correctness passed`. dkg 135 ms; EncryptBallots 0.201 ms/ballot, 134.7 MB; VerifyBallots 0.487 ms/ballot,
    6.2 MB; Tally 6 ms; VerifyTally 3 ms; DecryptTally 20 ms.
  - Console: `Done.`, then the expected ReadKey exception. tally.json
    `{"Contests":{"0":{"Choices":{"0-0":{"VoteCount":3},"0-1":{"VoteCount":0}}}}}`.
  - Tests: Core `Failed: 11, Passed: 855, Total: 866`; Perf `Passed: 199`. Every KAT passed. The failures:
    - `SelectionEncryptionsWellFormedVerificationTests.Verify_ProofChallengeOutOfRange_Throws_SubSection6BC`, `..._ProofResponseOutOfRange_Throws_SubSection6BC`
    - `AdherenceToVoteLimitsVerificationTests.Verify_ProofChallengeOutOfRange_Throws_SubSection7BC`, `..._ProofResponseOutOfRange_Throws_SubSection7BC`
    - `BallotEncryptorTests.Encrypt_InvalidManifestReference_ThrowsException`, `Encrypt_BallotStyleMismatch_ThrowsException`,
      `Encrypt_ChoiceCountMismatch_ThrowsException`, `Encrypt_ChoiceIdMismatch_SameChoiceCount_ThrowsException`,
      `Encrypt_SelectionValueExceedsOptionSelectionLimit_ThrowsException`, `Encrypt_NegativeSelectionValue_ThrowsException`
    - `BallotAggregationVerifierTests.AddBallot_AMalformedBallot_FaultsTheVerifier`
- Re-pinned and why (none weakened):
  - The four `*OutOfRange_Throws_SubSection6BC/7BC` tests pinned the G33 bug (0 rejected). They are now
    `Verify_ZeroChallenge_IsInZq_FailsOnlyTheSumCheck_SubSection6D/7D` and `Verify_ZeroResponse_...`. The same
    tamper, without re-proving, now passes 6.B/6.C or 7.B/7.C and fails 6.D or 7.D.
  - New tests show that a valid proof with c_j = v_j = 0 passes V6 (both selections) and V7. The helper,
    `ZeroChallengeRangeProof`, simulates branches with c_j = v_j = 0.
  - The six encryptor tests asserted an exact `Exception`. They now assert `InvalidBallotException`, a subclass,
    which is strictly stronger.
  - `AddBallot_AMalformedBallot_FaultsTheVerifier` pinned a `KeyNotFoundException` from the tally's dictionary. It
    now asserts `VerificationFailedException` with `SubSection == "9.structure"`. The fault-state assertions are
    unchanged. The doc comments of that test and of `BallotAggregationVerifier` were corrected: the malformed
    ballot's own ciphertexts are no longer partly added.
  - `CanonicalOrderTests.Encrypt_BallotListingAContestTwice_IsRejected` was tightened from `ThrowsAny<Exception>` to
    `Throws<InvalidBallotException>`. The comment in `RangeProofChallengeTests` that said the verifications reject
    zero is fixed.
- New tests (103; Core 866 → 969):
  - `Verify/BallotStructureTests` (G4). The valid ballot passes V6, V7, V8 and AddBallot. Eleven malformed shapes
    × {V6, V7, V8, AddBallot} each fail as `"N.structure"`:
    - duplicated contest;
    - duplicated option, appended or in place of another option;
    - missing option, extra option, an option of another contest;
    - missing style contest;
    - a manifest contest not on the style, a contest not in the manifest;
    - an unknown ballot style, another ballot style.
  - Also in `BallotStructureTests`:
    - A malformed ballot adds nothing to a tally (BallotsCast stays 0 and the aggregates stay at identity).
    - The verbatim contest-copy attack, with a matching confirmation code, passes 5.B and is rejected by V6, V7, V8,
      AddBallot and `BallotAggregationVerifier.AddBallot`.
  - G13:
    - Equal identifiers in separate arrays fail 5.A.
    - Equality and hash code are by content.
    - `SelectionEncryptionIdentifierSet` catches a duplicate in a later batch.
  - G23, `Serialization/StrictDecodingTests`:
    - Boundaries for each decoder: 0 and p-1 (or q-1) are accepted; p, p+1, 2^4096-1, q and 2^256-1 are rejected.
    - Wrong lengths are rejected (0/32/511/513, 31/33/512, 0/31/33).
    - The reducing constructor turns p (or q) into 0, which documents the old hole.
    - JSON and protobuf × {alpha padded to 513 bytes, alpha = p, response = q, response padded to 33 bytes, 31-byte
      id_B} each throw `NonCanonicalEncodingException`, while the untampered document decodes.
  - G24, `PreEncryptedBallotVerificationTests`: 13 shapes, each re-hashed so that 16.A-16.C would hold, fail
    `"16.structure"`:
    - a missing or extra null vector;
    - an option vector in place of a null vector, or a null vector in place of an option vector;
    - an option twice with one missing, or an unknown option;
    - a short or long vector;
    - a duplicated or missing contest, a contest not in the manifest, a wrong contest index;
    - an unknown style.
  - Also in `PreEncryptedBallotVerificationTests`: a re-hash of the valid ballot reproduces its confirmation code and
    passes.
  - G36: `Verify_TwoNonMemberSelectionsWhoseProductIsAMember_Throws_SubSection7A`. Both alphas of the contest are
    negated. The test asserts that the aggregate is unchanged and a member, and that the untouched contest proof
    still satisfies 7.D, so the old aggregate check passed this ballot. It now fails 7.A.
  - S1 carry-over, canonical-order fixtures where label order is the reverse of index order, for contests and
    options alike:
    - `CanonicalOrderTests`: the encryptor emits and hashes in index order, and V6, V7, V8 pass. A ballot stored in
      label order with canonical hashes passes V8. A confirmation code over label order fails 8.B. A contest hash
      over label-ordered options fails 8.A.
    - `BallotPreEncryptorTests.PreEncrypt_LabelOrderDiffersFromIndexOrder_OrdersContestsAndOptionsByIndex`: the
      output order is by index, the confirmation code differs from the label-order one, and V16 passes.
- Gate after:
  - Build: `0 Warning(s)`, `0 Error(s)`.
  - Smoke ×3: `correctness passed` each time. dkg 127-128 ms; EncryptBallots 0.201-0.205 ms/ballot, 134.7 MB;
    VerifyBallots 0.459 / 0.462 / 0.466 ms/ballot, 6.1-6.2 MB; Tally 6 ms; VerifyTally 3-4 ms; DecryptTally 19-20 ms.
  - Console: `Done.`, then the expected ReadKey exception. tally.json
    `{"Contests":{"0":{"Choices":{"0-0":{"VoteCount":3},"0-1":{"VoteCount":0}}}}}`.
  - Tests: Core `Passed: 969, Total: 969`; Perf `Passed: 199`.
- **Perf (the user asked for the G36 cost).** Same machine, sequential runs. The baseline is a HEAD (6fbc25c) copy of
  the tree, confirmed identical to HEAD apart from line endings.

  | Scenario | Metric | HEAD | S3 | Change |
  |---|---|---|---|---|
  | smoke (1 contest, 2 options; 3 runs each) | VerifyBallots ms/ballot | 0.365 / 0.368 / 0.365 | 0.459 / 0.462 / 0.466 | about +26% |
  | smoke | VerifyBallots alloc | 5.8 MB | 6.1-6.2 MB | +0.4 MB |
  | xsmall (famous-names-large manifest, medium's manifest; 2 runs each) | VerifyBallots ms/ballot | 6.655 / 6.662 | 7.249 / 7.710 | about +12% |
  | xsmall | VerifyBallots alloc | 82 MB | 88 MB | +6 MB |

  - EncryptBallots, Tally, VerifyTally and DecryptTally are unchanged.
  - The extra time is V7's per-ballot batch test (a Jacobi pass over 2·selections values, one 128-bit
    multi-exponentiation, one ^q). The `AggressiveOptimization` experiment below moves it by 0.3 ms/ballot. The
    structure check is a few comparisons per contest, and its pass path allocates nothing by construction. The
    extra allocation is attributed, without being measured separately, to V7's per-ballot components list and the
    batch test.
  - medium (100k ballots) was not run: at about 7.4 ms/ballot verify plus 3.5 ms/ballot encrypt it takes roughly 20
    minutes. xsmall uses medium's manifest, so its per-ballot cost stands in for medium's.
  - `AggressiveOptimization` on `SubgroupMembership.BatchTest`, `TryJacobiDivsteps`, `PosDivsteps62` and
    `ApplyTransition`, measured:
    - Without it: smoke VerifyBallots 0.759 / 0.761 / 0.767 ms/ballot.
    - With it: 0.47-0.49 ms/ballot.
    - xsmall: within noise either way.
    - Reason: a short run never tiers these loops up, and they used to run only on failing ballots. Kept, following
      the precedent on `ModInverseVariableTime`.
  - `egperf compare` against a pre-S3 smoke run will flag the VerifyBallots allocation. That is expected from Q8.
- Decisions taken (low-stakes API shape; none changes interoperable bytes):
  - **Structure SubSection convention:**
    - `"N.structure"`, with N the verification that found the failure: 6, 7, 8, 9 (`EncryptedTally.AddBallot`) or 16.
    - The message names the violation and says it is a §3.1.3 structural check that runs before the verification's
      lettered checks. The spec letters no such sub-check: it is implicit in the index-keyed model (§3.1.3 p.17,
      V6 preamble p.36, V7, V9).
    - Ordering: structure first, then 6.A or 7.A, then the remaining lettered checks. The structure decides which
      ciphertexts the lettered checks range over, so it cannot come after them. This refines the earlier rule that
      "6.A/7.A for any value is reported before anything else": that rule now means before any other lettered check.
  - **Ballot-style checks** are enforced for every regular ballot, not just challenged and pre-encrypted ones. The
    audit calls this hardening beyond the spec's 14.B and 19.B. The task scope asked for it.
  - **`NonCanonicalEncodingException`** is a deserialization error, not a 2.x/6.x/7.x sub-section:
    - A decoder does not know which checks a value feeds; one alpha enters 6.A, 7.A and V9.
    - Once a value is decoded, the types can hold only canonical values, so the range halves become invariants.
    - A record that does not decode does not verify.
  - **5.B and id_B length:** 5.B (`Verify(identifier, hash, H_E)`) still hashes the identifier as given. The 32-byte
    length is enforced at decode time. Existing 5.B tests use 3-byte identifiers built in memory.
  - **`InvalidBallotException`** derives from `ArgumentException`.
  - **Program.cs** now runs 5.B for every ballot. The old per-ballot one-element 5.A list checked nothing.
- Carry-overs:
  - The per-contest supplemental fields (overvote, null, undervote, write-in) are outside `BallotStructure`. S5
    redesigns them.
  - V6's `PassesStructuralChecks` still repeats the manifest lookups that `BallotStructure` now guarantees. They are
    harmless and cheap, and left alone.
  - Records (`EncryptionRecord`, `GuardianRecord`) still have no deserializer. The strict decoders are ready for S10.
  - The 8.D/8.E tautology (G37) is S8's.
- Spec questions: none new.

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
