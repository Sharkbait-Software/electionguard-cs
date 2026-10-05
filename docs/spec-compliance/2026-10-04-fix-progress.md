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
| S1 Hash encodings, indices, canonical order | G1, G6, G7, G35, G26 (1.F compare and constructor reuse), G12, G9 | — | in progress | |
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

## Log

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
