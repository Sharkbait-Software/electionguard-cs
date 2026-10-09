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
- **S7 decisions, answered 2026-10-07:**
  - **Q21 (S7a), attribution proof for the challenged-ballot nonce shares:** "No, keep as built". Guardians send m_i
    alone, as the spec defines. A wrong share is detected but the guardian is not named.
  - **Q22 (S7b), partial decryption for risk-limiting audits:** "Not yet". Only whole contests may be left out,
    until an audit workflow is designed.
  - **Q23 (S7c), label for the V13 hardening check g^ξ = C0:** "Report as 13.A".
  - **Q24 (S7d), fallback when nonce decryption fails:** "None for now". Fail closed.
- **Q25 (S8a), empty simple chain, answered 2026-10-07:** "Refuse to close". `DeviceChain.Close` throws for an empty simple
  chain, and V8/V16 reject an empty simple-chaining device record as N.structure. A device that encrypted nothing gets no
  published record.
- **S8b, carried to S10, no decision needed now:** chain initialization and close use only public inputs. Anyone who can
  rewrite the record could drop trailing ballots and recompute the close. When the election-record format is designed,
  sign or timestamp each device's closing hash at close.
- **S9 decisions, answered 2026-10-08:**
  - **Q26 (S9-1), supplemental fields, write-in fields and contest data with pre-encrypted ballots:** "Reject in
    manifest". Kept as built.
  - **Q27 (S9-2), undervote padding:** "Pad to L with nulls". Kept as built.
  - **Q28 (S9-3), what an uncast pre-encrypted ballot publishes:** "ξ_{i,j,k}; ξ_B opt-in". Kept as built.
  - **Q29 (S9-4), overvote on a pre-encrypted ballot:** "Refuse; caller decides". Kept as built.
  - **Q30 (S9-5), label for the V18 hardening:** "18.A". Kept as built.
  - **Q31 (S9-6), who may have a ballot's nonce decrypted, a security issue:** "Issued list + record check".
    - Pre-encrypted ballots: guardians decrypt a nonce only for an id_B on a printer-committed list of issued
      pre-encrypted ballots, and each at most once (guardian-side state).
    - Both paths, pre-encrypted and S7 challenged: guardians refuse any request whose id_B, H_I or C_ξB,0 matches a
      cast ballot in the published record.
    - This also closes the background security review finding on S7's `TallyGuardian.DecryptBallotNonce` (trusting
      the caller's Status field).
    - Implemented in S9b (done; see the S9b log entry). S9-6 and the security review finding are closed.
    - *Superseded in part by Q35 (S9c):* the pre-encrypted clause (issued list, at most once per id_B) went away with
      the guardians' pre-encrypted nonce path. The record check on the challenged path (part 2) stays.
    - *Implementer reading (S9b, awaiting the user's acceptance; open question S9b-1):* the at-most-once clause is
      also enforced on the challenged path: a challenged-ballot request whose id_B is on the issued list is refused
      (`IssuedPreEncryptedBallot`), since otherwise a printed ballot not yet recorded could be opened there, ahead of
      its voter and outside the once-only rule.
    - *Scope as built (S9b review round 1; open question S9b-3):* "each at most once (guardian-side state)" is per
      guardian. It binds every later quorum only when more than n - k guardians answered (always when n < 2k, as in
      the default 3-of-2); with n >= 2k a disjoint quorum can answer the same id_B again until the ballot is
      published as cast.
    - The record check also refuses, by design, nonce decryption of cast ballots selected for a risk-limiting audit
      (§3.3.4 p.30). An audit flow (Q22, "Not yet") needs its own authorization path.
- **S9b decisions and scope change, answered 2026-10-08:**
  - **Q32 (S9b-1), the challenged path refuses issued pre-encrypted id_Bs:** "Keep". This is superseded by Q35: the
    issued list goes away with the guardian pre-encrypted path.
    - *Sign-off pending (S9c review round 1, open question S9c-R1):* the user answered "Keep" in the same batch as
      Q35, so the loss of the S9b-1 property (an unrecorded printed ballot wrapped as a challenged regular ballot is
      answered) rests on the implementer's reading that Q35 supersedes Q32. It is asked explicitly as S9c-R1; until
      answered, the exposure is pinned by a known-exposure test and nothing in the code refuses it.
  - **Q33 (S9b-2), retries under once-only:** the user wrote: "This doesn't make any sense. The guardians are not
    required for the preencryption phase, the encryption package already exists. The guardians will have no knowledge
    of preencryptions until they are submitted as part of the tally process."
  - **Q34 (S9b-3), the once-only rule's reach when n ≥ 2k:** the user wrote: "There will pretty much never be more than
    about 9 guardians." Moot after Q35.
  - **Q35, scope of pre-encryption in this library:** the user wrote: "I think we should only be implementing the
    primitives needed for the preencryption process. Do not implement (and remove if already implemented) the
    encrypting tool and recordin tool. This question about databases is relevant for context of creating those, but
    those tools themselves are out of scope for the current state of this library." The scope line was then
    confirmed: "Yes, that line".
    - KEEP in Core: the spec formulas (eqs 113-116 selection, null-vector and contest hashes and the confirmation
      code; eqs 117-120 chaining; eq 121 deterministic nonces; hash trimming and short codes Ω), the published
      pre-encrypted record models, and Verifications 15-19.
    - REMOVE from Core: `BallotPreEncryptor` (the encrypting tool), `BallotRecordingTool`, the guardian
      pre-encrypted nonce path with its issued list and once-only state, and the console's pre-encrypted demo.
    - Ballot generation that tests need moves into test-only fixtures (`test/ElectionGuard.Testing.Common`).
    - The guardian check of challenged regular ballots against cast ballots (Q31 part 2) stays.
    - Done in S9c.
- **Q36 (S9c-R1), opening an unvoted printed pre-encrypted ballot early, answered 2026-10-08:** the user wrote: "In
  general, by the time guardians are doing decryption, voting will always be over and this data is sealed. The library
  can assume that. There is a special case of decryption that will occur during an election, but it is only when a
  voter purposefully challenges a ballot and we use the nonce (still in memory) to determine selections (also known
  as instant verification). I don't think we need to do anything special for guardians."
  - The library therefore assumes guardian decryption happens only after voting closes and the record is sealed. No
    guardian-side change is made.
  - `KnownExposure_S9b_1` documents accepted behavior under that assumption.
  - Instant verification (a voter challenges, and the ballot is opened with the in-memory nonce) is encryption-side
    and never involves guardians.
- **Q37, S10 scope, answered 2026-10-08:** "A and B". The user also wrote: "The ElectionRecord bundle needs to be
  canonically defined as well because of the fact that a verifier needs to be capable of operating on it. It will
  eventually receive a formal spec as well. That said, we need to take care to be able to handle it since it will often
  be large (GBs), and we could have multiple representations and such."
  - Plan: S10a fixes the Core correctness gaps (part A) and adds the G40 encryption timestamp.
  - S10b designs the canonical, streaming, multi-representation ElectionRecord. The design goes to the user for
    approval, then gets implemented together with a verify-everything entry point.
- **S10b design answers, 2026-10-09.** These refer to the design doc's Q-1..Q-18, plus #19 = S10a-1. The user's words
  are quoted.
  - **#1:** "Canonical encoding should be protobuf, not binary. It's important that the distributed format be something
    that can be used on any machine. JSON as a projection is fine as well."
    - Design consequence: the canonical hash form is a deterministic-protobuf profile. Every item is a protobuf
      message in field-number order, with no maps, no unknown fields and fixed-width `bytes` for group elements
      and Z_q values. Digests are taken over those bytes. Any language's protobuf library can parse them, and a
      verifier checks canonicality by re-encoding. JSON follows the proto3 JSON mapping.
  - **#2:** "Fine". SHA-256 with RFC 9162 Merkle framing.
  - **#3:** "Optimize for size of the files when encoding the encryptions. Beyond that, use json and protobuf standards
    for naming, or the stuff that's already there."
    - Group elements and Z_q values are raw fixed-width `bytes`, base64 in JSON.
    - Field names are snake_case in `.proto`, lowerCamelCase in JSON per the proto3 mapping.
  - **#4:** "NotSubmitted doesn't make sense. If we have it in the election record at all, it was by definition
    submitted. Anything not cast or challenged can probably be considered Spoiled." So a `Spoiled` status replaces
    `NotSubmitted` in the record.
  - **#5:** "I think pre-encrypted ballts never returned can be considered challenged ballots." So they are recorded
    as uncast pre-encrypted ballots, with released nonces.
  - **#6:** "Where does this come into play? I don't know enough to answer this question." Asked again with more
    detail.
  - **#7:** "Sure". The recommended attestation and signature defaults stand.
  - **#8:** "Yes". v1 requires a decryption for every challenged ballot.
  - **#9:** "I don't know what this means, need more detail." Asked again.
  - **#10:** "Need more detail." Asked again.
  - **#11:** "Out of range values are a problem for a verifier, not the election record format." So the format
    carries fixed-width bytes, and the verifier reports range failures under the spec's lettered checks.
  - **#12:** "Need more detail." Asked again.
  - **#13:** "If you want to argue for binary, you're going to need to do so, but we absolutely must be capable of
    working on any device in any programming language, and it should be relatively easy to do so. Space is a concern,
    which is why protobuf over json, and I'm open to other options, but binary seems like a nonstarter since someone
    would have a hell of a time getting something reasonable with a javascript verifier." So protobuf is canonical,
    and there is no custom binary format.
  - **#14:** "If .7z would save significant space, we can consider that, else .zip is the way to go."
    - Measured 2026-10-09 on current-format ballots: the cryptographic payload is incompressible (deflate 1.000, LZMA
      1.002), and JSON is 0.612 with deflate versus 0.609 with LZMA.
    - Decision: **.zip**.
  - **#15:** "Yes". The format and verify-all go in Core, and the command-line tool in ElectionGuard.Verifier.
  - **#16:** "We will do multiple tallies but we can wait and add it later." So v1 has one tally, with room left for
    more.
  - **#17:** "Sure". Keep the tally header.
  - **#18:** "Need more detail on this." Asked again.
  - **#19:** "The manifest need only be a valid document, and it should be output to the election record exactly as it
    was entered. The canonical serialization for the manifest is not as important." So the manifest is stored
    byte-for-byte as entered. `ManifestSerializer` only parses it, and its output is not canonical.
- **S10b follow-up answers, 2026-10-09:**
  - **#6 Timestamp precision:** "Full precision seems fine here. The entire point of the library is that an encrypted
    ballot can't yield actual results, nor can your confirmation code. If a ballot is challenged, then it's purposefully
    decrypted in a way that doesn't count and may not be a voter's actual votes. This isn't a real concern." So
    timestamps are millisecond UTC, with no precision setting.
  - **#9 Election info:** "Only what isn't in manifest". The record header carries only the format settings the library
    needs. Descriptive election facts live in the manifest.
  - **#10 Contest-data decryption:** "Record the requested set". The administrator's (ballot, contest) request list is
    sealed into the record before decryption. Verifiers check that every request is decrypted and nothing extra was.
  - **#12 String ballot id:** "Keep, optional". It is an optional free-text reference, documented as unverified.
  - **#18 Lookup indexes:** "Alongside, not signed". They go in `derived/`, outside the root, can be regenerated, and
    come with inclusion proofs.
  - **Canonical protobuf profile:** "Yes, canonical protobuf".
    - The `.proto` schemas are normative. Fields are written in field-number order, with no maps, no unknown fields
      and fixed-width bytes, under proto3 default-omission rules.
    - A verifier checks canonicality by re-serializing and comparing bytes.
    - JSON is the proto3 JSON mapping.
    - Golden vectors and a Python reference reader prove the profile.
- **EGRF v2 new questions, answered 2026-10-09:**
  - **NQ-1 Extensions:** the user wrote: "Vendors should never add fields to most of the types. The manifest is really
    the only field I would ever expect a vendor to provide additional data, so honestly it's canonical form should
    probably be json. Protobuf tends to be backwards compatible by default, so we should be good with future versions
    already. I don't think we need anything special here."
    - There is no per-item extension list.
    - The manifest stays JSON, stored byte for byte. Its reader ignores unknown properties (vendor data), which H_B
      still binds. It still rejects duplicate keys and malformed JSON.
    - The record profile allows unknown fields only after all known fields, in field-number order. Field numbers are
      append-only, so canonicality survives a re-encode by an older library.
    - A verifier that sees a newer `format_minor` reports that the record is newer but still verifies everything it
      understands.
  - **NQ-2 Compact uncast form:** "Compact required for unreturned". The compact item is mandatory for never-returned
    pre-encrypted ballots, and the verifier regenerates their content from ξ_B.
  - **NQ-3 JavaScript conformance reader:** "Defer".
  - **NQ-4 Election facts (§3.7):** "Optional manifest fields". Add optional name, date, location, type and
    jurisdiction fields to the manifest model, bound into H_B. The record header carries only the format version.
  - **NQ-5 Opening uncast pre-encrypted ballots:** "Later: guardian opens from sealed record". After S10b,
    `TallyGuardian.DecryptBallotNonce` opens an uncast pre-encrypted ballot from a sealed, verified record. It refuses
    any id_B cast in that record (Q31), with no issued list and no once-only state.
  - **NQ-6 Pipe input:** "Drop it". A non-seekable input is spooled to a temporary file first.
- **S10b-A readings, answered 2026-10-09:**
  - **R-1 When the compact uncast form applies:** "Whenever ξ_B is released". Kept as built: compact exactly when
    ξ_B is released, so every ballot has one encoding.
  - **R-2 A newer format_minor:** "Pass, flagged incomplete". Kept as built: the verdict is Passed with
    `Complete = false`, and the CLI exits 2.
  - **R-3 Near-miss manifest property names:** "Ignore them too". This is a CHANGE: remove
    `ManifestSerializer.RejectNearMisses` and its tests. Every unknown property is ignored, and H_B still binds the
    bytes.
  - **Guardian refusal of spoiled ballots:** "Refuse spoiled too". This is a CHANGE: the guardian's sealed-record view
    and Q31 check refuse any id_B, H_I or C_ξB,0 that matches a cast OR spoiled ballot.
- **Cadence:** "Keep going". After each stage: commit, update this tracker, push, start the next stage. Stop only
  for a new spec contradiction or question.
- **S7 design and API choices** (2026-10-06; implementer choices, none changes bytes the spec fixes; the first two are
  also listed as open questions in the S7 log entry):
  - **No proof for the ballot nonce decryption.** §3.6.7 defines none (no commitment or challenge hash, no §5.5.4
    row; the KAT oracle agrees), and ξ_B is never published, so β_B cannot be either. The guardians send m_i alone
    (eq. 107), one message, and the administrator combines (eq. 108), recovers ξ_B and publishes nothing unless
    every derived nonce reproduces the ballot's ciphertexts. A wrong m_i is detected but not attributed. The S4/S6
    three-round engine is not reused: running it would invent domain-separation bytes, and every guardian would
    compute β_B, so would learn ξ_B (every selection, even ones an RLA release withholds).
  - **Verification 14.B** reads "on the uncast pre-encrypted ballot" (the wording of 19.B). It is applied to the
    decrypted challenged ballot, as the Verification 14 preamble describes. A partial (RLA) decryption, which 13.B
    accepts, therefore fails 14.B.
  - **RLA granularity is the contest (S7 review round 2).** §3.6.7 p.52-53 also allows releasing "the desired subset of
    encryption nonces" within a contest, with the verifier using the ballot's given selection encryptions for the
    rest. Verification 13 as lettered recomputes every field of a decrypted contest ("For all 1≤j≤m_i"), and its RLA
    paragraph names only contests that "have not been decrypted". So V13 accepts a contest left out, but a decrypted
    contest that omits a field, or omits its contest data, fails `"13.structure"`. The V13 class remarks and CLAUDE.md
    say so. This belongs to open question Q-S7b, the RLA case as a whole.
  - **Trust boundary of the guardian's status check (S7 review round 2; spec-silent, documentation only).** Every
    check in `ChallengedBallotStatement.For` and `TallyGuardian.DecryptBallotNonce` reads the ballot object the caller
    hands in, and `EncryptedBallot.Status` has an `init` accessor. A cast ballot copied exactly (same id_B, H_I,
    contests, confirmation code and C_ξB) under a new string `Id` and marked `Challenged` passes all of them,
    including the eq. (38) proof, which binds H_I and not the string id. k such m_i give ξ_B, and with it every vote
    on the cast ballot. Verification 5.A (unique id_B) flags the duplicate only after the votes are out. In-process
    the caller holds the record. A distributed guardian must refuse when the published record holds any cast ballot
    with the same id_B (or H_I, or C_ξB,0); matching on `Id` is not enough. No overload was added: nothing would call
    it, and `EncryptionRecord` carries no ballot set (see the carry-over).
  - **14.E/14.F:** 14.E bounds an option by R and a supplemental field by its range bound (§3.3.9; Q2). 14.F sums
    the options and the write-in count (Q13: write-ins count toward the limit "exactly like selections"); the
    indicators and the undervote difference are not selections.
  - **Only a challenged ballot's nonce is decrypted.** Guardians and the administrator refuse any other status
    (`ArgumentException`), and Verifications 13 and 14 fail such a ballot as `"13.structure"`/`"14.structure"`.
  - **C_ξB,0 must be in Z_p^r** before any guardian raises it to ẑ_i (the S6 hardening, same shape; spec-silent).
  - **Verification 13.A requires α = g^ξ_i to equal the ballot's C_0** (S7 review round 1; library hardening of a
    spec gap, no bytes change; listed as open question Q-S7c for confirmation). The spec's 13.4-13.A never compares
    α with C_0, and χ_i (13.3) hashes the ballot's own (C_0, C_1, C_2), so without it a publisher could release any
    ξ' with D' = C_1 ⊕ k(ξ') and pass V13 and V14. Reported as `"13.A"` (13.4's α is the α of eq. 65, which is
    C_0), with a message naming C_0. The administrator already made the same check before publishing.
  - **Model:** `EncryptedBallotNonce` (C_0 as `IntegerModP`) replaces `EncryptedData` (also on
    `PreEncryptedBallot`). `EncryptedBallot.EncryptedBallotNonce` is required: protobuf field 10, JSON
    `encryptedBallotNonce`; `BallotStructure` requires it with a 32-byte C_1. The published record is
    `DecryptedChallengedBallot` (per contest: options and supplemental fields as (label, σ, ξ_{i,j}), and contest data
    as (ξ, D)), with no ξ_B, no indices (V13/V14 take them from the manifest) and no proof.
  - **Console:** the first ballot is encrypted a second time as `<id>-challenged` (fresh id_B and ξ_B) and challenged,
    as a voter would before casting, so the three cast ballots still tally 0-0: 3. Contest data is decrypted (§3.6.6)
    only for cast ballots; a challenged ballot's is released by §3.6.7.

- **S8 design and API choices** (2026-10-07; low-stakes implementer choices; none changes a hash input, every KAT
  family passes):
  - **Every ballot carries its chaining field B_C** (`EncryptedBallot.ChainingField`: JSON `chainingField`, protobuf
    field 11, exactly 36 bytes), as `PreEncryptedBallot` already did. Verification 13.B's "B_C is the chaining field
    for ballot B" reads it as published, and without it 8.D/8.E cannot be told apart from 8.B. 8.B now hashes the
    stored field; 8.D/8.E compare it with the field the device and chain position imply (G37).
  - **The §3.7 per-device list is a `DeviceChainRecord`** (device id, H_DI, ballot kind, chaining mode, confirmation
    codes in order, and under simple chaining H_0, B-bar_C and H-bar). Ballots are referenced by confirmation code (the
    chained value, bound to the ballot's contents and id_B), not by the string id. A record exists under no chaining
    too, with null close values. The record's mode must equal the manifest's (the library's chaining mode is
    election-wide).
  - **Per-ballot V8 vs per-device V8.** `Verify(ballot, record)` covers 8.A, 8.B and 8.D (no chaining) or the
    0x00000001 identifier (simple). `VerifyDevice`/`VerifyDevices` are the authoritative chain checks: completeness of
    the list (`"8.structure"`), 8.C on the recorded H_DI, 8.F, 8.D/8.E in list order, 8.G. A listed ballot that names
    another device is `"8.structure"`; one whose device id was rewritten fails 8.E (simple) or 8.D (none). The same
    walk serves 16.D-16.H.
  - **An empty simple chain is not closed** (refused by `DeviceChain.Close` and by the walk), since eq. (78) needs
    H_ℓ. Listed as open question 1 in the S8 log.
  - **Only chaining modes 0x00000000 and 0x00000001 (S8 review round 1).** §3.4.4 leaves any other mode to "a 4-byte
    identifier ... specified in the election manifest", and this manifest model specifies none, so
    `Manifest.Validate` refuses any other `ChainingMode` value (`InvalidManifestException`; this covers
    `EncryptionRecord` construction and deserialization, both encryptors, `DeviceChain` and every verification), and
    the public `ChainingField` builders throw `ArgumentOutOfRangeException`. Before, mode 2 (which JSON accepts) was
    treated as simple chaining with a 0x00000002 identifier on ballots but 0x00000001 in B_C,0 and the close.

- **S9 design and API choices** (2026-10-07; implementer choices unless marked as an open question in the S9 log
  entry; none changes a hash input, every KAT family passes). *S9c (Q35) removed the encrypting tool, the recording
  tool and the guardians' pre-encrypted nonce path: the "Recording tool inputs" and "Nonce decryption for
  pre-encrypted ballots" items below describe code that no longer exists; the record models, proofs and
  verification readings stand. See the S9c choices after this list.*
  - **A cast pre-encrypted ballot's record is a standard `EncryptedBallot`** with an optional
    `PreEncryptedContests` section (JSON `preEncryptedContests`, omitted when null; protobuf field 12, flagged by
    field 13 `IsPreEncrypted`, so a regular ballot encodes byte for byte as before). Its `Contests` are the combined
    vectors with standard proofs, its contest hashes eq. (115) and its confirmation code eq. (116). The tally,
    `BallotStructure` and Verifications 5-7 and 9-11 take it unchanged; Verification 8 refuses it as
    `"8.structure"` (p.64). This was chosen over a separate wrapper type so that the record self-describes and
    rides through the existing ballot serializers and streams.
  - **The cast record names no option** for a selected vector: per contest it publishes all m + L selection hashes
    strictly ascending and the L selected vectors ((α, β) only) sorted by hash, with short codes. No nonce of a cast
    ballot is serialized (`EncryptedValue.EncryptionNonce` is not written; the protobuf DTO has no nonce member).
  - **Recording tool inputs:** the printed `PreEncryptedBallot`, the decrypted ξ_B and (cast) a plaintext `Ballot`
    with values 0/1. It regenerates the ballot from ξ_B and refuses (`ArgumentException`) unless every vector, hash,
    label, short code, contest hash and the confirmation code match. It always combines exactly L vectors, padding
    with the contest's first null vectors (as the KAT oracle does; open question S9-2). It refuses more than L
    selections (open question S9-4), a value other than 0/1, write-ins and contest data.
  - **Proofs on the combined vector:** eq. (59) per component over 0..R (the manifest's option selection limit,
    p.64 "appropriate option selection limits"; a component is 0 or 1) and eq. (62) per contest over 0..L, keyed
    with the ballot's H_I, through the now `internal static` `BallotEncryptor.GenerateProofs` (with a proof-nonce
    test seam for the KAT).
  - **Nonce decryption for pre-encrypted ballots:** `TallyGuardian.DecryptBallotNonce(PreEncryptedBallot, ...)` and
    `TallyAdmin.DecryptPreEncryptedBallotNonce`/`CombinePreEncryptedBallotNonce` decrypt C_ξB as §3.6.7 does, for
    cast and uncast ballots (the recording tool needs ξ_B either way, §4.3.1); no status check exists to make.
    The administrator returns ξ_B only if it regenerates the ballot, else `TallyDecryptionException` naming no
    guardian. Whoever holds ξ_B of a cast ballot can link its selected vectors to options: §4.3's design.
    S9 review round 1: the guardians' checks read only id_B, H_I and C_ξB, which every published ballot carries
    under the same construction (§4.2), regular cast ballots included, so this path can open any published
    ballot (open question S9-6, widened). Enforced: the manifest must name Ω (`BallotStructure.FindViolation`
    for a `PreEncryptedBallot`), which closes the path in an election without pre-encrypted ballots.
  - **A pre-encrypted record is always cast (S9 review round 1).** `BallotStructure.FindPreEncryptedCastViolation`
    refuses any other status (`"15/16/17.structure"`): an uncast pre-encrypted ballot is published as a
    `PreEncryptedUncastBallot` and audited by V18, and a relabelled record would otherwise leave the tally
    silently. The challenged-ballot path refuses a pre-encrypted record: `ChallengedBallotStatement.For`
    (guardians, administrator; `ArgumentException`) and Verifications 13 and 14 (`"13.structure"`,
    `"14.structure"`). No weight rule: §3.5 weights apply to any ballot, and nothing in §4 excludes them.
  - **Uncast record:** `PreEncryptedUncastBallot` = the ballot, the released ξ_{i,j,k} per vector, and ξ_B only
    when `releaseBallotNonce: true` (open question S9-3). JSON only (`JsonPreEncryptedBallotSerializer`, strict).
  - **Verification readings:** 15.A is applied to every contest, not only L > 1 (the product of one vector is that
    vector; nothing else binds it). V16.B/V18.4 use ind_c (S7 precedent) and all m + L hashes (eq. 115). V18
    compares each recomputed encryption with the published one under its label and, when ξ_B is released, each
    nonce with eq. (121), both reported as `"18.A"` (open question S9-5). `BallotStructure` additionally requires
    each pre-encrypted vector's index to be eq. (121)'s j (option index; m + l for the l-th null vector).
  - **Manifest:** a manifest that names a hash-trimming function must name one of Ω1-Ω8 and declare no supplemental
    fields, write-in fields or contest data (open question S9-1, the S5 carry-over).
  - **Every ballot names its device (S9 review round 3).** `BallotStructure` refuses a regular or pre-encrypted
    ballot whose `DeviceId` is null (`"N.structure"`; JSON does not enforce the `required` annotation). S_device
    enters H_DI (eqs. 72, 119), and the recording tool regenerates on the ballot's device, so without the check a
    null id surfaced as an `ArgumentNullException`, on the pre-encrypted nonce path only after the guardians had
    decrypted their shares, and was reported there as a wrong m_i or ξ_B.

- **S9c design and API choices** (2026-10-07; low-stakes implementer choices under Q35; no hash input moves, every KAT
  family passes with the same vectors):
  - **One public static class, `PreEncryptionPrimitives`,** holds the formulas that had lived inside the tools:
    `GenerateSelection` (one vector by its eq. (121) index j), `GenerateContest` (m + L vectors and the eq. (115)
    hash), `GenerateContests` (a ballot style's contests in index order; validates the manifest and requires Ω),
    `HasUniqueShortCodes` (§4.1.5, one contest), `Combine` (§4.3 product and nonce sum) and `ProveCombinedContest`
    (eqs. 59 and 62 on a combined vector, returning the cast ballot's `EncryptedContest`). The keys are passed as
    `ElectionPublicKeys` so K-hat cannot be passed by mistake. Assembling a `PreEncryptedBallot` (H_I, C_ξB, B_C,
    H_C) is left to the caller: every piece is already a public formula, and the assembly is the encrypting tool.
  - **`ProveCombinedContest` refuses** a value outside 0..R or a sum outside 0..L (`ArgumentOutOfRangeException`):
    no valid proof exists then, and the old tool refused the same inputs earlier.
  - **The KAT proof-nonce seam** is an `internal` overload of `ProveCombinedContest`. The test fixture takes an
    optional prover delegate with the public signature, and the KAT passes one that calls the internal overload,
    so no `InternalsVisibleTo` was added for `ElectionGuard.Testing.Common` and no proof-nonce parameter is public.
  - **What a tool decides is in the test fixture only** (`PreEncryptedBallotFixtures`): drawing id_B and ξ_B, the
    unique-short-code retry, padding an undervote with the first null vectors (Q27), 0/1 values, checking a ballot
    against its regeneration, what an uncast record releases. The code-space check of the old encrypting tool's
    constructor (a contest with more vectors than Ω has codes) is not a primitive; `HashTrimming.CodeSpaceSize`
    stays public for a tool to use.
  - **Challenged path signatures:** `TallyGuardian.DecryptBallotNonce(ballot, record, castBallots)` and
    `TallyAdmin.DecryptChallengedBallot(guardians, ballot, record, castBallots)`;
    `BallotNonceDecryptionRefusal` keeps `ForeignElection` and `CastBallot`. `TallyGuardian`'s constructor is
    `(index, shares)` again.
  - **Per-contest precondition (S9c review round 1):** `GenerateSelection`, `GenerateContest` and
    `ProveCombinedContest` take a bare `Contest` and so cannot rely on `Manifest.Validate`; they share one check
    (`PreEncryptionPrimitives.Positions`): at least one option (`ArgumentException`, as `GenerateSelection` already
    threw) and option index = 1-based list position (`InvalidManifestException`, the exception and wording of
    `Manifest.Validate`). The contest index cannot be checked without the manifest; the class remarks say the
    contest must be the manifest's own. No byte moves for a conformant contest (the positions were already 1..m).

- **S10a design and API choices** (2026-10-08; low-stakes implementer choices under Q37 part A; none changes a hash
  input, `test/kat/vectors.json` is unchanged and every KAT family passes; the first is also open question S10a-1):
  - *Partly superseded by S10b-A (NQ-1, NQ-4): the manifest reader now ignores unknown properties (it still refuses
    near-miss member names and repeated members), and the manifest has optional election facts. See "S10b-A design
    and API choices". The bullet follows as written for S10a.*
  - **Manifest format = strict parse, not byte-canonical input.** `ManifestSerializer` is the one manifest format.
    Reading is strict (UTF-8 without BOM, case-sensitive camelCase members, no unknown or repeated member, comment,
    trailing comma, null value or null list entry, integers as JSON numbers, `kind` by exact
    `SupplementalFieldKind` name, then `Manifest.Validate`; any failure is `InvalidManifestException`). Writing is
    deterministic (compact, declaration order; a supplemental field writes `kind` first, as System.Text.Json orders
    a derived record's members; every optional member except a null `hashTrimmingFunction`; STJ's default string
    escaping). A file need not be in the written form to be read: H_B hashes the file as it is (§3.1.4) and §3.1.3
    leaves the representation "implementation specific". Requiring the written form byte for byte is S10a-1.
  - **The record's manifest is derived.** `EncryptionRecord.ManifestFile`'s init accessor parses the file and
    `EncryptionRecord.Manifest` is get-only; no constructor or member takes a parsed manifest. `GuardianRecord`
    carries only the file (it has no parsed manifest, so nothing to bind; the guardians check H_B over it).
  - **KAT records** keep the oracle's H_B and H_E (over `{"election":"kat"}`, not a manifest) as claims and carry the
    shaping manifest as their file; they never run 1.F. This was preferred to an internal factory that would accept
    a file and a parsed manifest side by side: no API, internal or public, lets the two disagree.
  - **Record JSON** (`JsonElectionRecordSerializer`): one class with typed `Serialize`/`Deserialize*` methods for the
    `EncryptionRecord`, `GuardianRecord`, `EncryptedTally`, `DecryptedTally`, `List<DecryptedContestData>` and
    `List<DecryptedChallengedBallot>`; camelCase, indented. Z_p/Z_q/hash values are base64 of their fixed-width
    big-endian bytes, as on ballots. p, q, g, r are b(p,512), b(q,32), b(g,512) and b(r,512) (r is 481 bytes for the
    spec's parameters, padded to the width of Z_p), never through `IntegerModP`/`IntegerModQ`. Hash claims (H_P,
    H_B, H_E) are kept as read (`FromCanonicalBytes`, exactly 32 bytes), so 1.E/1.F/4.A still check them.
    Structural errors are `JsonException`, value encodings `NonCanonicalEncodingException`, a manifest file that is
    not a manifest `InvalidManifestException`. The derived `Manifest` is removed from the serializer's contract, so it
    is not written and a document carrying a `manifest` member is refused. Bundling is S10b's.
  - **Tally decryption bound: publish the per-contest cast weight.** `EncryptedAggregateContest.CastWeight` (Σ W of
    the cast ballots that list the contest; `BallotStructure` makes every such ballot list every option and field)
    replaces the per-option `MaximumCount` accumulator; `MaximumCount` is now `CastWeight × MaximumValue`, computed.
    The encrypted tally record carries `castWeight` per contest (and `ballotsCast`, informational). Reading a tally
    takes the manifest (for `MaximumValue`) and keeps the document's keys, so V9 still sees an extra or missing
    option. V9 compares each contest's cast weight with the recomputed one, after 9.A/9.B, as `"9.structure"`; it
    does not compare the ballot count (one ballot of weight 3 aggregates exactly as three of weight 1, which
    `BallotAggregationVerifierTests.AddBallot_WeightedBallot_MatchesThatManyUnweightedCopies` pins). Chosen over
    recomputing from the cast ballots at load time, which needs the whole ballot set again for an administrator that
    only decrypts.
  - **Typed errors, split by kind.** A missing or null *scalar* of a decoded ballot (ballot id, ballot style, H_I, a
    contest's, option's or field's label, a contest data C_1) is a `NonCanonicalEncodingException` at decode time
    (`EncryptedBallotShape`, run by both ballot decoders), as were a missing ballot nonce and short code before. A
    missing or null *list* or list entry decodes (protobuf reads a missing repeated field as empty, since it cannot
    tell the two apart) and `BallotStructure` reports it as `"N.structure"`, as it already did for a null
    supplemental field list (S5 review). A missing proof list fails the proof count, as a null JSON proof list
    already did. A null device id or ballot nonce stays `BallotStructure`'s (pinned since S7/S9).
  - **Hash widths.** `ContestHash`, `ConfirmationCode`, `SelectionEncryptionIdentifierHash` and
    `VotingDeviceInformationHash` gained strict `FromCanonicalBytes` (exactly 32 bytes); every JSON converter and the
    protobuf decoder use them (a 31-byte confirmation code used to round-trip).
  - **G40 timestamp:** `EncryptedBallot.EncryptionTimestamp` (`DateTimeOffset?`, UTC, whole milliseconds; the init
    accessor refuses another offset or precision). `BallotEncryptor` takes an optional `TimeProvider` (default
    `TimeProvider.System`) and truncates its reading to the millisecond. JSON `encryptionTimestamp`, exactly
    `yyyy-MM-ddTHH:mm:ss.fffZ` (anything else `NonCanonicalEncodingException`), omitted when null; protobuf field 14,
    `int64` Unix milliseconds with presence, absent when null, years 0001-9999. Not a hash input: eq. (71) takes the
    contest hashes and B_C; §3.4 p.41 makes date and time an optional input the implementation chooses, and this
    library does not choose it. `BallotStructure` does not require it.
  - **Other readers tightened:** `JsonDeviceChainRecordSerializer` refuses unknown and repeated members, a null
    device id or list entry; `JsonPreEncryptedBallotSerializer` refuses unknown and repeated members (a name the model
    marks `[JsonIgnore]`, e.g. a computed property, is skipped by System.Text.Json, not refused; it keeps
    reading a null device id, which V16 reports, as pinned in S9c review round 1).
  - **Console:** writes and reads back the guardian record, encryption record, every encrypted ballot, the device
    chain record, the encrypted tally (`encrypted-tally.json`, new), the decrypted tally (`tally.json`, now camelCase),
    contest data and challenged ballots, and verifies (and decrypts the tally) from the copies read back; it prints the
    tally.
  - **S10a review round 1 additions** (2026-10-08):
    - **Base64 is canonical-only.** Every JSON decoder of a published value (the eight ballot converters, the
      selection hash and ballot nonce converters, the record converters) reads base64 through `StrictBase64.Read`:
      RFC 4648 §4 alphabet, padded to a multiple of 4, unused bits zero, no whitespace, checked by re-encoding the
      decoded bytes and comparing. Anything else is a `NonCanonicalEncodingException` (a value-encoding error, like
      a wrong width); a non-string token is a `JsonException`. `Convert.FromBase64String` and
      `Utf8JsonReader.GetBytesFromBase64` were both measured to accept `"AA AA"` and `"AA\nAA"` (whitespace
      skipped), and accept nonzero unused bits, so the reviewer's suggested switch to `GetBytesFromBase64` alone
      would not have given one encoding per value. This also tightens the ballot JSON reader (no writer produced
      whitespace or nonzero unused bits).
    - **Property names that are not text** (an escaped lone surrogate, invalid UTF-8) are a `JsonException` from
      `StrictJson.RejectAmbiguity` (it wraps the reader's `InvalidOperationException`), so the manifest reader
      reports `InvalidManifestException` and the record, device chain and pre-encrypted readers `JsonException`.
    - **Cast weight bounds.** The encrypted tally reader refuses a cast weight above `ballotsCast × int.MaxValue`
      (a sum of at most `ballotsCast` int weights; a consistency check only, since `ballotsCast` is published too).
      `MaximumCount` saturates at `long.MaxValue` rather than wrapping (saturation, not `checked`: an
      `OverflowException` from a property getter would be another untyped failure), and `Combine` refuses a bound
      that is negative (unreachable through `EncryptedTally` now) or above `int.MaxValue` with
      `TallyDecryptionException`. The real defense is ordering: `DeserializeEncryptedTally`, `TallyAdmin.Decrypt`
      and `Combine` now document that a tally read back must pass Verification 9 before it is decrypted (the
      console already does). Enforcing it in the API (e.g. a verified-tally type) is left to S10b's verify-everything
      entry point.
    - **The record copies its manifest file's bytes** when `ManifestFile` is set, so the caller's array cannot split
      1.F from the parse. `record.ManifestFile.Bytes` (the copy) and `record.Manifest` stay mutable objects that
      in-process code must treat as read-only; making them immutable (`ReadOnlyMemory<byte>`, read-only collections)
      is a wider API change not taken here. The "or change `record.Manifest`" advice was removed from CLAUDE.md and
      the fixture builder; `ManifestValidationTests.Encryptors_ManifestReorderedAfterRecordCreation_Throw` is kept,
      commented as a deliberate misuse probe.

- **S10b-A design and API choices** (2026-10-09; low-stakes implementer choices under NQ-1..NQ-6; none changes a
  hash input, `test/kat/` is unchanged and every KAT family passes). The first three are readings of the answers that
  the answers did not spell out; they are written into the design as stated and listed there as R-1..R-3 (§12) for
  the user to confirm:
  - **R-1, compact uncast form (NQ-2).** The form follows from what is released: `PreEncryptedCompactUncastBallot`
    iff ξ_B is released, the full `PreEncryptedUncastBallot` iff it is not. Never-returned ballots always release ξ_B,
    so they are always compact ("Compact required for unreturned"); a returned uncast ballot whose ξ_B is released
    under Q28's opt-in is compact too, so no ballot has two valid encodings. The release carries `ballot_nonce` alone
    for a compact item and `contests` alone for a full one (`18.structure` otherwise). The format cannot tell
    never-returned from returned; `DeviceSectionWriter.AppendUncastAsync` takes an `UncastDisposition` so the writer
    enforces the mandatory rule. Schema only so far (RecordItem member 16; same field numbers as the full item).
  - **R-2, newer minor (NQ-1).** "Reports that the record is newer but still verifies everything it understands" is
    read as informational: `Passed` = no failures; `Complete = false` is reported beside it with the content not
    understood; `egrecord verify` exits 0 / 2 / 1 for passed-complete / passed-incomplete / failed. Unknown critical
    sections and unknown item types in sections that must verify stay `R.version` failures. G-6 now promises that no
    reader reports `Complete` with unread content.
  - **R-3, near-miss manifest properties (NQ-1).** `ManifestSerializer` ignores unknown properties at every level but
    refuses one whose name equals a member's once case, `_` and `-` are disregarded (`ChainingMode`, `chaining_mode`,
    `Selection-Limit`): a loosely matching reader elsewhere would read it as that member and compute with another
    manifest under the same H_B. The check walks the document along the model's `JsonTypeInfo` (manifest, contests,
    options, supplemental fields, ballot styles) before deserializing.
  - **An ignored manifest value is still text (review round 2).** Ignoring an unknown property skips its value
    without decoding it, so `StrictJson.RejectAmbiguity` now checks the whole document with `Utf8.IsValid` (RFC 3629;
    RFC 8259 §8.1) and decodes every escaped string (a lone-surrogate escape such as `"\uD800"` is refused, as the
    protobuf side's W8 refuses surrogates). Acceptance therefore does not depend on which properties a reader knows.
    It applies to every strict reader (manifest, record, device chain, pre-encrypted), which already decoded every
    string they knew. The nesting limit of 64 levels (top-level value = level 1; the System.Text.Json default, which
    RFC 8259 §9 permits) is kept and now stated in `ManifestSerializer`'s remarks, the design's ManifestFile paragraph
    and the `media_type` comment; it applies to vendor data too.
  - **Unknown fields in the profile (NQ-1).** W6 rewritten: unknown fields only after every known field, ascending,
    numbered above every declared or reserved number of the message (`RecordItem` excepted: an unknown oneof member
    is an unknown item type), VARINT or LEN only, a VARINT never 0. Method B keeps unknown fields; on the normal path
    (record minor not newer than the reader's) a discard-unknown parse folds "no unknown field" into the comparison.
    `EgrfUnknownFieldBehaviourTests` showed C# writes kept unknown fields after the known ones **in the order read**,
    so a descending unknown tail survives Method B: for newer-minor records Method A's unknown-field branch is
    required, and the design says so. D7 (election_info keys) is gone; D2 treats an undeclared enum value in a newer
    record as content not understood (`R.version`, the item still digested); D5 is "exactly one field".
  - **Schema location and codegen.** The one normative copy is `proto/electionguard/egrf/v2/egrf.proto` at the
    repository root, as the design's §8.2 had planned (language-neutral; `go_package` already named that path), not
    under `src/ElectionGuard.Core`. `docs/spec-compliance/egrf_v2.proto` is deleted and the design's §4.6 no longer
    embeds the schema (it links it and lists the items). Core references Google.Protobuf 3.34.1 and Grpc.Tools 2.80.0
    (libprotoc 31.1, the version the feasibility run used; `PrivateAssets="All"`), both from the NuGet cache, and
    compiles the file with `Access="Internal"`, `GrpcServices="None"`.
  - **Namespace `ElectionGuard.Core.RecordFormat.Protobuf`, not `...Core.Record.Protobuf`.** The first build failed
    in the test files that call `Record.Exception`: a namespace `ElectionGuard.Core.Record` is found before xUnit's
    global `Record` class from any namespace under `ElectionGuard.Core`, so those calls stopped compiling. The
    design's planned `ElectionGuard.Core.Record` namespace and `src/ElectionGuard.Core/Record/` folder become
    `RecordFormat`. The test folder is `test/ElectionGuard.Core.UnitTests/RecordFormat/`.
  - **Reserved, not dropped.** `RecordHeader` field 3 (draft `election_info`) and `RecordItem` 2047 (draft
    `extensions`) are `reserved`: never published, but the feasibility vectors used them, and S6 says removed numbers
    are reserved.
  - **Schema lint and table.** `EgrfSchemaLint` (test project) checks S1-S8 on a `FileDescriptorProto` parsed from
    the compiled descriptor with the width options registered, so the same code runs on the real schema and on broken
    copies. Beyond the design's list it checks: the package name; that every enum starts with
    `<NAME>_UNSPECIFIED = 0`; that the only extensions are the three width options; that width options sit only on
    singular `bytes` fields; that every `bytes` field without a width is on an explicit variable-length list (so S7's
    "unannotated fixed-width field" is mechanical); that hot messages stay at 15 or below; that `RecordItem` has no
    regular field; and that repeated strings and bytes are refused along with repeated numerics (S3: "a list is a
    repeated message or one bytes field"). `test/egrf/schema.json` (generated, checked in) is the schema table; the
    test fails unless it equals the compiled schema, and checks any change against it for S6 (nothing removed or
    changed unless reserved, new fields above the old highest number, new item types anywhere unused). Accepting an
    append-only change: run the test with `EGRF_WRITE_SCHEMA=1`.
  - **Manifest election facts.** `ElectionName`, `ElectionDate`, `ElectionType`, `Jurisdiction`, `Location`: optional
    strings, informational, not validated (the date is free text, RFC 3339 full-date recommended), declared after
    `HashTrimmingFunction` with `JsonIgnore(WhenWritingNull)`, so the written form of every existing manifest is
    byte-identical and no H_B moved. A member written as JSON `null` reads as absent (as `hashTrimmingFunction`
    already did); the class remarks now say "no required member, list or list entry may be null".
  - **Manifest tolerance is the manifest reader's only.** `ManifestSerializer` sets `UnmappedMemberHandling.Skip` on
    its own options; `StrictJson.CreateOptions()` keeps `Disallow`, so the record, device-chain and pre-encrypted
    readers still refuse unknown members. Writing drops unknown properties (the model does not hold them).
  - **Statuses.** `RecordStatus` accepts Cast, Challenged and Spoiled, once. `EncryptedTally.AddBallot` skips
    Challenged and Spoiled and fails `"9.structure"` on anything else, undeclared values included. No reader refuses
    an undeclared status at decode time (the serializers that would retire in S10b-16 decode it as given; tallying
    refuses it). A pre-encrypted record marked Spoiled is refused like any non-cast one
    (`"15/16/17.structure"`), since its spoiled counterpart is the uncast item. Spoiled is not decrypted by this
    library's paths: the nonce path and V13/V14 already required Challenged; tests now pin Spoiled there. (Review
    round 1: that status test reads the requester's claim and the guardian's Q31 view holds cast ballots only, so a
    spoiled ballot relabelled Challenged would be opened, as an unrecorded one already could; the record's section
    seal and signatures protect the status. Whether a guardian should also refuse a match against a spoiled ballot
    of the sealed record is left to S10b-9/S10b-19.)
  - **Oneof members are messages (S8; review round 1).** W2 writes a set oneof member even at its default, so a
    scalar member would put an explicit VARINT 0 on the wire, which W6 tells an older reader to reject in an unknown
    field. Of the two fixes offered, the lint now refuses scalar oneof members (`RecordItem` complies; no bytes
    change) rather than W6 dropping "an unknown VARINT is not 0". Recorded in design §11 so the user can overrule it.
  - **Compact items and V17/V19 (review round 1).** A compact uncast item records no short codes or labels, and χ
    binds the contest index, not text, so 17.A and 19.A-D hold by construction on it. The design states this as a
    third divergence for the formal spec, and the report counts compact items as ones whose 17.A/19.A-D held by
    construction (§6.9), not as a new `VerificationOutcome` value (outcomes are per verification, not per item).
    It is the main practical difference between R-1's options for returned ballots (design §12).
  - **Nonce DTO (S10b-0).** Deleted `ProtobufEncryptedValueWithProofs.EncryptionNonce`, the `ToEncryptedValue()`
    method and the unused `ProtobufEncryptedValue` struct, and the mapping's `EncryptionNonce = s.EncryptionNonce`.
    The wire bytes are unchanged (the members never had `[ProtoMember]`).
  - **Console.** The first ballot is encrypted a third time as `<id>-spoiled`, appended to the device chain and
    recorded Spoiled. It is published with the others and passes V5-V8 (per ballot and per device); it is not
    tallied (tally unchanged: 0-0: 3, 0-1: 0) and not decrypted. Output only (`encrypted-json-ballots/0-spoiled.json`
    in C:\temp\eg\data\1); no input file changed.

## Stages

| Stage | G-IDs | Blocked on | Status | Commit |
|---|---|---|---|---|
| S1 Hash encodings, indices, canonical order | G1, G6, G7, G35, G26 (1.F compare and constructor reuse), G12, G9 | — | done | 3cec099 |
| S2 Key-generation hardening | G5, G14, G15, G25, G34, G26 (H_B in record and guardian check) | S1 | done | 6fbc25c |
| S3 Ballot verification strictness | G4, G13, G33, G23, G24, G36; plus the push security-review findings on V8 (missing completeness/validation checks: ballot contest set vs ballot style, option set vs manifest, duplicates) | — | done | 7ae4cfc |
| S4 Tally soundness | G2, G27, G28, G20, G21, G30, G38, G16 | — | done | c549325 |
| S5 Supplemental fields redesign (with S5b: user follow-up decisions Q11-Q16) | G3, G8, G22, G29, G10 | — | done | 27e75e2 (+ S5b f8a0699, S5c) |
| S5c Null-vote relation gains the overvote term (Q17) | G22 (Q17 follow-up) | S5b | done | 567e7a6 |
| S6 Contest data | G11, G32 | after S4 | done | e6d7be0 |
| S7 Ballot nonce and challenged ballots | G17, G18 | after S4 | done | 90ea38b |
| S8 Chain closing | G19, G37 | — | done | d60a56b |
| S9 Pre-encrypted recording tool | G31 (now primitives + verifications; the tools are out of scope, user decision Q35) | after S5, S7 | done (nonce-decryption gate: S9b); partly superseded by S9c (encrypting and recording tools removed per Q35) | 97aac86 |
| S9b Nonce-decryption authorization gate (Q31) | Q31 / S9-6; the security review finding on S7's `TallyGuardian.DecryptBallotNonce` (caller-controlled Status) | S9 | done; partly superseded by S9c (pre-encrypted half, issued list and once-only state removed per Q35; the cast-ballot record check stays) | 5d5e43c |
| S9c Pre-encryption scope: primitives only (Q35) | remove encrypting/recording tools and guardian pre-encrypted nonce path | after S9b | done | 99296bd |
| S10a Record correctness gaps (Q37 part A) | G40 (G39 won't fix, per Q9); S2 carry-overs: bind the parsed `Manifest` to `ManifestFile` (S2 review R1), record JSON round trip; S3/S5 carry-over: typed errors for malformed ballot documents; S4 carry-overs: a `DecryptedTally` record serializer, and a tally loaded from a record must carry or recompute each option's `MaximumCount` (S4 review R1/F2); S6/S7 carry-overs: `DecryptedContestData` and `DecryptedChallengedBallot` serializers | — | done | see next commit |
| S10b Canonical ElectionRecord bundle (Q37 part B) | streaming, multi-representation election record (EGRF v2, `2026-10-08-election-record-design.md`); verify-everything entry point; device-close signing/timestamp (S8b). Split into the stages below, one per design step (§9.2) | S10a; the design (answers recorded 2026-10-09) | in progress | |
| S10b-A EGRF groundwork | design update for NQ-1..NQ-6; S10b-0 nonce DTO cleanup; S10b-1 statuses (`Unrecorded`, `Spoiled`); S10b-1b manifest election facts and unknown-property tolerance (NQ-1, NQ-4); S10b-2 schema at `proto/electionguard/egrf/v2/egrf.proto`, codegen, schema lint | S10a | done (gate green; awaiting commit) | |
| S10b-3 Canonicality checker | Method A and B (unknown fields per NQ-1 / W6), D1-D6, segment header, signed statements; first golden and negative vectors | S10b-A | todo | |
| S10b-4 Domain mappers | one mapper per item; `RawZp`/`RawZq` range attribution; uncast split/join with the compact form (NQ-2); `RecordSetup`; reflection completeness test | S10b-3 | todo | |
| S10b-5 Merkle, TOC, phase roots | RFC 9162 frontier and proofs; TOC; phase roots | S10b-A | todo | |
| S10b-6 Directory carrier | writer and reader; frame ceiling; layout rules; phase gates; `DeviceSectionWriter` (`UncastDisposition`); torn tails | S10b-4, S10b-5 | todo | |
| S10b-7 `.zip` carrier | STORED/DEFLATE, ZIP64, local/central check; non-seekable input spooled (NQ-6) | S10b-6 | todo | |
| S10b-8 Streaming verifier pieces | `DeviceChainWalker`, `SpillingIdentifierSet`, `BallotAggregationVerifier.Merge`, join cursors | S10b-A | todo | |
| S10b-9 `VerifyAllAsync` | steps A-F, profiles, report (`Complete` informational for a newer minor; compact items counted as 17.A/19.A-D held by construction), checkpoints, `VerifiedAggregate`; tests that a spoiled ballot's id_B is in 5.A (a spoiled ballot sharing id_B with a cast one fails 5.A); decide, with S10b-19, whether a guardian refuses an id_B/H_I/C_ξB,0 matching a spoiled ballot of the sealed record (S10b-A review round 1) | S10b-6, S10b-8 | todo | |
| S10b-10 JSON projection, converter, diff | proto3 JSON with duplicate-member refusal; `ConvertAsync`; `DiffAsync` | S10b-6 | todo | |
| S10b-11 Attestations and signatures | statements, signers, verifiers, policies | S10b-9 | todo | |
| S10b-12 Python reference reader and golden records | `test/egrf/egrf_ref.py` (Method A with W6), golden records, schema-table diff against `test/egrf/schema.json` | S10b-6, S10b-7 | todo | |
| S10b-13 TypeScript reader | protobuf-es conformance reader | — | deferred (NQ-3: "Defer") | |
| S10b-14 `ElectionGuard.Verifier` | `egrecord` CLI | S10b-9, S10b-10 | todo | |
| S10b-15 Migration of the consumers | console, egperf `writeRecord`/`verifyRecord`, Testing.Cli, `test/data/*` | S10b-9, S10b-10 | todo | |
| S10b-16 Retire superseded code | old DTO tree, protobuf-net, JSON ballot/record serializers | S10b-15 | todo | |
| S10b-17 Live tailing | may be deferred | S10b-9 | todo | |
| S10b-18 Documentation and publication | CLAUDE.md record bullet, formal-spec skeleton, registered option numbers (user action) | S10b-16 | todo | |
| S10b-19 Guardians open uncast pre-encrypted ballots (NQ-5) | `TallyGuardian.DecryptBallotNonce` opens an uncast pre-encrypted item from a sealed, verified record; refuses an id_B cast in it (Q31); no issued list, no once-only state; with S10b-9, decide whether it also refuses an id_B/H_I/C_ξB,0 matching a spoiled ballot of the sealed record (today the Q31 view holds cast ballots only, so a spoiled ballot relabelled challenged is opened; S10b-A review round 1) | S10b-9 | todo (after S10b) | |

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

S7: no existing hash, nonce, ciphertext, contest hash, confirmation code or KAT value moved (every pre-S7 family
passed before and after). C_ξB was already computed with the spec's bytes and is not hashed into eq. (70) or (71).
What changed: every encrypted ballot now carries `encryptedBallotNonce` (JSON) / field 10 (protobuf), so serialized
ballots grow (smoke: JSON about 20.1 -> 20.9 KB, protobuf 11,824 -> 12,444 bytes). The eight new families are pinned
only by `KnownAnswerTests.ChallengedBallots.cs`; no test holds a literal. No test was re-pinned. The console's
`tally.json` counts are unchanged; it also writes `challenged-ballots.json`.

S7 review round 1: no pinned value moved and no test was re-pinned. The gate was green before any test edit. V13
gains one comparison (13.A: g^ξ = C_0), and an honest record never meets it.

S7 review round 2: no pinned value moved and no test was re-pinned. The library changed only in doc comments; the
round adds tests.

S8: no hash, nonce, ciphertext, contest hash, confirmation code or KAT value moved (every pre-S8 family passed before
and after; `chain_init` and `confirmation_code` go through the refactored `ChainingField` unchanged). What changed:
every encrypted ballot now carries `chainingField` (JSON) / field 11 (protobuf), so serialized ballots grow (smoke:
protobuf 12,444 -> 12,482 bytes, JSON about +60 bytes). The six chaining families are pinned only by
`KnownAnswerTests.Chaining.cs` (and `ChainInitialization_Eq74And75`); no test holds a literal. One behavior pin was
re-pinned (`ConfirmationCodeVerificationTests...MismatchedPreviousConfirmationCode`, 8.B -> 8.E; see the S8 log).
The console's `tally.json` counts are unchanged; it also writes `device-chains.json`. New committed fixture:
`test/data/single-contest-chained/manifest.json` (scenario `chained`).

S9: no existing hash, nonce, ciphertext, contest hash, confirmation code or KAT value moved, and no test expectation
was re-pinned. The orchestrator's oracle extension appended vectors that six existing KAT tests could not read
(they failed on the extended `vectors.json` before any S9 test edit): `PreEncryptedConfirmationCode_Eq116` x4 (the
appended P1/P2 vectors use H_I values outside `selection_encryption_identifier_hash` and a second
`preencrypted_chain_init`), `OracleChain_AsADeviceRecord_VerifiesAndDetectsTampering(preEncrypted: True)` (two
chain-init vectors) and `EveryVectorFamilyIsCheckedOrExplicitlyUnsupported` (six new families). Their lookups were
adapted (H_I from the `preencrypted_ballots` summary, chain-init by device, B_C read from the vector); no expected
value changed. The new families are pinned only by `KnownAnswerTests.PreEncryption.cs`, which also rebuilds P1
(cast) and P2 (uncast) end to end; no test holds a literal. Regular ballots serialize as before (protobuf 12,482
bytes in smoke, unchanged). The console's `tally.json` counts are unchanged; it also writes a `pre-encrypted/`
subdirectory. Fixture default: `ElectionFixtureBuilder.CreateMinimalManifest(hashTrimmingFunction: ...)` now
declares no supplemental fields (the new Manifest rule), which the existing pre-encryption tests rely on.

S9c: no pinned value moved and nothing was re-pinned; `test/kat/vectors.json` is unchanged. P1 and P2 are now rebuilt
through `PreEncryptionPrimitives` and the test-only `PreEncryptedBallotFixtures` (the S1 rows above that name
`BallotPreEncryptorTests` now refer to `PreEncryption/PreEncryptionPrimitivesTests.cs`, same assertions). The console
no longer writes a `pre-encrypted/` subdirectory (a stale one from earlier runs may remain under `C:/temp/eg/data/1`;
it is output, not gate input). S9c review round 1: no pinned value moved either (three tests added, none re-pinned).

S10a: no hash, nonce, ciphertext, contest hash, confirmation code or KAT value moved; `git diff test/kat/` is empty and
every KAT family passes. No test expectation was re-pinned. What moved, by design:
- Fixture manifests are written in `ManifestSerializer`'s form (`CreateMinimalManifest` used default
  System.Text.Json, PascalCase), so every fixture election's H_B, and with it H_E and everything downstream, differs
  from S9c. No test holds a literal for them.
- The KAT tests that build records (`Encryption_ReproducesTheContestHashAndConfirmationCodeVectors`,
  `TallyDecryptionProof_Eq86To93_AndVerification10`, `Encryption_WithContestData_...`,
  `ContestDataDecryptionProof_Eq96To106_AndVerification12`, every user of `MainChainRecord`) now pass the shaping
  manifest as the record's file and keep the oracle's H_B/H_E as claims; `TallyDecryptionProof_...` sets the
  contest's `CastWeight` to 3 where it set `MaximumCount` to 3 (same bound, asserted). Inputs and expected values are
  unchanged.
- The committed manifests' written bytes equal the `PerfJson.LineOptions` bytes the harness hashed before, so
  `manifestHash` is unchanged (`sha256:a2ec0152...` for `smoke`) and S9c perf records stay comparable.
- Every encrypted ballot the encryptor makes carries an encryption timestamp: smoke protobuf 12,482 -> 12,489 bytes,
  JSON about +50 bytes. Contest hashes and confirmation codes are unchanged (the timestamp is not hashed).
- The console's `tally.json` is now the record serializer's (camelCase, with `contestIndex`, `choiceIndex`, `t`,
  `challenge`, `response`); `contest-data.json` and `challenged-ballots.json` likewise; `encrypted-tally.json` is
  new. Counts unchanged (0-0: 3, 0-1: 0). No input under `C:/temp/eg/data` changed, so no .bak.

## Log

### 2026-10-09 — S10b-A review round 2 (ignored manifest values still text, nesting limit stated, spoiled ballots fail V6-V8)
Worktree changes only; nothing committed. Three minor findings (spec, code, tests); all applied. The spec and code
findings are the same defect. No hash input, KAT, fixture or pinned value moved, nothing was re-pinned,
`test/egrf/schema.json` is unchanged (one proto comment changed). Decision added under "S10b-A design and API choices":
an ignored manifest value is still text.

Per finding:
- **Spec / Code (an unknown manifest property's value is never decoded).** Correct. Probes against the round-1
  build: raw `0xFF 0xFE` or `"\uD800"` in an unknown value was accepted, and refused in a known one.
  `StrictJson.RejectAmbiguity` now refuses a document that is not well-formed UTF-8 (`Utf8.IsValid`, up front) and
  decodes every escaped string token (`GetString` on `String` tokens with `ValueIsEscaped`; unescaped ones are already
  valid by the UTF-8 check), translating the reader's `InvalidOperationException` as for property names. Chosen over
  calling `GetString` on every string: no extra allocation for the record readers' long base64 strings. The depth
  limit (64, the top-level object being level 1) is kept and documented: `ManifestSerializer` remarks, design
  ManifestFile paragraph, egrf.proto `media_type` comment, `StrictJson` summary, CLAUDE.md, and
  `JsonElectionRecordSerializer`'s remarks for the text rule. Tests (`ManifestSerializerTests`): `Malformations` rows
  "known value a lone high surrogate", "unknown value a lone high surrogate", "unknown nested value a lone low
  surrogate"; `Deserialize_NotUtf8_ThrowsInvalidManifestException` (6 rows: unknown value 0xFF 0xFE, an encoded
  surrogate ED A0 80, an overlong C0 AF, a truncated E2 82 inside an array, an unknown property name 0xFF, a known
  value 0xFF; each checks the untampered placeholder reads and the refusal names UTF-8);
  `Deserialize_UnknownValueNestedTo64Levels_IsRead_And65AreRefused`; and, added after the gate (test only; the
  manifest tests re-ran 51/51, so Core is now 2114), `Deserialize_AcceptsEscapedSurrogatePairs_KnownAndUnknown`: the
  writer's `🗳` pair round-trips and a pair in an unknown value reads, so the lone-surrogate refusal does
  not reach pairs. Mutation check: with both new checks disabled,
  the two unknown-surrogate rows and five of the six UTF-8 rows fail (the four unknown-value rows refused nothing;
  the known-value row was refused by the deserializer, but without naming UTF-8). The property-name row still passes,
  because names were already decoded.
- **Tests (spoiled ballot checked by V6-V8 only positively).** Correct. `SpoiledBallot_InTheChain_...` now also
  breaks the spoiled ballot three ways and asserts the sub-section: a selection proof response + 1 fails `"6.D"`, a
  contest proof challenge + 1 fails `"7.D"`, a flipped confirmation-code byte fails `"8.B"`. A status filter in V6,
  V7 or V8 would make these throw nothing.

Gate (before and after are one run; nothing was re-pinned; no test failed after the edits):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`; `EncryptBallots     245       0.245       165.7      0.1657      12/3/2     1,000`,
  `VerifyBallots      1,005     1.005       12.2       0.0122      0/0/0      1,000`, VerifyTally 0.004, DecryptTally
  0.035, VerifyDecryption 0.008 ms/ballot; a second run 0.244 / 0.990, Tally 0.008. No hot path changed (round 1:
  0.240 / 0.981): noise.
- Console: all verifications ran, `Tally, contest 0: 0-0=3, 0-1=0, ...`, `Done.`, then the expected ReadKey
  InvalidOperationException; tally.json 0-0 voteCount 3, 0-1 voteCount 0.
- Tests: Perf 231/231; Core 2113/2113 (2103 plus 3 `Malformations` rows, 6 UTF-8 rows and 1 depth test).

Carry-overs unchanged from round 1 (S10b-9 5.A spoiled id_B test, compact-item report, spoiled-match refusal with
S10b-19); R-1..R-3 still await the user.

### 2026-10-09 — S10b-A review round 1 (compact items and V17/V19, scalar oneof members, spoiled-ballot wording, lint and status test gaps)
Worktree changes only; nothing committed. Eight findings (three spec, one code, four tests); all applied, one
narrowed. No hash input, KAT, fixture or pinned value moved, nothing was re-pinned, and `test/egrf/schema.json` is
unchanged (only proto comments changed; the descriptor is the same). Decisions added under "S10b-A design and API
choices": oneof members are messages (S8), and how the report shows compact items for V17/V19.

Per finding:
- **Spec 1 (compact items cannot fail V17/V19).** Correct: 17.A (p.65) checks the short code "displayed with the
  selectable option", 19.A-D (p.67) the text labels "on the uncast pre-encrypted ballot", and eq. (115) hashes
  ind_c(Λ) and ψ, not labels. The compact item records neither, so they hold by construction. Design §3.2 (table row,
  a new paragraph, the narrowed claim "proves the ballot's ciphertexts, ψ and χ were the regenerated ones", a third
  divergence for the formal spec), §3.3 rows 17/19, §6.2 compact row, §6.9 (the report counts compact items as
  held by construction), the S10b-9/S10b-19 plan rows (V16 and V18, not V16-V19), §12 R-1 (the main difference
  between (a) and (b) for returned ballots), the status note, and the comment above
  `PreEncryptedCompactUncastBallot` in egrf.proto.
- **Spec 2 (W6's "unknown VARINT is not 0" vs a scalar oneof member).** Correct: W2 writes a set member at its
  default. Took option (a): S8 now requires oneof members to be messages, enforced by `EgrfSchemaLint` (new
  violation "is a member of oneof ... oneof members are messages"); design §4.2.1 S8, W6, Method A's comment, §11,
  and the egrf.proto header. Option (b) would weaken W6 for every record; (a) changes no bytes.
- **Spec 3 / Tests 3 (spoiled ballots and 11.D).** Added
  `TallyContentsVerificationTests.Verify_ContestIdsFromSpoiledBallotsCount`: the only ballot passed is spoiled and
  the tally lacks its contest, so it fails 11.D, and fails the test if the ballot-taking overload ever filters
  spoiled ballots. The spoiled-ballot test's summary now points there instead of claiming 11.D. Its relabel-as-cast
  assertion now pins `"9.A"` (V9 aggregates cast ballots only; 9.A comes before the cast-weight check). **Narrowed:**
  the 5.A case (a spoiled ballot sharing id_B with a cast one) cannot test status handling today, because
  `SelectionEncryptionIdentifierVerification.Verify` takes identifiers, not ballots; it is added to the S10b-9 row,
  where the record verifier collects them.
- **Code 1 ("never decrypted" overclaims).** Correct; doc only. `BallotStatus.Spoiled`'s summary, CLAUDE.md's Tally
  paragraph, design §3.2's divergence, §3.3's paragraph, §6.2's row and §8.3's enum comment now say "not decrypted
  by this library's paths", that the status test reads the requester's claim, that the Q31 view protects cast
  ballots only, and that the section seal and signatures protect the status (S10b-6+). The S10b-9 and S10b-19 rows
  carry the open question of refusing matches against spoiled ballots. No code change.
- **Tests 1 (append-only core check not isolated; major).** `AppendOnly_CatchesEachBreak` now takes the expected
  text and asserts the break produces exactly one violation containing it. "Below the highest number" adds DeviceClose
  field 5 under a published table that already has field 6 (the real schema has no gap below a highest number), and
  "at a reserved number" keeps `reserved 3`; neither touches a reservation. New row: a `RecordItem` member at the
  reserved 2047 (reservation kept) is rejected. Mutation check: disabling the numbering check fails those three rows.
- **Tests 2 (S8 range check masked by the RecordItem rule).** The range case is now a oneof in DeviceClose (message
  members 5 and 7, regular field 6); the RecordItem case moved to field 3000, above the member range. All 19
  `Lint_CatchesEachBreak` rows now assert exactly one violation with the expected text (the "omittable without a
  width" row moved from SignedStatement, whose field 5 exists, to DeviceClose). Mutation check: disabling the range
  loop fails the range row.
- **Tests 4 (R-3 rows).** The four near-miss rows moved out of `Malformations` into
  `NearMisses_AreRefused_ReadingR3`, a block marked as depending on R-3 (delete it with `RejectNearMisses` if the user
  picks R-3(b)); each asserts a `JsonException` inner exception whose message says "reads as its member", which also
  shows the `ElectionId` row fails on the near-miss path, not only on the missing required member.

Gate (before and after are one run; nothing was re-pinned; no failing tests at any point after the edits):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`; `EncryptBallots     240       0.240       165.8      0.1658      12/3/2     1,000`,
  `VerifyBallots      981       0.981       12.2       0.0122      0/0/0      1,000`, Tally 0.008, VerifyTally 0.004,
  DecryptTally 0.034, VerifyDecryption 0.009 ms/ballot. No runtime code changed (S10b-A: 0.244 / 0.988).
- Console: all verifications ran, `Tally, contest 0: 0-0=3, 0-1=0, ...`, `Done.`, then the expected ReadKey
  InvalidOperationException; tally.json 0-0 voteCount 3, 0-1 voteCount 0.
- Tests: Perf 231/231; Core 2103/2103 (2099, plus 2 lint rows, 1 append-only row, 1 spoiled 11.D test and 4 R-3
  rows, minus the 4 rows moved out of `Malformations`).

Carry-overs: S10b-9 (5.A test for a spoiled id_B; report counts compact items; spoiled-match refusal question with
S10b-19). R-1..R-3 still await the user.

### 2026-10-09 — S10b-A (EGRF groundwork: design update for NQ-1..NQ-6, nonce DTO cleanup, statuses, manifest fields, .proto + codegen + lint)
Worktree changes only; nothing committed. Implements design steps S10b-0, S10b-1, S10b-1b (new: the manifest
changes) and S10b-2, and applies the user's answers NQ-1..NQ-6 ("EGRF v2 new questions, answered 2026-10-09") to the
design document and the schema. No hash input, KAT vector (`git diff test/kat/` empty), committed fixture
(`git diff test/data/` empty) or pinned value moved, and nothing was re-pinned. Decisions: "S10b-A design and API
choices" under Decisions; three of them are readings for the user to confirm (design §12, R-1..R-3).

Per item:
- **Q37 part B / design (NQ-1..NQ-6), `2026-10-08-election-record-design.md` revision 3.**
  - NQ-1: the per-item `extensions` list is removed (2047 reserved). The canonical profile changes from "no unknown
    fields" to "unknown fields only after every known field, in field-number order, numbered above every declared or
    reserved number, kept on re-encoding": S6 (append-only, checked against `test/egrf/schema.json`), W6 rewritten,
    D2/D5 re-checked, D7 removed (rules are now D1-D6), Method A's pseudo-code gains the unknown-field branch, and
    Method B now **keeps** unknown fields (the opposite of revision 2's advice), with the discard parse kept as the
    one-pass form of "no unknown field" for a record of the reader's own minor. A newer `format_minor` is
    informational: `Passed` = no failures, `Complete = false` beside it (§6.9, §7, risk 16; reading R-2). §5.1:
    unknown fields survive protobuf re-encoding but cannot be converted to JSON (`R.version`). `R.extension` is gone.
    The manifest stays JSON stored byte for byte, its reader ignores unknown properties (§4.6, §9.3, §13).
  - NQ-2: `PreEncryptedCompactUncastBallot` (RecordItem 16): id_B, H_I, style, C_ξB, per contest (index, χ), H_C, B_C.
    Mandatory for never-returned ballots; the form follows from whether ξ_B is released (reading R-1); the release
    carries `ballot_nonce` alone for it and `contests` alone for a full item (§3.2, §4.2.3, §4.5, §4.7, §5.2, §6.2,
    §8.3 `UncastDisposition`, §10).
  - NQ-3: S10b-13 deferred. NQ-4: `RecordHeader` = `format_major`, `format_minor` (field 3 reserved); election facts
    are manifest fields (§3.1, §4.6, §8.3). NQ-5: new step S10b-19 (guardians open an uncast pre-encrypted ballot from
    a sealed, verified record; refuse an id_B cast in it; no issued list, no once-only state), referenced from §1,
    §3.2, §6.9. NQ-6: unchanged design (spool a non-seekable input), wording updated.
  - §11 gains a row per answer, with the user's words; §12 now lists only the three readings; §4.6 links the schema
    instead of embedding it; §8.1/§8.2 record the codegen as built and the `RecordFormat` namespace; §9.1/§9.2 mark
    S10b-0/1/1b/2 done and add S10b-1b and S10b-19.
  - `protoc` (Grpc.Tools 2.80.0, libprotoc 31.1) compiles the edited schema to C# and Python:
    `protoc -I proto -I <grpc.tools>/build/native/include --csharp_out --python_out --descriptor_set_out
    --include_imports proto/electionguard/egrf/v2/egrf.proto` succeeded, and the Core build compiles it.
- **S10b-0, nonce DTO (Q37 part B).** `IEncryptedBallotSerializer.cs`: the mapping no longer copies
  `s.EncryptionNonce`; `ProtobufEncryptedValueWithProofs.EncryptionNonce`, its `ToEncryptedValue()` and the unused
  `ProtobufEncryptedValue` struct are deleted. The wire format is unchanged. The test that asserted the DTO members
  read back null (`RoundTrip_DoesNotAttemptToSerializeEncryptionNonce`) can no longer compile and is replaced by
  `SerializationDtos_HaveNoNonceMember_AndNoNonceReachesTheWire`: reflection over every DTO type (no member named
  `*Nonce*` except `EncryptedBallotNonce`, the ciphertext) plus a search of a real ballot's protobuf bytes for each
  option and field nonce.
- **S10b-1, statuses.** `BallotStatus.NotSubmitted` → `Unrecorded` (0, in memory only); `Spoiled = 3`.
  `RecordStatus` accepts Cast, Challenged or Spoiled, once. `EncryptedTally.AddBallot` (and so V9) skips Challenged
  and Spoiled and fails `"9.structure"` on anything else. The nonce path and V13/V14 already required Challenged; the
  pre-encrypted cast record already required Cast. Doc comments of V5.A and V11 now say "submitted" = cast,
  challenged and spoiled. JSON (status as a number) and protobuf (field 9) carry 3 unchanged. The console encrypts the
  first ballot a third time and records it Spoiled (5 ballots on the device).
- **S10b-1b, manifest (NQ-4, NQ-1).** `Manifest.ElectionName`, `ElectionDate`, `ElectionType`, `Jurisdiction`,
  `Location` (optional strings, informational, omitted when null, so no manifest's written form or H_B moved).
  `ManifestSerializer` ignores unknown properties at every level (own options with `UnmappedMemberHandling.Skip`;
  the record readers keep `Disallow`), refuses near-miss names (reading R-3), and still refuses duplicate keys (known
  or not), a BOM, comments, trailing commas, wrong types, nulls where required and missing required members.
- **S10b-2, schema + codegen + lint.** `proto/electionguard/egrf/v2/egrf.proto` is the one normative copy
  (`docs/spec-compliance/egrf_v2.proto` deleted). Core: Google.Protobuf 3.34.1, Grpc.Tools 2.80.0 (build-only),
  generated types internal in `ElectionGuard.Core.RecordFormat.Protobuf`. Tests in
  `test/ElectionGuard.Core.UnitTests/RecordFormat/`: `EgrfSchemaLintTests` (S1-S8 on the compiled descriptor; 17 broken
  copies, one per rule kind; the schema table `test/egrf/schema.json` and the append-only check with 9 negative and one
  positive case; NQ-1/NQ-2/NQ-4 shape; generated types internal and status numbers equal to the domain's) and
  `EgrfUnknownFieldBehaviourTests` (C# keeps unknown fields after the known ones, in the order read; discard
  shortens; an unknown field before a known one is moved; a descending unknown tail survives, which is why Method A's
  unknown-field branch is required for newer-minor records). No mappers, readers or writers yet.

Re-pinned tests: none. Test expectations changed because the behaviour changed by decision, each with its reason in
the test:
- `ManifestSerializerTests.Malformations`: the "unknown property" row (S10a's refusal) is removed, since NQ-1 makes the
  manifest reader tolerant; `Deserialize_IgnoresUnknownProperties_WhichH_BStillBinds` now asserts the opposite
  (same manifest, different H_B). "property in another case" still fails, now as a near miss; "missing contests" still
  fails, now because the required member is missing (the misspelt one is ignored). Comments say so.
- `ProtobufEncryptedBallotSerializerTests.RoundTrip_DoesNotAttemptToSerializeEncryptionNonce` replaced (above).
- `BallotStatusAndWeightTests.RecordStatus_AcceptsOnlyCastOrChallenged` renamed `..._AcceptsOnlyCastChallengedOrSpoiled`
  (same cases: Unrecorded and 7 refused).
- `NotSubmitted` → `Unrecorded` in six test files and `ElectionFixtureBuilder` (rename only).

New or extended tests (Core 2047 -> 2099, +52; Perf 231 unchanged):
- `BallotStatusAndWeightTests`: `RecordStatus_IsFinal` over all three statuses; `BallotStatus_Values_AreTheRecordFormatsEnumNumbers`;
  `SpoiledBallot_InTheChain_PassesVerifications5To8_AndIsNotTallied` (simple chaining, a spoiled ballot between two
  cast ones: 5.A, 5.B, 6, 7, 8 per ballot and per device pass; the tally counts 2; relabelling it cast fails V9);
  Spoiled cases in the AddBallot skip, V9 leave-out and JSON/protobuf round-trip theories; an undeclared status (4)
  fails 9.structure.
- `ChallengedBallotDecryptionTests`: a Spoiled ballot's nonce request is refused by guardians and administrator;
  V13/V14 fail a Spoiled ballot presented with a decryption.
- `PublishedCastBallotsTests`: a Spoiled ballot is not added as cast. `PreEncryptedRecordVerificationTests`: a
  pre-encrypted record marked Spoiled fails structure.
- `ManifestSerializerTests`: unknown properties at the root, in a contest, an option, a supplemental field and a
  ballot style (objects, arrays, null); election facts round trip, absent by default, null reads as absent; near
  misses (another case, snake case, kebab case), a duplicate unknown key and a fact of the wrong type are refused.
- `RecordFormat/*` (35 tests, above).

Gate (all code and test changes in; no pinned value broke, so the gate before re-pinning is also the gate after):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`.
  - EncryptBallots 244 ms wall, 0.244 ms/ballot, 165.7 MB.
  - VerifyBallots 988 ms wall, 0.988 ms/ballot, 12.2 MB.
  - Tally 8 ms, VerifyTally 4 ms, DecryptTally 36 ms, VerifyDecryption 8 ms.
  - json 8,891 ser/s, 5,878 deser/s, 21,237 bytes; protobuf 48,386 ser/s, 40,581 deser/s, 12,489 bytes.
- Console: `Writing out guardian record.`, `Writing out encryption record.`, `Device Device 1: 5 ballots, chaining mode
  None.`, `Ballot 0, contest 0: contest data "Write-in: Ada Lovelace".`, `Challenged ballot 0-challenged, contest 0:
  0-0=1, 0-1=0, contest data "Write-in: Ada Lovelace".`, `Tally, contest 0: 0-0=3, 0-1=0, overvotes=0, null-votes=0,
  undervotes=0, undervote-difference=0, write-ins=0.`, `Done.`, then the expected ReadKey `InvalidOperationException`.
  `tally.json` has 0-0: 3, 0-1: 0. New output `encrypted-json-ballots/0-spoiled.json`; no input in C:\temp\eg\data
  changed.
- Tests: Perf `Passed: 231, Total: 231`; Core `Passed: 2099, Total: 2099`.

Perf: no hot path changed (the only runtime change on the pipeline is `AddBallot`'s status test). Smoke vs S10a
(0.237 Encrypt, 1.007 Verify ms/ballot): 0.244 / 0.988, and a second run 0.242 / 0.990, allocation 165.7-165.8 MB and
12.2 MB as before. Noise (S10a's own runs spanned 0.242-0.249 and 0.999-1.019).

Carry-overs:
- To the user: R-1 (compact iff ξ_B released), R-2 (newer minor informational), R-3 (near-miss manifest names);
  design §12.
- To S10b-3: Method B on the hot path with the discard parse for same-minor records and Method A for newer ones; the
  W6 negative vectors of §5.7.
- To S10b-4/S10b-6: the compact form and `UncastDisposition`; a mapper for the manifest's election facts is not
  needed (they ride in the bytes).
- Name clash to keep in mind: generated `ManifestFile`, `BallotStatus`, `EncryptedBallot`, `EncryptedContest` share
  names with domain types; the mappers (S10b-4) must alias one side.

### 2026-10-08 — S10a review round 1 (cast-weight bound, canonical base64, property-name errors, manifest copy, test gaps)
Worktree changes only; nothing committed. Ten minor findings covering seven distinct issues: the cast-weight finding
was raised twice and the pre-encrypted test gap three times. Six issues were fixed. The seventh, the ballot JSON
reader, is recorded as an explicit S10b carry-over, which is the first fix the reviewer offered. Two suggested fixes were changed after evidence, as described below. No hash input, KAT vector
(`git diff test/kat/` empty) or pinned value moved, and no existing test expectation was re-pinned. One existing test
helper was tightened (`PreEncryptedSerializationTests.AssertRefused` no longer accepts a bare `FormatException`).
Decisions: "S10a review round 1 additions" under "S10a design and API choices".

Findings and dispositions:
- **Cast weight trusted on load, `MaximumCount` wraps (spec F1 and code F5, the same defect): fixed.**
  - `MaximumCount` now saturates at `long.MaxValue`. Before, a probe gave -2 for weight `long.MaxValue` with
    MaximumValue 2, and `long.MinValue` for 2^62.
  - `Combine` refuses a negative bound, as well as one above `int.MaxValue`, with `TallyDecryptionException`.
  - `DeserializeEncryptedTally` refuses a weight above `ballotsCast × int.MaxValue` with `JsonException`.
  - `DeserializeEncryptedTally`, `TallyAdmin.Decrypt` and `Combine` now document that Verification 9 must pass
    before a tally read back is decrypted. The console already ran V9 first.
  - Saturation was chosen over the suggested `checked`, because an `OverflowException` from a getter would be one
    more untyped failure.
  - A weight just under the `int.MaxValue` search cap is still accepted at load. Only V9 can tell it is forged, so
    the documented ordering is the defense. A verified-tally API is left to S10b's verify-everything entry point.
- **Ballot JSON reader accepts unknown and repeated members (spec F3): carried over to S10b, not fixed here.**
  - The S10b design (`2026-10-08-election-record-design.md`) replaces this reader. S10b-6 lists "duplicate member"
    among the JSON negatives its codecs must refuse. S10b-9's legacy importer reads today's JSON ballots, and it
    must refuse a document that names a member twice: under last-wins, a second `alpha` changes what eqs. (70)
    and (71) bind.
  - The duplicate scan was not added to the hot reader in this round, which already changes the reader's base64
    path. Unknown members stay accepted because older documents carry retired members.
- **Property names that are not valid text threw a raw `InvalidOperationException` (code F4): fixed.**
  - `StrictJson.RejectAmbiguity` wraps the reader loop and rethrows as `JsonException`. The manifest reader
    therefore reports `InvalidManifestException`, and the record, device-chain and pre-encrypted readers report
    `JsonException`.
  - A dictionary key fails the same way. A probe showed that even `JsonSerializer.Deserialize` lets the raw
    exception out for a lone-surrogate dictionary key. A tally contest id and option id are now covered.
- **Record base64: invalid text threw a bare `FormatException`, and whitespace was accepted (code F7): fixed.**
  - The suggested `reader.GetBytesFromBase64()` fixes only the first half. A probe showed it, and
    `Convert.FromBase64String`, accept `"AA AA"` and `"AA\nAA"`.
  - New `StrictBase64` requires the canonical form, checked by re-encoding the bytes. It throws
    `NonCanonicalEncodingException`, which is a `FormatException`, so existing `FormatException` catches still work.
  - The eight ballot converters, the two pre-encryption converters and `RecordJson.ReadBase64` (behind the record
    converters) all use it.
- **Manifest binding could be split in process, and the docs endorsed it (code F6): fixed.**
  - The `ManifestFile` init accessor parses and keeps its own copy of the bytes.
  - The "or change `record.Manifest`" advice was removed from CLAUDE.md and from `CreateEncryptionRecord`'s remarks.
  - The reorder test is kept and is now commented as a deliberate misuse probe.
  - Read-only collections were not added; the reviewer agreed they are not needed here.
- **V10/V12/V13 value tamperings asserted only the exception type (code F8): fixed**, with each sub-section read
  from the verifier rather than taken from the finding:
  - A changed count fails 10.C (T = K^t).
  - A changed D fails 12.C.
  - A changed σ fails **13.B**, not 13.A as the finding guessed. The released value recomputes another (α, β), so
    another contest hash and H_C. 13.A covers only contest data.
- **Pre-encrypted reader strictness was untested (spec F2, code F9, tests F1): fixed.**
  - New theory `PreEncryptedSerializationTests.Json_AmbiguousOrNonCanonicalDocument_IsRefused` runs over both
    `DeserializeBallot` and `DeserializeUncastBallot`.
  - It covers an unknown member (a name the model does not have, so not a skipped `[JsonIgnore]` member), a member
    named twice, a leading BOM, a lone-surrogate name, and base64 with whitespace.
  - It first checks that the untampered bytes read back.

Tests: Core 2001 -> 2047 (+46); Perf 231 unchanged. New cases:
- **`ElectionRecordSerializationTests`:**
  - Not-base64, whitespace, unused-bit, lone-surrogate and invalid-UTF-8 cases in the encryption-record,
    guardian-record, encrypted-tally, decrypted-tally, contest-data, challenged-ballot and device-chain theories,
    plus a BOM case for the device chain.
  - `EncryptedTally_CastWeightAboveWhatTheBallotsCastCanGive_IsRefused`.
  - `EncryptedTally_ForgedCastWeightDecryptedWithoutVerification9_IsRefusedWithTallyDecryptionException`.
  - `MaximumCount_Saturates_InsteadOfWrapping` (5 cases).
  - `EncryptedTally_SaturatedBound_DecryptionRefusesWithTallyDecryptionException`.
- **`ManifestSerializerTests`:** high and low lone-surrogate names, an invalid-UTF-8 name, and
  `EncryptionRecord_CopiesTheManifestFile_SoTheCallersArrayCannotSplitTheBinding`.
- **`PreEncryptedSerializationTests`:** the theory above (10 cases).

Gate (all source changes in, before any expectation would have been touched; nothing needed re-pinning):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`.
  - EncryptBallots 246 ms wall, 0.246 ms/ballot, 165.8 MB.
  - VerifyBallots 1,019 ms wall, 1.019 ms/ballot, 12.2 MB.
  - Tally 8 ms, DecryptTally 35 ms.
  - json 8,836 ser/s, 5,374 deser/s, 21,217 bytes; protobuf 12,489 bytes.
- Console: `Writing out guardian record.`, `Writing out encryption record.`, `Device Device 1: 4 ballots, chaining mode
  None.`, `Ballot 0, contest 0: contest data "Write-in: Ada Lovelace".`, `Challenged ballot 0-challenged, contest 0:
  0-0=1, 0-1=0, contest data "Write-in: Ada Lovelace".`, `Tally, contest 0: 0-0=3, 0-1=0, overvotes=0, null-votes=0,
  undervotes=0, undervote-difference=0, write-ins=0.`, `Done.`, then the expected ReadKey `InvalidOperationException`.
  `tally.json` has 0-0: 3, 0-1: 0.
- Tests: Perf `Passed: 231, Total: 231`; Core `Passed: 2047, Total: 2047`. There were no failures, so the gate after
  is the same run.

Perf:
- The ballot JSON decode path changed; Encrypt, Verify, Tally and Decrypt did not.
- Two more smoke runs gave Encrypt 0.245 / 0.246 and Verify 1.002 / 1.001 ms/ballot at 165.8 MB and 12.2-12.3 MB.
  S10a gave 0.242-0.249 and 0.999-1.014, so the difference is noise.
- The harness's JSON deser/s fell from 10,048 / 7,877 (S10a) to 5,374 / 5,778 / 6,017. That figure times 100 cold
  iterations without warm-up, and it has swung from 1,073 to 10,048 across earlier runs.
- A warmed-up micro-benchmark (1,000,000 decodes of one escaped 512-byte value) measured the changed step directly:
  - old `Convert.FromBase64String(reader.GetString())`: 1.07-1.11 µs, 1,928 B per value;
  - new `StrictBase64.Read`: 0.49-0.52 µs, 536 B per value;
  - `GetBytesFromBase64`: 0.64 µs, 536 B per value.
- In steady state the new path is about 2x faster and allocates 3.6x less.
- A smoke run with `DOTNET_TieredCompilation=0` (fully optimized JIT from the first call) gave json 17,898 deser/s,
  above S10a's range. The lower default-run figure therefore reflects cold tier-0 JIT of the new methods in the
  harness's 100 iterations, not slower decoding. That run also gave Encrypt 0.243 and Verify 0.997 ms/ballot,
  `correctness passed`.
- The only committed JSON with ballot ciphertexts is `test/kat/vectors.json`, which the KAT tests read and which
  passed.

Carry-overs:
- To S10b: the ballot JSON reader's duplicate-member refusal, and how its legacy importer (S10b-9) handles unknown
  members.
- To S10b: a verified-tally API, so that a tally read back cannot be decrypted before Verification 9.

### 2026-10-08 — S10a (record correctness gaps: manifest binding, strict record round trips, typed errors, tally bound, G40 timestamp)
Worktree changes only; nothing committed. Implements Q37 part A ("A and B"; S10b, the canonical election record bundle,
is designed separately). No hash input, KAT vector (`git diff test/kat/` empty) or pinned value moved; no test
expectation was re-pinned (see the gate below for the setup-only test edits). Decisions taken: "S10a design and API
choices" in Decisions.

**Manifest binding (S2 review R1, security-relevant): closed.**
- New `Serialization/ManifestSerializer` (+ `StrictJson`: BOM and duplicate-member rejection, which .NET 9's
  System.Text.Json does not do, and `StrictEnumNameConverter`): the library's one manifest format, documented in its
  class remarks. `ManifestSerializer.Deserialize` validates (`Manifest.Validate`, which now also refuses null entries
  in the contest, option, supplemental field and ballot style lists and null contest ids in a style, instead of a
  `NullReferenceException`). `InvalidManifestException` gained an inner-exception constructor.
- `EncryptionRecord.Manifest` is derived: setting `ManifestFile` parses it; there is no other way in. H_B (eq. 5)
  stays over the exact file bytes. A forged parsed manifest now needs a forged file, which fails 1.F
  (`ManifestSerializerTests.EncryptionRecord_ManifestWithOtherLimits_ComesWithItsOwnFile_AndFails1F`).
- Consumers: `ElectionFixtureBuilder.CreateMinimalManifest` writes the manifest with `ManifestSerializer`;
  `CreateEncryptionRecord(set, manifest, file)` keeps its signature (86 callers) and throws unless `manifest` is what
  `file` holds. Perf: `ManifestLoader` reads through `ManifestSerializer` (an `InvalidManifestException` becomes the
  tool's `ScenarioConfigurationException`), `ManifestHasher` and `corpus` write its form (same bytes as before for
  every committed manifest; `manifestHash` unchanged). `Testing.Cli` writes its form. The console parses through the
  record. Every committed `test/data/*/manifest.json` and `C:/temp/eg/data/1/manifest.json` parse unchanged (no
  rewrite, no .bak).

**Strict JSON round trips for every record item Core produces: closed** (the S2, S3, S4, S6, S7 serializer
carry-overs). New `JsonElectionRecordSerializer` and `Converters/RecordJsonConverters` (strict hash claims, manifest
file, guardian index, parameters, n/k, K/K-hat); `ParameterBaseHash`/`ElectionBaseHash`/`ExtendedBaseHash` gained
`FromCanonicalBytes` (bytes kept as read); `ElectionPublicKeys.FromKeys` (K, K-hat as stated); `DecryptedChoice.VoteCount`
is now `required`. Before, `EncryptionRecord`/`GuardianRecord` JSON wrote every `HashValue` and `IntegerModP` as `{}`.
`JsonDeviceChainRecordSerializer` and `JsonPreEncryptedBallotSerializer` were checked: both now refuse unknown and
repeated members (the device chain reader also null device ids and null entries), and their hash converters are
width-strict. Every ballot hash type decodes strictly (`ContestHash`, `ConfirmationCode`, H_I, H_DI: exactly 32 bytes).

**Tally decryption bound on load (S4 review R1/F2, S5): closed.** Per-contest `CastWeight` replaces the per-option
accumulator; `MaximumCount` = `CastWeight × MaximumValue`. The tally record carries the cast weight; reading it back
restores every bound, and V9 checks it (`"9.structure"`, after 9.A/9.B). `EncryptedTally.Restore` (internal) rebuilds a
tally from a document; `BallotsCast` became `internal set`. Hot path: `AddBallot` now adds the weight once per contest
instead of once per option.

**Typed errors for malformed ballot documents (S3/S5 carry-overs): closed.** `EncryptedBallotShape` (both decoders) for
scalars, `BallotStructure` (null contest list or entry, null option list or entry) for lists, protobuf missing lists
read as empty. Both ballot readers now share one options instance.

**G40 (§3.7 p.55-56 "the date and time of the ballot encryption"): closed.** `EncryptedBallot.EncryptionTimestamp`,
`BallotEncryptor(..., TimeProvider? clock = null)`, JSON `encryptionTimestamp`, protobuf field 14. Eq. (71) (p.42) and
§3.4 p.41 checked: date and time are only an optional hash input, so none is added and no confirmation code changes
(`EncryptionTimestampTests.EncryptionTimestamp_IsNotAHashInput`).

**Console:** writes and reads back every record item, verifies V1-V14 from the copies, decrypts the tally read back
(which needs the restored bound), and prints the tally.

**Docs:** CLAUDE.md (the manifest-binding bullet replaces the "known gap" text; the tally-bound bullet; the
Serialization bullet: hash widths, decode-time shape check, timestamp, record serializer), `perf/README.md` (corpus
manifest form, `manifestHash` unchanged), XML docs on the touched types (`EncryptionRecord.ManifestFile`/`Manifest`,
`EncryptedAggregateChoice.MaximumCount`, `EncryptedAggregateContest.CastWeight`, `BallotAggregationVerifier.Verify`,
`NonCanonicalEncodingException`, the ballot and record serializers).

**Tests: Core 1843 -> 2001 (+158; Perf 231 unchanged).** New: `Serialization/ManifestSerializerTests` (determinism and
round trip, the documented written form, every committed manifest parses, indentation and member order accepted, 22
malformations -> `InvalidManifestException`, the record's manifest is the file's and has no setter, a non-manifest file
throws, other limits need another file and fail 1.F, the fixture refuses a mismatched pair);
`Serialization/ElectionRecordSerializationTests` (byte-for-byte round trip of each item; V1-V4, the guardians' own
verification, V9 + decryption, V10/V11, V12, V13/V14 on the copies read back; tampered claims decode and fail 1.F/4.A/3;
16 encryption record, 8 encrypted tally, 6 decrypted tally, 5 contest data, 6 challenged ballot and 6 device chain
tamperings; wrong cast weight fails V9 `"9.structure"`; too small a cast weight makes decryption fail closed; an extra
option decodes and fails V9); `Serialization/MalformedBallotDocumentTests` (JSON null lists/entries -> `"N.structure"`
for V6-V9; JSON null or short scalars and protobuf missing scalars -> `NonCanonicalEncodingException`; protobuf missing
lists -> `"N.structure"`; protobuf missing proof lists -> the proof count); `Serialization/EncryptionTimestampTests`
(clock reading in UTC ms, system clock default, not a hash input, both encodings round-trip and omit null, the exact
JSON form, malformed JSON and out-of-range protobuf values refused).

Gate before re-pinning (every source change in; the run that decided whether anything needed re-pinning):
- Build (`--no-incremental`): `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`; EncryptBallots 242 ms wall, 0.242 ms/ballot, 165.8 MB; VerifyBallots 999 ms wall,
  0.999 ms/ballot, 12.2 MB; Tally 8 ms; DecryptTally 34 ms; json 21,247 bytes; protobuf 12,489 bytes.
- Console: `Writing out guardian record.`, `Writing out encryption record.`, `Device Device 1: 4 ballots, chaining mode
  None.`, `Ballot 0, contest 0: contest data "Write-in: Ada Lovelace".`, `Challenged ballot 0-challenged, contest 0:
  0-0=1, 0-1=0, contest data "Write-in: Ada Lovelace".`, `Tally, contest 0: 0-0=3, 0-1=0, overvotes=0, null-votes=0,
  undervotes=0, undervote-difference=0, write-ins=0.`, `Done.`, then the expected ReadKey `InvalidOperationException`.
  `tally.json`: 0-0: 3, 0-1: 0.
- Tests: Perf `Passed: 231, Total: 231`; Core `Failed: 1, Passed: 1842, Total: 1843`. The one failure,
  `BallotAggregationVerifierTests.AddBallot_WeightedBallot_MatchesThatManyUnweightedCopies`, came from a V9
  ballot-count comparison this stage had added; the source was changed (V9 compares cast weights only), not the test.
- Before that gate, test *setup* (not expectations) was adapted where the API change forced it, as interim runs showed:
  with only the manifest binding in, Core failed 233 of 1843 (227 were fixtures that wrote manifests with default
  PascalCase System.Text.Json: `CanonicalOrderTests`, `PreEncryptedElection`, `ChallengedBallotDecryptionTests`,
  `BallotStructureTests`, now `ManifestSerializer.ToManifestFile`), then 6 (tests that handed the record a manifest the
  file did not hold, the gap itself: `TallyAdminSearchRangeTests.Decrypt_ManyChoices_RecoversEveryCount` and
  `Decrypt_ZeroPartialDecryption_ThrowsNamingTheGuardian` (helper builds the file after adding options),
  `ManifestValidationTests.EncryptionRecord_WithInvalidManifest_Throws` and `Validate_UndefinedChainingMode_Throws`
  x2 (the invalid manifest goes in as a file; same `InvalidManifestException`),
  `Encryptors_ManifestReorderedAfterRecordCreation_Throw` (reorders `record.Manifest`, the record's own parse; same
  assertions)). Compile-forced (the `Manifest` init accessor is gone): the record-building helpers of
  `PreEncryptionPrimitivesTests`, `PreEncryptedBallotVerificationTests`, `PreEncryptedRecordVerificationTests`,
  `ContestDataDecryptionTests`, `VerificationTests` and the KAT (see the pinned-value inventory) now pass the other
  manifest as a file; the KAT's `MaximumCount = 3` became `CastWeight = 3`. No expected value changed anywhere.

Gate after (all changes, docs included): build (`--no-incremental`) `0 Warning(s)`, `0 Error(s)`; smoke `correctness
passed`, EncryptBallots 0.249 ms/ballot 165.6 MB, VerifyBallots 1.014 ms/ballot 12.2 MB, json 21,162 bytes, protobuf
12,489 bytes; console as above, `Done.`, `tally.json` 0-0: 3, 0-1: 0, every supplemental count 0; Perf `Passed: 231,
Total: 231`; Core `Passed: 2001, Total: 2001`.

Perf: hot paths touched: `AddBallot` (one add per contest instead of per option), the encryptor (one clock read per
ballot), the ballot decoders (a scalar null walk). Smoke Encrypt 0.242 / 0.249 and Verify 0.999 / 1.014 ms/ballot in the
two runs vs S9c's 0.249 / 1.004 (round 1: 0.243 / 0.993): noise. Allocation unchanged (Encrypt 165.6-165.8 MB vs 165.7,
Verify 12.2 MB). Protobuf +7 bytes per ballot (field 14).

Open question for the user:
- **S10a-1 (manifest file canonicality; interoperable bytes):** the reader accepts any document that meets the strict
  rules, whatever its whitespace and member order, and H_B hashes the file as it is. Options: (a) keep that (the spec
  leaves the representation "implementation specific", and a file written by any tool in the schema works); (b) also
  require the file to be byte-identical to `ManifestSerializer.Serialize` of its parse, so one manifest has exactly one
  file and one H_B. (b) would make every committed manifest except the ones written compact fail to load until
  rewritten (the test/data fixtures are indented; the console's too), and a manifest tool in another language would
  have to reproduce System.Text.Json's escaping. Recommendation: (a) now; revisit with the S10b record format.

Carry-overs (to S10b unless noted):
- The record bundle, its streaming reader and the verify-everything entry point (Q37 part B); device closing hashes are
  still unsigned and untimestamped (S8b).
- Verifications 9, 11 and 14 take a bare `Manifest` parameter; callers pass `record.Manifest` (the console does). A
  record-taking overload belongs with the verify-everything entry point.
- The encryption timestamp is unauthenticated (not hashed); only the record's signature (§3.7) can protect it.
- The ballot JSON reader still accepts unknown and repeated members (left as is: it is on the deserialization hot path
  and older documents carry retired members); the record, manifest, device chain and pre-encrypted readers refuse them.
  Made an explicit S10b carry-over in S10a review round 1 (S10b-6/S10b-9 of the record design).
- Base64 in every JSON document is written with System.Text.Json's default escaping (`+` as `\u002B`), as ballots
  always were; readers unescape. Cosmetic.

### 2026-10-08 — S9c review round 1 (per-contest index precondition, Q32 sign-off, S9b-1 exposure pin, null deviceId reader test)
Worktree changes only; nothing committed. Four minor findings, all accepted (one needs no code). No hash input, KAT
vector (`git diff test/kat/` empty) or pinned value moved; no test expectation was re-pinned. No hot path touched.

**Per-contest primitives skip the §3.1.3 index rule (code lens): accepted, fixed.** `GenerateSelection`,
`GenerateContest` and `ProveCombinedContest` take a bare `Contest`; only `GenerateContests` called
`Manifest.Validate`. With option indices {1, 2, 4}, `GenerateContest` numbered the first null vector 5 while
`BallotStructure` (eq. 121, §4.2.1) expects m + 1 = 4, so V16/V17 would reject every such ballot as `N.structure`;
an empty contest threw `ArgumentOutOfRangeException` from `positions[^1]`. Now the three share
`PreEncryptionPrimitives.Positions`: no options -> `ArgumentException` (as `GenerateSelection` already threw), an
option whose index is not its 1-based list position -> `InvalidManifestException` (`Manifest.Validate`'s wording).
With the indices known to be 1..m, the null vectors are m + ℓ and the `OrderBy` / `SingleOrDefault` by index became
list order and `Choices[j - 1]`; bytes are unchanged for every conformant contest (P1/P2 KAT pass). Class remarks
state the contest must be the manifest's own (its contest index cannot be checked here). `Manifest.Validate`'s doc
named "the ballot encryptors' constructors" (one was removed in S9c) and now names `BallotEncryptor` and
`GenerateContests`. CLAUDE.md's index bullet and pre-encryption bullet say so. Tests:
`ManifestValidationTests.Encryptors_ManifestReorderedAfterRecordCreation_Throw` now also covers the three
per-contest primitives; new `PreEncryptionPrimitivesTests.PerContestPrimitives_OptionsNotNumberedOneToM_OrNoOptions_Throw`
({1, 2, 4}, {1, 3}, reversed -> `InvalidManifestException` from each; empty -> `ArgumentException` from each; the
manifest's own contest still generates).

**Q32 sign-off (code lens): accepted, no code change, asked as S9c-R1.** Restoring a refusal would contradict Q35's
confirmed scope line, so the code stays. But the user answered Q32 "Keep" in the same batch as Q35, and the S9c
entry treated Q32 as superseded without asking. The question is now explicit (below), the Q32 decision note says
so, the S9c entry's "not re-asked" is corrected, and CLAUDE.md points at the question and the pinning test.

**No test pins the reopened S9b-1 exposure (tests lens): accepted.** New
`PreEncryptedCastRecordTests.DecryptBallotNonce_UnrecordedPreEncryptedBallotWrappedAsChallenged_OpensIt_KnownExposure_S9b_1`:
a fixture-printed ballot's id_B, H_I and C_ξB in a regular ballot marked challenged; two guardians answer with
`NoCastBallots`; β_B (eq. 108, `TallyDecryptionHashes.LagrangeCoefficient`) and `BallotNonceEncryption.Decrypt` give
ξ_B, which equals the printed ballot's and regenerates its confirmation code through `PreEncryptedBallotFixtures`.
It also asserts that `TallyAdmin.CombineChallengedBallot` publishes nothing (`TallyDecryptionException`: the
wrapper's contests are not under that ξ_B), which does not help since the share holders need no administrator.
(The removed `CombinePreEncryptedBallotNonce` that the old test used is gone, so the combination is spelled out.)
If S9c-R1 is answered (b), flip it to assert the refusal.

**Serializer half of the deleted no-deviceId test (tests lens): accepted, restored.** New
`PreEncryptedSerializationTests.PreEncryptedBallot_Json_NullDeviceId_ReadsAsNull_AndVerification16FailsStructure`:
write a printed ballot, set `"deviceId": null`, read it with `JsonPreEncryptedBallotSerializer.DeserializeBallot`,
assert `DeviceId` is null and V16 throws `16.structure`. The S9c entry's deleted list now says this half was kept.
Also reworded that file's "the recording tool's input" to "what a recording tool reads".

**Tests: Core 1840 -> 1843 (+3); Perf 231 unchanged.**

Gate before re-pinning (all changes in; nothing failed, so nothing was re-pinned):
- Build (`--no-incremental`): `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`; EncryptBallots 243 ms wall, 0.243 ms/ballot, 165.7 MB; VerifyBallots 993 ms wall,
  0.993 ms/ballot, 12.2 MB; json 21,063 bytes; protobuf 12,482 bytes.
- Console: `Device Device 1: 4 ballots, chaining mode None.`, `Ballot 0, contest 0: contest data "Write-in: Ada
  Lovelace".`, `Challenged ballot 0-challenged, contest 0: 0-0=1, 0-1=0, contest data "Write-in: Ada Lovelace".`,
  `Done.`, then the expected ReadKey `InvalidOperationException`. `tally.json`: 0-0: 3, 0-1: 0, every
  supplemental count 0. No input under `C:/temp/eg/data` changed, so no .bak.
- Tests: Perf `Passed: 231, Total: 231`; Core `Passed: 1843, Total: 1843` (no failing test).

Gate after: only CLAUDE.md and this tracker changed after the gate above (every source, XML-doc and test edit was
in it), so it stands as the final gate; a rebuild after the Markdown edits gave `0 Warning(s)`, `0 Error(s)`.

Perf: no hot path changed (pre-encryption generation is test-only here; one O(m) index loop per contest call).
Smoke Encrypt 0.243 / Verify 0.993 ms/ballot vs S9c's 0.243-0.245 / 1.000: noise; allocation and protobuf size unchanged.

Open question for the user:
- **S9c-R1 (security sign-off; follows Q32/Q33/Q35):** with the guardians' pre-encrypted path and the issued list
  removed (Q35), the guardians cannot tell a printed pre-encrypted ballot that is not yet recorded from a regular
  challenged ballot: its id_B, H_I and C_ξB are built the same way (§4.2 "as shown in Section 3.3.4"), so wrapped as
  a challenged regular ballot it passes every check, and k shares give its ξ_B before its voter uses it (pinned by
  the known-exposure test above). Options: (a) accept: keeping such requests from the guardians is the
  deployment's and its recording tool's job, consistent with Q33 ("the guardians will have no knowledge of
  preencryptions until they are submitted as part of the tally process") and Q35; (b) give the challenged path an
  optional guardian-held view of known pre-encrypted id_Bs (like `IPublishedCastBallots`, no once-only state) that
  it refuses on, which reintroduces part of what Q35 removed and needs the guardians to learn of printed ballots
  before they are recorded, against Q33. Recommendation: (a). Not built either way until answered; nothing in the
  code changes under (a).

### 2026-10-07 — S9c (pre-encryption scope: primitives only, user decision Q35)
Worktree changes only; nothing committed. Implements Q35 ("only ... the primitives needed for the preencryption
process. Do not implement (and remove if already implemented) the encrypting tool and recordin tool"; the scope line
confirmed "Yes, that line"). No hash input, KAT vector (`git diff test/kat/` empty) or pinned value moved; no test
expectation was re-pinned. No ballot hot path changed.

**G31 (now "primitives + verifications"; the tools are out of scope by user decision Q35).**
- Removed from `src/ElectionGuard.Core`: `PreEncryption/BallotPreEncryptor.cs` (the §4.2 encrypting tool, which
  predates the audit, 846897e), `PreEncryption/BallotRecordingTool.cs`, `PreEncryption/IssuedPreEncryptedBallots.cs`
  (`IssuedPreEncryptedBallots`, `IssuedPreEncryptedBallot`), `PreEncryptedBallotNonceStatement`, the pre-encrypted
  `TallyGuardian.DecryptBallotNonce(PreEncryptedBallot, ...)`, `TallyAdmin.DecryptPreEncryptedBallotNonce` /
  `CombinePreEncryptedBallotNonce`, the guardian's once-only state (`DecryptedPreEncryptedBallots`, the constructor's
  import and write-ahead callback, `OwnedCopy`, `BeforeConsumingForTesting`), and the refusal reasons `NotIssued`,
  `IssuedNonceDiffers`, `AlreadyDecrypted`, `IssuedPreEncryptedBallot`. Removed from the console:
  `PreEncryptedElectionDemo.cs` and its call.
- Kept: every spec formula (eqs. 113-121, Ω), the published record models (`PreEncryptedBallot`,
  `EncryptedBallot.PreEncryptedContests`, `PreEncryptedUncastBallot`) and their serializers, Verifications 15-19,
  `BallotStructure`'s pre-encrypted checks, `DeviceChain`'s pre-encrypted append/close and the V16 walk.
- New public primitives, `PreEncryption/PreEncryptionPrimitives.cs`: `GenerateSelection`, `GenerateContest`,
  `GenerateContests`, `HasUniqueShortCodes`, `Combine`, `ProveCombinedContest` (+ an internal overload with the KAT
  proof-nonce seam). Generation is the old `BallotPreEncryptor.PreEncryptContest(s)` code moved verbatim (options in
  index order, positions = option indices, the l-th null vector's index = largest option index + l), and the proof
  code is the old `RecordCast` loop, so P1/P2 reproduce the oracle byte for byte.
- Q31 part 2 (the guardian-held cast-ballot check on the challenged path, `IPublishedCastBallots` /
  `PublishedCastBallots`) is kept with its tests; its signatures lost the issued list:
  `TallyGuardian.DecryptBallotNonce(ballot, record, castBallots)`, `TallyAdmin.DecryptChallengedBallot(guardians,
  ballot, record, castBallots)`. `ChallengedBallotStatement.RequireDecryptable` folded back into one instance method.
- Docs: `<see cref>`s to removed members in `EncryptedBallot`, `PreEncryptedRecords`, `PublishedCastBallots`,
  `ChallengedBallotDecryption`, `TallyGuardian`, `BallotEncryptor`, `BallotNonceEncryption`, `BallotStructure` and
  V18 reworded (build: 0 warnings). CLAUDE.md: the DeviceChain sentence, the `Manifest.Validate` call sites, the
  challenged-ballot sentences of the Tally bullet and the pre-encryption bullet (rewritten: primitives-only scope,
  tools out of scope, the primitive list, the test fixture), and the fixture bullet. `perf/README.md` mentions none
  of this: no change.
- Consequence, documented (TallyGuardian `DecryptBallotNonce` remarks, CLAUDE.md); *re-asked in S9c review round 1 as
  S9c-R1 and pinned by a known-exposure test there*: with the issued list
  gone, S9b-1's case is open by design. A printed pre-encrypted ballot not yet recorded is in no cast-ballot view,
  and its id_B, H_I and C_ξB (built as a regular ballot's, §4.2), wrapped as a challenged regular ballot, pass every
  check of the challenged path, so k shares would give its ξ_B before its voter uses it. Q33 ("the guardians will
  have no knowledge of preencryptions until they are submitted as part of the tally process") and Q35 put this
  outside the library: the deployment and its recording tool must keep such requests from the guardians. Carried
  over next to Q-S7b / Q22 (the RLA authorization path). Q32 and S9b-1/S9b-2/S9b-3 are closed by removal of the path.

**Tests (Core 1895 -> 1840, -55; Perf 231 unchanged).** Generation moved to the test-only
`test/ElectionGuard.Testing.Common/PreEncryptedBallotFixtures.cs` (deterministic `PreEncrypt` from id_B and ξ_B; a
random `PreEncrypt` with the §4.1.5 retry; `PreEncryptNext` on a `DeviceChain`; `RecordCast`, which pads to L with
the first null vectors and takes an optional prover; `RecordUncast`), built on the public primitives. It takes ξ_B
from the caller; `PreEncryptedElection` remembers each ballot's ξ_B by id_B (`BallotNonceOf`, replacing the
guardian-decrypting `DecryptNonce`) and its `Guardians` no longer need to be fresh per read.
- Retargeted, same assertions: `KnownAnswerTests.PreEncryption` P1 (cast, every α, β, summed ξ, c_j, v_j) and P2
  (uncast, every released nonce) through the fixture, with the KAT prover calling the internal seam;
  `PreEncryptedBallotVerificationTests` (V16/V17), `PreEncryptedDeviceChainTests` (devices built with
  `PreEncryptNext`), `PreEncryptedRecordVerificationTests` (V15-V19, the device walk, the mislabelled-vector V18
  case), `PreEncryptedSerializationTests` (the JSON round trip then cast), `ManifestValidationTests.
  Encryptors_ManifestReorderedAfterRecordCreation_Throw` (now `PreEncryptionPrimitives.GenerateContests`),
  `ChallengedBallotDecryptionTests` and `KnownAnswerTests.ChallengedBallots` (issued-list argument dropped).
- Moved: `BallotRecordingToolTests` lines 1-235 -> `PreEncryption/PreEncryptedCastRecordTests.cs` (8 cases: cast
  records verify under V5-V7 and V15-V17, publish every hash and the selected vectors, pad an undervote, are refused
  by V8, tally with regular ballots through V9-V11; uncast records pass V16-V19, with and without ξ_B).
  `BallotPreEncryptorTests` -> `PreEncryption/PreEncryptionPrimitivesTests.cs` (15 kept, retargeted to the primitives
  and the fixture). `PreEncryptNext_RefusesARegularBallotChain` -> `DeviceChain_OfRegularBallots_RefusesAPreEncryptedBallot`.
- New (+5): `GenerateSelection_IsTheContestsVectorOfThatIndex_AndRefusesAnIndexWithNoVector`,
  `Combine_MultipliesComponentwise_AndSumsTheNonces`, `Combine_RefusesNoVectors_VectorsOfDifferentLengths_AndVectorsWithoutNonces`,
  `ProveCombinedContest_ProofsPassVerifications6And7`, `ProveCombinedContest_RefusesValuesWithNoValidProof_AndMismatchedLengths`.
- Deleted, because they tested only removed behaviour (-60 cases):
  - `IssuedPreEncryptedBallotsTests` (all 12: layout and commitment, order independence, lookups and round trip,
    own copies, duplicate/31-byte id_B, 7 malformed encodings): the issued list is gone.
  - `BallotRecordingToolTests`, all but the 8 moved cases (44): `RecordCast_DoesNotModifyTheSelections`;
    `Record_WrongBallotNonce_Throws`, `Record_BallotWhoseConfirmationCodeDiffers_Throws`,
    `Record_PrintedBallotThatTheBallotNonceDoesNotRegenerate_IsRefusedPerSelection` (6) (the recording tool's
    regeneration refusal; at the record level V16-V18 catch forged printed ballots, e.g. the kept
    `Verification18_MislabelledVector_Fails18A`); `RecordCast_SelectionsItCannotRecord_Throw` (10) and
    `Constructor_ManifestWithoutHashTrimmingFunction_Throws` (the tool's API refusals; the Ω requirement is now
    `GenerateContests_ManifestWithoutHashTrimmingFunction_Throws`); every guardian pre-encrypted nonce test:
    `DecryptPreEncryptedBallotNonce_WithAQuorum_RegeneratesTheBallot`, `..._ACorruptShare_...`,
    `DecryptBallotNonce_PreEncryptedBallotWithAForeignSelectionIdentifierHash_Throws`,
    `..._WithAnInvalidSchnorrProof_...` (4), `..._WithANonMemberC0AndAValidProof_...` (2), `..._WithAShortC1_...`,
    `..._WithNoDeviceId_...` (*S9c review round 1: its serializer half, `"deviceId": null` read back as null and
    reported by V16 as `16.structure`, covered kept behaviour and was restored as
    `PreEncryptedSerializationTests.PreEncryptedBallot_Json_NullDeviceId_ReadsAsNull_AndVerification16FailsStructure`*),
    `..._RegularCastBallotWrappedAsPreEncrypted_WithoutHashTrimming_IsRefused`,
    `..._WithHashTrimming_IsRefused_S9_6`, and the issued-list/once-only tests (`..._IssuedAndUncast_IsDecryptedOnce_AndRecorded`,
    `..._NotOnTheIssuedList_...`, `..._IssuedIdentifierWithAnotherEncryptedNonce_...`, `..._SecondRequestForTheSameIssuedBallot_...`,
    `..._ConsumedIdentifiers_SurviveARestart_...`, `..._TwoRequestsPastTheChecksForOneIssuedBallot_...`,
    `..._OnceOnlyState_IsTheGuardiansOwnCopyOfEachIdentifier`, `..._MalformedRequestForAnIssuedBallot_DoesNotConsumeIt`,
    `..._IssuedBallotAlreadyRecordedCast_IsRefusedByTheRecordCheck`, `..._IssuedPreEncryptedBallotWrappedAsChallenged_IsRefused_S9b_1` (*S9c review round 1: replaced by
    `..._UnrecordedPreEncryptedBallotWrappedAsChallenged_OpensIt_KnownExposure_S9b_1`, its first half*),
    `..._ListsOfAnotherElection_AreRefused`). The challenged path's own C_ξB checks (membership, proof, short C_1,
    H_I, cast-ballot record check, foreign view) stay covered by `ChallengedBallotDecryptionTests`.
  - `BallotPreEncryptorTests` (4): `Constructor_ContestNeedingMoreShortCodesThanTheCodeSpace_Throws` (the tool
    constructor's check; generating 257 vectors to show the pigeonhole through `HasUniqueShortCodes` would cost tens
    of seconds) and `GenerateWithUniqueShortCodes_*` (3, the tool's retry loop; the fixture's loop is test code).
  - Arithmetic: -12 - 44 - 4 + 5 = -55.

Gate before re-pinning (all source and test changes in; nothing failed, so nothing was re-pinned):
- Build (`--no-incremental`): `0 Warning(s)`, `0 Error(s)`.
- Tests: Perf `Passed: 231, Total: 231`; Core `Passed: 1840, Total: 1840` (no failing test).
- Smoke: `correctness passed`. EncryptBallots 0.243 ms/ballot, 165.7 MB; VerifyBallots 1.000 ms/ballot, 12.2 MB;
  JSON 21,173 bytes, protobuf 12,482 bytes.
- Console: `Device Device 1: 4 ballots, chaining mode None.`, `Ballot 0, contest 0: contest data "Write-in: Ada
  Lovelace".`, `Challenged ballot 0-challenged, contest 0: 0-0=1, 0-1=0, contest data "Write-in: Ada Lovelace".`,
  `Done.`, then the expected ReadKey `InvalidOperationException`. The issued-list line and the pre-encrypted demo
  tally line are gone. `tally.json`: 0-0: 3, 0-1: 0. No input under `C:/temp/eg/data` changed, so no .bak.

Gate (after the documentation edits): build `0 Warning(s)`, `0 Error(s)`; Perf `Passed: 231, Total: 231`; Core `Passed: 1840,
Total: 1840`; smoke `correctness passed`, EncryptBallots 0.245 ms/ballot 165.7 MB, VerifyBallots 1.000 ms/ballot
12.2 MB, JSON 21,258 bytes, protobuf 12,482 bytes; console lines as above, `Done.`, the expected ReadKey exception;
`tally.json` 0-0: 3, 0-1: 0, every other count 0.

Perf: no ballot hot path changed (encryption, V6-V9, the tally and its decryption are untouched; the challenged path
lost one hash-set lookup per request). Smoke Encrypt 0.243 / Verify 1.000 ms/ballot (0.245 / 1.000 in the second run) vs S9b's 0.246 / 1.026: noise;
allocation and protobuf size unchanged.

Decisions taken (low-stakes API shape): see "S9c design and API choices" in Decisions.

Carry-overs: the unrecorded-printed-ballot exposure on the challenged path (above), with Q-S7b / Q22; S10 no longer
needs the issued list's commitment in the record (S9b's carry-over is void).

### 2026-10-07 — S9b review round 1 (once-only scope, RLA note, id_B aliasing, the consuming step's race guard)
Worktree changes only; nothing committed. Five minor findings, all accepted (two are one defect). No hash input,
KAT vector, pinned value or test expectation moved; the pinned-value inventory is unchanged. No hot path touched.

**Once-only is per guardian (spec lens): accepted, documentation.** `_decryptedPreEncryptedBallots` is per
`TallyGuardian` and guardians share nothing, as Q31's "guardian-side state" says, so "at most once per id_B" binds
every later quorum only when more than n - k guardians answered: always when n < 2k (any two quorums share a
guardian; the default 3-of-2), otherwise only when the request went to more than n - k guardians. With n >= 2k a
disjoint quorum answers again (up to floor(n/k) quorums each recover ξ_B) until the ballot is published as cast.
Stated in the `TallyGuardian` class summary and constructor, `DecryptedPreEncryptedBallots` (the old detection
claim missed this case: it shows only by comparing the union of every guardian's list with the guardians the
recording tool asked for each id_B), the pre-encrypted `DecryptBallotNonce`, `TallyAdmin.DecryptPreEncryptedBallotNonce`
(its "pass exactly the guardians that will answer" advice replaced), `IssuedPreEncryptedBallots`,
`PreEncryptedBallotNonceStatement`, CLAUDE.md, the Q31 decision notes and S9b-2. No code change: making the rule
election-wide needs shared state or guardian-to-guardian messages, a design change (question S9b-3 below).

**Q31 refuses RLA nonce decryption of cast ballots (spec lens): accepted, documentation.** §3.3.4 p.30 names
"ballots that are selected in the context of a risk limiting audit" as a use of ballot nonce decryption; those
are cast, so the record check refuses them by design. Stated in `IPublishedCastBallots`, the challenged
`DecryptBallotNonce` trust model, CLAUDE.md's Tally bullet and the Q31 notes: an audit flow (Q22, "Not yet")
needs its own authorization path, e.g. an audit-selection list committed after the record is final. Carried next
to Q-S7b.

**id_B aliasing in the once-only set and the issued list (code and tests lenses; one defect): accepted, fixed.**
`SelectionEncryptionIdentifier` wraps its array without copying and hashes by content. The guardian now keeps its
own copy wherever an id_B enters its state (`OwnedCopy`: the constructor import, which now throws
`ArgumentException` for an id_B that is not 32 bytes, and the consuming step, which copies the issued list's entry
after `RequireIssued`, now returning it, so every look-up and the insertion use one snapshot) and hands out copies
(`DecryptedPreEncryptedBallots`, the write-ahead callback's argument). `IssuedPreEncryptedBallots` copies each
id_B on construction, and `Ballots`, `TryGet` and `Commitment` return copies (`Count` and `ToCanonicalBytes` read
the private sorted list). The struct's public constructor is unchanged (deserialization and encryption use it).

**The consuming step's race guard was untested (tests lens): accepted, fixed structurally and tested.** The insertion
is now the test (`if (!_decryptedPreEncryptedBallots.Add(identifier)) throw AlreadyDecrypted`), and the early look
stays only to fail fast. New internal seam `TallyGuardian.BeforeConsumingForTesting`, called after every check and
before the insertion, lets a test make a second request overtake the first in that window deterministically.

Tests (Core 1892 -> 1895, +3):
- `BallotRecordingToolTests.DecryptBallotNonce_TwoRequestsPastTheChecksForOneIssuedBallot_OnlyOneIsAnswered`: the
  overtaking request gets the one share, the first is refused `AlreadyDecrypted` by the insertion.
- `BallotRecordingToolTests.DecryptBallotNonce_OnceOnlyState_IsTheGuardiansOwnCopyOfEachIdentifier`: a request with
  a byte-copied id_B is refused; changing the first request's array, an exported snapshot's, the callback's or one
  passed to the constructor after a restart leaves the id_B consumed.
- `IssuedPreEncryptedBallotsTests.List_HoldsItsOwnCopies_OfTheIdentifiersAndCommitment`: changing an input id_B,
  an id_B read from `Ballots` or `TryGet`, or the returned `Commitment` moves no look-up and no commitment.
- Mutation check (each fix undone in turn, `BallotRecordingToolTests` and `IssuedPreEncryptedBallotsTests` run,
  plus `ChallengedBallotDecryptionTests` and `PublishedCastBallotsTests` for the first; both files restored and
  their SHA-256 matched):
  insertion result ignored -> the race test fails; the request's own array in the set -> the own-copy test; export
  without copies -> the own-copy test; import without copies -> the own-copy test; the issued list keyed on the
  caller's array -> the issued-list test and the own-copy test; the callback given the set's own entry -> the
  own-copy test. (The last was run after the documentation edits; it was restored by hand and the full Core suite
  re-run, 1895/1895, build 0 warnings.)

Gate before re-pinning (code changes in, before the new tests): build `0 Warning(s)`, `0 Error(s)`; Perf `Passed:
231, Total: 231`; Core `Passed: 1892, Total: 1892` (no test failed, nothing to re-pin); smoke `correctness passed`,
EncryptBallots 0.249 ms/ballot 165.7 MB, VerifyBallots 0.987 ms/ballot 12.2 MB; console `Device Device 1: 4
ballots, chaining mode None.`, the challenged-ballot line, the issued-list line, the pre-encrypted demo tally line
unchanged, `Done.`, the expected ReadKey exception; `tally.json` 0-0: 3, 0-1: 0, every other count 0.

Gate (all changes in): build `0 Warning(s)`, `0 Error(s)`; Perf `Passed: 231, Total: 231`; Core `Passed: 1895,
Total: 1895`; smoke `correctness passed`, EncryptBallots 0.245 ms/ballot 165.8 MB, VerifyBallots 1.033 ms/ballot
12.2 MB, JSON 21,193 bytes, protobuf 12,482 bytes; console lines as before (commitment `ADC9E0082FDD8840...`,
random per run), `Done.`, the expected ReadKey exception; `tally.json` 0-0: 3, 0-1: 0. No input under
`C:/temp/eg/data` changed, so no .bak.

Perf: no ballot hot path changed. VerifyBallots 0.987 and 1.033 ms/ballot in this round's two runs vs 0.982 in S9b:
run-to-run noise (V6-V9 untouched); allocation and protobuf size unchanged. The new cost is two 32-byte copies per
pre-encrypted nonce request.

Decisions taken (low-stakes API shape): copies on the way in and out rather than a copying struct constructor;
`Commitment` stays `byte[]` (a copy per read); `TryGet` returns a copy; the race test uses a re-entrant seam, not
threads, so it is deterministic.

Open question (for the user):
- **S9b-3: once-only scope when n >= 2k.** (a, built) per guardian, as Q31's "guardian-side state" reads,
  documented, with detection by comparing every guardian's consumed list against the recording tool's log;
  (b) the deployment always asks more than n - k guardians (all n) for a pre-encrypted nonce, which an honest
  recording tool can do but a dishonest administrator can ignore; (c) S10 publishes each guardian's consumed list
  in the record so that a verifier flags an id_B consumed by guardians outside one request's set; (d) guardians
  share the consumed set (a coordination protocol this library does not have). Recommendation: (a) now, plus (b)
  as the documented deployment rule, and (c) in S10.

Carry-overs: the RLA authorization path (with Q-S7b / Q22); S9b-3 (c) for S10.

### 2026-10-07 — S9b (nonce-decryption authorization gate: Q31 / S9-6, the S7 security review finding)
Worktree changes only; nothing committed. Implements user decision Q31 ("Issued list + record check"). No hash
input, KAT vector or pinned value moved; one test was flipped and renamed (below); the pinned-value inventory is
unchanged. No ballot hot path was touched (encryption, V6-V9, the tally and its decryption are unchanged).

**Q31 / S9-6 / the security review finding (S7's `TallyGuardian.DecryptBallotNonce` trusts the caller's Status):
closed.** Both nonce-decryption entry points now decide whether a request is authorized before anything else, from
lists the guardian holds itself, and refuse with the new `BallotNonceDecryptionRefusedException` (`GuardianIndex`,
`BallotId`, `Reason`) before any exponentiation with ẑ_i and without producing a share:
- `IPublishedCastBallots` / `PublishedCastBallots` (`Tally/PublishedCastBallots.cs`): the guardian's view of the
  published record's cast ballots, regular and pre-encrypted. Three hash sets of 32-byte keys (id_B, H_I, and
  SHA-256 of C_ξB,0's 512-byte encoding), with `HashCode`-seeded hashing (crafted ids cannot degrade the sets),
  filled incrementally (`Add`, `AddRange`, `FromRecord`), thread-safe, about 3 x 32 bytes per cast ballot plus set
  overhead. Bound to H_E: `Add` refuses a ballot not recorded `Cast`, without C_ξB, with a non-32-byte id_B/H_I,
  or whose H_I is not H(H_E; 0x20, id_B) for the view's H_E (another election's ballot, or one failing 5.B).
  `Match` reports each matching field as `CastBallotMatch` flags. The interface lets a deployment back it with
  its own store.
- `IssuedPreEncryptedBallots` (`PreEncryption/IssuedPreEncryptedBallots.cs`): the printer-committed list, one
  `IssuedPreEncryptedBallot` (id_B, C_ξB,0) per printed ballot, bound to H_E, fixed at construction
  (`FromPrintedBallots`), duplicates refused. Library (non-spec) canonical encoding: the 48 ASCII bytes
  `electionguard-cs:issued-pre-encrypted-ballots:v1` ‖ H_E (32) ‖ n (4 bytes BE) ‖ entries in strictly increasing
  id_B order, each b(id_B,32) ‖ b(C_ξB,0,512); `Commitment` = SHA-256 of those bytes (plain SHA-256, not the spec's
  H, no §5.5 domain byte). `FromCanonicalBytes` reads it strictly (tag, H_E, exact length, order, C_ξB,0 < p;
  `NonCanonicalEncodingException`). Guardians compare `Commitment` to confirm they hold the same list.
- `TallyGuardian.DecryptBallotNonce(EncryptedBallot, record, castBallots, issuedBallots)` (challenged path, both
  required, no overload without them): `ForeignElection` if either list's H_E differs; `CastBallot` if the
  request's id_B, H_I or C_ξB,0 matches any cast ballot; `IssuedPreEncryptedBallot` if its id_B is on the issued
  list (S9b-1 below). Then, unchanged, the Status check (kept as a non-authoritative sanity check), structure, H_I,
  membership and the eq. (38) proof.
- `TallyGuardian.DecryptBallotNonce(PreEncryptedBallot, record, castBallots, issuedBallots)` (pre-encrypted path):
  `ForeignElection`; `CastBallot`; `NotIssued` if the id_B is not on the list; `IssuedNonceDiffers` if its C_ξB,0 is
  not the committed one; `AlreadyDecrypted` if this guardian has decrypted that id_B before. Then structure, H_I,
  membership and proof. The id_B is consumed only after every check passes, atomically with a last look (lock),
  then the optional write-ahead callback runs, then the share is computed: a malformed request burns nothing.
- Guardian-side state: `TallyGuardian(index, shares, decryptedPreEncryptedBallots = null,
  recordPreEncryptedBallotDecryption = null)`; `DecryptedPreEncryptedBallots` exports the consumed id_Bs (a
  snapshot to persist and pass back after a restart). The callback sees each id_B before the share exists; if it
  throws, no share is computed and the id_B stays consumed (fail closed). Documented: a premature or duplicate
  request burns a printed ballot, a detectable denial of service that the exported set records.
- `TallyAdmin.DecryptChallengedBallot(guardians, ballot, record, castBallots, issuedBallots)` and
  `DecryptPreEncryptedBallotNonce(guardians, ballot, record, castBallots, issuedBallots)` pass both lists to each
  guardian. `CombineChallengedBallot` and `CombinePreEncryptedBallotNonce` take neither: the administrator is the
  party the check guards against, and whoever holds k shares can combine without it (low-stakes API choice).
- Trust model, documented in `TallyGuardian` (class and both methods), `IPublishedCastBallots`,
  `IssuedPreEncryptedBallots`, `ChallengedBallotStatement.For`, the `PreEncryptedBallotNonceStatement` class
  remarks (now "Threat model ... closed by Q31"), `TallyAdmin.CombinePreEncryptedBallotNonce`, `BallotStatus.Challenged`,
  `BallotRecordingTool` and `BallotStructure`: everything in a request, Status included, is the requester's claim;
  the lists are the guardian's own (a distributed guardian builds the cast view from its own copy of the record and
  takes the issued list from the printer, never from the administrator). The cast view protects only what it holds,
  so challenged ballots are decrypted once the record's cast ballots are final; the pre-encrypted path does not
  depend on that (the issued list keeps regular ballots out, once-only keeps a recorded ballot out).
- Console: `Program.cs` builds `PublishedCastBallots.FromRecord` over the submitted ballots and an empty issued
  list (that election issues no pre-encrypted ballots). `PreEncryptedElectionDemo` commits the issued list after
  printing, starts the cast view with the regular cast ballots, adds each `RecordCast` result as it is recorded, and
  then shows the guardians refusing a second request for a recorded ballot and a regular ballot dressed as
  pre-encrypted (it throws if either is answered). New console line: `Issued list of 4 pre-encrypted ballots,
  commitment <16 hex>...; the guardians refused a repeated request and a regular ballot dressed as pre-encrypted.`
- CLAUDE.md: the Tally bullet's challenged-ballot sentences and the pre-encryption bullet now state the gate and
  the trust model (the "open question S9-6" text was false).

**S9b-1 (implementer reading, a question for the user): the challenged path also consults the issued list.** Found
while writing the record check: a printed pre-encrypted ballot not yet recorded is in no cast view, so its id_B, H_I
and C_ξB, wrapped in a regular-shaped ballot marked challenged, pass every challenged-path check (structure, H_I,
the eq. (38) proof, which binds the printed ballot's H_I) and k shares give its ξ_B ahead of the voter, outside
Q31's once-only rule. Q31's pre-encrypted clause says an issued ballot's nonce is decrypted at most once; this
reading makes that hold on both paths (a refusal, the conservative direction), so it is built: the challenged path
refuses an id_B on the issued list (`IssuedPreEncryptedBallot`; matching id_B suffices, since an issued C_ξB under
another id_B has another H_I and fails eq. (38)). In an election without pre-encrypted ballots the list is empty.
Listed for the user's acceptance.

**Test changes (Core 1862 -> 1892, +30).**
- Mechanical (before the gate below): every caller passes the new arguments, an empty cast view and an issued list
  holding the ballot under test (so each existing test still reaches the check it was written for):
  `ChallengedBallotDecryptionTests` (`Election.NoCastBallots`, later `NoIssuedBallots`), `KnownAnswerTests.
  ChallengedBallots` (empty lists; the KAT vectors are untouched), `PreEncryptedRecordVerificationTests:354`,
  `BallotRecordingToolTests`, and the `PreEncryptedElection` fixture (`NoCastBallots`, `NoIssuedBallots`,
  `IssuedFor(...)`, `SecretShares(index)`). The fixture's `Guardians` is now built fresh on every read: guardians
  carry once-only state and the fixture is a shared singleton documented as read-only.
- Flipped and renamed (not re-pinned to new output): `..._WithHashTrimming_OpensIt_KnownExposure_S9_6` ->
  `DecryptBallotNonce_RegularCastBallotWrappedAsPreEncrypted_WithHashTrimming_IsRefused_S9_6`, as its own doc
  comment instructed. It now uses the realistic lists (the printer's issued list, which the regular id_B is not on,
  and a cast view holding the regular ballot): `CastBallot` refusal with the view, `NotIssued` without it, the
  administrator's wrapper refused, no exponentiation, nothing consumed.
- New, `BallotRecordingToolTests` (+9): honest issued uncast ballot decrypted once and recorded by the answering
  guardians only; not on the issued list; issued id_B with another ballot's C_ξB (`IssuedNonceDiffers`, and the
  issued ballot still decrypts); second request for the same issued id_B (both answering guardians, and the
  administrator's wrapper with a quorum including one of them); restart persistence and the write-ahead callback
  (recorded before the share; a throwing store means no share and the id_B stays consumed); a malformed request
  (broken proof) for an issued id_B consumes nothing; an issued ballot already recorded cast refused by the record
  check alone (guardians with no memory of it; all three fields match; the cast record relabelled challenged is
  refused on the challenged path too); lists of another election; S9b-1 (shows the shares would open the printed
  ballot without the issued-list check, then the refusal).
- New, `ChallengedBallotDecryptionTests` (+7): a cast regular ballot relabelled challenged, under its own id and
  under a new id (theory, 2), refused by the record check with no exponentiation (the test first asserts that
  structure and proof would pass); a challenged ballot sharing only id_B+H_I, only H_I, or only C_ξB,0 with a
  cast ballot (theory, 3); the honest challenged path with cast ballots in the view decrypts and passes V13/V14; a
  cast view of another election.
- New, `IssuedPreEncryptedBallotsTests` (+11): the documented byte layout and SHA-256 commitment; commitment
  independent of input order and changed by any entry or H_E; `FromPrintedBallots` lookups and round trip;
  duplicate or 31-byte id_B; seven malformed encodings.
- New, `PublishedCastBallotsTests` (+3): `FromRecord` holds cast ballots only (regular and pre-encrypted); `Match`
  per field, by content, missing or wrong-length values match nothing; `Add` refuses non-cast, a wrong H_I, another
  election's ballot; re-adding is idempotent.
- "No exponentiation" is shown with the existing `PartialDecryptionTamperForTesting` seam, which runs immediately
  after `MontgomeryModP.PowModP(C_ξB,0, ẑ_i)` with no branch between: it never fires on a refusal.
- Mutation check (each guard disabled in turn in `TallyGuardian.cs`, the four affected classes run, the file
  restored and its SHA-256 compared): record check off -> 7 failures (the relabelled theory x2, the shared-value
  theory x3, the recorded-cast test, the flipped S9-6 test); issued check off -> 2; issued C_ξB,0 comparison off ->
  1; once-only off -> 2; consuming before the proof check -> 1; the challenged path's issued check off -> 1 (S9b-1);
  the cast view's H_E check off -> 2.

Gate before re-pinning (all source changes and the mechanical call-site updates in, before any test was flipped or
added):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Tests: Perf `Passed: 231, Total: 231`; Core `Failed: 1, Passed: 1861, Total: 1862`. Failing:
  `BallotRecordingToolTests.DecryptBallotNonce_RegularCastBallotWrappedAsPreEncrypted_WithHashTrimming_OpensIt_KnownExposure_S9_6`
  (`BallotNonceDecryptionRefusedException : Guardian 1 refuses to decrypt ballot wrapper's nonce: its id_B, H_I,
  C_ξB,0 matches a cast ballot in the published record`), the expected flip.
- Smoke: `correctness passed`. EncryptBallots 0.247 ms/ballot, 165.7 MB; VerifyBallots 1.016 ms/ballot, 12.2 MB;
  JSON 21,233 bytes, protobuf 12,482 bytes.
- Console: `Device Device 1: 4 ballots, chaining mode None.`, `Challenged ballot 0-challenged, contest 0: 0-0=1,
  0-1=0, ...`, the new issued-list line, the pre-encrypted demo tally line (`mayor-ada: 2, mayor-grace: 2,
  mayor-alan: 1, council-barbara: 2, council-claude: 2, council-donald: 2, council-edsger: 2. Verifications 1-11 and
  15-19 passed.`), `Done.`, then the expected ReadKey `InvalidOperationException`. `tally.json`: 0-0: 3, 0-1: 0,
  every field 0.
(The S9b-1 check was added after this gate; it changed one more signature, again only call sites, and the gate
below covers it.)

Gate (all changes in):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Tests: Perf `Passed: 231, Total: 231`; Core `Passed: 1892, Total: 1892` (S9 review round 3: 1862; +30).
- Smoke: `correctness passed`. EncryptBallots 0.242 ms/ballot, 165.8 MB; VerifyBallots 0.982 ms/ballot, 12.2 MB;
  JSON 21,368 bytes, protobuf 12,482 bytes.
- Console: the same lines as above (commitment `FC14940AEAC4045F...`, random per run), `Done.`, the expected ReadKey
  exception. `tally.json`: 0-0: 3, 0-1: 0, every field 0. No input under `C:/temp/eg/data` changed, so no .bak.

Perf: no ballot hot path changed. Smoke Encrypt 0.242 / Verify 0.982 ms/ballot vs S9's 0.244 / 0.996 (and round
3's 0.248 / 1.007): within noise; allocation and protobuf size unchanged. The new checks cost three hash-set
lookups (one SHA-256 of 512 bytes) per nonce request, nothing per ballot elsewhere.

Decisions taken (low-stakes API shape, recorded here):
- The issued list commits C_ξB,0 with each id_B (not id_B alone): the guardian then also refuses an issued id_B
  carrying another encrypted nonce, so a request cannot burn an issued ballot with a nonce of its own.
- The once-only state lives in `TallyGuardian` (constructor import, `DecryptedPreEncryptedBallots` export, optional
  write-ahead callback), not in a separate object.
- One new exception type with a `Reason` discriminator, distinct from `ArgumentException` (malformed ballot) and
  `TallyDecryptionException` (C_ξB fails its checks).
- The administrator's `Combine*` methods take no lists (see above).

Open questions (for the user):
- **S9b-1:** accept the strict reading built above (the challenged path refuses an id_B on the issued list), or
  drop it? Recommendation: keep it; it is the only thing that stops a printed ballot from being opened through the
  challenged path before its voter uses it, and it costs one lookup.
- **S9b-2: retries under once-only.** Every guardian that answers consumes the id_B, so if the administrator's
  combine fails afterwards (a guardian's share lost, a network error, a wrong m_i), a retry is refused by those
  guardians and the printed ballot is burned. Options: (a, built) strict once-only, the voter is issued another
  ballot; (b) a guardian may re-send the same m_i (it is deterministic) to the same authenticated recording tool,
  which needs requester identity this library does not model; (c) a short retry window per id_B. Recommendation:
  keep (a) until the record format and transport (S10) can carry an authenticated requester, then consider (b).
  (Review round 1: "those guardians" is exact; once-only is per guardian, so with n >= 2k a retry through a
  quorum disjoint from the first is answered. See S9b-3 in the round-1 entry above.)

Carry-overs: none blocking. S10 (record format) should carry the issued list's commitment in the published record
so verifiers and guardians can compare it, and give guardians a way to build `PublishedCastBallots` from the
record as it grows.

### 2026-10-07 — S9 review round 3 (G31: S9-6 restated, null device id, 15.A beta half, pre-encrypted JSON negatives)
Worktree changes only; nothing committed. One source change (`BallotStructure`); no hash input, KAT vector or
pinned value moved, and no test expectation was re-pinned. Four findings (one major, three minor).

**S9-6 trust boundary (major, code lens): no change, by the finding's own recommendation.** It restates open
question S9-6 so that it stays visible and says it does not block the commit. The Ω gate and
`DecryptBallotNonce_RegularCastBallotWrappedAsPreEncrypted_WithHashTrimming_OpensIt_KnownExposure_S9_6` stay as
built until the user decides; option (b)/(c) waits on S10's record access.

**Null `DeviceId` passes the pre-encrypted structure check (minor, code lens): accepted, fixed in the shared
check.** `BallotStructure.FindViolation` for both `EncryptedBallot` and `PreEncryptedBallot` now ends with
`DeviceIdViolation` ("Ballot X names no device; every ballot carries the S_device ..."). Placing it in the
`EncryptedBallot` check (not only in `RequirePreEncryptedCast`'s path) also covers regular ballots, where V8.C's
`new VotingDeviceInformationHash(H_E, null)` threw `ArgumentNullException` the same way; it is reported as
`"N.structure"` for N = 6, 7, 8, 9, 15, 16, 17, and the tally refuses the ballot. Effect on the S9 path: guardians
refuse such a ballot with `ArgumentException` before computing m_i, and the administrator refuses it before
combining, so the "wrong m_i or wrong ξ_B" misattribution is gone. Low-stakes hardening (spec-silent; S_device
is required by eqs. 72 and 119), no bytes change; added to the S9 design choices. (Verifications 12, 13, 14 and
18 also read this check, so they refuse such a ballot too.) Tests (+7):
- `BallotStructureTests.Shapes` row "null device id" (x V6, V7, V8, V9: +4).
- `PreEncryptedBallotVerificationTests.PreEncryptedShapes` row "null device id" (16.structure: +1).
- `PreEncryptedRecordVerificationTests.Verifications15And16_CastRecordWithNoDeviceId_FailStructure` (+1).
- `BallotRecordingToolTests.DecryptBallotNonce_PreEncryptedBallotWithNoDeviceId_IsRefusedAsMalformed` (+1): the
  realistic repro, a printed ballot JSON with `"deviceId": null` read through `DeserializeBallot`; the guardian
  and the administrator (with honest shares) both throw `ArgumentException` naming the missing device, not
  `TallyDecryptionException`, and V16 reports `16.structure`.
- Mutation check (run together with the V15 mutation below; the 8 failures split by test name): with
  `DeviceIdViolation` disabled, exactly these 7 tests fail.

**15.A beta half untested (minor, tests lens): accepted.**
`Verification15_CombinedVectorWithTheSameNoncesAndTheOneMoved_Fails15A` (+1): contest-1's combined vector is the
selected vector re-encrypted with the same nonces and the one moved from option 1 to option 2 (β_1 / K,
β_2 · K). It asserts every alpha equals the selected vector's and the betas differ, that V16 and V17 pass, and
that V15 fails 15.A. Mutation check: with `|| published.Beta != beta` deleted, this test (and no other) fails.

**Pre-encrypted ballot JSON negatives (minor, tests lens): accepted.**
- `MalformedUncastJson` gains "alpha = p in a printed vector" and "beta = p in a printed vector" (+2). A new
  `Replace` helper asserts the property exists before overwriting it (a `JsonNode` assignment to a wrong path
  adds a property and would test nothing).
- The uncast theory's assertion is tightened, as the cast theory's is: "= p" and "not below q" rows require
  `NonCanonicalEncodingException`; the rest keep `JsonException or FormatException`.
- New theory `PreEncryptedBallot_Json_MalformedValue_IsRefused` over `DeserializeBallot` (+6): alpha = p, beta = p,
  ballot nonce C0 = p, a 31-byte selection hash, no short code, a 35-byte chaining field.
- No mutation check for these rows: the decoders were not changed, and each row's exception type is asserted.
  (The two source mutations above were applied together and reverted; both files hash identically to their
  pre-mutation state.)

Gate before re-pinning: one run, with every change in; nothing failed, so nothing needed re-pinning. Failing
tests at that moment: none.

Gate (all changes in):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Tests: Perf `Passed: 231, Total: 231`; Core `Passed: 1862, Total: 1862` (round 2: 1846; +16).
- Smoke: `correctness passed`. EncryptBallots 0.248 ms/ballot, 165.7 MB; VerifyBallots 1.007 ms/ballot, 12.2 MB;
  JSON 20,978 bytes, protobuf 12,482 bytes.
- Console: `Device Device 1: 4 ballots, chaining mode None.`, the pre-encrypted demo tally line (`mayor-ada: 2,
  mayor-grace: 2, mayor-alan: 1, council-barbara: 2, council-claude: 2, council-donald: 2, council-edsger: 2.
  Verifications 1-11 and 15-19 passed.`), `Done.`, then the expected ReadKey `InvalidOperationException`.
  `tally.json`: 0-0: 3, 0-1: 0, every field 0. No input under `C:/temp/eg/data` changed.

Perf: the one hot-path change is a null comparison at the end of `BallotStructure.FindViolation`, which runs on
every ballot in V6/V7/V8 and `AddBallot`; it allocates nothing. Smoke Encrypt 0.248 / Verify 1.007 ms/ballot vs
round 2's 0.247 / 1.002: within noise; allocation and protobuf size unchanged.

### 2026-10-07 — S9 review round 2 (G31: recording-tool test gaps, the S9-6 exposure test)
Worktree changes only; nothing committed. Test-only round: `src/` is unchanged (mutations below were applied and
reverted, and `BallotRecordingTool.cs` hashes identically before and after), no hash input, KAT vector or pinned
value moved, and no test expectation was re-pinned. Three findings (one major, two minor), all accepted. All
changes are in `test/ElectionGuard.Core.UnitTests/PreEncryption/BallotRecordingToolTests.cs`.

**Per-selection regeneration check untested (major, tests lens): accepted.** Right: nothing reached the loop in
`BallotRecordingTool.Regenerate` that compares each selection's label, hash, short code and (α, β) with what ξ_B
regenerates. The existing refusal tests are also caught by the final H_C check, and the V18 attack tests build the
forged record around the tool (`RecordUncast(honest, ...) with { Ballot = forged }`), so the tool never sees it.
- New theory `Record_PrintedBallotThatTheBallotNonceDoesNotRegenerate_IsRefusedPerSelection`, 3 forgeries x
  {`RecordCast`, `RecordUncast`}, each with the honest ξ_B (+6):
  - "swapped": contest-1's first two honest vectors printed beside each other's options (as
    `Verification18_TwoVectorsPrintedBesideEachOthersOptions`). The test asserts its contest hashes and H_C equal
    the honest ballot's, so only the loop can refuse it.
  - "mislabelled": option 1's vector re-encrypted with the one at position 2, hashes recomputed (as
    `Verification18_MislabelledVector`).
  - "short code": one printed short code replaced, nothing else (short codes enter no hash; `FindViolation`
    checks only that one is present). This pins the ShortCode comparison.
  - Each asserts `ArgumentException` with "does not regenerate" and "selection vector", so it is the
    per-selection check that fires, not the contest-hash or H_C check.
- Mutation check: with the loop's refusal disabled, all 6 cases fail (the mislabelled ballot then falls to the
  contest-hash check, which the message assertion tells apart); with only the ShortCode comparison removed, the 2
  "short code" cases fail.

**Three `ReadSelections` refusals untested (minor): accepted.** `RefusedSelections` gains a contest not on the
ballot ("contest-3"), contest-1 listed twice, and contest-1 with `NumWriteinsSelected = 0` and non-null
`ContestData` (+3). Every row (old and new) now carries a message fragment, and the theory asserts it and
`ParamName == "selections"`, so each row is refused by its own check. Mutation check: dropping the foreign-contest
throw, the `TryAdd` check or the `ContestData` half of the write-in check each fails exactly its row.

**The S9-6 exposure pinned as passing behavior (minor): accepted, as a split and rename, not a skip.** The test
is split in two `[Fact]`s sharing a helper that builds the wrapper:
- `DecryptBallotNonce_RegularCastBallotWrappedAsPreEncrypted_WithoutHashTrimming_IsRefused`: the enforced part,
  a normal test.
- `DecryptBallotNonce_RegularCastBallotWrappedAsPreEncrypted_WithHashTrimming_OpensIt_KnownExposure_S9_6`:
  still asserts that the attack succeeds. Its doc comment says that a failure means S9-6 was fixed, not a
  regression, and how to update it.
- Not converted to `[Fact(Skip = ...)]` asserting the desired refusal: a skipped test runs nothing, so an
  accidental change to the guardian path would go unnoticed, and the rules forbid skipping without cause. The
  name now points at S9-6 directly. The S9-6 open question below names the test.

Gate before re-pinning: not separate this round. No source file changed, so nothing could break a pinned value;
the gate below ran once with every test in, and nothing failed or was re-pinned.

Gate (all changes in):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Tests: Perf `Passed: 231, Total: 231`; Core `Passed: 1846, Total: 1846` (round 1: 1836; +10).
- Smoke: `correctness passed`. EncryptBallots 0.247 ms/ballot, 165.7 MB; VerifyBallots 1.002 ms/ballot, 12.2 MB;
  JSON 21,023 bytes, protobuf 12,482 bytes.
- Console: `Device Device 1: 4 ballots, chaining mode None.`, the pre-encrypted demo tally line (`mayor-ada: 2,
  mayor-grace: 2, mayor-alan: 1, council-barbara: 2, council-claude: 2, council-donald: 2, council-edsger: 2.
  Verifications 1-11 and 15-19 passed.`), `Done.`, then the expected ReadKey `InvalidOperationException`.
  `tally.json`: 0-0: 3, 0-1: 0, every field 0. No input under `C:/temp/eg/data` changed.

Perf: no source change. Smoke is within noise of round 1 (Encrypt 0.242-0.244, Verify 0.987-0.997 ms/ballot);
allocation and the protobuf size are unchanged.

### 2026-10-07 — S9 review round 1 (G31: nonce-path exposure of regular ballots, cast-only records, test gaps)
Worktree changes only; nothing committed. No hash input, KAT vector or pinned value moved, and no test
expectation was re-pinned. Seven findings (one major, six minor), judged as five pieces of work.

**Pre-encrypted nonce path opens regular ballots too (major, spec lens; and the code-lens minor on Ω): accepted.**
The finding is right. `PreEncryptedBallotNonceStatement` checks the ballot's shape (which anyone can fabricate),
H_I = H(H_E; 0x20, id_B), C_ξB,0 in Z_p^r and the eq. (38) proof. All of these read only id_B, H_I and C_ξB. Every
regular ballot publishes those (S7 made C_ξB required), and §4.2 p.60 encrypts the pre-encrypted nonce "as shown
in Section 3.3.4", with no domain separation. So a regular cast ballot's values, wrapped in a made-up
`PreEncryptedBallot` of the right shape, get k shares that combine (eq. 108) to its ξ_B and, through eq. (33), its
votes. That bypasses S7's `Status == Challenged` gate without changing any status. The administrator's
regeneration check does not help, because whoever collects the shares can combine them.
- Enforced now: `BallotStructure.FindViolation(PreEncryptedBallot, ...)` refuses a manifest with no hash-trimming
  function (§4.1.5: an election that uses pre-encrypted ballots names Ω). The guardian and administrator
  pre-encrypted paths therefore throw `ArgumentException` in every election without pre-encrypted ballots. V16
  and V18 also report a printed or uncast ballot under such a manifest as `"16.structure"`/`"18.structure"`
  (V17's printed-ballot overload already failed it as 17.A, unchanged). The check sits in `FindViolation`, not
  only in the statement, so the cast-record check (which already had it) and the printed-ballot check agree.
- Still open in an election that has both kinds of ballot (the console demo is one). It is documented in the
  `PreEncryptedBallotNonceStatement` class remarks, both `TallyGuardian.DecryptBallotNonce` overloads,
  `TallyAdmin.CombinePreEncryptedBallotNonce`, CLAUDE.md and the S9 decisions bullet. The open question is
  widened below. An enforced fix changes who may obtain ξ_B, a security-semantics choice the rules leave to the
  user.
- `DecryptBallotNonce_RegularCastBallotWrappedAsPreEncrypted_RefusedWithoutHashTrimming_ExposedWithIt` pins
  both halves (split and renamed in review round 2: `..._WithoutHashTrimming_IsRefused` and
  `..._WithHashTrimming_OpensIt_KnownExposure_S9_6`). Without Ω, the guardian and the administrator refuse. With Ω, two guardians answer and their
  shares open the regular cast ballot through `CombineChallengedBallot` to its exact selections. The second half
  pins the documented exposure, not a desired behavior; it changes when S9-6 is decided.

**Pre-encrypted records are cast only (code lens, minor): accepted, except the weight rule.**
- `FindPreEncryptedCastViolation` refuses a status other than Cast (`"15/16/17.structure"`). Before, a cast
  record relabelled Challenged passed V15-V17, was skipped by the tally, and was audited by nothing (V18 takes
  only `PreEncryptedUncastBallot`).
- `ChallengedBallotStatement.For` refuses `IsPreEncrypted` (`ArgumentException`), so guardians release no share
  for a decryption that `Open` can never complete: it derives eq. (33) nonces, but a combined vector carries
  summed eq. (121) nonces. For consistency, Verifications 13 and 14 report such a ballot as
  `"13.structure"`/`"14.structure"`.
- Not applied: Weight == 1. §3.5 p.45 associates a weight with "each encrypted ballot in the election record"
  when weights are used, and nothing in §4 excludes pre-encrypted ballots. A regular ballot's weight is no more
  bound than a pre-encrypted one's. The recording tool still writes 1.

**Test gaps (four findings): all accepted and added.**
- Nonce path (`BallotRecordingToolTests`, +8):
  - a broken eq. (38) proof (response, challenge, C1, C0), refused by the guardian and again by the
    administrator, naming no guardian;
  - a non-member C_ξB,0 with a valid proof (zero, and -g^ξ-hat with an even c_B), forged on the pre-encrypted
    ballot's own H_I and C_ξB,1;
  - a 31-byte C_ξB,1 (`ArgumentException`);
  - the regular-ballot wrapper above.
- Serialization (`PreEncryptedSerializationTests`, +8):
  - protobuf DTO level: field 12 without the field-13 flag, a selected vector with no short code, α = p and
    β = p in a selected vector (`NonCanonicalEncodingException`);
  - JSON: no `shortCode`, a null `shortCode` (`JsonException`), α = p and β = p (`NonCanonicalEncodingException`).
- Structure (`PreEncryptedRecordVerificationTests`, +11):
  - `MalformedCastRecords` gains selected vectors in decreasing order, a selected vector with no short code,
    a 31-byte selected-vector hash, a selected vector with no hash, and the record marked Challenged or
    NotSubmitted;
  - a manifest without Ω (15/16/17.structure on a cast record, 16.structure on a printed ballot, 18.structure
    on an uncast record);
  - a cast record marked Challenged refused by the guardian, the administrator, V13 and V14;
  - two null vectors sharing m + 1 in the L = 2 contest;
  - a printed ballot with no C_ξB or a 31-byte C_ξB,1 (16.structure).
- Mutation check (each guard disabled in turn, the three test classes run, the sources restored and
  `git diff --stat` compared byte for byte). Every mutation failed at least one new test:
  - the Ω check: 2 tests;
  - the cast-status check: 2;
  - the `IsPreEncrypted` refusal: 1;
  - the guardian's and the administrator's `RequireDecryptable` on the pre-encrypted path: 6 each;
  - the protobuf flag check: 1;
  - `>= 0` weakened to `== 0` on the selected-vector order: 1;
  - the `nullSeen` index check: 1.

Gate before re-pinning (all code changes in, before any test was added or touched):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Tests: Perf `Passed: 231, Total: 231`; Core `Passed: 1809, Total: 1809`. Nothing failed, so nothing was
  re-pinned.
- Smoke: `correctness passed`. EncryptBallots 0.242 ms/ballot, 165.7 MB; VerifyBallots 0.987 ms/ballot, 12.2 MB;
  JSON 21,198 bytes, protobuf 12,482 bytes.
- Console: `Device Device 1: 4 ballots, chaining mode None.`, then `Pre-encrypted demo tally (2 regular + 3
  pre-encrypted cast ballots): mayor-ada: 2, mayor-grace: 2, mayor-alan: 1, council-barbara: 2, council-claude: 2,
  council-donald: 2, council-edsger: 2. Verifications 1-11 and 15-19 passed.`, then `Done.`, then the expected
  ReadKey `InvalidOperationException`. `tally.json`: 0-0: 3, 0-1: 0, every field 0.

Gate after (all changes and tests in):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Tests: Perf `Passed: 231, Total: 231`; Core `Passed: 1836, Total: 1836` (S9: 1809; +27).
- Smoke: `correctness passed`. EncryptBallots 0.244 ms/ballot, 165.7 MB; VerifyBallots 0.997 ms/ballot, 12.2 MB;
  JSON 21,258 bytes, protobuf 12,482 bytes.
- Console: the same lines as before (the device line, the pre-encrypted demo tally line, `Done.`, the expected
  ReadKey exception). `tally.json`: 0-0: 3, 0-1: 0, every field 0. No input under `C:/temp/eg/data` changed, so
  no .bak was needed.

Perf: no hot path changed. The new checks are one null test per pre-encrypted ballot, one status comparison per
cast record, and one boolean per challenged ballot; regular ballots in V6-V9 and the tally take none of them.

Open question (widened; replaces the S9 entry's S9-6 text):
- **S9-6: who may have a ballot's nonce decrypted through the pre-encrypted path.** Apart from the shape, the
  guardians' checks read only id_B, H_I and C_ξB. Every published ballot carries these (regular ballots cast or
  not, cast pre-encrypted records), and §4.2 encrypts the pre-encrypted nonce with the regular construction. So in
  an election that names Ω, anyone can wrap a published ballot's values in a made-up pre-encrypted ballot, and k
  guardians' shares give its ξ_B and its votes. For a regular cast ballot this bypasses S7's challenged-only gate
  without changing any status. Recording a cast pre-encrypted ballot needs its ξ_B (§4.3.1), so there is no
  status to check.
  - (a, built) Enforce Ω in the manifest (done: this closes the path in every election without pre-encrypted
    ballots) and document the rest; a distributed guardian is expected to refuse requests that match a
    published ballot.
  - (b) Guardians refuse any request whose id_B, H_I or C_ξB,0 matches ANY ballot in the record, regular or
    pre-encrypted, cast or not; matching cast pre-encrypted records alone leaves every regular ballot open.
    This needs record access (S10).
  - (c) Guardians accept only an id_B from a printer-committed list of issued pre-encrypted ballots, and decrypt
    each at most once (guardian-side state). The list keeps regular ballots out, since their id_B is not on it.
    Once-only keeps a recorded ballot from being decrypted again. A request made for a printed ballot before
    the voter uses it would consume that ballot (a detectable denial of service). The spec defines no such list.
  - (d) The recording tool takes ξ_B only from the printer's local database (§4.3.1 names it), and guardians
    never decrypt pre-encrypted nonces. Only this option removes the path outright; the database then holds
    every pre-encrypted ballot's ξ_B.
  - Recommendation: (c) together with (b) once S10 gives record access, or (d) if the deployment has a trusted
    printer database. Option (a) alone leaves regular cast ballots open in any mixed election.

### 2026-10-07 — S9 (pre-encrypted ballots: recording tool, cast/uncast records, Verifications 15, 18, 19: G31)
Worktree changes only; nothing staged or committed. The KAT oracle (`test/kat/*`) was extended by the orchestrator
before this stage (spec-only): six new families (`preencrypted_encryption_nonce` 25, `preencrypted_selection_hash`
14, `preencrypted_null_selection_hash` 8, `preencrypted_contest_hash` 5, `preencrypted_range_proof_challenge` 9,
`preencrypted_selection_limit_challenge` 3), appended vectors in three existing families, and a top-level
`preencrypted_ballots` summary (P1 cast, P2 uncast).

**G31: done.** Spec read: §4 (pp.57-69), Verifications 15-19 (pp.64-67) and §6.2.8 (pp.94-99).
- Recording tool (§4.3, `PreEncryption/BallotRecordingTool.cs`). Input: the printed `PreEncryptedBallot`, the
  decrypted ξ_B and, for a cast ballot, the selections as a plaintext `Ballot`. It regenerates every encryption from
  ξ_B (eq. 121, through the pre-encryptor's new `PreEncryptContests`) and refuses unless the ballot is exactly that.
  - `RecordCast` multiplies the selected vectors componentwise and sums their nonces mod q. It pads an undervote with
    the contest's first null vectors to exactly L. It proves each component with eq. (59) over 0..R and the contest
    with eq. (62) over 0..L (H_I-keyed, `BallotEncryptor.GenerateProofs` made `internal static` with a test seam). It
    returns a standard `EncryptedBallot`: status cast, weight 1, eq. (115) contest hashes, the eq. (116)
    confirmation code, the pre-encrypted B_C, C_ξB and device. The §4.4 extras go in
    `EncryptedBallot.PreEncryptedContests`: all m + L selection hashes sorted, the L selected vectors sorted by hash
    with their short codes, no option label, no nonce.
  - `RecordUncast` returns `PreEncryptedUncastBallot`: the ballot, every released ξ_{i,j,k}, and ξ_B only on
    request.
- Nonce decryption for the recording tool's wrapper (§4.3.1). `TallyGuardian.DecryptBallotNonce(PreEncryptedBallot,
  ...)`, `TallyAdmin.DecryptPreEncryptedBallotNonce`/`CombinePreEncryptedBallotNonce`. Same checks as §3.6.7
  (structure, recomputed H_I, C_ξB,0 in Z_p^r, eq. 38), for cast and uncast ballots alike. ξ_B is returned only
  if it regenerates the ballot. The quorum/combine code is shared with `CombineChallengedBallot` (messages
  unchanged), and the statement's decryptability check is now a shared static.
- Tallying: no change was needed in `EncryptedTally`, V9 or `BallotStructure.Require(EncryptedBallot)`. The cast
  record's `Contests` are standard. `Tally_MixedRegularAndPreEncryptedBallots_DecryptsToTheSumOfTheirSelections`
  and the console tally a mix and pass V9-V11.
- Verification 8 refuses a cast pre-encrypted ballot (`"8.structure"`, p.64) instead of failing 8.A.
- Verification 15 (`SelectionVectorAccumulationVerification`, 15.A for every contest), Verification 18
  (`UncastBallotEncryptionVerification`: 18.1-18.4 recomputed from the released nonces with δ from each vector's
  label, 18.A; plus the label-by-label comparison and the ξ_B consistency check, both reported as 18.A) and
  Verification 19 (`UncastBallotContentVerification`, 19.A-19.D; null vectors carry no label).
- V16 and V17 gain cast overloads: 16.A over the selected vectors (hash recomputed, and one of the published
  hashes), 16.B over the published hashes, 16.C-16.F shared, 17.A over the selected vectors' short codes.
- `PreEncryptedConfirmationCodeVerification.VerifyDevices(devices, cast, uncast, record)` walks a pre-encrypted
  device over its cast and uncast records together.
- Structure (`BallotStructure`): `RequirePreEncryptedCast` (`"15/16/17.structure"`: the regular structure, then a
  pre-encryption entry per contest in order, m + L well-formed hashes strictly ascending, exactly L selected
  vectors of m entries strictly ascending by hash, short codes present, and a manifest that names Ω). For every
  pre-encrypted ballot it now also requires each vector's index to be eq. (121)'s j and C_ξB with a 32-byte C_1.
- Serialization. Cast: JSON `preEncryptedContests` (strict `SelectionHashJsonConverter`, `ShortCodeJsonConverter`)
  and protobuf field 12 with flag 13 (strict: canonical α/β, 32-byte hashes, short code required; data without
  the flag is refused). Pre-encrypted and uncast ballots: `JsonPreEncryptedBallotSerializer` (strict; ξ_B exactly
  32 bytes via `BallotNonceJsonConverter`). Computed properties of `PreEncryptedBallot` are no longer written.
- S5 carry-over (supplemental fields on pre-encrypted ballots). §4 has no slot for them (§4.1 eqs. 112-114 and
  §4.2's output list), and p.66 says pre-encrypted contests have no contest data. The spec does not say how a
  contest that declares them is shared by both kinds of ballot. Implemented the safest option:
  `Manifest.Validate` refuses a manifest that names a hash-trimming function and declares supplemental fields,
  write-in fields or contest data (and refuses an Ω outside 1-8). Open question S9-1.
- Console (`PreEncryptedElectionDemo.cs`, called before "Done."). A separate in-memory election, since the gate's
  manifest declares fields. Two regular ballots and four pre-encrypted ballots on a simple-chaining printer;
  guardians decrypt each ξ_B; three are recorded cast and one uncast. It runs V1-V7, V8 on the regular ballots,
  V15-V17 on cast records, V16-V19 on the uncast one, both device walks, a mixed tally, V9-V11, and checks the
  counts against the selections. It writes a `pre-encrypted` subdirectory of the console's output directory
  (`C:/temp/eg/data/1/pre-encrypted`); no input file changed, so no .bak was needed.
- egperf: no pre-encrypted scenario (optional; see carry-overs).

Tests (Core 1654 -> 1809):
- `PreEncryption/BallotRecordingToolTests` (+22): combination, plaintexts, padding, no option labels, inputs not
  modified, V8 refusal, mixed tally, uncast release, refused inputs, nonce decryption, corrupt share.
- `Verify/PreEncryption/PreEncryptedRecordVerificationTests` (+43 cases): 15.A (wrong published vector, wrong
  combined vector), 6.D/7.D on the combined vector, 16.A x2, 16.B, 16.C, structure x8 for each of 15/16/17,
  17.A, the simple-chain walk with cast and uncast records (16.F, 16.structure x2), the eq. (121) index rule x3.
  - 18.A: a mislabelled vector (the cut-and-choose attack: the vector printed beside option 1 encrypts option 2)
    x2; two honest vectors printed beside each other's options x2, which changes no hash, χ or H_C, so only the
    label comparison catches it; a wrong nonce; a nonce not derived from ξ_B; a wrong ξ_B; a replaced confirmation
    code.
  - 18.structure x6; 19.A, 19.B, 19.C, 19.D x2, 19.structure x3.
- `Serialization/PreEncryptedSerializationTests` (+14), `ManifestValidationTests` (+6).
- KAT (148 -> 214 cases): `KnownAnswerTests.PreEncryption.cs` checks all six new families. Two end-to-end tests:
  - P1 rebuilt by the encrypting tool matches every ψ in generation order, short code (Ω1), χ, B_C and H_C. Recorded
    with the oracle's proof nonces, every combined component (α, β, summed ξ) and every c_j/v_j of eqs. (59)/(62)
    equals the oracle's, and V6/V7/V15/V16/V17 accept it.
  - P2 recorded as uncast releases exactly the oracle's 21 eq. (121) nonces and ξ_B = q + 11 as raw bytes;
    V16-V19 accept it.
  - The six existing KAT tests that the extension broke had their lookups adapted, not their expected values (see
    the Pinned-value inventory).

Mutation check (run, then restored from a byte-exact copy). With V18's label-by-label comparison disabled, the two
"printed beside each other's options" cases verify and fail the test; the mislabelled-vector cases still fail 18.A
on H_C, but their message assertion catches the change.

Gate before re-pinning (all changes in, before any existing test expectation was touched). Build `0 Warning(s)`,
`0 Error(s)`. Smoke `correctness passed`: EncryptBallots 0.247 ms/ballot, 165.7 MB; VerifyBallots 0.999 ms/ballot,
12.2 MB; JSON 21,228 bytes, protobuf 12,482 bytes. Console: `Device Device 1: 4 ballots, chaining mode None.`, the
pre-encrypted demo line `Pre-encrypted demo tally (2 regular + 3 pre-encrypted cast ballots): mayor-ada: 2,
mayor-grace: 2, mayor-alan: 1, council-barbara: 2, council-claude: 2, council-donald: 2, council-edsger: 2.
Verifications 1-11 and 15-19 passed.`, `Done.`, then the expected ReadKey `InvalidOperationException`;
`tally.json` 0-0: 3, 0-1: 0, every field 0. Tests: Perf `Passed: 231, Total: 231`, Core `Passed: 1805, Total:
1805`. Nothing failed, so nothing was re-pinned. (The six KAT harness failures caused by the oracle extension were
seen on the first targeted run and fixed in the harness lookups before this gate; no expected value moved.)

Gate after (rebuilt; three more tests and doc comments since): build `0 Warning(s)`, `0 Error(s)`. Smoke
`correctness passed`: EncryptBallots 0.242 ms/ballot, 165.7 MB; VerifyBallots 0.977 ms/ballot, 12.2 MB; JSON
21,268 bytes, protobuf 12,482 bytes. Console as above (`tally.json` 0-0: 3, 0-1: 0, every field 0). Tests: Perf
`Passed: 231, Total: 231`, Core `Passed: 1809, Total: 1809`.

Perf: no hot path changed. The regular encryptor calls the same proof code (now static, one null check for the
seam), and the new `Manifest.Validate` branch runs only when a hash-trimming function is named. Smoke against S8
(Encrypt 0.249, Verify 1.008 ms/ballot): Encrypt 0.242-0.247, Verify 0.977-0.999; allocation unchanged (165.7 MB,
12.2 MB); protobuf ballot size unchanged (12,482 bytes). JSON size varies by run (S8 recorded 21,138 and 21,168).

Open questions for the user (implemented as stated; none changes a hash input):
- **S9-1: supplemental fields, write-ins and contest data in an election with pre-encrypted ballots.** (a, built)
  `Manifest.Validate` refuses them when a hash-trimming function is named. (b) Treat a pre-encrypted ballot's
  missing fields as encryptions of 0 in aggregation (then `BallotStructure` must accept their absence on
  pre-encrypted ballots, which shows the ballot kind, though footnote 54 says the kind is visible anyway). (c) Have
  the recording tool derive and encrypt the fields from the selections with its own nonces and proofs (not
  spec-defined; it would add data that χ and H_C do not cover). Recommendation: (a) until a spec revision covers it.
- **S9-2: undervote padding.** (a, built; the KAT oracle does the same) Always combine exactly L vectors, padding
  with the first null vectors, so the record shows L short codes and never an undervote. (b) Combine only the
  selected vectors. Recommendation: (a).
- **S9-3: releasing ξ_B for uncast ballots.** §4.4 says it "is published"; §4.3 and V18 release the ξ_{i,j,k}
  instead, which allows contest-level release. (a, built) Always release the ξ_{i,j,k}, and ξ_B only on request,
  in which case V18 checks every nonce against it. (b) Always publish ξ_B too. Recommendation: (a), consistent with
  S7 (challenged ballots never publish ξ_B).
- **S9-4: more than L selections on a pre-encrypted ballot.** The spec is silent. (a, built) The recording tool
  refuses them (the caller decides, e.g. as a spoiled ballot). (b) Record an overvote as L null vectors (a blank
  contest; the published short codes would not be the voter's marks). Recommendation: (a).
- **S9-5: labels of the V18 hardening.** The label-by-label comparison (needed: a device that prints two honest
  vectors beside each other's options passes 18.A as lettered, because χ sorts the hashes) and the ξ_B consistency
  check are reported as "18.A", following Q23 (13.A). Alternative: new labels (e.g. "18.1"/"18.2"). Recommendation:
  "18.A".
- **S9-6: who may have a pre-encrypted ballot's nonce decrypted.** *Widened in S9 review round 1 (see that
  entry): the exposure covers every published ballot, regular cast ballots included.* The guardians' checks
  (`PreEncryptedBallotNonceStatement`: structure, recomputed H_I, C_ξB,0 in Z_p^r, eq. 38) depend only on id_B,
  H_I and C_ξB, all of which a published cast record carries. Anyone can wrap them in a fabricated
  `PreEncryptedBallot` (arbitrary vectors with consistent labels and indices) that k guardians accept. The m_i they
  return yield ξ_B before the administrator's regeneration check runs, and with ξ_B the cast record's selected
  vectors name the options: the vote. There is no status to check, because recording a cast ballot needs its ξ_B
  (§4.3.1). Checking the request against the printed-ballot list does not help: the id_B is a real one. (a, built)
  As documented; guardians are expected to refuse pre-encrypted nonce requests once cast records are published.
  (b) Guardians refuse when the id_B (or H_I, or C_ξB,0) is in any published cast record; this needs record access
  (S10). (c) The recording tool takes ξ_B only from the printer's local database (§4.3.1 names that option), and
  guardians never decrypt pre-encrypted nonces. Recommendation: (a) now, (b) with S10.
  *Whichever option is chosen, `BallotRecordingToolTests.DecryptBallotNonce_RegularCastBallotWrappedAsPreEncrypted_WithHashTrimming_OpensIt_KnownExposure_S9_6`
  asserts that the attack succeeds today and will fail once it is closed: replace its assertions with the refusal
  (see the S9 review round 2 entry).*

Spec readings recorded (no question needed): 16.B and 18.4 use ind_c, following eq. (115) and the S7 13.3
precedent. 18.2-18.4 cover all m + L vectors, following eq. (115) and the encrypting tool. 15.A is applied for every
L (a product of one vector). The eq. (121) i is ind_c, and j and k are option index and position, which agree
because `Manifest.Validate` makes option indices 1..m. Null vector l is j = m + l. Combined-vector proofs are over
0..R (p.64 "appropriate option selection limits"; the oracle's R = 1).

Carry-overs:
- No egperf pre-encrypted scenario: the runner encrypts regular ballots only. A scenario needs a hash-trimming
  manifest without fields, a printer chain, nonce decryption per ballot (about 2k + 2 full-width exponentiations
  for k guardians), regeneration (2·m·(m + L) per contest) and a cast/uncast split.
- Trust boundary (spec-silent, as S7; open question S9-6, widened in S9 review round 1): a guardian decrypts any
  well-formed pre-encrypted ballot's nonce, and a well-formed request can be fabricated from any published ballot,
  regular or pre-encrypted. See the review round 1 entry.
- Contest-level release for uncast ballots (§4.3 "selective decryption of specific contests") is not built: the
  tool releases every contest, and V18 requires every contest. This is the same as S7's Q22 ("not yet").
- Record serializers for the whole election record (S10): the uncast record has a JSON serializer; a manifest
  binding and record bundle remain S10's.
- Short-code uniqueness within a contest (§4.1.5) is the encrypting tool's duty (`BallotPreEncryptor` retries);
  V17 does not check it (the spec letters no such check).

### 2026-10-07 — S8 review round 1 (G19, G37: undefined chaining modes, V16 walk test gaps, egperf walk coverage, VerifyAll cost)
Worktree changes only; nothing committed. No hash input, pinned value or KAT moved, and no test expectation was
re-pinned. Seven findings, judged as four pieces of work.

**Undefined chaining modes (two minor findings, spec lens and code lens): fixed.** §3.4.4 p.42 specifies the modes
0x00000000 and 0x00000001 and leaves others to "a 4-byte identifier ... specified in the election manifest". The
manifest model specifies none, but nothing refused another value: JSON accepts `"chainingMode": 2`, and every
`mode != None` branch then treated it as simple chaining, with 0x00000002 on ballots (`ChainingField.For`) but
0x00000001 in B_C,0 and the close, and the per-ballot 8.E identifier check and the walk accepted all of it.
- `Manifest.Validate` refuses any `ChainingMode` outside {None, Simple} (`InvalidManifestException`). Every chaining
  path reads the mode from `EncryptionRecord.Manifest`, which is validated on assignment, so this covers record
  construction and deserialization, both encryptors, `DeviceChain`, V8/V16 per ballot and the walk.
- `ChainingField`'s public builders (`new ChainingField(...)`, `ForPreEncryptedBallots`) throw
  `ArgumentOutOfRangeException` on an undefined mode.
- The per-ballot V8 identifier check compares with 0x00000001 explicitly, not `(int)chainingMode`.
- No explicit `else throw` was added to the walk's `mode != None` branches: after `Validate` they are unreachable,
  and a device record claiming another mode already fails `"8.structure"`/`"16.structure"` (mode must equal the
  manifest's). CLAUDE.md and the Decisions section say so.
- Tests (`ManifestValidationTests`): `Validate_UndefinedChainingMode_Throws` (2 and -1, read from JSON, refused by
  `Validate` and by `CreateEncryptionRecord`), `Validate_SpecifiedChainingModes_DoNotThrow`,
  `ChainingField_UndefinedChainingMode_Throws`. No committed manifest (test/data, perf/scenarios, C:\temp\eg\data)
  uses another mode (grep: 10 × 0, 1 × 1).

**V16 device-walk test gaps (two minor findings, spec lens and tests lens): fixed; the S8 claim "the same for V16"
was wrong and is corrected in the S8 entry.** `PreEncryptedDeviceChainTests` now builds two devices (3 and 2
ballots) under both modes, as the V8 tests do, and adds: an honest no-chaining walk; no-chaining wrong B_C
(re-hashed, eq. 116) -> 16.E, and another device's ballot with its id rewritten -> 16.E (the walk's
`NoChainingSubSection` and `ForPreEncryptedBallots(None, ...)` are now exercised); wrong previous code -> 16.F;
first ballot chained from the regular H_0 -> 16.F; a spliced ballot of device-2 as published -> 16.structure and
with its id rewritten -> 16.F; H_0 missing -> 16.G; the closing hash alone flipped, a flipped closing field, a
missing hash, a missing field and the regular close -> 16.H (asserting which message, field or hash, fired); 16.D
under both modes; dropped from the list only and a mode other than the manifest's -> 16.structure; `VerifyDevices`
with device-2 unlisted -> 16.structure; `DeviceChain.Append(PreEncryptedBallot)` refusing another device's ballot,
a wrong position, and anything after close. 9 tests became 19 methods (24 cases). Totals: Core 1634 -> 1654
(+15 here, +5 in `ManifestValidationTests`), Perf 227 -> 231.

**egperf's device walk was untested (two minor findings, code lens and tests lens): fixed with a record hook; the
suggestion to move the ballot hook before `deviceChain.Append` was not taken.** The only runner test was rejected
earlier, by the per-ballot 8.E in the serial `VerifyChunk`. New internal seam
`ScenarioRunner.DeviceChainRecordHookForTesting` (applied between `deviceChain.Close()` and `VerifyDevices`). New
tests: `Run_ChainedManifest_WalksTheClosedDeviceRecord` (closing hash flipped -> the walk's 8.G message "The closing
hash recorded for device"; H_0 replaced -> 8.F's message; last code dropped from the list -> the structure message
"is not in its ordered list of ballots") and `Run_ChainedManifest_ClosesTheDeviceChainOverEveryBallot` (honest
run passes; the record covers all 8 ballots and carries a close). Deleting the `VerifyDevices` call fails all three
cases of the first. Why the ballot hook stays after `Append`: `Append` checks each ballot's B_C against its chain
position and throws `ArgumentException`, so moving the hook first would turn the existing wrong-previous-code test
into a harness failure instead of a verification failure. Appending first models what the record exists to expose:
the device recorded its ballots honestly, and the published ballots were tampered with afterwards. The ballot
hook's doc comment now says so; the existing test's summary says the per-ballot 8.E catches it.

**`VerifyAll` was O(devices × ballots) (one minor finding, code lens): fixed.** `DeviceChainWalk.VerifyAll` groups
the links by device id once and hands each device walk only its own group, so the completeness check is O(ballots)
for the whole record. `byCode` stays whole, so a listed ballot of another device is still found and reported as
structure. The single-device `VerifyDevice` overloads keep the full scan (they are given whatever list the caller
has). Behavior unchanged; covered by the existing `VerifyDevices` tests in both files.

Mutation check (run, then reverted from byte-exact copies): with the `VerifyDevices` call in the runner removed, the
pre-encrypted scheme's "16.E"/"16.G" labels changed, and the `Manifest.Validate` mode check disabled, 6 Core tests
(`Validate_UndefinedChainingMode_Throws` ×2, `WrongInitialHash_Fails16G` ×2, both 16.E tests) and 3 Perf tests
(`Run_ChainedManifest_WalksTheClosedDeviceRecord` ×3) fail.

Gate before re-pinning (all changes in): build `0 Warning(s)`, `0 Error(s)`; smoke `correctness passed`,
EncryptBallots 0.235 ms/ballot, 165.7 MB, VerifyBallots 0.996 ms/ballot, 12.2 MB, JSON 21,138 bytes, protobuf 12,482
bytes; console `Device Device 1: 4 ballots, chaining mode None.`, `Done.`, then the expected ReadKey
`InvalidOperationException`, `tally.json` 0-0: 3, 0-1: 0, every field 0; tests Perf `Passed: 231, Total: 231`, Core
`Passed: 1654, Total: 1654`. Nothing failed, so nothing was re-pinned.

Gate after (rebuilt after the mutation check): build `0 Warning(s)`, `0 Error(s)`; smoke `correctness passed`,
EncryptBallots 0.262 ms/ballot, 165.8 MB, VerifyBallots 1.018 ms/ballot, 12.2 MB, JSON 21,168 bytes, protobuf 12,482
bytes; console as above, `tally.json` 0-0: 3, 0-1: 0, every field 0; tests Perf `Passed: 231, Total: 231`, Core
`Passed: 1654, Total: 1654`. The `chained` scenario: `correctness passed`, EncryptBallots 2.395 ms/ballot,
VerifyBallots 15.292 ms/ballot (S8: 2.421 / 15.415).

Perf: no hot path changed (the smoke run is unchained and never reaches the walk; the per-ballot change swaps one
4-byte comparison operand). Smoke against S8's figures: Encrypt 0.235-0.262 against 0.217-0.243 ms/ballot (single
runs; the encrypt path is untouched), Verify 0.996-1.018 against 0.98-1.02 ms/ballot; memory unchanged (165.7-165.8
MB, 12.2 MB).

Carry-overs: none new. The S8 open questions and carry-overs stand.

### 2026-10-07 — S8 (ballot chaining: chain close, device records, Verification 8.D-8.G and 16.G/16.H: G19, G37)
Worktree changes only; nothing staged or committed. The KAT oracle (`test/kat/*`) was extended by the orchestrator
before this stage with four pre-encrypted chaining families (`preencrypted_confirmation_code` 3,
`preencrypted_chain_init` 1, `preencrypted_chain_close_inner` 1, `preencrypted_chain_close` 1) and a
`preencrypted_chain` summary; the two regular-ballot close families (`chain_close_inner`, `chain_close`) were listed
as unsupported until now. All six pass through the library on the first run; no byte needed a fix.

**Design (recorded under Decisions, "S8 design and API choices"):** the ballot now carries its chaining field B_C,
as `PreEncryptedBallot` already did. Without it, 8.D/8.E cannot be told apart from 8.B (the hash is one-way), and a
no-chaining ballot with a wrong B_C could only fail 8.B. No hash input changed: B_C was always computed and hashed
into H_C (eq. 71); it is now also kept.

**G19 (chain close and device records, §3.4.4 eqs. 74-78, §4.1.4 eqs. 116-120, §3.7):**
- `ChainingField` gains the per-device formulas: `InitialHash` (H_0 = H(H_E; 0x29, B_C,0), eq. 74),
  `InitialHashForPreEncryptedBallots` (0x42, eq. 117), `Closing` (B-bar_C = 0x00000001 ‖ H(H_E; 0x2B, H_ℓ, B_C,0),
  eq. 78), `ClosingForPreEncryptedBallots` (0x44, eq. 120, the 69-byte body form per Q4), `ClosingHash` (H-bar =
  H(H_E; 0x29, B-bar_C), eq. 77) and `ClosingHashForPreEncryptedBallots` (0x42, eq. 118); `FromCanonicalBytes`
  (exactly 36 bytes, else `NonCanonicalEncodingException`), `IsWellFormed`, content-based `GetHashCode`, hex
  `ToString`. The constructor and `ForPreEncryptedBallots` share one implementation (bytes unchanged; the
  `chain_init` and `confirmation_code` KATs pass as before).
- `ConfirmationCode.GetHashCode` hashed the array reference, so a decoded code could not find its ballot in a
  dictionary; it now hashes the bytes (and `Equals` tolerates a default value). Hex `ToString`.
- `DeviceChainRecord` (Models): `DeviceId` (S_device), `DeviceInformationHash`, `BallotKind` (`Encrypted` /
  `PreEncrypted`), `ChainingMode`, `ConfirmationCodes` (H_1..H_ℓ in order), and under simple chaining `InitialHash`,
  `ClosingChainingField`, `ClosingHash` (null under no chaining). Ballots are referenced by confirmation code.
  `DeviceChainLink` (id, device id, H_C, B_C) lets a streaming caller check a chain without keeping ballots.
- `DeviceChain` (BallotEncryption): a device's chain. `PreviousConfirmationCode` (null before the first ballot, and
  always under no chaining), `Append(EncryptedBallot)` / `Append(PreEncryptedBallot)` (refuses another device's
  ballot, a field that does not fit the position, anything after `Close`), `Close()` (the record; refuses an empty
  simple chain, see question 1). `BallotEncryptor.EncryptNext(ballot, chain)` and
  `BallotPreEncryptor.PreEncryptNext(id, style, chain)` encrypt from the chain's previous code and append. (Named
  `...Next` because an `Encrypt(Ballot, DeviceChain)` overload made every `Encrypt(ballot, null)` call ambiguous.)
- `EncryptedBallot.ChainingField` (required): JSON `chainingField` (base64, strict 36 bytes via the new
  `ChainingFieldJsonConverter`; missing or null is a `JsonException`), protobuf ballot field 11 (`byte[]?`, decoded
  with `ChainingField.FromCanonicalBytes`, so missing/35/37 bytes throw `NonCanonicalEncodingException`).
  `BallotStructure` requires a well-formed field on regular and pre-encrypted ballots (`"N.structure"`).
- `JsonDeviceChainRecordSerializer` (JSON only; the record does not ride on encrypted ballots).
- Verification 16 (`PreEncryptedConfirmationCodeVerification`): `VerifyDevice` (over ballots or links) and
  `VerifyDevices`, for 16.D, 16.F in list order, 16.G and 16.H; its remark no longer says 16.G/16.H are uncovered.

**G37 (8.D/8.E tautological):**
- `ConfirmationCodeVerification.Verify(ballot, record)` (new, per ballot): `"8.structure"`, 8.A, 8.B over the ballot's
  own B_C, then 8.D under no chaining (B_C = 0x00000000 ‖ H_DI with H_DI computed from the ballot's device id), or
  under simple chaining only the 0x00000001 identifier (as 8.E). `Verify(ballot, deviceHash, record, previous)` keeps
  its signature: the same, plus 8.C against the given device hash and 8.E against the given previous code (null = the
  device's first ballot, chaining from H_0). The two dead comparisons are gone.
- `VerifyDevice(record, ballots | links, encryptionRecord)` and `VerifyDevices(records, ballots | links, ...)`: the
  authoritative chain checks, through the shared `DeviceChainWalk` (Verify namespace, also used by V16).
  `"8.structure"` first: record kind and mode must be the verification's and the manifest's, no close values under no
  chaining, a non-empty simple chain, every listed code a ballot of the record named for this device and listed once,
  every ballot naming the device listed; `VerifyDevices` adds one list per device and a list for every ballot's
  device. Then 8.C (recorded H_DI), 8.F (recorded H_0), 8.D/8.E per ballot in list order, 8.G (recorded B-bar_C and
  H-bar over the last listed code). It does not redo 8.A/8.B: callers run the per-ballot check too (documented).
- `ChallengedBallotDecryptionVerification.Verify(record, ballot, decrypted)` (new overload): 13.B over the ballot's
  own B_C ("B_C is the chaining field for ballot B"); the old overload with device hash and previous code is kept and
  behaves as before.
- Detected by tests: wrong previous code (8.E), reordered (8.E; passes under no chaining, which attests to no
  order), dropped last ballot from list and record (8.G) or from the list only (8.structure), dropped middle ballot
  (8.E), wrong/missing closing hash or field (8.G), wrong/missing H_0 (8.F), wrong recorded H_DI (8.C), a ballot of
  another device spliced in (8.structure; with its device id rewritten, 8.E under simple and 8.D under no chaining),
  a no-chaining ballot with a wrong B_C re-hashed consistently (8.D per ballot and in the walk). For V16 S8 itself
  covered only a subset (16.D, 16.F for reordered and dropped-middle ballots, 16.G for a regular-ballot H_0, 16.H for
  truncation and a regular-ballot close, and 16.structure for the ballot kind); the rest of the V8 set was added
  for V16 in S8 review round 1 (see that entry).

**Pipelines:**
- Console (`Program.cs`, the old TODO): ballots in file-name order; a `DeviceChain` for "Device 1"; under no chaining
  encrypted in parallel and appended in file order, under simple chaining encrypted one at a time from the chain;
  the challenged ballot goes through `EncryptNext` (it was processed on the device); the chain is closed after
  encryption and written to `device-chains.json`; V8 per ballot (`Verify(ballot, record)`) then
  `VerifyDevices([record], ballots, ...)`; V13 uses the new overload. Ballot JSON files are now written with
  `File.Create` (truncating) instead of `File.OpenWrite`. No input file in `C:\temp\eg\data\1` changed (the
  manifest stays no-chaining), so no .bak was made.
- egperf: under simple chaining the runner appends each encrypted ballot to a `DeviceChain` (outside the encrypt
  timing), keeps a `DeviceChainLink` per published ballot while ballot verification runs, and after the last chunk
  closes the chain and runs `VerifyDevices`, billed to `VerifyBallots` without adding ballots. Under no chaining
  nothing new is kept (per-ballot 8.D is complete there); the parallel V8 call is now `Verify(ballot, record)`.
  New scenario `perf/scenarios/chained.json` (300 ballots, `test/data/single-contest-chained/manifest.json` =
  smoke's manifest with `chainingMode` 1 and its own `electionId`); `perf/README.md` describes it. First run:
  `correctness passed`, EncryptBallots 2.421 ms/ballot, VerifyBallots 15.415 ms/ballot (serial by design).

Gate before re-pinning (all code above, the console and the perf runner in; the test project only compile-fixed:
`ChainingField = x.ChainingField` copied into the hand-built ballot clones (16 test files), the KAT challenged-ballot
shells given the vector's B_C or `ElectionFixtureBuilder.PlaceholderChainingField` (new, 36 zero bytes), and the
protobuf DTO clones in `StrictDecodingTests` copying field 11; no assertion touched):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`. dkg 143 ms; EncryptBallots 221 ms, 0.221 ms/ballot, 165.7 MB; VerifyBallots 1,009 ms,
  1.009 ms/ballot, 12.3 MB; Tally 8, VerifyTally 5, DecryptTally 34, VerifyDecryption 8 ms; JSON 21,198 bytes,
  protobuf 12,482 bytes.
- Console: `Device Device 1: 4 ballots, chaining mode None.`, `Ballot 0, contest 0: contest data "Write-in: Ada
  Lovelace".`, `Challenged ballot 0-challenged, contest 0: 0-0=1, 0-1=0, contest data "Write-in: Ada Lovelace".`,
  `Done.`, then the expected ReadKey `InvalidOperationException`; `tally.json` 0-0: 3, 0-1: 0, every supplemental
  field 0; `device-chains.json` lists 4 confirmation codes, mode 0, null close values.
- Tests: Perf `Passed: 226, Total: 226`; Core `Failed: 2, Passed: 1558, Total: 1560`. The failures:
  `KnownAnswerTests.EveryVectorFamilyIsCheckedOrExplicitlyUnsupported` (the four new oracle families not yet
  checked; closed by the new KAT tests by design), and
  `ConfirmationCodeVerificationTests.Verify_ChainingModeSimple_MismatchedPreviousConfirmationCode_Throws_SubSection8B`
  (`Expected: "8.B"`, `Actual: "8.E"`; the behavior G37 asks for, re-pinned below).

Re-pinned (one behavior pin, no value):
- `ConfirmationCodeVerificationTests.Verify_ChainingModeSimple_MismatchedPreviousConfirmationCode_Throws_SubSection8B`
  -> `..._SubSection8E`, expecting `"8.E"`. The ballot carries the B_C it was hashed with, so 8.B passes; an
  unrelated previous code is a wrong chain position, which is 8.E's statement. Its old comment explained that 8.E
  was dead code (the G37 finding). Also: `KnownAnswerTests.UnsupportedFamilies` is now empty (the two `chain_close*`
  entries are checked), and the two serializer tests whose comment said B_C "is not a stored property of
  EncryptedBallot" now assert it round-trips.

New tests (Core 1560 -> 1634, Perf 226 -> 227):
- KAT (`KnownAnswerTests.Chaining.cs`): `ChainCloseInner_Eq78`, `ChainClose_Eq77`, `PreEncryptedChainInitialization_Eq117`,
  `PreEncryptedConfirmationCode_Eq116` (3), `PreEncryptedChainCloseInner_Eq120_BodyForm` (also asserts the library
  does not produce `lock_form_erratum.hash_hex` nor the 0x2B close), `PreEncryptedChainClose_Eq118`, and
  `OracleChain_AsADeviceRecord_VerifiesAndDetectsTampering` (regular and pre-encrypted: the oracle's H_0, H_1, H_2
  and close as a `DeviceChainRecord` pass `VerifyDevice`; truncated -> 8.G/16.H, swapped -> 8.E/16.F, the LOCK-form
  close -> 16.H). `ChainInitialization_Eq74And75` also checks `ChainingField.InitialHash`.
- `ConfirmationCodeVerificationTests` (+8 cases): the ballot carries its B_C; tampered B_C without re-hashing -> 8.B;
  no-chaining ballot with another device's hash, the simple identifier, or a zero hash (re-hashed) -> 8.D on both
  overloads; simple chaining per ballot checks only the identifier (8.E for 0x00000000); the first ballot must chain
  from its own device's H_0 (8.E); a default B_C -> 8.structure.
- `DeviceChainVerificationTests` (new, two devices of 4 and 2 ballots, one challenged): every case listed under G37,
  plus honest records under both modes, the record's values against eqs. 74/76/77/78, `VerifyDevices` completeness,
  and `DeviceChain` refusals (another device, wrong position, after close; an empty chain closes only without
  chaining; previous code null under no chaining; `EncryptNext` with another device's chain). One case documents
  the limit of the check: a shortened chain with a recomputed close passes, and differs from the published H-bar.
- `PreEncryptedDeviceChainTests` (new, 9): part of the 16.D-16.H counterparts on a `PreEncryptNext` chain (completed
  in S8 review round 1).
- `ChainingSerializationTests` (new, 5): B_C round trips (JSON and protobuf) and the decoded ballots still pass V8
  and `VerifyDevices`; JSON `chainingField` missing or null is refused; `DeviceChainRecord` JSON round trip
  (simple and no chaining) still verifies; a 35-byte closing field is refused.
- `StrictDecodingTests`: protobuf B_C missing, 35 and 37 bytes; JSON B_C 35 and 37 bytes.
  `BallotStructureTests`: shape "missing chaining field" × V6/7/8/9.
  `ChallengedBallotDecryptionTests.Verification13_OverTheBallotsOwnChainingField`.
- Perf `ScenarioRunnerTests.Run_ChainedManifest_FailsABallotChainedFromTheWrongPreviousCode`.
- Mutation check (run, then reverted): with 8.G/16.H and the simple-chaining 8.E/16.F comparisons disabled in
  `DeviceChainWalk`, 16 of the 47 device-chain and oracle-chain tests fail.

Gate after:
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke ×3, each `correctness passed`: dkg 138-139 ms; EncryptBallots 0.233 / 0.236 / 0.243 ms/ballot, 165.7 MB;
  VerifyBallots 0.993 / 1.018 / 1.012 ms/ballot, 12.1-12.3 MB; Tally 8-10, VerifyTally 4-6, DecryptTally 35,
  VerifyDecryption 8 ms. JSON 21,088-21,163 bytes, protobuf 12,482 bytes.
- Console: as before re-pinning (`Device Device 1: 4 ballots, chaining mode None.`, `Done.`, the expected ReadKey
  exception); `tally.json`, `device-chains.json`, `contest-data.json`, `challenged-ballots.json` rewritten at
  00:07:11; 0-0: 3, 0-1: 0, fields 0.
- Tests: Core `Passed: 1634, Total: 1634`; Perf `Passed: 227, Total: 227`.

Perf against S7. `--repeat 5` of S8 (group c1b66d04) against a same-load `--repeat 5` of HEAD `90ea38b` (S7 code,
detached worktree `.tmp-head-baseline`, records written into this worktree's `perf/results`, group 5eb152cf; the
worktree was removed). `compare --baseline 20261007T040647Z-b11c8e --candidate 20261007T040534Z-833fa4`, nothing
flagged:

| Phase | S7 (HEAD, same load) | S8 |
|---|---|---|
| EncryptBallots ms/ballot | 0.203 | 0.217 (+6.8%; runs 0.204-0.236 against 0.195-0.235) |
| EncryptBallots alloc B/ballot | 173,103 | 173,078 (-0.01%) |
| VerifyBallots ms/ballot | 0.975 | 0.980 (+0.4%) |
| VerifyBallots alloc B/ballot | 11,663 | 11,487 (-1.5%) |

Against the tracker's S7 figures (Encrypt 0.264, Verify 1.09 ms/ballot) S8 is lower on both; against S7 review
round 2's group 47eac1db the same compare flagged Tally (+7.1%) and VerifyTally (+7.0%) allocation, about 65 bytes
per ballot on paths S8 does not touch, which the same-load baseline above does not reproduce (-0.01%, +1.7%).
Encryption only stores the B_C it already built; verification computes H_DI per ballot as before and compares one
36-byte field. Serialized ballot: JSON +~60 bytes (about 21.1 KB), protobuf 12,444 -> 12,482 bytes (+38: B_C and
its tag). The smoke scenario and manifest hashes did not change, so S7 records stay comparable.

Note for later compares: group 5eb152cf holds S7 code, but its records carry the same `gitCommit` (`90ea38b`) as the
S8 worktree runs (group c1b66d04). Only the group id tells them apart. `perf/results/` is gitignored.

Open questions for the user (implemented as the recommended option; neither changes bytes the spec defines):
1. **Closing a simple chain that holds no ballot.** Eq. (78) closes over "the final confirmation code in the chain",
   which an empty chain lacks. (a) As built: `DeviceChain.Close` refuses, and Verification 8/16 reject an empty
   simple-chaining record (`"8.structure"`). (b) Close with H_ℓ = H_0, i.e. B-bar_C = 0x00000001 ‖ H(H_E; 0x2B,
   H_0, B_C,0), which invents bytes the spec does not give. (c) Publish no close for an unused device.
   Recommendation: (a) for now, or (c) if unused devices must appear in the record.
2. **Where the protection against truncation comes from.** H_0 and the close use no secret (H_E is public), so
   anyone who can rewrite the record can drop the last ballots and recompute B-bar_C and H-bar
   (`DroppedLastBallot_WithARecomputedClose_...` shows it passes). The spec's protection is that H-bar is
   "formed and published" when the chain closes. The library cannot enforce that by itself. Nothing to decide now;
   the record format and its signature (§3.7, S10/G40) should timestamp or sign each device's closing hash.

Carry-overs:
- egperf's chained path still verifies serially per ballot (4-argument V8 with the previous code) because the
  whole run is forced to parallelism 1. With B_C stored, per-ballot V8 no longer needs the chain, so verification
  could run in parallel with the cheap device walk at the end; that needs a verify-specific parallelism setting.
- The console's simple-chaining branch is exercised by the unit tests' `DeviceChain`/`EncryptNext` and the
  `chained` scenario, not by the console's own input (its manifest is no-chaining; changing it is outside S8).
- An election record type (S10/G40) should carry the `DeviceChainRecord` list; `VerifyDevices` is ready for it.
- Chaining modes other than 0 and 1 (§3.4.4: "must be uniquely identified by a 4-byte identifier and specified in
  the election manifest") are not supported; `ChainingMode` has only `None` and `Simple`. (S8 review round 1:
  `Manifest.Validate` now refuses any other value; before, nothing did.)

### 2026-10-06 — S7 review round 2 (G18: RLA granularity, guardian trust boundary, perf check, V13/V14 test gaps)
Worktree changes only; nothing staged or committed. Five minor findings. Two are accepted and resolved in
documentation, one is answered with a measurement, and two are accepted as new tests. No library behavior changed.

**Spec: V13 rejects a selection-level partial release. Accepted, documented as option (a).** §3.6.7 p.52 lets a
publication be "restricted to the desired subset of encryption nonces". p.53 has the verifier use the given
selection encryptions where nonces are not available. Verification 13 as lettered (p.54, p.92) recomputes every
field of a decrypted contest ("For all 1≤j≤m_i"), and its RLA paragraph speaks only of contests that "have not been
decrypted". So the code follows the lettered text, and a decrypted contest must release every field, plus its
contest data where it carries any. Option (b) would loosen what V13 accepts, a verification-semantics change the spec
does not settle, so it was not built. The V13 class remarks now say that the partial release works at contest
granularity only, and why. CLAUDE.md's V13 line says the same. New S7 design choice "RLA granularity is the contest".
Q-S7b is widened to cover it (below).

**Code: a cast ballot copied under a new string id passes every guardian check. Accepted, documentation and
carry-over.** Confirmed by reading: `ChallengedBallotStatement.For` checks `Status`, `BallotStructure` and the
recomputed H_I. `RequireDecryptable` checks C_ξB,0 membership and the eq. (38) proof, which binds H_I and not
`ballot.Id`. `EncryptedBallot.Status` has an `init` accessor (EncryptedBallot.cs). An exact copy with a new `Id` and
`Status = Challenged` passes all of these, and k m_i then give ξ_B and every vote on the cast ballot. V5.A flags the
duplicate id_B only afterwards. The remarks on `TallyGuardian.DecryptBallotNonce` and `ChallengedBallotStatement.For`
now state that a distributed guardian must refuse when the published record holds any cast ballot with the same id_B
(or H_I, or C_ξB,0), and that matching on `Id` is not enough. CLAUDE.md's `DecryptBallotNonce` sentence and the S7
carry-over say the same. New S7 design choice "Trust boundary of the guardian's status check". No overload was added,
because nothing in-process would call it. Its shape is recorded as a carry-over: a set of the cast ballots' id_B (or
C_ξB,0) values, and a refusal on a match.

**Code: round 1's perf claim was not measured. Accepted, measured.** Round 1 attributed the smoke wall-time rise to
machine load without a `compare` or `--repeat`. This round ran `--repeat 5` on smoke three ways (machine sethpc2023,
32 cores, server GC, Release):
- Candidate group d0adc6be (`20261007T015536Z-c04d5c`) against round 0's single S7 run `20261007T010213Z-a46335`,
  whose encrypt and verify code is byte-identical: exit 0.
  - EncryptBallots 0.243 -> 0.239 ms (-1.6%), allocation -0.44%.
  - VerifyBallots 0.995 -> 1.074 ms (+7.9%, under the 15% informational tolerance), allocation -9.9%.
  - Peak heap +12.5% `OVER TOLERANCE` (informational).
- The same group against the S6 run `20261006T031405Z-a89c53`: exit 0.
  - EncryptBallots 0.246 -> 0.239 ms (-2.9%), allocation -3.5%.
  - VerifyBallots 0.966 -> 1.074 ms (+11.1%), allocation -10.0%.
  - Both baselines are single cold runs. The candidate is the median of five runs in one process, of which runs 2-5
    are warm (dkg 63 ms against 146), hence the lower allocation.
- To separate load from code, a fresh S6 baseline was taken under the same load. A detached worktree of HEAD
  (`e6d7be0`, the S6 commit) was created at `.tmp-head-baseline` inside this worktree, run `--repeat 5` (group
  d501efad), its five records copied into this worktree's `perf/results/sethpc2023.jsonl`, and the worktree removed.
  S6 code now verifies at 1.046-1.091 ms/ballot, the same as S7's 1.040-1.098, so the machine is slower today. Then S7
  was run `--repeat 5` again right after (group 47eac1db). `compare --baseline 20261007T015703Z-223538` (S6, group
  d501efad), exit 0 for both S7 groups:

| Phase | S6 (HEAD, same load) | S7 group 47eac1db | S7 group d0adc6be |
|---|---|---|---|
| EncryptBallots ms/ballot | 0.232 | 0.239 (+3.1%) | 0.239 (+3.0%) |
| EncryptBallots alloc B/ballot | 178,587 | 173,123 (-3.1%) | 173,051 (-3.1%) |
| VerifyBallots ms/ballot | 1.060 | 1.080 (+1.9%) | 1.074 (+1.3%) |
| VerifyBallots alloc B/ballot | 11,664 | 11,663 (-0.01%) | 11,673 (+0.08%) |

Note for later compares: group d501efad holds S6 code, but its records carry the same `gitCommit` (`e6d7be0`) as the
S7 worktree runs. Only the group id tells them apart. `perf/results/` is gitignored.

Under the same load S7 verifies within 2% of S6, allocates the same, and encrypts with 3% less allocation. The
encrypt wall-time difference sits inside each group's own spread (S6 0.219-0.237, S7 0.211-0.253). No allocation
metric breached the 2% gate. DecryptTally showed +16% `OVER TOLERANCE` (informational, 0.013 -> 0.016 ms/ballot) in
one of the two comparisons; it is a 3 ms phase that S7 does not touch, and it was +2% in the other.

**Tests: V14's unknown-style branch had no test. Accepted.** `Copy` takes a `ballotStyleId`. New
`Verification14_BallotStyleNotInTheManifest_Fails14Structure` asserts `"14.structure"` and the message. V14 does not
run `BallotStructure`, so the lookup is its own check.

**Tests: V13 null/unknown branches had no tests. Accepted.** New `Verification13Tampers` rows: "no option list", "no
supplemental field list", "null option entry" and "unknown option label" -> `"13.structure"`; "contest data D null" ->
`"13.A"`, also asserting the `C_1 is not D XOR` message, so that the two 13.A causes stay distinguished.

Mutation check (applied together, then reverted with Edit, which updates the timestamps; the rebuilt DLL was
confirmed newer than the source):
- `released!.Count` in place of `released is null || released.Count`.
- `x!.Id` in place of `x?.Id`.
- The V14 `?? throw` removed.

Four new tests failed: "null option entry", "no option list", "no supplemental field list" and the V14 style test.
The "unknown option label" and "D null" rows share their throw sites with rows that were already tested, and they
pin those messages.

Gate before any test edit (doc comments, CLAUDE.md and tracker design choices in; no test touched):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Tests: `Passed!  - Failed:     0, Passed:   226, Skipped:     0, Total:   226` (Perf);
  `Passed!  - Failed:     0, Passed:  1554, Skipped:     0, Total:  1554` (Core). No test failed, so nothing needed
  re-pinning.
- Smoke: `correctness passed`.
  - dkg 152 ms; `EncryptBallots     261       0.261       165.7`; `VerifyBallots      1,102     1.102       12.3`.
  - Tally 9, VerifyTally 4, DecryptTally 36, VerifyDecryption 8 ms.
  - `tallyVerification: ran`, `decryptionVerification: ran`.
- Console: `Challenged ballot 0-challenged, contest 0: 0-0=1, 0-1=0, contest data "Write-in: Ada Lovelace".`, then
  `Done.`, then the expected ReadKey `InvalidOperationException`. `tally.json` (21:50:15) has 0-0: 3, 0-1: 0 and every
  field 0.

Re-pinned: nothing.

Gate after:
- Build: `0 Warning(s)`, `0 Error(s)`.
- Tests: Core `Passed: 1560, Total: 1560` (+6); Perf `Passed: 226, Total: 226`.
- Smoke `--repeat 5` ×2 (groups d0adc6be and 47eac1db), every run `correctness passed`:
  - EncryptBallots 0.211-0.259 ms/ballot, 165.0-165.8 MB.
  - VerifyBallots 1.040-1.098 ms/ballot, 11.1-12.4 MB.
- Console: the same lines. `tally.json` and `challenged-ballots.json` were rewritten at 21:54:56, with 0-0: 3, 0-1: 0
  and every field 0.

Open question widened (no new question):
- **Q-S7b (RLA partial decryption):**
  - (a) As built: V13 accepts whole contests left out, and requires every field of a decrypted contest. V14.B
    applies to the decrypted ballot, so any partial decryption fails 14.B.
  - (b) Support RLA as p.52-53 describe it. V13 would let a decrypted contest omit fields, using the ballot's own
    (α, β) for those in χ_i, and skip 13.4-13.A when ξ_i is withheld (duplicates and unknown labels still
    `"13.structure"`). V14.B would check against the encrypted ballot, and 14.C-14.F only what was released.
  - Recommendation: (a) until an audit flow is specified.

Carry-overs (in addition to S7's and round 1's): a guardian-side check against the published record's cast ballots,
matching on id_B, H_I or C_ξB,0 (an overload taking that set), for a distributed deployment.

### 2026-10-06 — S7 review round 1 (G18: V13 contest data binding, challenged-ballot fallback, test gaps)
Worktree changes only; nothing staged or committed. Six findings. Two major findings are accepted and fixed in the
library, and they are the same gap reported by three lenses. Three minor test findings are accepted. One minor
finding is recorded as an open question and a carry-over, not built.

**Major (spec, code and tests lenses): V13 did not bind the released contest data nonce to the ballot. Accepted, fixed.**
`ChallengedBallotDecryptionVerification` recomputed α = g^ξ_i and β = K-hat^ξ_i (13.4/13.5) and checked only
C_1 = D ⊕ k (13.A). The contest hash χ_i (13.3) hashes the ballot's own (C_0, C_1, C_2), not α, so 13.B never sees
ξ_i. A publisher could release any ξ' together with D' = C_1 ⊕ k(ξ'), and both V13 and V14 accepted it: forged
write-in text on a challenged ballot. The spec's 13.4-13.A has no α = C_0 step (pp.54, 92), so this is a spec gap. It
is not a wrong formula. The selections need no such check, because their recomputed (α_{i,j}, β_{i,j}) enter χ_i.
- Fix: before 13.A's D check, V13 requires g^ξ_i = the ballot's C_0 and fails `"13.A"` with a message naming C_0.
  13.A is the label because 13.4's α is the α of eq. (65), which for the ballot's ciphertext is C_0. This is library
  hardening, like S6's C_0 membership check; see the S7 design choices and open question Q-S7c. The cost is one
  comparison, since α was already computed. An honest record never meets it: `TallyAdmin.CombineChallengedBallot`
  already refuses to publish a ξ that does not reproduce C_0.
- Tests:
  - `Verification13_ContestDataForgedUnderAnotherNonce_Fails13A` builds the consistent forgery (ξ' = ξ + 1, D' from
    k(ξ')). It first asserts that D' decrypts C_1 under ξ', so the old 13.A holds by construction, then asserts
    `"13.A"` and the C_0 message.
  - The existing tamper rows now tell the two 13.A causes apart by message: "wrong contest data ξ" fails on C_0,
    while "tampered D" and "D one block short" fail on `C_1 is not D XOR`.
  - Mutation check (run, then reverted): with the comparison disabled, both tests fail.
- The admin branch "contest data nonce ξ (eq. 64) does not reproduce C_0" had no test, because the "another nonce"
  test fails at the first option's α. New `CombineChallengedBallot_ContestDataEncryptedUnderAnotherNonce_PublishesNothing`
  uses honest selections with contest data encrypted under another ballot nonce. It asserts that no guardian is named
  and checks that exact message.

**Minor (tests): no partly decrypted ballot with contests of both kinds. Accepted.** A new shared fixture
`TwoOfThreeContests` has a three-contest manifest. Its ballot style lists contests 1 and 3, so the ballot's second
contest has ind_c 3 at position 2. Contest 1 carries contest data and contest 3 carries none. The ballot is opened by
guardians 1 and 2. `Manifest.Validate` requires each contest index to equal its list position, so non-contiguous
ind_c can only come from a ballot style. New tests:
- `Verification13And14_BallotStyleSkippingAContest_AcceptTheFullDecryption`.
- `Verification13_OnlyOneOfTwoContestsDecrypted_VerifiesAndCatchesAWrongValue`, run for each contest. V13 accepts
  the partial decryption, and a wrong σ in the decrypted contest fails 13.B. Keying a hash by ballot position, or
  ordering the mixed hashes wrongly, would fail the honest case.

**Minor (tests): untested failure branches. Accepted.**
- V13: `"no contest list"` and `"null contest entry"` (13.structure rows), plus
  `Verification13_ContestDataReleasedForAContestWithout_Fails13Structure` on the two-contest fixture.
- V14: `"undervote difference L + 1"` (14.E), and `"no contest list"`, `"null contest entry"`, `"no option list"`,
  `"no supplemental field list"`, `"null option entry"` and `"null supplemental field entry"` (14.structure).

**Minor (spec): no fallback when the nonce route fails. Not built; recorded as Q-S7d and a carry-over.** §3.6.7
p.51 makes the nonce route the efficient alternative to decrypting "with their shares of the election secret key".
p.53 expects nonces that "may only reflect that the ballot nonce encryption was incorrect". So a device that
encrypted a wrong ξ_B, or a guardian that sends a wrong m_i (which cannot be named, Q-S7a), leaves a challenged ballot
that `CombineChallengedBallot` refuses and that nothing else can open. Each option is a design choice the spec does
not settle:
- Falling back to §3.6.5-style per-selection verifiable decryption needs a single-ballot statement path (S4's
  `EncryptedTally` skips challenged ballots) and a published record that Verifications 13/14 do not describe.
- Retrying other k-subsets helps only against a bad m_i, and only when more than k guardians are available.

Gate before any test edit (V13 fix in; no test or doc touched):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Tests: Perf `Passed: 226, Total: 226`; Core `Passed: 1539, Total: 1539`. No test failed, so nothing needed
  re-pinning.
- Smoke: `correctness passed`.
  - Timings: dkg 146 ms; EncryptBallots 0.265 ms/ballot, 165.7 MB; VerifyBallots 1.098 ms/ballot, 12.3 MB; Tally 9,
    VerifyTally 4, DecryptTally 37, VerifyDecryption 8 ms.
  - Notes: `tallyVerification: ran`, `decryptionVerification: ran`.
- Console: `Challenged ballot 0-challenged, contest 0: 0-0=1, 0-1=0, contest data "Write-in: Ada Lovelace".`, then
  `Done.`, then the expected ReadKey exception. `tally.json` (21:23:54) has 0-0: 3, 0-1: 0 and every field 0.

Re-pinned: nothing.

Gate after:
- Build: `0 Warning(s)`, `0 Error(s)`.
- Tests: Core `Passed: 1554, Total: 1554` (+15); Perf `Passed: 226, Total: 226`.
- Smoke ×2, each `correctness passed`: EncryptBallots 0.279 / 0.263 ms/ballot, 165.6-165.8 MB; VerifyBallots
  1.125 / 1.051 ms/ballot, 12.4 MB; DecryptTally 37-45 ms.
- Console: same lines as before. `tally.json` and `challenged-ballots.json` were rewritten at 21:32:03, with 0-0: 3,
  0-1: 0 and every field 0.
- Note: the first after-gate run of smoke, console and tests used a stale build that still held the mutation-check
  edit. Restoring the file with Copy-Item kept its old timestamp, so the incremental build skipped it. The two
  mutation-sensitive tests failed in that run. After touching the file and rebuilding, the numbers above are from
  the correct build.

Perf: no hot path changed. V13 is not in egperf, and the only library change is one comparison in it. The smoke wall
times are 5-10% above S7's runs (0.230-0.247 and 0.995-1.046 ms/ballot) on identical encrypt and verify code, and
allocation is unchanged. That is machine load, not this change.

Open questions added (for the user; both implemented or left as described):
- **Q-S7c (13.A hardening):** (a) as built, the α = C_0 comparison reports as `"13.A"`; (b) give it its own documented
  sub-section label (for example `"13.structure"` or a new `"13.A0"`); (c) remove it and follow the spec's letters
  exactly, which leaves the forgery open. Recommendation: (a).
- **Q-S7d (no fallback):** (a) as built, nothing is published and the ballot stays unopened; (b) fall back to a
  per-selection verifiable decryption (S4 engine, 0x30/0x31 hashes) of the challenged ballot's ciphertexts, and
  define how V13/V14 check it; (c) have the administrator retry other k-subsets of the received m_i before giving up.
  Recommendation: (a) for now, with (c) as a cheap later addition and (b) only once an audit flow is specified.

Carry-overs (in addition to S7's): the Q-S7d fallback.

### 2026-10-06 — S7 (ballot nonce and challenged ballots: G17, G18)
Worktree changes only; nothing staged or committed. The KAT oracle (`test/kat/*`) was extended by the orchestrator
before this stage with eight families (`ballot_nonce_*` ×4, `challenged_ballot_*` ×4) and a `challenged_ballots`
summary; this stage makes them pass through the library. All eight passed on the first run, with no library fix
needed for any byte.

**G17 (encrypted ballot nonce, §3.3.4 eqs. 34-38):**
- Checked against p.30 (page text and the KAT oracle's 300 dpi reading). The old `BallotNonceEncryption` already
  produced the spec's bytes: h = H(H_I; 0x22, α_B, β_B), k_1 = HMAC(h, 0x01 ‖ "ballot_nonce" ‖ 0x00 ‖
  "ballot_nonce_encrypt" ‖ 0x0100) (one-byte counter, two-byte length, not eq. 66's form), C_1 = b(ξ_B, 32) ⊕ k_1,
  c_B = H_q(H_I; 0x23, a_B, C_0, C_1) (len 1057, §5.5.3 p.75). It was rewritten as a public static class with the
  shared pieces (`SecretKey`, `EncryptionKey`, `ProofChallenge`, `ProofHolds`, `Encrypt` with optional ξ-hat_B/u_B,
  `Decrypt`), on pooled buffers, clearing β_B's buffer and h after use.
- Not a confirmation code input: eq. (71) hashes only χ_1..χ_m and B_C, and eq. (70) only the selection and contest
  data ciphertexts. Confirmed by `Encrypt_TheEncryptedBallotNonceIsNotAnInputToTheConfirmationCode` and the KAT (the
  ballot encrypted with the oracle's ξ-hat_B has the 13.B vector's H_C).
- `EncryptedBallot.EncryptedBallotNonce` (required; new `EncryptedBallotNonce` type with C_0 as `IntegerModP`,
  replacing `EncryptedData`, also on `PreEncryptedBallot`). The encryptor stores the C_ξB it already computed. JSON:
  `encryptedBallotNonce` (required property; C_0 through the strict converter). Protobuf: ballot field 10, reusing the
  `ProtobufEncryptedData` DTO; the decoder refuses a missing field, C_1 not exactly 32 bytes, and non-canonical
  C_0/c_B/v_B (`NonCanonicalEncodingException`). `BallotStructure` requires the field with a 32-byte C_1 (so
  6/7/8/9.structure). Test seam `BallotEncryptor.BallotNonceEncryptionNoncesForTesting`.

**G18 (challenged ballots, §3.6.7 eqs. 107-111, Verifications 13 and 14):**
- `TallyGuardian.DecryptBallotNonce(ballot, record)`: requires status `Challenged`, `BallotStructure` and
  H_I = H(H_E; 0x20, id_B) (`ArgumentException`), then C_ξB,0 in Z_p^r (the S6 carry-over) and the eq. (38) proof
  (`TallyDecryptionException`, no guardian named), then m_i = C_ξB,0^{ẑ_i} through `MontgomeryModP.PowModP`. One
  message (`BallotNoncePartialDecryption`); it does not touch a tally or contest data session. The tamper seam is
  called with (0, 0, m_i).
- `TallyAdmin.DecryptChallengedBallot`/`CombineChallengedBallot`: the same ballot checks; a quorum of distinct
  senders, one message each, for this ballot (else the sender is named), no zero m_j (named); β_B = ∏ m_j^{w_j}
  (eq. 108, constant-time), ξ_B (eq. 35/36); for each verifiable field ξ_{i,j} (eq. 33), α must equal g^ξ, σ found in
  [0, range bound] by K^ξ·K^σ = β (eq. 109; a few multiplications); for each contest data field ξ (eq. 64),
  C_0 = g^ξ, D by eqs. (110), (65), (66), (111). Any mismatch throws naming no guardian ("did not decrypt
  consistently"): with no proof for m_i, a wrong share and a wrong C_ξB look the same (p.53). ξ_B's bytes are cleared
  after use and never returned.
- Published record `DecryptedChallengedBallot` (§3.7 "the selections made on the ballot, the plaintext
  representation ..., decryption nonces"): per contest the options and supplemental fields as `DecryptedChallengedField`
  (label, σ, ξ_{i,j}) in manifest order, and `DecryptedChallengedContestData` (ξ, D, `DecodeText()`).
- `ChallengedBallotDecryptionVerification` = Verification 13: `"13.structure"` (other ballot, not challenged,
  `BallotStructure`, H_I, decrypted contest not on the ballot or listed twice, not exactly one release per option and
  declared field, contest data released where none is carried or the reverse), then per contest 13.1/13.2
  (α = g^ξ, β = K^{σ+ξ}), 13.3 (χ through `ContestHash`, keyed by ind_c, with the ballot's own C_0, C_1, C_2),
  13.4-13.7/13.A (with α = g^ξ, β = K-hat^ξ, KDF counter 1-based per Q6), then 13.B (H_C over the χ in contest-index
  order, B_C from the device hash and previous code as in V8). A contest left out (the RLA case) enters 13.B with its
  χ recomputed from the encrypted ballot.
- `ChallengedBallotWellFormednessVerification` = Verification 14: `"14.structure"` (other ballot, not challenged,
  unknown style, null/repeated entries), 14.A-14.D (labels against the style and the manifest, supplemental fields
  like options), then 14.E (σ in 0..R, or the field's bound) and 14.F (options + write-in count <= L, Q13).
- Console: the first ballot is encrypted again as `0-challenged` and challenged; V5-V8 and V11.D cover all four
  ballots, V9 and the tally the three cast ones; the challenged one is decrypted by all three guardians and checked by
  V13 and V14; output `challenged-ballots.json` (and `encrypted-json-ballots\0-challenged.json`) in
  `C:\temp\eg\data\1`. No input file there changed, so no .bak was made. Contest data decryption now covers cast
  ballots only (all three, as before).
- egperf: no challenged phase (see carry-overs).

Gate before re-pinning (code and the console in; the test project only compile-fixed: `EncryptedBallotNonce`
copied into the 11 hand-built ballot clones, `ElectionFixtureBuilder.PlaceholderBallotNonce` on 4 synthetic ballots,
and `new IntegerModP(data.C0)` -> `data.C0` in `BallotPreEncryptorTests`, which no longer compiled; no assertion
touched):
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke: `correctness passed`. dkg 140 ms; EncryptBallots 245 ms, 0.245 ms/ballot, 165.7 MB; VerifyBallots 1,034 ms,
  1.034 ms/ballot, 12.4 MB; Tally 9, VerifyTally 4, DecryptTally 34, VerifyDecryption 8 ms; `tallyVerification: ran`,
  `decryptionVerification: ran`.
- Console: `Ballot 0, contest 0: contest data "Write-in: Ada Lovelace".`, `Challenged ballot 0-challenged, contest 0:
  0-0=1, 0-1=0, contest data "Write-in: Ada Lovelace".`, `Done.`, then the expected ReadKey `InvalidOperationException`;
  `tally.json` rewritten at 20:48 with 0-0: 3, 0-1: 0, every supplemental field 0.
- Tests: Perf `Passed: 226, Total: 226`; Core `Failed: 1, Passed: 1417, Total: 1418`. The failure was
  `KnownAnswerTests.EveryVectorFamilyIsCheckedOrExplicitlyUnsupported` (the eight new oracle families were not yet
  checked), which the new KAT tests close by design.

Re-pinned: nothing. No existing expectation moved. One test helper was corrected:
`StrictDecodingTests.WithIdentifier` rebuilt the protobuf DTO without the new nonce, so its two id_B cases would have
failed on the missing nonce instead of on id_B; it now copies it.

New tests (Core 1418 -> 1539):
- KAT (`KnownAnswerTests.ChallengedBallots.cs`, 37): `BallotNonceSecretKey_Eq35` (4), `BallotNonceKdfKey_Eq36` (4;
  the 36-byte message), `BallotNonceEncryption_Eq34To38` (4, incl. ξ_B = 2^256 - 1 and ξ-hat_B = q - 1: C_0, C_1, c, v,
  the proof, h, k_1, decryption), `BallotNonceDecryption_Eq107And108` (4: each m_i through the guardian, w_i, β_B, h,
  k_1, ξ_B), `ChallengedBallotContestDataSecretKey_Verification13_4To13_6` (4), `..._KdfKey_Verification13_7` (7),
  `ChallengedBallotContestHash_Verification13_1To13_3` (5, incl. the sparse ballot's ind_c 2 and 5 and a contest
  without contest data), `ChallengedBallotConfirmationCode_Verification13B` (2, no and simple chaining), the oracle's
  two ballots end to end through guardians, administrator, V13 and V14 (every released ξ, σ, contest data ξ and D
  equal to the oracle's; ξ_B not among them), and the main-chain ballot through `BallotEncryptor` (its C_ξB equals the
  oracle's, its H_C the 13.B vector's; challenged, opened, V8/V13/V14 accept).
- `ChallengedBallotDecryptionTests` (56): every quorum opens a ballot and V13/V14 accept; released nonces are
  exactly eqs. (33)/(64) and the published JSON does not contain ξ_B; an overvote opens as the neutralized contest;
  C_ξB is not a confirmation code input; refusals: cast/not-submitted ballot (guardian and administrator), malformed
  ballot or foreign H_I, a broken eq. (38) proof (response, challenge, C_1, C_0; guardian and administrator), a
  non-member C_ξB,0 with a valid forged proof (zero; negated with an even c_B); a wrong m_i and a C_ξB of another nonce
  publish nothing and name no guardian; a zero m_i, a message for another ballot and a repeated message name the
  guardian; no quorum; V13: 15 tampers (wrong σ of an option or field, wrong or swapped ξ_{i,j} -> 13.B; wrong
  contest data ξ, tampered or short D, D and σ both -> 13.A; other ballot, contest not on the ballot or twice, option
  missing or twice, field missing, contest data missing -> 13.structure), a cast ballot (13/14.structure), malformed
  ballot or foreign H_I, another device (13.B), a partial decryption (V13 accepts, 14.B fails); V14: 15 tampers
  (14.A, 14.B, 14.C ×2, 14.D ×2, 14.E ×4, 14.F ×2 incl. the Q13 write-in case, 14.structure ×3) and indicators and
  the undervote difference not counted as selections.
- `EncryptedBallotNonceSerializationTests` (3): JSON and protobuf round trips keep C_ξB and its proof; JSON with the
  property missing (`JsonException`) or null (decodes, then `"6.structure"`).
- `StrictDecodingTests`: JSON `ballot nonce C0 = p`; protobuf: nonce missing, C_0 = p, C_0 of 513 bytes, C_1 of 31
  and 33 bytes, C_1 missing, c_B = q, v_B = q.
- `BallotStructureTests`: four shapes × V6/7/8/9 (nonce missing; C_1 one byte short, one byte long, null).
- `ProtobufEncryptedBallotSerializerTests.SerializedDto_NonListFields_RoundTripCorrectly_WhenInspectedDirectly`
  (which claims every ballot-level field) also asserts the DTO's C_ξB parts. No new test case.
- Mutation check (run, then reverted): with the C_ξB,0 membership check disabled, both forged-C_0 cases fail.

Gate after:
- Build: `0 Warning(s)`, `0 Error(s)`.
- Smoke ×3, each `correctness passed`: dkg 141-142 ms; EncryptBallots 0.247 / 0.243 / 0.230 ms/ballot,
  165.6-165.8 MB; VerifyBallots 1.030 / 0.995 / 1.046 ms/ballot, 12.4 MB; Tally 8-9; VerifyTally 4; DecryptTally
  34-35; VerifyDecryption 8-9 ms.
- Console: as before re-pinning (`Challenged ballot 0-challenged, contest 0: 0-0=1, 0-1=0, contest data "Write-in:
  Ada Lovelace".`, `Done.`, the expected ReadKey exception); `tally.json`, `contest-data.json` and
  `challenged-ballots.json` rewritten at 21:03:13; counts 0-0: 3, 0-1: 0, fields 0; `contest-data.json` holds
  ballots 0, 1, 2.
- Tests: Core `Passed: 1539, Total: 1539`; Perf `Passed: 226, Total: 226`.

Perf against S6 (same machine; `compare --baseline 20261006T031405Z-a89c53 --candidate 20261007T010213Z-a46335`):

| Phase | S6 | S7 |
|---|---|---|
| EncryptBallots | 0.237-0.246 ms, 179.2 KB/ballot | 0.230-0.247 ms, 173.8 KB/ballot (-3.1%) |
| VerifyBallots | 0.965-0.996 ms, 12.96 KB/ballot | 0.995-1.046 ms, 12.96 KB/ballot (-0.07%) |

Encryption did the C_ξB work before S7 and threw it away; it now keeps it and builds its hashes in pooled buffers,
hence 3% less allocation. Verification allocates the same; its only new work is a null and length check of C_ξB in
`BallotStructure`, so the 3-5% wall-time difference is run-to-run noise. `compare` flagged VerifyTally (+4.7%) and
VerifyDecryption (+3.6%) allocation as REGRESSION: about 50 and 7 bytes per ballot on paths S7 does not touch, and the
four S7 runs alone spread 1,001-1,087 and 183-193 bytes (the cold-run variance in memory). Serialized ballot: JSON
about 20.1 KB -> 20.9 KB, protobuf 11,824 -> 12,444 bytes (C_ξB). The scenario and manifest hashes did not change, so
S6 records remain comparable.

Open questions for the user (implemented as the recommended option; neither changes bytes the spec defines):
1. **Ballot nonce decryption has no proof (§3.6.7).** (a) As built: m_i alone; a wrong share is detected (nothing
   published) but not attributed. (b) Add an unpublished per-guardian Chaum-Pedersen proof that
   log_g(K-hat_i) = log_{C_ξB,0}(m_i), with an invented domain separator, so that the administrator can name the
   guardian. Recommendation: (a), since the spec defines no such proof and (b) invents interoperable bytes. Note that
   the S4/S6 three-round engine would also give every guardian β_B, so ξ_B.
2. **Verification 14.B on a partial (RLA) decryption.** (a) As built: 14.B applies to the decrypted ballot, so a
   decryption that leaves out contests fails 14.B although 13.B accepts it. (b) Check 14.B against the encrypted
   ballot (which `BallotStructure` already ties to the style) and 14.C-14.F only for the contests decrypted.
   Recommendation: (a) until the RLA flow is specified; the library decrypts every contest.

Carry-overs:
- No egperf challenged-ballot phase: the runner streams and discards ballots, so a phase needs retained ballots plus
  a `PhaseSettings` flag, CLI override, result-schema key and report support. Its cost per challenged ballot is about
  2k full-width exponentiations for k guardians (k checks of the proof, k m_i) plus the administrator's 2 + k, then
  3 per verifiable field (α, K^ξ, and V13's α, β) and 4 per contest data field. Unit tests, the KAT and the console
  exercise the path.
- A `DecryptedChallengedBallot` record serializer (with the S4/S6 record serializer carry-overs, S10).
- S9 (pre-encrypted recording tool, G31) will reuse `BallotNonceEncryption` and `CombineChallengedBallot`'s
  derivations for uncast pre-encrypted ballots (Verification 19).
- Trust boundary (spec-silent): a guardian refuses a ballot whose `Status` is not `Challenged`, but it reads the
  status from the ballot object the administrator hands it. In-process that is the record; in a distributed
  deployment a guardian should check the status against the published record, not the administrator's copy.
  (Sharpened in S7 review round 2: the match must be on id_B, H_I or C_ξB,0, not on the string `Id`.)

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
membership check (done in S7: `ChallengedBallotStatement.RequireDecryptable`), and no egperf contest-data phase.

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
(Done in S7: guardians and the administrator require C_ξB,0 in Z_p^r before the eq. (38) proof.)

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
  *Closed in S10a: the tally record carries each contest's cast weight, which restores the bound; V9 checks it.*
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
  supplemental fields. *Closed in S10a (missing lists read as empty and fail `"N.structure"`; missing scalars are
  `NonCanonicalEncodingException`).*
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
  - *Closed in S10a: `EncryptionRecord.Manifest` is parsed from `ManifestFile` by `ManifestSerializer`.*
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
