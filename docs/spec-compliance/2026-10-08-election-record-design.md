# ElectionGuard Record Format (EGRF) v2: the canonical election record (S10b design)

Status: design for Q37 part B, in implementation since stage S10b-A. Rewritten 2026-10-09 to apply every user answer
recorded in the tracker (`2026-10-04-fix-progress.md`, Decisions: "S10b design answers, 2026-10-09", "S10b follow-up
answers, 2026-10-09" and "EGRF v2 new questions, answered 2026-10-09").

**Revision 3 (2026-10-09, stage S10b-A): NQ-1 to NQ-6 are answered and applied** (§11), and the first steps are
implemented (§9.2: S10b-0, S10b-1, S10b-1b, S10b-2). What the answers changed:

- **No per-item extensions (NQ-1).** The `extensions` list on `RecordItem` is gone. The profile now allows unknown
  fields, but only after every known field of their message, in field-number order, and a reader keeps them when it
  re-encodes. Field numbers are append-only, so this is exactly what an older library sees in a newer record. A
  verifier reports a newer `format_minor` as informational and verifies everything it understands (W6, §4.4, §7).
- **Election facts live in the manifest (NQ-4).** `RecordHeader` carries only `format_major` and `format_minor`.
  The manifest gained optional name, date, type, jurisdiction and location fields, bound into H_B through its bytes.
- **The manifest reader ignores unknown properties (NQ-1).** The manifest stays JSON, stored byte for byte; vendor
  data in it is ignored by the parser and still bound by H_B. Duplicate keys and malformed JSON are still refused.
- **Compact uncast form (NQ-2).** `PreEncryptedCompactUncastBallot` is mandatory for a pre-encrypted ballot that was
  printed and never returned, and is the form of any uncast ballot whose ξ_B is released (§3.2). It records no
  short codes or labels, so 17.A and 19.A-D hold by construction on it (§3.2, a divergence for the formal spec).
- **No JavaScript reader for now (NQ-3).** S10b-13 is deferred.
- **Guardians open uncast pre-encrypted ballots, later (NQ-5).** A new step after S10b, S10b-19.
- **No single-pass pipe input (NQ-6).** A non-seekable input is spooled to a temporary file (§5.4), as designed.

The schema is now `proto/electionguard/egrf/v2/egrf.proto`, compiled by the Core build (§4.6, §8.1).

**Revision 4 (2026-10-09, stage S10b-B): the readings R-1..R-3 are answered (§12) and S10b-3, S10b-4 and S10b-5
are implemented.** R-1 ("Whenever ξ_B is released") and R-2 ("Pass, flagged incomplete") keep what was built. R-3
("Ignore them too") removes the near-miss refusal: the manifest reader ignores every unknown property (§4.6). The
user also answered the open spoiled-ballot question ("Refuse spoiled too"): the guardian's view of the sealed record
holds cast and spoiled ballots, and a nonce request matching either is refused (§3.3). The canonicality check
(`CanonicalProtobuf`, §4.4), the domain mappers with the range table fixed (§4.8) and the Merkle tree, TOC and phase
roots (§4.9) are in `src/ElectionGuard.Core/RecordFormat/`; the vectors are in `test/egrf/vectors/` (§5.7).

**Revision 5 (2026-10-10, stage S10b-C): the carriers, the JSON projection and V14's labeling.** S10b-6 (directory
carrier: the phase-gated writer, the streaming reader, `ResumeAsync` with torn-tail repair), S10b-7 (the `.zip`
carrier with this library's own zip reader, which checks local headers against the central directory; non-seekable
input spooled) and S10b-10 (the proto3 JSON projection with duplicate, alias and two-oneof-member refusal;
`ConvertAsync`; `DiffAsync`) are implemented. §8.3 lists where the build differs from the sketch. The user answered
the V14 question ("14.structure for mismatches", §4.6, §12): 14.B and 14.D are presence checks, and a pairing of
index and label that is not the manifest's is `14.structure`.

**Revision 6 (2026-10-10, stage S10b-D): verification, attestations and signatures; NQ-7 and the JSONL final line
feed.** S10b-8 (`DeviceChainWalker`, `SpillingIdentifierSet`, the standard-form V9 merge, `JoinCursor`), S10b-9
(`ElectionRecordVerifier.VerifyAllAsync` and `VerifyAggregatedAsync`, the profiles, the report, checkpoints,
`VerifiedAggregate`) and S10b-11 (statements, `ecdsa-p256-sha256` signers and verifiers, the writer's attestations and
record signatures, `SignaturePolicy`) are implemented; §8.3 "As built (S10b-D)" lists where the build differs. The user
answered NQ-7 ("Bump the major version": a new section kind needs a new major, no generic path; §4.3 D2, §4.5, §5.3.1,
§6.9, §7) and the S10b-C JSON lines question ("Optional": the last line feed may be absent, §5.5). NQ-8, NQ-9 and NQ-10
(§12) are new and do not block. Review round 1 put V15 and V16 in the guardian profile and V15 in the ballot
correctness profile (spec p.64), made every publisher-controlled fault a finding rather than an exception, digests the
guardians' second read against the verified roots, and raised NQ-11 (V17 in the guardian profile). Review round 2
checks a full uncast item from its printed content before its release (6.A, 16.A-16.C, 17, 19) and leaves V6 and V16
`NotEvaluable` over a compact one, never `Passed` (§6.9, NQ-10 revised); recognizes a later major by the header
section's segment header before the layout and D6 checks (§4.5, §5.3.1, §7); reports a device kind of a newer minor
as `R.version` (§7; since round 3 only in a join item's locator); and checkpoints only a record with a claimed TOC (§6.8). Review round 3 runs a compact uncast
item's 16.C from its printed χ, B_C and H_C before its release (§8.3, NQ-10); reports a device header of an undeclared
kind as a header that does not match its section, since v2's layout has no path for such a device (§7, NQ-9); and
makes the writer drop the attestations of a device that closes empty and serialize its record-signature adds.

Revision 2 summary (kept for the tracker's references):

**Review round 1 and the feasibility proof are applied** (same day). Two design reviews and a four-runtime
feasibility run (Python upb, C# Google.Protobuf, protobufjs, protobuf-es; §4.4) checked this revision. Every
canonical-bytes claim held in all four runtimes. The changes they caused are in place, and §13 explains each finding
that was rejected or changed in scope. The main changes:

- `RecordHeader` carried §3.7's election-identifying facts (superseded by NQ-4: they are manifest fields now).
- The `critical` bit is fixed per section type (§4.5).
- Later tallies arrive as new section types (§4.5).
- Frames are capped at 64 MiB (§5.2).
- Carrier layout and conflict rules are normative (§5.3.1).
- Single-pass reading from a pipe is dropped (§5.4, NQ-6).
- The JSON text is not canonical; only its parsed structure is (§5.5).
- Method B named its discard-unknown call for each runtime (superseded by NQ-1: Method B keeps unknown fields).
- Signed statements get the canonicality check (§4.9).

Spec basis: ElectionGuard v2.1.0 §3.6.1 (p.45), §3.7 (pp.55-56), §4.3-§4.5 (pp.61-64) and §6 (pp.79-99). Nothing
here changes a spec hash input (H_P, H_B, H_E, H_I, χ, H_C, B_C, ψ or any proof challenge). Every byte that S1-S10a
fixed stays where it is. The record format sits on top of those values.

**Format numbering.** This is format major **2**. Major 1 was the custom binary design that the user rejected (#1,
#13). It never shipped, so no record with major 1 exists, and the number is retired so that nobody mistakes one for
the other.

## 0. What changed from v1, and what did not

| Area | v1 (2026-10-08) | v2 (this document) | Decision |
|---|---|---|---|
| Canonical encoding | custom fixed-schema binary hash form | a **canonical protobuf profile**: the `.proto` is normative, and every item has exactly one protobuf encoding (§4) | #1, #13, follow-up "Yes, canonical protobuf" |
| Value encoding | raw big-endian bytes | unchanged: raw fixed-width big-endian `bytes`; lists of fixed-width values packed into one `bytes` field for size (§4.6) | #3 |
| Naming | snake_case JSON, uppercase hex | snake_case in `.proto`; JSON is the proto3 JSON mapping (lowerCamelCase, base64, 64-bit integers as strings) (§5.5) | #3 |
| Ballot status | `not_submitted`, `cast`, `challenged` | `CAST`, `CHALLENGED`, `SPOILED`; zero value `UNSPECIFIED` is invalid in a record (§4.6, §8.3); C# `BallotStatus.Unrecorded`/`Spoiled` (S10b-1, done) | #4 |
| Never-returned pre-encrypted ballots | `PreEncryptedUnreturnedBallot` stub | recorded as challenged (uncast) pre-encrypted ballots with released nonces, in the compact form with ξ_B released (§3.2) | #5, NQ-2 |
| Uncast nonces | inside the uncast item, in the sealed device section | split: printed content stays in the device section, the nonce release is a final-phase item (§3.2, §4.5) | consequence of #5 and Q36 |
| Timestamps | optional, precision setting, privacy-risk framing | `google.protobuf.Timestamp`, UTC, millisecond precision, no precision setting (§4.3) | follow-up #6 |
| Header | `election_info` key/value registry | format version only; the election facts are optional manifest fields (§3.1, §4.6) | follow-up #9, NQ-4 |
| Manifest | `ManifestSerializer` reading rules as "manifest format 1"; writers SHOULD publish the written form | stored byte for byte as entered; `ManifestSerializer` only parses, ignoring unknown properties; H_B over those bytes (§4.6, §9.3) | #19, NQ-1 |
| Carriers | directory and ZIP64; tar and `.egr` considered | directory and `.zip`; no `.7z`, no tar; normative layout and conflict rules (§5.3.1, §5.4) | #14 (measured) |
| Single-pass reading | a `.zip` read from a pipe in one pass | dropped; a non-seekable input is spooled to disk first (§5.4) | review round 1; NQ-6 |
| Frame size | unbounded | at most 64 MiB per frame (§5.2) | review round 1 |
| Out-of-range values | asked (Q-11) | the format checks widths only; the verifier reports ranges under the lettered checks (§4.8) | #11 |
| Per-item extensions | in-band list with a critical bit | none; vendor data goes in the manifest or a vendor section (§7) | NQ-1 |
| Unknown fields | refused | allowed only after every known field, in field-number order; kept on re-encoding; a newer minor is reported, not failed (W6, §4.4, §7) | NQ-1 |
| Codec | hand-written | Google.Protobuf code generated from the normative `.proto`; protobuf-net retired (§8.1) | implementer choice, justified |

**Kept from v1:** the content map to §3.7/§4.4 and V1-V19 (§3); sections, the TOC and phase roots that are prefixes
of one another (§4.5, §4.9); the streaming verification model and its memory bounds (§6); device attestations and
detached record signatures with the recommended defaults (#7); the V5.A algorithm (§6.5); the contest-data request
set (follow-up #10); the optional unverified `ballot_ref` (follow-up #12); `derived/` lookup indexes outside the root
(follow-up #18); one tally in v2.0, with later tallies as new section types (#16); the tally header (#17); a decryption for
every challenged ballot (#8); SHA-256 with RFC 9162 Merkle framing (#2); the format and verify-all in Core with the
CLI in `ElectionGuard.Verifier` (#15).

**Facts from the current tree** (S10a is committed as c4f1093):

- **G40** landed as `EncryptedBallot.EncryptionTimestamp : DateTimeOffset?`, nullable, UTC, truncated to the
  millisecond. `encrypted_at` maps to it one to one.
- **The manifest** is parsed from `EncryptionRecord.ManifestFile` (S10a binding). H_B hashes the file's bytes as
  they are (§3.1.4), and §3.1.3 leaves the representation "implementation specific".
- **Measured verify cost.** The 2026-10-08 smoke runs (`perf/results/sethpc2023.jsonl`) show `VerifyBallots` at
  about 1,000 ballots/s at parallelism 32, about 12 MB/s of ballots. Verification is CPU-bound by a wide margin, so
  the encoding affects storage, download size and random access, not verify time: about 17 min for 1M ballots,
  2.8 h for 10M, 28 h for 100M. This is why resumable verification is in scope and findings are collected by default.
- **Measured compression (2026-10-09).** On current-format ballots the cryptographic payload is incompressible
  (deflate 1.000, LZMA 1.002). JSON compresses to 0.612 of its size with deflate and 0.609 with LZMA. That is why the
  container is `.zip` and why protobuf entries are stored, not deflated.
- **The protobuf nonce hazard (fixed in S10b-0).** `ProtobufEncryptedValueWithProofs.EncryptionNonce` and
  `ProtobufEncryptedValue.EncryptionNonce` had no `[ProtoMember]`, but the mapping still copied `s.EncryptionNonce`
  into the DTO, so every selection nonce was one attribute away from being serialized. The members, the copy and the
  unused `ProtobufEncryptedValue` struct are deleted; a reflection test pins that no DTO member can hold a nonce
  and that no nonce of a real ballot appears in its serialized bytes.

---

## 1. Goals and non-goals

### Goals

1. **G-1 Canonical.** Every record item has exactly one byte encoding: its canonical protobuf encoding under the
   profile of §4.2-§4.3. The rules leave no judgment calls, so implementers in any language reach identical bytes,
   and they can be lifted into a formal spec as is. Every digest, signature and equivalence claim is defined over
   canonical item bytes, never over files.
2. **G-2 Complete.** Every item that §3.7 and §4.4 list is in the record, and so is every input of Verifications
   1-19. Bytes the spec hashes (the manifest file for H_B; ver, p, q, g for H_P; B_C; χ; ψ) are stored as exactly
   those bytes.
3. **G-3 GB-scale.** The format handles 10^6-10^8 ballots (about 13 GB to 1.3 TB). It can be written while the
   election runs, one device at a time. Verification streams with memory bounded independently of N, except for one
   stated term (V5.A, 8 B per ballot, which spills to disk). It runs in parallel and across machines, and it can be
   resumed.
4. **G-4 Many representations, one meaning.** Protobuf and JSON (the proto3 JSON mapping), each in a directory or a
   `.zip`. Two representations are equivalent if and only if they have equal root digests, and converters must
   preserve the root.
5. **G-5 Integrity hooks.**
   - Phase roots: setup, sealed, aggregated and final. Each is a prefix of the next, with RFC 9162 consistency.
   - Detached record signatures with a signing date (§3.7).
   - Per-device chain-close attestations (S8b) and optional mid-election prefix checkpoints.
   - Merkle inclusion proofs for voters looking up confirmation codes.
6. **G-6 Versioned and extensible.** No reader can report a record as completely verified (`Complete`) while content
   it did not understand went unchecked, in any representation. Content from a newer format minor is reported as
   informational, not as a failure, and everything the reader understands is still verified (NQ-1, §6.9, §7).
7. **G-7 Any device, any language.** Any language with a protobuf runtime (C#, Java, Go, Python, JavaScript and
   TypeScript, Rust, C++, Swift, Kotlin) reads a record with code generated from the `.proto`. A runtime is not even
   required: the Python reference reader (§5.7) does it with the standard library alone, about 300 lines for the
   wire format, the canonicality walk and the Merkle roots.

### Non-goals

- Changing any spec hash input.
- Key management, PKI and trust anchors. The format carries signatures; who is trusted is verifier configuration.
- Voter-facing presentation (§4.4.1). Derived views are regenerable and outside the root.
- Guardian-to-guardian traffic: encrypted shares, partial decryptions, commitment and response messages. They are
  not in §3.7's list, and a vendor section can carry them.
- Guardian-private data: secret keys, shares, the nonces of cast ballots, ξ_B of challenged regular ballots, and the
  combined pre-encryption nonces of cast ballots. **No message in the schema has a field for any of them, so no
  representation can carry one.** A reflection test pins this (S10b-4).
- Pre-encryption tools (Q35). The record holds pre-encrypted ballots only as published inputs. Producing the released
  nonces of uncast ballots (§4.3.1: "guardians, an administrator, or a local database") is the out-of-scope recording
  tool's job; the record carries them and Verification 18 checks them. Since S9c, Core has no path that decrypts the
  C_ξB of a pre-encrypted ballot (`TallyGuardian.DecryptBallotNonce` takes a challenged `EncryptedBallot` only). So
  until S10b-19, a record with uncast pre-encrypted ballots can be completed only with nonces from that out-of-scope
  tool. NQ-5 ("Later: guardian opens from sealed record") adds S10b-19 after S10b: the guardians open an uncast
  pre-encrypted ballot from a sealed, verified record.
- Transport compression. Ciphertexts do not compress (measured above). Digests are always over canonical item bytes.

---

## 2. Concepts

| Term | Meaning |
|---|---|
| Item | One record value: a ballot, a device header, a tally contest, and so on. It is always a `RecordItem` message, whose `oneof` field number is the item type. |
| Canonical bytes | The one encoding of an item allowed by the profile (§4.2-§4.3). Stored, hashed and signed as is. |
| Section | A typed, keyed, ordered sequence of items. A record is the list of its sections in canonical order (ascending type, then key bytes). |
| Phase | The protocol stage a section belongs to: setup, voting (sealed), aggregated or final. It is the section type's high byte (§4.5). |
| Device section | The section of one device, keyed by its 33-byte device key `kind ‖ H_DI`. It holds `DeviceHeader`, then the device's ballots in chain order, then `DeviceClose`. It **is** §3.7's "ordered list of the ballots encrypted by each device". |
| Locator | `(kind, H_DI, position)`, position 1-based (the spec's j). A ballot's canonical address. |
| TOC | The table of contents: one `TocEntry` per section, giving (type, key, critical, item count, Merkle root). The record root is the Merkle tree hash over the TOC entries. |
| Phase root | The Merkle tree hash over the TOC entries of every section whose phase is at or before a given phase. |
| Representation | Protobuf (canonical item bytes verbatim) or JSON (the proto3 JSON mapping of the same items). |
| Carrier | A directory tree or a `.zip` archive. |
| Derived view | A regenerable file outside the root: lookup indexes, offset sidecars, inclusion proofs. |

---

## 3. Record contents mapped to the spec and to the verifications

### 3.1 §3.7 The Election Record (pp.55-56)

| §3.7 item | Record location | Consumed by | Note |
|---|---|---|---|
| Information that identifies the election (date, location, type, ...) "not otherwise included in the election manifest" | the manifest's optional `electionName`, `electionDate`, `electionType`, `jurisdiction` and `location` (S10b-1b), inside `ManifestFile.content` | none (informational; bound by H_B through the manifest bytes) | Follow-up #9: "Only what isn't in manifest"; NQ-4: "Optional manifest fields". `RecordHeader` carries only the format version. Further facts a jurisdiction wants recorded can be vendor properties of the manifest, which the parser ignores and H_B binds (NQ-1). |
| The election manifest file | `ManifestFile.content`: the bytes exactly as entered, with `media_type` | V1.F (H_B over these bytes); parsed for everything else | #19. The parsed `Manifest` is only ever derived from these bytes (S10a binding). |
| p, q, r with p = qr + 1 | `Parameters.p/q/r`, raw `bytes` of 512, 32 and 512 | 1.B, 1.C | Raw bytes, never `IntegerModP`/`IntegerModQ`, which would reduce p and q to 0 (decision G1). r is not checked (v2.1 dropped it from V1). |
| Generator g | `Parameters.g` | 1.D | |
| n, k | `Parameters.n/k` | 1.E (inputs to H_P) | |
| H_P | `Parameters.h_p` | 1.E | Stored as a claim, never recomputed on load |
| H_B | `ManifestFile.h_b` | 1.F | Claim |
| Commitments K_{i,j}, K̂_{i,j} | `GuardianPublicKey.vote_commitments/data_commitments` (k values each, concatenated) | 2.A, 2.C | Maps to `GuardianPublicView` |
| Proofs of possession | `GuardianPublicKey.vote_proof/data_proof` (c ‖ v_0 ‖ ... ‖ v_k) | 2.B, 2.C | |
| K and K̂ | `ElectionKeys.k/k_hat` | 3.A, 3.B | Claims; loaded with `ElectionPublicKeys.FromKeys`, never the product constructor |
| κ_i with its proof of knowledge | `GuardianPublicKey.kappa`; the proof is the (k+1)th response of each Schnorr proof | 2.A, 2.C | |
| H_E | `ElectionKeys.h_e` | 4.A | Claim |
| Every encrypted ballot | `EncryptedBallot` items in regular device sections | 5-8 (all), 9 (cast), 11.D, 13-14 (challenged) | Spoiled ballots are in the chain too (#4) |
| — id_B, H_I | `id_b` (field 1), `h_i` | 5.A, 5.B | |
| — encrypted selections | `contests[].fields[]` (α, β), in manifest field order | 6.A | Indices, not labels (§4.6) |
| — range proofs | `fields[].range_proof`: R+1 pairs (c ‖ v), or bound+1 for a supplemental field (Q2) | 6.B-6.D | |
| — selection limit of each contest | the manifest (`Contest.SelectionLimit`) | V7 | An election constant, not repeated per ballot |
| — selection-limit proof | `contests[].limit_proof` (L+1 pairs), plus `undervote_difference_proof` and `null_vote_proof` when tracked (Q15/Q17) | 7.B-7.D | |
| — ballot weight | `weight` (≥ 1, so always present) | V9 | |
| — ballot style | `ballot_style` (the manifest's ballot style id) | structure | |
| — device information | the enclosing section's `DeviceHeader` (S_device, H_DI, mode, H_0) | 8.C, 16.D | Satisfied by placement; ballots do not repeat the device id |
| — date and time of encryption | `encrypted_at`: `google.protobuf.Timestamp`, UTC, milliseconds | none | Follow-up #6: full precision, no precision setting. Optional, as in S10a's model. Not an input to H_C, so covered by the root (§6.6). |
| — confirmation code | `confirmation_code` (H_C), `chaining_field` (B_C) | 8.A, 8.B, 8.D, 8.E | |
| — status | `status`: `CAST`, `CHALLENGED` or `SPOILED` | 9 (cast filter), 13/14 (challenged) | #4. Not in H_C; protected by the root, the section seal and signatures. `SPOILED` is a divergence from §3.7's "(cast or challenged)" (§3.2, divergences). |
| (S7) encrypted ballot nonce C_ξB | `encrypted_ballot_nonce` (c0, c1 of 32 B, c2 = c ‖ v), the name of the domain `EncryptedBallotNonce` | structure, 13 | `ballot_nonce` is reserved for the plaintext ξ_B, which only `UncastNonceRelease` carries |
| — (follow-up #12) string ballot id | `ballot_ref`: optional free text | none | Unverified and bound by no hash; never trusted (Q31) |
| Decryption of each challenged ballot | `ChallengedBallotDecryption` (final phase): per field index, label, σ, ξ_{i,j}; contest data (ξ, D) | 13, 14 | Nonce form (S7): no proof, no ξ_B. Required for every challenged ballot (#8). |
| Encrypted tally of each option | `EncryptedTallyHeader` (#17) and `EncryptedTallyContest` (A ‖ B per field, `cast_weight`), aggregated phase | 9, 10 | `MaximumCount` is derived from `cast_weight` (S10a), never stored |
| Full decryptions, plaintexts, proofs | `DecryptedTallyContest` (index, label, t, T, c ‖ v per field), final phase | 10, 11 | |
| Ordered lists of ballots per device | the device sections themselves (chain order) plus `DeviceHeader`/`DeviceClose` (H_0, B̄_C, H̄) | 8.C-8.G, 16.D-16.H | `DeviceChainRecord.ConfirmationCodes` is derived from section order, never stored |
| Encrypted contest data when available | `contests[].contest_data` (c0, c1 = 32·b_Λ B, c2 = c ‖ v, Q20) | 8.A (in χ), 12 | Present iff b_Λ > 0 (S6) |
| (§3.6.6) contest-data decryptions | `ContestDataRequest` (aggregated) and `ContestDataDecryption` (final) | 12 | Follow-up #10: the request set is sealed before decryption |
| Signed by administrators, with the date | detached `SignedStatement`s over a `RecordStatement` per phase, with `signed_at` | R.signature | Outside the root, appendable |
| Full download | `.zip` carrier (§5.4) | | #14 |
| Tools for voters to look up confirmation codes | `derived/` lookup index plus inclusion proofs to a signed phase root | | Follow-up #18: alongside, not signed |

### 3.2 §4.4 Pre-encrypted ballots (pp.62-63), as built through S9c (Q26-Q36)

| §4.4 item | Record location | Consumed by |
|---|---|---|
| Cast: standard selection vectors with all standard proofs | `PreEncryptedCastBallot.contests[].contest` (an `EncryptedContest` each) | 5, 6, 7, 9, 11.D |
| Cast: selection hashes of every option, nulls included, sorted numerically per contest | `contests[].selection_hashes`: m+L values, strictly ascending | 16.A-16.C |
| Cast: short codes and pre-encryption vectors of the voter's selections (nulls included) | `contests[].selected[]`: exactly L entries (Q27 null padding), strictly ascending by ψ; no option named | 15.A, 17.A |
| Uncast, returned, ξ_B not released: the printed content | `PreEncryptedUncastBallot` (full form) in the printer's device section: every vector, ψ, short code, χ, H_C, B_C, C_ξB | 5, 6.A (range layer only, §4.8; uncast vectors carry no range proofs, and subgroup membership follows from 18.A's recomputation), 16, 17, 19 |
| Uncast, **printed and never returned** (or returned with ξ_B released): the printed content | `PreEncryptedCompactUncastBallot` (compact form, NQ-2): id_B, H_I, style, C_ξB, per contest (index, χ), H_C, B_C | 5; 16 and 18 on the content regenerated from ξ_B; 17.A and 19.A-D hold by construction (no displayed codes or labels are recorded) |
| Uncast: "the ballot nonce for that ballot is published" | `UncastNonceRelease` (final phase): for a full item, ξ_{i,j,k} per vector (Q28); for a compact item, ξ_B and nothing else | 18 |
| Confirmation codes from the full set of pre-encryptions | `confirmation_code` and `chaining_field` on every pre-encrypted item | 16.C, 16.E-16.H |
| Pre-encrypted device chains | pre-encrypting device sections: cast and uncast items interleaved in print order | 16.D-16.H |
| §4.4.1 presentation | derived views only | |

**Never-returned ballots (#5, NQ-2).** The user wrote: "pre-encrypted ballots never returned can be considered
challenged ballots". §4.3 already calls every uncast ballot "implicitly or explicitly challenged", so a printed ballot
that never came back is recorded as an uncast one: an item in the device section, in print order, and its opening in
the final phase. v1's `PreEncryptedUnreturnedBallot` stub, which published no nonces, is removed. The status of a
pre-encrypted item is implied by its type: a `PreEncryptedCastBallot` is cast, and a `PreEncryptedUncastBallot` or
`PreEncryptedCompactUncastBallot` is challenged. None carries a `status` field (field 4 is reserved on all three), so
the two can never disagree.

**The compact form (NQ-2: "Compact required for unreturned").** Everything printed on a pre-encrypted ballot (every
vector, ψ and short code) is a deterministic function of ξ_B (eqs. 113-121). So when ξ_B is released, the device
section keeps only what the verifier compares: id_B, H_I, the style, C_ξB, per contest (index, χ), H_C and B_C
(`PreEncryptedCompactUncastBallot`, about 0.8 KB instead of about 31 KB per contest at m = 5, L = 1). The verifier
regenerates the vectors and ψ from the released ξ_B and checks each χ and H_C against the item, which proves that the
ballot's ciphertexts, ψ and χ were the regenerated ones. It then runs V16 and V18 on the regenerated content.

**What the compact form cannot check (V17, V19).** χ (eq. 115) hashes the contest index ind_c(Λ) and the ψ values,
not any printed text, and the compact item records no short codes and no labels. 17.A (p.65) checks "the short code
ω displayed with the selectable option", and 19.A-D (p.67) check the contest and option text labels "on the uncast
pre-encrypted ballot" against the manifest. On a compact item the only codes are Ω(ψ) of the regenerated ψ and the
only labels are the manifest's, so 17.A and 19.A-D hold by construction and cannot fail. The report says so: it
counts the compact items whose 17.A and 19.A-D held by construction (§6.9), so that a V17 or V19 `Passed` is not
read as a check of what was printed on them. What was actually printed is checked only by the voter, who
compares the paper ballot with the derived view (§5.6) generated from ξ_B. Under R-1(a) (§12) this also applies to a
returned uncast ballot whose ξ_B is released, which is the ballot a voter actually audits; a full item records its
codes and labels, so V17 and V19 check them. Rules:

- **Never returned ⇒ compact.** A printed ballot that never came back is always written in the compact form, and its
  release carries ξ_B.
- **One representation per ballot.** The form follows from what is released: the compact form iff ξ_B is released
  (`UncastNonceRelease.ballot_nonce` present, `contests` absent), the full form iff it is not (`contests` present,
  `ballot_nonce` absent). So a returned uncast ballot whose ξ_B is released under Q28's opt-in is compact too, and no
  ballot has two valid encodings. A release that does not match its item's form is `18.structure`.
- **The format cannot tell never-returned from returned.** Both are uncast; the mandatory rule binds the writer
  (`DeviceSectionWriter.AppendUncastAsync`, §8.3), which is told which case it has.
- Releasing ξ_B on an uncast ballot reveals no voter choice: a pre-encrypted ballot encodes every option, and the
  voter's marks are on paper. Two departures go into the formal spec: from §4.3.1/§4.4's "posts ... the full set of
  pre-encryption vectors" (they are derivable instead), and the voter-facing short codes coming from derived views.

**Why the release is split from the printed content.** The device section is sealed when voting closes (R_sealed).
Whether a printed ballot was cast, returned uncast or never returned is known only once voting is over, and its
release opens it as a challenged ballot's decryption does. So the printed content belongs in R_sealed and the release
in R_final, exactly as a challenged regular ballot sits in its device section and its decryption in the final phase.
This is a placement rule only; it does not say who produces the nonces. Spec p.66 derives the ξ_{i,j,k} "from the
ballot nonce ξ_B via Equation 121 after it has been decrypted as specified in Section 3.6.7". Under Q35 that producer
is the out-of-scope recording tool (§1, Non-goals), until S10b-19 lets the guardians open an uncast ballot from the
sealed record (NQ-5). The mapper splits the domain `PreEncryptedUncastBallot` (`Ballot` + `BallotNonce?` + released
`Contests`) into the two items and joins them on read. v2.0 requires exactly one release for every uncast item. That
follows from #5 (an uncast ballot is challenged) together with #8 (every challenged ballot has its decryption), and
from §4.4, which publishes the nonces of every uncast ballot.

**Cost of #5.** The full printed content of an uncast ballot per contest is (m+L) vectors of m·1,024 B, each with
its 32 B ψ and its short code: (m+L)·(m·1,024 + 32) B plus framing and short codes, 30,912 B at m = 5, L = 1. NQ-2's
compact form removes that cost for every never-returned ballot, which is where a vote-by-mail election would pay it
most often; only returned uncast ballots whose ξ_B stays secret are written in full.

**Divergences to state in the formal spec:**

- §4.4 says the uncast "ballot nonce" is published. Q28 publishes the per-selection nonces ξ_{i,j,k}, and ξ_B only
  when opted in or when the ballot was never returned (NQ-2), in which case the compact item replaces the printed
  vectors.
- §3.7 lists "the status of the ballot (cast or challenged)". The record adds `SPOILED` (#4) for a submitted ballot
  that was neither: it is in the chain, counts for 5.A and 11.D, gets V6-V8, is never tallied, and is not decrypted
  by this library's paths (§3.3).
- Verifications 17 and 19 check what is displayed and printed on an uncast ballot: the short codes (17.A, p.65) and
  the contest and option text labels (19.A-D, p.67). A compact item records neither, and χ (eq. 115) binds the
  contest index and ψ, not the text. So for a compact item 17.A and 19.A-D hold by construction, and the voter's
  comparison of the paper ballot with the derived view is the only check of the printed text (see above).

### 3.3 Verification inputs

| V | Inputs | Record source |
|---|---|---|
| 1 | ver, p, q, g, n, k, H_P, manifest bytes, H_B | `Parameters`, `ManifestFile`; compared with `EGParameters` (CLAUDE.md: record parameters are claims) |
| 2 | K_{i,j}, K̂_{i,j}, κ_i, c_i, ĉ_i, v_{i,j}, v̂_{i,j}; H_P | `GuardianPublicKey` × n |
| 3 | K_{i,0}, K̂_{i,0}; K, K̂ | guardians, `ElectionKeys` |
| 4 | H_B, K, K̂, H_E | `ManifestFile`, `ElectionKeys` |
| 5 | id_B, H_I of **every ballot item in every device section**, any status or kind (§4.5 p.64) | ballot items (5.A is cross-ballot) |
| 6, 7 | α, β, proofs; R, L and option bounds from the manifest; K; H_I | ballot items + manifest |
| 8 | α/β, contest data, χ, B_C, H_C, H_I; S_device, H_DI, H_0, B̄_C, H̄ | regular items + `DeviceHeader`/`DeviceClose` |
| 9 | (α, β) of every cast ballot, weight; (A, B), cast weight | cast items (both kinds) + `EncryptedTallyContest` |
| 10 | (A, B), T, t, c, v; K, H_E | encrypted and decrypted tally |
| 11 | tally labels, manifest labels, contests on submitted ballots | `DecryptedTallyContest` + manifest + contest indices seen on every ballot item |
| 12 | H_I, C_0, C_1, C_2, β, c, v, D; K̂ | ballot + `ContestDataRequest` + `ContestDataDecryption` |
| 13 | σ, ξ per field; ξ, D per contest data; the ballot's ciphertexts, χ, B_C, H_C | ballot + `ChallengedBallotDecryption` |
| 14 | decrypted labels and values; manifest | `ChallengedBallotDecryption` + manifest |
| 15 | selected vectors, combined vector | `PreEncryptedCastBallot` |
| 16 | vectors/hashes, χ, H_C, B_C, H_DI, H_0, close | pre-encrypted items + their section's header and close |
| 17 | ψ, short codes | cast and full uncast items; for a compact item 17.A holds by construction (no displayed codes recorded; codes would be Ω(ψ) of the regenerated ψ, §3.2) |
| 18 | uncast vectors, released nonces, K (V18's recomputation also settles the subgroup membership half of 6.A for uncast vectors) | `PreEncryptedUncastBallot` + `UncastNonceRelease`; for a compact item, the content regenerated from the released ξ_B, whose χ and H_C must equal the item's |
| 19 | uncast labels, manifest | `PreEncryptedUncastBallot` + manifest; for a compact item 19.A-D hold by construction (no labels recorded; χ binds the contest index, not the text, §3.2) |

**Spoiled ballots and "submitted".** Verifications 5.A and 11.D speak of "submitted (cast and challenged)"
ballots. The user wrote (#4): "If we have it in the election record at all, it was by definition submitted." So a
spoiled ballot counts as submitted: it is in 5.A and 5.B, and its contests count for 11.D. It gets V6-V8 like any
other ballot, and it is not aggregated (V9 reads cast ballots only). It is not decrypted by this library's paths, and
a `ChallengedBallotDecryption` that names it is `13.structure` in the record. `TallyGuardian.DecryptBallotNonce`'s
status test checks only the status the requester states, so it is a sanity check. The guardian's real authorization
is its own view of the sealed record, `IPublishedCastAndSpoiledBallots` (S10b-B; was `IPublishedCastBallots`), which
holds the cast **and spoiled** ballots: a request whose id_B, H_I or C_ξB,0 matches either is refused, with reason
`CastBallot` or `SpoiledBallot` (user decision "Refuse spoiled too", 2026-10-09; a match on both is reported as
`CastBallot`). So an administrator who relabels a spoiled ballot as challenged is refused, as one who relabels a cast
ballot is. Challenged ballots are not in the view (they are the ones a guardian opens), and a ballot of the record
without a recorded status is refused when the view is built. The recorded status itself is protected by the section
seal and the signatures (S10b-6 onward). In v2.0 11.D cannot fail on a spoiled ballot alone, because the one tally lists every manifest contest.

---

## 4. Canonical form: the EGRF protobuf profile

### 4.1 Why a profile, and what it buys

The user decided that the canonical encoding is protobuf (#1: "It's important that the distributed format be
something that can be used on any machine"; #13: "we absolutely must be capable of working on any device in any
programming language, and it should be relatively easy to do so. Space is a concern, which is why protobuf over
json"). Protobuf on its own is not canonical. Its specification lets a parser accept fields in any order, repeated
singular fields (last one wins, or messages merge), overlong varints, explicitly written default values, and unknown
fields anywhere, and its "deterministic serialization" option promises stability only within one binary, not across
languages or versions. So EGRF v2 is protobuf **plus a profile**:

1. **Schema rules** (§4.2.1) restrict the `.proto` so that the standard encoders' natural output is the only valid
   encoding: no maps, no packed-or-unpacked choice, no signed or floating types.
2. **Wire rules** (§4.2.2) state that unique encoding normatively, so it does not depend on any runtime's behaviour.
3. **Decode rules** (§4.3) cover what an encoding cannot express: fixed widths, timestamp precision, enum and integer
   ranges.
4. **A check** (§4.4) that any language can run: walk the wire bytes against the schema, or parse, re-serialize and
   compare bytes.

The result is the property v1 had by grammar: a strict reader D and the writer E satisfy D(E(x)) = x, and whenever
D(b) is defined, E(D(b)) = b. Every digest is over the bytes as stored, so a protobuf reader hashes items in place,
never re-encoding GBs.

**Forward compatibility (NQ-1).** The user wrote: "Protobuf tends to be backwards compatible by default, so we should
be good with future versions already." The profile keeps that property without giving up uniqueness. A later format
minor only appends fields, above every number a message already declares, so in a canonical encoding the fields an
older reader does not know always come last, in ascending order (W6). An older reader keeps them when it re-encodes
(the default in C#, Python, protobuf-es, Go and Java; the placement is pinned for C# and still to be pinned for the
others, §4.4), so E(D(b)) = b still holds for it and every digest survives. It verifies what it understands and
reports the rest (§7).

### 4.2 Profile rules (normative)

#### 4.2.1 Schema rules

The schema is `proto/electionguard/egrf/v2/egrf.proto` (§4.6), package `electionguard.egrf.v2`. A schema lint test
(`EgrfSchemaLintTests`, S10b-2) enforces these rules on the compiled descriptor, and checks each one against a
deliberately broken copy, so a future edit cannot break them silently.

- **S1.** `syntax = "proto3"`.
- **S2.** Field types are `uint32`, `uint64`, `bool`, an enum, `string`, `bytes`, a message of this package, or
  `google.protobuf.Timestamp`. No `int32`/`int64`/`sint*`/`fixed*`/`sfixed*` (no negative values, no fixed-width
  wire types), no `float`/`double`, no `map`, no `google.protobuf.Any`, no groups.
- **S3.** No repeated scalar numeric field. A list is `repeated <message>` or one `bytes` field holding a
  concatenation of fixed-width values. **So the packed-versus-unpacked question never arises.** A future repeated
  numeric field would be packed, written as exactly one record, and omitted when empty.
- **S4.** No `optional` keyword. Every optional field is either a message (explicit presence by nature) or a
  `string`/`bytes` whose empty value is never valid when present (§4.2.3).
- **S5.** Within each message, fields (oneof members included) are declared in ascending field-number order. This is
  hygiene that keeps the schema readable, not the mechanism behind W1. All four tested runtimes write fields in
  field-number order even with scrambled declarations (feasibility run, `scratch_order.proto`).
- **S6.** Field numbers are append-only. A format minor version adds fields only with numbers above every number the
  message already declares, reserved numbers included, so an added field follows every older field on the wire (the
  basis of W6). The one exception is `RecordItem`: a new item type is a new member of its oneof, at any number not
  used or reserved before (§7). Removed fields become `reserved`, and a reserved number is never reused. Hot messages
  (`EncryptedBallot`, `EncryptedContest`, `EncryptedField`, `HashedCiphertext`) keep every field at 15 or below, so
  each tag is one byte. The lint test checks every schema change against the committed table `test/egrf/schema.json`
  (§4.6): no field, reservation, message or enum value disappears or changes, and new fields are numbered above the
  old ones.
- **S7.** Every `bytes` field that carries a fixed-width value is annotated with `(width)` or `(width_multiple)`,
  plus `(omittable) = true` when it may be absent. Every enum has `..._UNSPECIFIED = 0`, which is invalid wherever
  the field is required. The lint test holds the list of variable-length `bytes` fields (segment and TOC keys, the
  manifest content, vendor values, the parts of a signed statement), so a new unannotated `bytes` field fails it.
- **S8.** No regular (non-oneof) field number lies between the lowest and highest member numbers of a oneof in the
  same message. Rust's prost encodes a oneof at the position of its lowest-numbered member, whichever member is set
  (prost-derive's source says so in a TODO). With S8 that position is still field-number order. Today `RecordItem`
  is the only oneof (members 1-100), and it has no regular field at all. S8 also requires every oneof member to be a
  message. W2 writes a set member even when its value is the default, so a scalar member could put an explicit
  VARINT 0 on the wire; with message members, an explicit 0 never occurs, which is what lets W6 reject an unknown
  VARINT of 0 without rejecting a canonical record of a newer minor that adds a oneof. `RecordItem` already
  complies.

#### 4.2.2 Wire rules: the canonical encoding of a message

- **W1 Order.** Fields appear in strictly ascending field-number order. The elements of a repeated field are
  contiguous, in list order.
- **W2 Presence.** An implicit-presence field (every `uint32`, `uint64`, `bool`, enum, `string` and `bytes` field)
  is written if and only if its value differs from the default (0, false, the zero enum value, empty). A message
  field, including a `Timestamp`, is written if and only if it is set, even when every field inside it is default
  (then it is the tag and a zero length). A oneof member is written if and only if it is the set member. A singular
  field appears at most once.
- **W3 Wire types.** `uint32`, `uint64`, `bool` and enum fields use VARINT (0). `string`, `bytes` and message
  fields, and repeated messages, use LEN (2). No other wire type occurs.
- **W4 Minimal varints.** Every varint (tag, length, value) uses the fewest bytes: no final byte of 0x00 after a
  continuation, one byte for 0. A `bool` is the single byte 0x01 (false is absent).
- **W5 Exact lengths.** A LEN record's length is the exact byte count of its payload, and a nested message's
  payload is that message's canonical encoding (recursively).
- **W6 Unknown fields (NQ-1).** Every field number is defined in the schema the record's `format_minor` names, so a
  reader that knows that minor (or a later one) rejects any number its schema does not define (`R.encoding`). A
  reader older than the record meets fields it does not know, and checks that the encoding is still canonical as far
  as it can tell:
  - every unknown field of a message comes after all of its known fields, and the unknown fields are in strictly
    ascending number order (W1), except that a LEN field may repeat in contiguous records;
  - each unknown number is above every number the reader's schema declares or reserves for that message (S6). The
    one exception is `RecordItem`, whose only field may be an unknown oneof member: an item type the reader does not
    know (D5, §7);
  - each unknown field has wire type VARINT or LEN (W3), minimal varints (W4) and an exact length (W5); an unknown
    VARINT is not 0 (W2: no explicitly written default; S8 keeps scalars out of every oneof, so no later minor can
    write one) and occurs once (S3: a repeated numeric field would be LEN).
  The reader cannot check an unknown LEN field's payload (message, string or bytes), so it is kept opaque, digested as
  stored and reported (§7).
- **W7 Repeated messages.** One LEN record per element, never packed.
- **W8 Strings.** Valid UTF-8 (RFC 3629: no surrogate code points, no overlong forms). No normalization: labels
  compare byte for byte with the manifest's.

#### 4.2.3 Presence in practice

Optional fields, and how absence is expressed:

| Field | Absent means | Mechanism |
|---|---|---|
| `encrypted_at` (both cast ballot kinds), `DeviceClose.closed_at` | not recorded | message presence |
| `ballot_ref` (all ballot items) | no reference | empty string |
| `DeviceHeader.initial_hash`; `DeviceClose.closing_chaining_field`, `closing_hash`; `ChainCloseStatement.closing_hash` | no chaining | `(omittable)` bytes |
| `EncryptedContest.undervote_difference_proof`, `null_vote_proof` | not tracked by the manifest | `(omittable)` bytes |
| `EncryptedContest.contest_data`, `DecryptedContest.contest_data` | b_Λ = 0 | message presence |
| `UncastSelection.option_label` | a null vector | empty string |
| `UncastNonceRelease.ballot_nonce` | ξ_B not released (Q28); present exactly when the released item is compact (NQ-2) | `(omittable)` bytes |
| `UncastNonceRelease.contests` | the released item is compact, so the nonces follow from ξ_B | empty repeated field |
| `SignedStatement.signer_key`, `timestamp_token` | out of band; no token | empty bytes |

Fields where 0 is a meaningful value, so the value 0 is written as absence (the proto3 rule, and no ambiguity):
`DeviceHeader.chaining_mode` (0 = no chaining), `DecryptedField.value` (σ = 0), `DecryptedTallyField.tally`
(t = 0), `EncryptedTallyContest.cast_weight`, `RecordHeader.format_minor`, `SegmentHeader.first_ordinal`,
`TocEntry.item_count` and `critical`. Fields that are never 0 in a valid record, so are always present: every
1-based index, `weight`, `status`, `kind`, `format_major`, n and k.

### 4.3 Decode rules (checked after parsing)

Re-serialization cannot see these, so every reader checks them explicitly. A failure is `R.encoding` unless noted.

- **D1 Widths.** A present `bytes` field with `(width) = w` has exactly w bytes; with `(width_multiple) = w`, a
  positive multiple of w bytes. A field with a width annotation that is absent fails unless it is `(omittable)`.
  Widths are a property of the encoding; **counts** that depend on the manifest (k, k+1, R+1, L+1, m+L, the style's
  contests) are structure (`N.structure`, §4.8). Values are big-endian b(x, w) (§5.1), leading zeros kept, never
  minimal-length integers.
- **D2 Enums.** The value is a declared member, and not `UNSPECIFIED` where the field is required. Proto3 enums are
  open, so a runtime keeps an unknown integer; a reader that knows the record's minor rejects it. A reader older than
  the record treats an undeclared value as content it does not understand (a later minor may add enum values, §7):
  the checks that depend on it are `NotEvaluable` with `R.version`, and the item is still digested. `SectionType`
  additionally admits the vendor range 32768-65533 in `SegmentHeader` and `TocEntry`, and is the one enum no minor
  extends: a new section kind needs a new format major (user decision NQ-7, §7), so an undeclared non-vendor
  `SectionType` is D2 for a reader of any minor (and a reader refuses a claimed TOC entry naming one with
  `R.version` before its D2, §4.5).
- **D3 Timestamps.** `seconds` in [0, 253402300799], which is 1970-01-01T00:00:00Z to 9999-12-31T23:59:59Z, and
  `nanos` in {0, 1,000,000, ..., 999,000,000}: UTC, millisecond precision, as S10a's `EncryptionTimestamp`
  (follow-up #6). S10a's `DateTimeOffset` also admits times before 1970, so the writer's mapper refuses a pre-1970
  time rather than writing negative seconds.
- **D4 Integer bounds.** `uint32` values below 2^31 (the spec's 4-byte indices have MSB 0, §5.1.3, and C# reads them
  as `int`); `uint64` values below 2^63 (`long`).
- **D5 Envelope.** A `RecordItem` has exactly one field: one member of its oneof. For a reader older than the record
  that field may be an unknown member, an item type the reader does not know (§7). An empty `RecordItem`, or one with
  two fields, fails.
- **D6 Segment header.** A `SegmentHeader` passes the §4.4 check like an item, and D1-D4 where they apply. `magic` is
  `"EGRF"` and `format_major` is 2, and the header agrees with the file's path (§5.3.1). Any failure is
  `R.container`.

(Revision 2's D7, the key order of `election_info`, is gone with that field, NQ-4.)

**The decode rules are mandatory in every conformant reader.** The feasibility run confirmed that no runtime enforces
any of them. In all four runtimes tested, every decode-rule negative vector passed parse, re-serialize and compare:
an undeclared enum value, `UNSPECIFIED` status, a `uint32` ≥ 2^31, sub-millisecond nanos, negative seconds, a wrong
width or width multiple, an absent width field that is not omittable, and an empty `RecordItem`. They apply to known
fields; an unknown field's payload is opaque (W6).

**Range is not a decode rule** (#11: "Out of range values are a problem for a verifier, not the election record
format"). A 512-byte value ≥ p or a 32-byte value ≥ q decodes. The verifier reports it under the spec's lettered
check (§4.8).

### 4.4 Checking canonicality in any language

Two methods are conformant. Both run on the stored bytes of each item, before its leaf hash is accepted.

**Method A, the wire walk (the normative reference).** About 150 lines over the schema's descriptor (or a transcribed
table of field numbers, types, width options and reserved numbers, such as `test/egrf/schema.json`):

```
walk(bytes, message type, reader knows the record's minor):
  last = 0; in_unknown = false
  while bytes remain:
    tag = read minimal varint                      -- W4
    number, wiretype = tag >> 3, tag & 7
    field = schema(message type, number)
    if field is known:
      not in_unknown or fail                       -- W6: known fields all come before unknown ones
      wiretype == field's wire type or fail        -- W3
      number > last, or (number == last and field is repeated and the previous record was this field) or fail  -- W1, W2
      value = read minimal varint, or read minimal-varint length then exactly that many bytes  -- W4, W5
      implicit-presence field: value != default or fail                                         -- W2
      string: valid UTF-8 or fail                                                               -- W8
      message: walk(value, field's message type, ...)                                           -- W5
    else:                                          -- W6
      reader is older than the record or fail (R.encoding)
      message type is RecordItem and this is its only field: an unknown item type (D5, §7)
        or number > every number the schema declares or reserves for the message, or fail
      number > last, or (number == last and wiretype == LEN and the previous record was this field) or fail
      wiretype is VARINT (value != 0: W2, S8) or LEN (minimal length, exactly that many bytes), or fail
      in_unknown = true; record (message type, number) as content not understood
    last = number
  then apply D1-D6 to the decoded known values
```

**Method B, parse, re-serialize, compare.** Parse with the generated code **keeping unknown fields**, apply the
decode rules D1-D6, serialize, and compare with the input byte for byte. Equal bytes mean canonical as far as the
reader's schema reaches. Then apply the W6 rule for unknown fields, as below.

- **Why it is sound.** Method B accepts only bytes that equal a canonical serializer's output. A runtime whose
  parser is lenient or quirky can therefore cause false rejections, never false acceptances. The checks fall out as
  follows. W1, W2, W4 and W5 change the bytes. W3 either becomes an unknown field or makes the parse throw (protobuf-es
  reads the payload by the schema's type, loses sync and throws "illegal tag"). W8 either throws or is replaced,
  which changes the bytes. An unknown field placed before a known one is written back after the known fields, which
  changes the bytes (pinned for C# by `EgrfUnknownFieldBehaviourTests`).
- **Keeping unknown fields is required (NQ-1), and is the default of every runtime below that has the option.**
  That is what makes a newer record's bytes survive a re-encode by an older library. The v2 revision of this design
  discarded them instead; under the new rule that would make every newer-minor item fail Method B.

  | Runtime | Keeps unknown fields | Where it writes them back | Evidence |
  |---|---|---|---|
  | C# Google.Protobuf | by default | after the known fields, in the order read | tested (`EgrfUnknownFieldBehaviourTests`, all three cases) |
  | Python protobuf (upb) | by default | kept and written back (feasibility run); placement and order not tested | feasibility run, partial |
  | protobuf-es | by default (`readUnknownFields: true`) | kept and written back (feasibility run); placement and order not tested | feasibility run, partial |
  | Go | by default (documented) | not tested | none |
  | Java | by default for proto3 since 3.5 (documented) | not tested | none |
  | protobufjs | never: always discards | n/a | feasibility run |
  | Rust prost | never: always discards (documented) | n/a | none |

  S10b-3 pins the untested placements with the newer-minor golden vectors (§5.7), and S10b-12 runs them in Python;
  a runtime that fails them uses Method A for newer-minor records.

- **Method B does not check the unknown fields themselves.** C# writes unknown fields back in the order it read
  them, so a descending unknown tail survives re-encoding unchanged (pinned by
  `EgrfUnknownFieldBehaviourTests.DescendingUnknownTail_SurvivesReEncoding_SoMethodBAloneDoesNotCatchIt`), and no
  runtime can tell whether an unknown number lies in a reserved range. So the W6 rule is a separate step:
  - **The record's minor is not newer than the reader's** (the normal case): any unknown field is `R.encoding`. A
    parse that discards unknown fields detects one in the same pass, because discarding shortens the bytes and the
    comparison fails. So on this path a runtime may use its discard option, and protobufjs and prost, which always
    discard, are conformant here. The calls: C# `Parser.WithDiscardUnknownFields(true)`, Python
    `msg.DiscardUnknownFields()` after parsing, protobuf-es `fromBinary(schema, bytes, { readUnknownFields: false })`,
    Go `proto.UnmarshalOptions{DiscardUnknown: true}`, Java `DiscardUnknownFieldsParser.wrap(parser)`.
  - **The record's minor is newer**: the reader runs Method A, whose walk checks W6, or Method B keeping unknown
    fields followed by Method A's unknown-field branch. Runtimes that always discard (protobufjs, prost) must use
    Method A for these records.
- **Field order.** Method B relies on the runtime writing a map-free message's fields in field-number order. All four
  tested runtimes do, oneof members included. S8 covers prost. The golden vectors (§5.7) arbitrate, and a runtime
  that fails any of them uses Method A.
- **The decode rules are separate code.** Parse, re-serialize and compare accepted every D-rule vector in every
  runtime (§4.3), so a reader that runs Method B without D1-D6 is not conformant.
- **Cost.** One serialization per item, a few microseconds for a 13 KB ballot, against about 1 ms of verification
  cryptography per ballot.

**Feasibility result (2026-10-09).** For one item of every `RecordItem` member, a `SegmentHeader` and four edge cases,
Python's `SerializeToString()` equalled an encoder written from §4.2 alone. Parse then re-serialize was byte-identical
in Python, C#, protobufjs and protobuf-es. Building from values in protobufjs and protobuf-es gave Python's bytes. JSON
to bytes was lossless in Python, C# and protobuf-es. Method A rejected all 37 hand-built negative vectors with the
rule this section names. Method B rejected the same 27 wire-level vectors in all four runtimes, and needed explicit
decode-rule code (D1-D5, which were the rules then) for the other 10. Java and Go were not tested.

The C# reference uses Method B on the hot path (with `WithDiscardUnknownFields(true)` when the record's minor is not
newer than the library's, which folds the W6 check into the same comparison) and Method A for records of a newer
minor (§7) and as a cross-check in tests. The Python reference reader (§5.7) uses Method A only, with the standard
library.

(The feasibility run's negative vectors predate NQ-1. Its "unknown field" vectors stay negatives for a reader at the
record's minor; S10b-3 adds the newer-minor vectors of §5.7.)

### 4.5 Sections, phases and canonical order

A section has a type, a key (`bytes`, empty except for device sections) and an ordered list of items. **The
canonical section order is ascending (type, key bytes).** The type's high byte gives the phase, so the canonical
order also follows the protocol's phase order.

| Type | Name | Phase | Key | Items, in canonical order | Presence | Critical |
|---|---|---|---|---|---|---|
| 0x0001 | header | setup | empty | `record_header` | exactly once | yes |
| 0x0002 | parameters | setup | empty | `parameters` | exactly once | yes |
| 0x0003 | manifest | setup | empty | `manifest_file` | exactly once | yes |
| 0x0004 | guardians | setup | empty | `guardian_public_key` × n, index 1..n with no gaps | exactly once | yes |
| 0x0005 | election_keys | setup | empty | `election_keys` | exactly once | yes |
| 0x0101 | device | voting | 33 bytes: kind ‖ H_DI, where kind is the `DeviceKind` number (0x01 regular, 0x02 pre-encrypting; not the C# `DeviceChainBallotKind` value) | `device_header`; ballot items in chain order; `device_close` | iff the device produced ≥ 1 ballot item (Q25); keys strictly ascending | yes |
| 0x0102 | device_attestations | voting | empty | `device_attestation`, ascending (device key, statement item type, SHA-256(statement), then the item's bytes: two signers of one statement), unique | exactly once once voting is sealed; may be empty | yes |
| 0x0201 | encrypted_tally | aggregated | empty: the election-wide tally of every cast ballot | `encrypted_tally_header`, then `encrypted_tally_contest` per manifest contest, ascending index | exactly once once aggregated | yes |
| 0x0202 | contest_data_requests | aggregated | empty | `contest_data_request`, ascending (locator, contest index), unique | exactly once once aggregated; may be empty | yes |
| 0x0301 | decrypted_tally | final | empty: the election-wide tally | `decrypted_tally_contest` per manifest contest, ascending index | exactly once once final | yes |
| 0x0302 | challenged_ballot_decryptions | final | empty | `challenged_ballot_decryption`, ascending locator, unique | exactly once once final; may be empty | yes |
| 0x0303 | contest_data_decryptions | final | empty | `contest_data_decryption`, ascending (locator, contest index), unique | exactly once once final; may be empty | yes |
| 0x0304 | uncast_nonce_releases | final | empty | `uncast_nonce_release`, ascending locator, unique | exactly once once final; may be empty | yes |
| 0x8000-0xFFFD | vendor | final | vendor-chosen | `vendor_item` | optional | the writer's choice; taken from the claimed TOC |
| 0xFFFE | toc (pseudo) | none | empty | `toc_entry` | the claimed TOC; never in a TOC | n/a |
| 0xFFFF | signatures (pseudo) | none | empty | `record_signature` | outside every root | n/a |

Phase = min(type >> 8, 3): 0 setup, 1 voting, 2 aggregated, 3 final (`RecordPhase` SETUP..FINAL = phase + 1). A
record is *at phase p* when it holds every required section of phases ≤ p and nothing of a later phase. Anything else
is `R.structure`.

**The `critical` bit is a leaf input of every phase root, so it is fixed wherever it can be.** For every section type
a reader knows, the bit is the table's value, and a claimed TOC entry that disagrees is `R.root`. For a vendor
section, the one kind of section whose type the table does not fix, the reader has no other source, so it takes the
bit from the claimed TOC entry. That is the one place a verifier uses a claimed TOC value, and a flipped bit still
changes the root, so signatures cover it. With these rules and the presence rules, two conformant writers of the same
content produce the same TOC.

**No other section kind exists within a major (user decision NQ-7, "Bump the major version", 2026-10-10).** Adding a
section kind requires a new `format_major`; minor versions add only fields (§7). A reader therefore refuses a claimed
TOC entry whose type is neither in this table nor in the vendor range with `R.version` (checked before the entry's
own D2), and the layout has no path for such a section (§5.3.1), so its files are `R.container`.

**Canonical ballot order** is device sections in key order, and chain order within each section. Locator order
(kind, H_DI bytes, position) is the same order, and the final-phase join sections are sorted by it, which is what
makes O(1)-memory merge joins possible (§6.3). Sort order is defined on values, not on encoded bytes.

**Several tallies (#16).** v2.0 has exactly one `encrypted_tally` and one `decrypted_tally` section, each with an
empty key, and they always mean the election-wide tally over every cast ballot. That meaning never changes. Further
tallies (per precinct, #16) arrive as **new section types in a new major version** (user decision NQ-7), not as
more keyed copies of 0x0201/0x0301. For example:

- `tally_definitions` (0x0203): one `TallyDefinition` item per tally id, naming its ballot set for V9;
- `subset_encrypted_tally` (0x0204) and `subset_decrypted_tally` (0x0305), keyed by tally id.

A v2 reader refuses such a record (`R.version`), recognizing it by the segment header of its header section at v2's
path, which it reads before the layout and D6 checks (§5.3.1, §7). A design that keyed the existing types
instead would have broken v2 readers silently: they would report two `encrypted_tally` sections as `R.structure`,
and would run V9 over all cast ballots against a subset tally and fail 9.A. (Revisions before NQ-7 had these types
arrive in a later minor as non-critical sections that a v2.0 reader digests with `Complete = false`; that needed a
generic path for section kinds a reader does not know, which NQ-7 declined.)

Rules for device sections:

- `DeviceHeader.kind` and `h_di` must equal the key, and the verifier recomputes H_DI from `device_id` and kind
  (eq. 72 with 0x2A for regular devices; eq. 119 with 0x43 for pre-encrypting ones; 8.C/16.D). Strictly ascending
  keys make "one device, two sections of the same kind" a structural error found in O(1).
- A regular section holds `encrypted_ballot` items only, of any status. A pre-encrypting section holds
  `pre_encrypted_cast_ballot`, `pre_encrypted_uncast_ballot` and `pre_encrypted_compact_uncast_ballot` items only,
  interleaved in print order. Anything else is `8.structure` or `16.structure`.
- Under no chaining, the order is still the device's recorded processing order. Only the chain-close attestation
  fixes it cryptographically (§4.9).
- Spoiled ballots stay in their chain position (#4), so 8.E and 8.G hold on an honest record.

### 4.6 The schema (normative)

The schema is [`proto/electionguard/egrf/v2/egrf.proto`](../../proto/electionguard/egrf/v2/egrf.proto), package
`electionguard.egrf.v2`. That file is the one normative copy (S10b-2 moved it there from `docs/spec-compliance/`;
this document no longer embeds it, so the two cannot drift). It sits at the repository root, outside any project,
because every implementation shares it: the Core build generates its C# types from it (§8.1), and the Python
reference reader transcribes it. `test/egrf/schema.json` is the same schema as a table (field numbers, types,
labels, width options, reserved numbers; `"label": "optional"` is the descriptor's name for a singular field, not
the forbidden `optional` keyword), generated from the compiled descriptor by `EgrfSchemaLintTests`, which
also enforces S1-S8 (§4.2.1) and checks every change against the committed table for S6. It compiles with the
protoc in the Grpc.Tools NuGet package (2.80.0, libprotoc 31.1) to C# and Python.

What the schema holds, by `RecordItem` member (the oneof field number is the item type):

| Members | Phase | Messages |
|---|---|---|
| 1-5 | setup | `RecordHeader` (format version only, NQ-4), `Parameters`, `ManifestFile`, `GuardianPublicKey`, `ElectionKeys` |
| 10-16 | voting | `DeviceHeader`, `EncryptedBallot`, `PreEncryptedCastBallot`, `PreEncryptedUncastBallot` (full form), `DeviceClose`, `device_attestation` (`SignedStatement`), `PreEncryptedCompactUncastBallot` (compact form, NQ-2) |
| 20-22 | aggregated | `EncryptedTallyHeader`, `EncryptedTallyContest`, `ContestDataRequest` |
| 30-33 | final | `DecryptedTallyContest`, `ChallengedBallotDecryption`, `ContestDataDecryption`, `UncastNonceRelease` |
| 40-44 | statements | `ChainCloseStatement`, `SectionSealStatement`, `PrefixCheckpointStatement`, `RecordStatement`, `record_signature` (`SignedStatement`) |
| 50-51 | digest leaves | `TocEntry`, `ConfirmationCodeLeaf` |
| 100 | vendor sections | `VendorItem` |

`RecordItem` has no other field. Number 2047 (the draft's per-item extension list) and `RecordHeader` field 3 (the
draft's `election_info`) are `reserved`: neither was ever published, but draft feasibility vectors used them.


Decisions behind the layout:

- **The item type is the oneof field number.** Every stored item, statement and digest leaf is a `RecordItem`, so
  its first bytes are the tag of its oneof member. Leaves of different types can never collide, a signature over a
  chain-close statement can never be replayed as a record signature, and no separate type and version prefix is
  needed. An incompatible new version of an item is a new oneof member (for example a future RLA form of
  `ChallengedBallotDecryption`).
- **Lists of fixed-width values are one `bytes` field** (#3: "Optimize for size of the files when encoding the
  encryptions"). Proof lists are (c_j ‖ v_j) pairs of 64 bytes, a pre-encryption vector is m × (α ‖ β), commitments
  are k × 512. A `repeated Proof { bytes c; bytes v; }` message would add 6 bytes to every 64-byte proof (about
  1.4 % of a ballot); one `bytes` field adds 2-3 bytes per list. A reader slices fixed-width chunks, which is a
  one-line loop in any language.
- **α and β stay separate fields.** They are two values with different meanings, not a list, and keeping them named
  costs nothing measurable.
- **Encrypted items carry indices; plaintext items carry index and label.** The spec's hashes bind contest and option
  indices (eqs. 59, 62, 70, 115). Labels on encrypted ballots would add 5-10 % per ballot, and no verification reads
  them there. Where a verification checks text (V11 tally, V14 challenged decryption, V19 uncast), the item carries
  both: the index drives V13's ciphertext lookup, and the label is compared in V14, so a mislabelled field fails V14
  rather than surfacing as a 13.x crypto failure against the wrong ciphertext. The domain decryption carries both
  (`DecryptedChallengedContest.Index`, `DecryptedChallengedField.Index`, S10b-B review round 1). 14.B and 14.D are the
  spec's presence checks (each manifest label "appears"/"occurs"); a label that is no manifest label fails 14.A or
  14.C first, as the spec orders the checks. After them, V14 requires each manifest label at its own index, and each
  field in the list of its kind (option or supplemental field): a contest or field whose (index, label) pairing is not
  the manifest's (two labels swapped, or an index moved) is **`14.structure`** (user decision 2026-10-10, "14.structure
  for mismatches"; S10b-C, which changed S10b-B's 14.B/14.D reporting). An index moved to another field also opens
  the wrong ciphertext, so it fails 13.B as well. Without the pairing rule a label paired with another contest's or
  field's index would pass both V13 (by index) and V14 (by label).
- **Lists inside an item are in ascending index order** where the schema says so (a ballot's contests, an uncast
  ballot's contests and vectors, a challenged decryption's contests, a release's contests). Out of order, the same
  content would have a second encoding and leaf hash. The decoders report it (§4.8 layer 3); a repeated index is a
  content error left to the verifications' own structure checks (a contest listed twice).
- **No device id on ballots.** It comes from the section. The domain `EncryptedBallot.DeviceId` is filled in from
  `DeviceHeader` on decode, which also removes the "ballot names another device" failure class.
- **`MaximumCount` is not stored.** S10a publishes the per-contest `cast_weight`, and `MaximumCount` is
  `cast_weight × MaximumValue`, computed. V9 compares `cast_weight` with the recomputed value (`9.structure`).
- **The header holds the format version only** (NQ-4: "Optional manifest fields"). Spec §3.7 bullet 1 asks for
  "Information sufficient to uniquely identify and describe the election, such as date, location, election type, etc.
  (not otherwise included in the election manifest)". Those facts are now optional manifest fields (`electionName`,
  `electionDate`, `electionType`, `jurisdiction`, `location`; S10b-1b), so they sit inside `ManifestFile.content` and
  are bound into H_B, which no record-level field could be. They are informational: no verification reads them. Any
  further fact a jurisdiction wants recorded can be a vendor property of the manifest, which the parser ignores and
  H_B still binds (NQ-1). Producer software, creation time and notes are not election facts. They go in `meta.json`,
  outside the root, so that two writers of the same content produce one root.
- **`DeviceHeader.chaining_mode` repeats the manifest's mode**, the one repetition of a manifest value. Spec 8.D/16.E
  are phrased per device ("If the device used the no-chaining mode"), so the device states its mode, and the
  verifier checks that it equals the manifest's (`8.structure`/`16.structure`).
- **The manifest is stored byte for byte as entered** (#19: "it should be output to the election record exactly as it
  was entered"), and its canonical form is JSON (NQ-1: "The manifest is really the only field I would ever expect a
  vendor to provide additional data, so honestly it's canonical form should probably be json"). `ManifestFile.content`
  is exactly the H_B input of eq. (5). The record path never re-encodes it: `ManifestSerializer` only parses it, and
  its writer's output has no canonical status. `media_type` names the parser,
  `"application/vnd.electionguard.manifest+json;format=1"` for `ManifestSerializer`'s reading rules: UTF-8 JSON
  without a BOM, no comments, trailing commas or duplicate keys, the model's members matched exactly and read
  strictly (types, required members, `Manifest.Validate`), and **unknown properties ignored** at every level (vendor
  data, still bound by H_B through the bytes). Ignoring a value does not exempt it from being JSON text: every byte
  of the file is well-formed UTF-8 (RFC 8259 §8.1, RFC 3629), no string or name escapes to a lone surrogate, and
  nesting is at most 64 levels deep (the top-level object is level 1; RFC 8259 §9 lets a parser limit depth), vendor
  values included, so whether a file is a manifest does not depend on which properties a reader knows (S10b-A review
  round 2). Member names are matched exactly, so a name that differs from a member's only in case, `_` or `-`
  (`ChainingMode`, `chaining_mode`) is an unknown property and is ignored like any other (user decision R-3, "Ignore
  them too"; S10b-A had refused such near misses). A conformant reader in any language matches names exactly too.
  "As entered" therefore means byte for byte for any document that parser accepts (#19: "need only be a valid
  document").
  Whitespace, member order, number spelling and vendor properties survive. A document the parser refuses, such as one
  that starts with a UTF-8 BOM or names a key twice, would make the record unverifiable, so `WriteSetupAsync` parses
  the bytes first and refuses them. It never strips or rewrites them. A carrier may also write the manifest as a plain
  file, `setup/manifest.json`, outside the root, for people to read; a verifier that finds one checks that it is
  byte-identical to `ManifestFile.content` (`R.container`).
- **Timestamps are `google.protobuf.Timestamp`**, with D3 restricting them to non-negative seconds and whole
  milliseconds. Both candidates are canonical under the profile: `Timestamp`, because D3 leaves exactly one
  (seconds, nanos) pair per instant and W2 omits a zero `nanos`; a `uint64` of milliseconds, because a varint has one
  minimal form. `Timestamp` wins on three counts. A message field has explicit presence, so "not recorded" needs no
  sentinel such as 0. The proto3 JSON mapping renders it as an RFC 3339 string (`"2026-10-08T14:03:07.412Z"`), while a
  `uint64` renders as a digit string. And every protobuf runtime ships it as a well-known type. It costs about 6 bytes
  more per ballot than a bare varint, 0.05 %.
- **`ballot_ref` is optional, free text, and unverified** (follow-up #12). No hash binds it, so nothing may trust it
  (Q31). It is useful for matching paper in an audit.
- **The verifier never trusts the TOC.** It is a stored claim that the verifier recomputes.

### 4.7 Byte sizes

Per selection with R = 1, the payload is 1,024 B of ciphertext and 128 B of proof. The profile adds about 12 B (tags
and lengths for α, β, the proof and the field message), about 1.0 %. Per contest with L = 1, add the 128 B limit proof,
the 32 B χ and about 9 B of framing. The fixed per-ballot part is about 800 B, mostly the 615 B ballot-nonce
ciphertext. Worked example (10 fields with R = 1 in 3 contests with L = 1, a timestamp, short style and reference):
12,740 B of raw cryptographic payload, about 12,945 B encoded, **1.6 % over the raw values**. That is about
13 GB per million ballots.

**Measured (feasibility run, 2026-10-09).** The ballot is a real C# encryption from the `test/data/single-contest`
manifest: one contest with 4 options and 5 supplemental fields (9 fields, each with R = 1), limit, undervote-difference
and null-vote proofs, contest data with b_Λ = 2, a millisecond timestamp and a `ballot_ref`.

| Form | Bytes |
|---|---|
| raw cryptographic payload | 12,100 |
| EGRF canonical protobuf `RecordItem` | 12,285 (+1.53 %; 12,287 as a frame) |
| today's protobuf-net | 12,491 |
| EGRF proto3 JSON, compact | 16,953 (1.38 ×) |
| EGRF proto3 JSON, C# `JsonFormatter` default (spaced) | 17,082 |
| today's JSON as written (indented) | 21,264 (1.73 ×) |
| EGRF protobuf, deflate -9 | 12,296 (incompressible) |
| EGRF compact JSON, deflate -9 | 12,732 |

EGRF protobuf is 1.6 % smaller than today's protobuf-net, which also carries a device id, string ids and an
`is_pre_encrypted` flag. Today's JSON is larger in part because System.Text.Json's default encoder escapes every `+`
in base64 as `+`, 5 extra bytes each, about 1.3 KB per ballot. The proto3 JSON writers do not do this.

- A pre-encrypted cast item adds (m+L)·32 B of hashes and L·m·1,024 B of vectors per contest.
- A full pre-encrypted uncast item costs (m+L)·(m·1,024 + 32) B per contest plus short codes and framing (30,912 B
  at m = 5, L = 1). Its release adds (m+L)·m·32 B.
- A compact uncast item (NQ-2; every never-returned ballot) costs about 40 B per contest (index and χ with framing)
  plus about 750 B per ballot (id_B, H_I, C_ξB, H_C, B_C), and its release 32 B (ξ_B) plus the locator.
- **Large items.** A full uncast item grows with m² per contest: about 0.95 MB at m = 30, L = 1, and about 11.3 MB
  at m = 100, L = 10. A multi-contest returned uncast ballot whose ξ_B is not released can therefore approach the
  64 MiB frame ceiling (§5.2), which the writer enforces. Never-returned ballots are always compact, so they never do.

### 4.8 Validity layers and failure attribution (normative, so verifiers in all languages agree)

Checks run in three layers, in this order, and each failure carries a fixed code:

1. **Encoding** (`R.encoding`): the wire rules W1-W8 and decode rules D1-D6 (D6 failures are `R.container`). The item's leaf hash is still computed
   from the bytes as read, so the root check still runs. The item is then opaque, and its verifications are
   `NotEvaluable` for it.
2. **Range** (lettered where the spec assigns a letter; #11): a fixed-width value outside Z_p or Z_q. S10a's
   `FromCanonicalBytes` throws on such a value, which made 6.B, 6.C and 2.B unreachable from a deserialized record.
   The record reader instead decodes the bytes raw and reports:

   | Value | Code |
   |---|---|
   | ballot and pre-encryption-vector α, β (V6 covers every selection encryption, spec §4.5): regular ballots, the combined and the selected vectors of a cast pre-encrypted ballot, uncast vectors | 6.A |
   | selection range-proof c, v | 6.B, 6.C |
   | limit, undervote-difference and null-vote proof c, v | 7.B, 7.C |
   | contest data C_0 and C_2 = (c, v) (hashed into χ by eq. 70, so first read by V8) | 8.structure |
   | a ballot's encrypted ballot nonce C_ξB,0 and C_ξB,2 (no input to H_C; first read by V13), regular or cast pre-encrypted | 13.structure |
   | guardian commitments, κ_i; a guardian index of 0 (as V2 reports any index outside 1..n since S2/G25: some G_i is then missing, and its 2.A cannot be confirmed) | 2.A |
   | guardian responses v_{i,j}, v̂_{i,j} | 2.B |
   | guardian challenges c_i, ĉ_i (no letter checks their range; H_q's output is below q, so a stored c ≥ q can never equal the recomputed one) | 2.C |
   | election keys K, K̂ (3.A and 3.B are K = (∏K_i) mod p and K̂ = (∏K̂_i) mod p, p.82: the c_i reasoning) | 3.A, 3.B |
   | `ver` that is not a version string padded with zero bytes | 1.A |
   | n, k that are no threshold scheme (not 1 ≤ k ≤ n) | 1.structure |
   | encrypted tally A, B (the recomputed product is below p, so a stored value ≥ p can never equal it: the c_i reasoning) | 9.A, 9.B |
   | decrypted tally T (T = K^t mod p cannot hold), c, v | 10.C, 10.B, 10.A |
   | contest-data decryption β, c, v | 12.structure, 12.B, 12.A |
   | challenged-ballot released nonces ξ_{i,j}, contest-data ξ | 13.structure |
   | uncast released nonces ξ_{i,j,k}; an uncast ballot's own C_ξB,0 and C_ξB,2 ("Verification 13 is replaced by Verification 18", p.66) | 18.structure |
   | a count that does not fit the domain's integers (`cast_ballot_count`, a tally t above 2^31 - 1) | 9.structure, 10.structure |
   | a decrypted-tally contest or field label listed twice (the domain tally is keyed by label) | 11.structure |

   The table is fixed (S10b-4, `RecordValueRanges`). The mappers decode every fixed-width value raw (`RawZp`,
   `RawZq`: a big-endian compare against `EGParameters.P`/`Q`, never a reduction), collect every range finding of the
   item, and then hand no domain object on (`RecordDecoded<T>`). The verifications' record-item entry points
   (internal overloads of V1-V3, V6 for regular, cast pre-encrypted and uncast ballots, V7-V13, V16 and V18) run a
   gate first: a finding of their own verification is their `VerificationFailedException` with its code; a finding of
   another on an item they read leaves them not evaluable on the item (`RecordItemNotEvaluableException`); otherwise
   the existing domain verification runs. Every code in the table has such an owner. A verification gates every item
   it reads: V10 both tallies, V12 and V13 the decryption and the encrypted ballot it opens (so the ballot's
   13.structure is V13's failure, and its 6.x-8.structure leave V12 and V13 not evaluable), V9 the encrypted tally
   and every cast ballot item (a cast ballot with any finding leaves V9 not evaluable, since the recomputed aggregate
   would miss its factor; a challenged or spoiled one is not aggregated). V6 on a cast pre-encrypted ballot checks
   6.A on the selected vectors as well as the combined one: two in-range non-members can multiply to a member, so
   the combined vector's 6.A and V15 do not imply it. The setup is several items
   decoded together, and each of its findings names its item, so the gate counts only the items a verification reads:
   V1 the parameters and the manifest, V2 the guardian keys, V3 the guardian keys and the election keys (a guardian's
   κ_i ≥ p leaves V1 evaluable; K ≥ p, which fails 3.A, leaves V1 and V2 evaluable). Verification 6 on an uncast ballot is 6.A over
   every vector entry (p.64: V6 covers "all individual selection encryptions within the selection vectors on
   pre-encrypted ballots"; an uncast ballot has no range proofs). The record verifier (S10b-9) reports each finding
   once, under its code, whether or not its owner runs on that item: V13 runs only on challenged ballots, so a cast or
   spoiled ballot's C_ξB,0 ≥ p is reported from the item's findings, not through V13's gate. An item with a range failure
   is still digested, chain-walked (H_C and B_C are hashes) and entered into 5.A. Decoding never fails on the manifest:
   a contest index or field position the manifest lacks decodes under an id that is not text, so `BallotStructure`
   reports it as `N.structure` under the verification that runs it.
3. **Structure** (`N.structure`): counts fixed by the manifest (k, k+1, R+1, L+1, m+L, the style's contests),
   required messages and strings (a missing `encrypted_ballot_nonce`, `ballot_style` or `device_id`; a contest-data
   request or decryption with no `ballot` locator 12.structure, a challenged ballot decryption with none 13.structure:
   an absent message is canonical, since D1 and D2 cover only bytes and enum fields), a challenged ballot
   decryption's contest or field whose (index, label) pairing is not the manifest's 14.structure (after V14's
   presence checks 14.A-14.D; user decision 2026-10-10, §4.6), the section placement rules of §4.5, and today's
   `BallotStructure` rules. A list inside an item that the schema orders by ascending index
   and that is out of order (an index below its predecessor's) is reported by the decoder under the structure code of
   the verification that reads the list in that order: a regular ballot's contests 8.structure (H_C, eq. 59), a cast
   pre-encrypted ballot's 16.structure (eq. 116; V8 does not apply), an uncast ballot's printed contests and a
   contest's vectors 16.structure, a challenged decryption's contests 13.structure, a release's contests
   18.structure. The cast pre-encrypted case has no gate of its owner on the item (V16 is the device pass), so the
   record verifier reports it from the item's findings, as it does a cast ballot's C_ξB.

The pass or fail verdict is the same as S10a's range-strict serializers would give; only the code differs, and it is
the spec's.

### 4.9 Digests, roots, attestations and signatures

**Hash construction** (#2): SHA-256 with RFC 9162 (Certificate Transparency v2) Merkle Tree Hash framing, not the
spec's H.

```
leaf(item)  = SHA-256(0x00 ‖ canonical RecordItem bytes)
node(l, r)  = SHA-256(0x01 ‖ l ‖ r)
MTH([])     = SHA-256("")
MTH([d])    = leaf(d)                                                                 (one item)
MTH(D[n])   = node(MTH(D[0:k]), MTH(D[k:n])), n > 1, k = the largest power of two < n (RFC 9162 §2.1.1)

section_root  = MTH(items of the section, in canonical order)
TocEntry_i    = RecordItem{toc_entry: (type, key, critical, item_count, section_root)}
R_phase(p)    = MTH(TocEntry_1 .. TocEntry_j), j = the last entry whose section phase ≤ p
record root   = R_phase(the record's phase)
codes_root(ℓ) = MTH(RecordItem{confirmation_code_leaf: H_1} .. RecordItem{confirmation_code_leaf: H_ℓ})
```

Exact leaf bytes, for signers and checkers in other languages: `confirmation_code_leaf` is field 51, so its tag is
the varint of 51·8 + 2 = 410, the bytes 0x9A 0x03. The inner message is field 1, 32 bytes: 0x0A 0x20 ‖ H_j, 34
bytes. So `leaf = SHA-256(0x00 ‖ 0x9A 0x03 0x22 0x0A 0x20 ‖ H_j)`. A `toc_entry` (field 50) starts 0x92 0x03. For a
device section, `item_count` is ℓ + 2 (the header and the close).

The stored item bytes **are** the hash input, so a protobuf reader hashes them in place after the canonicality check;
a JSON reader encodes each item canonically and hashes that. Bare SHA-256 can never equal a protocol value of the
HMAC-keyed H, and the format claims none of the spec's domain-separation bytes.

**Phase roots.** Sections are ordered by phase, so R_setup, R_sealed, R_aggregated and R_final are prefixes of one
another:

| Root | Covers | When fixed | Who relies on it |
|---|---|---|---|
| R_setup | the encryption record (sections 0x0001-0x0005) | before voting | devices and observers pin it |
| R_sealed | R_setup plus every device section and the attestations | when voting closes | Q36: the record is sealed before any decryption |
| R_aggregated | R_sealed plus the encrypted tally and the contest-data requests | after aggregation | §3.6.1: guardians run V4-V9 on exactly this, then decrypt |
| R_final | R_aggregated plus the decryptions, the uncast nonce releases and vendor sections | at publication | the public |

An RFC 9162 consistency proof, or recomputation from the TOC, shows that a later root extends an earlier one, so
nothing published after the seal can have altered a ballot.

**Device attestations (S8b; #7 defaults).** Statements produced at the device, or by the collector receiving from it,
stored as `device_attestation` items (a `SignedStatement`) inside R_sealed:

- **Chain close** (`ChainCloseStatement`, item 40) is status-independent. It commits to every H_C in order through
  `codes_root`, and through H_C to every ciphertext, χ, B_C and H_I. It binds order under **both** chaining modes
  (under no chaining it is the only thing that does). A pre-encrypting printer can sign it at print time, because it
  needs no cast content. It is the attestation that fixes S8b's "drop trailing ballots and recompute the close".
  **Recommended for every device; the verifier reports its absence.**
- **Section seal** (`SectionSealStatement`, item 41) commits every byte of the section, including status, weight and
  `encrypted_at`. That blocks relabelling a challenged ballot as cast (the S7/Q31 attack) at the device level. It is
  possible only where the whole section exists at close (regular devices), so it is optional.
- **Prefix checkpoint** (`PrefixCheckpointStatement`, item 42) is optional: a mid-election commitment to the first
  `ballot_count` codes, signed or posted to a bulletin board. The verifier checks it against its running codes
  frontier at no extra I/O.
- The verifier **always** checks statement contents against the record (`R.attestation`): h_e, the device key, the
  mode, the count, the recomputed `codes_root` and `section_root`, and H̄. It checks signature validity only against
  configured trust anchors (`ISignatureVerifier`); otherwise the report says "present, not checked".
- Every statement starts `h_e`, `device_key` (fields 1 and 2), so the key is at a fixed place, and attestation items
  sort by (device key, statement item type, SHA-256 of `statement`), then by the item's canonical bytes, so that two
  signatures over one statement (two signers) still have one order (S10b-D; a writer orders them, a reader reports
  any other order as `R.order`).
- **Append-only.** Nothing may be added to `device_attestations`, or to any other section, after the phase root
  covering it is fixed, or the prefix-consistency claim fails. Late countersignatures and RFC 3161 tokens go only in
  the detached signatures layer.

**Record signatures** (§3.7, "together with the date") are detached `record_signature` items (a `SignedStatement`)
over a `RecordStatement` (item 43: phase, root, h_e, format version, `signed_at`, signer role). They live in the
signatures pseudo-section, outside the root; any number can exist, and more can be appended later. Binding H_E makes
a signature unusable on another election's record.

**What is signed.** A signature is over the statement's canonical `RecordItem` bytes, exactly as carried in
`SignedStatement.statement`; the algorithm applies its own digest. Only an RFC 3161 token is over
SHA-256(statement).

**Statements are checked as items first.** `statement` is an opaque `bytes` field, so the wire walk of the enclosing
`SignedStatement` never enters it. Before it checks a signature or compares contents, the verifier therefore runs the
§4.4 check and D1-D6 on `statement` as a `RecordItem`. It also checks that the set member is a statement type: 40-42
in `device_attestation`, 43 in `record_signature`. Any failure is `R.attestation` or `R.signature`. Without this, a
non-canonical statement, or one whose unknown fields break W6, could carry a valid signature over bytes that
different runtimes decode differently. A statement of a newer minor with W6-conformant unknown fields is checked for
the fields the verifier knows, and its unknown content is reported (§7).

| Algorithm | Notes |
|---|---|
| `ecdsa-p256-sha256` (DER) | Mandatory to implement. It is in the .NET BCL and ships first. |
| `rsa-pss-sha256` | |
| `ed25519` | Pluggable. Check BCL support in the target SDK; otherwise it needs a dependency. |
| `x509-cms-detached` | Needs `System.Security.Cryptography.Pkcs` |
| `rfc3161` | A `TimeStampToken` over SHA-256(statement) |

Default policy (#7): `SignaturePolicy.Report`, with `RequireValid` recommended for official verification. Signer roles
(device, poll worker, administrator) and key distribution are deployment policy.

---

## 5. Representations, carriers and equivalence

### 5.1 The equivalence model (normative)

- The **logical record** L is the list of (section type, key, [canonical item bytes]) in canonical order.
- A **representation** R has a strict decoder D_R from bytes to L (or a rejection) and an encoder E_R, with
  D_R(E_R(L)) = L.
  - **Protobuf:** D is the canonicality check of §4.4 on each stored item; the item bytes are L's bytes unchanged.
  - **JSON:** D parses each line with a proto3 JSON parser, applies D1-D6, and encodes the message canonically.
- Section roots, the TOC and the phase roots are pure functions of L. So **two physical records are equivalent iff
  they decode to the same L, iff their record roots (and phases) are equal.** "If" holds by construction; "only if"
  holds because the decoders are injective and SHA-256 is collision-resistant.
- `egrecord digest <path>` prints the phase roots of any representation, and printing the same roots is the
  equivalence check. A converter is correct iff it preserves every phase root.
- **JSON bytes are never hashed.** A JSON reader hashes the canonical protobuf encoding of what it parsed.
- **Opaque content survives conversion.** `VendorItem.value` is `bytes`, so it crosses every representation
  unchanged. Unknown *fields* (NQ-1) survive any protobuf-to-protobuf copy or re-encode, because readers keep them
  (§4.4), but they cannot cross into JSON: the proto3 JSON mapping has no form for a field the converter cannot name.
  So a converter that meets content it does not fully understand (an unknown field, oneof member or enum value)
  **refuses** (`R.version`) to write it as JSON rather than dropping it, and no conversion can change a root. A newer
  library converts it.

### 5.2 Segment files (`.binpb`)

Every section is stored as one or more segment files. Singletons use the same format, so there is one file format.
`.binpb` is the extension the protobuf project recommends for binary protobuf.

```
segment := delimited(SegmentHeader) ‖ delimited(RecordItem)*
delimited(m) := varint(length of m's canonical bytes) ‖ m's canonical bytes
```

This is the standard length-delimited stream, written and read by stock APIs: C# `WriteDelimitedTo` /
`MessageParser.ParseDelimitedFrom`, Java `writeDelimitedTo` / `parseDelimitedFrom`, Go `protodelim`, protobuf-es
`sizeDelimitedEncode` / `sizeDelimitedDecodeStream`, and a five-line varint loop in Python. The length varint is
minimal (W4).

- **Frame ceiling (normative).** A frame's length is at least 1 and at most **64 MiB (67,108,864 bytes)**. This holds
  for the `SegmentHeader` and for every `RecordItem`, `ManifestFile` and `VendorItem` included. A writer refuses a
  larger item. A reader rejects a larger length (`R.container`) before it allocates, so a hostile length varint cannot
  make a streaming reader allocate up to 2 GiB. A zero length would be an empty `RecordItem` (D5) and is never
  written. Stock delimited readers differ, so a reader sets the limit explicitly:

  | Runtime | Setting | Default |
  |---|---|---|
  | Go `protodelim` | `UnmarshalOptions{MaxSize: 64 << 20}` | 4 MiB, which rejects valid large items |
  | protobuf-es | `sizeDelimitedDecodeStream(..., { readMaxBytes: 64 * 1024 * 1024 })` | 64 MiB |
  | C# Google.Protobuf | check the length before `ParseDelimitedFrom`, or read frames with the library's own varint loop | no practical limit |
  | Python | the reference reader's varint loop checks it | none |

  64 MiB covers every regular ballot and every pre-encrypted item up to about m = 100 options per contest (§4.7). A
  full uncast item larger than that is refused by the writer; a never-returned ballot is always in the compact form,
  so only a returned uncast ballot whose ξ_B is not released can reach the ceiling.

- **Segments.** A section may be split into segments at any item boundary. Segment n+1's `first_ordinal` equals
  segment n's `first_ordinal` plus its item count; a gap or overlap is `R.container`. Segment size is the writer's
  choice (default 256 MiB) and is not canonical. Workers can start at any segment, and the header says where they
  are.
- **Byte identity.** A device section's items are byte-identical in every protobuf carrier and in the device's own
  part files. Assembling a record means copying files and writing the TOC, never re-encoding GBs.
- **Pseudo-sections.** `toc.binpb` (type 0xFFFE, `toc_entry` items) and `signatures/*.binpb` (type 0xFFFF,
  `record_signature` items) never appear in a TOC and are outside every root.
- **No per-item checksum.** The Merkle roots cover every item.
- **Torn tails.** A crash mid-append leaves at most one torn trailing frame, whose length varint is cut short or runs
  past the end of the file. Some filesystems also leave the file extended with zero bytes after a crash. Each 0x00
  would read as a zero-length frame, which is never valid, so `ResumeAsync` treats a trailing run of zero bytes as part
  of the torn tail, together with what precedes it in the torn frame: the first bytes of a length varint (which then
  read as a length that is not minimal), a whole length whose frame is all zeros (no item is all zeros, since
  field number 0 is never valid), or a whole length and the first part of its frame, the rest of the frame zeros
  (the file's new size committed, its last pages not): a last frame that ends in a zero byte, is not canonical
  (as a `SegmentHeader` when it is the segment's first frame) and is followed only by zeros (S10b-C review
  round 3). It truncates the tail and rebuilds the frontier by rescanning. A zero-filled hole that happens to leave a
  canonical item (zeros inside a `bytes` field) cannot be told from data; a device that must not lose a ballot
  flushes it to the disk (`DeviceSectionWriter.FlushAsync(durable: true)`) before it reports the ballot recorded. The previous H_C for `DeviceChain`
  is recovered from the last complete item. A crash at a segment rollover can leave the section's newest segment
  empty, or with its segment header torn (cut short or zero-filled): that segment, and only the newest, is removed,
  and the writer continues the previous segment, so the next append rolls over again and writes the header (S10b-C
  review round 1). A corrupt middle item, a segment other than the newest without a complete header, or a
  zero-length frame, a length that is not minimal (W4) or a frame of zeros followed by anything other than zeros, is
  not repaired: the section stays unsealable until an operator decides (deliberate). Nor is a section the TOC does
  not list removed unless it is a section of the next phase, which an unfinished seal or completion leaves (a device
  section after voting was sealed, a vendor section or another phase's section is refused and kept; S10b-C review
  round 2). A verifier never repairs anything; for it a zero-length frame or a length that is not minimal anywhere is
  `R.container`.
- **A returned phase root is durable** (the library's writer; S10b-C review round 3). Every segment is flushed to
  the disk when it rolls over and when its section is completed, and the TOC is written to a temporary file that is
  flushed to the disk before it is renamed over the previous one, all before the writer returns the phase's TOC. So
  after a power failure the TOC on disk is the old one or the new one, and every section it lists is whole. The
  plain manifest copy is flushed with the setup. .NET has no portable way to flush a directory, so on POSIX the
  rename itself is as durable as the filesystem's metadata journaling makes it; if it is lost, the old TOC is found,
  and the resumed writer redoes the step (the sections of the next phase are removed as unfinished).

### 5.3 Directory carrier (reference layout)

```
<record>/
  toc.binpb                                   toc_entry items (a claim; recomputed by every verifier)
  setup/header.binpb parameters.binpb manifest.binpb guardians.binpb election_keys.binpb
  setup/manifest.json                         OPTIONAL plain copy of ManifestFile.content (outside the root; checked)
  devices/regular-<H_DI hex>/00000000.binpb ...
  devices/pre-encrypting-<H_DI hex>/00000000.binpb ...
  device_attestations.binpb
  aggregated/encrypted_tally.binpb contest_data_requests.binpb
  final/decrypted_tally.binpb
  final/challenged_ballot_decryptions/00000000.binpb
  final/contest_data_decryptions/00000000.binpb
  final/uncast_nonce_releases/00000000.binpb
  vendor/<type hex>-<key hex>/00000000.binpb
  signatures/<phase>-<SHA-256(statement) hex>.binpb     OUTSIDE the root
  derived/                                    OUTSIDE the root (§5.6)
  meta.json                                   OUTSIDE the root: producer software, creation time, notes
```

The JSON representation uses the same tree with `.jsonl` in place of `.binpb`. Device paths are keyed by kind and
H_DI, never by ordinals assigned at seal, so a device can append to its final path during voting and a late device
never renames anything. This is the live-publication form.

#### 5.3.1 Layout and discovery rules (normative, for both carriers)

Two conformant readers must assemble the same logical record from the same bytes. So the layout is a function of the
logical record, and anything outside it is an error rather than something a reader may resolve its own way.

- **Paths are derived, never chosen.** Each section's directory or file name is fixed by its type and key, as in the
  tree above. Hex is **lowercase**, with no separators. A vendor section is `vendor/<type as 4 hex digits>` followed by
  `-<key hex>` when its key is non-empty. A device directory's kind word (`regular` or `pre-encrypting`) and hex
  together are the 33-byte key.
- **Segment files** are named `<8-digit zero-padded decimal index>.<ext>`, starting at `00000000` with no gaps. Their
  order is the numeric order of those names. The first segment's `first_ordinal` is 0, and each later one's equals the
  previous one's `first_ordinal` plus its item count. Anything else is `R.container`. A section that the tree shows
  as a single file (the setup sections, `device_attestations`, the tallies, the requests) is exactly one segment with
  that name.
- **The path and the `SegmentHeader` agree.** The header's `section_type` and `key` must equal what the path implies,
  or the file is `R.container` (D6). Neither one wins.
- **One encoding per record.** Every section file of a record has the same extension, `.binpb` or `.jsonl`, or the
  record is `R.container`. A directory with both is not a record.
- **No unlisted files.** A file or zip entry outside `derived/` and not in the layout is `R.container`. The layout
  includes `toc.<ext>`, `signatures/`, `meta.json` and `setup/manifest.json`. Files inside `derived/` are never
  read during verification.
- **Names are exact.** Every name of a record, `derived/` included (and, in a zip, a directory entry's name without
  its trailing `/`), consists of printable ASCII bytes 0x20-0x7E other than `\` and `:`; anything else, a control
  character, DEL or any non-ASCII byte included, is `R.container` (S10b-C review round 3: a name outside the
  layout's own alphabet can only be under `derived/`, and refusing the rest keeps two readers from decoding a zip name
  as CP437 and as UTF-8, and from folding case by different Unicode tables). Paths use `/`, are relative (no leading
  `/`), and contain no `.` or `..` segment and no empty segment. They are compared byte for byte. Two names that are
  equal ignoring ASCII case are `R.container`, because they collide when extracted on Windows or macOS (the names
  being ASCII, that is Unicode case folding too).
- **No generic path for unknown section kinds** (user decision NQ-7). The paths above are every section kind of the
  major; a file outside them is `R.container`, and a section kind a later format adds comes with a new major, which a
  reader refuses as `R.version`: it reads the header section's segment header at v2's path (`setup/header.<ext>`)
  before this rule and D6 apply, and magic "EGRF" with another `format_major` stops the record there (§7). A file at
  an unlisted path in a record whose header section says major 2 is still `R.container` (S10b-D review round 2).
- **The TOC never decides membership.** The sections are the ones the layout finds. A required section that is
  missing is `R.structure`. A section in the claimed TOC that has no files, or files with no TOC entry, is `R.root`.
- **JSON items obey the frame ceiling too.** A `.jsonl` line whose canonical protobuf encoding exceeds 64 MiB is
  `R.container`.

### 5.4 The `.zip` carrier

- A `.zip` archive of either directory, for distribution (§3.7 "full download"; #14). ZIP64 extensions are used when
  an entry or the archive passes 4 GiB or 65,535 entries; they are part of the zip format, and every mainstream zip
  library reads them.
- Protobuf entries are STORED (method 0), so they can be memory-mapped and seeked. JSON entries may be DEFLATEd
  (0.61 of their size). Byte offsets into a DEFLATEd entry are not seekable. So a verifier reads a DEFLATEd JSON join
  section with one sequential cursor, or inflates it to a temporary file first, and offset sidecars (§5.6) describe
  STORED entries only.
- **Zip consistency (normative).** The central directory is authoritative for the set of entries. For every entry it
  reads, a reader checks that the local header agrees with the central directory: name, method, sizes and CRC-32,
  taking ZIP64 extra fields into account. One exception, for streaming writers: when the local header's
  general-purpose flag bit 3 (data descriptor) is set, its CRC-32, compressed size and size may all three be 0, and
  are then not compared; any other local values must agree. In every case the central directory's CRC-32 and sizes
  govern, and the entry's data must match them as it is read (`R.container` otherwise). A data descriptor is
  never read and never decides anything, so a reader that reads it and one that does not reach the same verdict
  (S10b-C review round 3). Any disagreement is `R.container`, so no reader can see different content from another
  reader. Entry names follow §5.3.1 byte for byte: a name with a byte outside 0x20-0x7E is refused before it is
  decoded, whatever the UTF-8 flag (bit 11) says. Duplicate entry names, encrypted entries and methods other than STORED and DEFLATE are
  `R.container`. Readers also locate the central directory and count its entries in different ways (Python's
  `zipfile` walks it by its size and places it by the end record's offset; others walk it by the entry count), so
  these are `R.container` too (S10b-C review round 1): a central directory that does not fill exactly the bytes from
  its offset to the (ZIP64) end-of-central-directory record; one that holds bytes after its stated number of entries;
  end-record entry counts that disagree (this disk, total); a ZIP64 end record that is not just before its locator
  (with no extensible data), or whose values differ from 32-bit fields that are not the ZIP64 marker; a ZIP64 marker
  without a locator; and an end record that is not the last end-record signature of the archive (a signature in the
  comment). Directory entries are optional and otherwise ignored, but they follow §5.3.1's naming rules (the name
  without its trailing `/`, case folding against every other name included) and may not carry or hide data: STORED,
  both sizes 0, not encrypted, with a local header that agrees, or the archive is `R.container` (S10b-C review
  round 2). Every other entry follows §5.3.1.
- **No `.7z`, no tar.** The user asked for `.7z` only "if .7z would save significant space". Measured on
  current-format ballots (2026-10-09), the cryptographic payload is incompressible (deflate 1.000, LZMA 1.002), and on
  JSON LZMA beats deflate by half a percent (0.609 against 0.612). `.7z` saves nothing worth a second format, and
  `.zip` is the only one of the three with random access to entries in every language's standard library.
- **No single-pass reading** (review round 1; NQ-6). v1 offered verifying a `.zip` read once from a pipe, and asked
  whether to drop it. It is dropped, for three reasons:
  - No stock library supports it. .NET's `ZipArchive` copies a non-seekable input into a `MemoryStream` before it
    returns any entry, which is impossible at 13 GB. Python `zipfile`, Go `archive/zip` and yauzl need the central
    directory. Java's `ZipInputStream` refuses STORED entries that have a data descriptor, which is what a streaming
    zip writer produces. Every language would need a hand-written local-header parser, and every writer would need
    extra rules.
  - The join sections would have to be buffered, and that has no bound. Uncast releases alone are
    U × contests × (m+L)·m·32 B, about 9.6 GB at 10^6 never-returned ballots with 10 contests of m = 5, L = 1.
  - It contradicts the memory bound of §6.4.

  A seekable input accepts any entry order, and an HTTP source with range requests is seekable. A non-seekable stream
  given to the verifier is spooled to a temporary file first, which costs disk equal to the record. The archive has
  no prescribed entry order. Writers should still put `toc` and `setup/*` first, as a convenience for people browsing
  it.
- Transport compression (for example `.zip.zst`) is not part of the record.

### 5.5 JSON representation: the proto3 JSON mapping

Each `.jsonl` file's first line is the `SegmentHeader` and every following line is one `RecordItem`, each in the
**proto3 JSON mapping** (#3, follow-up "JSON is the proto3 JSON mapping"):

- **Names** are lowerCamelCase (`idB`, `hI`, `ballotStyle`, `encryptedAt`, `chainingField`); a `RecordItem` line is
  an object with one member named after its oneof member (`{"encryptedBallot":{...}}`).
- **Bytes** are base64 (RFC 4648 standard alphabet, padded, when writing). Group elements, Z_q values and hashes are
  therefore base64 of exactly their fixed-width bytes, as on today's JSON ballots.
- **Integers:** `uint32` values are JSON numbers; `uint64` values are decimal strings (`"ballotCount":"412"`), so
  JavaScript reads them without loss.
- **Enums** are their value names (`"BALLOT_STATUS_CAST"`, `"DEVICE_KIND_REGULAR"`).
- **Timestamps** are RFC 3339 in UTC with a `Z` suffix (`"2026-10-08T14:03:07.412Z"`).
- **Defaults** are omitted when writing; readers accept explicit defaults, which have no effect on the canonical
  bytes.
- **Only the parsed structure is defined, not the text.** JSON writers differ in ways the mapping allows:
  - C#'s `JsonFormatter` has no compact mode and writes `{ "a": 1 }` spacing.
  - C# escapes astral characters as surrogate-pair escapes, where Python and protobuf-es write them raw.
  - Go's protojson randomizes whitespace on purpose ("Do not depend on the output being stable").

  Two JSON files are equivalent when they parse to the same items, which is the same thing as the same canonical
  bytes. JSON text is never hashed, compared byte for byte across runtimes, or signed.
- **Lines (normative; S10b-C review round 3).** What the parsed structure is read from is fixed, so that every
  reader splits a file into the same items:
  - A `.jsonl` file is a sequence of lines, each ended by a line feed (0x0A), except that **the last line's line
    feed is optional**, as jsonlines.org makes it (user decision 2026-10-10, "Optional"; S10b-C had required it). A
    last line cut short by a crash is still refused: a JSON value cut short does not parse, so it is `R.encoding`.
    (A cut that happens to leave a whole JSON value, at a value boundary, is not detectable by any line rule; the
    item's decode rules and the roots then decide.) This library's writer ends every line, and its resume cuts an
    unterminated last line of its own segment as the torn tail (§5.2): the line's ballot was never flushed.
  - One carriage return (0x0D) just before a line feed, or at the end of an unterminated last line, is removed, so
    CRLF files read as LF files.
  - An empty line (nothing, or only that carriage return, before the line feed) is `R.container`. Any other line
    must parse as one JSON value (whitespace around it is JSON's own), else `R.encoding`.
  - A line longer than 128 MiB (2^27 bytes, without its line feed) is `R.container` before it is parsed, whatever it
    holds; within that, a line whose canonical protobuf encoding exceeds 64 MiB is `R.container` too (§5.3.1).
  - Text that is not UTF-8, a byte-order mark included, fails JSON parsing: `R.encoding`.
- **The library's writer** emits one item per line, LF line endings and members in field-number order, so `diff` is
  meaningful. Its lines are compact: C# re-writes `JsonFormatter`'s output through `Utf8JsonWriter` with indentation
  off. How non-ASCII characters are escaped is not specified.
- **The library's reader** follows the mapping (Google.Protobuf `JsonParser`, whose default settings reject unknown
  members; a negative vector pins this). It also refuses ambiguity (S10a's `StrictJson.RejectAmbiguity`, extended;
  this closes the S10a carry-over F3). Every runtime tested leaves a different gap open: Python rejects an exact
  duplicate key but accepts `{"formatMajor":2,"format_major":3}` (last wins); protobuf-es rejects that alias pair but
  accepts an exact duplicate (last wins); C# accepts both silently. So the reader refuses, as `R.encoding`:
  - a member named twice in one object;
  - a field named by both its JSON name and its proto name (`formatMajor` and `format_major` are one member);
  - two members of the same oneof in one object, such as a `RecordItem` line with two item members. A last-wins parse
    would hide this from D5.

  The other leniencies the mapping allows (unpadded or URL-safe base64, `null` for a default, numbers given as strings)
  cannot change what is hashed, because the reader hashes the canonical protobuf encoding of what it parsed.
- **JavaScript uses protobuf-es for JSON.** protobufjs writes canonical binary, but it does not implement the proto3
  JSON mapping. Its `toObject` renders a `Timestamp` as `{seconds, nanos}`, and its `fromObject` throws on an RFC 3339
  string. protobuf-es's `toJsonString` matched Python's compact output byte for byte, astral characters included.

An abbreviated item line:

```json
{"encryptedBallot":{"idB":"q83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4k=","hI":"...","ballotStyle":"style-1","status":"BALLOT_STATUS_CAST","weight":1,"encryptedAt":"2026-10-08T14:03:07.412Z","contests":[{"index":1,"fields":[{"alpha":"...","beta":"...","rangeProof":"..."}],"limitProof":"...","contestHash":"..."}],"confirmationCode":"...","chainingField":"...","encryptedBallotNonce":{"c0":"...","c1":"...","c2":"..."}}}
```

JSON converts losslessly to canonical protobuf and back for every item a reader understands (no floats or maps, bytes
exact, every enum named). It is for people, interop and debugging; distribute GB records as protobuf.

### 5.6 Derived views (outside the root; regenerable and checkable by regenerating)

Follow-up #18: "Alongside, not signed".

- **Confirmation-code lookup:** H_C → (locator, segment, offset), sorted by H_C. With inclusion proofs (leaf path in
  the device section, the device's TOC entry, the TOC path) it serves §3.7's lookup tool. A voter's checker needs only
  SHA-256, and a proof is under 1 KB.
- **Sorted id_B index:** (id_B, locator), strictly ascending. It is an optional O(1)-memory V5.A path (§6.5) and can
  back the record-side `IPublishedCastAndSpoiledBallots` (Q31; spoiled ballots too, 2026-10-09).
- **Offset sidecars:** ordinal → byte offset per segment, for random access.

### 5.7 Conformance artifacts (`test/egrf/`)

- **In place since S10b-B:** `test/egrf/vectors/items.json` (a golden canonical item per `RecordItem` member and a
  segment header, with leaf hash and proto3 JSON; newer-minor items with their verdict), `negatives.json` (one or more
  per rule W1-W6, W8, D1-D6 and the §4.9 statement codes, with the record's minor; W7 is a schema property, S3) and
  `merkle-rfc9162.json` (the Certificate Transparency reference roots for 0..8 leaves and its inclusion and consistency
  proofs, transcribed from transparency-dev/merkle). The first two are generated by the C# tests from synthetic byte
  patterns (`EGRF_WRITE_VECTORS=1` rewrites them); the feasibility run's draft-schema vectors were not reused.
  The layout, framing, torn-tail, zip and JSON negatives below are C# tests since S10b-C
  (`RecordDirectoryCarrierTests`, `RecordZipCarrierTests`, `RecordResumeTests`, `RecordJsonProjectionTests`). They
  are whole records rather than items, so their files come with the golden records in S10b-12, where the Python
  reader must reproduce them too.
- **Golden vectors** (`test/egrf/vectors/`):
  - every item type: canonical bytes (hex), proto3 JSON and leaf hash. The JSON is compared by structure: parse
    both sides and compare members and values. The feasibility run's comparison matched C# against Python for 31 of
    31 items. Bytes and leaf hashes are compared byte for byte. The feasibility vectors
    (`vectors.json`, `negatives.json`) seed this set;
  - MTH roots for n = 0..17 and 1,000, cross-checked with the RFC 9162 test vectors;
  - three complete small records, each as a protobuf directory, a JSON directory and a `.zip`, all with the same
    roots: regular with no chaining; simple chaining with contest data and cast, challenged and spoiled ballots;
    pre-encrypted with cast, returned uncast (full form) and never-returned uncast (compact form) ballots and their
    releases;
  - **newer-minor items** (NQ-1): items with unknown fields appended in canonical position, with the verdict a reader
    of the older minor must reach (canonical, content reported) and the bytes it must re-encode them to (unchanged).
- **Negative vectors**, one per rule, each with its expected code: an overlong varint (in a tag, a length and a
  value), fields out of order, a singular field written twice, a default-valued field written explicitly, an unknown
  field, a known field with the wrong wire type, a wrong width, an absent non-omittable width field, a timestamp with
  sub-millisecond nanos, negative seconds, negative nanos, `UNSPECIFIED` status, an undeclared enum value, a
  `uint32` ≥ 2^31, a `uint64` ≥ 2^63, ill-formed UTF-8, an empty `RecordItem`, a `RecordItem` with two fields, a
  non-canonical `SegmentHeader`, a frame over 64 MiB, a zero-length frame, a torn
  tail (cut short, and zero-filled), a segment gap, a path that disagrees with its `SegmentHeader`, an uppercase-hex
  path, an unlisted file, a name under `derived/` with a byte outside 0x20-0x7E, a `:` or a `\` (in a directory and
  in a zip), a duplicate zip entry, a zip local header that disagrees with the central directory, a zip local header
  with bit 3 set and only some of its CRC-32 and sizes zero (with the positive: all three zero, the archive read),
  a `.jsonl` file whose last line is cut short (`R.encoding`; with the positive: a last line without its line feed
  reads), an empty line, a line one byte over 128 MiB (with the positive: CRLF line endings read as LF), a TOC entry
  naming a section kind the major does not define (`R.version`, NQ-7), a
  non-canonical signed statement and one with a non-statement member, and a TOC entry whose `critical` bit
  disagrees with §4.5. Unknown-field negatives (W6), for a reader older than the record: an unknown field before a
  known field, unknown fields in descending order, an unknown number inside the message's declared or reserved range,
  an unknown field with wire type 1 or 5, an unknown VARINT of 0, an unknown VARINT repeated, and a non-minimal varint
  inside an unknown field; and for a reader at the record's minor, any unknown field. A compact uncast item whose
  release lacks ξ_B, and a full one whose release carries it. JSON negatives: a duplicate member, a JSON-name and
  proto-name alias pair, two members of one oneof, and an unknown member. Plus one per `R.*` code and join rule.
- **The Python reference reader** (`test/egrf/egrf_ref.py`) is Python 3, standard library only, in the spirit of the
  KAT oracle (`test/kat/eg_kat.py`). It transcribes the schema by hand from the `.proto` into a table (field numbers,
  types, widths, reserved numbers), implements Method A (§4.4, unknown fields included), the length-delimited segment
  reader, the Merkle tree and the phase roots, and reproduces the golden roots and every negative vector's verdict.
  A C# test (`EgrfSchemaLintTests`, S10b-2) already writes `test/egrf/schema.json` from the compiled descriptor
  (custom width options included); CI will fail if the Python table and that file disagree. This is the acceptance
  test for the formal spec: anything the Python reader needs that the spec does not say is a gap in the spec. It also
  demonstrates G-7: no protobuf runtime is required.

---

## 6. Streaming verification model

### 6.1 Phases of a run

| Step | Reads | Runs | Gate |
|---|---|---|---|
| A. Record | the carrier's file or entry list, `toc`, the header | layout and zip consistency (§5.3.1, §5.4; `R.container`); format version (`R.version`); phase and presence (`R.structure`) | An unknown major version or a layout failure stops the run. |
| B. Setup | sections 0x0001-0x0005 | V1 against `EGParameters`; parse the manifest from `ManifestFile.content` by media type (`ManifestSerializer`: known members strict, unknown properties ignored, then `Manifest.Validate`); V2 per guardian, in parallel; V3; V4. Build `EncryptionRecord` from claims (`ElectionPublicKeys.FromKeys`, manifest from bytes). | A V1 failure, an unparseable manifest or a V4 failure stops all cryptography (later outcomes `NotEvaluable`). Digests and structure still run to the end. |
| C. Join prep | `device_attestations` and the four join sections (`contest_data_requests`, `challenged_ballot_decryptions`, `contest_data_decryptions`, `uncast_nonce_releases`) | A **framing pre-scan**: read each item's leading locator (field 1 of the inner message, within its first 60 bytes) to check sort order (`R.order`), and record the offset where each device key's run begins (O(D)). Load the attestation statements per device (O(D)). *As built (S10b-D): no pre-scan; one sequential cursor per join section checks the order as the device pass reads it (§8.3).* | |
| D. Ballots | device sections, in parallel across sections | per §6.2 | Findings are collected, and the run continues. |
| E. Tally | `encrypted_tally`, `decrypted_tally` | Merge the V9 partials and compare (9.A, 9.B), and each contest's `cast_weight` (`9.structure`). Header counts against recounted cast ballots and weight (`R.summary`, `BallotAggregationVerifier.VerifySummary`; beside V9's outcome, never as it: a false header still passes V9). V10 per field, in parallel. V11.A-C. V11.D from the bitset of contests on submitted ballots. | |
| F. Completion | | Finish 5.A (§6.5). Every cursor exhausted (leftovers are `12.structure`, `13.structure` or `18.structure`). Section roots against the TOC (`R.root`). Phase roots against any `Expected*Root` option. Record signatures (`R.signature`, governed by the policy). | |

### 6.2 The device pass

For each device section, the pipeline has three stages:

- **Reader.** Reads delimited items sequentially with read-ahead, rejecting a frame length over 64 MiB before it
  allocates (§5.2), and posts (ordinal, bytes) to a channel bounded **by bytes** (default 64 MiB per section, and at
  least one item), not by item count, so a section of large pre-encrypted items cannot multiply memory.
- **Workers**, in parallel within the section. For each item: the canonicality check (§4.4), the leaf hash, the
  decode with range and structure attribution (§4.8), then the per-item verifications:

  | Item | Checks |
  |---|---|
  | `EncryptedBallot`, any status | 5.B, 6, 7, 8.A, 8.B; set the 11.D bits (every recorded ballot is submitted, #4) |
  | `EncryptedBallot`, `CAST` | also: fold into this worker's `BallotAggregationVerifier` (weighted) |
  | `EncryptedBallot`, `CHALLENGED` | also: take the decryption at this locator from the section's cursor and run V13 and V14 while the ballot is in memory |
  | `EncryptedBallot`, `CAST` with contest-data requests at this locator | also: run V12 on each matching `ContestDataDecryption` |
  | `EncryptedBallot`, `SPOILED` | nothing beyond the first row: not tallied; a decryption naming it is `13.structure` (§3.3) |
  | `PreEncryptedCastBallot` | 5.B, 6, 7, 15, 16.A-C, 17, V9 fold, 11.D |
  | `PreEncryptedUncastBallot` | 5.B, 6.A at the range layer only (§3.2), 16.A-C, 17, 19, 11.D; take the release at this locator from the cursor and run V18 |
  | `PreEncryptedCompactUncastBallot` | 5.B, 11.D; take the release at this locator from the cursor, regenerate the vectors and ψ from its ξ_B (eqs. 113-121), compare each χ and H_C with the item's, and run 16.A-C and 18 on the regenerated content; count the item as one whose 17.A and 19.A-D hold by construction (§3.2: no displayed codes or labels are recorded) |

- **Sequencer**, in position order with O(1) work per item:
  - append the leaf to the section frontier and H_C to the codes frontier;
  - append id_B's keyed prefix to the 5.A run buffer;
  - advance the chain walker (8.D/8.E or 16.E/16.F) on the stated H_C and B_C, whose correctness is the worker's
    8.B/16.C;
  - match each prefix-checkpoint statement when the codes frontier reaches its count;
  - advance the join cursors and check the join rules below.

  At `DeviceClose` it checks 8.C/8.F/8.G or 16.D/16.G/16.H, ℓ, the section root, and the chain-close and
  section-seal statements.

**Join rules** (each failure is reported at the ballot's locator, naming id_B):

- Every `CHALLENGED` regular ballot has exactly one `ChallengedBallotDecryption`, whose `h_i` equals the ballot's
  (`13.structure`). v2.0 requires one for every challenged ballot (#8); under Q24 (fail closed) a ballot whose nonce
  decryption failed therefore fails the record.
- A `ChallengedBallotDecryption` that names a `CAST` or `SPOILED` ballot, or a pre-encrypting locator, is
  `13.structure`. This is the Q31 property, checked from the published record.
- Every `PreEncryptedUncastBallot` and `PreEncryptedCompactUncastBallot` (returned or never returned, #5) has exactly
  one `UncastNonceRelease` with equal `h_i`, and every release names an uncast item (`18.structure`). The release
  matches the item's form (NQ-2): `contests` for a full item, `ballot_nonce` alone for a compact one (`18.structure`).
- Every `ContestDataRequest` names a `CAST` regular ballot and a contest with b_Λ > 0, and has exactly one matching
  `ContestDataDecryption`; every decryption has exactly one matching request (`12.structure`; follow-up #10).
- **RLA note (Q22):** the format admits a `ChallengedBallotDecryption` that leaves out whole contests, as 13.B allows.
  As built, 14.B (the S7 reading) fails such a decryption. That stays the behaviour until the audit workflow is
  designed, when a new oneof member will carry partial decryptions.

Per-ballot ordering semantics are unchanged: `VerifyFused`/`VerifyInOrder` still report 6.A/7.A first. A ballot that
fails `9.structure` faults `BallotAggregationVerifier` by design, so V9 is then reported as `NotEvaluable`, never as
passed.

### 6.3 Joins and seekability

The four join sections are in canonical ballot order, so they are joined by merge:

- **Single-threaded:** one cursor per join section, advanced in step with the device pass. O(1) memory.
- **Parallel:** each device worker opens its own cursors at the run offsets step C recorded for its key. That needs
  O(D) offsets, and reads stay sequential within each run, which suits HTTP range reads. *Not built (S10b-D): the
  device pass is one stream of items in canonical order, parallel within batches, so the single-threaded cursors
  suffice and no offsets are kept (§8.3 "As built (S10b-D)"); a distributed verifier would split at offsets.*
- **DEFLATEd JSON join sections** (§5.4) have no seekable offsets. The verifier either joins them with one sequential
  cursor per section, which serializes the joins but not the device pass, or inflates each to a temporary file first
  and then uses the parallel path. Either way memory stays O(1) per cursor.
- **Non-seekable input** is spooled to a temporary file and then read as seekable (§5.4). The join sections are
  never buffered in memory, so their size does not affect the bound in §6.4.

### 6.4 Memory per verification

Notation: N ballot items; D device sections; F verifiable fields in the manifest; C contests; W workers; X, Y, U
challenged decryptions, contest-data decryptions and uncast releases. The example column uses N = 10^7, D = 5,000,
F = 200, C = 50, W = 32 and X = 10^5.

| Verification | State across items | Bound | Example |
|---|---|---|---|
| Pipeline | in-flight items | the reader's byte bound per open section (default 64 MiB), plus one decoded item per worker (≤ 64 MiB each, §5.2; ~13 KB for a ballot) | 32 × 4 × 13 KB ≈ 2 MB for regular ballots; worst case W × 64 MiB with 64 MiB items |
| Digests | a frontier per open stream; D section roots | ≤ 64 × 32 B per stream + ~80 B × D | < 1 MB |
| V1-V4 | manifest bytes, parsed manifest, guardians | O(manifest) + n·k·512 B | < 10 MB |
| **V5.A** | keyed 64-bit id_B prefixes in sorted runs | **8 B × N**, in RAM up to the budget (default 256 MiB, about 32M ids), spilled beyond it. | 80 MB, or ≤ 256 MiB plus disk at 10^8 |
| V5.B, 6, 7, 8.A/B, 12-19 | none across items | inside the pipeline | |
| 8.C-8.G, 16.D-16.H | per open section: H_{j−1}, j, H_0, mode, codes frontier | ~2.2 KB × W | < 100 KB |
| V9 | (A, B) partial products per field per worker (`ModPProduct`) | ~1.3 KB × F × W | ~8 MB |
| V10, V11.A-C | the encrypted tally, joined with the decrypted tally | O(F) × ~1 KB | < 1 MB |
| V11.D | contest bitset per worker | C bits × W | bytes |
| Joins | one item per cursor per worker, plus O(D) run offsets (as built, S10b-D: four sequential cursors, the items of one batch, no offsets) | ~2 KB × 4 × W + ~50 B × D | < 1 MB |
| Attestations | expected statements per device | ~250 B × D | ~1.3 MB |

**Total ≈ the V5.A budget + about 30 MB, independent of N**, for records of ordinary items. Records with items near the
64 MiB ceiling add up to W × 64 MiB of decoded items, which `MaxDegreeOfParallelism` bounds. V5.A is the only state that grows with N, and the spec
requires that: 5.A is a global uniqueness check over random values, and the format cannot store ballots sorted by
id_B without breaking chain order and appending. This replaces today's `DeviceChainWalk.Index`, which keeps every link
in a dictionary (O(N), about 150-250 B per ballot), and today's `HashSet<SelectionEncryptionIdentifier>`, about 100 B
per id.

### 6.5 V5.A algorithm (exact, spill-bounded, adversary-resistant)

1. Per run, draw a secret 128-bit key k. For each ballot item of every kind and status (spec §4.5 p.64: "the full set
   of ballots, including the pre-encrypted ballots"), append `prefix = first 8 bytes of SHA-256(k ‖ id_B)` to the run
   buffer.
2. When the buffer reaches the budget, sort it and spill a run file. **Runs are sorted on the keyed prefix, not
   bucketed by id_B's own bytes**, so a record that skews its id_B values cannot overflow any in-memory partition.
3. At the end, k-way merge the runs and collect any prefix seen twice. The expected count is about N²/2^65: about
   3 × 10^-6 at 10^7.
4. If any prefix repeats, make a confirmation pass. Hop item to item by the length varints, reading only the first
   48 bytes of each: the frame length, the `RecordItem` tag and length, then field 1, which is `id_b` (0x0A 0x20 and
   32 bytes) on every ballot item. Recompute the prefix, keep the full id_B and locator for the colliding prefixes,
   and compare exactly. Report 5.A with both locators. On JSON the pass parses each line's `idB` instead, which is
   slower, but JSON verification already is.
5. **Distributed verification:** the coordinator supplies k to every shard, keeping it secret from the record's
   publisher, and merges their run files.

Optional O(1)-memory path: if a sorted id_B index (§5.6) is published, strictly ascending entries, each entry's
locator resolving to a ballot with that id_B, and an entry count equal to N together make the index a bijection onto
the ballots. That proves uniqueness at the cost of one 32-byte random read per ballot.

### 6.6 What only the root and signatures protect

`status`, `weight`, `encrypted_at`, `ballot_ref` and `ballot_style` are not inputs to H_C. Only the record root, the
phase signatures and (per device) the section seal stop someone from turning a challenged or spoiled ballot into a
cast one after the fact. An unsigned record cannot rule that out. That is why `SignaturePolicy.RequireValid` is
recommended for official verification, and why the section seal is offered for regular devices.

### 6.7 Parallelism, distribution and throughput

- **Within a process.** Device sections are scheduled with work stealing, largest first. Within a large section (a
  central-count scanner with millions of ballots), segments let several readers start at segment headers, and the
  sequencer stitches the chain across segment boundaries.
- **Accumulators.** They commute and merge: the 5.A runs, the V9 partials (`BallotAggregationVerifier.Merge`; a
  faulted operand faults the result), the bitsets and the counters.
- **Across machines.** A shard is a set of device sections. Each shard returns its section roots and counts, its 5.A
  run files, its V9 partials **in standard (A, B) form**, its 11.D bitset, its codes roots and its findings.
  `ModPProduct` values carry engine-specific Montgomery drift (R differs between AVX-512 and scalar; CLAUDE.md), so a
  raw product never crosses a process boundary. The join sections travel with their devices, split at the run
  offsets.
- **Parallelism option.** `MaxDegreeOfParallelism` passes through to `BallotAggregationVerifier`,
  `TallyDecryptionVerification` and the pipeline, so `--parallelism 1` stays a true single-threaded baseline.
- **Throughput.** It is CPU-bound at about 1,000 ballots/s on 32 logical cores (measured). SHA-256 of a 13 KB item
  (about 8 µs), the canonicality check and the decode are under 0.1 % of a ballot's verify cost.

### 6.8 Resumable and incremental verification

A **VerifierCheckpoint** is local, trusted state, written atomically (a temp file, then rename) every
`CheckpointInterval` and at section ends. It holds:

- the record identity: the claimed TOC root and the phase. A record without a claimed TOC (a live record) is never
  checkpointed: a resumed run does not re-read the prefix it verified, so only a TOC root binds that prefix to the
  bytes on disk (S10b-D review round 2; the writer likewise has nothing to resume without a TOC);
- the options hash: profile, verification subset and key k;
- per device section: next position and byte offset, section frontier, codes frontier and chain-walker state;
- the V9 partials in standard (A, B) form, never raw `ModPProduct`;
- the 5.A run files, with the current buffer flushed as a run;
- the 11.D bitset, the cursor positions, the counters and the findings so far.

On resume, each section continues from its saved offset and frontier. The final section root must equal the TOC's.
Because the frontier commits to the verified prefix, a match proves that the record being finished extends exactly
what was verified, so nothing is re-read. **A checkpoint is never accepted from a third party**, because it holds
verdicts. The checkpoint's own encoding is an implementation detail (a protobuf message in the C# implementation), not
part of the format.

A **live record** (S10b-17) uses the same machinery. It tails the device part files under `devices/`, checks
prefix-checkpoint statements as they appear, and at seal runs only the remaining items plus steps E-F.

### 6.9 Profiles and the report

| Profile | Input phase | Runs |
|---|---|---|
| `Full` | final | everything |
| `GuardianPreliminary` | aggregated | §3.6.1: V1-V9, with V15 and V16 (spec p.64: on pre-encrypted ballots V16 checks the confirmation codes in place of V8, and V15 the accumulated selection vectors with V7; both `NotApplicable` without a pre-encrypting device), and the request rules. V17 is not in it (question NQ-11). It reports two sets: the ballots the guardians will open (exactly the `CHALLENGED` regular ballots, through `TallyGuardian.DecryptBallotNonce`), and the uncast pre-encrypted ballots that need a release (from the out-of-scope recording tool until S10b-19, after which the guardians open them from the sealed record, NQ-5). Takes `ExpectedAggregatedRoot`, obtained out of band, so guardians decrypt exactly what they verified (Q36). Returns a `VerifiedAggregate` (§8.3) that tally decryption from a record requires, closing the S10a carry-over "a tally read back cannot be decrypted before Verification 9". |
| `BallotCorrectness` | any | for chosen locators or confirmation codes: 5.B, 6, 7, 8.A/8.B or 15/16.A-C/17/18/19, 13/14 where applicable, plus an inclusion proof to the root. Reads only those items, through derived offsets or a scan. |
| `Custom` | any | any subset of 1-19 (used by the structure-only GB tests) |

**Report semantics:**

- **Outcome per verification** (1-19): `Passed`, `Failed`, `NotApplicable` (for example 15-19 with no pre-encrypting
  section), `NotEvaluable` (blocked by an earlier failure) or `NotRun` (outside the profile).
- **R-codes:** `R.container`, `R.encoding`, `R.order`, `R.structure`, `R.version`, `R.root`,
  `R.summary`, `R.attestation`, `R.signature`.
- **`Complete`** is false whenever the reader skipped content it does not understand: an unknown field, oneof
  member or enum value of a newer minor (§7). A vendor section does not make it false: vendor sections are part of
  the format (digested, never verified) and are counted in the statistics. (There is no unknown standard section
  kind to skip: NQ-7 puts any new section kind in a new major.) That is informational, not a failure (NQ-1: a verifier that
  sees a newer `format_minor` "reports that the record is newer but still verifies everything it understands"), so
  **`Passed` means no failures**, and `Complete` is reported beside it with the record's and the reader's format
  versions and the content not understood (`SkippedUnknownContent`). Content a reader must understand to verify is
  never informational: a critical vendor section (its writer says it must be understood), or an unknown item type in
  a section that must verify, is a `R.version` failure. `egrecord verify` exits 0 when passed and complete, 2 when passed but incomplete, 1 on any
  failure, so a script cannot mistake one for the other.
- **Findings** carry `SubSection` (the existing `VerificationFailedException` convention: "6.D", "13.structure",
  "R.order"), the verification number, the section, the locator, id_B in hex, the contest and field index, and a
  message (as built, S10b-D: the section key and the item's ordinal; the contest and field are named in the message).
  The report's phase is the phase verified: a guardian run of a final record reports `Aggregated`, and its roots and
  TOC comparison cover the aggregated prefix only. They are ordered deterministically: by step (§6.1), then by canonical record order, then by sub-section.
  They are capped at `MaxFindings` (default 10,000); the verdict is already Failed when the cap truncates.
- **Default is collect-all.** At about 1,000 ballots/s, a run that stopped at the first failure would waste hours.
  `StopOnFirstFailure` is available.
- **Also reported:** all four phase roots, attestation and signature results, unknown content skipped, and statistics
  (N by kind and status, per-device counts, bytes, per-step timings). Among them, the number of compact uncast items,
  stated as the items whose 17.A and 19.A-D held by construction (§3.2): the record holds no printed codes or labels
  for them, so their V17 and V19 outcomes say nothing about what was printed.

---

## 7. Versioning and extension

| Layer | Mechanism | A reader that does not understand it |
|---|---|---|
| Spec version | `Parameters.version` (the exact eq. 4 bytes), checked by 1.A | V1.A fails |
| Format major | `RecordHeader.format_major`, repeated in `SegmentHeader` and `RecordStatement`; the `.proto` package is `electionguard.egrf.v<major>` | refuses the record (`R.version`, stop). The reader reads the header section's segment header at v2's path first, before the layout and D6 refuse anything a later major may hold (new paths, segment headers at its own major): magic "EGRF" with another `format_major` is `R.version` (review round 2); then the `record_header` item's major is checked again |
| Format minor | `RecordHeader.format_minor` | reads in compatible mode (below) |
| Section type | a new section kind needs a **new major** (user decision NQ-7, "Bump the major version"); later tallies arrive this way (§4.5). Vendor types (0x8000-0xFFFD) are the one open range | a v2 reader refuses the record at its header section's segment header, read first (`R.version`, the row above); a claimed TOC entry naming an undefined non-vendor type is `R.version` too, and there is no path for one (§5.3.1). A vendor section: the bit comes from the claimed TOC (§4.5); critical: `R.version` failure; non-critical: digested |
| Item type | a new `RecordItem` oneof member (a field of `RecordItem`) | in a section it must verify: that item's checks are `NotEvaluable`, with `R.version`; `Complete = false` |
| Field | a new field number, append-only (S6), after every older field on the wire (W6) | verifies what it knows, keeps and digests the rest, reports it, `Complete = false` (informational; "Older readers" below) |
| Enum value | a new value of an existing enum, except `SectionType` (NQ-7) | the checks that depend on it are `NotEvaluable` with `R.version`; the item is digested (D2). As built: a ballot status (review round 1); a device kind in a join item's ballot locator (the item joins nothing; review round 2). A device of a new kind would also need a new section path, which v2's layout does not have (§5.3.1; NQ-7: no generic path), so a v2 reader refuses such a record whole at open (`R.container`, the unlisted path); a device header of an undeclared kind inside a declared kind's section is a header that does not name its section's key, the device's structure code (review round 3; NQ-9) |
| Vendor data | none in the record items (NQ-1: "Vendors should never add fields to most of the types"); vendor properties in the manifest (ignored by the parser, bound by H_B) or vendor sections | n/a |
| Files | `SegmentHeader.magic` and `format_major` | `R.container` |

Rules:

- A **major** change alters an existing field's meaning or type, the profile, the digest rules or the fixed widths.
  A new spec version that changes published objects means a new major, and a new `.proto` package.
- A **minor** change only adds fields (numbered above every number the message declared or reserved before, S6; a
  new `RecordItem` oneof member is such a field) and enum values other than section types: protobuf forward
  compatibility under NQ-1's rules. It never adds a section kind (user decision NQ-7: that is a new major), never
  changes the meaning of an existing check, and a field it adds defaults to "absent" with the old meaning.
- **Writers MUST use the lowest representation that can carry the content.** A new field is written only when the
  content needs it (otherwise it is absent by W2), and a new oneof member only for content the old one cannot carry.
  So an old reader keeps verifying every record that does not use the new capability.
- **Older readers (NQ-1).** A reader that knows minor m and reads a record of minor m' > m checks each item with
  Method A, or with Method B keeping unknown fields plus Method A's unknown-field rule (§4.4). For an unknown field it
  checks the W6 placement (after every known field, ascending, above every declared or reserved number), wire type,
  minimal varints and exact lengths; it cannot check a LEN payload or a width. The item is digested as stored, and
  if the reader re-encodes it (a copy, a resumed writer), it keeps the unknown fields, which by W6 re-encode to the
  same bytes, so every root survives. The reader verifies everything it understands and reports the newer minor and
  the content it skipped (`Complete = false`, informational, §6.9). In JSON an unknown member cannot be turned into
  canonical bytes without its field number, so a JSON reader stops with `R.version`; the protobuf representation is
  the one to verify a newer record with. Neither path reports `Complete` with unread content (G-6), and the roots
  computed from the protobuf representation are exact.
- **Vendor sections** (0x8000-0xFFFD) are final-phase, digested and never verified. The library's writer marks them
  non-critical unless told otherwise, and readers take the bit from the claimed TOC (§4.5).
- **Election options** (chaining mode, Ω, supplemental fields, b_Λ) come from the manifest. The format has no
  feature flags.

---

## 8. C# implementation

### 8.1 Codec: Google.Protobuf, generated from the normative `.proto`

**Decision: Google.Protobuf runtime, with C# generated at build time from `egrf.proto` by Grpc.Tools.** In place
since S10b-2: `ElectionGuard.Core.csproj` references Google.Protobuf 3.34.1 and Grpc.Tools 2.80.0 (libprotoc 31.1;
`PrivateAssets="All"`, a build-only dependency) and compiles
`<Protobuf Include="..\..\proto\electionguard\egrf\v2\egrf.proto" ProtoRoot="..\..\proto" Access="Internal" GrpcServices="None" />`.
The generated types are in `ElectionGuard.Core.RecordFormat.Protobuf` (not `...Core.Record...`: a namespace named
`ElectionGuard.Core.Record` hides xUnit's `Record` class from every test in `ElectionGuard.Core.UnitTests`, which
the first build showed). protobuf-net is retired with the old DTO tree (S10b-16), so Core ends with one
serialization dependency.

Why not protobuf-net, which Core uses today:

- **The `.proto` is normative** (follow-up: "The `.proto` schemas are normative"). Generating C# from it means the
  field numbers, types and names in C# cannot drift from the published schema. protobuf-net is code-first: the schema
  lives in attributes on hand-written classes, and a `.proto` can at best be exported from them. Both of today's
  protobuf hazards come from that model: the "add a field in both the domain type and its DTO" rule (CLAUDE.md,
  Serialization) and the dormant nonce copy at line 83.
- **Determinism the profile can rely on.** protoc's C# generator writes fields in field-number order, omits proto3
  defaults, writes a set oneof member even when it is default, keeps unknown fields by default and writes them after
  the known ones (NQ-1, §4.4; pinned by `EgrfUnknownFieldBehaviourTests`), and has `WithDiscardUnknownFields(true)`
  for a reader at the record's own minor. In protobuf-net, ordering, default omission and packing are per-attribute
  choices, and keeping unknown fields needs `Extensible`.
- **The custom options are readable.** The descriptor exposes `(width)`, `(width_multiple)` and `(omittable)`, so the
  decode rules and the schema lint test read the same annotations as every other language.
- **The proto3 JSON mapping comes with it.** `JsonFormatter` and `JsonParser` implement the mapping. protobuf-net has
  none, so §5.5 would be hand-written. Two gaps are ours to close (§5.5): `JsonFormatter` has no compact mode, so the
  writer re-writes its output, and `JsonParser` accepts duplicate and aliased members, so `StrictJson` runs first.
- **Cost.** Parsing copies each `bytes` field into a `ByteString`, about 25 allocations per ballot. Against about
  1 ms of cryptography per ballot this is noise, but egperf's allocation gate will show it; the write path avoids
  copies with `UnsafeByteOperations.UnsafeWrap`, and S10b-15 measures it.
- **Generated types stay internal** (`Access="Internal"`). The public API remains the domain types, and mappers
  convert at the boundary.

A hand-written codec was the third option. It would put canonicality back on our own encoder, which is v1's cost
without v1's benefit, and the JSON mapping would also be hand-written.

### 8.2 Placement (#15)

- `src/ElectionGuard.Core/RecordFormat/` (namespace `ElectionGuard.Core.RecordFormat`, §8.1): the generated types,
  the canonicality check, the mappers, Merkle, the carriers, the JSON projection, the writer and the reader.
- `src/ElectionGuard.Core/Verify/ElectionRecordVerifier.cs`: the verify-everything entry point.
- `src/ElectionGuard.Verifier/` (new): the `egrecord` CLI (`verify | digest | convert | diff | prove | show`).
  `ElectionGuard.Administration` will be the main writer when it exists.
- `proto/electionguard/egrf/v2/egrf.proto`: the schema, shared by every implementation (in place since S10b-2).
- `test/egrf/schema.json`: the schema table (in place since S10b-2); later the golden vectors and the Python reader.

### 8.3 API sketch

```csharp
namespace ElectionGuard.Core.BallotEncryption;

/// The values equal the record's BallotStatus enum numbers. Implemented in S10b-1.
public enum BallotStatus
{
    Unrecorded = 0,   // in memory only: no decision yet. Never written; a writer refuses it. (was NotSubmitted)
    Cast = 1,
    Challenged = 2,
    Spoiled = 3,      // in the record, neither cast nor challenged (#4). Not tallied; never opened: guardians refuse a match (§3.3).
}
// EncryptedBallot.RecordStatus accepts Cast, Challenged or Spoiled, once.
```

```csharp
namespace ElectionGuard.Core.RecordFormat;

public readonly record struct RecordFormatVersion(ushort Major, ushort Minor) { public static readonly RecordFormatVersion V2_0 = new(2, 0); }
public enum RecordPhase : byte { Setup = 1, Sealed = 2, Aggregated = 3, Final = 4 }   // = the proto enum numbers
public enum RecordEncoding { Protobuf, Json }
public enum RecordCarrier { Directory, Zip }
public enum RecordSectionType : ushort
{
    Header = 0x0001, Parameters = 0x0002, Manifest = 0x0003, Guardians = 0x0004, ElectionKeys = 0x0005,
    Device = 0x0101, DeviceAttestations = 0x0102,
    EncryptedTally = 0x0201, ContestDataRequests = 0x0202,
    DecryptedTally = 0x0301, ChallengedBallotDecryptions = 0x0302, ContestDataDecryptions = 0x0303,
    UncastNonceReleases = 0x0304,
}

public readonly record struct Sha256Digest(/* 32 bytes inline */);
public readonly record struct DeviceKey(DeviceChainBallotKind Kind, VotingDeviceInformationHash DeviceInformationHash)
    : IComparable<DeviceKey>;                                     // 33-byte section key; kind byte = proto DeviceKind
public readonly record struct BallotLocator(DeviceKey Device, long Position) : IComparable<BallotLocator>;
public readonly record struct SectionKey(RecordSectionType Type, ReadOnlyMemory<byte> Key) : IComparable<SectionKey>;

/// One stored item: its canonical RecordItem bytes and its position. The leaf hash is over Bytes.
public readonly record struct RecordItemBytes(ReadOnlyMemory<byte> Bytes, long Ordinal);

// ---- canonical profile ---------------------------------------------------------------------------------------
public static class CanonicalProtobuf                             // implemented in S10b-3
{
    /// Method B (§4.4); on a rejection Method A names the rule. For a newer minor, Method B keeping unknown fields
    /// and then Method A's W6 branch.
    public static CanonicalCheck Check(ReadOnlySpan<byte> item, ushort recordFormatMinor);
    public static CanonicalCheck CheckSegmentHeader(ReadOnlySpan<byte> header, ushort recordFormatMinor);   // D6
    public static CanonicalCheck CheckSignedStatement(ReadOnlySpan<byte> item, ushort recordFormatMinor);   // §4.9
}
public readonly record struct CanonicalCheck(bool IsCanonical, string? Rule /* "W4", "D1", ... */, bool HasUnknownContent,
    string? Message = null);

// Mappers (internal, S10b-4; RecordFormat/Mappers): SetupMapper, BallotMapper (regular and cast pre-encrypted),
// DeviceMapper (DeviceChainRecord = DeviceHeader + DeviceClose; locators), UncastMapper (Split/Join, compact iff ξ_B
// is released, R-1), TallyMapper (EncryptedTally + header, DecryptedTally), DecryptionMapper (ContestDataRequest,
// ContestDataDecryption, ChallengedBallotDecryption), joined to string ballot ids by RecordBallotIndex. They decode
// raw Z_p/Z_q bytes and return RecordDecoded<T> (the object, or the §4.8 range findings) instead of throwing.
public readonly record struct RawZp(ReadOnlyMemory<byte> Bytes) { public bool TryToModP(out IntegerModP value); }
public readonly record struct RawZq(ReadOnlyMemory<byte> Bytes) { public bool TryToModQ(out IntegerModQ value); }

// ---- Merkle (RFC 9162) ---------------------------------------------------------------------------------------
public sealed class MerkleFrontier                                // O(log n) state; serializable for checkpoints (S10b-5)
{
    public static Sha256Digest LeafHash(ReadOnlySpan<byte> canonicalItem);
    public void Append(ReadOnlySpan<byte> canonicalItem);
    public void AppendLeafHash(in Sha256Digest leaf);              // workers hash; the sequencer appends
    public long Count { get; }
    public Sha256Digest Root();
    public byte[] Serialize(); public static MerkleFrontier Deserialize(ReadOnlySpan<byte> state);
}
public static class MerkleTree { EmptyRoot; LeafHash; NodeHash; Root(IEnumerable<Sha256Digest>) }
public static class MerkleProofs
{
    public static IReadOnlyList<Sha256Digest> InclusionProof(IReadOnlyList<Sha256Digest> leafHashes, long index);
    public static IReadOnlyList<Sha256Digest> ConsistencyProof(IReadOnlyList<Sha256Digest> leafHashes, long oldSize);
    public static bool VerifyInclusion(Sha256Digest leaf, long index, long size, Sha256Digest root, IReadOnlyList<Sha256Digest> path);
    public static bool VerifyConsistency(long oldSize, Sha256Digest oldRoot, long newSize, Sha256Digest newRoot, IReadOnlyList<Sha256Digest> proof);
}
public sealed record TocEntry(RecordSectionType Type, ReadOnlySpan<byte> Key, bool Critical, long ItemCount, Sha256Digest Root)
{
    public byte[] ToRecordItemBytes(); public Sha256Digest LeafHash();     // key compared by content
}
public sealed class TableOfContents(IEnumerable<TocEntry> entries)  // refuses a non-canonical order or a repeat
{
    public RecordPhase Phase { get; }
    public Sha256Digest Root { get; }
    public Sha256Digest PhaseRoot(RecordPhase phase);
    public bool Extends(TableOfContents earlier);                   // same entries for every phase up to earlier's
    public IReadOnlyList<Sha256Digest> ConsistencyProof(TableOfContents earlier);
}
public static class RecordDigests { ConfirmationCodeLeafBytes; CodesRoot; SectionRoot }

// ---- items not already in the domain model ------------------------------------------------------------------
public sealed record DeviceHeader(DeviceChainBallotKind Kind, string DeviceId, VotingDeviceInformationHash DeviceInformationHash,
    ChainingMode ChainingMode, ConfirmationCode? InitialHash);
public sealed record DeviceClose(long BallotCount, ChainingField? ClosingChainingField, ConfirmationCode? ClosingHash,
    DateTimeOffset? ClosedAt);
public sealed record ContestDataRequest(BallotLocator Ballot, SelectionEncryptionIdentifierHash IdentifierHash, int ContestIndex);
public sealed record EncryptedTallyHeader(long CastBallotCount, long TotalCastWeight);   // EncryptedTally.TotalCastWeight is new (S10b-4)
// §3.7 bullet 1's election facts are Manifest.ElectionName, ElectionDate, ElectionType, Jurisdiction, Location (NQ-4).

public sealed record RecordSetup(RecordFormatVersion Format, CryptographicParameters Parameters, GuardianParameters GuardianParameters,
    ParameterBaseHash ParameterBaseHash, ManifestFile ManifestFile, string ManifestMediaType, ElectionBaseHash ElectionBaseHash,
    IReadOnlyList<GuardianPublicView> Guardians, ElectionPublicKeys Keys, ExtendedBaseHash ExtendedBaseHash)
{
    public EncryptionRecord ToEncryptionRecord();                  // Manifest parsed from ManifestFile (S10a); keys via FromKeys
    public GuardianRecord ToGuardianRecord();
    public static RecordSetup FromEncryptionRecord(EncryptionRecord record);
    public static RecordSetup FromGuardianRecord(GuardianRecord record, ExtendedBaseHash extendedBaseHash);  // the keys item carries H_E
}

// ---- reading -------------------------------------------------------------------------------------------------
public interface IElectionRecordReader : IAsyncDisposable
{
    RecordEncoding Encoding { get; }
    RecordCarrier Carrier { get; }
    bool IsSeekable { get; }
    TableOfContents? ClaimedToc { get; }                          // as stored; recomputed, never trusted
    ValueTask<RecordSetup> ReadSetupAsync(CancellationToken ct = default);
    IReadOnlyList<DeviceKey> Devices { get; }                     // includes live sections without a close
    IDeviceSectionReader OpenDevice(DeviceKey device, long fromPosition = 1);
    IAsyncEnumerable<RecordItemBytes> ReadSectionAsync(SectionKey section, long fromOrdinal = 0, CancellationToken ct = default);
    IAsyncEnumerable<RecordItemBytes> ReadSectionFromAsync(SectionKey section, BallotLocator from, CancellationToken ct = default);
}
public interface IDeviceSectionReader : IAsyncDisposable
{
    DeviceKey Key { get; }
    ValueTask<DeviceHeader> ReadHeaderAsync(CancellationToken ct = default);
    IAsyncEnumerable<RecordItemBytes> ReadEntriesAsync(CancellationToken ct = default);   // chain order
    ValueTask<DeviceClose?> ReadCloseAsync(CancellationToken ct = default);               // null while live
}
public static class ElectionRecord
{
    public static ValueTask<IElectionRecordReader> OpenAsync(string path, CancellationToken ct = default);          // directory or .zip, either encoding
    public static ValueTask<IElectionRecordReader> OpenAsync(Stream zip, string? spoolDirectory = null,
        CancellationToken ct = default);                           // a non-seekable stream is spooled to disk first (§5.4)
    public static ValueTask<ElectionRecordWriter> CreateAsync(string directory, RecordEncoding encoding, CancellationToken ct = default);
    public static ValueTask<ElectionRecordWriter> ResumeAsync(string directory, CancellationToken ct = default);    // repairs a torn tail
    public static ValueTask<TableOfContents> ConvertAsync(IElectionRecordReader source, string destination,
        RecordEncoding encoding, RecordCarrier carrier, int maxDegreeOfParallelism = -1, CancellationToken ct = default);
    public static ValueTask<TableOfContents> ComputeTocAsync(IElectionRecordReader source, int maxDegreeOfParallelism = -1,
        CancellationToken ct = default);
    public static IAsyncEnumerable<RecordDifference> DiffAsync(IElectionRecordReader a, IElectionRecordReader b, CancellationToken ct = default);
}

// ---- writing (phase-gated) -----------------------------------------------------------------------------------
public sealed class ElectionRecordWriter : IAsyncDisposable
{
    public ValueTask WriteSetupAsync(EncryptionRecord encryptionRecord, IReadOnlyList<GuardianPublicView> guardians,
        CancellationToken ct = default);                                                  // parses the manifest bytes first; fixes R_setup
    public ValueTask<DeviceSectionWriter> OpenDeviceAsync(DeviceHeader header, CancellationToken ct = default);   // create or resume
    public ValueTask AddDevicePartAsync(string devicePartDirectory, CancellationToken ct = default);  // validates, copies bytes
    public ValueTask AddAttestationAsync(SignedStatement attestation, CancellationToken ct = default);
    public ValueTask<TableOfContents> SealVotingAsync(CancellationToken ct = default);          // all devices closed -> R_sealed
    public ValueTask<TableOfContents> SealAggregatedAsync(EncryptedTally tally,
        IEnumerable<ContestDataRequest> requests, CancellationToken ct = default);             // -> R_aggregated
    public ISortedSectionWriter<DecryptedChallengedBallot> ChallengedDecryptions { get; }   // throw before R_aggregated (Q36)
    public ISortedSectionWriter<DecryptedContestData> ContestDataDecryptions { get; }
    public ISortedSectionWriter<PreEncryptedUncastBallot> UncastNonceReleases { get; }      // must match the sealed item and its form (NQ-2)
    public ValueTask<TableOfContents> CompleteAsync(DecryptedTally tally, CancellationToken ct = default); // -> R_final
    public ValueTask AddRecordSignatureAsync(SignedStatement signature, CancellationToken ct = default);   // any time after its phase
}
public sealed class DeviceSectionWriter : IAsyncDisposable                    // also usable standalone on a device
{
    public DeviceKey Key { get; }
    public long Count { get; }
    public ConfirmationCode? LastConfirmationCode { get; }        // resumes DeviceChain after a restart
    /// Requires: kind matches, B_C continues the chain (simple chaining), BallotStructure valid, and a final status
    /// (Cast, Challenged or Spoiled; Unrecorded is refused). Items are appended once, in chain order, so a device
    /// records an abandoned ballot as Spoiled before appending the next one. Does not run V6/V7.
    public ValueTask AppendAsync(EncryptedBallot ballot, CancellationToken ct = default);
    /// A pre-encrypted ballot that was not cast (#5). NeverReturned and ReturnedBallotNonceReleased are written in the
    /// compact form (NQ-2: mandatory for never-returned ballots; ξ_B is then released), ReturnedNoncesReleased in full.
    public ValueTask AppendUncastAsync(PreEncryptedBallot printed, UncastDisposition disposition, CancellationToken ct = default);
    public ValueTask FlushAsync(bool durable, CancellationToken ct = default);
    public byte[] PrefixCheckpointStatement(ExtendedBaseHash he, DateTimeOffset at);
    public ValueTask<DeviceSeal> CloseAsync(DeviceChainRecord closing, CancellationToken ct = default);  // from DeviceChain.Close
}
public sealed record DeviceSeal(DeviceKey Key, long ItemCount, Sha256Digest SectionRoot, Sha256Digest CodesRoot)
{
    public byte[] ChainCloseStatement(ExtendedBaseHash he, DateTimeOffset closedAt);   // canonical RecordItem bytes to sign
    public byte[] SectionSealStatement(ExtendedBaseHash he);
}
public interface ISortedSectionWriter<T> { ValueTask AddAsync(T item, CancellationToken ct = default); }  // sorts and spills into locator order
public enum UncastDisposition { NeverReturned, ReturnedBallotNonceReleased, ReturnedNoncesReleased }

// ---- signatures ----------------------------------------------------------------------------------------------
public sealed record SignedStatement(ReadOnlyMemory<byte> Statement, string Algorithm, ReadOnlyMemory<byte> KeyId,
    ReadOnlyMemory<byte> SignerKey, ReadOnlyMemory<byte> Signature, ReadOnlyMemory<byte> TimestampToken);
public interface IStatementSigner { string Algorithm { get; } ValueTask<SignedStatement> SignAsync(ReadOnlyMemory<byte> statement, CancellationToken ct = default); }
public interface ISignatureVerifier { string Algorithm { get; } SignatureCheck Verify(SignedStatement signed); }   // EcdsaP256Sha256 ships first
```

(`PreEncryptedCastBallot` items are appended through `AppendAsync(EncryptedBallot)`, since a cast pre-encrypted
ballot is an `EncryptedBallot` with `PreEncryptedContests`, S9.)

**As built (S10b-C, the carriers; differences from the sketch above).**

- Record-level failures are `VerificationFailedException` with the R-code as `SubSection` (`RecordCodes`), as
  `VerifySummary`'s `R.summary` already was, so every failure reads the same way.
- `RecordItemBytes(Bytes, Ordinal, Check)` carries the item's `CanonicalCheck`: a reader hands on a non-canonical
  protobuf item with the bytes as read (§4.8 layer 1), and its consumer decides. Framing, layout and segment-header
  failures throw `R.container` at once. A JSON line that does not parse throws `R.encoding`, since it has no bytes to
  digest.
- `IElectionRecordReader` also exposes `Format`, `Phase`, `Sections` and `ReadSignaturesAsync`. `IsSeekable` is gone:
  every input is seekable, because a non-seekable stream is spooled. `ReadSectionFromAsync(locator)` (join cursors)
  is S10b-8's. `IDeviceSectionReader` is not disposable: it holds nothing between calls.
- `ElectionRecord.Create` (synchronous) and `ResumeAsync`, `ComputeTocAsync`, and `CheckClaimedTocAsync` (recompute,
  compare with the claimed TOC entry by entry: `R.root`). `ConvertAsync(..., deflateJson, segmentSizeBytes)` streams
  section by section. It is sequential; `maxDegreeOfParallelism` is kept for the shape. It takes only a reader that
  `OpenAsync` returned: the files outside every root (signatures, `meta.json`, the manifest copy) are not on
  `IElectionRecordReader`, so another implementation is refused (`ArgumentException`) rather than converted without
  them (S10b-C review round 3; S10b-11 may put them on the interface).
- Writer: `WriteSetupAsync(EncryptionRecord | RecordSetup)`; `OpenDeviceAsync(deviceId, kind)` computes the header
  (or `OpenDeviceAsync(DeviceHeader)`, checked against eq. 72/119, the manifest's mode and eq. 74/117). The final-phase
  items go through `AddChallengedDecryptionAsync(ballot, decrypted)`, `AddContestDataDecryptionAsync(ballot,
  decrypted)` and `AddUncastReleaseAsync(uncast)`, not `ISortedSectionWriter` properties: the writer locates the
  ballot by H_I in its own index (`Locate(H_I)`; about 100 B per ballot) and sorts through a spilling external sort.
  They may be called concurrently: they and `CompleteAsync` take turns through one gate (S10b-C review round 3).
  `CompleteAsync` refuses while a challenged ballot, an uncast ballot or a request lacks its item (#8, #5, #10), and,
  as a backstop, when a join section's spool does not hold one item per mark.
- `DeviceSectionWriter.AppendAsync`/`AppendUncastAsync` return the ballot's `BallotLocator`. `CloseAsync(closedAt)`
  computes B̄_C and H̄ itself; `CloseAsync(DeviceChainRecord, closedAt)` checks `DeviceChain.Close`'s record against
  the section (codes root included). A device that appended nothing has its section removed, and `CloseAsync`
  returns null (Q25).
- Not built here: `AddDevicePartAsync` and vendor sections in the writer (the reader reads them). `AddAttestationAsync`,
  `AddRecordSignatureAsync`, the prefix checkpoint statement and the `DeviceSeal` statement builders came with S10b-D
  (below).

```csharp
namespace ElectionGuard.Core.Verify;

public enum VerificationProfile { Full, GuardianPreliminary, BallotCorrectness, Custom }
public enum SignaturePolicy { Ignore, Report, RequireValid }
public enum VerificationOutcome { Passed, Failed, NotApplicable, NotEvaluable, NotRun }

public sealed record VerifyAllOptions
{
    public VerificationProfile Profile { get; init; } = VerificationProfile.Full;
    public IReadOnlySet<int>? Verifications { get; init; }                    // Custom: subset of 1..19
    public IReadOnlyCollection<BallotLocator>? Ballots { get; init; }          // BallotCorrectness
    public int MaxDegreeOfParallelism { get; init; } = -1;                    // passed through everywhere
    public long UniquenessMemoryBudgetBytes { get; init; } = 256L << 20;      // V5.A, then spill
    public string? TempDirectory { get; init; }
    public string? CheckpointPath { get; init; }                              // resumable when set
    public TimeSpan CheckpointInterval { get; init; } = TimeSpan.FromMinutes(5);
    public bool StopOnFirstFailure { get; init; }                             // default: collect
    public int MaxFindings { get; init; } = 10_000;
    public SignaturePolicy SignaturePolicy { get; init; } = SignaturePolicy.Report;
    public IReadOnlyList<ISignatureVerifier> SignatureVerifiers { get; init; } = [];
    public Sha256Digest? ExpectedSetupRoot { get; init; }
    public Sha256Digest? ExpectedSealedRoot { get; init; }
    public Sha256Digest? ExpectedAggregatedRoot { get; init; }
}

public sealed record VerificationFinding(string SubSection, int Verification /* 0 = R.* */, RecordSectionType? Section,
    BallotLocator? Locator, string? SelectionEncryptionIdentifierHex, int? ContestIndex, int? FieldIndex, string Message);

public sealed record VerificationReport(
    bool Passed,                                          // no failures AND Complete
    bool Complete,                                        // false if anything was skipped as not understood
    RecordPhase Phase,
    IReadOnlyDictionary<RecordPhase, Sha256Digest> PhaseRoots, bool RootsMatchClaimedToc,
    IReadOnlyDictionary<int, VerificationOutcome> Verifications,     // 1..19
    IReadOnlyList<VerificationFinding> Findings, bool Truncated,
    IReadOnlyList<AttestationResult> Attestations, IReadOnlyList<SignatureCheck> Signatures,
    IReadOnlyList<string> SkippedUnknownContent, RecordStatistics Statistics);

/// Exists only when a GuardianPreliminary or Full run passed V1-V9 on an aggregated record; carries its
/// R_aggregated and the EncryptedTally it verified. TallyAdmin.Decrypt gains an overload that takes it.
public sealed class VerifiedAggregate { /* no public constructor */ }

public static class ElectionRecordVerifier
{
    public static Task<VerificationReport> VerifyAllAsync(IElectionRecordReader record, VerifyAllOptions? options = null,
        IProgress<VerificationProgress>? progress = null, CancellationToken ct = default);
    public static Task<(VerificationReport Report, VerifiedAggregate? Aggregate)> VerifyAggregatedAsync(
        IElectionRecordReader record, VerifyAllOptions options, CancellationToken ct = default);
}
```

**As built (S10b-D: S10b-8, S10b-9, S10b-11; differences from the sketch and from §6).**

- **One stream of device items, single join cursors.** The device pass reads the device sections in canonical order
  as one stream and cuts it into batches (`VerifyAllOptions.BatchBytes`, default 64 MiB, at least one item, and at
  most max(64, 4 × workers) items). Each batch runs a sequencer (framing, canonicality, kind, the `DeviceChainWalker`,
  5.A's keyed prefix, prefix checkpoints, and the join items at each ballot's locator), then the workers in parallel
  (leaf hash, decode, per-item verifications with the joined decryption or release, the V9 fold into pooled
  recounts), then the sequencer again (leaves into the section frontier; at a device's close its root and its
  attestations). Parallelism therefore spans devices, a single central-count section included, and each join section
  is read once, sequentially, by one `JoinCursor` (§6.3's single-threaded join): no step-C pre-scan and no run
  offsets, since nothing reads a join section from the middle. A cursor checks the order as it reads (`R.order`; a
  repeated key, an item without a locator or of another member, and a stray are the section's structure code).
- **Findings** are `VerificationFinding(SubSection, Verification, Section, Ordinal, Locator, IdB hex, Message)`: the
  section key and the item's ordinal in it instead of a contest and field index (the message names those). Each is
  reported once; a decode finding is reported from the item whatever its owner does, and the verifications that would
  read the item are not evaluable on it. Join-rule findings name the join item (the ballot's own item when an item is
  missing). The order is step, section (setup-level first), ordinal, verification, sub-section, message; a report is
  equal across parallelism, resumption and the four representations (tests compare all but `Elapsed`).
- **Per-ballot Verification 16 on the record path** is given H_DI as computed from S_device and the previous code the
  ballot's own B_C states, so it reports 16.A-16.C and the device walk alone reports 16.D-16.H (once per device, not
  once per ballot).
- **Uncast ballots before their release** (a guardian run of the aggregated prefix) get 5.B and the device walk
  (16.D-16.H: V16 is in the guardian profile, review round 1), and are listed in `UncastBallotsToRelease`. A full
  uncast item carries every vector, ψ, χ, short code and label, so its 6.A, 16.A-16.C, 17 and 19 are checked on the
  printed item at once (review round 2: spec p.64 asks V6 "for all selection encryptions on all ballots, including
  ... pre-encrypted ballots" and p.65 V16 "for each pre-encrypted ballot"); only its 18 waits for the release and is
  `NotEvaluable`. A compact item has no vectors until its ξ_B is released, so 6, 16 (for 16.A-16.B) and 17-19 are
  `NotEvaluable` on it: a verification is never `Passed` while an item it applies to was deferred (NQ-10). Its 16.C
  needs no ξ_B (spec p.65: H_C = H(H_I; 0x42, χ_1, ..., χ_mB, B_C), every input printed on the item), so it runs at once
  after a structure check (the style's contest indices, ascending, each once; 16.structure), with 16.D-16.F as for any
  ballot (review round 3); a mismatch is 16.C at the item and makes V16 `Failed`. In a final record an uncast
  ballot without a release fails 18.structure, and a full one is still checked from its printed content.
- **Checkpoints** are written between batches (every `CheckpointInterval`), never mid-batch, as JSON next to a
  `<checkpoint>.5a/` directory of 5.A runs. A resumed run redoes steps A-C (cheap, deterministic, the findings
  deduplicated) and continues the device pass; a checkpoint whose record (claimed TOC root, phase) or options
  (profile, verifications, cap, policy, expected roots, and each signature verifier's trust anchors,
  `ISignatureVerifier.TrustAnchorsIdentity`) differ, or whose 5.A runs are gone, or which does not parse, is deleted.
  A record without a claimed TOC is never checkpointed (review round 2: the resumed run does not re-read its verified
  prefix, and nothing but the TOC root binds that prefix to the bytes on disk). The guardians'
  published-ballot view is not in the checkpoint (it is O(cast + spoiled), with C_0): `VerifyAggregatedAsync` builds
  it by a second read of the device sections once the run passed, digesting each section and requiring the root and
  count the run verified; a section that differs is `R.root`, the report fails and no aggregate is returned (Q31, Q36).
- **Faults a publisher controls never throw.** A carrier or line failure in a join section (`R.container`,
  `R.encoding`) is reported at the section, which then has no root (`R.root` against the claimed TOC); the ballots
  joined after it have their join items unknown, so a missing decryption, request or release there is not evaluable,
  not a structure finding. 5.A's confirmation pass offers only 32-byte identifiers and stops at a section's read
  failure, exactly as the device pass added them. The signature files are read one at a time. A regular ballot whose
  status is an enum value of a newer minor is `R.version` at the item, with V9 (and V12-V14 where they would read
  the status) not evaluable (§7 "Enum value").
- **Profiles.** `Full` on a record before the final phase verifies what exists and reports `R.structure` (the profile's
  input phase); `GuardianPreliminary` (V1-V9, 15 and 16) reads only sections of phases up to aggregated (a final
  record's aggregated prefix verifies the same way) and its request-rule findings are reported under `12.structure`,
  failing the run, while Verification 12 itself stays `NotRun` (a finding under a verification outside the profile
  never changes its outcome);
  `BallotCorrectness` reads only the chosen ballots' device sections and the join sections, compares only those
  sections' roots, and gives each chosen ballot RFC 9162 inclusion proofs to the claimed root (`BallotInclusion`).
- **Vendor sections** are digested and counted (`RecordStatistics.VendorSections`); they do not make `Complete` false
  (a known mechanism, never verified; question NQ-8, §12). A vendor section whose claimed TOC entry is critical is
  `R.version`.
- **Statements and signatures.** `RecordStatements.ChainClose/SectionSeal/PrefixCheckpoint/Record` build the canonical
  statement bytes; `DeviceSeal` (now also carrying S_device, the mode, H̄ and the close time) gives a device's chain
  close and section seal, `DeviceSectionWriter.PrefixCheckpointStatement` a prefix checkpoint. `SignedStatement`,
  `IStatementSigner`, `ISignatureVerifier`, `SignatureAlgorithms` (key id = SHA-256 of the DER
  SubjectPublicKeyInfo) and `EcdsaP256Sha256Signer`/`EcdsaP256Sha256Verifier` (DER signatures; every key checked to be
  on P-256) are in `ElectionGuard.Core.RecordFormat`. The writer's `AddAttestationAsync` (until the voting seal; kept
  in memory, so added again after a resume) checks the item's canonicality and statement type, H_E and the device; a
  device that then closes with no ballots has no section (Q25), so its attestations are dropped (review round 3).
  `AddRecordSignatureAsync` checks the statement names a root the writer fixed, H_E and this format version, and
  writes `signatures/<phase>-<SHA-256(statement)>` (a second signer of the same statement joins the file; the
  read-merge-replace is serialized per writer, and writers in different processes must coordinate). A
  verifier holds trust anchors (an `ISignatureVerifier` per algorithm, with the keys it accepts); a key carried in
  the statement is never trusted by itself. Statement contents are checked whatever the policy (`R.attestation`:
  H_E, device key, S_device, mode, ℓ, codes_root, H̄; ℓ + 2 and the section root; a prefix's codes root;
  `R.signature`: the phase root, H_E, the major). `SignaturePolicy.Report` lists every check
  (`SignatureStatus.Valid/Invalid/NotChecked/Ignored`) and the recommended chain close's absence
  (`AttestationResult.Present = false`); `RequireValid` fails a device without a validly signed, matching chain close,
  a record without a valid signature over its phase root, and any signature not valid; `Ignore` checks none.
- **`VerifiedAggregate`** carries the `EncryptionRecord`, the verified `EncryptedTally`, R_aggregated and the published
  cast and spoiled ballots; `TallyAdmin.Decrypt(guardians, VerifiedAggregate, maxDegreeOfParallelism)` is the overload
  for a tally read from a record. It is returned only when the run passed and Verification 9 passed (not merely did
  not fail).
- **Merge.** `BallotAggregationVerifier.ExportStandardForm()` gives a `BallotAggregationPartial` (counts, faulted, per
  contest the cast weight and per field b(A, 512), b(B, 512)); `ImportStandardForm` and `Merge(partial | verifier)`
  multiply it in (a faulted operand faults the result; a partial over another manifest is refused).

### 8.4 What is reused and what is new

- **Reused unchanged**, through `RecordSetup.ToEncryptionRecord()`: the per-ballot classes (V5.B, V6, V7, V8 per
  ballot, V12-V19), `TallyDecryptionVerification`, `TallyContentsVerification` (fed the 11.D bitset mapped to labels)
  and `ParameterVerification`/V2-V4. Each throws `VerificationFailedException`; the orchestrator catches per item and
  attributes the finding.
- **New in existing namespaces:**
  - `Verify.DeviceChainWalker`: the incremental, O(1) form of `DeviceChainWalk`, with `Begin(header)`, `Next(link)`
    and `End(close)`, and the same scheme, sub-sections and messages. `VerifyDevice(s)` keep their signatures and are
    reimplemented on it.
  - `SpillingIdentifierSet` (§6.5), behind `SelectionEncryptionIdentifierSet`'s 5.A message.
  - `BallotAggregationVerifier.Merge`, plus `ExportStandardForm()`/`ImportStandardForm()` for checkpoints and shards.
  - `BallotStatus.Spoiled`, and `Unrecorded` as the new name of the in-memory zero value (S10b-1, done).
  - The manifest's optional election facts and its tolerance of unknown properties (S10b-1b, done).

### 8.5 How the consumers use it

- **egperf.** Two optional scenario phases. `writeRecord` assigns the streamed ballots to `deviceCount` simulated
  devices, appends each chunk through one `DeviceSectionWriter` per device, closes the chains with chain-close
  statements, writes the tally sections and seals each phase; the encoding and carrier come from scenario JSON.
  `verifyRecord` runs `VerifyAllAsync` from disk with `--parallelism` passed through. Both add bytes per ballot,
  MB/s, ballots/s, peak working set and `PhaseRoots` to the JSONL line. The existing serialization phase moves from
  `IEncryptedBallotSerializer` to the `RecordItem` codec. A `profile`/`verifications` setting lets a huge
  structure-only run skip V6/V7.
- **Console (`Program.cs`).** Writes the canonical pipeline's record twice, as a protobuf directory and as a JSON
  `.zip`, asserts that `ComputeTocAsync` gives equal roots for both, and runs `VerifyAllAsync` on each. Then it flips
  one ballot's status and shows the root mismatch and the `R.root` finding.
- **`ElectionGuard.Testing.Cli`** emits records in both encodings; `test/data/*` fixtures are regenerated in the new
  format.

---

## 9. Implementation plan

### 9.1 Ordering and gate

S10a is committed (c4f1093). The design is approved and NQ-1 to NQ-6 are answered (§11). Stage S10b-A implemented
S10b-0, S10b-1, S10b-1b and S10b-2 (2026-10-09). NQ-1 and NQ-4 shaped the schema (S10b-2) and the manifest
(S10b-1b), NQ-2 shapes the uncast mapper and writer (S10b-4, S10b-6), NQ-3 deferred S10b-13, NQ-6 is S10b-7's
spooling, and NQ-5 is S10b-19, after S10b. Every step
below is sized for one implementer and is one reviewable commit with the gate green: the full test suite, the KAT
families unchanged, and for steps that touch verification or serialization a perf smoke run plus
`compare --repeat 5` against a HEAD worktree baseline (single cold runs false-flag the allocation gate). Each step
updates the tracker.

### 9.2 Steps

| Step | Content | Tests |
|---|---|---|
| **S10b-0** Nonce hazard (first; independent). **Done (S10b-A).** | Delete `EncryptionNonce` from `ProtobufEncryptedValueWithProofs` and `ProtobufEncryptedValue` **and the line-83 copy** into the DTO | A reflection test that no serialization DTO has a nonce member; protobuf round trips unchanged |
| **S10b-1** Ballot status. **Done (S10b-A).** | `BallotStatus.NotSubmitted` → `Unrecorded` (0); add `Spoiled = 3`. `RecordStatus` accepts Cast, Challenged or Spoiled, once. `EncryptedTally.AddBallot` skips Spoiled as it skips Challenged (and still rejects Unrecorded). The guardians' nonce path and V13/V14 treat Spoiled as not challenged. The existing ballot serializers carry the new value until they retire. | Aggregation excludes spoiled ballots; a spoiled ballot's nonce request is refused; `RecordStatus` is once-only across all three; V5-V8 accept a spoiled ballot; serializer round trips of each status |
| **S10b-1b** Manifest (NQ-1, NQ-4). **Done (S10b-A).** | Optional `ElectionName`, `ElectionDate`, `ElectionType`, `Jurisdiction`, `Location` on `Manifest` (strings, informational, omitted from the written form when null); `ManifestSerializer` ignores unknown properties at every level (near-miss names too since S10b-B, R-3), and keeps refusing duplicate keys, malformed JSON, wrong types and missing required members | Unknown properties at every level parse to the manifest without them while H_B differs; near misses are ignored like any unknown property (S10b-B); duplicate unknown keys and wrong types refused; the election facts round-trip and are absent from a manifest that does not set them |
| **S10b-2** Schema and codegen. **Done (S10b-A).** | Move `egrf_v2.proto` to `proto/electionguard/egrf/v2/egrf.proto` (with the NQ-1 outcome); Google.Protobuf and Grpc.Tools in Core, generated types internal; a schema lint test enforcing S1-S8 on the compiled descriptor; a test that writes `test/egrf/schema.json` (numbers, types, labels, width options, reserved numbers) and checks every schema change against it for S6 | The lint test fails on a deliberately added map, `int32`, packed repeated scalar, out-of-order declaration, unannotated fixed-width field or regular field numbered inside a oneof's range (run against fixture descriptors); the append-only check fails on a removed, renumbered or retyped field, a field added below the highest number, and a dropped reservation; C# Google.Protobuf's unknown-field behaviour (§4.4) is pinned |
| **S10b-3** Canonicality checker. **Done (S10b-B).** | `CanonicalProtobuf.Check`: Method B (parse keeping unknown fields, D1-D6, re-serialize, compare; a discard-unknown parse when the record's minor is not newer than the library's) and Method A (descriptor-driven wire walk, with W6's unknown-field rule for newer-minor records); the `SegmentHeader` check (D6) and the signed-statement check (§4.9); the first golden item vectors and every negative vector of §5.7 under `test/egrf/vectors/` (regenerated from the current schema in S10b-B: the feasibility run's `vectors.json` and `negatives.json` were built against the draft schema, so only their rule list was kept) | Each negative vector rejected with its rule by both methods; the newer-minor vectors accepted with their unknown content reported, and re-encoded to the same bytes; property tests: encode-then-check always passes; every single-byte mutation of a golden item is rejected or decodes to a different item, and Methods A and B never disagree |
| **S10b-4** Domain mappers. **Done (S10b-B).** | One mapper per item type; `RawZp`/`RawZq` and the §4.8 range table, fixed against the Verify classes' lettering; the uncast split and join, with NQ-2's compact form (mandatory for never-returned ballots; the form follows from whether ξ_B is released); `RecordSetup` | A **reflection completeness test** pins every public property of every recorded domain type to a schema field or an explicit exclusion list (nonces, the device id taken from the section, computed properties), replacing the "add it in both" hazard; domain → bytes → domain is the identity; values ≥ p and ≥ q give the lettered codes |
| **S10b-5** Merkle, TOC, phase roots. **Done (S10b-B).** | `MerkleFrontier`, `MerkleProofs`, `Sha256Digest`, TOC and phase-root functions, `Extends` | RFC 9162 published vectors; MTH for n = 0..17 and 1,000; inclusion and consistency proofs; frontier serialize/resume equals an uninterrupted run |
| **S10b-6** Directory carrier: writer and reader. **Done (S10b-C).** | Delimited `.binpb` segments and `SegmentHeader`; the 64 MiB frame ceiling on both sides; the §5.3.1 layout and discovery rules; `ElectionRecordWriter` phase gates; `DeviceSectionWriter` (final status required, `AppendUncastAsync` with its `UncastDisposition`); `ResumeAsync` with torn-tail repair, zero-filled tails included; presence rules; the optional `setup/manifest.json` copy; as built, §8.3 "As built" | Write then read gives the same domain objects (S10a's strict round-trip tests ported); segment rollover does not change roots; a torn tail is repaired and a corrupt middle item refused; decryption and release writers throw before R_aggregated; R_setup ⊑ R_sealed ⊑ R_aggregated ⊑ R_final; a manifest copy that differs is `R.container`; the manifest bytes survive byte for byte (whitespace, member order, number spelling and vendor properties preserved), and a manifest the parser refuses (a BOM, a duplicate key) is refused by `WriteSetupAsync`; a never-returned uncast ballot is written compact whatever the caller passes, and a release of the wrong form is refused; an oversized item is refused by the writer and a hostile length by the reader before allocation; every §5.3.1 layout negative |
| **S10b-7** `.zip` carrier. **Done (S10b-C),** except the > 4 GiB entry (manual, not run) and the DEFLATEd join with sequential cursors (S10b-9 verifies; the reader already streams DEFLATEd entries). | `System.IO.Compression` writer (STORED protobuf entries, optional DEFLATE for JSON, ZIP64) and a seekable reader that checks every local header it reads against the central directory; a non-seekable `Stream` is spooled to disk (NQ-6) | Roots equal the directory's; any entry order is accepted; a duplicate entry, a local/central mismatch, an unlisted entry and a case-folding collision are each `R.container`; a DEFLATEd JSON record verifies with sequential join cursors; a > 4 GiB synthetic entry round-trips (manual or nightly) |
| **S10b-8** Streaming verifier pieces. **Done (S10b-D),** with the join cursors sequential (§8.3 "As built (S10b-D)"). | `DeviceChainWalker`; `SpillingIdentifierSet`; `BallotAggregationVerifier.Merge` and standard-form export; merge cursors with run offsets | The walker agrees with `DeviceChainWalk` on every existing V8/V16 test; 5.A with planted duplicates at random positions, **adversarially skewed id_B prefixes** and a 1 MiB budget forcing spills; AVX-512 and scalar partials merged through the standard form equal one engine (`DOTNET_EnableAVX512F=0`) |
| **S10b-9** `VerifyAllAsync`. **Done (S10b-D).** | Steps A-F, profiles, report, attestation-content checks, resumable checkpoint, `VerifiedAggregate` and the `TallyAdmin.Decrypt` overload (S10a carry-over) | One test per R-code and per join rule (a missing challenged decryption, a decryption naming a cast or spoiled ballot, a missing or stray uncast release, an unmatched contest-data request); spoiled ballots excluded from V9 and included in 5.A and 11.D; a never-returned uncast ballot (compact) passes V16 and V18 with its released ξ_B, is counted as an item whose 17.A and 19.A-D hold by construction (§3.2), and fails 16/18 when ξ_B regenerates a different χ or H_C; a spoiled ballot sharing id_B with a cast one fails 5.A (the record verifier collects every submitted ballot's id_B, whatever its status); a newer-minor record passes with `Complete = false` and its unknown content reported; V9 `NotEvaluable` after a faulted aggregator; kill-and-resume gives the same report as one run; GuardianPreliminary on an aggregated record; a run over a `.zip` given as a stream whose `Seek` throws (spooled, same report) |
| **S10b-10** JSON projection, converter, diff. **Done (S10b-C),** except identical `VerificationReport`s (S10b-9; the four representations have identical roots and no difference). | `JsonFormatter`/`JsonParser` plus duplicate-member refusal; `ConvertAsync`; `DiffAsync` | protobuf → JSON → protobuf is byte-identical; JSON → protobuf → JSON parses to the same structure (byte-identical only within one runtime, §5.5); the four representations of each golden record give identical roots and identical `VerificationReport`s, findings included; content with an unknown field is refused for conversion to JSON and copied unchanged protobuf to protobuf; JSON negatives: a duplicate member, a JSON-name/proto-name alias pair, two members of one oneof, an unknown member, a wrong decoded width, a `uint64` ≥ 2^63, negative `Timestamp` nanos, an undeclared enum name |
| **S10b-11** Attestations and signatures. **Done (S10b-D),** `ecdsa-p256-sha256` only. | Statements, `IStatementSigner`, `ISignatureVerifier` (`ecdsa-p256-sha256` first; others pluggable), policies | Statements signed and verified; a tampered count, codes root or status caught (`R.attestation`); dropping trailing ballots caught under both chaining modes when a chain close exists; a missing or invalid signature under each policy |
| **S10b-12** Python reference reader and golden records | `test/egrf/egrf_ref.py` (standard library; Method A with W6's unknown-field rule, D1-D6, delimited segments with the frame ceiling, the §5.3.1 layout rules, Merkle, phase roots, `.zip` via `zipfile` with the local-header check), the three complete golden records in all representations, the schema-table diff against `test/egrf/schema.json` | CI runs `python test/egrf/egrf_ref.py --check`: every golden root reproduced and every negative vector's verdict matched |
| **S10b-13** TypeScript reader. **Deferred (NQ-3: "Defer").** | `test/egrf/js/`: protobuf-es generated code (binary and the proto3 JSON mapping; not protobufjs, §5.5), Method B (with `readUnknownFields: false` for records of its own minor), D1-D6, `sizeDelimitedDecodeStream` with `readMaxBytes` set, Merkle roots | Reproduces the golden roots and negative verdicts in CI |
| **S10b-14** `ElectionGuard.Verifier` | New project; `egrecord verify | digest | convert | diff | prove | show` over the Core API | CLI tests on the golden records: exit codes, report output, `digest` equal across representations |
| **S10b-15** Migration of the consumers | `Program.cs` as in §8.5; egperf `writeRecord`/`verifyRecord` and the serialization phase on the item codec; `ElectionGuard.Testing.Cli` emits records; `test/data/*` regenerated | Console pipeline passes; perf smoke run and `compare --repeat 5` against a HEAD worktree baseline (allocation of the Google.Protobuf parse path checked here) |
| **S10b-16** Retire superseded code | Remove `ProtobufEncryptedBallotSerializer` and its `Protobuf*` DTO tree, the protobuf-net package, `IEncryptedBallotSerializer`, the JSON ballot serializer, `JsonElectionRecordSerializer` (**replaced** by the proto3 JSON projection; its per-object API has no use once records are read and written as a whole, and `egrecord show` prints any item as JSON), `JsonPreEncryptedBallotSerializer`, `JsonDeviceChainRecordSerializer`, `StrictBase64` and `EncryptedBallotShape` (folded into the mappers). `ManifestSerializer` stays as the manifest parser; its writer stays only as an authoring helper whose output has no canonical status. | No remaining reference; the full suite green; CLAUDE.md's Serialization bullet rewritten |
| **S10b-17** Live tailing (may be deferred) | `FollowLiveRecord`, prefix-checkpoint checking | Tail a record while a writer appends; a checkpoint mismatch is caught |
| **S10b-18** Documentation and publication | CLAUDE.md "Record" architecture bullet; a formal-spec skeleton generated from §4 and the `.proto`; register `width`, `width_multiple` and `omittable` in protobuf's global extension registry and replace the draft numbers 50001-50003 (a user action: it is a pull request to the protobuf project) | Review only; the lint test pins the registered numbers |
| **S10b-19** Guardians open uncast pre-encrypted ballots (NQ-5; after S10b, needs S10b-9) | `TallyGuardian.DecryptBallotNonce` (and the administrator's combine) also opens a pre-encrypted uncast item taken from a sealed record the guardian has verified (`VerifiedAggregate`, §6.9): it decrypts C_ξB as §3.6.7 does, and the administrator publishes the release (ξ_B for a compact item; the ξ_{i,j,k} by eq. 121 for a full one) only if it regenerates the item. It refuses any id_B, H_I or C_ξB,0 that matches a cast or spoiled ballot of that record (Q31; "Refuse spoiled too"). No issued list and no once-only state (Q35, Q36: guardians decrypt only after the record is sealed). | A never-returned ballot opened by k guardians gives a release that passes V16 and V18 (17.A and 19.A-D hold by construction on the compact item, §3.2); an id_B, H_I or C_ξB,0 that matches a spoiled ballot of the sealed record is refused as one matching a cast ballot is (decided 2026-10-09, "Refuse spoiled too"; the regular-ballot view does it since S10b-B); an id_B cast in the record is refused; a ballot not in the sealed record is refused; a wrong m_i is detected and nothing is published |

**No legacy importer.** v1's S10b-9 planned importers for today's JSON ballots, device chains and pre-encrypted
JSON. No election record has been published in those formats, and the fixtures are regenerated (S10b-15), so the
importer is dropped. That also settles the S10a carry-over about how it would treat unknown members.

**Step numbers the tracker cites from v1:** S10b-0a → S10b-0; S10b-6 (JSON negatives, duplicate member) → S10b-10;
S10b-9 (legacy importer) → dropped; S10b-12 (retire protobuf) → S10b-16.

### 9.3 Interaction with S10a

| S10a work | What S10b does with it |
|---|---|
| `ManifestSerializer` (strict reading, deterministic writing) | Parsing only on the record path (#19). Its reading rules, which since S10b-1b ignore unknown properties (NQ-1), are what `media_type` `...;format=1` names. H_B is over the stored bytes as entered, vendor properties included. The writer stays an authoring helper with no canonical status. |
| `EncryptionRecord.Manifest` parsed from `ManifestFile` | `RecordSetup.ToEncryptionRecord()` uses it. There is no second path from a record to a `Manifest`. |
| `EncryptionTimestamp` (nullable, ms, UTC; protobuf field 14) | Maps to `encrypted_at` (`Timestamp`, D3), same semantics. Field 14 retires with the DTO tree. |
| `JsonElectionRecordSerializer` | Replaced by the proto3 JSON projection (S10b-16). Its strict round-trip tests become templates for S10b-4 and S10b-6. |
| Range-strict decoding (`FromCanonicalBytes` throws for ≥ p or ≥ q) | The record mappers decode raw and attribute ranges (#11, §4.8). The domain serializers that throw retire. |
| `DecryptedTally`/`EncryptedTally` serializers, `CastWeight` | The record carries (A, B), `cast_weight` and (t, T, c ‖ v). `MaximumCount` stays computed. |
| `StrictJson`, `StrictBase64` | `StrictJson` keeps its duplicate-member refusal for JSON reading. `StrictBase64` retires: JSON bytes are never hashed (§5.5). |
| S10a's `BallotStructure` and aggregator changes | Used unchanged by the workers. 9.structure faults are reported as V9 `NotEvaluable`. |
| Carry-overs to S10b | The record bundle and verify-everything entry point (S10b-6 to S10b-9); duplicate-member refusal (S10b-10); a verified-tally API (S10b-9, `VerifiedAggregate`); device-close signing and timestamp, S8b (S10b-11). |

### 9.4 GB-scale test strategy

1. **Full-crypto scale run (nightly or manual, egperf).** About 1M real ballots, about 13 GB of protobuf. Generating
   them costs about 0.25 ms per ballot at 32 threads (a few minutes), and verifying them about 17 min at the measured
   rate. This checks throughput, peak working set and a resumed run against an uninterrupted one.
2. **Structure-only synthetic records at 10^7-10^8 items.** A generator emits valid items, random id_B with correct
   H_I, contest hashes over random ciphertext bytes, and correct chains (H_C, B_C, H_0, closes). The `Custom` profile
   runs 5, 8 and 16 plus integrity, skipping V6/V7. Assertions: peak working set at N and 4N differs only by the 5.A
   term; planted duplicate id_Bs are found with both locators; a skewed-prefix record stays within budget.
3. **Fault injection at scale:** a torn trailing frame; one flipped status byte (`R.root`, and `R.attestation` with a
   section seal); a spoiled ballot relabelled cast (caught by the section seal); a dropped final ballot plus a
   recomputed close (caught by chain close); a reordered pair under no chaining (caught by the codes root).
4. **Large items and spooling.** Uncast items near the 64 MiB ceiling, checking that the reader's byte bound holds
   peak working set to the §6.4 figure. A `.zip` of about 10^6 synthetic items given as a non-seekable stream,
   checking that it is spooled and verified with the same report.
5. **Cross-representation at scale.** Converting a 10^6-item record protobuf → JSON `.zip` → protobuf gives identical
   roots, with converter memory bounded because it streams per section.

---

## 10. Risks and trade-offs

1. **Canonicality rests on a profile, not on the protobuf library.** A runtime that serializes in another order, or
   writes kept unknown fields anywhere but after the known ones, would disagree under Method B, and no runtime checks
   the order or numbering of unknown fields (§4.4). Mitigations: Method A is normative and needs no runtime, the
   schema lint test keeps the `.proto` inside the profile and its changes append-only, the golden and negative
   vectors arbitrate between runtimes, and the Python reader proves the rules are complete.
2. **Packed fixed-width lists are less self-describing.** A proof list is one base64 string in JSON, not an array of
   (c, v) objects. The width options and comments say how to slice it. This is the price of #3's size priority (about
   1.4 % of a ballot).
3. **Uncast pre-encrypted ballots are expensive in full form** (§3.2, §4.7). NQ-2 makes the compact form mandatory
   for never-returned ballots, so only returned uncast ballots whose ξ_B stays secret pay the full cost.
4. **Device partitioning** puts grouping and print-order placement on whoever assembles the record. There is no
   global arrival order apart from `encrypted_at`. One huge device serializes only its cheap chain walk; decoding
   still runs in parallel.
5. **V5.A stays O(N).** It is 8 B per ballot, exact, and spills. 10^8 ballots need about 800 MB of temporary disk. A
   non-seekable input also needs disk equal to the record, because it is spooled (§5.4).
6. **Status, weight and timestamps are protected only by the root, signatures and section seals** (§6.6).
7. **Indices on encrypted ballots.** A ballot item is unreadable without the manifest. That is acceptable because the
   manifest is always in the record, and the tools print labels as a derived view.
8. **JSON is about 1.4 × protobuf and cannot carry unknown fields.** Distribute GB records as protobuf. A converter
   refuses to write content it does not understand as JSON rather than dropping it, and a JSON reader cannot verify a
   newer-minor record; the protobuf representation can (§7).
9. **Merkle subtleties.** RFC 9162's split rule and empty tree are easy to get wrong. They are pinned with published
   and own vectors.
10. **`EGParameters` is process-static.** VerifyAll checks V1 against it and never swaps it, so verifying records with
    different parameter sets in one process needs `OverrideScope` per record and no parallel records.
11. **Attestations depend on deployment** (device keys, a collector TSA). Without them, S8b's truncation protection
    rests on the administrators' signature only. The verifier reports it rather than failing, unless the policy says
    otherwise.
12. **Divergence from a future official record spec** (§3.7: "specified in a separate document"). The §3 content map
    carries over, and the format version and root-preserving converters bound the rework.
13. **Allocation on the Google.Protobuf parse path** (§8.1). Measured in S10b-15 against the perf gate.
14. **The frame ceiling refuses some pre-encrypted elections.** A multi-contest returned uncast ballot with about
    m ≥ 100 options per contest can exceed 64 MiB in full form (§4.7). The writer refuses it with a clear error.
    Releasing its ξ_B (Q28's opt-in) puts it in the compact form; a later minor that splits uncast items per contest
    would also lift the limit. Never-returned ballots are always compact (NQ-2).
16. **Newer-minor records verify incompletely by design** (NQ-1). An older verifier reports `Passed` with
    `Complete = false` when a record uses a later minor's fields. A later minor never changes the meaning of an
    existing check, so what the older verifier checked stays right, but whatever the new fields carry is unchecked.
    The report and `egrecord verify`'s exit code 2 say so; an official verification should use a verifier that knows
    the record's minor.
15. **The draft option numbers.** Until `width`, `width_multiple` and `omittable` have registered extension numbers
    (S10b-18), a descriptor pool that also loads another organization's 50001-50003 options could collide. The
    numbers change once, before publication. That changes no item bytes, because options are not on the wire.

---

## 11. Resolved decisions

From the tracker, Decisions, "S10b design answers, 2026-10-09" and "S10b follow-up answers, 2026-10-09". The v1
question numbers are kept so the tracker's references still resolve.

| # (v1 question) | User's answer | Applied in |
|---|---|---|
| #1 (Q-1) Canonical encoding | "Canonical encoding should be protobuf, not binary. ... JSON as a projection is fine as well." | §4 (profile), §5.5 (JSON), format major 2 |
| #2 (Q-2) Record digest hash | "Fine": SHA-256 with RFC 9162 Merkle framing | §4.9 |
| #3 (Q-3) Naming and size | "Optimize for size of the files when encoding the encryptions. Beyond that, use json and protobuf standards for naming" | §4.6 (fixed-width bytes, packed lists), §5.5 |
| #4 (Q-4) Ballots neither cast nor challenged | "NotSubmitted doesn't make sense. ... Anything not cast or challenged can probably be considered Spoiled." | §3.3, §4.5, §6.2, §8.3 (`Spoiled = 3`, `Unrecorded` in memory), S10b-1 |
| #5 (Q-5) Never-returned pre-encrypted ballots | "pre-encrypted ballots never returned can be considered challenged ballots" | §3.2 (uncast item plus release; stub removed), §6.2 |
| #6 (Q-6) Timestamps | Follow-up: "Full precision seems fine here. ... This isn't a real concern." | §4.3 D3, §4.6 (`Timestamp`, ms, no precision setting); the privacy-risk item is removed |
| #7 (Q-7) Attestations and signatures | "Sure": chain close recommended, section seal optional, `ecdsa-p256-sha256` mandatory, `Report` default with `RequireValid` for official runs | §4.9 |
| #8 (Q-8) Challenged ballot with no decryption | "Yes": v1 (now v2.0) requires a decryption for every challenged ballot | §6.2 join rules, extended to uncast releases |
| #9 (Q-9) Election info | Follow-up: "Only what isn't in manifest" | §3.1, §4.6; NQ-4 settled where: optional manifest fields, and a header with the format version only |
| #10 (Q-10) Contest-data decryption | Follow-up: "Record the requested set" | `ContestDataRequest`, §6.2 |
| #11 (Q-11) Out-of-range values | "Out of range values are a problem for a verifier, not the election record format." | §4.3, §4.8 |
| #12 (Q-12) String ballot id | Follow-up: "Keep, optional" | `ballot_ref`, §4.6 |
| #13 (Q-13) Protobuf | "binary seems like a nonstarter ... protobuf over json" | §4, §8.1; the old DTO tree retires (S10b-16) |
| #14 (Q-14) Archive | "If .7z would save significant space, we can consider that, else .zip is the way to go." Measured: it does not. | §5.4 |
| #15 (Q-15) Code placement | "Yes": Core plus `ElectionGuard.Verifier` | §8.2 |
| #16 (Q-16) Multiple tallies | "We will do multiple tallies but we can wait and add it later." | §4.5 (the election-wide tally now; later tallies as new section types in a new major, NQ-7) |
| #17 (Q-17) Tally header | "Sure" | `EncryptedTallyHeader` |
| #18 (Q-18) Derived views | Follow-up: "Alongside, not signed" | §5.6 |
| #19 (S10a-1) Manifest bytes | "it should be output to the election record exactly as it was entered. The canonical serialization for the manifest is not as important." | §4.6, §9.3 |
| Profile | Follow-up: "Yes, canonical protobuf": normative `.proto`, field-number order, no maps, no unknown fields, fixed-width bytes, re-serialize to check, proto3 JSON, golden vectors and a Python reader. "No unknown fields" is amended by NQ-1 | §4, §5.5, §5.7 |
| NQ-1 Per-item extensions | "Vendors should never add fields to most of the types. The manifest is really the only field I would ever expect a vendor to provide additional data, so honestly it's canonical form should probably be json. Protobuf tends to be backwards compatible by default, so we should be good with future versions already. I don't think we need anything special here." | No extension list (`RecordItem` 2047 reserved, §4.6). Unknown fields allowed only after every known field, ascending, append-only numbers, kept on re-encoding (S6, W6, §4.4); a newer minor is informational (§6.9, §7). The manifest stays JSON stored byte for byte; its reader ignores unknown properties and still refuses duplicate keys and malformed JSON (§4.6; S10b-1b) |
| NQ-2 Compact uncast form | "Compact required for unreturned" | `PreEncryptedCompactUncastBallot`; mandatory for never-returned ballots, and the form of any uncast ballot whose ξ_B is released (§3.2, §4.6, §6.2) |
| NQ-3 JavaScript conformance reader | "Defer" | S10b-13 deferred |
| NQ-4 Election facts | "Optional manifest fields" | `Manifest.ElectionName`/`ElectionDate`/`ElectionType`/`Jurisdiction`/`Location` (S10b-1b); `RecordHeader` = format version only (field 3 reserved) (§3.1, §4.6) |
| NQ-5 Opening uncast pre-encrypted ballots | "Later: guardian opens from sealed record" | S10b-19, after S10b (§1, §3.2, §6.9) |
| NQ-6 Pipe input | "Drop it" | A non-seekable input is spooled to a temporary file (§5.4, §6.3; S10b-7) |
| NQ-7 Where a later version's section kinds live | "Bump the major version" (2026-10-10) | A new section kind needs a new major; a v2 reader refuses an unknown one (`R.version`); no generic path; minors add only fields (§4.3 D2, §4.5, §5.3.1, §6.9, §7; S10b-D) |
| JSONL final line feed (S10b-C question) | "Optional" (2026-10-10) | jsonlines.org: the last line's line feed may be absent; a last line cut short fails its parse (`R.encoding`) (§5.5; S10b-D) |

Decided while applying review round 1 of S10b-A (no user decision needed; listed so it can be overruled): **oneof
members are messages (S8).** A set scalar member would be written as an explicit VARINT 0 (W2), which W6 tells an
older reader never to accept in an unknown field. Restricting oneof members to messages, which `RecordItem` already
satisfies, keeps W6's check and changes no bytes; the other fix, dropping W6's "unknown VARINT is not 0" clause, would
weaken the check for every record. The lint enforces it.

Changed after review: single-pass verification of a `.zip` from a pipe (v1's Q-14 sub-question) is dropped. It turned
out to cost much more than the prescribed entry order (§5.4), and NQ-6 confirmed the drop.

---

## 12. New questions

NQ-1 to NQ-6, asked in revision 2 with options and recommendations, are answered (2026-10-09). The answers are in
§11 and applied throughout; revision 2's option text is in the repository history. Applying them took three readings
that the answers did not spell out. The user answered them on 2026-10-09 (tracker, "S10b-A readings, answered
2026-10-09"): R-1 "Whenever ξ_B is released" and R-2 "Pass, flagged incomplete" keep what is written below; R-3
"Ignore them too" changed the manifest reader (S10b-B). The same answers settled the spoiled-ballot question
("Refuse spoiled too", §3.3). The readings as they were put:

- **R-1 (NQ-2) When the compact form applies.** "Compact required for unreturned" makes the compact item mandatory
  for never-returned ballots. Revision 2's option (b), which (c) extends, also allowed it for any uncast ballot whose
  ξ_B is released. This design makes the form a function of what is released, so that no ballot has two valid
  encodings: compact iff ξ_B is released (never-returned ballots always are), full iff it is not (§3.2). The
  alternative is "compact iff never returned", with a returned ballot always in full even when its ξ_B is released
  (then the full item and ξ_B are both published, and the record says which ballots came back). The main difference
  for returned ballots (review round 1 of S10b-A): a compact item records no short codes or labels, so 17.A and
  19.A-D hold by construction on it (§3.2), and only the voter's comparison of the paper with the derived view checks
  what was printed. Under (a) that holds for a returned ballot whose ξ_B is released, which is the ballot a voter
  actually audits; under (b) the full item keeps those codes and labels in the record, so V17 and V19 check them, at
  about 31 KB per contest (m = 5, L = 1).
- **R-2 (NQ-1) What a newer minor does to the verdict.** "Reports that the record is newer but still verifies
  everything it understands" is read as informational: `Passed` means no failures, `Complete = false` is reported
  beside it, and `egrecord verify` exits 2 instead of 0 (§6.9, risk 16). Revision 2 required `Complete` for `Passed`.
  Unknown critical sections and unknown item types in sections that must verify stay `R.version` failures.
- **R-3 (NQ-1) Near-miss manifest properties.** *Answered "Ignore them too": the refusal is removed (S10b-B), and a
  near-miss name is ignored like any unknown property.* As asked: the manifest reader ignores unknown properties but refuses one whose
  name equals a member's name once case, `_` and `-` are disregarded (`ChainingMode`, `chaining_mode`), because a
  loosely matching reader in another language would read it as that member and compute with another manifest under
  the same H_B (§4.6, S10b-1b). Ignoring those too would follow "ignores unknown properties" literally.
- **V14 labeling (S10b-B review round 2).** *Answered 2026-10-10, "14.structure for mismatches": 14.B and 14.D are
  pure label-presence checks, and a decrypted contest or field whose (index, label) pairing does not match the
  manifest is `14.structure` (applied in S10b-C; §4.6).* As asked: (a) keep the at-index rule under 14.B (contest) and
  14.D (field), as S10b-B built it, or (b) keep 14.B/14.D as presence checks and report the pairing as 14.structure.
- **NQ-7 Where a later minor's standard section type lives (S10b-C review round 2).** *Answered 2026-10-10, "Bump the
  major version" (option (c)): a new section kind requires a new `format_major`, a reader refuses a section kind it
  does not know with `R.version`, there is no generic path, and minor versions add only fields (applied in S10b-D:
  §4.3 D2, §4.5, §5.3.1, §6.9, §7; per-precinct tallies, #16, come with a major).* As asked: §4.5 ("Several tallies")
  and §7 ("Section type") promise that a v2.0 reader digests a non-critical standard section type that a later minor
  adds (for example `tally_definitions`, 0x0203) and reports `Complete = false` (R-2). But §5.3.1 derives every path
  from the types the reader knows and makes any other file `R.container`, so such a section, whatever its path, stops
  a v2.0 reader at open. The code follows §5.3.1 (`RecordLayout.Parse`); `CriticalOf` and the TOC reader already
  allow unknown types. The path is interoperable (every reader in every language must find the same sections), so it
  is the user's choice:
  - (a) *Recommended.* A generic path for standard types now, in v2.0: a standard type a minor adds lives at
    `sections/<type as 4 hex digits>[-<key hex>]/<8-digit>.<ext>`, like a vendor section. A reader accepts that path
    only for a standard type it does not know (one it knows at its own path is `R.container`), takes the critical bit
    from the claimed TOC (§4.5), and fails a critical one with `R.version` and digests a non-critical one with
    `Complete = false` (§7). Paths stay a function of type and key.
  - (b) The same rule with the phase directory in front (`aggregated/0203/...`, `final/0305-<key>/...`), so the tree
    stays grouped by phase; the sealed phase has no directory today, so it would need one.
  - (c) Qualify §4.5 and §7: a new standard section type needs a new major, and later tallies arrive with v3.
- **NQ-8 Does a vendor section make `Complete` false? (S10b-D; open, not blocking.)** After NQ-7 a vendor section
  (0x8000-0xFFFD) is the only section a v2 verifier does not understand. As built it is digested, counted
  (`RecordStatistics.VendorSections`) and does not make `Complete` false (a critical one is `R.version`): vendor
  sections are part of the format and are never verified, so a record that carries one is as complete as the format
  can make it. The alternative is `Complete = false` with the section listed in `SkippedUnknownContent`, so that
  `egrecord verify` exits 2 for any record with vendor data. Recommendation: keep as built.
- **NQ-10 What a guardian run checks on an uncast ballot before its release (S10b-D; open, not blocking).** §3.6.1 has
  the guardians run Verifications 4-9 before they decrypt, which on pre-encrypted ballots spec p.64 maps to 15 and 16
  as well (review round 1 put both in the guardian profile). On the aggregated prefix an uncast pre-encrypted ballot
  has no release yet. As built since review round 2 it gets 5.B and its device's walk (16.D-16.H, once per device)
  and is listed for release; a full item is also checked from its printed content for 6.A, 16.A-16.C, 17 and 19 (the
  guardian profile runs 6 and 16 of these; 6.A costs a batch membership test over its 2·(m+L)·m values per contest,
  16.A-16.C hashes only), and a compact item, which has no vectors until its ξ_B is released, gets 16.C from its
  printed χ, B_C and H_C (review round 3: that check needs no ξ_B; one hash) and leaves 6 and 16 (for 16.A-16.B)
  `NotEvaluable`. Review round 2 found the earlier build (everything deferred to the release, on §13's argument that
  V18 recomputes every α and β) reported V6 and V16 `Passed` over items they never ran on; a tampered ψ on a full
  uncast item passed a guardian run and yielded an aggregate. A visible consequence: a never-returned ballot is
  always compact (NQ-2), so a guardian run of a real pre-encrypted election will show V6 and V16 `NotEvaluable`; the
  run still passes and the aggregate is still returned (only V9 gates it). Alternatives: (b) defer the full item's
  checks to the release as before, `NotEvaluable` whenever any uncast ballot exists; (c) as built, but report the
  deferred compact items as a note (like `SkippedUnknownContent`) with V6 and V16 `Passed` over what ran.
  Recommendation: keep as now built (spec p.64: V6 "for all selection encryptions on all ballots, including ...
  pre-encrypted ballots"; `NotEvaluable` says exactly what happened).
- **NQ-11 Verification 17 in the guardian profile (S10b-D review round 1; open, not blocking).** Spec p.65 asks for
  V17 "additionally, for all pre-encrypted ballots", outside the 4-9 mapping of §3.6.1 and p.64. It checks that the
  short codes shown to voters derive from the selection hashes; it does not bear on which ciphertexts the guardians
  decrypt or whether they are well formed. As built the guardian profile leaves it out (it runs in `Full` and
  `BallotCorrectness`). The alternative is to add it (cheap: one hash per short code). Recommendation: keep it out.
- **NQ-9 Enum values in a minor (S10b-D; open, not blocking).** The NQ-7 answer says minor versions "add only fields".
  As built, a minor may still add a value to an existing enum other than `SectionType` (a reader older than the record
  treats it as content not understood, D2), since that is protobuf's own forward compatibility, which the same answer
  invokes. The alternative is to close every enum like `SectionType` (D2 at any reader age, so a new status or device
  kind needs a major). Recommendation: keep as built; no v2.0 enum is expected to grow. Either way the verifier does
  not guess (review round 1): a regular ballot whose status is a value it does not know is `R.version` at the item,
  and V9 and the checks that read the status are not evaluable (§7 "Enum value"). Review round 3 adds a sub-question
  for `DeviceKind`: a new device kind also needs a new section path (`devices/<prefix>-<hex>/`), and v2's layout has
  none for an undeclared kind (NQ-7: no generic path), so as built a genuine record of a newer minor with a new device
  kind is refused whole at open (`R.container`, the unlisted path), not verified with `R.version` at that device.
  Either close `DeviceKind` like `SectionType` (a new kind needs a major; the canonical reader reports kind 3 anywhere
  as D2), or define a generic device path in v2 (for example `devices/kind-<NN>-<hex>/`) so that such a section is
  digested and reported `R.version`. Recommendation: close `DeviceKind`, since a new device kind is a new section kind
  in all but name and NQ-7 already gives that a major.

---

## 13. Review notes (round 1 and the feasibility run, 2026-10-09)

Most findings were applied as given; the changes are listed in the Status note at the top and in each section. This
appendix records the findings that were rejected, narrowed or changed in scope, and why.

- **Manifest BOM (review 1, #19).** Applied by narrowing the S10b-6 test, not by relaxing the parser. A manifest with
  a BOM is refused by `WriteSetupAsync`, because the media type's parser refuses it. The bytes are never rewritten,
  so "exactly as entered" holds for every manifest the record accepts. Relaxing `ManifestSerializer` would change
  S10a's strict reading for one byte sequence, which no one has asked for.
- **Unknown manifest properties (review 1, #19).** Revision 2 kept them refused. Superseded by NQ-1 (the manifest is
  where vendors add data) and NQ-4 (the election facts are manifest fields): the reader now ignores them, and H_B
  binds them through the bytes (S10b-1b).
- **Mandatory release for every uncast item (review 1, #8 extrapolation).** Kept. §4.4 publishes the nonces of every
  uncast ballot, #5 makes never-returned ballots uncast, and #8 requires every challenged ballot's opening. Who
  produces the release is NQ-5 (the guardians, from the sealed record, in S10b-19), not a format question.
- **V6 on uncast vectors (review 1).** Settled as 6.A at the range layer only. Spec p.65 applies V6 to "all individual
  selection encryptions within the selection vectors", but uncast vectors carry no range proofs, so 6.B-6.D cannot
  apply. Subgroup membership is implied by V18, which recomputes each α and β from the released nonces. An explicit
  ^q check per uncast value would add (m+L)·m·2 exponentiations per contest and decide nothing V18 does not. For the
  same reason the record verifier ran 6.A on an uncast ballot only with its release (S10b-D): before the releases
  exist (a guardian run of the aggregated prefix) it was listed for release and verified later. *Superseded by S10b-D
  review round 2 (§8.3 "Uncast ballots before their release", NQ-10): a full uncast item's 6.A is checked from its
  printed vectors at once (one batch membership test), since a guardian run then reported V6 Passed over items it
  never ran on; a compact item leaves V6 `NotEvaluable` until its release.*
- **Single-pass `.zip` (review 2, HIGH).** Of the two fixes offered, the design takes "drop" rather than "make
  normative", for the reasons in NQ-6. That also resolves the unbounded join buffering (review 2, HIGH), which
  existed only on that path.
- **Tally-id key versus new section types (review 1, #16).** Took new section types. Defining the tally-id key and
  `TallyDefinition` now would add v2.0 schema surface with nothing to fill it.
- **A 4 MiB frame ceiling (review 2, implied by Go's default).** Rejected in favour of 64 MiB. 4 MiB would refuse
  ordinary uncast pre-encrypted ballots (about 1 MB per contest at m = 30). 64 MiB is protobuf-es's default, and Go
  readers set `MaxSize`.
- **A durable committed-length file for torn tails (review 2, LOW).** Not adopted. Treating a trailing run of zero
  bytes as torn is enough, because a zero-length frame is never valid. It also avoids a new file that the §5.3.1
  "no unlisted files" rule would have to admit.
- **`java_package` (review 2, LOW).** Not set. A Java package name implies a domain the project may not own, and the
  default, the proto package `electionguard.egrf.v2`, is valid Java. `go_package` uses the repository's hosting
  path, and `java_multiple_files` is set.
- **Extension numbers 50001-50003 (both reviews).** Kept as marked draft placeholders. Registering numbers is a pull
  request to the protobuf project, which only the user can make (S10b-18, risk 15).
- **Timestamp versus a `uint64` of milliseconds (review 1, #3 judgment call).** Kept `Timestamp`, at about 6 B
  (0.05 %) per ballot, for the reasons in §4.6.
- **"Two conformant writers produce the same TOC" (review 1).** Was false only because of the `critical` bit; now
  true (§4.5).
- **C# `JsonParser` rejecting unknown members (feasibility, not tested).** The design keeps the claim, which matches
  Google.Protobuf's default `IgnoreUnknownFields = false`, and pins it with a negative vector (§5.7).

**S10b-A implementation review, round 1 (2026-10-09).** All eight findings were applied; none was rejected. The
design changes: the compact form's limits on V17 and V19 (§3.2, §3.3, §6.2, §6.9, §12 R-1, and a third divergence
for the formal spec); S8 now keeps scalars out of oneofs, so W6's "unknown VARINT is not 0" cannot reject a
canonical newer record (§4.2.1, §4.2.2, §4.4, §11); and the spoiled-ballot wording says what actually stops a
decryption (§3.3, §8.3, S10b-9 and S10b-19 rows). One finding was narrowed. A test that a spoiled ballot sharing id_B
with a cast one fails 5.A cannot be written against today's API, because Verification 5.A takes identifiers, not
ballots, and so has no status to filter on. It is added to S10b-9's tests, where the record verifier collects the
identifiers.
