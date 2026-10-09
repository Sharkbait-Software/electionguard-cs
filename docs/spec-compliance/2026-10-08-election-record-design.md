# ElectionGuard Record Format (EGRF) v2: the canonical election record (S10b design)

Status: revised design for user approval (Q37 part B), rewritten 2026-10-09 to apply every user answer recorded in
the tracker (`2026-10-04-fix-progress.md`, Decisions: "S10b design answers, 2026-10-09" and "S10b follow-up answers,
2026-10-09"). Nothing is implemented. The only other file this revision writes is the normative schema,
`docs/spec-compliance/egrf_v2.proto`, which §4.6 embeds verbatim. It compiles to C# and Python with the protoc that
ships in the Grpc.Tools NuGet package (2.72.0 and 2.80.0; the latter is libprotoc 31.1).

**Review round 1 and the feasibility proof are applied** (same day). Two design reviews and a four-runtime
feasibility run (Python upb, C# Google.Protobuf, protobufjs, protobuf-es; §4.4) checked this revision. Every
canonical-bytes claim held in all four runtimes. The changes they caused are in place, and §13 explains each finding
that was rejected or changed in scope. The main changes:

- `RecordHeader` carries §3.7's election-identifying facts again, limited to what the manifest lacks (§3.1, NQ-4).
- The `critical` bit is fixed per section type (§4.5).
- Later tallies arrive as new section types (§4.5).
- Frames are capped at 64 MiB (§5.2).
- Carrier layout and conflict rules are normative (§5.3.1).
- Single-pass reading from a pipe is dropped (§5.4, NQ-6).
- The JSON text is not canonical; only its parsed structure is (§5.5).
- Method B names its discard-unknown call for each runtime (§4.4).
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
| Ballot status | `not_submitted`, `cast`, `challenged` | `CAST`, `CHALLENGED`, `SPOILED`; zero value `UNSPECIFIED` is invalid in a record (§4.6, §8.3) | #4 |
| Never-returned pre-encrypted ballots | `PreEncryptedUnreturnedBallot` stub | recorded as challenged (uncast) pre-encrypted ballots with released nonces; the stub is gone (§3.2) | #5 |
| Uncast nonces | inside the uncast item, in the sealed device section | split: printed content stays in the device section, the nonce release is a final-phase item (§3.2, §4.5) | consequence of #5 and Q36 |
| Timestamps | optional, precision setting, privacy-risk framing | `google.protobuf.Timestamp`, UTC, millisecond precision, no precision setting (§4.3) | follow-up #6 |
| Header | `election_info` key/value registry | format version plus `election_info`, limited to facts the manifest does not carry (§4.6) | follow-up #9 (reading confirmed by NQ-4) |
| Manifest | `ManifestSerializer` reading rules as "manifest format 1"; writers SHOULD publish the written form | stored byte for byte as entered; `ManifestSerializer` only parses; H_B over those bytes (§4.6, §9.3) | #19 |
| Carriers | directory and ZIP64; tar and `.egr` considered | directory and `.zip`; no `.7z`, no tar; normative layout and conflict rules (§5.3.1, §5.4) | #14 (measured) |
| Single-pass reading | a `.zip` read from a pipe in one pass | dropped; a non-seekable input is spooled to disk first (§5.4) | review round 1; NQ-6 |
| Frame size | unbounded | at most 64 MiB per frame (§5.2) | review round 1 |
| Out-of-range values | asked (Q-11) | the format checks widths only; the verifier reports ranges under the lettered checks (§4.8) | #11 |
| Per-item extensions | in-band list with a critical bit | one `extensions` field on the item envelope, pending NQ-1 | new question |
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
- **The protobuf nonce hazard.** `ProtobufEncryptedValueWithProofs.EncryptionNonce` and
  `ProtobufEncryptedValue.EncryptionNonce` (`IEncryptedBallotSerializer.cs` lines 508 and 532) have no
  `[ProtoMember]`, but the mapping at line 83 still copies `s.EncryptionNonce` into the DTO. Every selection nonce is
  one attribute away from being serialized. Step S10b-0 deletes them before anything else.

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
6. **G-6 Versioned and extensible.** No reader can report a full pass while content it did not understand went
   unchecked, in any representation.
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
  C_ξB of a pre-encrypted ballot (`TallyGuardian.DecryptBallotNonce` takes a challenged `EncryptedBallot` only). So a
  record with uncast pre-encrypted ballots can be completed only with nonces from that out-of-scope tool. NQ-5 asks
  whether Core should instead open sealed uncast ballots through the guardians.
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
| Information that identifies the election (date, location, type, ...) "not otherwise included in the election manifest" | `RecordHeader.election_info`: (key, value) entries, strictly ascending by key, from a small registry plus `x-` vendor keys | none (covered by the root and signatures) | Follow-up #9: "Only what isn't in manifest". The manifest model (`Manifest.cs`) has no date, location or type, and `ManifestSerializer` refuses unknown properties, so these facts have no other signed place. Nothing the manifest carries is repeated. NQ-4 confirms this reading. |
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
| Uncast (returned uncast, **or printed and never returned**): the printed content | `PreEncryptedUncastBallot` in the printer's device section: every vector, ψ, short code, χ, H_C, B_C, C_ξB | 5, 6.A (range layer only, §4.8; uncast vectors carry no range proofs, and subgroup membership follows from 18.A's recomputation), 16, 17, 19 |
| Uncast: "the ballot nonce for that ballot is published" | `UncastNonceRelease` (final phase): ξ_{i,j,k} per vector; `ballot_nonce` (ξ_B) only when opted in (Q28) | 18 |
| Confirmation codes from the full set of pre-encryptions | `confirmation_code` and `chaining_field` on every pre-encrypted item | 16.C, 16.E-16.H |
| Pre-encrypted device chains | pre-encrypting device sections: cast and uncast items interleaved in print order | 16.D-16.H |
| §4.4.1 presentation | derived views only | |

**Never-returned ballots (#5).** The user wrote: "pre-encrypted ballots never returned can be considered challenged
ballots". §4.3 already calls every uncast ballot "implicitly or explicitly challenged", so a printed ballot that never
came back is recorded exactly as a returned uncast one: its printed content in the device section, in print order,
and its nonces released in the final phase. v1's `PreEncryptedUnreturnedBallot` stub, which published no nonces, is
removed. The status of a pre-encrypted item is implied by its type: a `PreEncryptedCastBallot` is cast and a
`PreEncryptedUncastBallot` is challenged. Neither carries a `status` field (field 4 is reserved on both), so the two
can never disagree.

**Why the release is split from the printed content.** The device section is sealed when voting closes (R_sealed).
Whether a printed ballot was cast, returned uncast or never returned is known only once voting is over, and its
release opens it as a challenged ballot's decryption does. So the printed content belongs in R_sealed and the release
in R_final, exactly as a challenged regular ballot sits in its device section and its decryption in the final phase.
This is a placement rule only; it does not say who produces the nonces. Spec p.66 derives the ξ_{i,j,k} "from the
ballot nonce ξ_B via Equation 121 after it has been decrypted as specified in Section 3.6.7". Under Q35 that producer
is the out-of-scope recording tool (§1, Non-goals), and NQ-5 asks whether the guardians should do it in Core. The
mapper splits the domain `PreEncryptedUncastBallot` (`Ballot` + `BallotNonce?` + released `Contests`) into the two
items and joins them on read. v2.0 requires exactly one release for every uncast item. That follows from #5 (an
uncast ballot is challenged) together with #8 (every challenged ballot has its decryption), and from §4.4, which
publishes the nonces of every uncast ballot.

**Cost of #5.** The printed content of an uncast ballot per contest is (m+L) vectors of m·1,024 B, each with its 32 B
ψ and its short code: (m+L)·(m·1,024 + 32) B plus framing and short codes, 30,912 B at m = 5, L = 1. A vote-by-mail
election where many printed ballots never come back pays that for each one. NQ-2 offers a compact form that keeps the
decision and drops most of the cost.

**Divergences to state in the formal spec:**

- §4.4 says the uncast "ballot nonce" is published. Q28 publishes the per-selection nonces ξ_{i,j,k}, and ξ_B only
  when opted in.
- §3.7 lists "the status of the ballot (cast or challenged)". The record adds `SPOILED` (#4) for a submitted ballot
  that was neither: it is in the chain, counts for 5.A and 11.D, gets V6-V8, and is never tallied or decrypted
  (§3.3).

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
| 17 | ψ, short codes | cast and uncast items |
| 18 | uncast vectors, released nonces, K (V18's recomputation also settles the subgroup membership half of 6.A for uncast vectors) | `PreEncryptedUncastBallot` + `UncastNonceRelease` |
| 19 | uncast labels, manifest | `PreEncryptedUncastBallot` + manifest |

**Spoiled ballots and "submitted".** Verifications 5.A and 11.D speak of "submitted (cast and challenged)"
ballots. The user wrote (#4): "If we have it in the election record at all, it was by definition submitted." So a
spoiled ballot counts as submitted: it is in 5.A and 5.B, and its contests count for 11.D. It gets V6-V8 like any
other ballot, it is not aggregated (V9 reads cast ballots only), and it is never decrypted: a
`ChallengedBallotDecryption` that names it is `13.structure`, and the guardians' Q31 check refuses it because it is
not challenged. In v2.0 11.D cannot fail on a spoiled ballot alone, because the one tally lists every manifest
contest.

---

## 4. Canonical form: the EGRF protobuf profile

### 4.1 Why a profile, and what it buys

The user decided that the canonical encoding is protobuf (#1: "It's important that the distributed format be
something that can be used on any machine"; #13: "we absolutely must be capable of working on any device in any
programming language, and it should be relatively easy to do so. Space is a concern, which is why protobuf over
json"). Protobuf on its own is not canonical. Its specification lets a parser accept fields in any order, repeated
singular fields (last one wins, or messages merge), overlong varints, explicitly written default values, and unknown
fields, and its "deterministic serialization" option promises stability only within one binary, not across languages
or versions. So EGRF v2 is protobuf **plus a profile**:

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

### 4.2 Profile rules (normative)

#### 4.2.1 Schema rules

The schema is `egrf_v2.proto` (§4.6), package `electionguard.egrf.v2`. A schema lint test (S10b-2) enforces these
rules on the compiled descriptor, so a future edit cannot break them silently.

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
- **S6.** Field numbers are append-only. A format minor version adds fields only with numbers above every existing
  field of that message, except the envelope's `extensions = 2047`, which stays last. Removed fields become
  `reserved`. Hot messages (`EncryptedBallot`, `EncryptedContest`, `EncryptedField`, `HashedCiphertext`) keep every
  field at 15 or below, so each tag is one byte.
- **S7.** Every `bytes` field that carries a fixed-width value is annotated with `(width)` or `(width_multiple)`,
  plus `(omittable) = true` when it may be absent. Every enum has `..._UNSPECIFIED = 0`, which is invalid wherever
  the field is required.
- **S8.** No regular (non-oneof) field number lies between the lowest and highest member numbers of a oneof in the
  same message. Rust's prost encodes a oneof at the position of its lowest-numbered member, whichever member is set
  (prost-derive's source says so in a TODO). With S8 that position is still field-number order. Today `RecordItem`
  is the only oneof (members 1-100), and only `extensions = 2047` follows it.

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
- **W6 Known fields only.** Every field number is defined in the schema the record's `format_minor` names. A reader
  that knows that minor rejects any other number (`R.encoding`); a reader older than the record follows §7.
- **W7 Repeated messages.** One LEN record per element, never packed.
- **W8 Strings.** Valid UTF-8 (RFC 3629: no surrogate code points, no overlong forms). No normalization: labels
  compare byte for byte with the manifest's.

#### 4.2.3 Presence in practice

Optional fields, and how absence is expressed:

| Field | Absent means | Mechanism |
|---|---|---|
| `encrypted_at` (both cast ballot kinds), `DeviceClose.closed_at` | not recorded | message presence |
| `ballot_ref` (all ballot items) | no reference | empty string |
| `RecordHeader.election_info` | no facts given | empty repeated field |
| `DeviceHeader.initial_hash`; `DeviceClose.closing_chaining_field`, `closing_hash`; `ChainCloseStatement.closing_hash` | no chaining | `(omittable)` bytes |
| `EncryptedContest.undervote_difference_proof`, `null_vote_proof` | not tracked by the manifest | `(omittable)` bytes |
| `EncryptedContest.contest_data`, `DecryptedContest.contest_data` | b_Λ = 0 | message presence |
| `UncastSelection.option_label` | a null vector | empty string |
| `UncastNonceRelease.ballot_nonce` | ξ_B not released (Q28) | `(omittable)` bytes |
| `SignedStatement.signer_key`, `timestamp_token` | out of band; no token | empty bytes |

Fields where 0 is a meaningful value, so the value 0 is written as absence (the proto3 rule, and no ambiguity):
`DeviceHeader.chaining_mode` (0 = no chaining), `DecryptedField.value` (σ = 0), `DecryptedTallyField.tally`
(t = 0), `EncryptedTallyContest.cast_weight`, `RecordHeader.format_minor`, `SegmentHeader.first_ordinal`,
`TocEntry.item_count` and `critical`, `Extension.critical`. Fields that are never 0 in a valid record, so are always
present: every 1-based index, `weight`, `status`, `kind`, `format_major`, n and k.

### 4.3 Decode rules (checked after parsing)

Re-serialization cannot see these, so every reader checks them explicitly. A failure is `R.encoding` unless noted.

- **D1 Widths.** A present `bytes` field with `(width) = w` has exactly w bytes; with `(width_multiple) = w`, a
  positive multiple of w bytes. A field with a width annotation that is absent fails unless it is `(omittable)`.
  Widths are a property of the encoding; **counts** that depend on the manifest (k, k+1, R+1, L+1, m+L, the style's
  contests) are structure (`N.structure`, §4.8). Values are big-endian b(x, w) (§5.1), leading zeros kept, never
  minimal-length integers.
- **D2 Enums.** The value is a declared member, and not `UNSPECIFIED` where the field is required. Proto3 enums are
  open, so a runtime keeps an unknown integer; the reader rejects it. `SectionType` additionally admits the vendor
  range 32768-65533 in `SegmentHeader` and `TocEntry`.
- **D3 Timestamps.** `seconds` in [0, 253402300799], which is 1970-01-01T00:00:00Z to 9999-12-31T23:59:59Z, and
  `nanos` in {0, 1,000,000, ..., 999,000,000}: UTC, millisecond precision, as S10a's `EncryptionTimestamp`
  (follow-up #6). S10a's `DateTimeOffset` also admits times before 1970, so the writer's mapper refuses a pre-1970
  time rather than writing negative seconds.
- **D4 Integer bounds.** `uint32` values below 2^31 (the spec's 4-byte indices have MSB 0, §5.1.3, and C# reads them
  as `int`); `uint64` values below 2^63 (`long`).
- **D5 Envelope.** A `RecordItem` has exactly one oneof member set. `extensions` tags are strictly ascending and at
  least 1.
- **D6 Segment header.** A `SegmentHeader` passes the §4.4 check like an item, and D1-D4 where they apply. `magic` is
  `"EGRF"` and `format_major` is 2, and the header agrees with the file's path (§5.3.1). Any failure is
  `R.container`.
- **D7 Keyed lists.** `RecordHeader.election_info` keys are non-empty, strictly ascending by UTF-8 bytes (so unique),
  and each is a registry key or starts with `x-`. Values are non-empty. A registry key whose value breaks its syntax
  (for example an `election_date` that is not an RFC 3339 full-date) is `R.structure`.

**The decode rules are mandatory in every conformant reader.** The feasibility run confirmed that no runtime enforces
any of them. In all four runtimes tested, every decode-rule negative vector passed parse, re-serialize and compare:
an undeclared enum value, `UNSPECIFIED` status, a `uint32` ≥ 2^31, sub-millisecond nanos, negative seconds, a wrong
width or width multiple, an absent width field that is not omittable, an empty `RecordItem`, and extension tags out
of order.

**Range is not a decode rule** (#11: "Out of range values are a problem for a verifier, not the election record
format"). A 512-byte value ≥ p or a 32-byte value ≥ q decodes. The verifier reports it under the spec's lettered
check (§4.8).

### 4.4 Checking canonicality in any language

Two methods are conformant. Both run on the stored bytes of each item, before its leaf hash is accepted.

**Method A, the wire walk (the normative reference).** About 120 lines over the schema's descriptor (or a transcribed
table of field numbers, types and width options):

```
walk(bytes, message type):
  last = 0
  while bytes remain:
    tag = read minimal varint                      -- W4
    number, wiretype = tag >> 3, tag & 7
    field = schema(message type, number) or fail   -- W6
    wiretype == field's wire type or fail          -- W3
    number > last, or (number == last and field is repeated and the previous record was this field) or fail  -- W1, W2
    value = read minimal varint, or read minimal-varint length then exactly that many bytes  -- W4, W5
    implicit-presence field: value != default or fail                                         -- W2
    string: valid UTF-8 or fail                                                               -- W8
    message: walk(value, field's message type)                                                -- W5
    last = number
  then apply D1-D7 to the decoded values
```

**Method B, parse, re-serialize, compare.** Parse with the generated code **discarding unknown fields**, apply the
decode rules D1-D7, serialize, and compare with the input byte for byte. Equal bytes mean canonical.

- **Why it is sound.** Method B accepts only bytes that equal a canonical serializer's output. A runtime whose
  parser is lenient or quirky can therefore cause false rejections, never false acceptances. The checks fall out as
  follows. W1, W2, W4 and W5 change the bytes. Under W6, a discarded unknown field shortens the output. W3 either
  becomes an unknown field or makes the parse throw (protobuf-es reads the payload by the schema's type, loses sync
  and throws "illegal tag"). W8 either throws or is replaced, which changes the bytes.
- **Discarding unknown fields is required, and each runtime spells it differently.** C# Google.Protobuf, Python
  (upb) and protobuf-es keep unknown fields by default and write them back out. With those defaults, all three
  accepted every unknown-field vector in the feasibility run. The calls:

  | Runtime | Discard unknown fields | Tested |
  |---|---|---|
  | C# Google.Protobuf | `Parser.WithDiscardUnknownFields(true)` | yes |
  | Python protobuf (upb) | `msg.DiscardUnknownFields()` after parsing | yes |
  | protobuf-es | `fromBinary(schema, bytes, { readUnknownFields: false })` | yes |
  | protobufjs | always discards; no option | yes |
  | Go | `proto.UnmarshalOptions{DiscardUnknown: true}` | no |
  | Java | `DiscardUnknownFieldsParser.wrap(parser)` | no |
  | Rust prost | always discards | no |

- **Field order.** Method B relies on the runtime writing a map-free message's fields in field-number order. All four
  tested runtimes do, oneof members included. S8 covers prost. The golden vectors (§5.7) arbitrate, and a runtime
  that fails any of them uses Method A.
- **The decode rules are separate code.** Parse, re-serialize and compare accepted every D-rule vector in every
  runtime (§4.3), so a reader that runs Method B without D1-D7 is not conformant.
- **Cost.** One serialization per item, a few microseconds for a 13 KB ballot, against about 1 ms of verification
  cryptography per ballot.

**Feasibility result (2026-10-09).** For one item of every `RecordItem` member, a `SegmentHeader` and four edge cases,
Python's `SerializeToString()` equalled an encoder written from §4.2 alone. Parse then re-serialize was byte-identical
in Python, C#, protobufjs and protobuf-es. Building from values in protobufjs and protobuf-es gave Python's bytes. JSON
to bytes was lossless in Python, C# and protobuf-es. Method A rejected all 37 hand-built negative vectors with the
rule this section names. Method B rejected the same 27 wire-level vectors in all four runtimes, and needed explicit
decode-rule code (D1-D5, which were the rules then) for the other 10. Java and Go were not tested.

The C# reference uses Method B on the hot path and Method A for records of a newer minor (§7) and as a cross-check in
tests. The Python reference reader (§5.7) uses Method A only, with the standard library.

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
| 0x0102 | device_attestations | voting | empty | `device_attestation`, ascending (device key, statement item type, SHA-256(statement)) | exactly once once voting is sealed; may be empty | yes |
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
a reader knows, the bit is the table's value, and a claimed TOC entry that disagrees is `R.root`. For a type the reader
does not know (a vendor section, or a later minor's standard type), the reader has no other source, so it takes the
bit from the claimed TOC entry. That is the one place a verifier uses a claimed TOC value, and a flipped bit still
changes the root, so signatures cover it. With these rules and the presence rules, two conformant writers of the same
content produce the same TOC.

**Canonical ballot order** is device sections in key order, and chain order within each section. Locator order
(kind, H_DI bytes, position) is the same order, and the final-phase join sections are sorted by it, which is what
makes O(1)-memory merge joins possible (§6.3). Sort order is defined on values, not on encoded bytes.

**Several tallies (#16).** v2.0 has exactly one `encrypted_tally` and one `decrypted_tally` section, each with an
empty key, and they always mean the election-wide tally over every cast ballot. That meaning never changes. A later
minor version adds further tallies as **new section types**, not as more keyed copies of 0x0201/0x0301. For example:

- `tally_definitions` (0x0203): one `TallyDefinition` item per tally id, naming its ballot set for V9;
- `subset_encrypted_tally` (0x0204) and `subset_decrypted_tally` (0x0305), keyed by tally id.

Those types are non-critical. A v2.0 reader then verifies the election-wide tally in full, digests the new sections,
and reports `Complete = false` (§7). A design that keyed the existing types instead would break v2.0 readers: they
would report two `encrypted_tally` sections as `R.structure`, and would run V9 over all cast ballots against a subset
tally and fail 9.A.

Rules for device sections:

- `DeviceHeader.kind` and `h_di` must equal the key, and the verifier recomputes H_DI from `device_id` and kind
  (eq. 72 with 0x2A for regular devices; eq. 119 with 0x43 for pre-encrypting ones; 8.C/16.D). Strictly ascending
  keys make "one device, two sections of the same kind" a structural error found in O(1).
- A regular section holds `encrypted_ballot` items only, of any status. A pre-encrypting section holds
  `pre_encrypted_cast_ballot` and `pre_encrypted_uncast_ballot` items only, interleaved in print order. Anything else
  is `8.structure` or `16.structure`.
- Under no chaining, the order is still the device's recorded processing order. Only the chain-close attestation
  fixes it cryptographically (§4.9).
- Spoiled ballots stay in their chain position (#4), so 8.E and 8.G hold on an honest record.

### 4.6 The schema (normative)

The schema below is `docs/spec-compliance/egrf_v2.proto`, copied verbatim. On implementation (S10b-2) it moves to
`proto/electionguard/egrf/v2/egrf.proto` at the repository root, a language-neutral location that the C# build, the
Python reference reader and any other implementation share.

```proto
// EGRF v2: the ElectionGuard Record Format, canonical protobuf profile.
//
// This schema is NORMATIVE. The profile rules that make every item's bytes unique (field order,
// presence, widths, varints, framing) are in the design document,
// docs/spec-compliance/2026-10-08-election-record-design.md §4.2, and are summarized here:
//
//  - proto3. Field types are restricted to uint32, uint64, bool, enum, string, bytes, message and
//    google.protobuf.Timestamp. No maps, floating point, signed or fixed-width integer types, Any,
//    groups, `optional` keyword, or repeated scalar numeric fields (so packing never arises).
//  - Fields are declared, and MUST be written, in ascending field-number order.
//  - Implicit presence: a scalar, string or bytes field is written if and only if it differs from its
//    default (0, false, the zero enum value, empty). Message fields are written iff set.
//  - Every list is `repeated <message>` or one `bytes` field holding a concatenation of fixed-width
//    values (option width_multiple). Fixed-width values are big-endian b(x, w) (spec §5.1): Z_p 512
//    bytes, Z_q 32, hashes 32, chaining fields 36. Range (x < p, x < q) is NOT a format rule; the
//    verifier reports it under the spec's lettered checks.
//  - Timestamps are UTC with millisecond precision: seconds in [0, 253402300799] (1970-01-01 to
//    9999-12-31), nanos a multiple of 1,000,000.
//  - No oneof's member numbers may enclose a regular field's number (lint rule S8), so runtimes that
//    encode a oneof at its lowest member's position (prost) still write field-number order.
//  - No runtime enforces the decode rules (widths, enum membership, integer bounds, timestamp
//    precision, envelope and key order). Every conformant reader checks them itself.
//
// Spec basis: ElectionGuard v2.1.0 §3.7 (pp.55-56), §4.4 (pp.62-63), Verifications 1-19.
// Comments name the spec symbol each field carries.

syntax = "proto3";

package electionguard.egrf.v2;

import "google/protobuf/descriptor.proto";
import "google/protobuf/timestamp.proto";

option csharp_namespace = "ElectionGuard.Core.Record.Protobuf";
option go_package = "github.com/Sharkbait-Software/electionguard-cs/proto/electionguard/egrf/v2;egrfv2";
option java_multiple_files = true;

// ---- profile annotations (machine-readable width rules for any-language readers) -----------------

// The numbers 50001-50003 are DRAFT placeholders in protobuf's 50000-99999 range for in-house use.
// Before the schema is published they are replaced by numbers registered in protobuf's global
// extension registry (S10b-18), so that no third party's options collide in a shared descriptor pool.
extend google.protobuf.FieldOptions {
  // A present bytes field has exactly this many bytes.
  uint32 width = 50001;
  // A present bytes field has a positive multiple of this many bytes.
  uint32 width_multiple = 50002;
  // A width-constrained bytes field that may be absent. Without it, absence is a width error.
  bool omittable = 50003;
}

// ---- enumerations -------------------------------------------------------------------------------

// Section types. The phase is min(type >> 8, 3): 0 setup, 1 voting (sealed), 2 aggregated, 3 final.
// 32768-65533 are vendor sections (final phase); proto3 enums are open, so they travel as numbers.
enum SectionType {
  SECTION_TYPE_UNSPECIFIED = 0;
  SECTION_TYPE_HEADER = 1;
  SECTION_TYPE_PARAMETERS = 2;
  SECTION_TYPE_MANIFEST = 3;
  SECTION_TYPE_GUARDIANS = 4;
  SECTION_TYPE_ELECTION_KEYS = 5;
  SECTION_TYPE_DEVICE = 257;                         // 0x0101; key = device key (33 bytes)
  SECTION_TYPE_DEVICE_ATTESTATIONS = 258;            // 0x0102
  SECTION_TYPE_ENCRYPTED_TALLY = 513;                // 0x0201
  SECTION_TYPE_CONTEST_DATA_REQUESTS = 514;          // 0x0202
  SECTION_TYPE_DECRYPTED_TALLY = 769;                // 0x0301
  SECTION_TYPE_CHALLENGED_BALLOT_DECRYPTIONS = 770;  // 0x0302
  SECTION_TYPE_CONTEST_DATA_DECRYPTIONS = 771;       // 0x0303
  SECTION_TYPE_UNCAST_NONCE_RELEASES = 772;          // 0x0304
  SECTION_TYPE_TOC = 65534;                          // pseudo-section: the claimed TOC; never in a TOC
  SECTION_TYPE_SIGNATURES = 65535;                   // pseudo-section: outside every root
}

enum DeviceKind {
  DEVICE_KIND_UNSPECIFIED = 0;
  DEVICE_KIND_REGULAR = 1;          // Verification 8; H_DI by eq. (72)
  DEVICE_KIND_PRE_ENCRYPTING = 2;   // Verification 16; H_DI by eq. (119)
}

// §3.7 "the status of the ballot". Anything in the record was submitted; a ballot that was neither
// cast nor challenged is SPOILED. UNSPECIFIED is invalid in a record.
enum BallotStatus {
  BALLOT_STATUS_UNSPECIFIED = 0;
  BALLOT_STATUS_CAST = 1;
  BALLOT_STATUS_CHALLENGED = 2;
  BALLOT_STATUS_SPOILED = 3;
}

enum RecordPhase {
  RECORD_PHASE_UNSPECIFIED = 0;
  RECORD_PHASE_SETUP = 1;
  RECORD_PHASE_SEALED = 2;
  RECORD_PHASE_AGGREGATED = 3;
  RECORD_PHASE_FINAL = 4;
}

// ---- framing ------------------------------------------------------------------------------------

// A segment file is a varint-length-delimited stream: one SegmentHeader, then RecordItems
// (WriteDelimitedTo / parseDelimitedFrom / protodelim / sizeDelimitedEncode). Every frame's length
// is at most 64 MiB (67,108,864 bytes); a reader rejects a larger length before allocating. The
// SegmentHeader is checked for canonicality like an item, and must agree with the file's path.
message SegmentHeader {
  string magic = 1;              // "EGRF"
  uint32 format_major = 2;       // 2
  SectionType section_type = 3;
  bytes key = 4;                 // empty, except a device section's 33-byte device key
  uint64 first_ordinal = 5;      // 0-based ordinal, within the section, of this segment's first item
}

// Every item, statement and digest leaf is a RecordItem. Its canonical bytes are what is stored,
// hashed (leaf = SHA-256(0x00 || bytes)) and signed; the oneof field number is the item type.
message RecordItem {
  oneof item {
    // setup
    RecordHeader record_header = 1;
    Parameters parameters = 2;
    ManifestFile manifest_file = 3;
    GuardianPublicKey guardian_public_key = 4;
    ElectionKeys election_keys = 5;
    // voting: device sections and attestations
    DeviceHeader device_header = 10;
    EncryptedBallot encrypted_ballot = 11;
    PreEncryptedCastBallot pre_encrypted_cast_ballot = 12;
    PreEncryptedUncastBallot pre_encrypted_uncast_ballot = 13;
    DeviceClose device_close = 14;
    SignedStatement device_attestation = 15;
    // aggregated
    EncryptedTallyHeader encrypted_tally_header = 20;
    EncryptedTallyContest encrypted_tally_contest = 21;
    ContestDataRequest contest_data_request = 22;
    // final
    DecryptedTallyContest decrypted_tally_contest = 30;
    ChallengedBallotDecryption challenged_ballot_decryption = 31;
    ContestDataDecryption contest_data_decryption = 32;
    UncastNonceRelease uncast_nonce_release = 33;
    // statements: signed payloads, never section items
    ChainCloseStatement chain_close_statement = 40;
    SectionSealStatement section_seal_statement = 41;
    PrefixCheckpointStatement prefix_checkpoint_statement = 42;
    RecordStatement record_statement = 43;
    SignedStatement record_signature = 44;          // signatures pseudo-section only
    // digest leaves
    TocEntry toc_entry = 50;                        // TOC pseudo-section and the TOC tree
    ConfirmationCodeLeaf confirmation_code_leaf = 51; // codes_root leaves; never stored
    // vendor sections only
    VendorItem vendor_item = 100;
  }
  // Open question NQ-1. Strictly ascending by tag; absent in every v2.0 writer's output.
  repeated Extension extensions = 2047;
}

message Extension {
  uint32 tag = 1;      // 1-65535 registry; 65536 and above vendor
  bool critical = 2;   // a reader that does not know the tag must not evaluate the item
  bytes value = 3;
}

message VendorItem {
  string type_url = 1;  // vendor-chosen identifier; never verified
  bytes value = 2;
}

// ---- setup --------------------------------------------------------------------------------------

// The format version, plus §3.7's "information sufficient to uniquely identify and describe the
// election ... (not otherwise included in the election manifest)". Nothing the manifest carries
// (election id, contests, styles, chaining mode, hash trimming) is repeated here.
message RecordHeader {
  uint32 format_major = 1;                 // 2
  uint32 format_minor = 2;                 // 0 (absent) in v2.0
  repeated ElectionInfo election_info = 3; // strictly ascending by key bytes; may be empty
}

// One descriptive fact about the election. Covered by the root and signatures; never verified.
// Registry keys (v2.0): "election_name", "election_date" (RFC 3339 full-date, YYYY-MM-DD; a
// multi-day election repeats it as "election_date.2", ...), "election_type", "jurisdiction",
// "location", "administrator". Other keys are "x-<vendor>-<name>". Producer software and creation
// time are not election facts; they go in meta.json, outside the root.
message ElectionInfo {
  string key = 1;    // non-empty; a registry key or "x-" prefixed
  string value = 2;  // non-empty
}

message Parameters {
  bytes version = 1 [(width) = 32];   // eq. (4) ver: "v2.1.0" then 0x00 padding to 32 bytes
  bytes p = 2 [(width) = 512];        // raw b(p,512), not an element of Z_p (decision G1)
  bytes q = 3 [(width) = 32];
  bytes r = 4 [(width) = 512];
  bytes g = 5 [(width) = 512];
  uint32 n = 6;
  uint32 k = 7;
  bytes h_p = 8 [(width) = 32];       // claim; Verification 1.E
}

message ManifestFile {
  string media_type = 1;  // v2.0: "application/vnd.electionguard.manifest+json;format=1", whose
                          // parser is S10a's strict ManifestSerializer reading (UTF-8 without a
                          // BOM, no unknown properties); a writer refuses content it cannot parse
  bytes content = 2;      // the manifest exactly as entered; the H_B input of eq. (5); never re-encoded
  bytes h_b = 3 [(width) = 32];  // claim; Verification 1.F
}

message GuardianPublicKey {
  uint32 index = 1;                                      // i, 1..n
  bytes vote_commitments = 2 [(width_multiple) = 512];  // K_{i,0} || ... || K_{i,k-1}
  bytes data_commitments = 3 [(width_multiple) = 512];  // K-hat_{i,0} || ... || K-hat_{i,k-1}
  bytes kappa = 4 [(width) = 512];                       // kappa_i
  bytes vote_proof = 5 [(width_multiple) = 32];          // c_i || v_{i,0} || ... || v_{i,k}
  bytes data_proof = 6 [(width_multiple) = 32];          // c-hat_i || v-hat_{i,0} || ... || v-hat_{i,k}
}

message ElectionKeys {
  bytes k = 1 [(width) = 512];      // K (claim; 3.A)
  bytes k_hat = 2 [(width) = 512];  // K-hat (claim; 3.B)
  bytes h_e = 3 [(width) = 32];     // H_E (claim; 4.A)
}

// ---- voting -------------------------------------------------------------------------------------

message DeviceHeader {
  DeviceKind kind = 1;             // = the section key's first byte
  string device_id = 2;            // S_device
  bytes h_di = 3 [(width) = 32];   // = the section key's last 32 bytes
  uint32 chaining_mode = 4;        // §3.4.4 identifier: 0 none (absent), 1 simple; must equal the
                                   // manifest's (8.D/16.E are per device, so the device states it)
  bytes initial_hash = 5 [(width) = 32, (omittable) = true];  // H_0; present iff simple chaining
}

message HashedCiphertext {
  bytes c0 = 1 [(width) = 512];
  bytes c1 = 2 [(width_multiple) = 32];  // 32 (ballot nonce) or 32 * b_Lambda (contest data)
  bytes c2 = 3 [(width) = 64];           // b(c,32) || b(v,32) (Q20)
}

message EncryptedField {
  bytes alpha = 1 [(width) = 512];
  bytes beta = 2 [(width) = 512];
  bytes range_proof = 3 [(width_multiple) = 64];  // (c_j || v_j), j = 0..R (or 0..bound, Q2)
}

message EncryptedContest {
  uint32 index = 1;                      // ind_c
  repeated EncryptedField fields = 2;    // manifest order: options, then supplemental fields (Q1/Q14)
  bytes limit_proof = 3 [(width_multiple) = 64];                                     // eq. (62), L+1 pairs
  bytes undervote_difference_proof = 4 [(width_multiple) = 64, (omittable) = true];  // iff tracked (Q15)
  bytes null_vote_proof = 5 [(width_multiple) = 64, (omittable) = true];             // iff tracked (Q17)
  HashedCiphertext contest_data = 6;     // iff b_Lambda > 0 (S6)
  bytes contest_hash = 7 [(width) = 32]; // chi
}

message EncryptedBallot {
  bytes id_b = 1 [(width) = 32];        // first, so an id-only scan reads one field per frame
  bytes h_i = 2 [(width) = 32];
  string ballot_style = 3;
  BallotStatus status = 4;              // CAST, CHALLENGED or SPOILED; never UNSPECIFIED
  uint32 weight = 5;                    // >= 1, so always present (§3.5)
  google.protobuf.Timestamp encrypted_at = 6;   // G40; ms UTC; absent when not recorded
  repeated EncryptedContest contests = 7;       // ascending index; exactly the style's contests
  bytes confirmation_code = 8 [(width) = 32];   // H_C
  bytes chaining_field = 9 [(width) = 36];      // B_C
  HashedCiphertext encrypted_ballot_nonce = 10; // C_xiB (§3.3.4); c1 exactly 32 bytes
  string ballot_ref = 11;                       // optional free text; unverified, bound by no hash
}

message SelectedVector {
  bytes vector = 1 [(width_multiple) = 1024];  // m x (alpha || beta), option order
  bytes psi = 2 [(width) = 32];                // selection hash psi
  string short_code = 3;
}

message PreEncryptedCastContest {
  EncryptedContest contest = 1;                         // combined vector, standard proofs (Q26: no contest data)
  bytes selection_hashes = 2 [(width_multiple) = 32];  // all m+L psi, strictly ascending
  repeated SelectedVector selected = 3;                 // exactly L, strictly ascending by psi (Q27)
}

message PreEncryptedCastBallot {
  bytes id_b = 1 [(width) = 32];
  bytes h_i = 2 [(width) = 32];
  string ballot_style = 3;
  reserved 4;                                   // status: CAST, implied by the item type
  uint32 weight = 5;
  google.protobuf.Timestamp encrypted_at = 6;   // when the cast record was formed
  repeated PreEncryptedCastContest contests = 7;
  bytes confirmation_code = 8 [(width) = 32];   // eq. (116)
  bytes chaining_field = 9 [(width) = 36];
  HashedCiphertext encrypted_ballot_nonce = 10;  // C_xiB
  string ballot_ref = 11;
}

message UncastSelection {
  uint32 selection_index = 1;   // eq. (121)'s j: option index, or m+l for the l-th null vector
  string option_label = 2;      // absent exactly on null vectors
  bytes vector = 3 [(width_multiple) = 1024];  // m x (alpha || beta)
  bytes psi = 4 [(width) = 32];
  string short_code = 5;
}

message UncastContest {
  uint32 index = 1;
  string label = 2;
  repeated UncastSelection selections = 3;  // m+L, ascending selection_index
  bytes contest_hash = 4 [(width) = 32];
}

// The printed content of a pre-encrypted ballot that was not cast: returned uncast, or printed and
// never returned (both are challenged). Its nonces are released in the final phase (UncastNonceRelease).
message PreEncryptedUncastBallot {
  bytes id_b = 1 [(width) = 32];
  bytes h_i = 2 [(width) = 32];
  string ballot_style = 3;
  reserved 4, 5, 6;                             // status CHALLENGED is implied; no weight or time
  repeated UncastContest contests = 7;          // ascending index
  bytes confirmation_code = 8 [(width) = 32];
  bytes chaining_field = 9 [(width) = 36];
  HashedCiphertext encrypted_ballot_nonce = 10;  // C_xiB
  string ballot_ref = 11;
}

message DeviceClose {
  uint64 ballot_count = 1;   // l = the number of ballot items in the section
  bytes closing_chaining_field = 2 [(width) = 36, (omittable) = true];  // B-bar_C; iff simple chaining
  bytes closing_hash = 3 [(width) = 32, (omittable) = true];            // H-bar; iff simple chaining
  google.protobuf.Timestamp closed_at = 4;
}

// A signed statement: a device attestation (in R_sealed) or a detached record signature.
message SignedStatement {
  bytes statement = 1;        // the canonical RecordItem bytes of a statement, exactly as signed.
                              // Opaque to the wire walk, so the verifier checks it as a RecordItem
                              // (canonicality, decode rules, member 40-43) before anything else.
  string algorithm = 2;       // registry: ecdsa-p256-sha256, rsa-pss-sha256, ed25519, x509-cms-detached
  bytes key_id = 3;
  bytes signer_key = 4;       // public key or certificate chain; may be absent (out of band)
  bytes signature = 5;
  bytes timestamp_token = 6;  // RFC 3161 TimeStampToken over SHA-256(statement); optional
}

// ---- aggregated ---------------------------------------------------------------------------------

message EncryptedTallyHeader {
  uint64 cast_ballot_count = 1;   // both kinds; checked (R.summary)
  uint64 total_cast_weight = 2;
}

message EncryptedTallyContest {
  uint32 index = 1;
  bytes fields = 2 [(width_multiple) = 1024];   // per manifest field: A || B
  uint64 cast_weight = 3;                       // S10a: sum of W over cast ballots listing the contest
}

message BallotLocator {
  DeviceKind kind = 1;
  bytes h_di = 2 [(width) = 32];
  uint64 position = 3;   // 1-based chain position (the spec's j)
}

// A contest-data ciphertext "marked for decryption" (§3.6.1), sealed before any decryption.
message ContestDataRequest {
  BallotLocator ballot = 1;        // a cast regular ballot
  bytes h_i = 2 [(width) = 32];    // binding: must equal the ballot's
  uint32 contest_index = 3;
}

// ---- final --------------------------------------------------------------------------------------

message DecryptedTallyField {
  uint32 index = 1;                      // manifest option or field index
  string label = 2;
  uint64 tally = 3;                      // t
  bytes encoded_tally = 4 [(width) = 512];  // T = K^t
  bytes proof = 5 [(width) = 64];        // c || v
}

message DecryptedTallyContest {
  uint32 index = 1;
  string label = 2;
  repeated DecryptedTallyField fields = 3;
}

message DecryptedField {
  uint32 index = 1;
  string label = 2;
  uint32 value = 3;                 // sigma
  bytes nonce = 4 [(width) = 32];   // xi_{i,j}
}

message ReleasedContestData {
  bytes nonce = 1 [(width) = 32];          // xi_i
  bytes data = 2 [(width_multiple) = 32];  // D, 32 * b_Lambda bytes
}

message DecryptedContest {
  uint32 index = 1;
  string label = 2;
  repeated DecryptedField fields = 3;       // every field of the contest
  ReleasedContestData contest_data = 4;     // iff the contest has contest data
}

// §3.6.7 decryption of a challenged regular ballot, in nonce form (S7): no proof, no xi_B.
message ChallengedBallotDecryption {
  BallotLocator ballot = 1;              // a CHALLENGED regular ballot
  bytes h_i = 2 [(width) = 32];          // binding: must equal the ballot's
  repeated DecryptedContest contests = 3;  // ascending index
}

// §3.6.6 decryption of one requested contest-data ciphertext.
message ContestDataDecryption {
  BallotLocator ballot = 1;
  bytes h_i = 2 [(width) = 32];
  uint32 contest_index = 3;
  bytes beta = 4 [(width) = 512];
  bytes proof = 5 [(width) = 64];          // c || v
  bytes data = 6 [(width_multiple) = 32];  // D
}

message UncastContestNonces {
  uint32 index = 1;
  bytes nonces = 2 [(width_multiple) = 32];  // xi_{i,j,k}: (m+L) selections x m options, selection-major
}

// The opening of an uncast pre-encrypted ballot (§4.3: "returns the encryption nonces"; Q28).
message UncastNonceRelease {
  BallotLocator ballot = 1;                  // a PreEncryptedUncastBallot
  bytes h_i = 2 [(width) = 32];
  repeated UncastContestNonces contests = 3; // ascending index; every contest in v2.0
  bytes ballot_nonce = 4 [(width) = 32, (omittable) = true];  // xi_B in plaintext, only when opted in (Q28)
}

// ---- statements ---------------------------------------------------------------------------------

message ChainCloseStatement {
  bytes h_e = 1 [(width) = 32];
  bytes device_key = 2 [(width) = 33];   // kind byte || H_DI
  string device_id = 3;
  uint32 chaining_mode = 4;
  uint64 ballot_count = 5;
  bytes codes_root = 6 [(width) = 32];   // MTH over the section's confirmation codes, chain order
  bytes closing_hash = 7 [(width) = 32, (omittable) = true];  // H-bar; iff simple chaining
  google.protobuf.Timestamp closed_at = 8;
}

message SectionSealStatement {
  bytes h_e = 1 [(width) = 32];
  bytes device_key = 2 [(width) = 33];
  uint64 item_count = 3;                 // l + 2 (header and close)
  bytes section_root = 4 [(width) = 32];
}

message PrefixCheckpointStatement {
  bytes h_e = 1 [(width) = 32];
  bytes device_key = 2 [(width) = 33];
  uint64 ballot_count = 3;
  bytes codes_root = 4 [(width) = 32];
  google.protobuf.Timestamp at = 5;
}

message RecordStatement {
  RecordPhase phase = 1;
  bytes root = 2 [(width) = 32];
  bytes h_e = 3 [(width) = 32];
  uint32 format_major = 4;
  uint32 format_minor = 5;
  google.protobuf.Timestamp signed_at = 6;   // §3.7 "together with the date"
  string signer_role = 7;
}

// ---- digest leaves ------------------------------------------------------------------------------

message TocEntry {
  SectionType section_type = 1;
  bytes key = 2;
  bool critical = 3;               // fixed per standard section type (design §4.5: true for every
                                   // v2.0 type); for a type the reader does not know (vendor, or a
                                   // later minor's), taken from the claimed TOC entry
  uint64 item_count = 4;
  bytes root = 5 [(width) = 32];   // the section's Merkle root
}

message ConfirmationCodeLeaf {
  bytes code = 1 [(width) = 32];   // H_C
}
```

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
  both: the index drives V13's ciphertext lookup, and the label is compared in V14, so a mislabelled field fails 14.D
  rather than surfacing as a 13.x crypto failure against the wrong ciphertext.
- **No device id on ballots.** It comes from the section. The domain `EncryptedBallot.DeviceId` is filled in from
  `DeviceHeader` on decode, which also removes the "ballot names another device" failure class.
- **`MaximumCount` is not stored.** S10a publishes the per-contest `cast_weight`, and `MaximumCount` is
  `cast_weight × MaximumValue`, computed. V9 compares `cast_weight` with the recomputed value (`9.structure`).
- **The header holds the format version and the election facts the manifest lacks** (follow-up #9, "Only what isn't
  in manifest"; spec §3.7 bullet 1: "Information sufficient to uniquely identify and describe the election, such as
  date, location, election type, etc. (not otherwise included in the election manifest)"). The manifest model has
  only an election id, contests, styles, the chaining mode and hash trimming. `ManifestSerializer` refuses unknown
  properties, so a jurisdiction cannot put the date or location there. `election_info` is therefore the only signed
  place for them. Its registry leaves out anything the manifest already says. It is a sorted repeated message, not a
  `map` (S2), so its bytes are unique (D7). No verification reads it. Producer software, creation time and notes are
  not election facts. They go in `meta.json`, outside the root, so that two writers of the same content produce one
  root. NQ-4 confirms this reading with the user; the alternative is to extend the manifest model.
- **`DeviceHeader.chaining_mode` repeats the manifest's mode**, the one repetition of a manifest value. Spec 8.D/16.E
  are phrased per device ("If the device used the no-chaining mode"), so the device states its mode, and the
  verifier checks that it equals the manifest's (`8.structure`/`16.structure`).
- **The manifest is stored byte for byte as entered** (#19: "it should be output to the election record exactly as it
  was entered"). `ManifestFile.content` is exactly the H_B input of eq. (5). The record path never re-encodes it:
  `ManifestSerializer` only parses it (strict reading, then `Manifest.Validate`), and its writer's output has no
  canonical status. `media_type` names the parser, `"application/vnd.electionguard.manifest+json;format=1"` for S10a's
  reading rules. "As entered" therefore means byte for byte for any document that parser accepts (#19: "need only be
  a valid document"). Whitespace, member order and number spelling survive. A document the parser refuses, such as one
  that starts with a UTF-8 BOM or has an unknown property, would make the record unverifiable, so
  `WriteSetupAsync` parses the bytes first and refuses them. It never strips or rewrites them. A carrier may also write
  the manifest as a plain file, `setup/manifest.json`, outside the root, for people to read; a verifier that finds one
  checks that it is byte-identical to `ManifestFile.content` (`R.container`).
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
- A pre-encrypted uncast item costs (m+L)·(m·1,024 + 32) B per contest plus short codes and framing (30,912 B at
  m = 5, L = 1). Its release adds (m+L)·m·32 B. NQ-2 is about this cost.
- **Large items.** An uncast item grows with m² per contest: about 0.95 MB at m = 30, L = 1, and about 11.3 MB at
  m = 100, L = 10. A multi-contest uncast ballot can therefore approach the 64 MiB frame ceiling (§5.2), which the
  writer enforces. NQ-2's compact form removes the case.

### 4.8 Validity layers and failure attribution (normative, so verifiers in all languages agree)

Checks run in three layers, in this order, and each failure carries a fixed code:

1. **Encoding** (`R.encoding`): the wire rules W1-W8 and decode rules D1-D7 (D6 failures are `R.container`). The item's leaf hash is still computed
   from the bytes as read, so the root check still runs. The item is then opaque, and its verifications are
   `NotEvaluable` for it.
2. **Range** (lettered where the spec assigns a letter; #11): a fixed-width value outside Z_p or Z_q. S10a's
   `FromCanonicalBytes` throws on such a value, which made 6.B, 6.C and 2.B unreachable from a deserialized record.
   The record reader instead decodes the bytes raw and reports:

   | Value | Code |
   |---|---|
   | ballot and pre-encryption-vector α, β (V6 covers every selection encryption, spec §4.5), uncast vectors included | 6.A |
   | selection range-proof c, v | 6.B, 6.C |
   | limit, undervote-difference and null-vote proof c, v | 7.B, 7.C |
   | guardian commitments, κ_i | 2.A |
   | guardian responses v_{i,j}, v̂_{i,j} | 2.B |
   | guardian challenges c_i, ĉ_i (no letter checks their range; H_q's output is below q, so a stored c ≥ q can never equal the recomputed one) | 2.C |
   | tally v | 10.A |
   | tally c (same reasoning as c_i) | 10.B |
   | contest-data decryption v | 12.A |
   | contest-data decryption c | 12.B |
   | any other value | `N.structure`, where N is the first verification that consumes it (for example ξ ≥ q in a challenged decryption is 13.structure; K ≥ p is 3.structure) |

   The final per-field table is fixed in S10b-4 against the Verify classes' current lettering. An item with a range
   failure is not passed to the domain verifiers, which take `IntegerModP` values. It is still digested,
   chain-walked (H_C and B_C are hashes) and entered into 5.A.
3. **Structure** (`N.structure`): counts fixed by the manifest (k, k+1, R+1, L+1, m+L, the style's contests),
   required messages and strings (a missing `encrypted_ballot_nonce`, `ballot_style` or `device_id`), the section placement
   rules of §4.5, and today's `BallotStructure` rules.

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
  sort by (device key, statement item type, SHA-256 of `statement`).
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
§4.4 check and D1-D7 on `statement` as a `RecordItem`. It also checks that the set member is a statement type: 40-42
in `device_attestation`, 43 in `record_signature`. Any failure is `R.attestation` or `R.signature`. Without this, a
non-canonical statement, or one with an unknown field, could carry a valid signature over bytes that different
runtimes decode differently.

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
  - **JSON:** D parses each line with a proto3 JSON parser, applies D1-D7, and encodes the message canonically.
- Section roots, the TOC and the phase roots are pure functions of L. So **two physical records are equivalent iff
  they decode to the same L, iff their record roots (and phases) are equal.** "If" holds by construction; "only if"
  holds because the decoders are injective and SHA-256 is collision-resistant.
- `egrecord digest <path>` prints the phase roots of any representation, and printing the same roots is the
  equivalence check. A converter is correct iff it preserves every phase root.
- **JSON bytes are never hashed.** A JSON reader hashes the canonical protobuf encoding of what it parsed.
- **Opaque content survives conversion.** `VendorItem.value` and `Extension.value` are `bytes`, so they cross every
  representation unchanged. Unknown *fields* cannot: the proto3 JSON mapping has no form for them. So a converter
  that meets content it does not fully understand (an unknown field, oneof member or enum value) **refuses**
  (`R.version`) rather than dropping it, and no conversion can change a root.

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

  64 MiB covers every regular ballot and every pre-encrypted item up to about m = 100 options per contest (§4.7). An
  uncast item larger than that is refused by the writer; NQ-2's compact form removes the case.

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
  of the torn tail. It truncates the tail and rebuilds the frontier by rescanning. The previous H_C for `DeviceChain`
  is recovered from the last complete item. A corrupt middle item, or a zero-length frame followed by anything other
  than zeros, is not repaired: the section stays unsealable until an operator decides (deliberate). A verifier never
  repairs anything; for it a zero-length frame anywhere is `R.container`.

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
- **Names are exact.** Paths use `/`, are relative, and contain no `.` or `..` segment, no backslash and no empty
  segment. They are compared byte for byte. Two names that are equal under Unicode case folding are `R.container`,
  because they collide when extracted on Windows or macOS.
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
  taking ZIP64 extra fields into account. Any disagreement is `R.container`, so no reader can see different content
  from another reader. Duplicate entry names, encrypted entries and methods other than STORED and DEFLATE are
  `R.container`. Directory entries are optional and ignored. Every other entry follows §5.3.1.
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
  back the record-side `IPublishedCastBallots` (Q31).
- **Offset sidecars:** ordinal → byte offset per segment, for random access.

### 5.7 Conformance artifacts (`test/egrf/`)

- **Golden vectors** (`test/egrf/vectors/`):
  - every item type: canonical bytes (hex), proto3 JSON and leaf hash. The JSON is compared by structure: parse
    both sides and compare members and values. The feasibility run's comparison matched C# against Python for 31 of
    31 items. Bytes and leaf hashes are compared byte for byte. The feasibility vectors
    (`vectors.json`, `negatives.json`) seed this set;
  - MTH roots for n = 0..17 and 1,000, cross-checked with the RFC 9162 test vectors;
  - three complete small records, each as a protobuf directory, a JSON directory and a `.zip`, all with the same
    roots: regular with no chaining; simple chaining with contest data and cast, challenged and spoiled ballots;
    pre-encrypted with cast, returned uncast and never-returned uncast ballots and their releases.
- **Negative vectors**, one per rule, each with its expected code: an overlong varint (in a tag, a length and a
  value), fields out of order, a singular field written twice, a default-valued field written explicitly, an unknown
  field, a known field with the wrong wire type, a wrong width, an absent non-omittable width field, a timestamp with
  sub-millisecond nanos, negative seconds, negative nanos, `UNSPECIFIED` status, an undeclared enum value, a
  `uint32` ≥ 2^31, a `uint64` ≥ 2^63, ill-formed UTF-8, an empty `RecordItem`, unordered extension tags, unordered or
  duplicate `election_info` keys, a non-canonical `SegmentHeader`, a frame over 64 MiB, a zero-length frame, a torn
  tail (cut short, and zero-filled), a segment gap, a path that disagrees with its `SegmentHeader`, an uppercase-hex
  path, an unlisted file, a duplicate zip entry, a zip local header that disagrees with the central directory, a
  non-canonical signed statement and one with a non-statement member, and a TOC entry whose `critical` bit
  disagrees with §4.5. JSON negatives: a duplicate member, a JSON-name and proto-name alias pair, two members of one
  oneof, and an unknown member. Plus one per `R.*` code and join rule.
- **The Python reference reader** (`test/egrf/egrf_ref.py`) is Python 3, standard library only, in the spirit of the
  KAT oracle (`test/kat/eg_kat.py`). It transcribes the schema by hand from the `.proto` into a table (field numbers,
  types, widths), implements Method A (§4.4), the length-delimited segment reader, the Merkle tree and the phase
  roots, and reproduces the golden roots and every negative vector's verdict. A C# test writes
  `test/egrf/schema.json` from the compiled descriptor (custom width options included), and CI fails if the Python
  table and that file disagree. This is the acceptance test for the formal spec: anything the Python reader needs that
  the spec does not say is a gap in the spec. It also demonstrates G-7: no protobuf runtime is required.

---

## 6. Streaming verification model

### 6.1 Phases of a run

| Step | Reads | Runs | Gate |
|---|---|---|---|
| A. Record | the carrier's file or entry list, `toc`, the header | layout and zip consistency (§5.3.1, §5.4; `R.container`); format version (`R.version`); phase and presence (`R.structure`) | An unknown major version or a layout failure stops the run. |
| B. Setup | sections 0x0001-0x0005 | V1 against `EGParameters`; parse the manifest from `ManifestFile.content` by media type (`ManifestSerializer`, strict, then `Manifest.Validate`); V2 per guardian, in parallel; V3; V4. Build `EncryptionRecord` from claims (`ElectionPublicKeys.FromKeys`, manifest from bytes). | A V1 failure, an unparseable manifest or a V4 failure stops all cryptography (later outcomes `NotEvaluable`). Digests and structure still run to the end. |
| C. Join prep | `device_attestations` and the four join sections (`contest_data_requests`, `challenged_ballot_decryptions`, `contest_data_decryptions`, `uncast_nonce_releases`) | A **framing pre-scan**: read each item's leading locator (field 1 of the inner message, within its first 60 bytes) to check sort order (`R.order`), and record the offset where each device key's run begins (O(D)). Load the attestation statements per device (O(D)). | |
| D. Ballots | device sections, in parallel across sections | per §6.2 | Findings are collected, and the run continues. |
| E. Tally | `encrypted_tally`, `decrypted_tally` | Merge the V9 partials and compare (9.A, 9.B), and each contest's `cast_weight` (`9.structure`). Header counts against recounted cast ballots and weight (`R.summary`). V10 per field, in parallel. V11.A-C. V11.D from the bitset of contests on submitted ballots. | |
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
  | `EncryptedBallot`, `SPOILED` | nothing beyond the first row: not tallied, never decrypted |
  | `PreEncryptedCastBallot` | 5.B, 6, 7, 15, 16.A-C, 17, V9 fold, 11.D |
  | `PreEncryptedUncastBallot` | 5.B, 6.A at the range layer only (§3.2), 16.A-C, 17, 19, 11.D; take the release at this locator from the cursor and run V18 |

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
- Every `PreEncryptedUncastBallot` (returned or never returned, #5) has exactly one `UncastNonceRelease` with equal
  `h_i`, and every release names an uncast item (`18.structure`).
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
  O(D) offsets, and reads stay sequential within each run, which suits HTTP range reads.
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
| Joins | one item per cursor per worker, plus O(D) run offsets | ~2 KB × 4 × W + ~50 B × D | < 1 MB |
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

- the record identity: the claimed TOC root, or the section heads for a live record;
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
| `GuardianPreliminary` | aggregated | §3.6.1: V1-V9 and the request rules. It reports two sets: the ballots the guardians will open (exactly the `CHALLENGED` regular ballots, through `TallyGuardian.DecryptBallotNonce`), and the uncast pre-encrypted ballots that need a release from the out-of-scope recording tool (§1; NQ-5 asks whether guardians should open these too). Takes `ExpectedAggregatedRoot`, obtained out of band, so guardians decrypt exactly what they verified (Q36). Returns a `VerifiedAggregate` (§8.3) that tally decryption from a record requires, closing the S10a carry-over "a tally read back cannot be decrypted before Verification 9". |
| `BallotCorrectness` | any | for chosen locators or confirmation codes: 5.B, 6, 7, 8.A/8.B or 16.A-C/17/18/19, 13/14 where applicable, plus an inclusion proof to the root. Reads only those items, through derived offsets or a scan. |
| `Custom` | any | any subset of 1-19 (used by the structure-only GB tests) |

**Report semantics:**

- **Outcome per verification** (1-19): `Passed`, `Failed`, `NotApplicable` (for example 15-19 with no pre-encrypting
  section), `NotEvaluable` (blocked by an earlier failure) or `NotRun` (outside the profile).
- **R-codes:** `R.container`, `R.encoding`, `R.order`, `R.structure`, `R.version`, `R.extension`, `R.root`,
  `R.summary`, `R.attestation`, `R.signature`.
- **`Complete`** is false whenever the reader skipped a non-critical unknown section, field, oneof member or extension
  (§7). **`Passed` requires no failures and `Complete = true`.**
- **Findings** carry `SubSection` (the existing `VerificationFailedException` convention: "6.D", "13.structure",
  "R.order"), the verification number, the section, the locator, id_B in hex, the contest and field index, and a
  message. They are ordered deterministically: by step (§6.1), then by canonical record order, then by sub-section.
  They are capped at `MaxFindings` (default 10,000); the verdict is already Failed when the cap truncates.
- **Default is collect-all.** At about 1,000 ballots/s, a run that stopped at the first failure would waste hours.
  `StopOnFirstFailure` is available.
- **Also reported:** all four phase roots, attestation and signature results, unknown content skipped, and statistics
  (N by kind and status, per-device counts, bytes, per-step timings).

---

## 7. Versioning and extension

| Layer | Mechanism | A reader that does not understand it |
|---|---|---|
| Spec version | `Parameters.version` (the exact eq. 4 bytes), checked by 1.A | V1.A fails |
| Format major | `RecordHeader.format_major`, repeated in `SegmentHeader` and `RecordStatement`; the `.proto` package is `electionguard.egrf.v<major>` | refuses the record (`R.version`, stop) |
| Format minor | `RecordHeader.format_minor` | reads in compatible mode (below) |
| Section type | new `SectionType` values within a phase band; `TocEntry.critical`, fixed per type by that minor's §4.5 table (later tallies arrive this way, §4.5) | the bit comes from the claimed TOC (§4.5). Critical: `R.version` failure. Non-critical: items digested, `Complete = false`. |
| Item type | a new `RecordItem` oneof member | in a section it must verify: that item's checks are `NotEvaluable`, with `R.version`. In a non-critical vendor section: digested, `Complete = false`. |
| Field | a new field number, append-only (S6) | see "Older readers" below |
| Extension | `RecordItem.extensions` (NQ-1), `critical` per entry | critical: `R.extension`, the item is not evaluated. Non-critical: digested, reported, `Complete = false`. |
| Files | `SegmentHeader.magic` and `format_major` | `R.container` |

Rules:

- A **major** change alters an existing field's meaning or type, the profile, the digest rules or the fixed widths.
  A new spec version that changes published objects means a new major, and a new `.proto` package.
- A **minor** change only adds: section types, oneof members, fields (numbered above the message's existing fields),
  enum values or registered extension tags. It never changes the meaning of an existing check, and a field it adds
  defaults to "absent" with the old meaning.
- **Writers MUST use the lowest representation that can carry the content.** A new field is written only when the
  content needs it (otherwise it is absent by W2), and a new oneof member only for content the old one cannot carry.
  So an old reader keeps verifying every record that does not use the new capability.
- **Older readers.** A reader that knows minor m and reads a record of minor m' > m checks the items with Method A:
  for an unknown field it still checks order, wire type validity, minimal varints and exact lengths, but cannot check
  its default or width, so it digests the item as stored and sets `Complete = false`. In JSON an unknown member cannot
  be parsed without being lost, so the reader stops with `R.version`. Neither path reports a pass with unread content
  (G-6), and the roots computed from the protobuf representation are still exact.
- **Vendor sections** (0x8000-0xFFFD) are final-phase, digested and never verified. The library's writer marks them
  non-critical unless told otherwise, and readers take the bit from the claimed TOC (§4.5).
- **Election options** (chaining mode, Ω, supplemental fields, b_Λ) come from the manifest. The format has no
  feature flags.

---

## 8. C# implementation

### 8.1 Codec: Google.Protobuf, generated from the normative `.proto`

**Decision: Google.Protobuf runtime, with C# generated at build time from `egrf.proto` by Grpc.Tools**
(`<Protobuf Include="..." Access="Internal" GrpcServices="None" />`; Grpc.Tools is a build-only dependency).
protobuf-net is retired with the old DTO tree (S10b-16), so Core ends with one serialization dependency.

Why not protobuf-net, which Core uses today:

- **The `.proto` is normative** (follow-up: "The `.proto` schemas are normative"). Generating C# from it means the
  field numbers, types and names in C# cannot drift from the published schema. protobuf-net is code-first: the schema
  lives in attributes on hand-written classes, and a `.proto` can at best be exported from them. Both of today's
  protobuf hazards come from that model: the "add a field in both the domain type and its DTO" rule (CLAUDE.md,
  Serialization) and the dormant nonce copy at line 83.
- **Determinism the profile can rely on.** protoc's C# generator writes fields in field-number order, omits proto3
  defaults, writes a set oneof member even when it is default, and has `WithDiscardUnknownFields(true)` for Method B
  (§4.4). In protobuf-net, ordering, default omission and packing are per-attribute choices, and keeping unknown
  fields needs `Extensible`.
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

- `src/ElectionGuard.Core/Record/`: the generated types, the canonicality check, the mappers, Merkle, the carriers,
  the JSON projection, the writer and the reader.
- `src/ElectionGuard.Core/Verify/ElectionRecordVerifier.cs`: the verify-everything entry point.
- `src/ElectionGuard.Verifier/` (new): the `egrecord` CLI (`verify | digest | convert | diff | prove | show`).
  `ElectionGuard.Administration` will be the main writer when it exists.
- `proto/electionguard/egrf/v2/egrf.proto`: the schema, shared by every implementation.

### 8.3 API sketch

```csharp
namespace ElectionGuard.Core.BallotEncryption;

/// The values equal the record's BallotStatus enum numbers.
public enum BallotStatus
{
    Unrecorded = 0,   // in memory only: no decision yet. Never written; a writer refuses it. (was NotSubmitted)
    Cast = 1,
    Challenged = 2,
    Spoiled = 3,      // in the record, neither cast nor challenged (#4). Not tallied, never decrypted.
}
// EncryptedBallot.RecordStatus accepts Cast, Challenged or Spoiled, once, as today.
```

```csharp
namespace ElectionGuard.Core.Record;

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
public static class CanonicalProtobuf
{
    /// Method B (§4.4) on the hot path; Method A when the record's minor is newer than this library's.
    public static CanonicalCheck Check(ReadOnlySpan<byte> item, ushort recordFormatMinor);
}
public readonly record struct CanonicalCheck(bool IsCanonical, string? Rule /* "W4", "D1", ... */, bool HasUnknownContent);

// Mappers (internal): domain <-> generated message, decoding raw Z_p/Z_q bytes and returning range and structure
// findings instead of throwing (§4.8). The uncast mapper splits PreEncryptedUncastBallot into the printed item and
// its UncastNonceRelease, and joins them on read.
public readonly record struct RawZp(ReadOnlyMemory<byte> Bytes) { public bool TryToModP(out IntegerModP value); }
public readonly record struct RawZq(ReadOnlyMemory<byte> Bytes) { public bool TryToModQ(out IntegerModQ value); }

// ---- Merkle (RFC 9162) ---------------------------------------------------------------------------------------
public sealed class MerkleFrontier                                // O(log n) state; serializable for checkpoints
{
    public static Sha256Digest LeafHash(ReadOnlySpan<byte> canonicalItem);
    public void AppendLeafHash(in Sha256Digest leaf);              // workers hash; the sequencer appends
    public long Count { get; }
    public Sha256Digest Root();
}
public static class MerkleProofs
{
    public static bool VerifyInclusion(Sha256Digest leaf, long index, long size, Sha256Digest root, IReadOnlyList<Sha256Digest> path);
    public static bool VerifyConsistency(long oldSize, Sha256Digest oldRoot, long newSize, Sha256Digest newRoot, IReadOnlyList<Sha256Digest> proof);
}
public sealed record TocEntry(RecordSectionType Type, ReadOnlyMemory<byte> Key, bool Critical, long ItemCount, Sha256Digest Root);
public sealed record TableOfContents(IReadOnlyList<TocEntry> Entries)
{
    public RecordPhase Phase { get; }
    public Sha256Digest PhaseRoot(RecordPhase phase);
    public bool Extends(TableOfContents earlier);
}

// ---- items not already in the domain model ------------------------------------------------------------------
public sealed record DeviceHeader(DeviceChainBallotKind Kind, string DeviceId, VotingDeviceInformationHash DeviceInformationHash,
    ChainingMode ChainingMode, ConfirmationCode? InitialHash);
public sealed record DeviceClose(long BallotCount, ChainingField? ClosingChainingField, ConfirmationCode? ClosingHash,
    DateTimeOffset? ClosedAt);
public sealed record ContestDataRequest(BallotLocator Ballot, SelectionEncryptionIdentifierHash IdentifierHash, int ContestIndex);
public sealed record EncryptedTallyHeader(long CastBallotCount, long TotalCastWeight);
public sealed record ElectionInfo(string Key, string Value);     // §3.7 bullet 1; registry keys or "x-" (D7)

public sealed record RecordSetup(RecordFormatVersion Format, IReadOnlyList<ElectionInfo> ElectionInfo, CryptographicParameters Parameters, GuardianParameters GuardianParameters,
    ParameterBaseHash ParameterBaseHash, ManifestFile ManifestFile, string ManifestMediaType, ElectionBaseHash ElectionBaseHash,
    IReadOnlyList<GuardianPublicView> Guardians, ElectionPublicKeys Keys, ExtendedBaseHash ExtendedBaseHash)
{
    public EncryptionRecord ToEncryptionRecord();                  // Manifest parsed from ManifestFile (S10a); keys via FromKeys
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
        IReadOnlyList<ElectionInfo> electionInfo, CancellationToken ct = default);        // parses the manifest bytes first; fixes R_setup
    public ValueTask<DeviceSectionWriter> OpenDeviceAsync(DeviceHeader header, CancellationToken ct = default);   // create or resume
    public ValueTask AddDevicePartAsync(string devicePartDirectory, CancellationToken ct = default);  // validates, copies bytes
    public ValueTask AddAttestationAsync(SignedStatement attestation, CancellationToken ct = default);
    public ValueTask<TableOfContents> SealVotingAsync(CancellationToken ct = default);          // all devices closed -> R_sealed
    public ValueTask<TableOfContents> SealAggregatedAsync(EncryptedTally tally,
        IEnumerable<ContestDataRequest> requests, CancellationToken ct = default);             // -> R_aggregated
    public ISortedSectionWriter<DecryptedChallengedBallot> ChallengedDecryptions { get; }   // throw before R_aggregated (Q36)
    public ISortedSectionWriter<DecryptedContestData> ContestDataDecryptions { get; }
    public ISortedSectionWriter<PreEncryptedUncastBallot> UncastNonceReleases { get; }      // must match the sealed printed item
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
    public ValueTask AppendUncastAsync(PreEncryptedBallot printed, CancellationToken ct = default);  // returned uncast or never returned (#5)
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

// ---- signatures ----------------------------------------------------------------------------------------------
public sealed record SignedStatement(ReadOnlyMemory<byte> Statement, string Algorithm, ReadOnlyMemory<byte> KeyId,
    ReadOnlyMemory<byte> SignerKey, ReadOnlyMemory<byte> Signature, ReadOnlyMemory<byte> TimestampToken);
public interface IStatementSigner { string Algorithm { get; } ValueTask<SignedStatement> SignAsync(ReadOnlyMemory<byte> statement, CancellationToken ct = default); }
public interface ISignatureVerifier { string Algorithm { get; } SignatureCheck Verify(SignedStatement signed); }   // EcdsaP256Sha256 ships first
```

(`PreEncryptedCastBallot` items are appended through `AppendAsync(EncryptedBallot)`, since a cast pre-encrypted
ballot is an `EncryptedBallot` with `PreEncryptedContests`, S9.)

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
  - `BallotStatus.Spoiled`, and `Unrecorded` as the new name of the in-memory zero value (S10b-1).

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

S10a is committed (c4f1093). S10b code starts once the user approves this design and answers NQ-1 to NQ-6 (§12).
NQ-1 and NQ-4 shape the schema (S10b-2), NQ-2 the uncast mapper and writer (S10b-4, S10b-6), NQ-3 only S10b-13, NQ-6
only S10b-7. NQ-5 does not block S10b: it would be a later Core step on the guardian side. Every step
below is sized for one implementer and is one reviewable commit with the gate green: the full test suite, the KAT
families unchanged, and for steps that touch verification or serialization a perf smoke run plus
`compare --repeat 5` against a HEAD worktree baseline (single cold runs false-flag the allocation gate). Each step
updates the tracker.

### 9.2 Steps

| Step | Content | Tests |
|---|---|---|
| **S10b-0** Nonce hazard (first; independent) | Delete `EncryptionNonce` from `ProtobufEncryptedValueWithProofs` and `ProtobufEncryptedValue` **and the line-83 copy** into the DTO | A reflection test that no serialization DTO has a nonce member; protobuf round trips unchanged |
| **S10b-1** Ballot status | `BallotStatus.NotSubmitted` → `Unrecorded` (0); add `Spoiled = 3`. `RecordStatus` accepts Cast, Challenged or Spoiled, once. `EncryptedTally.AddBallot` skips Spoiled as it skips Challenged (and still rejects Unrecorded). The guardians' nonce path and V13/V14 treat Spoiled as not challenged. The existing ballot serializers carry the new value until they retire. | Aggregation excludes spoiled ballots; a spoiled ballot's nonce request is refused; `RecordStatus` is once-only across all three; V5-V8 accept a spoiled ballot; serializer round trips of each status |
| **S10b-2** Schema and codegen | Move `egrf_v2.proto` to `proto/electionguard/egrf/v2/egrf.proto` (with the NQ-1 outcome); Google.Protobuf and Grpc.Tools in Core, generated types internal; a schema lint test enforcing S1-S8 on the compiled descriptor; a test that writes `test/egrf/schema.json` (numbers, types, labels, width options) | The lint test fails on a deliberately added map, `int32`, packed repeated scalar, out-of-order declaration, unannotated fixed-width field or regular field numbered inside a oneof's range (run against fixture descriptors) |
| **S10b-3** Canonicality checker | `CanonicalProtobuf.Check`: Method B (discard-unknown parse with each runtime's call from §4.4, D1-D7, re-serialize, compare) and Method A (descriptor-driven wire walk); the `SegmentHeader` check (D6) and the signed-statement check (§4.9); the first golden item vectors, seeded from the feasibility run's `vectors.json` and `negatives.json`, and every negative vector of §5.7 under `test/egrf/vectors/` | Each negative vector rejected with its rule by both methods; property tests: encode-then-check always passes; every single-byte mutation of a golden item is rejected or decodes to a different item, and Methods A and B never disagree |
| **S10b-4** Domain mappers | One mapper per item type; `RawZp`/`RawZq` and the §4.8 range table, fixed against the Verify classes' lettering; the uncast split and join (and NQ-2's compact form if accepted); `RecordSetup` | A **reflection completeness test** pins every public property of every recorded domain type to a schema field or an explicit exclusion list (nonces, the device id taken from the section, computed properties), replacing the "add it in both" hazard; domain → bytes → domain is the identity; values ≥ p and ≥ q give the lettered codes |
| **S10b-5** Merkle, TOC, phase roots | `MerkleFrontier`, `MerkleProofs`, `Sha256Digest`, TOC and phase-root functions, `Extends` | RFC 9162 published vectors; MTH for n = 0..17 and 1,000; inclusion and consistency proofs; frontier serialize/resume equals an uninterrupted run |
| **S10b-6** Directory carrier: writer and reader | Delimited `.binpb` segments and `SegmentHeader`; the 64 MiB frame ceiling on both sides; the §5.3.1 layout and discovery rules; `ElectionRecordWriter` phase gates; `DeviceSectionWriter` (final status required, `AppendUncastAsync`); `ResumeAsync` with torn-tail repair, zero-filled tails included; presence rules; `election_info` (D7); the optional `setup/manifest.json` copy | Write then read gives the same domain objects (S10a's strict round-trip tests ported); segment rollover does not change roots; a torn tail is repaired and a corrupt middle item refused; decryption and release writers throw before R_aggregated; R_setup ⊑ R_sealed ⊑ R_aggregated ⊑ R_final; a manifest copy that differs is `R.container`; the manifest bytes survive byte for byte (whitespace, member order and number spelling preserved), and a manifest the parser refuses (a BOM, an unknown property) is refused by `WriteSetupAsync`; an oversized item is refused by the writer and a hostile length by the reader before allocation; every §5.3.1 layout negative |
| **S10b-7** `.zip` carrier | `System.IO.Compression` writer (STORED protobuf entries, optional DEFLATE for JSON, ZIP64) and a seekable reader that checks every local header it reads against the central directory; a non-seekable `Stream` is spooled to disk (NQ-6) | Roots equal the directory's; any entry order is accepted; a duplicate entry, a local/central mismatch, an unlisted entry and a case-folding collision are each `R.container`; a DEFLATEd JSON record verifies with sequential join cursors; a > 4 GiB synthetic entry round-trips (manual or nightly) |
| **S10b-8** Streaming verifier pieces | `DeviceChainWalker`; `SpillingIdentifierSet`; `BallotAggregationVerifier.Merge` and standard-form export; merge cursors with run offsets | The walker agrees with `DeviceChainWalk` on every existing V8/V16 test; 5.A with planted duplicates at random positions, **adversarially skewed id_B prefixes** and a 1 MiB budget forcing spills; AVX-512 and scalar partials merged through the standard form equal one engine (`DOTNET_EnableAVX512F=0`) |
| **S10b-9** `VerifyAllAsync` | Steps A-F, profiles, report, attestation-content checks, resumable checkpoint, `VerifiedAggregate` and the `TallyAdmin.Decrypt` overload (S10a carry-over) | One test per R-code and per join rule (a missing challenged decryption, a decryption naming a cast or spoiled ballot, a missing or stray uncast release, an unmatched contest-data request); spoiled ballots excluded from V9 and included in 5.A and 11.D; a never-returned uncast ballot passes V16-V19 with its release; V9 `NotEvaluable` after a faulted aggregator; kill-and-resume gives the same report as one run; GuardianPreliminary on an aggregated record; a run over a `.zip` given as a stream whose `Seek` throws (spooled, same report) |
| **S10b-10** JSON projection, converter, diff | `JsonFormatter`/`JsonParser` plus duplicate-member refusal; `ConvertAsync`; `DiffAsync` | protobuf → JSON → protobuf is byte-identical; JSON → protobuf → JSON parses to the same structure (byte-identical only within one runtime, §5.5); the four representations of each golden record give identical roots and identical `VerificationReport`s, findings included; content with an unknown field is refused for conversion; JSON negatives: a duplicate member, a JSON-name/proto-name alias pair, two members of one oneof, an unknown member, a wrong decoded width, a `uint64` ≥ 2^63, negative `Timestamp` nanos, an undeclared enum name |
| **S10b-11** Attestations and signatures | Statements, `IStatementSigner`, `ISignatureVerifier` (`ecdsa-p256-sha256` first; others pluggable), policies | Statements signed and verified; a tampered count, codes root or status caught (`R.attestation`); dropping trailing ballots caught under both chaining modes when a chain close exists; a missing or invalid signature under each policy |
| **S10b-12** Python reference reader and golden records | `test/egrf/egrf_ref.py` (standard library; Method A, D1-D7, delimited segments with the frame ceiling, the §5.3.1 layout rules, Merkle, phase roots, `.zip` via `zipfile` with the local-header check), the three complete golden records in all representations, the schema-table diff against `test/egrf/schema.json` | CI runs `python test/egrf/egrf_ref.py --check`: every golden root reproduced and every negative vector's verdict matched |
| **S10b-13** TypeScript reader (only if NQ-3 is accepted) | `test/egrf/js/`: protobuf-es generated code (binary and the proto3 JSON mapping; not protobufjs, §5.5), Method B with `readUnknownFields: false`, D1-D7, `sizeDelimitedDecodeStream` with `readMaxBytes` set, Merkle roots | Reproduces the golden roots and negative verdicts in CI |
| **S10b-14** `ElectionGuard.Verifier` | New project; `egrecord verify | digest | convert | diff | prove | show` over the Core API | CLI tests on the golden records: exit codes, report output, `digest` equal across representations |
| **S10b-15** Migration of the consumers | `Program.cs` as in §8.5; egperf `writeRecord`/`verifyRecord` and the serialization phase on the item codec; `ElectionGuard.Testing.Cli` emits records; `test/data/*` regenerated | Console pipeline passes; perf smoke run and `compare --repeat 5` against a HEAD worktree baseline (allocation of the Google.Protobuf parse path checked here) |
| **S10b-16** Retire superseded code | Remove `ProtobufEncryptedBallotSerializer` and its `Protobuf*` DTO tree, the protobuf-net package, `IEncryptedBallotSerializer`, the JSON ballot serializer, `JsonElectionRecordSerializer` (**replaced** by the proto3 JSON projection; its per-object API has no use once records are read and written as a whole, and `egrecord show` prints any item as JSON), `JsonPreEncryptedBallotSerializer`, `JsonDeviceChainRecordSerializer`, `StrictBase64` and `EncryptedBallotShape` (folded into the mappers). `ManifestSerializer` stays as the manifest parser; its writer stays only as an authoring helper whose output has no canonical status. | No remaining reference; the full suite green; CLAUDE.md's Serialization bullet rewritten |
| **S10b-17** Live tailing (may be deferred) | `FollowLiveRecord`, prefix-checkpoint checking | Tail a record while a writer appends; a checkpoint mismatch is caught |
| **S10b-18** Documentation and publication | CLAUDE.md "Record" architecture bullet; a formal-spec skeleton generated from §4 and the `.proto`; register `width`, `width_multiple` and `omittable` in protobuf's global extension registry and replace the draft numbers 50001-50003 (a user action: it is a pull request to the protobuf project) | Review only; the lint test pins the registered numbers |

**No legacy importer.** v1's S10b-9 planned importers for today's JSON ballots, device chains and pre-encrypted
JSON. No election record has been published in those formats, and the fixtures are regenerated (S10b-15), so the
importer is dropped. That also settles the S10a carry-over about how it would treat unknown members.

**Step numbers the tracker cites from v1:** S10b-0a → S10b-0; S10b-6 (JSON negatives, duplicate member) → S10b-10;
S10b-9 (legacy importer) → dropped; S10b-12 (retire protobuf) → S10b-16.

### 9.3 Interaction with S10a

| S10a work | What S10b does with it |
|---|---|
| `ManifestSerializer` (strict reading, deterministic writing) | Parsing only on the record path (#19). Its reading rules are what `media_type` `...;format=1` names. H_B is over the stored bytes as entered. The writer stays an authoring helper with no canonical status. |
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
   keeps unknown fields, would disagree under Method B. Mitigations: Method A is normative and needs no runtime, the
   schema lint test keeps the `.proto` inside the profile, the golden and negative vectors arbitrate between
   runtimes, and the Python reader proves the rules are complete.
2. **Packed fixed-width lists are less self-describing.** A proof list is one base64 string in JSON, not an array of
   (c, v) objects. The width options and comments say how to slice it. This is the price of #3's size priority (about
   1.4 % of a ballot).
3. **Never-returned pre-encrypted ballots are expensive** in full form (§3.2, §4.7). NQ-2 offers the compact form.
4. **Device partitioning** puts grouping and print-order placement on whoever assembles the record. There is no
   global arrival order apart from `encrypted_at`. One huge device serializes only its cheap chain walk; decoding
   still runs in parallel.
5. **V5.A stays O(N).** It is 8 B per ballot, exact, and spills. 10^8 ballots need about 800 MB of temporary disk. A
   non-seekable input also needs disk equal to the record, because it is spooled (§5.4).
6. **Status, weight and timestamps are protected only by the root, signatures and section seals** (§6.6).
7. **Indices on encrypted ballots.** A ballot item is unreadable without the manifest. That is acceptable because the
   manifest is always in the record, and the tools print labels as a derived view.
8. **JSON is about 1.4 × protobuf and cannot carry unknown fields.** Distribute GB records as protobuf. A converter
   refuses content it does not understand rather than dropping it.
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
14. **The frame ceiling refuses some pre-encrypted elections.** A multi-contest uncast ballot with about m ≥ 100
    options per contest can exceed 64 MiB in full form (§4.7). The writer refuses it with a clear error. NQ-2's compact
    form, or a later minor that splits uncast items per contest, lifts the limit.
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
| #9 (Q-9) Election info | Follow-up: "Only what isn't in manifest" | §3.1, §4.6 (`RecordHeader.election_info`, limited to facts the manifest lacks; the reading is confirmed by NQ-4) |
| #10 (Q-10) Contest-data decryption | Follow-up: "Record the requested set" | `ContestDataRequest`, §6.2 |
| #11 (Q-11) Out-of-range values | "Out of range values are a problem for a verifier, not the election record format." | §4.3, §4.8 |
| #12 (Q-12) String ballot id | Follow-up: "Keep, optional" | `ballot_ref`, §4.6 |
| #13 (Q-13) Protobuf | "binary seems like a nonstarter ... protobuf over json" | §4, §8.1; the old DTO tree retires (S10b-16) |
| #14 (Q-14) Archive | "If .7z would save significant space, we can consider that, else .zip is the way to go." Measured: it does not. | §5.4 |
| #15 (Q-15) Code placement | "Yes": Core plus `ElectionGuard.Verifier` | §8.2 |
| #16 (Q-16) Multiple tallies | "We will do multiple tallies but we can wait and add it later." | §4.5 (the election-wide tally now; later tallies as new non-critical section types) |
| #17 (Q-17) Tally header | "Sure" | `EncryptedTallyHeader` |
| #18 (Q-18) Derived views | Follow-up: "Alongside, not signed" | §5.6 |
| #19 (S10a-1) Manifest bytes | "it should be output to the election record exactly as it was entered. The canonical serialization for the manifest is not as important." | §4.6, §9.3 |
| Profile | Follow-up: "Yes, canonical protobuf": normative `.proto`, field-number order, no maps, no unknown fields, fixed-width bytes, re-serialize to check, proto3 JSON, golden vectors and a Python reader | §4, §5.5, §5.7 |

Changed after review: single-pass verification of a `.zip` from a pipe (v1's Q-14 sub-question) is dropped. It turned
out to cost much more than the prescribed entry order (§5.4), and NQ-6 lets the user keep it anyway.

---

## 12. New questions

These arise from the protobuf choice, the answers above and review round 1. Each has options and a recommendation.

- **NQ-1 Per-item extensions under "no unknown fields".**
  - Options: (a) keep `repeated Extension extensions = 2047` on `RecordItem` (tag, critical flag, opaque bytes),
    so a vendor can attach data to one item, and a reader that does not know a critical tag refuses to evaluate the
    item; (b) no per-item extensions: vendor data goes only in vendor sections that reference items by locator, and
    standard additions come only as minor-version fields.
  - **Recommend (a).** It costs nothing when unused (an empty repeated field is absent), it survives conversion
    because the payload is bytes, and the critical flag keeps G-6 for vendor data. The cost is one decode rule (D5)
    and opaque base64 in JSON.
- **NQ-2 Compact form for uncast pre-encrypted ballots whose ξ_B is released.**
  - Context: #5 makes every never-returned printed ballot a full uncast record, (m+L)·(m·1,024 + 32) B per contest,
    about 31 KB at m = 5, L = 1, and over 11 MB at m = 100, L = 10 (§4.7). Very large ones can pass the 64 MiB frame
    ceiling (§5.2). A ballot's vectors, ψ and short codes are all deterministic in ξ_B (eqs. 113-121).
  - Options: (a) always the full printed content, as §4.3.1 describes; (b) allow a compact item when the release
    carries ξ_B: the device section keeps id_B, H_I, the style, C_ξB, per contest only (index, χ), H_C and B_C; the
    verifier regenerates every vector, ψ and short code from ξ_B, checks χ and H_C against the item (which proves the
    printed ballot is exactly the regenerated one), and runs V16-V19 on the regenerated content; (c) like (b), but
    required for never-returned ballots.
  - **Recommend (b).** About 0.8 KB instead of about 31 KB per contest, and no item comes near the frame ceiling.
    Verification costs the same, since V18 already recomputes every encryption. Releasing ξ_B on an uncast ballot
    reveals no voter choice: a pre-encrypted ballot encodes every option, and the voter's marks are on paper. Q28's
    opt-in stays for selective release. (b) changes how an uncast ballot is represented, not #5's decision: the ballot
    is still recorded as challenged and opened. Two departures go into the formal spec: from §4.3.1/§4.4's "posts ...
    the full set of pre-encryption vectors", and the voter-facing short codes coming from derived views.
- **NQ-3 A JavaScript conformance reader.**
  - Options: (a) the Python reference reader only; (b) also a minimal TypeScript reader in `test/egrf/js/`
    (protobuf-es generated code, Method B, Merkle roots) that CI runs against the golden vectors; (c) defer.
  - **Recommend (b).** The user named a JavaScript verifier as the case that must stay easy (#13). The feasibility run
    supports it. protobuf-es matched Python's canonical bytes for every item, and its `toJsonString` matched Python's
    JSON byte for byte. protobufjs also writes canonical binary, but it does not implement the proto3 JSON mapping
    (§5.5), so the reader uses protobuf-es. About 200 lines and one npm dev dependency prove it, and it doubles as a
    second runtime for Method B. It adds Node to CI and is not a product commitment.
- **NQ-4 Where §3.7's election-identifying facts live** (confirms follow-up #9).
  - Context: §3.7 bullet 1 asks for "information sufficient to uniquely identify and describe the election, such as
    date, location, election type, etc. (not otherwise included in the election manifest)". The user answered "Only
    what isn't in manifest". The tracker recorded that as "the header carries only format settings; descriptive facts
    live in the manifest". But the manifest model has no date, location or type field, and `ManifestSerializer`
    refuses unknown properties. On that reading, these facts would have no signed place in the record. This revision
    therefore reads the answer as the spec's parenthetical: the header carries those facts, but only the ones the
    manifest does not.
  - Options: (a) `RecordHeader.election_info`, a sorted list of (key, value) pairs from a small registry
    (`election_name`, `election_date`, `election_type`, `jurisdiction`, `location`, `administrator`) plus `x-` vendor
    keys, covered by the root and signatures and never verified (as now written, §4.6); (b) add optional fields for
    these facts to the manifest model and its strict reader, so they are bound into H_B, and keep the header to the
    format version; (c) carry none, and leave §3.7 bullet 1 to `meta.json`, outside the root.
  - **Recommend (a).** It follows the spec's wording and needs no change to the manifest model or to H_B's input.
    (b) is also sound, and puts the facts under H_B, but it changes the manifest schema that every encryptor reads.
    (c) leaves a §3.7 item unsigned.
- **NQ-5 Who opens uncast pre-encrypted ballots.**
  - Context: v2.0 requires a nonce release for every uncast pre-encrypted ballot, never-returned ones included (#5,
    #8). Spec p.66 derives the released nonces from ξ_B "after it has been decrypted as specified in Section 3.6.7",
    which is a guardian decryption of C_ξB. Q35 removed the guardians' pre-encrypted nonce path from Core, along with
    the issued list that guarded it against early opening. Q36 has since removed that concern: guardians decrypt only
    after voting is over and the record is sealed. Today, only the out-of-scope recording tool can supply the
    releases.
  - Options: (a) keep it out of scope: releases come from the recording tool, or from the printer's own database;
    (b) let `TallyGuardian.DecryptBallotNonce` also open a `PreEncryptedUncastBallot` taken from a sealed record the
    guardian has verified (the `VerifiedAggregate` of §6.9), refusing any id_B that is cast in that record (Q31's
    check), with no issued list and no once-only state.
  - **Recommend (b), as a step after S10b.** It is the §3.6.7 primitive the spec names for this, Q36 makes it safe
    without the machinery Q35 removed, and without it Core cannot complete its own records when printed ballots are
    never returned. It does not block S10b: the format is the same either way.
- **NQ-6 Single-pass verification from a pipe.**
  - Context: v1 kept single-pass reading of a `.zip` from a pipe and asked whether to drop it. Review round 1 found
    three problems. No stock zip library reads a non-seekable archive entry by entry (.NET buffers the whole input).
    Every writer would need extra rules. And the join sections would have to be buffered without bound, about 9.6 GB
    of uncast releases in the case worked in §5.4.
  - Options: (a) drop it: a non-seekable input is spooled to a temporary file, and HTTP range requests count as
    seekable (as now written, §5.4); (b) keep it, with normative writer rules (STORED entries with sizes and CRC in the
    local header, no data descriptors, a prescribed entry order), a hand-written local-header reader in every
    language, and join sections spilled to disk as they stream past.
  - **Recommend (a).** It costs disk equal to the record, and only when the input cannot seek. (b) adds format rules
    and per-language code for a case that a download followed by verification already covers.

---

## 13. Review notes (round 1 and the feasibility run, 2026-10-09)

Most findings were applied as given; the changes are listed in the Status note at the top and in each section. This
appendix records the findings that were rejected, narrowed or changed in scope, and why.

- **Manifest BOM (review 1, #19).** Applied by narrowing the S10b-6 test, not by relaxing the parser. A manifest with
  a BOM is refused by `WriteSetupAsync`, because the media type's parser refuses it. The bytes are never rewritten,
  so "exactly as entered" holds for every manifest the record accepts. Relaxing `ManifestSerializer` would change
  S10a's strict reading for one byte sequence, which no one has asked for.
- **Unknown manifest properties (review 1, #19).** Kept refused. "Need only be a valid document" is read as "valid
  under the media type's parser". The one need for extra properties found, the §3.7 election facts, is met by
  `election_info`. NQ-4 option (b) is the alternative.
- **Mandatory release for every uncast item (review 1, #8 extrapolation).** Kept. §4.4 publishes the nonces of every
  uncast ballot, #5 makes never-returned ballots uncast, and #8 requires every challenged ballot's opening. Who
  produces the release is NQ-5, not a format question.
- **V6 on uncast vectors (review 1).** Settled as 6.A at the range layer only. Spec p.65 applies V6 to "all individual
  selection encryptions within the selection vectors", but uncast vectors carry no range proofs, so 6.B-6.D cannot
  apply. Subgroup membership is implied by V18, which recomputes each α and β from the released nonces. An explicit
  ^q check per uncast value would add (m+L)·m·2 exponentiations per contest and decide nothing V18 does not.
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
