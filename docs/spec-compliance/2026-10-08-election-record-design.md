# ElectionGuard Record Format (EGRF) v1: the canonical election record (S10b design)

Status: synthesized design for user approval (Q37 part B). Nothing is implemented, and no repo file was edited.
Spec basis: ElectionGuard v2.1.0 §3.6.1 (p.45), §3.7 (pp.55-56), §4.4 (pp.62-63), §4.5 (pp.63-64) and §6
(pp.79-99). The non-normative EG 2.0 data serialization draft 0.0.1 is followed where it has rules and the
departures are noted. Nothing here changes a spec hash input (H_P, H_B, H_E, H_I, χ, H_C, B_C, ψ or any proof
challenge). Every byte that S1-S10a fixed stays where it is. The record format sits on top of those values.

## 0. How this design was assembled

Three candidate designs were scored by three judges. Streaming-first (EGREC) scored 8 + 8.5 + 7.5 = 24.0, and
canonical-encoding-first (EGRF) scored 8 + 8 + 8 = 24.0. That is a tie. EGRF is the skeleton because its fatal
flaws are cheaper to repair. Its free-text `producer` field inside the hash form and its lack of an extension
slot are each a one-line fix. Its section, TOC and phase-prefix root model also repairs streaming-first's fatal
flaw: a flat root that exempted the ballots section and gave Q36's "sealed before decryption" no mandatory
anchor. The grafts are:

| From | Grafted idea |
|---|---|
| EGRF | Fixed-schema binary grammar; sections + TOC; record root = MTH over TOC entries; phase roots that are prefixes of one another; section-presence rules; device part files byte-identical to their sections; keyed 64-bit V5.A prefixes; status-independent chain-close attestation plus an optional section seal; deletion of the protobuf nonce members |
| Streaming-first | `item_type ‖ item_version` prefix and extension lists with a critical bit on every item; stream files with a `first_ordinal` header; full locators (kind, H_DI, position) plus an H_I binding; carrier order not canonical (single-pass ZIP); resumable verifier checkpoint; retiring protobuf for the record; a strict decoder that doubles as the canonicality check; a JSON reader contract that never hashes JSON bytes |
| Verifier-first | An **aggregated** phase that seals the encrypted tally before any decryption (§3.6.1, Q36); verification profiles (GuardianPreliminary, BallotCorrectness); out-of-range values reported under the spec's lettered sub-checks; index *and* label on plaintext items; collect-all findings with a deterministic order |
| Judges | V5.A over every ballot (§4.5 p.64); 11.D over all submitted ballots; a recorded set of contest-data decryption requests (EGRF OQ-15); standard-form V9 partials across process boundaries; throughput sized from measured numbers; "unknown content means incomplete, never a full pass" in every representation |

Facts from the current tree override all three designs:

- **G40 landed in S10a** as `EncryptedBallot.EncryptionTimestamp : DateTimeOffset?`: nullable, UTC, truncated to
  the millisecond, JSON `encryptionTimestamp` in the fixed shape `yyyy-MM-ddTHH:mm:ss.fffZ`. The record's
  `encrypted_at` is therefore optional and uses the same millisecond semantics.
- **The manifest schema is no longer a shared blocker.** S10a's `ManifestSerializer` is strict and deterministic,
  and `EncryptionRecord.Manifest` is parsed from `EncryptionRecord.ManifestFile`. Its reading rules become the
  normative *manifest format 1*, named by a media type in the `ManifestFile` item (§4.4).
- **Measured verify cost.** The 2026-10-08 smoke runs (`perf/results/sethpc2023.jsonl`) show `VerifyBallots` at
  about 1,000 ms per 1,000 ballots at parallelism 32. That is about 1,000 ballots/s, or about 12 MB/s of binary
  ballots, so verification is CPU-bound by a wide margin. The estimates are about 17 min for 1M ballots, 2.8 h
  for 10M and 28 h for 100M. The encoding therefore affects storage, download size and random access, not verify
  time. These numbers are why resumable verification is in v1 and why findings are collected by default.
- **The protobuf nonce hazard is wider than reported.** `ProtobufEncryptedValueWithProofs.EncryptionNonce` and
  `ProtobufEncryptedValue.EncryptionNonce` (`IEncryptedBallotSerializer.cs` ~508 and ~532) have no
  `[ProtoMember]`, but the mapping at ~line 83 still copies `s.EncryptionNonce` into the DTO. Every selection
  nonce is one attribute away from being serialized.

---

## 1. Goals and non-goals

### Goals

1. **G-1 Canonical.** Every record item has exactly one byte encoding, called its *hash form*. The definition is
   precise enough that implementers in any language reach identical bytes with no judgment calls, and it can be
   lifted into a formal spec as is. Every digest, signature and equivalence claim is defined over hash forms,
   never over files.
2. **G-2 Complete.** Every item that §3.7 and §4.4 list is in the record, as is every input of Verifications 1-19.
   Bytes the spec hashes (the manifest file for H_B; ver, p, q, g, n, k for H_P; B_C; χ; ψ) are stored as exactly
   those bytes, and they appear as verbatim substrings of the item bytes.
3. **G-3 GB-scale.** The format handles 10^6-10^8 ballots (12 GB to 1.2 TB in binary). It can be written while
   the election runs, one device at a time. Verification streams with memory bounded independently of N, except
   for one stated term (V5.A, 8 B per ballot, which spills to disk). It runs in parallel and across machines, and
   it can be resumed.
4. **G-4 Many representations, one meaning.** Binary and JSON encodings, each in a directory or a ZIP64 archive.
   Two representations are equivalent if and only if they have equal root digests, and converters must preserve
   the root.
5. **G-5 Integrity hooks.**
   - Phase roots: setup, sealed, aggregated and final. Each is a prefix of the next, with RFC 9162 consistency.
   - Detached record signatures with a signing date (§3.7).
   - Per-device chain-close attestations (S8b) and optional mid-election prefix checkpoints.
   - Merkle inclusion proofs for voters looking up confirmation codes.
6. **G-6 Versioned and extensible.** No reader can report a full pass while content it did not understand went
   unchecked, and this holds identically in every representation.
7. **G-7 Implementable elsewhere.** A verifier in another language needs about 1-2 KLoC on top of SHA-256 and a
   bignum library, with no schema compiler, protobuf runtime or CBOR library.

### Non-goals

- Changing any spec hash input.
- Key management, PKI and trust anchors. The format carries signatures; who is trusted is verifier
  configuration.
- Voter-facing presentation (§4.4.1). Derived views are regenerable and outside the root.
- Guardian-to-guardian traffic: encrypted shares, partial decryptions, commitment and response messages. These
  are not in §3.7's list, and a vendor section can carry them.
- Guardian-private data: secret keys, shares, the nonces of cast ballots, ξ_B of challenged ballots, and the
  combined pre-encryption nonces of cast ballots. **No item type has a field for any of them, so no
  representation can carry one.**
- Pre-encryption tools (Q35). The record holds pre-encrypted ballots only as published inputs.
- Transport compression. Ciphertexts do not compress. Carriers may be wrapped in zstd for transfer, and digests
  are always over the uncompressed hash forms.

---

## 2. Concepts

| Term | Meaning |
|---|---|
| Item | One record value: a ballot, a device header, a tally contest, and so on. Its hash form is `u16 item_type ‖ u16 item_version ‖ body ‖ extensions` (§4.2). |
| Section | A typed, keyed, ordered sequence of items. A record is the list of its sections in canonical order (ascending type, then key bytes). |
| Phase | The protocol stage a section belongs to: setup, voting, aggregated or final. It is the section type's high byte (§4.3). |
| Device section | The section of one device, keyed by `kind ‖ H_DI` (33 bytes). It holds `DeviceHeader`, then the device's ballots in chain order, then `DeviceClose`. It **is** §3.7's "ordered list of the ballots encrypted by each device". |
| Locator | `(kind, H_DI, position)`, with position 1-based (the spec's j). It is a ballot's canonical address. |
| TOC | The table of contents: one `TocEntry` per section, giving (type, key, flags, item count, Merkle root). The record root is the MTH over the TOC entries. |
| Phase root | The MTH over the TOC entries of every section whose phase is at or before a given phase. |
| Representation | Binary (hash forms verbatim) or JSON (a lossless projection). |
| Carrier | A directory tree or a ZIP64 archive. |
| Derived view | A regenerable file outside the root: lookup indexes, offset sidecars, inclusion proofs. |

---

## 3. Record contents mapped to the spec and to the verifications

### 3.1 §3.7 The Election Record (pp.55-56)

| §3.7 item | Record location | Consumed by | Note |
|---|---|---|---|
| Information that identifies the election (date, location, type, ...) not in the manifest | `RecordHeader.election_info`: key/value pairs, strictly ascending by key | none (covered by the root) | Key registry in §4.4; open question Q-9 |
| The election manifest file | `ManifestFile.bytes`: the exact H_B input of eq. (5), with `media_type` | V1.F; parsed (manifest format 1) for everything else | The parsed `Manifest` is only ever derived from these bytes (S10a binding) |
| p, q, r with p = qr + 1 | `Parameters.p/q/r`, raw `Bytes(512)/Bytes(32)/Bytes(512)` | 1.B, 1.C | Not `Zp`/`Zq`, which would reduce p and q to 0 (decision G1). r is not checked (v2.1 dropped it from V1). |
| Generator g | `Parameters.g` | 1.D | |
| n, k | `Parameters.n/k` (u32) | 1.E (inputs to H_P) | |
| H_P | `Parameters.h_p` | 1.E | Stored as a claim, never recomputed on load |
| H_B | `ManifestFile.h_b` | 1.F | Claim |
| Commitments K_{i,j}, K̂_{i,j} | `GuardianPublicKey.vote_commitments/data_commitments` (k each) | 2.A, 2.C | Maps to `GuardianPublicView` |
| Proofs of possession | `GuardianPublicKey.vote_proof/data_proof` (c, v_0..v_k) | 2.B, 2.C | |
| K and K̂ | `ElectionKeys.k/k_hat` | 3.A, 3.B | Claims; loaded with `ElectionPublicKeys.FromKeys`, never the product constructor |
| κ_i with its proof of knowledge | `GuardianPublicKey.kappa`; the proof is the (k+1)th response of each Schnorr proof (eqs. 2.2/2.4) | 2.A, 2.C | |
| H_E | `ElectionKeys.h_e` | 4.A | Claim |
| Every encrypted ballot (cast or challenged) | `EncryptedBallot` items in kind-0 device sections | 5-8, 9 (cast), 11.D, 13-14 (challenged) | Ballots that were never submitted are also in the chain (status `not_submitted`, §4.4) |
| — id_B, H_I | `id_b` (first field), `h_i` | 5.A, 5.B | |
| — encrypted selections | `contests[].fields[]` (α, β), positional in manifest field order | 6.A | Indices, not labels (§4.4) |
| — range proofs | `fields[].range_proof` (R+1, or bound+1 for a supplemental field, Q2) | 6.B-6.D | |
| — selection limit of each contest | the manifest (`Contest.SelectionLimit`) | V7 reads it | An election constant, not repeated per ballot |
| — selection-limit proof | `contests[].limit_proof` (L+1), plus `undervote_difference_proof?` and `null_vote_proof?` (Q15/Q17) | 7.B-7.D | |
| — ballot weight | `weight` (u32 ≥ 1, always written) | V9 | |
| — ballot style | `ballot_style` (the manifest's ballot style id) | structure | |
| — device information | the enclosing section's `DeviceHeader` (S_device, H_DI, mode, H_0) | 8.C, 16.D | Satisfied by section placement; ballots do not repeat device_id |
| — date and time of encryption | `encrypted_at: Option<Timestamp>` (G40, ms, UTC) | none | Not an input to H_C, so it is covered only by the root (§6.6). Optional, as in the S10a model (Q-6) |
| — confirmation code | `confirmation_code` (H_C), `chaining_field` (B_C) | 8.A, 8.B, 8.D, 8.E | |
| — status | `status` u8: 0 not_submitted, 1 cast, 2 challenged | 9 (cast filter), 13/14 | Not in H_C. Protected by the root, by the section seal and by signatures. |
| (S7) encrypted ballot nonce C_ξB | `ballot_nonce` (C_0, C_1 = 32 B, c, v) | structure, 13 | |
| Decryption of each challenged ballot: selections, plaintext, proofs or nonces | `ChallengedBallotDecryption` (final phase): per field index, label, σ, ξ_{i,j}; contest data (ξ, D) | 13, 14 | Nonce form (S7): no proof, no ξ_B |
| Encrypted tally of each option | `EncryptedTallyContest` (A, B per field), aggregated phase | 9, 10 | `MaximumCount` is derived, not stored (S4 carry-over) |
| Full decryptions, plaintexts, proofs | `DecryptedTallyContest` (index, label, t, T, c, v per field), final phase | 10, 11 | |
| Ordered lists of ballots per device | the device sections themselves (chain order) plus `DeviceHeader`/`DeviceClose` (H_0, B̄_C, H̄) | 8.C-8.G, 16.D-16.H | `DeviceChainRecord.ConfirmationCodes` is derived from section order and never stored |
| Encrypted contest data when available | `contests[].contest_data` (C_0, C_1 = 32·b_Λ B, C_2 = c‖v, Q20) | 8.A (in χ), 12 | Present iff b_Λ > 0 (S6) |
| (§3.6.6) contest-data decryptions | `ContestDataRequest` (aggregated phase) and `ContestDataDecryption` (final phase) | 12 | The request set makes a missing decryption detectable |
| Signed by administrators, with the date | detached `RecordStatement` signatures per phase, with `signed_at` | R.signature | Outside the root, appendable |
| Full download | ZIP64 carrier (§5.4) | | |
| Tools for voters to look up confirmation codes | `derived/` lookup index plus inclusion proofs to a signed phase root | | Non-canonical |

### 3.2 §4.4 Pre-encrypted ballots (pp.62-63), as built through S9c (Q26-Q35)

| §4.4 item | Record location | Consumed by |
|---|---|---|
| Cast: standard selection vectors with all standard proofs | `PreEncryptedCastBallot.contests[].contest` (an `EncryptedContest` each) | 5, 6, 7, 9, 11.D |
| Cast: selection hashes of every option, nulls included, sorted numerically per contest | `contests[].selection_hashes`: m+L values, strictly ascending | 16.A-16.C |
| Cast: short codes and pre-encryption vectors of the voter's selections (nulls included) | `contests[].selected[]`: exactly L entries (Q27 null padding), strictly ascending by ψ; no option named | 15.A, 17.A |
| Uncast: "the ballot nonce for that ballot is published" | `PreEncryptedUncastBallot`: ξ_{i,j,k} per vector; `ballot_nonce_released` (ξ_B) only when opted in | 16, 17, 18.A, 19 |
| Confirmation codes from the full set of pre-encryptions | `confirmation_code` and `chaining_field` on every kind-1 item | 16.C, 16.E-16.H |
| Pre-encrypted device chains | kind-1 device sections: cast, uncast and unreturned items, interleaved in print order | 16.D-16.H |
| Printed but never returned (not in §4.4; needed by the chain) | `PreEncryptedUnreturnedBallot` stub: id_B, H_I, χ per contest, B_C, H_C (§4.4, Q-5) | 5.A, 5.B, 16.C, 16.E-16.H |
| §4.4.1 presentation | derived views only | |

**Divergence to state in the formal spec:** §4.4 says the uncast "ballot nonce" is published. Q28 publishes the
per-selection nonces ξ_{i,j,k}, and ξ_B only when opted in.

### 3.3 Verification inputs

| V | Inputs | Record source |
|---|---|---|
| 1 | ver, p, q, g, n, k, H_P, manifest bytes, H_B | `Parameters`, `ManifestFile`; compared with `EGParameters` (CLAUDE.md: record parameters are claims) |
| 2 | K_{i,j}, K̂_{i,j}, κ_i, c_i, ĉ_i, v_{i,j}, v̂_{i,j}; H_P | `GuardianPublicKey` × n |
| 3 | K_{i,0}, K̂_{i,0}; K, K̂ | guardians, `ElectionKeys` |
| 4 | H_B, K, K̂, H_E | `ManifestFile`, `ElectionKeys` |
| 5 | id_B, H_I of **every ballot item in every device section** (§4.5 p.64) | ballot items (5.A is cross-ballot) |
| 6, 7 | α, β, proofs; R, L and option bounds from the manifest; K; H_I | ballot items + manifest |
| 8 | α/β, contest data, χ, B_C, H_C, H_I; S_device, H_DI, H_0, B̄_C, H̄ | kind-0 items + `DeviceHeader`/`DeviceClose` |
| 9 | (α, β) of every cast ballot, weight; (A, B) | cast items (both kinds) + `EncryptedTallyContest` |
| 10 | (A, B), T, t, c, v; K, H_E | encrypted and decrypted tally |
| 11 | tally labels, manifest labels, contests on submitted (cast + challenged) ballots | `DecryptedTallyContest` + manifest + contest indices seen |
| 12 | H_I, C_0, C_1, C_2, β, c, v, D; K̂ | ballot + `ContestDataRequest` + `ContestDataDecryption` |
| 13 | σ, ξ per field; ξ, D per contest data; the ballot's ciphertexts, χ, B_C, H_C | ballot + `ChallengedBallotDecryption` |
| 14 | decrypted labels and values; manifest | `ChallengedBallotDecryption` + manifest |
| 15 | selected vectors, combined vector | `PreEncryptedCastBallot` |
| 16 | vectors/hashes, χ, H_C, B_C, H_DI, H_0, close | kind-1 items + kind-1 section header/close |
| 17 | ψ, short codes | cast and uncast items |
| 18 | uncast vectors, released nonces, K | `PreEncryptedUncastBallot` |
| 19 | uncast labels, manifest | `PreEncryptedUncastBallot` + manifest |

---

## 4. Canonical form

### 4.1 Primitives

All integers are big-endian, as in the spec's b(x, n) (§5.1). There are no varints and no alternative
encodings. Fixed widths (512 for Z_p, 32 for Z_q) are fixed by format major 1, because the spec's §5.1 encodings
fix them for v2.1.0. A parameter set needing other widths requires a new major version.

| Type | Encoding | Decoder rejects (`R.encoding`) |
|---|---|---|
| `u8`, `u16` | 1 or 2 bytes | a value outside the field's enumeration, where one is declared |
| `u32` | 4 bytes | x ≥ 2^31 (MSB 0, as in §5.1.3) |
| `u64` | 8 bytes | x ≥ 2^53, so JSON numbers and doubles stay exact |
| `Timestamp` | `u64` milliseconds since 1970-01-01T00:00:00Z | x ≥ 2^53 |
| `Zp` | exactly 512 bytes | a wrong length. **The range x < p is not a decoding rule** (§4.6). |
| `Zq` | exactly 32 bytes | a wrong length. The range x < q is §4.6's. |
| `H32` | 32 raw bytes (a hash, id_B, H_I, H_C, χ, ψ) | |
| `B36` | 36 raw bytes (a chaining field B_C or B̄_C) | |
| `Bytes(n)` | exactly n raw bytes, with no prefix | |
| `VBytes` | `u32` length ‖ bytes | a length past the end of the item |
| `Text` | `VBytes` holding UTF-8 | ill-formed UTF-8, including encoded surrogates. **No normalization:** labels compare byte for byte with the manifest's. |
| `List<T>` | `u32` count ‖ count × T | a count that exceeds the remaining bytes divided by T's minimum size. A layout that fixes the count (k, k+1, L+1, m+L, ...) also checks it as structure (§4.6). |
| `Option<T>` | `u8` 0, or `u8` 1 ‖ T | any other tag |
| `Proof` | `Zq c ‖ Zq v` | |
| `Ciphertext` | `Zp α ‖ Zp β` | |
| `HashedCiphertext` | `Zp c0 ‖ VBytes c1 ‖ Zq c ‖ Zq v` (C_2 = b(c,32) ‖ b(v,32), Q20) | a c1 length other than 32 (ballot nonce) or 32·b_Λ (contest data, checked as structure) |
| `Locator` | `u8 kind ‖ H32 h_di ‖ u64 position` (position ≥ 1) | position 0 |
| `InfoPair` | `Text key ‖ Text value` | |

**Canonical by construction.** Every field is fixed-width or count- or length-prefixed. Every option has an
explicit tag. Field order is fixed, and nothing is omitted by default (a weight of 1 is written). So the encoding
is injective and prefix-free, and trailing bytes are an error. A strict decoder D and the encoder E satisfy
D(E(x)) = x, and whenever D(b) is defined, E(D(b)) = b. Canonicality is a property of the grammar, not a rule a
writer must remember to apply.

### 4.2 The item envelope and extensions

```
item       := u16 item_type ‖ u16 item_version ‖ body ‖ extensions
extensions := u32 count ‖ extension × count           (4 zero bytes when there are none)
extension  := u32 tag ‖ VBytes value                  (tags strictly ascending; bit 31 set = critical)
```

- Tags 0x00000001-0x0000FFFF are assigned by the format registry. Tags 0x00010000-0x7FFFFFFF are vendor tags,
  RECOMMENDED to be namespaced by an enterprise number in the upper 16 bits.
- Extensions are part of the hash form. They are digested, signed and carried by every representation whether
  or not the reader understands them.
- A required new field is a new `item_version`, never an extension (§7).
- Statements (§4.7) use the same envelope.

### 4.3 Sections, phases and canonical order

A section has a type (`u16`), a key (`VBytes`, empty except for device sections) and an ordered list of items.
**The canonical section order is ascending (type, key bytes).** The type's high byte gives the phase, so the
canonical order also follows the protocol's phase order.

| Type | Name | Phase | Key | Items, in canonical order | Presence |
|---|---|---|---|---|---|
| 0x0001 | header | setup | empty | `RecordHeader` | exactly once |
| 0x0002 | parameters | setup | empty | `Parameters` | exactly once |
| 0x0003 | manifest | setup | empty | `ManifestFile` | exactly once |
| 0x0004 | guardians | setup | empty | `GuardianPublicKey` × n, index 1..n with no gaps | exactly once |
| 0x0005 | election_keys | setup | empty | `ElectionKeys` | exactly once |
| 0x0101 | device | voting | `Bytes(33)`: kind ‖ H_DI | `DeviceHeader`; ballot items in chain order; `DeviceClose` | iff the device produced ≥ 1 ballot item (Q25); keys strictly ascending |
| 0x0102 | device_attestations | voting | empty | `DeviceAttestation`, ascending (device key, statement type, SHA-256(statement)) | exactly once once voting is sealed; may be empty |
| 0x0201 | encrypted_tally | aggregated | empty | `EncryptedTallyHeader`, then `EncryptedTallyContest` per manifest contest, ascending index | exactly once once aggregated |
| 0x0202 | contest_data_requests | aggregated | empty | `ContestDataRequest`, ascending (locator, contest index), unique | exactly once once aggregated; may be empty |
| 0x0301 | decrypted_tally | final | empty | `DecryptedTallyContest` per manifest contest, ascending index | exactly once once final |
| 0x0302 | challenged_ballot_decryptions | final | empty | `ChallengedBallotDecryption`, ascending locator, unique | exactly once once final; may be empty |
| 0x0303 | contest_data_decryptions | final | empty | `ContestDataDecryption`, ascending (locator, contest index), unique | exactly once once final; may be empty |
| 0x8000-0xFFFD | vendor | final | vendor-chosen | vendor items | optional |

Phase = min(type >> 8, 3), giving 0 setup, 1 voting, 2 aggregated and 3 final. A record is *at phase p* when it
holds every required section of phases ≤ p and nothing of a later phase. Anything else is `R.structure`. These
presence rules mean two conformant writers of the same content produce the same TOC.

**Canonical ballot order** is device sections in key order, and chain order within each section. Locator order
(kind, h_di bytes, position) is therefore the same order, and the decryption sections are sorted by it, which is
what makes O(1) merge joins possible (§6.3).

Rules for device sections:

- `DeviceHeader.kind` and `h_di` must equal the key, and the verifier recomputes H_DI from `device_id` and kind
  (eq. 72 with 0x2A for kind 0; eq. 119 with 0x43 for kind 1; 8.C/16.D). The strictly ascending keys make "one
  device, two sections of the same kind" a structural error found in O(1).
- Kind 0 holds `EncryptedBallot` items only. Kind 1 holds `PreEncryptedCastBallot`, `PreEncryptedUncastBallot` and
  `PreEncryptedUnreturnedBallot` items only. Anything else is `8.structure` or `16.structure`.
- Under no chaining, the order is still the device's recorded processing order. Only the chain-close attestation
  fixes it cryptographically (§4.7).

### 4.4 Item layouts (registry v1; item_version = 1 throughout)

Item types and section types are separate `u16` namespaces. Item 0x0101 is `RecordHeader`, while section 0x0101
is `device`. Item types are grouped by phase (0x01xx setup, 0x02xx voting, 0x03xx aggregated, 0x04xx final, 0x0Exx
statements, 0x0Fxx digest leaves, 0x8000-0xFFFE vendor).

Notation: `field: Type`, with comments after `--`. Fields appear in canonical order. Every item ends with
`extensions` (§4.2), which is omitted from the listings below. A "label" is the manifest's string identifier for
a contest, option or ballot style, which is what Verifications 11, 14 and 19 compare.

```
-- setup ---------------------------------------------------------------------------------------------------
RecordHeader (0x0101) :=
  format_major  : u16                    -- 1
  format_minor  : u16                    -- 0
  election_info : List<InfoPair>         -- strictly ascending by key bytes. Registry keys: "election_name",
                                         --  "election_date" (YYYY-MM-DD; "election_date.2" ... for multi-day),
                                         --  "jurisdiction", "location", "election_type", "administrator",
                                         --  "timestamp_precision" ("ms"|"s"|"min"|"hour"|"day"), plus
                                         --  "x-<vendor>-<name>" keys (Q-9). Software/producer names are NOT here.

Parameters (0x0102) :=
  version : Bytes(32)                    -- eq. (4) ver: "v2.1.0" then 0x00 padding to 32 bytes
  p : Bytes(512)   q : Bytes(32)   r : Bytes(512)   g : Bytes(512)   -- raw b(x,w), not Zp/Zq (G1)
  n : u32          k : u32
  h_p : H32

ManifestFile (0x0103) :=
  media_type : Text                      -- v1: "application/vnd.electionguard.manifest+json;format=1"
                                         --  = S10a ManifestSerializer's strict reading rules (§9.3)
  bytes      : VBytes                    -- EXACTLY the bytes H_B hashes (eq. 5); never re-encoded
  h_b        : H32

GuardianPublicKey (0x0104) :=
  index            : u32                 -- i, 1..n
  vote_commitments : List<Zp>            -- K_{i,0..k-1}, exactly k
  data_commitments : List<Zp>            -- K̂_{i,0..k-1}, exactly k
  kappa            : Zp                  -- κ_i
  vote_proof       : SchnorrProof        -- c_i, v_{i,0..k}
  data_proof       : SchnorrProof        -- ĉ_i, v̂_{i,0..k}
SchnorrProof := challenge: Zq, responses: List<Zq>     -- exactly k+1

ElectionKeys (0x0105) := k: Zp, k_hat: Zp, h_e: H32

-- voting --------------------------------------------------------------------------------------------------
DeviceHeader (0x0201) :=
  kind          : u8                     -- 0 regular, 1 pre-encrypting; = the section key's first byte
  device_id     : Text                   -- S_device
  h_di          : H32                    -- = the key's last 32 bytes
  chaining_mode : Bytes(4)               -- 0x00000000 or 0x00000001; must equal the manifest's
  initial_hash  : Option<H32>            -- H_0; present iff simple chaining

EncryptedBallot (0x0202) :=              -- kind-0 sections only
  id_b              : H32                -- FIRST, so an id-only pass reads 32 bytes per frame (§6.5)
  h_i               : H32
  ballot_style      : Text
  status            : u8                 -- 0 not_submitted, 1 cast, 2 challenged (Q-4)
  weight            : u32                -- ≥ 1, always written
  encrypted_at      : Option<Timestamp>  -- G40; mirrors EncryptedBallot.EncryptionTimestamp (Q-6)
  contests          : List<EncryptedContest>   -- ascending contest index; exactly the style's contests
  confirmation_code : H32                -- H_C
  chaining_field    : B36                -- B_C
  ballot_nonce      : HashedCiphertext   -- C_ξB, §3.3.4; c1 exactly 32 bytes
  ballot_ref        : Option<Text>       -- today's string EncryptedBallot.Id; unbound by any hash (Q-12)

EncryptedContest :=
  index                      : u32
  fields                     : List<EncryptedField>   -- manifest VerifiableFields order: options, then
                                                      --  supplemental fields (Q1/Q14)
  limit_proof                : List<Proof>            -- L+1 (eq. 62 with the Q15/Q17 terms)
  undervote_difference_proof : Option<List<Proof>>    -- iff the manifest tracks u
  null_vote_proof            : Option<List<Proof>>    -- iff the manifest tracks null
  contest_data               : Option<HashedCiphertext>  -- iff b_Λ > 0 (S6); c1 = 32·b_Λ bytes
  contest_hash               : H32                    -- χ
EncryptedField := ciphertext: Ciphertext, range_proof: List<Proof>   -- R+1, or bound+1 for a supplemental field

PreEncryptedCastBallot (0x0203) :=       -- kind-1 only; always cast (S9)
  id_b, h_i : H32, H32
  ballot_style : Text
  weight : u32
  encrypted_at : Option<Timestamp>       -- semantics (print vs record time): Q-6
  contests : List<PreEncryptedCastContest>     -- ascending index
  confirmation_code : H32                -- eq. (116)
  chaining_field : B36
  ballot_nonce : HashedCiphertext
  ballot_ref : Option<Text>
PreEncryptedCastContest :=
  contest          : EncryptedContest    -- combined vector and standard proofs (no contest data, Q26)
  selection_hashes : List<H32>           -- all m+L ψ, strictly ascending
  selected         : List<SelectedVector>  -- exactly L, strictly ascending by ψ
SelectedVector := vector: List<Ciphertext> (m), psi: H32, short_code: Text

PreEncryptedUncastBallot (0x0204) :=     -- kind-1 only
  id_b, h_i : H32, H32
  ballot_style : Text
  ballot_nonce : HashedCiphertext
  contests : List<UncastContest>         -- ascending index
  confirmation_code : H32
  chaining_field : B36
  ballot_nonce_released : Option<Zq>     -- ξ_B, only when opted in (Q28)
  ballot_ref : Option<Text>
UncastContest   := index: u32, label: Text, selections: List<UncastSelection> (m+L, ascending selection_index),
                   contest_hash: H32
UncastSelection := selection_index: u32 (eq. 121's j: option index, or m+l for the l-th null vector),
                   option_label: Option<Text> (absent exactly on null vectors),
                   vector: List<Ciphertext> (m), psi: H32, short_code: Text, nonces: List<Zq> (m: ξ_{i,j,1..m})
-- The codec splits the domain model's separate released-nonce lists out of, and back into, the selections.

PreEncryptedUnreturnedBallot (0x0205) := -- kind-1 only; printed, never returned (Q-5). Checked against the
                                         --  repo: 16.C (ConfirmationCode.ForPreEncryptedBallot, eq. 116) needs only
                                         --  H_I, the χ list in contest-index order and B_C, all carried here.
  id_b, h_i : H32, H32
  ballot_style : Text
  contest_hashes : List<(u32 index, H32 chi)>   -- ascending index; exactly the style's contests
  confirmation_code : H32
  chaining_field : B36
  ballot_ref : Option<Text>

DeviceClose (0x0206) :=
  ballot_count           : u64           -- ℓ = the number of ballot items in the section
  closing_chaining_field : Option<B36>   -- B̄_C (eq. 78 / 120, Q4); iff simple chaining
  closing_hash           : Option<H32>   -- H̄; iff simple chaining
  closed_at              : Option<Timestamp>

DeviceAttestation (0x0207) :=
  statement       : VBytes               -- the hash form of a 0x0E01-0x0E03 statement (§4.7), exactly as signed
  algorithm       : Text                 -- registry in §4.7
  key_id          : VBytes
  signer_key      : VBytes               -- public key or certificate chain; may be empty (out of band)
  signature       : VBytes
  timestamp_token : Option<VBytes>       -- RFC 3161 TimeStampToken over SHA-256(statement)

-- aggregated ----------------------------------------------------------------------------------------------
EncryptedTallyHeader (0x0301) := cast_ballot_count: u64, total_cast_weight: u64   -- both kinds; checked (R.summary)
EncryptedTallyContest (0x0302) := index: u32, fields: List<Ciphertext>            -- (A, B), manifest field order
ContestDataRequest (0x0303) := ballot: Locator (kind 0), h_i: H32, contest_index: u32
                               -- the contest-data ciphertexts "marked for decryption" (§3.6.1)

-- final ---------------------------------------------------------------------------------------------------
DecryptedTallyContest (0x0401) := index: u32, label: Text, fields: List<DecryptedTallyField>
DecryptedTallyField := index: u32 (manifest option index), label: Text, t: u64, T: Zp, c: Zq, v: Zq

ChallengedBallotDecryption (0x0402) :=
  ballot   : Locator (kind 0)
  h_i      : H32                         -- binding: must equal the ballot's
  contests : List<DecryptedContest>      -- ascending index; contest subsets only for RLA (Q22, §6.2 note)
DecryptedContest := index: u32, label: Text, fields: List<DecryptedField> (every field of the contest),
                    contest_data: Option<ReleasedData>
DecryptedField   := index: u32, label: Text, value: u32 (σ), nonce: Zq (ξ_{i,j})
ReleasedData     := nonce: Zq (ξ_i), data: VBytes (D, 32·b_Λ)

ContestDataDecryption (0x0403) :=
  ballot: Locator (kind 0), h_i: H32, contest_index: u32, beta: Zp, c: Zq, v: Zq, data: VBytes (D)

-- digest and statements ------------------------------------------------------------------------------------
TocEntry (0x0F01) := section_type: u16, key: VBytes, flags: u8 (bit 0 = critical), item_count: u64, root: H32
ConfirmationCodeLeaf (0x0F02) := code: H32       -- leaf payload of codes_root (§4.7); never stored as an item
```

Decisions behind the layouts:

- **Encrypted items carry indices; plaintext items carry index and label.** The spec's hashes bind contest and
  option indices (eqs. 59, 62, 70, 115). Labels on encrypted ballots would add 5-10 % per ballot, and no
  verification reads them there. Where a verification checks text (V11 tally, V14 challenged decryption, V19
  uncast), the item carries both. The index drives V13's ciphertext lookup, and the label is compared in V14. A
  mislabelled field therefore fails 14.D, and does not show up as a 13.x crypto failure against the wrong
  ciphertext.
- **No device_id on ballots.** It comes from the section. The domain `EncryptedBallot.DeviceId` is filled in from
  `DeviceHeader` on decode, which also removes the "ballot names another device" failure class.
- **`MaximumCount` is not stored.** No verification needs it (10.C checks T = K^t directly). A loader that rebuilds
  an `EncryptedTally` for decryption recomputes it from Σ weight × field maximum in the V9 pass.
- **The verifier never trusts the TOC.** It is a stored claim that the verifier recomputes.

### 4.5 Byte sizes

A field with R = 1 costs 1,024 B for the ciphertext and 128 B for the proof. A contest adds (L+1)·64 B for the
limit proof and 32 B for χ. The fixed per-ballot part is about 790 B, mostly the 608 B ballot-nonce ciphertext.
That puts a binary ballot within a few percent of today's protobuf ballot (about 12 KB for the perf manifests):
12 GB per million ballots. JSON is about 2.05× binary (hex), and about 1.1× binary after deflate.

Pre-encrypted items are larger:

- A cast item adds (m+L)·32 B of hashes and L·m·1,024 B of vectors per contest.
- An uncast item costs about (m+L)·m·(1,024 + 32) B per contest, about 32 KB per contest at m = 5, L = 1, so it
  can dominate a kind-1 section.
- An unreturned stub costs about 140 B plus 36 B per contest.

### 4.6 Validity layers and failure attribution (normative, so verifiers in all languages agree)

Checks run in three layers, in this order, and each failure carries a fixed code:

1. **Encoding** (`R.encoding`): the §4.1 rules, trailing bytes, an unknown enumeration value, an option tag
   other than 0 or 1, unsorted extension tags. The item's leaf hash is still computed from the bytes as read, so
   the root check still runs. The item is then opaque, and its verifications are `NotEvaluable` for it.
2. **Range** (lettered where the spec assigns a letter): a fixed-width value outside Z_p or Z_q. Today
   `FromCanonicalBytes` throws on such a value, which makes 6.B, 6.C and 2.B unreachable from a deserialized
   record. The record reader instead decodes the bytes raw and reports:

   | Value | Code |
   |---|---|
   | ballot and pre-encryption-vector α, β (V6 covers every selection encryption, §4.5) | 6.A |
   | selection range-proof c, v | 6.B, 6.C |
   | limit, undervote-difference and null-vote proof c, v | 7.B, 7.C |
   | guardian commitments, κ_i | 2.A |
   | guardian responses and challenges | 2.B |
   | tally v | 10.A |
   | contest-data decryption v | 12.A |
   | any other value | `N.structure`, where N is the first verification that consumes it (for example ξ ≥ q in a challenged decryption is 13.structure; K ≥ p is 3.structure) |

   The final per-field table is fixed in step 2 of §9 against the Verify classes' current lettering. An item
   with a range failure is not passed to the domain verifiers, because they take `IntegerModP` values. It is
   still digested, chain-walked (H_C and B_C are hashes) and entered into 5.A.
3. **Structure** (`N.structure`): counts fixed by the manifest (k, k+1, R+1, L+1, m+L, the style's contests),
   option presence rules, the section placement rules of §4.3, and today's `BallotStructure` rules.

Q-11 asks the user to confirm layer 2. It changes S10a's stated contract for the domain JSON serializers, but not
the pass or fail verdict.

### 4.7 Digests, roots, attestations and signatures

**Hash construction.** SHA-256 with RFC 9162 (Certificate Transparency v2) Merkle Tree Hash framing, not the
spec's H (Q-2):

```
leaf(item)  = SHA-256(0x00 ‖ hash_form(item))            -- the hash form starts with its item_type
node(l, r)  = SHA-256(0x01 ‖ l ‖ r)
MTH([])     = SHA-256("")
MTH(D[n])   = node(MTH(D[0:k]), MTH(D[k:n])), k = the largest power of two < n      (RFC 9162 §2.1.1)

section_root  = MTH(items of the section, in canonical order)
TocEntry_i    = (type, key, flags, item_count, section_root) as a 0x0F01 item
R_phase(p)    = MTH(TocEntry_1 .. TocEntry_j), j = the last entry whose section phase ≤ p
record root   = R_phase(the record's phase)
codes_root(ℓ) = MTH(ConfirmationCodeLeaf(H_1) .. ConfirmationCodeLeaf(H_ℓ))     -- one device, chain order
```

Exact leaf bytes, for signers in other languages:
`leaf(ConfirmationCodeLeaf(H_j)) = SHA-256(0x00 ‖ 0x0F02 ‖ 0x0001 ‖ H_j ‖ 0x00000000)`. That is the leaf prefix,
the envelope (type, then version 1), the body, and an empty extension list. For a device section, `item_count` in
its `TocEntry` and in a `SectionSealStatement` is ℓ + 2 (the header and the close).

Every leaf is type-prefixed, so items, TOC entries and code leaves can never collide. Bare SHA-256 can never equal
a protocol value of the HMAC-keyed H, and the format claims none of the spec's domain-separation bytes.

**Phase roots.** Sections are ordered by phase, so R_setup, R_sealed, R_aggregated and R_final are prefixes of
one another:

| Root | Covers | When fixed | Who relies on it |
|---|---|---|---|
| R_setup | the encryption record (sections 0x0001-0x0005) | before voting | devices and observers pin it |
| R_sealed | R_setup plus every device section and the attestations | when voting closes | Q36: the record is sealed before any decryption |
| R_aggregated | R_sealed plus the encrypted tally and the contest-data requests | after aggregation | §3.6.1: guardians run V4-V9 on exactly this, then decrypt |
| R_final | R_aggregated plus the decryptions and vendor sections | at publication | the public |

An RFC 9162 consistency proof, or recomputation from the TOC, shows that a later root extends an earlier one. So
nothing published after the seal can have altered a ballot.

**Device attestations (S8b).** These are statements produced at the device, or by the collector receiving from
it, and stored as `DeviceAttestation` items inside R_sealed:

```
ChainCloseStatement (0x0E01) := h_e: H32, device_key: Bytes(33), device_id: Text, chaining_mode: Bytes(4),
                                ballot_count: u64, codes_root: H32, closing_hash: Option<H32>, closed_at: Timestamp
SectionSealStatement (0x0E02) := h_e: H32, device_key: Bytes(33), item_count: u64, section_root: H32
PrefixCheckpointStatement (0x0E03) := h_e: H32, device_key: Bytes(33), ballot_count: u64, codes_root: H32,
                                      at: Timestamp
```

- **Chain close** is status-independent. It commits to every H_C in order, and through H_C to every ciphertext,
  χ, B_C and H_I. It binds order under **both** chaining modes (under no chaining it is the only thing that
  does). A pre-encrypting printer can sign it at print time, because it does not need cast content that exists
  only after recording. It is the attestation that fixes S8b's "drop trailing ballots and recompute the close".
- **Section seal** commits every byte of the section, including status, weight and `encrypted_at`. That blocks
  relabelling a challenged ballot as cast (the S7/Q31 attack) at the device level. It is possible only where the
  whole section exists at close (regular devices), so it is optional (Q-7).
- **Prefix checkpoint** is optional. It is a mid-election commitment to the first `ballot_count` codes, signed or
  posted to a bulletin board. The verifier checks it against its running codes frontier at no extra I/O.
- The verifier **always** checks statement contents against the record (`R.attestation`): h_e, the key, the mode,
  the count, the recomputed codes_root and section_root, and H̄. It checks signature validity only against
  configured trust anchors (`ISignatureVerifier`). Otherwise the report says "present, not checked".
- All three statements begin `h_e ‖ device_key`, so the key sits at a fixed offset. `DeviceAttestation` items
  sort by (device_key, statement item type, SHA-256 of the `statement` VBytes payload).
- **Append-only.** Nothing may be added to `device_attestations`, or to any other section, after the phase root
  covering it is fixed, or the prefix-consistency claim fails. Late countersignatures and RFC 3161 tokens go only
  in the detached `signatures/` layer. Likewise `election_info` is frozen at R_setup.

**Record signatures** (§3.7, "together with the date") are detached. They live outside the root, any number can
exist, and more can be appended later:

```
RecordStatement (0x0E04) := phase: u8 (0 setup, 1 sealed, 2 aggregated, 3 final), root: H32, h_e: H32,
                            format_major: u16, format_minor: u16, election_id: Text (from the manifest),
                            signed_at: Timestamp, signer_role: Text
SignatureEnvelope (0x0E10) := statement: VBytes, algorithm: Text, key_id: VBytes, signer_key: VBytes,
                              signature: VBytes, timestamp_token: Option<VBytes>
```

**What is signed.** A signature (in a `DeviceAttestation` or a `SignatureEnvelope`) is over the statement's
hash-form bytes, and the algorithm applies its own digest. Only an `rfc3161` token is over SHA-256(statement).
Each statement kind is a distinct item type in the envelope, so a chain-close signature can never be replayed as a
record signature, or the other way round.

Algorithm registry:

| Algorithm | Notes |
|---|---|
| `ecdsa-p256-sha256` (DER) | Mandatory to implement. It is in the .NET BCL and ships first. |
| `rsa-pss-sha256` | |
| `ed25519` | Pluggable. Check BCL support in the target SDK; otherwise it needs a dependency. |
| `x509-cms-detached` | Needs `System.Security.Cryptography.Pkcs` |
| `rfc3161` | A `TimeStampToken` over SHA-256(statement) |

Binding H_E makes a signature unusable on another election's record.

---

## 5. Representations, carriers and equivalence

### 5.1 The equivalence model (normative)

- The **logical record** L is the list of (section type, key, [hash forms]) in canonical order.
- A **representation** R has a strict decoder D_R from bytes to L (or a rejection) and an encoder E_R, with
  D_R(E_R(L)) = L. Strict means:
  - it is deterministic;
  - it rejects anything §4.1 or §5.5 rejects;
  - it maps each item to exactly one hash form.
- Section roots, the TOC and the phase roots are pure functions of L. So **two physical records are equivalent
  iff they decode to the same L, iff their record roots (and phases) are equal.** The "if" direction holds by
  construction. "Only if" holds because the decoders are injective and SHA-256 is collision-resistant.
- `egrecord digest <path>` prints the phase roots of any representation, and printing the same roots is the
  equivalence check. A converter is correct iff it preserves every phase root.
- Representation bytes are never hashed. A binary reader hashes the frames it reads in place, because for binary
  re-encoding is the identity. A JSON reader re-encodes each line to its hash form and hashes that.
- **Unknown content survives conversion.** A converter that meets an item type, item version or extension it does
  not understand carries the raw hash form across: binary verbatim, JSON as `{"item_type":n, "item_version":v,
  "raw":"HEX"}`. So no conversion can change the root, and no representation can verify more or less than
  another (§7). For the same reason a converter copies `RecordHeader` verbatim, `format_minor` included.

### 5.2 Binary stream files (`.egs`)

Every section is stored as one or more stream files. Singletons use the same format, so there is only one file
format.

```
egs    := header ‖ frame*
header := "EGS1" ‖ u16 section_type ‖ VBytes key ‖ u64 first_ordinal
frame  := u32 length ‖ item hash form
```

- **Segments.** A section may be split into segments at any frame boundary. Segment n+1's `first_ordinal`
  equals segment n's first_ordinal plus its frame count; a gap or overlap is `R.container`. Segment size is the
  writer's choice (default 256 MiB) and is not canonical. Workers can start at any segment, and the header says
  where they are.
- **Byte identity.** A device section's frames are byte-identical in every binary carrier and in the device's own
  part files. Assembling a record therefore means copying files and writing the TOC, never re-encoding GBs.
- **Pseudo-sections.** `toc.egs` uses section type 0xFFFE (`TocEntry` frames), and `signatures/*.egs` uses 0xFFFF
  (`SignatureEnvelope` frames). These two types never appear in a TOC and are outside every root. That leaves
  vendor sections 0x8000-0xFFFD.
- **No per-frame checksum.** The Merkle roots cover every frame.
- **Torn tails.** A crash mid-append leaves at most one torn trailing frame, whose length prefix runs past the end
  of the file. `ResumeAsync` truncates it and rebuilds the frontier by rescanning. The previous H_C for
  `DeviceChain` is recovered from the last complete frame. A corrupt middle frame is not repaired: the section
  stays unsealable until an operator decides (deliberate).

### 5.3 Directory carrier (reference layout)

```
<record>/
  toc.egs                                   TocEntry frames (a claim; recomputed by every verifier)
  setup/header.egs  parameters.egs  manifest.egs  guardians.egs  election_keys.egs
  devices/<k>-<H_DI hex>/00000000.egs ...   k = 0 or 1; paths stable from the first ballot onward
  device_attestations.egs
  aggregated/encrypted_tally.egs  contest_data_requests.egs
  final/decrypted_tally.egs  challenged_ballot_decryptions/00000000.egs  contest_data_decryptions/00000000.egs
  vendor/<type hex>-<key hex>/00000000.egs
  signatures/<phase>-<SHA-256(statement) hex>.egs     OUTSIDE the root (SignatureEnvelope frames)
  derived/                                  OUTSIDE the root (§5.6)
  meta.json                                 OUTSIDE the root: producer software, creation time, notes
```

Device paths are keyed by kind and H_DI hex, never by ordinals assigned at seal. A device can therefore append to
its final path during voting, and a late device never renames anything. This is the live-publication form.

### 5.4 ZIP64 carrier

- A ZIP64 archive of either directory, for distribution (§3.7 "full download").
- Binary entries are STORED (method 0), so they can be memory-mapped and seeked. JSON entries may be DEFLATEd.
- **Prescribed physical order** (not canonical; required only for single-pass reading): `toc`, `setup/*`,
  `device_attestations`, `aggregated/*`, `final/*`, then `devices/*` in key order, then `vendor/*`,
  `signatures/*`, `derived/*`, `meta.json`.
- With that order, a single-pass reader (`curl ... | egverify -`) learns the claimed roots and the election
  first. It buffers only the small decryption and request sections, about X × 2 KB, and then streams the device
  sections past (§6.3). A seekable reader accepts any entry order.
- Transport compression (`.zip.zst`) is not part of the record.

### 5.5 JSON projection (normative, for humans and interop)

The tree and file names are the same as §5.3, with `.jsonl` in place of `.egs`. Each file's first line is the
header object `{"egs":1,"section":"device","section_type":257,"key":"HEX","first_ordinal":0}`. Every following
line is one item.

- **Item object.** It starts with `"item":"<snake name>"` and `"item_version":n`, followed by the fields'
  snake_case names in layout order. Readers MUST accept any member order and any RFC 8259 whitespace. They MUST
  reject duplicate names, unknown names outside `extensions`, and `null`. An absent `Option` is an omitted member
  (draft §0.4.4). Lists are always present, even when empty; the one exception is `extensions`, which is omitted
  when empty. Defaults are always written (`"weight":1`).
- **Fixed-width values.** `Zp`, `Zq`, `H32`, `B36`, `Bytes(n)` and non-text `VBytes` are uppercase hex of exactly
  the binary bytes, regex `^[0-9A-F]{2w}$` (draft §0.6.2). Readers reject lowercase, short and long forms. The
  manifest's bytes are hex too, never embedded JSON, because embedding invites re-serialization, and that would
  change H_B.
- **Integers.** `u8`, `u16`, `u32` and `u64` are JSON numbers with no sign, fraction or exponent. Every one is
  below 2^53 by §4.1, so JavaScript and doubles read them exactly.
- **Timestamps.** `"YYYY-MM-DDTHH:MM:SS.sssZ"` (exactly 24 characters, the shape of S10a's
  `encryptionTimestamp`).
- **Enumerations.** Lowercase strings: `"not_submitted"`, `"cast"`, `"challenged"`, `"regular"`,
  `"pre_encrypting"`. `chaining_mode` is 8 hex digits.
- **Locators.** `{"kind":"regular","h_di":"HEX","position":n}`.
- **Text.** A JSON string. Writers escape only `"`, `\` and U+0000-U+001F (short escapes or `\u00XX`), and write
  everything else as raw UTF-8. Readers reject lone surrogates.
- **Extensions.** `"extensions":[{"tag":n,"value":"HEX"}]`, omitted when empty. A registered extension may define
  a typed JSON form, provided it maps one to one onto its bytes.
- **Canonical JSON writer.** Writers emit compact output in layout order, one item per line, LF line endings.
  This makes `diff` meaningful. It is still never hashed, which is why readers can be lenient on member order
  and whitespace.

A JSON-only consumer that wants to check digests needs the hash-form encoder anyway: §4.1 plus the layout tables,
about 300 lines in any language. That is the price of not hashing JSON, and it is far less than a byte-exact
canonical-JSON emitter and checker, which an RFC 8785-incompatible member order would require.

### 5.6 Derived views (outside the root; regenerable and checkable by regenerating)

- **Confirmation-code lookup:** H_C → (locator, segment, offset), sorted by H_C. With inclusion proofs (leaf path
  in the device section, the device's TocEntry, the TOC path) it serves §3.7's lookup tool. A voter's checker
  needs only SHA-256, and the proof is under 1 KB.
- **Sorted id_B index:** (id_B, locator), strictly ascending. It is an optional O(1)-memory V5.A path (§6.5) and
  can back the record-side `IPublishedCastBallots` (Q31).
- **Offset sidecars:** ordinal → byte offset per segment, for random access.

### 5.7 Conformance artifacts

- `test/kat/record/` golden vectors:
  - every item type in hash form, JSON and leaf hash;
  - MTH roots for n = 0..17 and 1,000, cross-checked with RFC 9162 vectors;
  - three complete small records, each as a binary directory, a JSON directory and a ZIP, all with the same
    roots: regular with no chaining; simple chaining with contest data, challenged and not-submitted ballots;
    pre-encrypted with cast, uncast and unreturned items.
- **Negative vectors:** one per `R.*` code and per strictness rule, each with its expected code.
- **A second-language reference reader:** the existing Python KAT oracle under `test/kat`, extended to compute
  leaves, section roots and phase roots of the golden records. This is the acceptance test for the formal spec:
  anything it needs that the spec does not say is a gap in the spec.

---

## 6. Streaming verification model

### 6.1 Phases of a run

| Step | Reads | Runs | Gate |
|---|---|---|---|
| A. Record | `toc`, the header | format version (`R.version`); phase and presence (`R.structure`) | An unknown major version stops the run. |
| B. Setup | sections 0x0001-0x0005 | V1 against `EGParameters`; parse the manifest from `ManifestFile.bytes` by media type (`ManifestSerializer`, strict, then `Manifest.Validate`); V2 per guardian, in parallel; V3; V4. Build `EncryptionRecord` from claims (`ElectionPublicKeys.FromKeys`, manifest from bytes). | A V1 failure, an unparseable manifest or a V4 failure stops all crypto (later outcomes `NotEvaluable`). Digests and structure still run to the end. |
| C. Join prep | `device_attestations`, `contest_data_requests`, both decryption sections | A **framing pre-scan**: read each frame's leading locator (41 bytes after the envelope) to check sort order (`R.order`), and record the offset where each device key's run begins (O(D)). Load the attestation statements per device (O(D)). | |
| D. Ballots | device sections, in parallel across sections | per §6.2 | Findings are collected, and the run continues. |
| E. Tally | `encrypted_tally`, `decrypted_tally` | Merge the V9 partials and compare (9.A, 9.B). Header counts against recounted cast ballots and weight (`R.summary`). V10 per field, in parallel. V11.A-C. V11.D from the bitset of contests on cast and challenged ballots. | |
| F. Completion | | Finish 5.A (§6.5). Every cursor exhausted (leftovers are 12.structure or 13.structure). Section roots against the TOC (`R.root`). Phase roots against any `Expected*Root` option. Record signatures (`R.signature`, governed by the policy). | |

### 6.2 The device pass

For each device section, the pipeline has three stages:

- **Reader.** Reads frames sequentially with read-ahead and posts (ordinal, bytes) to a bounded channel.
- **Workers**, in parallel within the section. For each frame: the leaf hash, the strict decode (§4.6 layers 1-3),
  then the per-item verifications:

  | Item | Checks |
  |---|---|
  | `EncryptedBallot`, any status | 5.B, 6, 7, 8.A, 8.B |
  | `EncryptedBallot`, cast | also: fold into this worker's `BallotAggregationVerifier` (weighted); set the 11.D bits |
  | `EncryptedBallot`, challenged | also: set the 11.D bits; take the decryption at this locator from the section's cursor and run V13 and V14 while the ballot is in memory |
  | `EncryptedBallot`, cast with contest-data requests at this locator | also: run V12 on each matching `ContestDataDecryption` |
  | `EncryptedBallot`, not_submitted | nothing beyond V5-V8: not tallied, never decrypted |
  | `PreEncryptedCastBallot` | 5.B, 6, 7, 15, 16.A-C, 17, V9 fold, 11.D |
  | `PreEncryptedUncastBallot` | 5.B, 16.A-C, 17, 18, 19 |
  | `PreEncryptedUnreturnedBallot` | 5.B, 16.C (H_C recomputed from H_I, the χ list and B_C) |

- **Sequencer**, in position order with O(1) work per item:
  - append the leaf to the section frontier and H_C to the codes frontier;
  - append id_B's keyed prefix to the 5.A run buffer;
  - advance the chain walker (8.D/8.E or 16.E/16.F) on the stated H_C and B_C, whose correctness is the worker's
    8.B/16.C;
  - match each prefix-checkpoint statement when the codes frontier reaches its count;
  - advance the join cursors and check the join rules below.

  At `DeviceClose` it checks 8.C/8.F/8.G or 16.D/16.G/16.H, ℓ, the section root, and the chain-close and
  section-seal statements.

**Join rules** (each failure is `12.structure` or `13.structure` at the ballot's locator, naming id_B):

- Every challenged ballot has exactly one `ChallengedBallotDecryption`, whose `h_i` equals the ballot's.
- A decryption that names a cast, not-submitted or kind-1 locator is a failure. This is the Q31 property, checked
  from the published record.
- Every `ContestDataRequest` names a cast kind-0 ballot and a contest with b_Λ > 0, and has exactly one matching
  `ContestDataDecryption`. Every decryption has exactly one matching request.
- Under Q24 (fail closed), a challenged ballot whose nonce decryption failed has no decryption, so the record
  fails 13.structure (Q-8).
- **RLA note (Q22):** the format admits a `ChallengedBallotDecryption` that leaves out whole contests, as 13.B
  allows. As built, 14.B (the S7 reading) fails such a decryption. That stays the behaviour until the audit
  workflow is designed, when a new `item_version` of 0x0402 will carry it.

Per-ballot ordering semantics are unchanged: `VerifyFused`/`VerifyInOrder` still report 6.A/7.A first. A ballot
that fails `9.structure` faults `BallotAggregationVerifier` by design, so V9 is then reported as `NotEvaluable`,
never as passed.

### 6.3 Joins, seekability and single-pass input

The decryption and request sections are in canonical ballot order, so they are joined by merge:

- **Single-threaded:** one cursor per section, advanced in step with the device pass. O(1) memory.
- **Parallel:** each device worker opens its own cursor at the run offset that step C recorded for its key. That
  needs O(D) offsets, and reads stay sequential within each run, which suits HTTP range reads.
- **Non-seekable single pass (ZIP from a pipe):** the prescribed entry order (§5.4) delivers these sections
  before the devices. The verifier buffers them, about X × 2 KB plus Y × 1.2 KB plus the requests, and then joins
  from memory.

### 6.4 Memory per verification

Notation:

- N: ballot items
- D: device sections
- F: verifiable fields in the manifest
- C: contests
- W: workers
- X, Y: challenged decryptions and contest-data decryptions

The example column uses N = 10^7, D = 5,000, F = 200, C = 50, W = 32 and X = 10^5.

| Verification | State across items | Bound | Example |
|---|---|---|---|
| Pipeline | in-flight decoded ballots | W × queue depth × ~30 KB | 32 × 4 × 30 KB ≈ 4 MB |
| Digests | a frontier per open stream; D section roots | ≤ 64 × 32 B per stream + ~80 B × D | < 1 MB |
| V1-V4 | manifest bytes, parsed manifest, guardians | O(manifest) + n·k·512 B | < 10 MB |
| **V5.A** | keyed 64-bit id_B prefixes in sorted runs | **8 B × N**, held in RAM up to the budget (default 256 MiB, about 32M ids), spilled beyond it. Non-seekable input: 40 B × N (full id + ordinal), spilled. | 80 MB, or ≤ 256 MiB plus disk at 10^8 |
| V5.B, 6, 7, 8.A/B, 12-19 | none across items | inside the pipeline | |
| 8.C-8.G, 16.D-16.H | per open section: H_{j−1}, j, H_0, mode, codes frontier | ~2.2 KB × W | < 100 KB |
| V9 | (A, B) partial products per field per worker (`ModPProduct`) | ~1.3 KB × F × W | ~8 MB |
| V10, V11.A-C | the encrypted tally, joined with the decrypted tally | O(F) × ~1 KB | < 1 MB |
| V11.D | contest bitset per worker | C bits × W | bytes |
| Joins | one item per cursor per worker, plus O(D) run offsets | ~2 KB × 3 × W + ~50 B × D | < 1 MB |
| Attestations | expected statements per device | ~250 B × D | ~1.3 MB |

**Total ≈ the V5.A budget + about 30 MB, independent of N.** V5.A is the only state that grows with N, and the
spec requires that: 5.A is a global uniqueness check over random values, and the format cannot store ballots
sorted by id_B without breaking chain order and appending. This replaces today's `DeviceChainWalk.Index`, which
keeps every link in a dictionary (O(N), about 150-250 B per ballot), and today's
`HashSet<SelectionEncryptionIdentifier>`, which costs about 100 B per id.

### 6.5 V5.A algorithm (exact, spill-bounded, adversary-resistant)

1. Per run, draw a secret 128-bit key k. For each ballot item of every kind (§4.5 p.64: "the full set of ballots,
   including the pre-encrypted ballots"), append `prefix = first 8 bytes of SHA-256(k ‖ id_B)` to the run buffer.
2. When the buffer reaches the budget, sort it and spill a run file. **Runs are sorted on the keyed prefix, not
   bucketed by id_B's own bytes**, so a record that skews its id_B values cannot overflow any in-memory partition.
3. At the end, k-way merge the runs and collect any prefix seen twice. The expected count is about N²/2^65: about
   3 × 10^-6 at 10^7.
4. If any prefix repeats, make a confirmation pass. Hop frame to frame by the length prefixes, reading only the
   first 36 bytes of each frame (the 4-byte envelope, then id_b, which is the first field of every ballot item), recompute the prefix, keep the full id_B and locator for the
   colliding prefixes, and compare exactly. Report 5.A with both locators. On JSON the pass scans lines for `id_b`
   instead, which is slower, but JSON verification already is.
5. **Non-seekable input:** no second pass is possible, so the runs carry (id_B, global ordinal) at 40 B per entry
   and the merge is exact in one pass.
6. **Distributed verification:** the coordinator supplies k to every shard, keeping it secret from the record's
   publisher, and merges their run files.

Optional O(1)-memory path: if a sorted id_B index (§5.6) is published, strictly ascending entries, each entry's
locator resolving to a ballot with that id_B, and an entry count equal to N together make the index a bijection
onto the ballots. That proves uniqueness at the cost of one 32-byte random read per ballot.

### 6.6 What only the root and signatures protect

`status`, `weight`, `encrypted_at`, `ballot_ref` and `ballot_style` are not inputs to H_C. Only the record root,
the phase signatures and (per device) the section seal stop someone from turning a challenged ballot into a cast
one after the fact. An unsigned record cannot rule that out. That is why `SignaturePolicy.RequireValid` is
recommended for official verification, and why the section seal is offered for regular devices.

### 6.7 Parallelism, distribution and throughput

- **Within a process.** Device sections are scheduled with work stealing, largest first. Within a large section
  (a central-count scanner with millions of ballots), segments let several readers start at segment headers, and
  the sequencer stitches the chain across segment boundaries.
- **Accumulators.** They commute and merge: the 5.A runs, the V9 partials (`BallotAggregationVerifier.Merge`; a
  faulted operand faults the result), the bitsets and the counters.
- **Across machines.** A shard is a set of device sections. Each shard returns its section roots and counts, its
  5.A run files, its V9 partials **in standard (A, B) form**, its 11.D bitset, its codes_roots and its findings.
  `ModPProduct` values carry engine-specific Montgomery drift (R differs between AVX-512 and scalar; CLAUDE.md), so
  a raw product never crosses a process boundary. The decryption sections travel with their devices, split at the
  run offsets.
- **Parallelism option.** `MaxDegreeOfParallelism` passes through to `BallotAggregationVerifier`,
  `TallyDecryptionVerification` and the pipeline, so `--parallelism 1` stays a true single-threaded baseline.
- **Throughput.** It is CPU-bound at about 1,000 ballots/s on 32 logical cores (measured). SHA-256 of a 12 KB
  frame (about 8 µs) and a strict decode are under 0.1 % of a ballot's verify cost.

### 6.8 Resumable and incremental verification

A **VerifierCheckpoint** is local, trusted state. It is written atomically (a temp file, then rename) every
`CheckpointInterval` and at section ends. It holds:

- the record identity: the claimed TOC root, or the section heads for a live record;
- the options hash: profile, verification subset and key k;
- per device section: next position and byte offset, section frontier, codes frontier and chain-walker state;
- the V9 partials in standard (A, B) form, never raw `ModPProduct`;
- the 5.A run files, with the current buffer flushed as a run;
- the 11.D bitset, the cursor positions, the counters and the findings so far.

On resume, each section continues from its saved offset and frontier. The final section root must equal the
TOC's. Because the frontier commits to the verified prefix, a match proves that the record being finished extends
exactly what was verified, so nothing is re-read. **A checkpoint is never accepted from a third party**, because
it holds verdicts.

A **live record** (implementation step 10) uses the same machinery. It tails the device part files under
`devices/`, checks prefix-checkpoint statements as they appear, and at seal runs only the remaining items plus
steps E-F.

### 6.9 Profiles and the report

| Profile | Input phase | Runs |
|---|---|---|
| `Full` | final | everything |
| `GuardianPreliminary` | aggregated | §3.6.1: V1-V9, the request rules, and a check that the challenged set is exactly the status-challenged ballots. Takes `ExpectedAggregatedRoot`, obtained out of band, so guardians decrypt exactly what they verified (Q36). |
| `BallotCorrectness` | any | for chosen locators or confirmation codes: 5.B, 6, 7, 8.A/8.B or 16.A-C/17/18/19, 13/14 where applicable, plus an inclusion proof to the root. Reads only those items, through derived offsets or a scan. |
| `Custom` | any | any subset of 1-19 (used by the structure-only GB tests) |

**Report semantics:**

- **Outcome per verification** (1-19): `Passed`, `Failed`, `NotApplicable` (for example 15-19 with no kind-1
  section), `NotEvaluable` (blocked by an earlier failure) or `NotRun` (outside the profile).
- **R-codes:** `R.container`, `R.encoding`, `R.order`, `R.structure`, `R.version`, `R.extension`, `R.root`,
  `R.summary`, `R.attestation`, `R.signature`.
- **`Complete`** is false whenever the reader skipped a non-critical unknown section, item version or extension
  (§7). **`Passed` requires no failures and `Complete = true`.** Because unknown content travels identically in
  every representation (§5.1), the verdict cannot depend on the representation.
- **Findings** carry `SubSection` (the existing `VerificationFailedException` convention: "6.D", "13.structure",
  "R.order"), the verification number, the section, the locator, id_B in hex, the contest and field index, and a
  message. They are ordered deterministically: by step (§6.1), then by canonical record order, then by
  sub-section. They are capped at `MaxFindings` (default 10,000); the verdict is already Failed when the cap
  truncates.
- **Default is collect-all.** At about 1,000 ballots/s, a run that stopped at the first failure would waste hours.
  `StopOnFirstFailure` is available.
- **Also reported:** all four phase roots, attestation and signature results, unknown content skipped, and
  statistics (N by kind and status, per-device counts, bytes, per-step timings).

---

## 7. Versioning and extension

| Layer | Mechanism | A reader that does not understand it |
|---|---|---|
| Spec version | `Parameters.version` (the exact eq. 4 bytes), checked by 1.A | V1.A fails |
| Format major | `RecordHeader.format_major`, repeated in every `RecordStatement` | refuses the record (`R.version`, stop) |
| Format minor | `RecordHeader.format_minor` | reads it in compatible mode (below) |
| Section type | new types within a phase band; `TocEntry.flags` bit 0 = critical | critical: `R.version` failure. Non-critical: items are digested, `Complete = false`. |
| Item type / version | the `u16 item_type ‖ u16 item_version` that starts every hash form | in a section it must verify: that item's checks are `NotEvaluable`, with `R.version`. In a non-critical vendor section: digested, `Complete = false`. |
| Field | extension lists (§4.2), with bit 31 = critical | critical: `R.extension`, the item is not evaluated. Non-critical: digested, reported, `Complete = false`. |
| Files | the `EGS1` magic | `R.container` |

Rules:

- A **major** change alters an existing item's layout or meaning, a primitive, the digest rules or the fixed
  widths. A new spec version that changes published objects means a new major.
- A **minor** change only adds: section types, item types, item versions or registered extension tags. It never
  changes the meaning of an existing check.
- **Writers MUST use the lowest item_version that can represent the content.** So an old reader keeps verifying
  every record that does not use the new capability. Example: RLA partial decryptions will be 0x0402 version 2,
  used only for decryptions that leave fields out.
- **Vendor sections** (0x8000-0xFFFD) are final-phase, non-critical by default, digested and never verified.
- **Election options** (chaining mode, Ω, supplemental fields, b_Λ) come from the manifest. The format has no
  feature flags.

This combines EGRF's "never a full pass with unread content" with streaming-first's critical flags. It fixes
EGRF's rigidity, since G40 would have been a minor change (a new item version or an extension), and
verifier-first's representation-dependent compatible mode.

---

## 8. C# API

Placement:

- `src/ElectionGuard.Core/Record/`: primitives, item codecs, Merkle, containers, JSON projection, writer and
  reader. These depend only on the BCL.
- `src/ElectionGuard.Core/Verify/ElectionRecordVerifier.cs`: the verify-everything entry point.
- The future `ElectionGuard.Verifier` project hosts the `egrecord` CLI (`verify | digest | convert | diff | prove |
  import`). `ElectionGuard.Administration` will be the main writer.

This split is Q-15.

```csharp
namespace ElectionGuard.Core.Record;

public readonly record struct RecordFormatVersion(ushort Major, ushort Minor) { public static readonly RecordFormatVersion V1_0 = new(1, 0); }
public enum RecordPhase : byte { Setup = 0, Sealed = 1, Aggregated = 2, Final = 3 }
public enum RecordEncoding { Binary, Json }
public enum RecordCarrier { Directory, Zip }

public enum RecordSectionType : ushort
{
    Header = 0x0001, Parameters = 0x0002, Manifest = 0x0003, Guardians = 0x0004, ElectionKeys = 0x0005,
    Device = 0x0101, DeviceAttestations = 0x0102,
    EncryptedTally = 0x0201, ContestDataRequests = 0x0202,
    DecryptedTally = 0x0301, ChallengedBallotDecryptions = 0x0302, ContestDataDecryptions = 0x0303,
}
public enum RecordItemType : ushort { RecordHeader = 0x0101, /* ... §4.4 ... */ TocEntry = 0x0F01 }
public enum BallotStatusCode : byte { NotSubmitted = 0, Cast = 1, Challenged = 2 }   // = BallotStatus values

public readonly record struct Sha256Digest(/* 32 bytes inline */);
public readonly record struct DeviceKey(DeviceChainBallotKind Kind, VotingDeviceInformationHash DeviceInformationHash)
    : IComparable<DeviceKey>;                                     // 33-byte section key
public readonly record struct BallotLocator(DeviceKey Device, long Position) : IComparable<BallotLocator>;
public readonly record struct SectionKey(RecordSectionType Type, ReadOnlyMemory<byte> Key) : IComparable<SectionKey>;

// ---- canonical encoding (strict) --------------------------------------------------------------------------
public ref struct CanonicalWriter                                 // over IBufferWriter<byte>
{
    public void WriteEnvelope(RecordItemType type, ushort version);
    public void WriteU8(byte v); public void WriteU16(ushort v); public void WriteU32(int v); public void WriteU64(long v);
    public void WriteZp(IntegerModP v); public void WriteZq(IntegerModQ v); public void WriteRawZp(ReadOnlySpan<byte> b512);
    public void WriteHash(ReadOnlySpan<byte> h32); public void WriteFixed(ReadOnlySpan<byte> bytes);
    public void WriteVBytes(ReadOnlySpan<byte> bytes); public void WriteText(string text);   // throws on lone surrogates
    public void WriteCount(int count); public void WriteOptionTag(bool present);
    public void WriteExtensions(IReadOnlyList<RecordExtension> extensions);
}
public ref struct CanonicalReader                                 // strict; NonCanonicalEncodingException => R.encoding
{
    public (RecordItemType Type, ushort Version) ReadEnvelope();
    public RawZp ReadZp(); public RawZq ReadZq();                // width-strict, range NOT checked (§4.6 layer 2)
    public ReadOnlySpan<byte> ReadHash(); public ReadOnlySpan<byte> ReadFixed(int n);
    public ReadOnlySpan<byte> ReadVBytes(); public string ReadText(); public int ReadCount(int minElementSize);
    public bool ReadOptionTag(); public IReadOnlyList<RecordExtension> ReadExtensions(); public void EnsureEnd();
}
public readonly record struct RawZp(ReadOnlyMemory<byte> Bytes) { public bool TryToModP(out IntegerModP value); }
public readonly record struct RawZq(ReadOnlyMemory<byte> Bytes) { public bool TryToModQ(out IntegerModQ value); }
public sealed record RecordExtension(uint Tag, ReadOnlyMemory<byte> Value) { public bool Critical => (Tag & 0x8000_0000) != 0; }

/// A frame as stored: its type, version and hash form. Its leaf hash is computed from HashForm.
public readonly record struct RecordItem(RecordItemType Type, ushort Version, ReadOnlyMemory<byte> HashForm, long Ordinal);

/// One codec per item type. Decoding returns findings for layers 2-3 instead of throwing, so the verifier
/// can attribute them (§4.6). Context = the manifest parsed from ManifestFile bytes plus the device header.
public interface IRecordItemCodec<T>
{
    RecordItemType Type { get; }
    ushort MaxVersion { get; }
    void Write(ref CanonicalWriter writer, T value, RecordContext context);
    DecodeResult<T> Read(ref CanonicalReader reader, ushort version, RecordContext context);
    void WriteJson(System.Text.Json.Utf8JsonWriter writer, T value, RecordContext context);
    DecodeResult<T> ReadJson(ref System.Text.Json.Utf8JsonReader reader, RecordContext context);
}
public readonly record struct DecodeResult<T>(T? Value, IReadOnlyList<VerificationFinding> RangeAndStructureFindings);

// ---- Merkle (RFC 9162) -------------------------------------------------------------------------------------
public sealed class MerkleFrontier                                // O(log n) state; serializable for checkpoints
{
    public static Sha256Digest LeafHash(ReadOnlySpan<byte> hashForm);
    public void AppendLeafHash(in Sha256Digest leaf);              // workers hash; the sequencer appends
    public long Count { get; }
    public Sha256Digest Root();
    public byte[] Serialize(); public static MerkleFrontier Deserialize(ReadOnlySpan<byte> state);
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
    public bool Extends(TableOfContents earlier);                  // prefix check, for consistency
}

// ---- items not already in the domain model ----------------------------------------------------------------
public sealed record RecordHeader(RecordFormatVersion Format, IReadOnlyList<KeyValuePair<string, string>> ElectionInfo);
public sealed record DeviceHeader(DeviceChainBallotKind Kind, string DeviceId, VotingDeviceInformationHash DeviceInformationHash,
    ChainingMode ChainingMode, ConfirmationCode? InitialHash);
public sealed record DeviceClose(long BallotCount, ChainingField? ClosingChainingField, ConfirmationCode? ClosingHash,
    DateTimeOffset? ClosedAt);
public sealed record PreEncryptedUnreturnedBallot(/* id_B, H_I, style, (index, χ) list, H_C, B_C, ballot_ref */);
public sealed record ContestDataRequest(BallotLocator Ballot, SelectionEncryptionIdentifierHash IdentifierHash, int ContestIndex);
public sealed record EncryptedTallyHeader(long CastBallotCount, long TotalCastWeight);
public abstract record DeviceEntry(long Position);                 // Regular / PreEncryptedCast / Uncast / Unreturned subtypes

public sealed record RecordSetup(RecordHeader Header, CryptographicParameters Parameters, GuardianParameters GuardianParameters,
    ParameterBaseHash ParameterBaseHash, ManifestFile ManifestFile, string ManifestMediaType, ElectionBaseHash ElectionBaseHash,
    IReadOnlyList<GuardianPublicView> Guardians, ElectionPublicKeys Keys, ExtendedBaseHash ExtendedBaseHash)
{
    public EncryptionRecord ToEncryptionRecord();                  // Manifest parsed from ManifestFile (S10a); keys via FromKeys
}

// ---- reading ------------------------------------------------------------------------------------------------
public interface IElectionRecordReader : IAsyncDisposable
{
    RecordEncoding Encoding { get; }
    RecordCarrier Carrier { get; }
    bool IsSeekable { get; }
    TableOfContents? ClaimedToc { get; }                          // as stored; recomputed, never trusted
    ValueTask<RecordSetup> ReadSetupAsync(CancellationToken ct = default);
    IReadOnlyList<DeviceKey> Devices { get; }                     // includes live sections without a close
    IDeviceSectionReader OpenDevice(DeviceKey device, long fromPosition = 1);
    IAsyncEnumerable<RecordItem> ReadSectionAsync(SectionKey section, long fromOrdinal = 0, CancellationToken ct = default);
    IAsyncEnumerable<RecordItem> ReadSectionFromAsync(SectionKey section, BallotLocator from, CancellationToken ct = default); // join cursors
}
public interface IDeviceSectionReader : IAsyncDisposable
{
    DeviceKey Key { get; }
    ValueTask<DeviceHeader> ReadHeaderAsync(CancellationToken ct = default);
    IAsyncEnumerable<RecordItem> ReadEntriesAsync(CancellationToken ct = default);   // raw frames, chain order
    ValueTask<DeviceClose?> ReadCloseAsync(CancellationToken ct = default);           // null while live
}
public static class ElectionRecord
{
    public static ValueTask<IElectionRecordReader> OpenAsync(string path, CancellationToken ct = default);          // dir or .zip, either encoding
    public static ValueTask<IElectionRecordReader> OpenAsync(Stream singlePassZip, CancellationToken ct = default);  // non-seekable
    public static ValueTask<ElectionRecordWriter> CreateAsync(string directory, RecordEncoding encoding, CancellationToken ct = default);
    public static ValueTask<ElectionRecordWriter> ResumeAsync(string directory, CancellationToken ct = default);    // repairs a torn tail
    public static ValueTask<TableOfContents> ConvertAsync(IElectionRecordReader source, string destination,
        RecordEncoding encoding, RecordCarrier carrier, int maxDegreeOfParallelism = -1, CancellationToken ct = default);
    public static ValueTask<TableOfContents> ComputeTocAsync(IElectionRecordReader source, int maxDegreeOfParallelism = -1,
        CancellationToken ct = default);
    public static IAsyncEnumerable<RecordDifference> DiffAsync(IElectionRecordReader a, IElectionRecordReader b, CancellationToken ct = default);
}

// ---- writing (phase-gated) --------------------------------------------------------------------------------
public sealed class ElectionRecordWriter : IAsyncDisposable
{
    public ValueTask WriteSetupAsync(RecordHeader header, EncryptionRecord encryptionRecord,
        IReadOnlyList<GuardianPublicView> guardians, CancellationToken ct = default);          // fixes R_setup
    public ValueTask<DeviceSectionWriter> OpenDeviceAsync(DeviceHeader header, CancellationToken ct = default); // create or resume
    public ValueTask AddDevicePartAsync(string devicePartDirectory, CancellationToken ct = default);  // validates, copies bytes
    public ValueTask AddAttestationAsync(DeviceAttestation attestation, CancellationToken ct = default);
    public ValueTask<TableOfContents> SealVotingAsync(CancellationToken ct = default);          // all devices closed -> R_sealed
    public ValueTask<TableOfContents> SealAggregatedAsync(EncryptedTally tally,
        IEnumerable<ContestDataRequest> requests, CancellationToken ct = default);             // -> R_aggregated
    public ISortedSectionWriter<ChallengedBallotDecryptionRecord> ChallengedDecryptions { get; } // throws before R_aggregated (Q36)
    public ISortedSectionWriter<ContestDataDecryptionRecord> ContestDataDecryptions { get; }
    public ValueTask<TableOfContents> CompleteAsync(DecryptedTally tally, CancellationToken ct = default); // -> R_final
    public ValueTask AddRecordSignatureAsync(SignatureEnvelope signature, CancellationToken ct = default); // any time after its phase
}
public sealed class DeviceSectionWriter : IAsyncDisposable                    // also usable standalone on a device
{
    public DeviceKey Key { get; }
    public long Count { get; }
    public ConfirmationCode? LastConfirmationCode { get; }        // resumes DeviceChain after a restart
    /// Requires: kind matches, B_C continues the chain (simple chaining), BallotStructure valid, status final.
    /// Does not run V6/V7 (writers are not verifiers).
    public ValueTask AppendAsync(EncryptedBallot ballot, CancellationToken ct = default);
    public ValueTask AppendAsync(PreEncryptedUncastBallot ballot, CancellationToken ct = default);
    public ValueTask AppendAsync(PreEncryptedUnreturnedBallot ballot, CancellationToken ct = default);
    public ValueTask FlushAsync(bool durable, CancellationToken ct = default);
    public byte[] PrefixCheckpointStatement(ExtendedBaseHash he, DateTimeOffset at);
    public ValueTask<DeviceSeal> CloseAsync(DeviceChainRecord closing, CancellationToken ct = default);  // from DeviceChain.Close
}
public sealed record DeviceSeal(DeviceKey Key, long ItemCount, Sha256Digest SectionRoot, Sha256Digest CodesRoot)
{
    public byte[] ChainCloseStatement(ExtendedBaseHash he, DateTimeOffset closedAt);   // hash form to sign (§4.7)
    public byte[] SectionSealStatement(ExtendedBaseHash he);
}
public interface ISortedSectionWriter<T> { ValueTask AddAsync(T item, CancellationToken ct = default); }  // sorts and spills into locator order

// ---- signatures ---------------------------------------------------------------------------------------------
public sealed record SignatureEnvelope(ReadOnlyMemory<byte> Statement, string Algorithm, ReadOnlyMemory<byte> KeyId,
    ReadOnlyMemory<byte> SignerKey, ReadOnlyMemory<byte> Signature, ReadOnlyMemory<byte>? TimestampToken);
public interface IStatementSigner { string Algorithm { get; } ValueTask<SignatureEnvelope> SignAsync(ReadOnlyMemory<byte> statement, CancellationToken ct = default); }
public interface ISignatureVerifier { string Algorithm { get; } SignatureCheck Verify(SignatureEnvelope envelope); }   // EcdsaP256Sha256 ships first
```

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

public static class ElectionRecordVerifier
{
    public static Task<VerificationReport> VerifyAllAsync(IElectionRecordReader record, VerifyAllOptions? options = null,
        IProgress<VerificationProgress>? progress = null, CancellationToken ct = default);
}
```

**What is reused and what is new.**

- **Reused unchanged**, through `RecordSetup.ToEncryptionRecord()`: the per-ballot classes (V5.B, V6, V7, V8 per
  ballot, V12-V19), `TallyDecryptionVerification`, `TallyContentsVerification` (fed the 11.D bitset mapped to
  labels) and `ParameterVerification`/V2-V4. Each throws `VerificationFailedException`. The orchestrator catches
  per item and attributes the finding.
- **New in existing namespaces:**
  - `Verify.DeviceChainWalker`: the incremental, O(1) form of `DeviceChainWalk`, with `Begin(header)`,
    `Next(link)` and `End(close)`, and the same scheme, sub-sections and messages. `VerifyDevice(s)` keep their
    signatures and are reimplemented on it.
  - `SpillingIdentifierSet` (§6.5), behind `SelectionEncryptionIdentifierSet`'s 5.A message.
  - `BallotAggregationVerifier.Merge`, plus `ExportStandardForm()`/`ImportStandardForm()` for checkpoints and
    shards.
  - `BallotStatus` gains nothing: the record status codes are the existing enum values.

**How the consumers use it.**

- **egperf.** Two optional scenario phases.
  - `writeRecord` assigns the streamed ballots to `deviceCount` simulated devices, appends each chunk through one
    `DeviceSectionWriter` per device, closes the chains with chain-close statements, writes the tally sections and
    seals each phase. The representation and carrier come from scenario JSON.
  - `verifyRecord` runs `VerifyAllAsync` from disk with `--parallelism` passed through.
  - Both add bytes per ballot, MB/s, ballots/s, peak working set and `PhaseRoots` to the JSONL line, so the scale
    claims sit under the perf gate. A `profile`/`verifications` setting in scenario JSON lets a huge
    structure-only run skip V6/V7.
- **Console (`Program.cs`).** It writes the canonical pipeline's record twice, as a binary directory and as a
  JSON ZIP. It asserts that `ComputeTocAsync` gives equal roots for both and runs `VerifyAllAsync` on each. Then it
  tampers one ballot's status and shows the root mismatch and the `R.root` finding.

---

## 9. Implementation plan

### 9.1 Ordering constraint

S10a is editing `src/` now: `ManifestSerializer`, `JsonElectionRecordSerializer`, `StrictJson`,
`EncryptionRecord`, `EncryptionTimestamp` and the tallies. **S10b code starts only after S10a is committed and its
review rounds are closed.** Every step below is one reviewable commit with the gate green: full test suite, the KAT
families unchanged, and a perf smoke `compare` for the steps that touch verification. Each step updates the
tracker.

### 9.2 Steps

| Step | Content | Tests |
|---|---|---|
| S10b-0a Nonce hazard (first commit, independent; could be an S10a follow-up) | Delete `EncryptionNonce` from `ProtobufEncryptedValueWithProofs`/`ProtobufEncryptedValue` **and the line-83 copy** into the DTO | A reflection test that no transport or record DTO has a nonce member |
| S10b-0b Model additions | `PreEncryptedUnreturnedBallot` domain type; `DeviceHeader`/`DeviceClose` ↔ `DeviceChainRecord` mapping (`ConfirmationCodes` derived from order); not-submitted ballots allowed through `DeviceChain` close and excluded from tally inputs | Unit tests for the mapping; 16.C, 16.E and 16.F accept a chain that contains unreturned stubs |
| S10b-1 Primitives and Merkle | `CanonicalWriter`/`Reader`, `RawZp`/`RawZq`, `MerkleFrontier`, `MerkleProofs`, `Sha256Digest` | Every §4.1 primitive: round trip and every rejection rule; RFC 9162 published vectors; MTH for n = 0..17 and 1,000; consistency and inclusion proofs; frontier serialize/resume equals uninterrupted |
| S10b-2 Item codecs + golden vectors | One codec per §4.4 type; the §4.6 range-attribution table; `RecordContext` (manifest from bytes, device header) | Property tests: E then D is the identity; D then E is byte-identical; every single-byte mutation either rejects or decodes to a different item. A **reflection completeness test** pins every public property of every recorded domain type to a codec field or to an explicit exclusion list (nonces); this replaces the protobuf "add it in both" hazard. Golden hex and leaf hashes in `test/kat/record/`. Range values ≥ p and ≥ q yield the lettered code. |
| S10b-3 Containers and writer/reader (binary directory) | `.egs` segments, TOC, phase roots, `ElectionRecordWriter` phase gates, `DeviceSectionWriter`, `ResumeAsync`, presence rules | Write then read gives the same domain objects (strict record round trip, from S10a's tests); segment rollover does not change roots; a torn tail is repaired; a corrupt middle frame is refused; decryption writers throw before R_aggregated; R_setup ⊑ R_sealed ⊑ R_aggregated ⊑ R_final (`Extends`) |
| S10b-4 Streaming verifier pieces | `DeviceChainWalker`; `SpillingIdentifierSet`; `BallotAggregationVerifier.Merge` and standard-form export; merge cursors with run offsets | The walker agrees with `DeviceChainWalk` on every existing V8/V16 test; 5.A with planted duplicates at random positions, with **adversarially skewed id_B prefixes** and with a 1 MiB budget forcing spills; AVX-512 and scalar partials merged through the standard form equal one engine (`DOTNET_EnableAVX512F=0` job) |
| S10b-5 `VerifyAllAsync` | Steps A-F, profiles, report, attestation-content checks, resumable checkpoint | One test per R-code and per join rule (a missing decryption, a decryption of a cast ballot, a kind-1 locator, an unmatched request); not-submitted ballots excluded from V9 and 11.D; unreturned stubs chain correctly; V9 `NotEvaluable` after a faulted aggregator; the console pipeline passes; a kill-and-resume test (cancel at a random point, resume, same report as one run); GuardianPreliminary on an aggregated record |
| S10b-6 JSON projection and converter | Hand-written `Utf8JsonWriter`/`Utf8JsonReader` codecs, canonical JSON writer, raw passthrough for unknown items, `ConvertAsync`, `DiffAsync` | **Cross-representation equivalence:** for the golden records and for random generated records, binary → JSON → binary is byte-identical, JSON → binary → JSON gives identical canonical JSON, and all representations give identical phase roots and identical `VerificationReport`s (findings included). Records with unknown non-critical extensions and sections give `Complete = false` in both encodings. JSON negatives: lowercase hex, duplicate member, null, number ≥ 2^53, lone surrogate. |
| S10b-7 ZIP carrier and single-pass | ZIP64 writer with the prescribed order; seekable and non-seekable readers | A `Stream` wrapper that throws on `Seek` runs the full verification; an out-of-order ZIP is refused for single-pass but accepted when seekable; the roots equal the directory's |
| S10b-8 Attestations and signatures | Statements, `IStatementSigner`, `ISignatureVerifier` (`ecdsa-p256-sha256` first; others pluggable), policies | Statements signed and verified; a tampered count, codes_root or status is caught (`R.attestation`); truncating trailing ballots is caught under both chaining modes when a chain-close exists; a missing or invalid signature under each policy |
| S10b-9 Migration | Legacy importers (`egrecord import`) for today's JSON ballots, device chains and pre-encrypted JSON | The importer maps labels to indices through the manifest and refuses unknown labels |
| S10b-10 egperf, console, fixtures | `writeRecord`/`verifyRecord` phases; `Program.cs`; `ElectionGuard.Testing.Cli` emits records in both encodings; regenerate `test/data/*` (if Q-3 accepts) | perf smoke run, `compare --repeat 5` against a HEAD worktree baseline (MEMORY: cold-run variance) |
| S10b-11 Live tailing (may be deferred) | `FollowLiveRecord`, prefix-checkpoint checking | Tail a record while a writer appends; a checkpoint mismatch is caught |
| S10b-12 Retire and document | Retire `ProtobufEncryptedBallotSerializer` once egperf's serialization phase uses the binary item codec (Q-13); CLAUDE.md "Record" architecture bullet; a formal-spec skeleton generated from the §4 tables | Python reference reader computes the golden roots in CI |

### 9.3 Interaction with S10a

| S10a work | What S10b does with it |
|---|---|
| `ManifestSerializer` (strict reading, deterministic writing) | Its reading rules become **manifest format 1**, named by `ManifestFile.media_type`. S10b adds golden and negative manifest vectors so the formal spec can cite them. Writers SHOULD publish the deterministic written form. H_B is still over whatever bytes were published. |
| `EncryptionRecord.Manifest` parsed from `ManifestFile` | `RecordSetup.ToEncryptionRecord()` uses this constructor. There is no second path from a record to a `Manifest`. |
| `EncryptionTimestamp` (nullable, ms, UTC; JSON shape; protobuf field 14) | Maps to `encrypted_at: Option<Timestamp>` with the same JSON shape. Protobuf field 14 goes away with protobuf (Q-13). |
| `JsonElectionRecordSerializer` (camelCase, base64, indented, range-strict) | Its strict round-trip tests become the template for the codec round-trip tests in step 3. For publication it is superseded by the record JSON projection; its own remarks say bundling "is not decided here (S10b)". Keep it as a debug per-item format, or retire it: Q-3. |
| Range-strict decoding (`FromCanonicalBytes` throws for ≥ p or ≥ q) | The domain serializers keep it. The record codec decodes raw values and attributes the range (§4.6). Q-11 asks the user to confirm. |
| `DecryptedTally`/`EncryptedTally` serializers, the `MaximumCount` carry-over | The record carries only (A, B) and (t, T, c, v). The loader recomputes `MaximumCount` in the V9 pass. |
| S10a's `BallotStructure` and aggregator changes | Used unchanged by the workers. Whatever 9.structure faulting S10a settles is reported as V9 `NotEvaluable`. |

### 9.4 GB-scale test strategy

1. **Full-crypto scale run (nightly or manual, egperf).** About 1M real ballots, about 12 GB binary. Generating
   them costs about 0.25 ms per ballot at 32 threads (a few minutes), and verifying them about 17 min at the
   measured rate. This checks throughput, peak working set and a resumed run against an uninterrupted one.
2. **Structure-only synthetic records at 10^7-10^8 items.** A generator emits valid framing, random id_B with
   correct H_I, contest hashes over random ciphertext bytes, and correct chains (H_C, B_C, H_0, closes). The
   `Custom` profile runs 5, 8 and 16 plus integrity, skipping V6/V7. Assertions:
   - peak working set at N and 4N differs only by the 5.A term (about 8 B per ballot extra, or nothing beyond the
     budget once spilled);
   - planted duplicate id_Bs are found with both locators;
   - a skewed-prefix record stays within budget.
3. **Fault injection at scale:**
   - a torn trailing frame;
   - one flipped status byte (`R.root`, and `R.attestation` with a section seal);
   - a dropped final ballot plus a recomputed close (caught by chain-close);
   - a reordered pair under no chaining (caught by codes_root).
4. **Non-seekable path.** The single-pass ZIP through the throwing-`Seek` stream at about 10^6 synthetic items,
   checking that the buffered sections stay within X × 2 KB.
5. **Cross-representation at scale.** Converting a 10^6-item record binary → JSON ZIP → binary gives identical
   roots. Converter memory is bounded, since it streams per section.

---

## 10. Risks and trade-offs

1. **A custom canonical binary.** Every language needs a hand-written codec, about 300 lines of primitives plus
   per-type layouts. In exchange, canonicality comes by construction. The mitigations are the layout tables, the
   golden and negative vectors and the Python reference reader. Deterministic CBOR and canonical JSON would leave
   canonicality to each library's conformance (Q-1).
2. **Device partitioning** puts grouping and print-order placement on whoever assembles the record. There is no
   global arrival order apart from `encrypted_at`. One huge device serializes only its cheap chain walk; decoding
   still runs in parallel.
3. **V5.A stays O(N).** It is 8 B per ballot, exact, and spills. 10^8 ballots need about 800 MB of temporary disk,
   or 4 GB for a non-seekable input.
4. **Status, weight and timestamps are protected only by the root, signatures and section seals** (§6.6).
5. **Timestamps plus chain order can de-anonymize voters.** Millisecond `encrypted_at` next to the order §3.7
   requires lets an observer at a polling place link a voter to a ballot. This is the most important policy
   question (Q-6).
6. **Indices on encrypted ballots.** A ballot item is unreadable without the manifest. That is acceptable because
   the manifest is always in the record, and the tools print labels as a derived view.
7. **JSON is about 2× binary.** Distribute GB records in binary, or as JSON in a ZIP with deflate.
8. **Merkle subtleties.** RFC 9162's split rule and empty tree are easy to get wrong. They are pinned with
   published and own vectors.
9. **`EGParameters` is process-static.** VerifyAll checks V1 against it and never swaps it, so verifying records
   with different parameter sets in one process needs `OverrideScope` per record and no parallel records.
10. **Attestations depend on deployment** (device keys, a collector TSA). Without them, S8b's truncation
    protection rests on the administrators' signature only. The verifier reports it rather than failing, unless
    the policy says otherwise.
11. **Divergence from a future official record spec** (§3.7: "specified in a separate document"). The §3 content
    map carries over. The format version and root-preserving converters bound the rework.
12. **Strictness costs interop with sloppy producers**: base64, lowercase hex and unknown members are rejected.
    This is intended. The legacy importers bridge today's files.

---

## 11. Open questions for the user (each with options and a recommendation)

- **Q-1 Canonical encoding.**
  - Options: (a) the fixed-schema binary hash form of §4; (b) deterministic CBOR (RFC 8949 §4.2); (c) canonical
    JSON per the EG 2.0 draft.
  - **Recommend (a).** It is canonical by grammar, stored and hashed in place at protobuf size, and JSON stays a
    lossless projection.
- **Q-2 Record digest hash.**
  - Options: (a) SHA-256 with RFC 9162 Merkle framing; (b) the spec's H keyed by a fixed record constant or by H_E.
  - **Recommend (a).** Off-the-shelf transparency-log tooling and proofs work unchanged, and it cannot collide with
    a protocol value. It adds a second hash construction to the trusted base.
- **Q-3 JSON conventions and S10a's JSON serializers.**
  - Options: (a) the record JSON projection uses uppercase fixed-width hex and snake_case (EG 2.0 draft); S10a's
    camelCase/base64 serializers stay as debug and legacy per-item formats, and `test/data` fixtures are
    regenerated; (b) keep base64 and camelCase in the projection.
  - **Recommend (a).** It is draft-aligned and grep-able, and the existing fixtures are imported once.
- **Q-4 Ballots in a chain that are neither cast nor challenged** (abandoned after encryption).
  - Options: (a) publish them with status 0 `not_submitted` (the existing `BallotStatus.NotSubmitted`), verified by
    V5-V8 and never tallied or decrypted; (b) a new status 3 `spoiled`; (c) require the collector to record them as
    challenged; (d) omit them, which breaks 8.E/8.G on honest records.
  - **Recommend (a).** It needs no new domain value and keeps every chain link.
- **Q-5 Printed pre-encrypted ballots that are never returned.**
  - Options: (a) the `PreEncryptedUnreturnedBallot` stub (id_B, H_I, χ per contest, B_C, H_C), so 5.A/5.B, 16.C
    and the chain stay checkable without releasing nonces; (b) publish them as uncast, with nonces; (c) exclude
    them from chains, which fails 16.F.
  - **Recommend (a).** Also confirm that the record assembler, not the library, puts cast items in print order
    (Q35).
- **Q-6 `encrypted_at`: required, precision and meaning.**
  - Options: (a) optional, as in S10a's model, with a declared `timestamp_precision` in `election_info` and a
    writer default of minute precision; (b) required at millisecond precision; (c) optional at millisecond
    precision, as now.
  - **Recommend (a).** §3.7 lists it, but millisecond times next to chain order can link voters to ballots.
  - For pre-encrypted cast ballots, recommend recording time (the print time is implied by chain position).
- **Q-7 Attestations and signatures.**
  - Options for device attestations: (a) chain-close recommended, and the verifier reports its absence; (b)
    required for every device. Section seal is optional for regular devices.
  - Algorithms: `ecdsa-p256-sha256` mandatory, Ed25519/RSA-PSS/CMS/RFC 3161 pluggable.
  - Default policy: `Report`, with `RequireValid` for official verification.
  - **Recommend (a) plus these defaults.** Signer roles (device, poll worker, administrator) and key distribution
    are deployment policy.
- **Q-8 A challenged ballot with no decryption** (nonce decryption failed and Q24 fails closed).
  - Options: (a) v1 requires a decryption for every challenged ballot (13.structure otherwise); (b) add a
    `ChallengedDecryptionUnavailable` item stating the reason, reported but not failed.
  - **Recommend (a) for v1.** Revisit (b) with the RLA workflow (Q22).
- **Q-9 `election_info` keys.**
  - Options: (a) a small registry (§4.4) plus `x-` vendor keys; (b) free form.
  - **Recommend (a).** Producer software names are kept out of the hash form so that two writers give one root.
- **Q-10 Contest-data decryption policy.**
  - Options: (a) the aggregated phase records the requested set (`ContestDataRequest`), so omissions are
    detectable, and the administrator chooses the set; (b) require every cast ballot's contest data to be
    decrypted.
  - **Recommend (a).**
- **Q-11 Range-failure attribution.**
  - Options: (a) the record reader decodes widths strictly and reports ≥ p/≥ q under the spec's lettered sub-checks
    (6.A, 6.B, 6.C, 2.A, 2.B, 7.B, 7.C, 10.A, 12.A); S10a's domain serializers stay range-strict; (b) treat range
    failures as `R.encoding`, as S10a's serializers do.
  - **Recommend (a).** The lettered checks become reachable, and verifiers in different languages emit the same
    code. The pass or fail verdict is unchanged.
- **Q-12 The string ballot id.**
  - Options: (a) keep it as the optional, unbound `ballot_ref` (useful for paper matching in an RLA, and never
    trusted, per Q31); (b) drop it.
  - **Recommend (a).**
- **Q-13 Protobuf.**
  - Options: (a) retire `ProtobufEncryptedBallotSerializer` once egperf's serialization phase uses the binary item
    codec, and use the binary item as the device-to-collector transport; (b) keep protobuf as a transport
    projection with a normative mapping.
  - **Recommend (a).** One codec, no parallel DTO tree, and the nonce-copy hazard goes away. Delete the nonce
    members now either way.
- **Q-14 Archive carrier.**
  - Options: (a) ZIP64 with STORED binary entries and a prescribed order; (b) tar plus zstd; (c) EGRF's custom
    byte-deterministic `.egr`.
  - **Recommend (a).** It is universal and seekable, and a single pass works through the order. Equivalence comes
    from roots, not file hashes.
  - Also confirm: is single-pass verification from a pipe a hard requirement? The design supports it.
- **Q-15 Code placement.**
  - Options: (a) the format and `VerifyAllAsync` in `ElectionGuard.Core` (tests, egperf and Administration share
    them), with the CLI in `ElectionGuard.Verifier`; (b) everything in `ElectionGuard.Verifier`.
  - **Recommend (a).**
- **Q-16 Multiple tallies.**
  - Options: (a) v1 has one election-wide tally; per-precinct or per-batch tallies come later as new sections; (b)
    allow several in v1, with a defined ballot set each for V9.
  - **Recommend (a).**
- **Q-17 The tally header claim.**
  - Options: (a) keep `EncryptedTallyHeader` (cast count, total cast weight) as a cheap `R.summary` check; (b)
    derive the numbers only.
  - **Recommend (a).**
- **Q-18 Derived views.**
  - Options: (a) publish the confirmation-code lookup and the sorted id_B index under `derived/`, outside the root,
    regenerable and checkable; (b) add them to the root as optional final-phase sections.
  - **Recommend (a).** Inclusion proofs already tie lookups to the signed roots.
