# ElectionGuard Record Format (EGRF) v2.0: specification

**Status: DRAFT (S10b-18 skeleton, 2026-10-10). Not for publication.** This document states the normative rules of
the election record format as a specification, so that an implementation in any language can be written from it
and the `.proto` alone. It is drawn from the design, `2026-10-08-election-record-design.md` (§4-§7; the section
numbers in brackets below point there), which keeps the rationale, the alternatives and the measurements. Where the
two disagree, the design governs until this draft is reviewed. Rules marked **[provisional]** are implementation
choices awaiting the user's sign-off (§11). Appendix A is generated from `test/egrf/schema.json` and the `.proto`
by `test/egrf/spec_tables.py` and must not be edited by hand.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119.

## 1. Scope and conformance

An EGRF record is the election record of ElectionGuard v2.1.0 §3.7 (pp.55-56) and §4.4 (pp.62-63): every published
value of one election, in four phases, with Merkle roots that commit to it. The format defines:

- one logical record (§3) and its canonical encoding (§4);
- four physical representations: protobuf segments or JSON lines, each in a directory or a `.zip` (§5);
- the digests, roots, attestations and signatures over it (§6);
- how a verifier attributes a failure (§7) and in which order it verifies (§8).

Conformance classes:

- A **writer** MUST produce only canonical items (§4), in the layout of §5, with the phase gates of §3.3.
- A **reader** MUST check every item it accepts (§4.4, including the decode rules D1-D6), and MUST apply the layout
  and discovery rules of §5.3 so that two readers assemble the same logical record from the same bytes.
- A **verifier** is a reader that runs the spec's Verifications 1-19 and the record-level rules, reporting failures
  under the codes of §7.

The normative schema is `proto/electionguard/egrf/v2/egrf.proto`, package `electionguard.egrf.v2`.

## 2. Terms

- **Item**: one `RecordItem` message (a oneof of every item type), stored as its canonical bytes.
- **Section**: a type (`SectionType`), a key (empty except for device sections) and an ordered list of items.
- **Logical record** L: the list of (type, key, [canonical item bytes]) in canonical section order.
- **Locator**: (device kind, H_DI, position), a ballot's address; position is 1-based chain order (the spec's j).
- **Phase**: setup, sealed (voting), aggregated, final.
- **Record format version**: `format_major`.`format_minor`; this document is 2.0.

## 3. The logical record [§4.5, §3]

### 3.1 Sections

| Type | Name | Phase | Key | Items, in canonical order | Presence |
|---|---|---|---|---|---|
| 0x0001 | header | setup | empty | `record_header` | exactly once |
| 0x0002 | parameters | setup | empty | `parameters` | exactly once |
| 0x0003 | manifest | setup | empty | `manifest_file` | exactly once |
| 0x0004 | guardians | setup | empty | `guardian_public_key` × n, index 1..n, no gaps | exactly once |
| 0x0005 | election_keys | setup | empty | `election_keys` | exactly once |
| 0x0101 | device | voting | kind ‖ H_DI (33 bytes; kind is the `DeviceKind` number) | `device_header`; ballot items in chain order; `device_close` | iff the device produced at least one ballot item; keys strictly ascending |
| 0x0102 | device_attestations | voting | empty | `device_attestation`, ascending (device key, statement item type, SHA-256(statement), item bytes), unique | once voting is sealed; may be empty |
| 0x0201 | encrypted_tally | aggregated | empty | `encrypted_tally_header`, then `encrypted_tally_contest` per manifest contest, ascending index | once aggregated |
| 0x0202 | contest_data_requests | aggregated | empty | `contest_data_request`, ascending (locator, contest index), unique | once aggregated; may be empty |
| 0x0301 | decrypted_tally | final | empty | `decrypted_tally_contest` per manifest contest, ascending index | once final |
| 0x0302 | challenged_ballot_decryptions | final | empty | `challenged_ballot_decryption`, ascending locator, unique | once final; may be empty |
| 0x0303 | contest_data_decryptions | final | empty | `contest_data_decryption`, ascending (locator, contest index), unique | once final; may be empty |
| 0x0304 | uncast_nonce_releases | final | empty | `uncast_nonce_release`, ascending locator, unique | once final; may be empty |
| 0xFFFE | toc (pseudo) | none | empty | `toc_entry` | the claimed TOC; never in a TOC |
| 0xFFFF | signatures (pseudo) | none | empty | `record_signature` | outside every root |

Every section type of this table is **critical**; a TOC entry's `critical` bit MUST be true. No other section type
exists in major 2: a new section kind requires a new major (user decision NQ-7). There are no vendor sections;
vendors extend only the manifest (NQ-1).

A regular device section holds `encrypted_ballot` items only, of any status (cast, challenged, spoiled). A
pre-encrypting device section holds `pre_encrypted_cast_ballot`, `pre_encrypted_uncast_ballot` and
`pre_encrypted_compact_uncast_ballot` items only, in print order. Anything else is the device's structure code
(`8.structure`, `16.structure`). `DeviceHeader.kind` and `h_di` MUST equal the section key.

### 3.2 Order

The canonical section order is ascending (type, key bytes). The **canonical ballot order** is device sections in key
order and chain order within each; locator order is the same order, and every final-phase join section is sorted by
it. Sort order is defined on values, not on encoded bytes.

### 3.3 Phases

The phase of a section is min(type >> 8, 3): 0 setup, 1 voting, 2 aggregated, 3 final (`RecordPhase` = phase + 1).
A record is *at phase p* when it holds every required section of phases ≤ p and nothing of a later phase; anything
else is `R.structure`. A writer MUST NOT add anything to a section after the phase root covering it is fixed, and
MUST NOT write a decryption or release before R_aggregated is fixed (Q36).

## 4. Canonical encoding [§4.2-§4.4]

Every item has exactly one valid encoding. A reader MUST reject any other (`R.encoding`, or `R.container` for D6).
Range (a value ≥ p or ≥ q) is **not** an encoding rule (§7).

### 4.1 Schema rules S1-S8

- **S1** `syntax = "proto3"`.
- **S2** Field types are `uint32`, `uint64`, `bool`, an enum, `string`, `bytes`, a message of this package, or
  `google.protobuf.Timestamp`. No signed or fixed-width integers, floating point, maps, `Any` or groups.
- **S3** No repeated scalar numeric field: a list is `repeated <message>` or one `bytes` field of fixed-width values.
- **S4** No `optional` keyword.
- **S5** Fields are declared in ascending number order.
- **S6** Numbers are append-only: a minor adds fields only above every number the message declares or reserves (a
  new `RecordItem` oneof member at any unused number); a removed number is reserved, never reused.
- **S7** Every fixed-width `bytes` field carries `(width)` or `(width_multiple)`, plus `(omittable) = true` when it
  may be absent; every enum has `..._UNSPECIFIED = 0`.
- **S8** Every oneof member is a message, and no regular field number lies inside a oneof's member range.

### 4.2 Wire rules W1-W8

- **W1 Order.** Fields in strictly ascending number order; a repeated field's elements contiguous, in list order.
- **W2 Presence.** An implicit-presence field is written iff it differs from its default; a message field iff it is
  set (even when empty); a oneof member iff it is the set member; a singular field at most once.
- **W3 Wire types.** VARINT for `uint32`, `uint64`, `bool`, enums; LEN for `string`, `bytes`, messages.
- **W4 Minimal varints.** Every tag, length and value in the fewest bytes; a `bool` is 0x01.
- **W5 Exact lengths.** A LEN length is the payload's byte count; a nested message is itself canonical.
- **W6 Unknown fields.** A reader of the record's minor (or later) rejects any number its schema does not define. A
  reader older than the record accepts an unknown field only after every known field of the message, in ascending
  order, numbered above every declared or reserved number (in `RecordItem`: an unknown member as its only field),
  VARINT (never 0, once) or LEN, with minimal varints and an exact length; its LEN payload is opaque, digested as
  stored and reported.
- **W7 Repeated messages.** One LEN record per element, never packed.
- **W8 Strings.** Valid UTF-8 (RFC 3629); no normalization.

### 4.3 Decode rules D1-D6

Every reader MUST check these after parsing; no protobuf runtime enforces them.

- **D1 Widths.** A present field with `(width) = w` has exactly w bytes; with `(width_multiple) = w`, a positive
  multiple of w. An absent width-annotated field fails unless `(omittable)`.
- **D2 Enums.** A declared member, and not `UNSPECIFIED` where the field is required. `SectionType` and `DeviceKind`
  are closed (NQ-7, NQ-9): an undeclared value is D2 for a reader of any minor. Another enum's undeclared value is D2
  for a reader that knows the record's minor; an older reader treats it as content it does not understand.
- **D3 Timestamps.** `seconds` in [0, 253402300799], `nanos` a multiple of 1,000,000.
- **D4 Integer bounds.** `uint32` below 2^31; `uint64` below 2^63.
- **D5 Envelope.** A `RecordItem` has exactly one field.
- **D6 Segment header.** A `SegmentHeader` is canonical, `magic` is `"EGRF"`, `format_major` is 2, and it agrees
  with its file's path (§5.3). Any failure is `R.container`.

### 4.4 Checking canonicality

A reader MUST use one of:

- **Method A, the wire walk** (the normative reference): walk the bytes against the schema table, checking W1-W8 and
  W6's unknown-field rule, then D1-D6 on the decoded known values. [§4.4 gives the pseudocode.]
- **Method B, parse, re-serialize, compare**, keeping unknown fields, with D1-D6 applied explicitly; for a record of
  a newer minor followed by Method A's unknown-field rule (a runtime that writes unknown fields back in the order
  read does not catch a misplaced one). A runtime that always discards unknown fields MAY use Method B only for
  records whose minor is not newer than its own.

Presence in practice, and which zero values are meaningful, are tabulated in design §4.2.3.

## 5. Representations and carriers [§5]

### 5.1 Equivalence

Two physical records are equivalent iff they decode to the same logical record, iff their phases and record roots
are equal. A converter is correct iff it preserves every phase root. JSON text is never hashed: a JSON reader hashes
the canonical protobuf encoding of what it parsed. Content a JSON line cannot carry (an unknown field, member or enum
value) MUST be refused (`R.version`), never dropped.

### 5.2 Segments (`.binpb`)

```
segment      := delimited(SegmentHeader) ‖ delimited(RecordItem)*
delimited(m) := varint(length of m's canonical bytes) ‖ m's canonical bytes
```

- A frame's length is at least 1 and at most 64 MiB (67,108,864 bytes); a reader MUST reject a larger length before
  allocating (`R.container`), and a writer MUST refuse a larger item.
- A section MAY be split into segments at item boundaries; segment n+1's `first_ordinal` is segment n's plus its item
  count, starting at 0.
- A zero-length frame or a non-minimal length is `R.container` for a verifier (a resuming writer MAY cut a torn
  tail of its own segment, design §5.2).

### 5.3 Directory layout and discovery

```
<record>/
  toc.<ext>
  setup/header.<ext> parameters.<ext> manifest.<ext> guardians.<ext> election_keys.<ext>
  setup/manifest.json                 optional copy of the manifest content, outside the root, byte-identical
  devices/regular-<H_DI hex>/00000000.<ext> ...
  devices/pre-encrypting-<H_DI hex>/00000000.<ext> ...
  device_attestations.<ext>
  aggregated/encrypted_tally.<ext> contest_data_requests.<ext>
  final/decrypted_tally.<ext>
  final/challenged_ballot_decryptions/00000000.<ext>
  final/contest_data_decryptions/00000000.<ext>
  final/uncast_nonce_releases/00000000.<ext>
  signatures/<phase>-<SHA-256(statement) hex>.<ext>   outside the root
  derived/                            outside the root, never read during verification
  meta.json                           outside the root
```

`<ext>` is `binpb` or `jsonl`. Rules (each failure `R.container` unless stated):

- Paths are derived from (type, key), never chosen; hex is lowercase. A signature file's `<phase>` is `setup`,
  `sealed`, `aggregated` or `final`.
- Segment files are `<8-digit zero-padded index>.<ext>` from `00000000` with no gaps; a section shown as one file is
  exactly one segment of that name.
- The path and the segment header MUST agree (D6).
- One encoding per record.
- No file outside the layout and `derived/`.
- Every name is printable ASCII 0x20-0x7E other than `\` and `:`, with `/` separators, relative, no `.`, `..` or
  empty segment; names equal ignoring ASCII case collide.
- The TOC never decides membership: a missing required section is `R.structure`; a claimed entry with no files, or
  files with no entry, `R.root`.
- **[provisional]** A claimed TOC is read at open; one that is not well formed (its file's framing code; an item not
  canonical `R.encoding`; an undefined section type `R.version`; an item that is not a `toc_entry`, a pseudo-section
  entry, no entry or bad order `R.root`) refuses the record. A well-formed claimed TOC that differs from the
  recomputed one is an `R.root` finding.
- **[provisional]** The header section is read at open, after the layout, phase and presence rules; one that cannot
  be read (its segment `R.container`; a second item `R.structure`; an item not canonical `R.encoding`; no
  `record_header` `R.structure`; another major `R.version`) refuses the record. A reader reads the header section's
  segment header at v2's path first, so a record of another major is `R.version` before its paths could be
  `R.container`.
- Segments are judged frame by frame: an item is judged before the next frame is read.

### 5.4 Zip carrier

A `.zip` of the directory. Protobuf entries are STORED; JSON entries MAY be DEFLATEd. The central directory is
authoritative and MUST fill exactly the bytes up to the (ZIP64) end record and hold exactly its stated entries; every
local header read MUST agree with it (name, method, sizes, CRC-32; with flag bit 3 the local CRC-32 and sizes MAY all
be 0); CRC-32 and sizes are checked as an entry is read; duplicate names, encryption and methods other than 0 and 8
are refused; directory entries follow the naming rules, are empty, STORED and unencrypted. Every disagreement is
`R.container`. A non-seekable input is spooled to a file before reading (NQ-6). [§5.4 lists every rule.]

### 5.5 JSON lines (`.jsonl`)

Each line is one message in the proto3 JSON mapping: the first line the `SegmentHeader`, every later line one
`RecordItem` (`{"encryptedBallot":{...}}`). Bytes are standard base64; `uint64` values decimal strings; enums by
name; timestamps RFC 3339 UTC with `Z`.

- Lines end with a line feed; the last line's line feed is optional (user decision 2026-10-10). One carriage return
  before a line feed is removed. An empty line is `R.container`; a line over 128 MiB is `R.container`; an item line
  that does not parse is `R.encoding`; a line whose canonical encoding exceeds 64 MiB is `R.container`.
- A reader MUST refuse, as `R.encoding`: a member named twice, a field named by both its JSON and its proto name, two
  members of one oneof, an unknown member or undeclared enum name (`R.version` for a record of a newer minor).
- **[provisional]** D6 governs a segment header line: any failure of it is `R.container`.
- **[provisional]** One written form: bytes in standard padded base64 with zero unused bits, integers (enum numbers
  included) in plain decimal, timestamps as a JSON string in the form the mapping's formatter writes for a value D3
  allows (`Z`, no fraction for a whole second, else exactly three digits: `2026-11-03T20:00:00Z`,
  `2026-11-03T20:00:00.005Z`; not an offset, `.000`, `.0050` or `.005000`); any other spelling is `R.encoding`. A
  timestamp outside D3 is D3's.
- **[provisional]** An undeclared `SectionType` *name* in a JSON TOC line is `R.encoding` (a number is `R.version`).

## 6. Digests, roots, attestations and signatures [§4.9]

```
leaf(item)    = SHA-256(0x00 ‖ canonical RecordItem bytes)
node(l, r)    = SHA-256(0x01 ‖ l ‖ r)
MTH([])       = SHA-256("")
MTH([d])      = leaf(d)
MTH(D[n])     = node(MTH(D[0:k]), MTH(D[k:n])), k the largest power of two < n      (RFC 9162 §2.1.1)
section_root  = MTH(the section's items, in order)
TocEntry_i    = RecordItem{toc_entry: (type, key, critical, item_count, section_root)}
R_phase(p)    = MTH(TocEntry_1 .. TocEntry_j), j the last entry whose section phase ≤ p
codes_root(ℓ) = MTH(RecordItem{confirmation_code_leaf: H_1} .. RecordItem{confirmation_code_leaf: H_ℓ})
```

- The phase roots R_setup ⊑ R_sealed ⊑ R_aggregated ⊑ R_final are prefixes of one another; a later root extends an
  earlier one (RFC 9162 consistency).
- A device section's `item_count` is ℓ + 2 (header and close). `confirmation_code_leaf` is field 51, so
  `leaf = SHA-256(0x00 ‖ 0x9A 0x03 0x22 0x0A 0x20 ‖ H_j)`.
- **Statements** (`ChainCloseStatement` 40, `SectionSealStatement` 41, `PrefixCheckpointStatement` 42,
  `RecordStatement` 43) are canonical `RecordItem`s, carried as bytes in a `SignedStatement`. A verifier MUST check
  `statement` as an item (§4.4, D1-D6) and its member type (40-42 in `device_attestation`, 43 in
  `record_signature`) before anything else (`R.attestation`, `R.signature`), MUST always compare statement contents
  with the record, and checks signature validity only against configured trust anchors. A signature is over the
  statement's canonical bytes; an RFC 3161 token over SHA-256(statement). `ecdsa-p256-sha256` (DER) is mandatory to
  implement.
- Device attestations are inside R_sealed; record signatures (over a phase root and H_E) are detached, outside every
  root, and may be added at any time after their phase.

## 7. Validity layers and failure attribution [§4.8, §6.9]

Checks run in three layers, in order, each failure under a fixed code:

1. **Encoding**: W1-W8 and D1-D5 `R.encoding`, D6 `R.container`. The item's leaf is still computed from the bytes as
   read; the item is then opaque and its verifications are `NotEvaluable` for it.
2. **Range**: a fixed-width value outside Z_p or Z_q decodes raw (never reduced) and is reported under the spec's
   lettered check or `N.structure` (table in design §4.8: for example ballot α, β 6.A; range-proof c, v 6.B, 6.C;
   contest proofs 7.B, 7.C; contest data C_0 and C_2 8.structure; a ballot's C_ξB 13.structure; guardian
   commitments 2.A, responses 2.B, challenges 2.C; K, K̂ 3.A, 3.B; tally A, B 9.A, 9.B; T, c, v 10.C, 10.B, 10.A;
   contest-data decryption β, c, v 12.structure, 12.B, 12.A; released nonces 13.structure, 18.structure). The
   verifications that would read such a value are `NotEvaluable` on the item.
3. **Structure** (`N.structure`): counts fixed by the manifest, required messages and strings, the section placement
   rules, and in-item lists out of ascending index order (reported under the code of the verification that reads the
   list in that order).

Record-level codes:

| Code | Meaning |
|---|---|
| `R.container` | carrier: layout and naming, framing and the 64 MiB ceiling, zip consistency, D6 |
| `R.encoding` | an item that is not canonical (W1-W8, D1-D5), a JSON line that is not one item |
| `R.order` | a section's items out of canonical order |
| `R.structure` | section presence and phase |
| `R.version` | a format version, or content of a newer minor, the reader cannot verify |
| `R.root` | a section or phase root that is not the claimed one; a claimed TOC that is not well formed |
| `R.summary` | the encrypted tally header against the recounted cast ballots |
| `R.attestation` | a device attestation |
| `R.signature` | a record signature |

## 8. Verification order and report [§6]

A verifier runs, in order: **A** record (layout, version, phase and presence; a layout failure or an unknown major
stops the run); **B** setup (V1 against the verifier's own parameters, the manifest parsed from the stored bytes,
V2, V3, V4; a V1 failure, an unparseable manifest or a V4 failure stops all cryptography, not the digests); **C** join
preparation (attestations; the join sections' order); **D** the device pass (per item: canonicality, chain walk,
5.A, V5.B-V8 or V15-V19, the joined decryptions and releases V12-V14 and V18, the V9 fold; per device: the chain's
close and its attestations); **E** the tally (V9 and each contest's cast weight, `R.summary`, V10, V11); **F**
completion (5.A, leftover join items, section roots against the claimed TOC, phase roots against any expected root,
record signatures).

- Nothing a record's publisher controls may stop a verifier with an error: every fault is a finding under its code.
- Outcomes per verification: `Passed`, `Failed`, `NotApplicable`, `NotEvaluable` (never `Passed` over an item it
  could not read), `NotRun` (outside the profile).
- Findings are collected, not stop-on-first, and ordered by step, canonical record order, then sub-section, so every
  conformant verifier, every representation and any parallelism give one report.
- `Passed` means no failure; `Complete` is false when the reader skipped content of a newer minor (informational).
- Profiles: `Full` (a final record), `GuardianPreliminary` (an aggregated prefix: V1-V9, V15, V16 and the request
  rules; the guardians decrypt only a tally that passed it, with R_aggregated obtained out of band), `BallotCorrectness`
  (chosen ballots, with inclusion proofs), `Custom`.

## 9. Versioning [§7]

- A **major** change alters an existing field's meaning or type, the profile, the digests or the widths, or adds a
  section kind; the `.proto` package becomes `electionguard.egrf.v<major>`. A reader MUST refuse another major
  (`R.version`).
- A **minor** change only adds fields (S6; a new `RecordItem` member is a field) and enum values other than
  `SectionType` and `DeviceKind`. A reader older than the record verifies what it understands, keeps and digests the
  rest, and reports `Complete = false`. In JSON it stops with `R.version`.
- Writers MUST use the lowest representation that carries the content.
- Vendor data lives only in the manifest's unknown properties, which H_B binds.

## 10. Registered numbers

The profile annotations `width`, `width_multiple` and `omittable` are custom `FieldOptions` extensions numbered
50001, 50002 and 50003, **draft placeholders** in protobuf's 50000-99999 range for in-house use. Before publication
they MUST be replaced by numbers registered in protobuf's global extension registry (a pull request to the protobuf
project's `docs/options.md`, a user action, S10b-18), so that no third party's options collide with them in a shared
descriptor pool. Changing the numbers changes no item's bytes (options are not on the wire) but changes the
descriptor, so `test/egrf/schema.json` and every reader's schema table follow, and `EgrfSchemaLintTests` pins the
registered numbers once they exist.

## 11. Provisional rules awaiting sign-off

Listed for the user in the tracker (S10b-E review round 3, questions a-e), implemented as the C# reader behaves and
pinned by negative records labelled `basis: implementation-chosen, awaiting sign-off` in `test/egrf/records/index.json`:

- (a) the claimed TOC is read at open and stops the read when not well formed (§5.3);
- (b) the header section is read at open and stops the read when unreadable (§5.3);
- (c) D6 governs a `.jsonl` segment header line (§5.5);
- (d) JSON values have one written form (§5.5): bytes, integers and (since S10b-F review round 2) timestamps;
- (e) an undeclared `SectionType` name in a JSON TOC stays `R.encoding` (§5.5).

## 12. Not yet specified here

Derived views (design §5.6), live tailing (S10b-17), the TypeScript reader (deferred, NQ-3) and the deployment
policies for signer roles and key distribution are outside this draft. Per-item sizes are in design §4.7.

## Appendix A. Schema tables

<!-- BEGIN GENERATED: test/egrf/spec_tables.py -->

Package `electionguard.egrf.v2`. Generated from `test/egrf/schema.json` and the `.proto`'s field comments; do not edit by hand.

Width (bytes), decode rule D1 (§4.3): a number is the field's exact length; "multiple of w" is a positive whole multiple of w bytes, how many being set by the field's note (the schema does not fix the count); "omittable" means the field may also be left out, as an empty value.

### A.1 Messages

#### `SegmentHeader`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `magic` | `string` |  |  |  | "EGRF" |
| 2 | `format_major` | `uint32` |  |  |  | 2 |
| 3 | `section_type` | `SectionType` |  |  |  |  |
| 4 | `key` | `bytes` |  |  |  | empty, except a device section's 33-byte device key |
| 5 | `first_ordinal` | `uint64` |  |  |  | 0-based ordinal, within the section, of this segment's first item |

#### `RecordItem`

Reserved: 100, 2047.

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `record_header` | `RecordHeader` |  |  | item |  |
| 2 | `parameters` | `Parameters` |  |  | item |  |
| 3 | `manifest_file` | `ManifestFile` |  |  | item |  |
| 4 | `guardian_public_key` | `GuardianPublicKey` |  |  | item |  |
| 5 | `election_keys` | `ElectionKeys` |  |  | item |  |
| 10 | `device_header` | `DeviceHeader` |  |  | item |  |
| 11 | `encrypted_ballot` | `EncryptedBallot` |  |  | item |  |
| 12 | `pre_encrypted_cast_ballot` | `PreEncryptedCastBallot` |  |  | item |  |
| 13 | `pre_encrypted_uncast_ballot` | `PreEncryptedUncastBallot` |  |  | item |  |
| 14 | `device_close` | `DeviceClose` |  |  | item |  |
| 15 | `device_attestation` | `SignedStatement` |  |  | item |  |
| 16 | `pre_encrypted_compact_uncast_ballot` | `PreEncryptedCompactUncastBallot` |  |  | item |  |
| 20 | `encrypted_tally_header` | `EncryptedTallyHeader` |  |  | item |  |
| 21 | `encrypted_tally_contest` | `EncryptedTallyContest` |  |  | item |  |
| 22 | `contest_data_request` | `ContestDataRequest` |  |  | item |  |
| 30 | `decrypted_tally_contest` | `DecryptedTallyContest` |  |  | item |  |
| 31 | `challenged_ballot_decryption` | `ChallengedBallotDecryption` |  |  | item |  |
| 32 | `contest_data_decryption` | `ContestDataDecryption` |  |  | item |  |
| 33 | `uncast_nonce_release` | `UncastNonceRelease` |  |  | item |  |
| 40 | `chain_close_statement` | `ChainCloseStatement` |  |  | item |  |
| 41 | `section_seal_statement` | `SectionSealStatement` |  |  | item |  |
| 42 | `prefix_checkpoint_statement` | `PrefixCheckpointStatement` |  |  | item |  |
| 43 | `record_statement` | `RecordStatement` |  |  | item |  |
| 44 | `record_signature` | `SignedStatement` |  |  | item | signatures pseudo-section only |
| 50 | `toc_entry` | `TocEntry` |  |  | item | TOC pseudo-section and the TOC tree |
| 51 | `confirmation_code_leaf` | `ConfirmationCodeLeaf` |  |  | item | codes_root leaves; never stored |

#### `RecordHeader`

Reserved: 3.

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `format_major` | `uint32` |  |  |  | 2 |
| 2 | `format_minor` | `uint32` |  |  |  | 0 (absent) in v2.0 |

#### `Parameters`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `version` | `bytes` |  | 32 |  | eq. (4) ver: "v2.1.0" then 0x00 padding to 32 bytes |
| 2 | `p` | `bytes` |  | 512 |  | raw b(p,512), not an element of Z_p (decision G1) |
| 3 | `q` | `bytes` |  | 32 |  |  |
| 4 | `r` | `bytes` |  | 512 |  |  |
| 5 | `g` | `bytes` |  | 512 |  |  |
| 6 | `n` | `uint32` |  |  |  |  |
| 7 | `k` | `uint32` |  |  |  |  |
| 8 | `h_p` | `bytes` |  | 32 |  | claim; Verification 1.E |

#### `ManifestFile`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `media_type` | `string` |  |  |  | v2.0: "application/vnd.electionguard.manifest+json;format=1", whose parser is ManifestSerializer's reading: UTF-8 JSON without a BOM, no duplicate keys, known members strict, unknown properties ignored (vendor data, still bound by H_B; NQ-1) but still well-formed UTF-8 with no lone-surrogate escapes, nesting at most 64 levels everywhere. A writer refuses content it cannot parse |
| 2 | `content` | `bytes` |  |  |  | the manifest exactly as entered; the H_B input of eq. (5); never re-encoded |
| 3 | `h_b` | `bytes` |  | 32 |  | claim; Verification 1.F |

#### `GuardianPublicKey`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `index` | `uint32` |  |  |  | i, 1..n |
| 2 | `vote_commitments` | `bytes` |  | multiple of 512 |  | K_{i,0} \|\| ... \|\| K_{i,k-1} |
| 3 | `data_commitments` | `bytes` |  | multiple of 512 |  | K-hat_{i,0} \|\| ... \|\| K-hat_{i,k-1} |
| 4 | `kappa` | `bytes` |  | 512 |  | kappa_i |
| 5 | `vote_proof` | `bytes` |  | multiple of 32 |  | c_i \|\| v_{i,0} \|\| ... \|\| v_{i,k} |
| 6 | `data_proof` | `bytes` |  | multiple of 32 |  | c-hat_i \|\| v-hat_{i,0} \|\| ... \|\| v-hat_{i,k} |

#### `ElectionKeys`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `k` | `bytes` |  | 512 |  | K (claim; 3.A) |
| 2 | `k_hat` | `bytes` |  | 512 |  | K-hat (claim; 3.B) |
| 3 | `h_e` | `bytes` |  | 32 |  | H_E (claim; 4.A) |

#### `DeviceHeader`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `kind` | `DeviceKind` |  |  |  | = the section key's first byte |
| 2 | `device_id` | `string` |  |  |  | S_device |
| 3 | `h_di` | `bytes` |  | 32 |  | = the section key's last 32 bytes |
| 4 | `chaining_mode` | `uint32` |  |  |  | §3.4.4 identifier: 0 none (absent), 1 simple; must equal the manifest's (8.D/16.E are per device, so the device states it) |
| 5 | `initial_hash` | `bytes` |  | 32, omittable |  | H_0; present iff simple chaining |

#### `HashedCiphertext`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `c0` | `bytes` |  | 512 |  |  |
| 2 | `c1` | `bytes` |  | multiple of 32 |  | 32 (ballot nonce) or 32 * b_Lambda (contest data) |
| 3 | `c2` | `bytes` |  | 64 |  | b(c,32) \|\| b(v,32) (Q20) |

#### `EncryptedField`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `alpha` | `bytes` |  | 512 |  |  |
| 2 | `beta` | `bytes` |  | 512 |  |  |
| 3 | `range_proof` | `bytes` |  | multiple of 64 |  | (c_j \|\| v_j), j = 0..R (or 0..bound, Q2) |

#### `EncryptedContest`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `index` | `uint32` |  |  |  | ind_c |
| 2 | `fields` | `EncryptedField` | repeated |  |  | manifest order: options, then supplemental fields (Q1/Q14) |
| 3 | `limit_proof` | `bytes` |  | multiple of 64 |  | eq. (62), L+1 pairs |
| 4 | `undervote_difference_proof` | `bytes` |  | multiple of 64, omittable |  | iff tracked (Q15) |
| 5 | `null_vote_proof` | `bytes` |  | multiple of 64, omittable |  | iff tracked (Q17) |
| 6 | `contest_data` | `HashedCiphertext` |  |  |  | iff b_Lambda > 0 (S6) |
| 7 | `contest_hash` | `bytes` |  | 32 |  | chi |

#### `EncryptedBallot`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `id_b` | `bytes` |  | 32 |  | first, so an id-only scan reads one field per frame |
| 2 | `h_i` | `bytes` |  | 32 |  |  |
| 3 | `ballot_style` | `string` |  |  |  |  |
| 4 | `status` | `BallotStatus` |  |  |  | CAST, CHALLENGED or SPOILED; never UNSPECIFIED |
| 5 | `weight` | `uint32` |  |  |  | >= 1, so always present (§3.5) |
| 6 | `encrypted_at` | `google.protobuf.Timestamp` |  |  |  | G40; ms UTC; absent when not recorded |
| 7 | `contests` | `EncryptedContest` | repeated |  |  | ascending index; exactly the style's contests |
| 8 | `confirmation_code` | `bytes` |  | 32 |  | H_C |
| 9 | `chaining_field` | `bytes` |  | 36 |  | B_C |
| 10 | `encrypted_ballot_nonce` | `HashedCiphertext` |  |  |  | C_xiB (§3.3.4); c1 exactly 32 bytes |
| 11 | `ballot_ref` | `string` |  |  |  | optional free text; unverified, bound by no hash |

#### `SelectedVector`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `vector` | `bytes` |  | multiple of 1024 |  | m x (alpha \|\| beta), option order |
| 2 | `psi` | `bytes` |  | 32 |  | selection hash psi |
| 3 | `short_code` | `string` |  |  |  |  |

#### `PreEncryptedCastContest`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `contest` | `EncryptedContest` |  |  |  | combined vector, standard proofs (Q26: no contest data) |
| 2 | `selection_hashes` | `bytes` |  | multiple of 32 |  | all m+L psi, strictly ascending |
| 3 | `selected` | `SelectedVector` | repeated |  |  | exactly L, strictly ascending by psi (Q27) |

#### `PreEncryptedCastBallot`

Reserved: 4.

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `id_b` | `bytes` |  | 32 |  |  |
| 2 | `h_i` | `bytes` |  | 32 |  |  |
| 3 | `ballot_style` | `string` |  |  |  |  |
| 5 | `weight` | `uint32` |  |  |  |  |
| 6 | `encrypted_at` | `google.protobuf.Timestamp` |  |  |  | when the cast record was formed |
| 7 | `contests` | `PreEncryptedCastContest` | repeated |  |  | ascending contest.index; exactly the style's contests |
| 8 | `confirmation_code` | `bytes` |  | 32 |  | eq. (116) |
| 9 | `chaining_field` | `bytes` |  | 36 |  |  |
| 10 | `encrypted_ballot_nonce` | `HashedCiphertext` |  |  |  | C_xiB |
| 11 | `ballot_ref` | `string` |  |  |  |  |

#### `UncastSelection`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `selection_index` | `uint32` |  |  |  | eq. (121)'s j: option index, or m+l for the l-th null vector |
| 2 | `option_label` | `string` |  |  |  | absent exactly on null vectors |
| 3 | `vector` | `bytes` |  | multiple of 1024 |  | m x (alpha \|\| beta) |
| 4 | `psi` | `bytes` |  | 32 |  |  |
| 5 | `short_code` | `string` |  |  |  |  |

#### `UncastContest`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `index` | `uint32` |  |  |  |  |
| 2 | `label` | `string` |  |  |  |  |
| 3 | `selections` | `UncastSelection` | repeated |  |  | m+L, ascending selection_index |
| 4 | `contest_hash` | `bytes` |  | 32 |  |  |

#### `PreEncryptedUncastBallot`

Reserved: 4-6.

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `id_b` | `bytes` |  | 32 |  |  |
| 2 | `h_i` | `bytes` |  | 32 |  |  |
| 3 | `ballot_style` | `string` |  |  |  |  |
| 7 | `contests` | `UncastContest` | repeated |  |  | ascending index |
| 8 | `confirmation_code` | `bytes` |  | 32 |  |  |
| 9 | `chaining_field` | `bytes` |  | 36 |  |  |
| 10 | `encrypted_ballot_nonce` | `HashedCiphertext` |  |  |  | C_xiB |
| 11 | `ballot_ref` | `string` |  |  |  |  |

#### `CompactUncastContest`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `index` | `uint32` |  |  |  |  |
| 2 | `contest_hash` | `bytes` |  | 32 |  | chi, eq. (115) |

#### `PreEncryptedCompactUncastBallot`

Reserved: 4-6.

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `id_b` | `bytes` |  | 32 |  |  |
| 2 | `h_i` | `bytes` |  | 32 |  |  |
| 3 | `ballot_style` | `string` |  |  |  |  |
| 7 | `contests` | `CompactUncastContest` | repeated |  |  | ascending index; exactly the style's contests |
| 8 | `confirmation_code` | `bytes` |  | 32 |  | eq. (116) |
| 9 | `chaining_field` | `bytes` |  | 36 |  |  |
| 10 | `encrypted_ballot_nonce` | `HashedCiphertext` |  |  |  | C_xiB |
| 11 | `ballot_ref` | `string` |  |  |  |  |

#### `DeviceClose`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `ballot_count` | `uint64` |  |  |  | l = the number of ballot items in the section |
| 2 | `closing_chaining_field` | `bytes` |  | 36, omittable |  | B-bar_C; iff simple chaining |
| 3 | `closing_hash` | `bytes` |  | 32, omittable |  | H-bar; iff simple chaining |
| 4 | `closed_at` | `google.protobuf.Timestamp` |  |  |  |  |

#### `SignedStatement`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `statement` | `bytes` |  |  |  | the canonical RecordItem bytes of a statement, exactly as signed. Opaque to the wire walk, so the verifier checks it as a RecordItem (canonicality, decode rules, member 40-43) before anything else. |
| 2 | `algorithm` | `string` |  |  |  | registry: ecdsa-p256-sha256, rsa-pss-sha256, ed25519, x509-cms-detached |
| 3 | `key_id` | `bytes` |  |  |  |  |
| 4 | `signer_key` | `bytes` |  |  |  | public key or certificate chain; may be absent (out of band) |
| 5 | `signature` | `bytes` |  |  |  |  |
| 6 | `timestamp_token` | `bytes` |  |  |  | RFC 3161 TimeStampToken over SHA-256(statement); optional |

#### `EncryptedTallyHeader`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `cast_ballot_count` | `uint64` |  |  |  | both kinds; checked (R.summary) |
| 2 | `total_cast_weight` | `uint64` |  |  |  |  |

#### `EncryptedTallyContest`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `index` | `uint32` |  |  |  |  |
| 2 | `fields` | `bytes` |  | multiple of 1024 |  | per manifest field: A \|\| B |
| 3 | `cast_weight` | `uint64` |  |  |  | S10a: sum of W over cast ballots listing the contest |

#### `BallotLocator`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `kind` | `DeviceKind` |  |  |  |  |
| 2 | `h_di` | `bytes` |  | 32 |  |  |
| 3 | `position` | `uint64` |  |  |  | 1-based chain position (the spec's j) |

#### `ContestDataRequest`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `ballot` | `BallotLocator` |  |  |  | a cast regular ballot |
| 2 | `h_i` | `bytes` |  | 32 |  | binding: must equal the ballot's |
| 3 | `contest_index` | `uint32` |  |  |  |  |

#### `DecryptedTallyField`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `index` | `uint32` |  |  |  | manifest option or field index |
| 2 | `label` | `string` |  |  |  |  |
| 3 | `tally` | `uint64` |  |  |  | t |
| 4 | `encoded_tally` | `bytes` |  | 512 |  | T = K^t |
| 5 | `proof` | `bytes` |  | 64 |  | c \|\| v |

#### `DecryptedTallyContest`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `index` | `uint32` |  |  |  |  |
| 2 | `label` | `string` |  |  |  |  |
| 3 | `fields` | `DecryptedTallyField` | repeated |  |  |  |

#### `DecryptedField`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `index` | `uint32` |  |  |  |  |
| 2 | `label` | `string` |  |  |  |  |
| 3 | `value` | `uint32` |  |  |  | sigma |
| 4 | `nonce` | `bytes` |  | 32 |  | xi_{i,j} |

#### `ReleasedContestData`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `nonce` | `bytes` |  | 32 |  | xi_i |
| 2 | `data` | `bytes` |  | multiple of 32 |  | D, 32 * b_Lambda bytes |

#### `DecryptedContest`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `index` | `uint32` |  |  |  |  |
| 2 | `label` | `string` |  |  |  |  |
| 3 | `fields` | `DecryptedField` | repeated |  |  | every field of the contest |
| 4 | `contest_data` | `ReleasedContestData` |  |  |  | iff the contest has contest data |

#### `ChallengedBallotDecryption`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `ballot` | `BallotLocator` |  |  |  | a CHALLENGED regular ballot |
| 2 | `h_i` | `bytes` |  | 32 |  | binding: must equal the ballot's |
| 3 | `contests` | `DecryptedContest` | repeated |  |  | ascending index |

#### `ContestDataDecryption`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `ballot` | `BallotLocator` |  |  |  |  |
| 2 | `h_i` | `bytes` |  | 32 |  |  |
| 3 | `contest_index` | `uint32` |  |  |  |  |
| 4 | `beta` | `bytes` |  | 512 |  |  |
| 5 | `proof` | `bytes` |  | 64 |  | c \|\| v |
| 6 | `data` | `bytes` |  | multiple of 32 |  | D |

#### `UncastContestNonces`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `index` | `uint32` |  |  |  |  |
| 2 | `nonces` | `bytes` |  | multiple of 32 |  | xi_{i,j,k}: (m+L) selections x m options, selection-major |

#### `UncastNonceRelease`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `ballot` | `BallotLocator` |  |  |  | a PreEncryptedUncastBallot or PreEncryptedCompactUncastBallot |
| 2 | `h_i` | `bytes` |  | 32 |  |  |
| 3 | `contests` | `UncastContestNonces` | repeated |  |  | full item: ascending index, every contest; compact item: absent |
| 4 | `ballot_nonce` | `bytes` |  | 32, omittable |  | xi_B in plaintext: present iff the item is compact (Q28 opt-in, or never returned, NQ-2); the xi_{i,j,k} follow by eq. (121) |

#### `ChainCloseStatement`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `h_e` | `bytes` |  | 32 |  |  |
| 2 | `device_key` | `bytes` |  | 33 |  | kind byte \|\| H_DI |
| 3 | `device_id` | `string` |  |  |  |  |
| 4 | `chaining_mode` | `uint32` |  |  |  |  |
| 5 | `ballot_count` | `uint64` |  |  |  |  |
| 6 | `codes_root` | `bytes` |  | 32 |  | MTH over the section's confirmation codes, chain order |
| 7 | `closing_hash` | `bytes` |  | 32, omittable |  | H-bar; iff simple chaining |
| 8 | `closed_at` | `google.protobuf.Timestamp` |  |  |  |  |

#### `SectionSealStatement`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `h_e` | `bytes` |  | 32 |  |  |
| 2 | `device_key` | `bytes` |  | 33 |  |  |
| 3 | `item_count` | `uint64` |  |  |  | l + 2 (header and close) |
| 4 | `section_root` | `bytes` |  | 32 |  |  |

#### `PrefixCheckpointStatement`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `h_e` | `bytes` |  | 32 |  |  |
| 2 | `device_key` | `bytes` |  | 33 |  |  |
| 3 | `ballot_count` | `uint64` |  |  |  |  |
| 4 | `codes_root` | `bytes` |  | 32 |  |  |
| 5 | `at` | `google.protobuf.Timestamp` |  |  |  |  |

#### `RecordStatement`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `phase` | `RecordPhase` |  |  |  |  |
| 2 | `root` | `bytes` |  | 32 |  |  |
| 3 | `h_e` | `bytes` |  | 32 |  |  |
| 4 | `format_major` | `uint32` |  |  |  |  |
| 5 | `format_minor` | `uint32` |  |  |  |  |
| 6 | `signed_at` | `google.protobuf.Timestamp` |  |  |  | §3.7 "together with the date" |
| 7 | `signer_role` | `string` |  |  |  |  |

#### `TocEntry`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `section_type` | `SectionType` |  |  |  |  |
| 2 | `key` | `bytes` |  |  |  |  |
| 3 | `critical` | `bool` |  |  |  | fixed per section type (design §4.5: true for every v2 type); a claimed TOC entry that disagrees is R.root. A new section type comes only with a new format major (user decision NQ-7); a v2 reader refuses one (R.version) |
| 4 | `item_count` | `uint64` |  |  |  |  |
| 5 | `root` | `bytes` |  | 32 |  | the section's Merkle root |

#### `ConfirmationCodeLeaf`

| # | Field | Type | Label | Width (bytes) | Oneof | Note |
|---|---|---|---|---|---|---|
| 1 | `code` | `bytes` |  | 32 |  | H_C |

### A.2 Enumerations

#### `SectionType`

| # | Value | Note |
|---|---|---|
| 0 | `SECTION_TYPE_UNSPECIFIED` |  |
| 1 | `SECTION_TYPE_HEADER` |  |
| 2 | `SECTION_TYPE_PARAMETERS` |  |
| 3 | `SECTION_TYPE_MANIFEST` |  |
| 4 | `SECTION_TYPE_GUARDIANS` |  |
| 5 | `SECTION_TYPE_ELECTION_KEYS` |  |
| 257 | `SECTION_TYPE_DEVICE` | 0x0101; key = device key (33 bytes) |
| 258 | `SECTION_TYPE_DEVICE_ATTESTATIONS` | 0x0102 |
| 513 | `SECTION_TYPE_ENCRYPTED_TALLY` | 0x0201 |
| 514 | `SECTION_TYPE_CONTEST_DATA_REQUESTS` | 0x0202 |
| 769 | `SECTION_TYPE_DECRYPTED_TALLY` | 0x0301 |
| 770 | `SECTION_TYPE_CHALLENGED_BALLOT_DECRYPTIONS` | 0x0302 |
| 771 | `SECTION_TYPE_CONTEST_DATA_DECRYPTIONS` | 0x0303 |
| 772 | `SECTION_TYPE_UNCAST_NONCE_RELEASES` | 0x0304 |
| 65534 | `SECTION_TYPE_TOC` | pseudo-section: the claimed TOC; never in a TOC |
| 65535 | `SECTION_TYPE_SIGNATURES` | pseudo-section: outside every root |

#### `DeviceKind`

| # | Value | Note |
|---|---|---|
| 0 | `DEVICE_KIND_UNSPECIFIED` |  |
| 1 | `DEVICE_KIND_REGULAR` | Verification 8; H_DI by eq. (72) |
| 2 | `DEVICE_KIND_PRE_ENCRYPTING` | Verification 16; H_DI by eq. (119) |

#### `BallotStatus`

| # | Value | Note |
|---|---|---|
| 0 | `BALLOT_STATUS_UNSPECIFIED` |  |
| 1 | `BALLOT_STATUS_CAST` |  |
| 2 | `BALLOT_STATUS_CHALLENGED` |  |
| 3 | `BALLOT_STATUS_SPOILED` |  |

#### `RecordPhase`

| # | Value | Note |
|---|---|---|
| 0 | `RECORD_PHASE_UNSPECIFIED` |  |
| 1 | `RECORD_PHASE_SETUP` |  |
| 2 | `RECORD_PHASE_SEALED` |  |
| 3 | `RECORD_PHASE_AGGREGATED` |  |
| 4 | `RECORD_PHASE_FINAL` |  |

<!-- END GENERATED -->
