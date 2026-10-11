#!/usr/bin/env python3
"""EGRF v2 reference reader (design §5.7, S10b-12).

An independent second implementation of the ElectionGuard Record Format v2, written from
docs/spec-compliance/2026-10-08-election-record-design.md and proto/electionguard/egrf/v2/egrf.proto
only, in the spirit of the KAT oracle (test/kat/eg_kat.py). Python 3, standard library only: no
protobuf runtime. It implements

  - the schema, transcribed by hand from the .proto into SCHEMA below (checked against
    test/egrf/schema.json, which the C# lint test generates from the compiled descriptor);
  - Method A, the wire walk (§4.4), with W1-W8, the W6 unknown-field rule for a reader older than
    the record, and the decode rules D1-D6 (§4.3);
  - the signed-statement check (§4.9: R.attestation, R.signature);
  - length-delimited segments with the 64 MiB frame ceiling (§5.2), the directory and .zip carriers
    (§5.3, §5.3.1, §5.4; the zip checks are done on the raw bytes, `zipfile` reads the entries), and
    the JSON-lines projection (§5.5: proto3 JSON parsed into canonical bytes);
  - RFC 9162 Merkle trees, section roots, the TOC and the phase roots (§4.9), the claimed-TOC
    comparison (R.root), section presence (R.structure), join and attestation order (R.order), the
    tally header (R.summary), and the contents of attestations and record signatures
    (R.attestation, R.signature).

It does not run the cryptographic verifications (V1-V19), and it does not check signature validity
(the standard library has no ECDSA): a signature is checked for its statement's form and contents
only.

Usage:
  egrf_ref.py --check [--root REPO]        schema table, vectors, Merkle vectors, golden records
  egrf_ref.py read PATH [--json]           read a record (directory or .zip) and report
  egrf_ref.py item HEX [--minor N]         check one RecordItem

Exit codes of `read`: 0 no finding and complete, 2 no finding but content of a newer minor skipped,
1 any finding, 3 usage or I/O error.
"""

import base64
import datetime
import hashlib
import json
import os
import re
import struct
import sys
import zipfile
import zlib

READER_MAJOR = 2
READER_MINOR = 0
MAX_FRAME = 64 * 1024 * 1024
MAX_LINE = 1 << 27

# ---------------------------------------------------------------------------------------------
# Schema (transcribed from egrf.proto)
# ---------------------------------------------------------------------------------------------

U32, U64, BOOL, ENUM, STR, BYTES, MSG, I64, I32 = (
    "uint32", "uint64", "bool", "enum", "string", "bytes", "message", "int64", "int32")
VARINT_TYPES = (U32, U64, BOOL, ENUM, I64, I32)


class Field:
    def __init__(self, number, name, ftype, ref=None, repeated=False, width=None, wm=None,
                 omit=False, oneof=None):
        self.number, self.name, self.type, self.ref = number, name, ftype, ref
        self.repeated, self.width, self.wm, self.omit, self.oneof = repeated, width, wm, omit, oneof
        self.json_name = json_name(name)


def json_name(name):
    parts = name.split("_")
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


class Message:
    def __init__(self, name, fields, reserved=()):
        self.name = name
        self.fields = {f.number: f for f in fields}
        self.reserved = set(reserved)
        self.max_number = max(list(self.fields) + list(self.reserved))
        self.by_json = {}
        for f in fields:
            self.by_json[f.json_name] = f
            self.by_json[f.name] = f


def F(number, name, ftype, ref=None, **kw):
    return Field(number, name, ftype, ref, **kw)


def B(number, name, width=None, wm=None, omit=False):
    return Field(number, name, BYTES, None, width=width, wm=wm, omit=omit)


def M(number, name, ref, repeated=False, oneof=None):
    return Field(number, name, MSG, ref, repeated=repeated, oneof=oneof)


TS = "google.protobuf.Timestamp"

_ITEM_MEMBERS = [
    (1, "record_header", "RecordHeader"), (2, "parameters", "Parameters"),
    (3, "manifest_file", "ManifestFile"), (4, "guardian_public_key", "GuardianPublicKey"),
    (5, "election_keys", "ElectionKeys"), (10, "device_header", "DeviceHeader"),
    (11, "encrypted_ballot", "EncryptedBallot"), (12, "pre_encrypted_cast_ballot", "PreEncryptedCastBallot"),
    (13, "pre_encrypted_uncast_ballot", "PreEncryptedUncastBallot"), (14, "device_close", "DeviceClose"),
    (15, "device_attestation", "SignedStatement"),
    (16, "pre_encrypted_compact_uncast_ballot", "PreEncryptedCompactUncastBallot"),
    (20, "encrypted_tally_header", "EncryptedTallyHeader"),
    (21, "encrypted_tally_contest", "EncryptedTallyContest"),
    (22, "contest_data_request", "ContestDataRequest"),
    (30, "decrypted_tally_contest", "DecryptedTallyContest"),
    (31, "challenged_ballot_decryption", "ChallengedBallotDecryption"),
    (32, "contest_data_decryption", "ContestDataDecryption"),
    (33, "uncast_nonce_release", "UncastNonceRelease"),
    (40, "chain_close_statement", "ChainCloseStatement"),
    (41, "section_seal_statement", "SectionSealStatement"),
    (42, "prefix_checkpoint_statement", "PrefixCheckpointStatement"),
    (43, "record_statement", "RecordStatement"), (44, "record_signature", "SignedStatement"),
    (50, "toc_entry", "TocEntry"), (51, "confirmation_code_leaf", "ConfirmationCodeLeaf"),
]
MEMBER_NAME = {n: name for n, name, _ in _ITEM_MEMBERS}


def _ballot_fields(contest_ref, cast):
    fields = [B(1, "id_b", 32), B(2, "h_i", 32), F(3, "ballot_style", STR)]
    if cast:
        fields += [F(5, "weight", U32), M(6, "encrypted_at", TS)]
    fields += [M(7, "contests", contest_ref, repeated=True), B(8, "confirmation_code", 32),
               B(9, "chaining_field", 36), M(10, "encrypted_ballot_nonce", "HashedCiphertext"),
               F(11, "ballot_ref", STR)]
    return fields


SCHEMA = {m.name: m for m in [
    Message(TS, [F(1, "seconds", I64), F(2, "nanos", I32)]),
    Message("SegmentHeader", [F(1, "magic", STR), F(2, "format_major", U32),
                              F(3, "section_type", ENUM, "SectionType"), B(4, "key"),
                              F(5, "first_ordinal", U64)]),
    Message("RecordItem", [M(n, name, ref, oneof="item") for n, name, ref in _ITEM_MEMBERS],
            reserved=[100, 2047]),
    Message("RecordHeader", [F(1, "format_major", U32), F(2, "format_minor", U32)], reserved=[3]),
    Message("Parameters", [B(1, "version", 32), B(2, "p", 512), B(3, "q", 32), B(4, "r", 512),
                           B(5, "g", 512), F(6, "n", U32), F(7, "k", U32), B(8, "h_p", 32)]),
    Message("ManifestFile", [F(1, "media_type", STR), B(2, "content"), B(3, "h_b", 32)]),
    Message("GuardianPublicKey", [F(1, "index", U32), B(2, "vote_commitments", wm=512),
                                  B(3, "data_commitments", wm=512), B(4, "kappa", 512),
                                  B(5, "vote_proof", wm=32), B(6, "data_proof", wm=32)]),
    Message("ElectionKeys", [B(1, "k", 512), B(2, "k_hat", 512), B(3, "h_e", 32)]),
    Message("DeviceHeader", [F(1, "kind", ENUM, "DeviceKind"), F(2, "device_id", STR),
                             B(3, "h_di", 32), F(4, "chaining_mode", U32),
                             B(5, "initial_hash", 32, omit=True)]),
    Message("HashedCiphertext", [B(1, "c0", 512), B(2, "c1", wm=32), B(3, "c2", 64)]),
    Message("EncryptedField", [B(1, "alpha", 512), B(2, "beta", 512), B(3, "range_proof", wm=64)]),
    Message("EncryptedContest", [F(1, "index", U32), M(2, "fields", "EncryptedField", repeated=True),
                                 B(3, "limit_proof", wm=64),
                                 B(4, "undervote_difference_proof", wm=64, omit=True),
                                 B(5, "null_vote_proof", wm=64, omit=True),
                                 M(6, "contest_data", "HashedCiphertext"), B(7, "contest_hash", 32)]),
    Message("EncryptedBallot", [B(1, "id_b", 32), B(2, "h_i", 32), F(3, "ballot_style", STR),
                                F(4, "status", ENUM, "BallotStatus"), F(5, "weight", U32),
                                M(6, "encrypted_at", TS),
                                M(7, "contests", "EncryptedContest", repeated=True),
                                B(8, "confirmation_code", 32), B(9, "chaining_field", 36),
                                M(10, "encrypted_ballot_nonce", "HashedCiphertext"),
                                F(11, "ballot_ref", STR)]),
    Message("SelectedVector", [B(1, "vector", wm=1024), B(2, "psi", 32), F(3, "short_code", STR)]),
    Message("PreEncryptedCastContest", [M(1, "contest", "EncryptedContest"),
                                        B(2, "selection_hashes", wm=32),
                                        M(3, "selected", "SelectedVector", repeated=True)]),
    Message("PreEncryptedCastBallot", _ballot_fields("PreEncryptedCastContest", True), reserved=[4]),
    Message("UncastSelection", [F(1, "selection_index", U32), F(2, "option_label", STR),
                                B(3, "vector", wm=1024), B(4, "psi", 32), F(5, "short_code", STR)]),
    Message("UncastContest", [F(1, "index", U32), F(2, "label", STR),
                              M(3, "selections", "UncastSelection", repeated=True),
                              B(4, "contest_hash", 32)]),
    Message("PreEncryptedUncastBallot", _ballot_fields("UncastContest", False), reserved=[4, 5, 6]),
    Message("CompactUncastContest", [F(1, "index", U32), B(2, "contest_hash", 32)]),
    Message("PreEncryptedCompactUncastBallot", _ballot_fields("CompactUncastContest", False),
            reserved=[4, 5, 6]),
    Message("DeviceClose", [F(1, "ballot_count", U64), B(2, "closing_chaining_field", 36, omit=True),
                            B(3, "closing_hash", 32, omit=True), M(4, "closed_at", TS)]),
    Message("SignedStatement", [B(1, "statement"), F(2, "algorithm", STR), B(3, "key_id"),
                                B(4, "signer_key"), B(5, "signature"), B(6, "timestamp_token")]),
    Message("EncryptedTallyHeader", [F(1, "cast_ballot_count", U64), F(2, "total_cast_weight", U64)]),
    Message("EncryptedTallyContest", [F(1, "index", U32), B(2, "fields", wm=1024),
                                      F(3, "cast_weight", U64)]),
    Message("BallotLocator", [F(1, "kind", ENUM, "DeviceKind"), B(2, "h_di", 32),
                              F(3, "position", U64)]),
    Message("ContestDataRequest", [M(1, "ballot", "BallotLocator"), B(2, "h_i", 32),
                                   F(3, "contest_index", U32)]),
    Message("DecryptedTallyField", [F(1, "index", U32), F(2, "label", STR), F(3, "tally", U64),
                                    B(4, "encoded_tally", 512), B(5, "proof", 64)]),
    Message("DecryptedTallyContest", [F(1, "index", U32), F(2, "label", STR),
                                      M(3, "fields", "DecryptedTallyField", repeated=True)]),
    Message("DecryptedField", [F(1, "index", U32), F(2, "label", STR), F(3, "value", U32),
                               B(4, "nonce", 32)]),
    Message("ReleasedContestData", [B(1, "nonce", 32), B(2, "data", wm=32)]),
    Message("DecryptedContest", [F(1, "index", U32), F(2, "label", STR),
                                 M(3, "fields", "DecryptedField", repeated=True),
                                 M(4, "contest_data", "ReleasedContestData")]),
    Message("ChallengedBallotDecryption", [M(1, "ballot", "BallotLocator"), B(2, "h_i", 32),
                                           M(3, "contests", "DecryptedContest", repeated=True)]),
    Message("ContestDataDecryption", [M(1, "ballot", "BallotLocator"), B(2, "h_i", 32),
                                      F(3, "contest_index", U32), B(4, "beta", 512),
                                      B(5, "proof", 64), B(6, "data", wm=32)]),
    Message("UncastContestNonces", [F(1, "index", U32), B(2, "nonces", wm=32)]),
    Message("UncastNonceRelease", [M(1, "ballot", "BallotLocator"), B(2, "h_i", 32),
                                   M(3, "contests", "UncastContestNonces", repeated=True),
                                   B(4, "ballot_nonce", 32, omit=True)]),
    Message("ChainCloseStatement", [B(1, "h_e", 32), B(2, "device_key", 33), F(3, "device_id", STR),
                                    F(4, "chaining_mode", U32), F(5, "ballot_count", U64),
                                    B(6, "codes_root", 32), B(7, "closing_hash", 32, omit=True),
                                    M(8, "closed_at", TS)]),
    Message("SectionSealStatement", [B(1, "h_e", 32), B(2, "device_key", 33),
                                     F(3, "item_count", U64), B(4, "section_root", 32)]),
    Message("PrefixCheckpointStatement", [B(1, "h_e", 32), B(2, "device_key", 33),
                                          F(3, "ballot_count", U64), B(4, "codes_root", 32),
                                          M(5, "at", TS)]),
    Message("RecordStatement", [F(1, "phase", ENUM, "RecordPhase"), B(2, "root", 32),
                                B(3, "h_e", 32), F(4, "format_major", U32), F(5, "format_minor", U32),
                                M(6, "signed_at", TS), F(7, "signer_role", STR)]),
    Message("TocEntry", [F(1, "section_type", ENUM, "SectionType"), B(2, "key"),
                         F(3, "critical", BOOL), F(4, "item_count", U64), B(5, "root", 32)]),
    Message("ConfirmationCodeLeaf", [B(1, "code", 32)]),
]}

ENUMS = {
    "SectionType": {0: "SECTION_TYPE_UNSPECIFIED", 1: "SECTION_TYPE_HEADER", 2: "SECTION_TYPE_PARAMETERS",
                    3: "SECTION_TYPE_MANIFEST", 4: "SECTION_TYPE_GUARDIANS",
                    5: "SECTION_TYPE_ELECTION_KEYS", 257: "SECTION_TYPE_DEVICE",
                    258: "SECTION_TYPE_DEVICE_ATTESTATIONS", 513: "SECTION_TYPE_ENCRYPTED_TALLY",
                    514: "SECTION_TYPE_CONTEST_DATA_REQUESTS", 769: "SECTION_TYPE_DECRYPTED_TALLY",
                    770: "SECTION_TYPE_CHALLENGED_BALLOT_DECRYPTIONS",
                    771: "SECTION_TYPE_CONTEST_DATA_DECRYPTIONS",
                    772: "SECTION_TYPE_UNCAST_NONCE_RELEASES", 65534: "SECTION_TYPE_TOC",
                    65535: "SECTION_TYPE_SIGNATURES"},
    "DeviceKind": {0: "DEVICE_KIND_UNSPECIFIED", 1: "DEVICE_KIND_REGULAR", 2: "DEVICE_KIND_PRE_ENCRYPTING"},
    "BallotStatus": {0: "BALLOT_STATUS_UNSPECIFIED", 1: "BALLOT_STATUS_CAST", 2: "BALLOT_STATUS_CHALLENGED",
                     3: "BALLOT_STATUS_SPOILED"},
    "RecordPhase": {0: "RECORD_PHASE_UNSPECIFIED", 1: "RECORD_PHASE_SETUP", 2: "RECORD_PHASE_SEALED",
                    3: "RECORD_PHASE_AGGREGATED", 4: "RECORD_PHASE_FINAL"},
}
ENUM_BY_NAME = {e: {v: k for k, v in vals.items()} for e, vals in ENUMS.items()}
# §4.3 D2 and §7: SectionType (NQ-7) and DeviceKind (NQ-9) are closed: an undeclared value is D2 for
# a reader of any minor. The others may grow in a minor.
CLOSED_ENUMS = {"SectionType", "DeviceKind"}


# ---------------------------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------------------------

class Fail(Exception):
    """A profile-rule failure: `rule` is W1-W8 or D1-D6."""

    def __init__(self, rule, message):
        super().__init__(f"{rule}: {message}")
        self.rule, self.message = rule, message


class RecordFail(Exception):
    """A record-level failure that stops reading: `code` is an R-code."""

    def __init__(self, code, message, rule=None):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.rule = code, message, rule


# ---------------------------------------------------------------------------------------------
# Method A: the wire walk (§4.2.2, §4.3, §4.4)
# ---------------------------------------------------------------------------------------------

def read_varint(buf, pos):
    """A minimal varint (W4) of at most 64 bits; W5 if cut short."""
    value, shift, start = 0, 0, pos
    while True:
        if pos >= len(buf):
            raise Fail("W5", f"varint cut short at byte {start}")
        b = buf[pos]
        pos += 1
        if shift == 63 and b > 1:
            raise Fail("W4", f"varint longer than 64 bits at byte {start}")
        value |= (b & 0x7F) << shift
        if b < 0x80:
            if b == 0 and pos - start > 1:
                raise Fail("W4", f"overlong varint at byte {start}")
            return value, pos
        shift += 7
        if shift > 63:
            raise Fail("W4", f"varint longer than 64 bits at byte {start}")


def encode_varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


class Ctx:
    """The reader's view of the record: whether the record's minor is newer than the reader's."""

    def __init__(self, record_minor=READER_MINOR):
        self.newer = record_minor > READER_MINOR
        self.unknown = []   # content not understood: (message, what)

    def note(self, msg, what):
        self.unknown.append(f"{msg}: {what}")


def walk(buf, msg_name, ctx):
    """Check `buf` as a canonical encoding of `msg_name`; return its known values by field name."""
    msg = SCHEMA[msg_name]
    pos, last, in_unknown = 0, 0, False
    values, raw_counts = {}, 0
    while pos < len(buf):
        tag, pos = read_varint(buf, pos)
        number, wt = tag >> 3, tag & 7
        if number == 0 or number > (1 << 29) - 1:
            raise Fail("W3", f"{msg_name}: invalid field number {number}")
        field = msg.fields.get(number)
        raw_counts += 1
        if field is not None:
            if in_unknown:
                raise Fail("W6", f"{msg_name}: known field {number} after an unknown field")
            expected = 0 if field.type in VARINT_TYPES else 2
            if wt != expected:
                raise Fail("W3", f"{msg_name}.{field.name}: wire type {wt}, expected {expected}")
            if number < last:
                raise Fail("W1", f"{msg_name}.{field.name}: field {number} after field {last}")
            if number == last and not field.repeated:
                raise Fail("W2", f"{msg_name}.{field.name}: singular field written twice")
            if wt == 0:
                value, pos = read_varint(buf, pos)
                if value == 0:
                    raise Fail("W2", f"{msg_name}.{field.name}: default value written explicitly")
                if field.type == BOOL and value != 1:
                    raise Fail("W4", f"{msg_name}.{field.name}: bool written as {value}")
            else:
                length, pos = read_varint(buf, pos)
                if pos + length > len(buf):
                    raise Fail("W5", f"{msg_name}.{field.name}: length {length} past the end")
                payload = bytes(buf[pos:pos + length])
                pos += length
                if field.type == STR:
                    if not payload:
                        raise Fail("W2", f"{msg_name}.{field.name}: empty string written")
                    try:
                        value = payload.decode("utf-8", "strict")
                    except UnicodeDecodeError:
                        raise Fail("W8", f"{msg_name}.{field.name}: ill-formed UTF-8")
                elif field.type == BYTES:
                    if not payload:
                        raise Fail("W2", f"{msg_name}.{field.name}: empty bytes written")
                    value = payload
                else:
                    value = walk(payload, field.ref, ctx)
            if field.repeated:
                values.setdefault(field.name, []).append(value)
            else:
                values[field.name] = value
        else:
            if not ctx.newer:
                raise Fail("W6", f"{msg_name}: unknown field {number} in a record of the reader's minor")
            if msg_name == "RecordItem":
                if number in msg.reserved:
                    raise Fail("W6", f"RecordItem: unknown member {number} at a reserved number")
            elif number <= msg.max_number:
                raise Fail("W6", f"{msg_name}: unknown field {number} inside the declared or reserved range")
            if number < last:
                raise Fail("W6", f"{msg_name}: unknown field {number} after field {last}")
            if number == last and wt != 2:
                raise Fail("W6", f"{msg_name}: unknown VARINT field {number} repeated")
            if wt == 0:
                value, pos = read_varint(buf, pos)
                if value == 0:
                    raise Fail("W2", f"{msg_name}: unknown VARINT field {number} of value 0")
            elif wt == 2:
                length, pos = read_varint(buf, pos)
                if pos + length > len(buf):
                    raise Fail("W5", f"{msg_name}: unknown field {number} past the end")
                pos += length
            else:
                raise Fail("W3", f"{msg_name}: unknown field {number} of wire type {wt}")
            in_unknown = True
            ctx.note(msg_name, f"unknown field {number}")
        last = number
    decode_rules(msg, values, ctx)
    if msg_name == "RecordItem" and raw_counts != 1:
        raise Fail("D5", f"RecordItem with {raw_counts} fields")
    return values


def decode_rules(msg, values, ctx):
    for f in msg.fields.values():
        v = values.get(f.name)
        if f.type == BYTES and (f.width or f.wm):
            if v is None:
                if not f.omit:
                    raise Fail("D1", f"{msg.name}.{f.name}: absent, and not omittable")
            elif f.width and len(v) != f.width:
                raise Fail("D1", f"{msg.name}.{f.name}: {len(v)} bytes, width {f.width}")
            elif f.wm and len(v) % f.wm:
                raise Fail("D1", f"{msg.name}.{f.name}: {len(v)} bytes, not a multiple of {f.wm}")
        elif f.type == ENUM:
            if v is None:
                raise Fail("D2", f"{msg.name}.{f.name}: absent, so UNSPECIFIED")
            # An enum is an int32 on the wire, a negative one sign-extended to 64 bits: a varint in
            # [2^31, 2^64 - 2^31) is no int32 encoding, D2 at any reader age; one at or above
            # 2^64 - 2^31 is the negative int32 v - 2^64, which no enum declares, decided below.
            if (1 << 31) <= v < (1 << 64) - (1 << 31):
                raise Fail("D2", f"{msg.name}.{f.name}: {v} is no int32 enum value")
            if v >= (1 << 64) - (1 << 31):
                v -= 1 << 64
            if v not in ENUMS[f.ref]:
                if f.ref in CLOSED_ENUMS or not ctx.newer:
                    raise Fail("D2", f"{msg.name}.{f.name}: undeclared {f.ref} value {v}")
                ctx.note(msg.name, f"undeclared {f.ref} value {v} in {f.name}")
        elif f.type == U32 and v is not None and v >= 1 << 31:
            raise Fail("D4", f"{msg.name}.{f.name}: uint32 {v} not below 2^31")
        elif f.type == U64 and v is not None and v >= 1 << 63:
            raise Fail("D4", f"{msg.name}.{f.name}: uint64 {v} not below 2^63")
    if msg.name == TS:
        seconds = values.get("seconds", 0)
        nanos = values.get("nanos", 0)
        if seconds >= 1 << 63:
            seconds -= 1 << 64
        if nanos >= 1 << 63:
            nanos -= 1 << 64
        if not 0 <= seconds <= 253402300799:
            raise Fail("D3", f"timestamp seconds {seconds} outside 1970-01-01..9999-12-31")
        if not 0 <= nanos <= 999_000_000 or nanos % 1_000_000:
            raise Fail("D3", f"timestamp nanos {nanos} not whole milliseconds")


def check_item(buf, ctx):
    """Method A on one RecordItem; returns (member number, member name, values)."""
    values = walk(buf, "RecordItem", ctx)
    if not values:
        # The one field was an unknown member (a reader older than the record).
        tag, _ = read_varint(buf, 0)
        return tag >> 3, None, None
    (name, value), = values.items()
    number = next(n for n, f in SCHEMA["RecordItem"].fields.items() if f.name == name)
    return number, name, value


def check_segment_header(buf, ctx, expect_type=None, expect_key=None):
    """D6: any failure is R.container."""
    try:
        v = walk(buf, "SegmentHeader", ctx)
    except Fail as e:
        raise RecordFail("R.container", f"segment header: {e.rule} {e.message}", "D6")
    if v.get("magic") != "EGRF":
        raise RecordFail("R.container", f"segment header magic {v.get('magic')!r}", "D6")
    if v.get("format_major") != READER_MAJOR:
        raise RecordFail("R.container", f"segment header of format major {v.get('format_major')}", "D6")
    if expect_type is not None and v.get("section_type") != expect_type:
        raise RecordFail("R.container",
                         f"segment header names section type {v.get('section_type')}, the path {expect_type}",
                         "D6")
    if expect_key is not None and v.get("key", b"") != expect_key:
        raise RecordFail("R.container", "segment header key differs from the path", "D6")
    return v


STATEMENT_MEMBERS = {15: ("R.attestation", {40, 41, 42}), 44: ("R.signature", {43})}


def check_signed_statement(member, value, ctx):
    """§4.9: the statement bytes are a canonical RecordItem of a statement member."""
    code, allowed = STATEMENT_MEMBERS[member]
    statement = value.get("statement", b"")
    try:
        smember, sname, svalues = check_item(statement, ctx)
    except Fail as e:
        raise RecordFail(code, f"statement not canonical: {e.rule} {e.message}", e.rule)
    if smember not in allowed:
        raise RecordFail(code, f"statement member {smember} is not one of {sorted(allowed)}")
    return smember, sname, svalues


def leaf_hash(item):
    return hashlib.sha256(b"\x00" + item).digest()


# ---------------------------------------------------------------------------------------------
# Merkle (RFC 9162 §2.1)
# ---------------------------------------------------------------------------------------------

def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    """Merkle tree hash over leaf hashes."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _split(n)
    return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()


def inclusion_path(m, leaves):
    n = len(leaves)
    if n <= 1:
        return []
    k = _split(n)
    if m < k:
        return inclusion_path(m, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_path(m - k, leaves[k:]) + [mth(leaves[:k])]


def consistency_proof(m, leaves):
    def sub(m, d, b):
        n = len(d)
        if m == n:
            return [] if b else [mth(d)]
        k = _split(n)
        if m <= k:
            return sub(m, d[:k], b) + [mth(d[k:])]
        return sub(m - k, d[k:], False) + [mth(d[:k])]
    return sub(m, leaves, True)


def verify_inclusion(leaf, index, size, root, path):
    """RFC 9162 §2.1.3.2."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ---------------------------------------------------------------------------------------------
# Proto3 JSON projection (§5.5): parse a line into canonical bytes
# ---------------------------------------------------------------------------------------------

class JsonFail(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


class JObj(list):
    """A JSON object as its list of (name, value) pairs, in document order."""


def _no_duplicates(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise JsonFail("R.encoding", f"member {k!r} named twice")
        seen.add(k)
    return JObj(pairs)


def _reject_constant(name):
    raise JsonFail("R.encoding", f"JSON constant {name}")


class JNumber:
    """A JSON number token as written (json.loads' parse_int/parse_float hooks): an integer's form
    is judged on its text (§5.5)."""
    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text


def parse_json_line(text_bytes):
    try:
        text = text_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise JsonFail("R.encoding", "line is not UTF-8")
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant,
                          parse_int=JNumber, parse_float=JNumber)
    except JsonFail:
        raise
    except ValueError as e:
        raise JsonFail("R.encoding", f"line does not parse as JSON: {e}")


_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_DECIMAL = re.compile(r"0|-?[1-9][0-9]*")


def _b64(s, where):
    """§5.5: bytes are the standard base64 alphabet with padding, unused bits zero, nothing else (the
    one form the mapping writes; URL-safe, unpadded or spaced forms are R.encoding)."""
    if not isinstance(s, str) or not _B64.match(s) or len(s) % 4:
        raise JsonFail("R.encoding", f"{where}: not canonical base64")
    try:
        value = base64.b64decode(s, validate=True)
    except ValueError:
        raise JsonFail("R.encoding", f"{where}: not canonical base64")
    if base64.b64encode(value).decode("ascii") != s:
        raise JsonFail("R.encoding", f"{where}: not canonical base64")
    return value


def _integer(v, where, bits, signed=False):
    """§5.5: an integer is a JSON number or a string, either in plain decimal (no sign but a leading
    '-', no leading zero, no fraction or exponent); any other form is R.encoding."""
    text = v.text if isinstance(v, JNumber) else v
    if not isinstance(text, str) or not _DECIMAL.fullmatch(text):
        raise JsonFail("R.encoding", f"{where}: not an integer in plain decimal")
    v = int(text)
    lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    if not lo <= v <= hi:
        raise JsonFail("R.encoding", f"{where}: {v} out of range")
    return v


_RFC3339 = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$")


def _timestamp(v, where):
    m = _RFC3339.match(v) if isinstance(v, str) else None
    if not m:
        raise JsonFail("R.encoding", f"{where}: not an RFC 3339 timestamp")
    y, mo, d, h, mi, s, frac, off = m.groups()
    try:
        dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s),
                               tzinfo=datetime.timezone.utc)
    except ValueError:
        raise JsonFail("R.encoding", f"{where}: not a valid date")
    seconds = (dt - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)) // datetime.timedelta(seconds=1)
    if off != "Z":
        sign = 1 if off[0] == "+" else -1
        seconds -= sign * (int(off[1:3]) * 3600 + int(off[4:6]) * 60)
    nanos = int((frac or "").ljust(9, "0")) if frac else 0
    if 0 <= seconds <= 253402300799 and nanos % 1_000_000 == 0:
        # §5.5 one written form (provisional rule (d), S10b-F review round 2): what the mapping's
        # formatter writes for a value D3 allows: Z, no fraction for a whole second, else exactly
        # three digits. A value outside D3 is left for D3 to name.
        at = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=seconds)
        written = (f"{at.year:04d}-{at.month:02d}-{at.day:02d}T{at.hour:02d}:{at.minute:02d}:{at.second:02d}"
                   + (f".{nanos // 1_000_000:03d}" if nanos else "") + "Z")
        if written != v:
            raise JsonFail("R.encoding", f"{where}: {v!r} is not in the one written form {written!r}")
    out = {}
    if seconds:
        out["seconds"] = seconds
    if nanos:
        out["nanos"] = nanos
    return out


def json_to_values(obj, msg_name, ctx, where):
    """Map a proto3 JSON object to the walk's value form (field name -> value)."""
    if msg_name == TS:
        return _timestamp(obj, where)
    if not isinstance(obj, JObj):
        raise JsonFail("R.encoding", f"{where}: {msg_name} is not an object")
    msg = SCHEMA[msg_name]
    out, oneof_seen = {}, None
    for key, raw in obj:
        f = msg.by_json.get(key)
        if f is None:
            raise JsonFail("R.version" if ctx.newer else "R.encoding",
                           f"{where}: unknown member {key!r} of {msg_name}")
        if f.name in out or (f.name + "\0seen") in out:
            raise JsonFail("R.encoding", f"{where}: {f.name} named twice ({f.json_name}/{f.name})")
        out[f.name + "\0seen"] = True
        if f.oneof:
            if oneof_seen is not None:
                raise JsonFail("R.encoding", f"{where}: two members of oneof {f.oneof}")
            oneof_seen = f.name
        if raw is None:
            continue
        w = f"{where}.{f.json_name}"
        if f.repeated:
            if not isinstance(raw, list) or isinstance(raw, JObj):
                raise JsonFail("R.encoding", f"{w}: not an array")
            out[f.name] = [json_to_values(_pairs(e), f.ref, ctx, w) if f.ref != TS else
                           _timestamp(e, w) for e in raw]
            continue
        if f.type == MSG:
            out[f.name] = _timestamp(raw, w) if f.ref == TS else json_to_values(_pairs(raw), f.ref, ctx, w)
        elif f.type == BYTES:
            out[f.name] = _b64(raw, w)
        elif f.type == STR:
            if not isinstance(raw, str):
                raise JsonFail("R.encoding", f"{w}: not a string")
            try:
                raw.encode("utf-8", "strict")
            except UnicodeEncodeError:
                raise JsonFail("R.encoding", f"{w}: lone surrogate")
            out[f.name] = raw
        elif f.type == BOOL:
            if not isinstance(raw, bool):
                raise JsonFail("R.encoding", f"{w}: not a bool")
            out[f.name] = raw
        elif f.type == ENUM:
            if isinstance(raw, str):
                if raw not in ENUM_BY_NAME[f.ref]:
                    raise JsonFail("R.version" if ctx.newer and f.ref not in CLOSED_ENUMS else "R.encoding",
                                   f"{w}: undeclared {f.ref} name {raw!r}")
                out[f.name] = ENUM_BY_NAME[f.ref][raw]
            else:
                out[f.name] = _integer(raw, w, 32, signed=True) & 0xFFFFFFFFFFFFFFFF
        elif f.type == U32:
            out[f.name] = _integer(raw, w, 32)
        elif f.type == U64:
            out[f.name] = _integer(raw, w, 64)
        else:
            raise JsonFail("R.encoding", f"{w}: unsupported type")
    return {k: v for k, v in out.items() if not k.endswith("\0seen")}


def _pairs(v):
    # json.loads with object_pairs_hook gives lists of pairs for objects.
    return v


def encode_values(values, msg_name):
    """Canonical encoding (§4.2.2) of a value tree."""
    msg = SCHEMA[msg_name]
    out = bytearray()
    for number in sorted(msg.fields):
        f = msg.fields[number]
        if f.name not in values:
            continue
        v = values[f.name]
        items = v if f.repeated else [v]
        for e in items:
            if f.type == MSG:
                payload = encode_values(e, f.ref)
                out += encode_varint(number << 3 | 2) + encode_varint(len(payload)) + payload
            elif f.type in (BYTES, STR):
                payload = e.encode("utf-8") if f.type == STR else e
                if not payload and not f.oneof:
                    continue
                out += encode_varint(number << 3 | 2) + encode_varint(len(payload)) + payload
            else:
                n = int(e) & 0xFFFFFFFFFFFFFFFF if f.type in (I64, I32, ENUM) else int(e)
                if n == 0:
                    continue
                out += encode_varint(number << 3) + encode_varint(n)
    return bytes(out)


def json_line_to_bytes(line, msg_name, ctx):
    obj = parse_json_line(line)
    values = json_to_values(obj, msg_name, ctx, msg_name)
    return encode_values(values, msg_name)


def values_to_json(values, msg_name):
    """The proto3 JSON mapping of a decoded value tree (for --show); not canonical text."""
    msg = SCHEMA[msg_name]
    if msg_name == TS:
        s, n = values.get("seconds", 0), values.get("nanos", 0)
        dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=s)
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + (f".{n // 1_000_000:03d}" if n else "") + "Z"
    out = {}
    for number in sorted(msg.fields):
        f = msg.fields[number]
        if f.name not in values:
            continue
        v = values[f.name]
        conv = (lambda e: values_to_json(e, f.ref)) if f.type == MSG else \
            (lambda e: base64.b64encode(e).decode()) if f.type == BYTES else \
            (lambda e: ENUMS[f.ref].get(e, e)) if f.type == ENUM else \
            (lambda e: str(e)) if f.type == U64 else (lambda e: e)
        out[f.json_name] = [conv(e) for e in v] if f.repeated else conv(v)
    return out


# ---------------------------------------------------------------------------------------------
# Sections and layout (§4.5, §5.3.1)
# ---------------------------------------------------------------------------------------------

HEADER, PARAMETERS, MANIFEST, GUARDIANS, ELECTION_KEYS = 1, 2, 3, 4, 5
DEVICE, ATTESTATIONS = 0x0101, 0x0102
ENCRYPTED_TALLY, REQUESTS = 0x0201, 0x0202
DECRYPTED_TALLY, CHALLENGED, CD_DECRYPTIONS, RELEASES = 0x0301, 0x0302, 0x0303, 0x0304
TOC, SIGNATURES = 0xFFFE, 0xFFFF
STANDARD_TYPES = {HEADER, PARAMETERS, MANIFEST, GUARDIANS, ELECTION_KEYS, DEVICE, ATTESTATIONS,
                  ENCRYPTED_TALLY, REQUESTS, DECRYPTED_TALLY, CHALLENGED, CD_DECRYPTIONS, RELEASES}
REQUIRED = {0: [HEADER, PARAMETERS, MANIFEST, GUARDIANS, ELECTION_KEYS], 1: [ATTESTATIONS],
            2: [ENCRYPTED_TALLY, REQUESTS], 3: [DECRYPTED_TALLY, CHALLENGED, CD_DECRYPTIONS, RELEASES]}
PHASE_NAMES = ["setup", "sealed", "aggregated", "final"]
KIND_WORDS = {"regular": 1, "pre-encrypting": 2}

SINGLE_FILES = {"setup/header": HEADER, "setup/parameters": PARAMETERS, "setup/manifest": MANIFEST,
                "setup/guardians": GUARDIANS, "setup/election_keys": ELECTION_KEYS,
                "device_attestations": ATTESTATIONS, "aggregated/encrypted_tally": ENCRYPTED_TALLY,
                "aggregated/contest_data_requests": REQUESTS, "final/decrypted_tally": DECRYPTED_TALLY}
SEGMENTED_DIRS = {"final/challenged_ballot_decryptions": CHALLENGED,
                  "final/contest_data_decryptions": CD_DECRYPTIONS,
                  "final/uncast_nonce_releases": RELEASES}
# Items each section may hold (anything else is a structure finding of the verifications; this
# reader does not report it).


def phase_of(section_type):
    return min(section_type >> 8, 3)


def check_name(name):
    """§5.3.1 'Names are exact'."""
    for ch in name:
        o = ord(ch)
        if o < 0x20 or o > 0x7E or ch in "\\:":
            raise RecordFail("R.container", f"name {name!r} has a byte outside the layout's alphabet")
    if name.startswith("/") or any(seg in ("", ".", "..") for seg in name.split("/")):
        raise RecordFail("R.container", f"name {name!r} is not a relative path of non-empty segments")


class Layout:
    """Every file of the record mapped to its role (§5.3, §5.3.1)."""

    def __init__(self, names):
        self.sections = {}     # (type, key) -> {segment index: name} or {None: name}
        self.toc = None
        self.signatures = []
        self.manifest_copy = None
        self.meta = None
        ext = None
        folded = {}
        for name in names:
            check_name(name)
            low = name.lower()
            if low in folded:
                raise RecordFail("R.container", f"names {folded[low]!r} and {name!r} differ only in case")
            folded[low] = name
        for name in sorted(names):
            if name.startswith("derived/"):
                continue
            if name == "meta.json":
                self.meta = name
                continue
            if name == "setup/manifest.json":
                self.manifest_copy = name
                continue
            m = re.fullmatch(r"(.+)\.(binpb|jsonl)", name)
            if not m:
                raise RecordFail("R.container", f"unlisted file {name!r}")
            stem, e = m.groups()
            if ext is None:
                ext = e
            elif ext != e:
                raise RecordFail("R.container", f"files of both encodings ({ext}, {e})")
            if stem == "toc":
                self.toc = name
            elif stem in SINGLE_FILES:
                self.sections[(SINGLE_FILES[stem], b"")] = {None: name}
            elif re.fullmatch(r"signatures/(setup|sealed|aggregated|final)-[0-9a-f]{64}", stem):
                self.signatures.append(name)
            else:
                d = re.fullmatch(r"devices/(regular|pre-encrypting)-([0-9a-f]{64})/([0-9]{8})", stem)
                s = re.fullmatch(r"(final/[a-z_]+)/([0-9]{8})", stem)
                if d:
                    key = bytes([KIND_WORDS[d.group(1)]]) + bytes.fromhex(d.group(2))
                    self.sections.setdefault((DEVICE, key), {})[int(d.group(3))] = name
                elif s and s.group(1) in SEGMENTED_DIRS:
                    self.sections.setdefault((SEGMENTED_DIRS[s.group(1)], b""), {})[int(s.group(2))] = name
                else:
                    raise RecordFail("R.container", f"unlisted file {name!r}")
        self.ext = ext
        for (t, key), segs in self.sections.items():
            if None not in segs and sorted(segs) != list(range(len(segs))):
                raise RecordFail("R.container", f"segments of section {t:#06x} are not 0..n-1 without gaps")


# ---------------------------------------------------------------------------------------------
# Carriers
# ---------------------------------------------------------------------------------------------

class DirectorySource:
    def __init__(self, path):
        self.path = path
        self.names = []
        for root, dirs, files in os.walk(path):
            rel = os.path.relpath(root, path).replace(os.sep, "/")
            for f in files:
                self.names.append(f if rel == "." else f"{rel}/{f}")
            for d in dirs:
                check_name(d)

    def read(self, name):
        with open(os.path.join(self.path, *name.split("/")), "rb") as fh:
            return fh.read()


class ZipSource:
    """§5.4: the central directory is authoritative; every local header agrees with it."""

    def __init__(self, path):
        with open(path, "rb") as fh:
            self.data = data = fh.read()
        self.path = path
        self.entries = self._parse(data)
        self.names = [e["name"] for e in self.entries if not e["dir"]]
        try:
            self.zf = zipfile.ZipFile(path)
        except zipfile.BadZipFile as e:
            raise RecordFail("R.container", f"zip: {e}")
        self.infos = {}
        for info, e in zip(self.zf.infolist(), self.entries):
            self.infos[e["name"]] = (info, e)

    @staticmethod
    def _fail(msg):
        raise RecordFail("R.container", f"zip: {msg}")

    def _parse(self, d):
        eocd = d.rfind(b"PK\x05\x06")
        if eocd < 0 or eocd + 22 > len(d):
            self._fail("no end of central directory record")
        (_, disk, cd_disk, n_disk, n_total, cd_size, cd_off, clen) = struct.unpack_from("<IHHHHIIH", d, eocd)
        if eocd + 22 + clen != len(d):
            self._fail("the end record is not the last end-record signature, or its comment length is wrong")
        if n_disk != n_total:
            self._fail("end-record entry counts disagree")
        end_of_cd = eocd
        zip64 = 0xFFFF in (disk, cd_disk, n_disk, n_total) or 0xFFFFFFFF in (cd_size, cd_off)
        loc = eocd - 20
        has_locator = loc >= 0 and d[loc:loc + 4] == b"PK\x06\x07"
        if zip64 and not has_locator:
            self._fail("a ZIP64 marker without a ZIP64 locator")
        if has_locator:
            (_, _, z_off, _) = struct.unpack_from("<IIQI", d, loc)
            if z_off + 56 != loc or d[z_off:z_off + 4] != b"PK\x06\x06":
                self._fail("the ZIP64 end record is not just before its locator")
            (_, rec_size, _, _, z_disk, z_cd_disk, z_n_disk, z_n_total, z_cd_size, z_cd_off) = \
                struct.unpack_from("<IQHHIIQQQQ", d, z_off)
            if rec_size != 44:
                self._fail("ZIP64 end record with extensible data")
            if z_n_disk != z_n_total:
                self._fail("ZIP64 end-record entry counts disagree")
            for small, big, marker in ((n_total, z_n_total, 0xFFFF), (n_disk, z_n_disk, 0xFFFF),
                                       (cd_size, z_cd_size, 0xFFFFFFFF), (cd_off, z_cd_off, 0xFFFFFFFF)):
                if small != marker and small != big:
                    self._fail("ZIP64 end record disagrees with the end record")
            n_total, cd_size, cd_off = z_n_total, z_cd_size, z_cd_off
            end_of_cd = z_off
        if cd_off + cd_size != end_of_cd:
            self._fail("the central directory does not fill exactly the bytes before the end record")
        pos, entries, seen = cd_off, [], set()
        for _ in range(n_total):
            if d[pos:pos + 4] != b"PK\x01\x02":
                self._fail("bad central directory entry")
            (_, _, _, flags, method, _, _, crc, csize, usize, nlen, xlen, clen2, _, _, _, lho) = \
                struct.unpack_from("<IHHHHHHIIIHHHHHII", d, pos)
            raw_name = d[pos + 46:pos + 46 + nlen]
            extra = d[pos + 46 + nlen:pos + 46 + nlen + xlen]
            pos += 46 + nlen + xlen + clen2
            if any(b < 0x20 or b > 0x7E for b in raw_name):
                self._fail(f"entry name {raw_name!r} has a byte outside 0x20-0x7E")
            name = raw_name.decode("ascii")
            usize, csize, lho = self._zip64_extra(extra, usize, csize, lho)
            if name in seen:
                self._fail(f"duplicate entry {name!r}")
            seen.add(name)
            if flags & 1:
                self._fail(f"encrypted entry {name!r}")
            if method not in (0, 8):
                self._fail(f"entry {name!r} uses method {method}")
            is_dir = name.endswith("/")
            if is_dir:
                check_name(name[:-1])
                if method != 0 or csize or usize:
                    self._fail(f"directory entry {name!r} carries data")
            self._check_local(d, name, raw_name, method, flags, crc, csize, usize, lho)
            entries.append({"name": name, "dir": is_dir, "method": method, "crc": crc,
                            "csize": csize, "usize": usize})
        if pos != end_of_cd:
            self._fail("bytes after the stated number of central directory entries")
        return entries

    @staticmethod
    def _zip64_extra(extra, usize, csize, off, local=False):
        i = 0
        while i + 4 <= len(extra):
            hid, size = struct.unpack_from("<HH", extra, i)
            body = extra[i + 4:i + 4 + size]
            if hid == 1:
                j = 0
                if usize == 0xFFFFFFFF:
                    usize = struct.unpack_from("<Q", body, j)[0]
                    j += 8
                if csize == 0xFFFFFFFF:
                    csize = struct.unpack_from("<Q", body, j)[0]
                    j += 8
                if not local and off == 0xFFFFFFFF:
                    off = struct.unpack_from("<Q", body, j)[0]
            i += 4 + size
        return usize, csize, off

    def _check_local(self, d, name, raw_name, method, cflags, crc, csize, usize, lho):
        if d[lho:lho + 4] != b"PK\x03\x04":
            self._fail(f"no local header for {name!r}")
        (_, _, flags, lmethod, _, _, lcrc, lcsize, lusize, nlen, xlen) = struct.unpack_from("<IHHHHHIIIHH", d, lho)
        lname = d[lho + 30:lho + 30 + nlen]
        lextra = d[lho + 30 + nlen:lho + 30 + nlen + xlen]
        lusize, lcsize, _ = self._zip64_extra(lextra, lusize, lcsize, 0, local=True)
        if lname != raw_name or lmethod != method or (flags & 1) != (cflags & 1):
            self._fail(f"local header of {name!r} disagrees with the central directory")
        if flags & 8 and lcrc == 0 and lcsize == 0 and lusize == 0:
            pass
        elif (lcrc, lcsize, lusize) != (crc, csize, usize):
            self._fail(f"local header of {name!r} disagrees with the central directory (CRC or sizes)")

    def read(self, name):
        info, e = self.infos[name]
        try:
            data = self.zf.read(info)
        except (zipfile.BadZipFile, zlib.error, OSError) as ex:
            raise RecordFail("R.container", f"zip entry {name!r}: {ex}")
        if len(data) != e["usize"] or (zlib.crc32(data) & 0xFFFFFFFF) != e["crc"]:
            raise RecordFail("R.container", f"zip entry {name!r} does not match its CRC-32 or size")
        return data


# ---------------------------------------------------------------------------------------------
# Segments (§5.2, §5.5)
# ---------------------------------------------------------------------------------------------

def frames_binpb(data, name):
    """The frames of a .binpb segment, yielded one at a time: a frame's length is read and checked
    only when the frame before it has been handed on, so an item is judged before a failure further
    on (§5.2: a reader streams frame by frame; S10b-E review round 3)."""
    pos = 0
    while pos < len(data):
        try:
            length, npos = read_varint(data, pos)
        except Fail as e:
            raise RecordFail("R.container", f"{name}: frame length at byte {pos}: {e.message}")
        if length == 0:
            raise RecordFail("R.container", f"{name}: zero-length frame at byte {pos}")
        if length > MAX_FRAME:
            raise RecordFail("R.container", f"{name}: frame of {length} bytes over the 64 MiB ceiling")
        if npos + length > len(data):
            raise RecordFail("R.container", f"{name}: frame at byte {pos} runs past the end (torn tail)")
        yield bytes(data[npos:npos + length])
        pos = npos + length


def lines_jsonl(data, name):
    """The lines of a .jsonl segment, yielded one at a time like frames_binpb's frames. The last
    line feed is optional (§5.5); one '\\r' before a line's end is removed; a line over 128 MiB
    (counted before that removal) or an empty line is R.container."""
    pos, i = 0, 0
    while pos < len(data):
        end = data.find(b"\n", pos)
        if end < 0:
            line, pos = data[pos:], len(data)
        else:
            line, pos = data[pos:end], end + 1
        i += 1
        if len(line) > MAX_LINE:
            raise RecordFail("R.container", f"{name}: line {i} longer than 128 MiB")
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line:
            raise RecordFail("R.container", f"{name}: empty line {i}")
        yield bytes(line)


def segment_items(data, name, ext, ctx, stype, skey, first_ordinal):
    """One segment (§5.2, D6): its segment header, checked now (any failure R.container, a .jsonl
    header line that does not parse included: D6 governs the header line, S10b-E review round 3),
    then a generator of its items' canonical bytes, one at a time. A .jsonl item line that does not
    parse is its JSON code (R.encoding, or R.version for a newer minor); one whose encoding is empty
    is R.encoding and one over 64 MiB R.container (§5.3.1)."""
    if ext == "binpb":
        frames = frames_binpb(data, name)
        first = next(frames, None)
        if first is None:
            raise RecordFail("R.container", f"{name}: no segment header")
        header = check_segment_header(first, ctx, stype, skey)
        items = frames
    else:
        lines = lines_jsonl(data, name)
        first = next(lines, None)
        if first is None:
            raise RecordFail("R.container", f"{name}: no segment header")
        try:
            hb = json_line_to_bytes(first, "SegmentHeader", ctx)
        except JsonFail as e:
            raise RecordFail("R.container", f"{name}: segment header line: {e.message}", "D6")
        header = check_segment_header(hb, ctx, stype, skey)
        items = _json_items(lines, name, ctx)
    if header.get("first_ordinal", 0) != first_ordinal:
        raise RecordFail("R.container",
                         f"{name}: first_ordinal {header.get('first_ordinal', 0)}, expected {first_ordinal}")
    return items


def _json_items(lines, name, ctx):
    for i, line in enumerate(lines):
        try:
            b = json_line_to_bytes(line, "RecordItem", ctx)
        except JsonFail as e:
            raise RecordFail(e.code, f"{name}: line {i + 2}: {e.message}")
        if not b:
            raise RecordFail("R.encoding", f"{name}: line {i + 2} encodes to no bytes; an item is 1 byte to 64 MiB")
        if len(b) > MAX_FRAME:
            raise RecordFail("R.container", f"{name}: line {i + 2} encodes to over 64 MiB")
        yield b


# ---------------------------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------------------------

class Section:
    def __init__(self, stype, key):
        self.type, self.key = stype, key
        self.items = []         # canonical bytes (protobuf: as stored; JSON: as encoded)
        self.decoded = []       # (member, values) or None per item
        self.broken = None      # message when the section could not be read whole
        self.root = None

    @property
    def phase(self):
        return phase_of(self.type)


class Report:
    def __init__(self):
        self.findings = []
        self.unknown = []

    def add(self, code, message, rule=None, where=None):
        f = {"code": code, "message": message}
        if rule:
            f["rule"] = rule
        if where:
            f["where"] = where
        self.findings.append(f)


def open_source(path):
    if os.path.isdir(path):
        return DirectorySource(path), "directory"
    if path.lower().endswith(".zip"):
        return ZipSource(path), "zip"
    raise RecordFail("R.container", f"{path} is neither a directory nor a .zip")


def read_record(path):
    rep = Report()
    out = {"path": path}
    try:
        _read_record(path, rep, out)
    except RecordFail as e:
        rep.add(e.code, e.message, e.rule)
        out["stopped"] = True
    out["findings"] = rep.findings
    out["codes"] = sorted({f["code"] for f in rep.findings})
    out["unknownContent"] = sorted(set(rep.unknown))
    # §6.9 and R-2 ("Pass, flagged incomplete"): a record of a newer minor is reported incomplete
    # whatever it holds, beside anything skipped as not understood.
    out["complete"] = not rep.unknown and not out.get("stopped", False) \
        and out.get("formatMinor", READER_MINOR) <= READER_MINOR
    out["passed"] = not rep.findings
    return out


def _peek_header(src, layout_names):
    """§5.3.1, §7: read the header section's segment header at v2's path before anything else."""
    for ext in ("binpb", "jsonl"):
        name = f"setup/header.{ext}"
        if name in layout_names:
            data = src.read(name)
            try:
                if ext == "binpb":
                    length, pos = read_varint(data, 0)
                    first = data[pos:pos + length]
                    values = walk(first, "SegmentHeader", Ctx(1 << 31))
                else:
                    first = next(lines_jsonl(data, name))
                    obj = parse_json_line(first)
                    values = {f: v for f, v in obj if f in ("magic", "formatMajor")}
                    major = values.get("formatMajor")
                    major = major.text if isinstance(major, JNumber) else major
                    values = {"magic": values.get("magic"),
                              "format_major": int(major) if isinstance(major, str) and major.isdigit() and major.isascii() else None}
            except (Fail, RecordFail, JsonFail, IndexError, AttributeError, ValueError, TypeError, StopIteration):
                return
            if values.get("magic") == "EGRF" and values.get("format_major") not in (None, READER_MAJOR):
                raise RecordFail("R.version", f"record of format major {values.get('format_major')}")


RECORD_HEADER_MEMBER = next(n for n, f in SCHEMA["RecordItem"].fields.items() if f.name == "record_header")


def _read_format(src, layout):
    """The record's format minor, read at open from the header section (§4.5, §7), which fixes the
    minor every other item is judged at. A header section that cannot be read stops the read, as
    ElectionRecordReader.ReadFormatAsync does (design §5.3.1; S10b-E review round 3): read as a reader
    older than any minor reads it (unknown fields allowed, W6), its segment under R.container, then
    item by item a second item R.structure and an item that is not canonical R.encoding, then
    R.structure for no record_header, and R.version for another major or a minor over 65535."""
    segs = layout.sections.get((HEADER, b""), {})
    name = segs.get(None)
    if name is None:
        raise RecordFail("R.structure", "the record has no header section")
    ctx = Ctx(0xFFFF)
    header = None
    for item in segment_items(src.read(name), name, layout.ext, ctx, HEADER, b"", 0):
        if header is not None:
            raise RecordFail("R.structure", "the header section holds more than one item (§4.5)")
        try:
            header = check_item(item, ctx)
        except Fail as e:
            raise RecordFail("R.encoding", f"the header item is not canonical: {e.message}", e.rule)
    if header is None or header[0] != RECORD_HEADER_MEMBER:
        raise RecordFail("R.structure", "the header section does not hold one record_header item (§4.5)")
    hdr = header[2] or {}
    major, minor = hdr.get("format_major", 0), hdr.get("format_minor", 0)
    if major != READER_MAJOR or minor > 0xFFFF:
        raise RecordFail("R.version", f"the record is EGRF {major}.{minor}; this reader reads major {READER_MAJOR}")
    return minor


def _read_section(src, layout, key, ctx, rep):
    stype, skey = key
    sec = Section(stype, skey)
    segs = layout.sections[key]
    names = [segs[None]] if None in segs else [segs[i] for i in sorted(segs)]
    ordinal = 0
    try:
        for name in names:
            for item in segment_items(src.read(name), name, layout.ext, ctx, stype, skey, ordinal):
                sec.items.append(item)
                try:
                    member, mname, value = check_item(item, ctx)
                    if member in STATEMENT_MEMBERS and value is not None:
                        try:
                            check_signed_statement(member, value, ctx)
                        except RecordFail as e:
                            rep.add(e.code, e.message, e.rule, f"{_section_label(sec)}#{ordinal}")
                    sec.decoded.append((member, value))
                except Fail as e:
                    rep.add("R.encoding", e.message, e.rule, f"{_section_label(sec)}#{ordinal}")
                    sec.decoded.append(None)
                ordinal += 1
    except RecordFail as e:
        sec.broken = e.message
        rep.add(e.code, e.message, e.rule, _section_label(sec))
        return sec
    sec.root = mth([leaf_hash(i) for i in sec.items])
    return sec


def _section_label(sec):
    return f"{sec.type:#06x}" + (f"-{sec.key.hex()}" if sec.key else "")


def toc_entry_bytes(stype, key, critical, count, root):
    entry = {"section_type": stype, "root": root}
    if key:
        entry["key"] = key
    if critical:
        entry["critical"] = True
    if count:
        entry["item_count"] = count
    return encode_values({"toc_entry": entry}, "RecordItem")


def _read_record(path, rep, out):
    src, carrier = open_source(path)
    out["carrier"] = carrier
    names = list(src.names)
    for n in names:
        check_name(n)
    _peek_header(src, set(names))
    layout = Layout(names)
    out["encoding"] = {"binpb": "protobuf", "jsonl": "json", None: None}[layout.ext]

    # Phase and presence (§4.5): R.structure, at open, from the layout alone and before any section
    # is read, as ElectionRecordReader.OpenAsync checks them. A record that is at no phase has no
    # record root (§4.9: R_phase of the record's phase), so the roots, the TOC and the signatures over
    # them cannot be judged: the read stops here.
    present = {t for t, _ in layout.sections}
    phase = -1
    for p in range(4):
        if all(t in present for t in REQUIRED[p]):
            phase = p
        else:
            break
    if phase < 0:
        raise RecordFail("R.structure", "a required setup section is missing")
    if any(phase_of(t) > phase for t, _ in layout.sections):
        raise RecordFail("R.structure",
                         f"a section of a phase after {PHASE_NAMES[phase]} without every required section")
    out["phase"] = PHASE_NAMES[phase]

    # The header section (the minor every item is judged at), then the claimed TOC, both at open.
    minor = _read_format(src, layout)
    ctx = Ctx(minor)
    out["formatMajor"], out["formatMinor"] = READER_MAJOR, minor
    claimed_toc = _read_claimed_toc(src, layout, ctx)

    sections = {}
    for key in sorted(layout.sections, key=lambda k: (k[0], k[1])):
        sections[key] = _read_section(src, layout, key, ctx, rep)
    rep.unknown.extend(ctx.unknown)

    # TOC, phase roots (§4.9).
    entries = []
    for key, sec in sorted(sections.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        if sec.root is None:
            continue
        entries.append((key, sec, toc_entry_bytes(sec.type, sec.key, True, len(sec.items), sec.root)))
    out["sections"] = [{"type": f"{s.type:#06x}", "key": s.key.hex(), "itemCount": len(s.items),
                        "root": s.root.hex()} for _, s, _ in entries]
    roots = {}
    for p in range(phase + 1):
        roots[PHASE_NAMES[p]] = mth([leaf_hash(b) for k, s, b in entries if s.phase <= p]).hex()
    out["phaseRoots"] = roots
    out["root"] = roots[PHASE_NAMES[phase]]

    # The claimed TOC (§4.5, §5.3.1): R.version, then R.root.
    out["claimedTocMatches"] = None
    if claimed_toc is not None:
        computed = [b for _, _, b in entries]
        out["claimedTocMatches"] = not any(s.root is None for s in sections.values()) and claimed_toc == computed
        if not out["claimedTocMatches"]:
            rep.add("R.root", "the claimed TOC differs from the TOC recomputed from the sections")

    _check_manifest_copy(src, layout, sections, rep)
    _check_section_structure(sections, rep)
    _check_manifest_media_type(sections, rep)
    he = _election_hash(sections)
    _check_order(sections, rep)
    _check_summary(sections, rep)
    _check_attestations(sections, he, rep)
    _check_signatures(src, layout, ctx, he, roots, rep)


def _read_claimed_toc(src, layout, ctx):
    """The claimed TOC (§4.5, §5.3.1), read at open: its items' bytes, or None when the record has
    no TOC. A claimed TOC that is not a well-formed list of toc_entry items stops the read, as a record
    of another major does (design §8.3 "As built (S10b-E)", review round 2): its frames, segment header
    and lines under their own codes; then, item by item, R.version for a section type v2 does not
    define (checked before the item's own D2, NQ-7), R.encoding for an item that is not canonical,
    R.root for one that is not a toc_entry or names a pseudo-section; then R.root for an empty TOC or
    entries out of canonical (type, key) order. A well-formed claimed TOC that differs from the one
    recomputed from the sections is R.root found after open, and the read goes on."""
    if not layout.toc:
        return None
    name = layout.toc
    # Item by item, as the C# reader streams it: an item is judged before the next frame or line is
    # read, so a non-canonical item before a torn tail is R.encoding, not R.container (S10b-E review
    # round 3).
    raw = segment_items(src.read(name), name, layout.ext, ctx, TOC, b"", 0)
    claimed, keys = [], []
    for i, item in enumerate(raw):
        stype = _raw_toc_section_type(item)
        if stype is not None and stype != 0 and stype not in ENUMS["SectionType"]:
            raise RecordFail("R.version", f"claimed TOC entry {i} names section type {stype:#06x}, "
                                          "a section kind of another major (NQ-7)")
        try:
            member, _, entry = check_item(item, ctx)
        except Fail as e:
            raise RecordFail("R.encoding", f"claimed TOC entry {i} is not canonical: {e.message}", e.rule)
        if member != 50:
            raise RecordFail("R.root", f"claimed TOC item {i} is not a toc_entry")
        if entry["section_type"] in (TOC, SIGNATURES):
            raise RecordFail("R.root", f"claimed TOC item {i} names the pseudo-section {entry['section_type']:#06x}")
        keys.append((entry["section_type"], entry.get("key", b"")))
        claimed.append(item)
    if not claimed:
        raise RecordFail("R.root", "the claimed TOC has no entry; a TOC holds at least the header section")
    for i in range(1, len(keys)):
        if keys[i - 1] >= keys[i]:
            raise RecordFail("R.root", f"claimed TOC entry {i} is not after entry {i - 1} in canonical (type, key) order")
    return claimed


def _raw_toc_section_type(item):
    """The section_type a toc_entry item names, read without any profile rule; None if it is none."""
    try:
        tag, pos = read_varint(item, 0)
        if tag != (50 << 3 | 2):
            return None
        length, pos = read_varint(item, pos)
        inner, pos = item[pos:pos + length], 0
        while pos < len(inner):
            tag, pos = read_varint(inner, pos)
            if tag == (1 << 3):
                return read_varint(inner, pos)[0]
            if tag & 7 == 0:
                _, pos = read_varint(inner, pos)
            elif tag & 7 == 2:
                length, pos = read_varint(inner, pos)
                pos += length
            else:
                return None
    except Fail:
        return None
    return None


def _check_manifest_copy(src, layout, sections, rep):
    if not layout.manifest_copy:
        return
    sec = sections.get((MANIFEST, b""))
    manifest_member = next(n for n, f in SCHEMA["RecordItem"].fields.items() if f.name == "manifest_file")
    content = None
    if sec and sec.decoded and sec.decoded[0] and sec.decoded[0][0] == manifest_member and sec.decoded[0][1] is not None:
        content = sec.decoded[0][1].get("content", b"")
    # A finding, not a stop: the copy lies outside every root, and the record it sits beside is read
    # (and digested) whatever it holds (design §8.3 "As built (S10b-E)"). With no stored manifest read
    # (its first item not canonical, or not a manifest_file) there is nothing to compare the copy
    # with: not evaluable, and the stored manifest's own finding is reported where it was read.
    if content is not None and src.read(layout.manifest_copy) != content:
        rep.add("R.container", "setup/manifest.json differs from ManifestFile.content")


SETUP_MEMBERS = [(HEADER, 1, False), (PARAMETERS, 2, False), (MANIFEST, 3, False), (GUARDIANS, 4, True),
                 (ELECTION_KEYS, 5, False)]


def _check_section_structure(sections, rep):
    """§4.5's contents of the setup and tally sections (R.structure), as the C# verifier's steps B and
    E judge them: each item of its section's member (the encrypted tally: its header first, then
    contests), and a setup singleton holding exactly one item (guardians at least one). Only for a
    section read whole: one read in part claims no count (S10b-E review round 3). An item that is not
    canonical is its own R.encoding and is not judged by member. The decrypted tally's members are
    judged only when the setup was read, as the C# step E reads it only then."""
    for t, member, many in SETUP_MEMBERS:
        sec = sections.get((t, b""))
        if sec is None or sec.broken:
            continue
        for i, d in enumerate(sec.decoded):
            if d is not None and d[0] != member:
                rep.add("R.structure", f"section {t:#06x} item {i} is member {d[0]}; it holds member {member} only",
                        where=f"{_section_label(sec)}#{i}")
        if (len(sec.decoded) == 0) if many else (len(sec.decoded) != 1):
            rep.add("R.structure", f"section {t:#06x} holds {len(sec.decoded)} items", where=_section_label(sec))
    sec = sections.get((ENCRYPTED_TALLY, b""))
    if sec is not None and not sec.broken:
        readable, header = True, False
        for i, d in enumerate(sec.decoded):
            if d is None:
                readable = False
            elif i == 0 and d[0] == 20:
                header = True
            elif i > 0 and d[0] == 21:
                pass
            else:
                readable = False
                rep.add("R.structure", f"encrypted tally item {i} is member {d[0]}", where=f"{_section_label(sec)}#{i}")
        if not header and readable:
            rep.add("R.structure", "the encrypted tally has no encrypted_tally_header", where=_section_label(sec))
    sec = sections.get((DECRYPTED_TALLY, b""))
    if sec is not None and not sec.broken and _setup_read(sections):
        for i, d in enumerate(sec.decoded):
            if d is not None and d[0] != 30:
                rep.add("R.structure", f"decrypted tally item {i} is member {d[0]}", where=f"{_section_label(sec)}#{i}")


MANIFEST_MEDIA_TYPE = "application/vnd.electionguard.manifest+json;format=1"


def _check_manifest_media_type(sections, rep):
    """§4.6: media_type names the manifest's parser; a type this reader does not read is R.version."""
    # Read, as the C# verifier's step B reads it, only when every setup section was read whole and
    # every item in them decoded (otherwise the setup is not evaluable and the manifest is not parsed).
    if not _setup_read(sections):
        return
    sec = sections.get((MANIFEST, b""))
    manifest_member = next(n for n, f in SCHEMA["RecordItem"].fields.items() if f.name == "manifest_file")
    if sec and sec.root is not None and len(sec.decoded) == 1 and sec.decoded[0] \
            and sec.decoded[0][0] == manifest_member and sec.decoded[0][1] is not None:
        media_type = sec.decoded[0][1].get("media_type", "")
        if media_type != MANIFEST_MEDIA_TYPE:
            rep.add("R.version", f"the manifest's media type is {media_type!r}; this reader reads {MANIFEST_MEDIA_TYPE!r}")


def _election_hash(sections):
    sec = sections.get((ELECTION_KEYS, b""))
    if sec and sec.decoded and sec.decoded[0] and sec.decoded[0][0] == 5 and sec.decoded[0][1]:
        return sec.decoded[0][1].get("h_e")
    return None


def _locator_key(loc):
    if loc is None:
        return None
    return (loc.get("kind", 0), loc.get("h_di", b""), loc.get("position", 0))


def _check_order(sections, rep):
    """§4.5 canonical order in the join sections: R.order (a repeated key is structure)."""
    keyers = {REQUESTS: (22, lambda v: (_locator_key(v.get("ballot")), v.get("contest_index", 0))),
              CHALLENGED: (31, lambda v: (_locator_key(v.get("ballot")),)),
              CD_DECRYPTIONS: (32, lambda v: (_locator_key(v.get("ballot")), v.get("contest_index", 0))),
              RELEASES: (33, lambda v: (_locator_key(v.get("ballot")),))}
    for stype, (member, keyer) in keyers.items():
        sec = sections.get((stype, b""))
        if not sec:
            continue
        prev = None
        for i, d in enumerate(sec.decoded):
            if not d or d[0] != member or d[1] is None or d[1].get("ballot") is None:
                continue
            k = keyer(d[1])
            if prev is not None and k < prev:
                rep.add("R.order", f"item {i} is out of locator order", where=f"{_section_label(sec)}#{i}")
            prev = k


def _device_ballots(sec):
    """(member, values) of the ballot items of a device section, in chain order."""
    return [d for d in sec.decoded if d and d[0] in (11, 12, 13, 16)]


def _setup_read(sections):
    """Whether every setup section was read whole, every item in it decoded as its section's member,
    in the count §4.5 gives: the C# verifier's step B is evaluable only then (what it decides beyond
    that, V1 and V4, this reader does not check)."""
    for t, member, many in SETUP_MEMBERS:
        s = sections.get((t, b""))
        if s is None or s.root is None or any(d is None or d[0] != member for d in s.decoded):
            return False
        if (len(s.decoded) == 0) if many else (len(s.decoded) != 1):
            return False
    return True


def _chain_state(dev):
    """(header values or None, close values or None, chain known) for a device section read whole:
    the header when it decoded as a device_header naming the section's key; the close when the last
    item decoded as a device_close; and whether the chain is known, which needs the header and every
    item between header and close (between header and the end when there is no close) decoded as a
    ballot of the device's kind. The C# verifier's walk is the same: an item that is not canonical or
    of another member is skipped, and the chain after it is not evaluable."""
    d = dev.decoded
    header = None
    if d and d[0] is not None and d[0][0] == 10 and d[0][1] is not None:
        h = d[0][1]
        if h.get("kind", 0) == dev.key[0] and h.get("h_di", b"") == dev.key[1:]:
            header = h
    close = d[-1][1] if len(d) > 1 and d[-1] is not None and d[-1][0] == 14 and d[-1][1] is not None else None
    allowed = {11} if dev.key[0] == 1 else {12, 13, 16}
    middle = d[1:-1] if close is not None else d[1:]
    known = all(x is not None and x[0] in allowed and x[1] is not None for x in middle)
    return header, close, known


def _check_summary(sections, rep):
    """The tally header against the cast ballots (R.summary)."""
    sec = sections.get((ENCRYPTED_TALLY, b""))
    if not sec or not sec.decoded or not sec.decoded[0] or sec.decoded[0][0] != 20:
        return
    if sec.broken or any(d is None for d in sec.decoded) or not _setup_read(sections):
        return      # the tally or the election was not read: not evaluable (design §6.1 steps B, E)
    header = sec.decoded[0][1] or {}
    count = weight = 0
    for (t, key), dev in sections.items():
        if t != DEVICE:
            continue
        if dev.broken or any(d is None for d in dev.decoded):
            return      # an unreadable ballot: the recount is not evaluable
        if not _chain_state(dev)[2]:
            return      # an item that is no ballot of its device's kind may be a cast ballot
        for member, v in _device_ballots(dev):
            if member == 11 and v.get("status", 0) not in (1, 2, 3):
                return  # a status of a newer minor (or none): whether it is tallied is unknown
            if member == 11 and v.get("status") == 1 or member == 12:
                if v.get("weight", 0) < 1:
                    # A cast ballot with a weight below 1 is 9.structure and has no factor in the
                    # recount, so the header cannot be judged (as for any cast ballot with a
                    # finding, design §6.2; S10b-E review round 3).
                    return
                count += 1
                weight += v.get("weight", 0)
    if header.get("cast_ballot_count", 0) != count or header.get("total_cast_weight", 0) != weight:
        rep.add("R.summary", f"tally header says {header.get('cast_ballot_count', 0)} cast ballots of weight "
                             f"{header.get('total_cast_weight', 0)}; the record holds {count} of weight {weight}")


def _codes_root(codes):
    return mth([leaf_hash(encode_values({"confirmation_code_leaf": {"code": c}}, "RecordItem"))
                for c in codes])


def _check_attestations(sections, he, rep):
    sec = sections.get((ATTESTATIONS, b""))
    if not sec:
        return
    # The contents are compared against the election (H_E) only when the setup was read: the C#
    # verifier compares them in its device pass, which a setup that is not evaluable stops (design
    # §6.1 step B). The order and the device each names are checked whatever the setup holds.
    setup_ok = _setup_read(sections)
    prev = None
    for i, d in enumerate(sec.decoded):
        where = f"{_section_label(sec)}#{i}"
        if d is None:
            continue    # not canonical: reported with the item (R.encoding)
        if d[0] != 15 or d[1] is None:
            rep.add("R.attestation", f"item member {d[0]} is not a device_attestation (§4.5)", where=where)
            continue
        statement = d[1].get("statement", b"")
        try:
            smember, _, s = check_signed_statement(15, d[1], Ctx(READER_MINOR))
        except RecordFail:
            continue    # reported with the item
        key = (s.get("device_key", b""), smember, hashlib.sha256(statement).digest(), sec.items[i])
        if prev is not None and key <= prev:
            rep.add("R.order", "device attestations out of order", where=where)
        prev = key
        dev = sections.get((DEVICE, s.get("device_key", b"")))
        if dev is None:
            rep.add("R.attestation", "statement names no device section of the record", where=where)
            continue
        if not setup_ok or dev.broken:
            continue    # the election or the section cannot be read whole: not evaluable, not a mismatch
        if s.get("h_e") != he:
            rep.add("R.attestation", "statement names another H_E", where=where)
            continue
        # A section seal binds the section root, known whenever the section was read whole. A chain
        # close binds the header, the codes in chain order and the close, and a prefix checkpoint the
        # codes: compared only when those were read (design §4.9, §6.9; S10b-E review round 3), so an
        # item that is not canonical leaves them not evaluable rather than mismatched.
        header, close, known = _chain_state(dev)
        ballots = _device_ballots(dev)
        codes = [v.get("confirmation_code", b"") for _, v in ballots]
        if smember == 40:
            if header is None or close is None or not known:
                continue
            ok = (s.get("device_id", "") == header.get("device_id", "")
                  and s.get("chaining_mode", 0) == header.get("chaining_mode", 0)
                  and s.get("ballot_count", 0) == len(ballots) == close.get("ballot_count", 0)
                  and s.get("codes_root") == _codes_root(codes)
                  and s.get("closing_hash", b"") == close.get("closing_hash", b""))
        elif smember == 41:
            ok = s.get("item_count", 0) == len(dev.items) and s.get("section_root") == dev.root
        else:
            n = s.get("ballot_count", 0)
            if n != 0 and (header is None or not known):
                continue
            ok = n <= len(codes) and s.get("codes_root") == _codes_root(codes[:n])
        if not ok:
            rep.add("R.attestation", f"statement {MEMBER_NAME[smember]} does not match the device section",
                    where=where)


def _check_signatures(src, layout, ctx, he, roots, rep):
    for name in layout.signatures:
        m = re.fullmatch(r"signatures/(setup|sealed|aggregated|final)-([0-9a-f]{64})\.\w+", name)
        # File by file and item by item, as the C# verifier reads them: an item before a failure in
        # its file is judged; the failure is R.signature (R.version stays R.version).
        try:
            for i, item in enumerate(segment_items(src.read(name), name, layout.ext, ctx, SIGNATURES, b"", 0)):
                _check_signature_item(name, i, item, m, ctx, he, roots, rep)
        except RecordFail as e:
            rep.add("R.version" if e.code == "R.version" else "R.signature", e.message, e.rule, name)


def _check_signature_item(name, i, item, m, ctx, he, roots, rep):
    phase_by_number = {1: "setup", 2: "sealed", 3: "aggregated", 4: "final"}
    where = f"{name}#{i}"
    try:
        member, _, value = check_item(item, ctx)
        if member != 44:
            raise RecordFail("R.signature", f"item member {member} is not a record_signature")
        _, _, s = check_signed_statement(44, value, ctx)
    except (Fail, RecordFail) as e:
        rep.add("R.signature", e.message, e.rule, where)
        return
    phase = phase_by_number.get(s.get("phase"))
    if hashlib.sha256(value.get("statement", b"")).hexdigest() != m.group(2) or phase != m.group(1):
        rep.add("R.signature", "file name does not name the statement's phase and SHA-256", where=where)
    elif phase not in roots or bytes.fromhex(roots[phase]) != s.get("root"):
        rep.add("R.signature", f"statement root is not the record's {phase} root", where=where)
    elif he is not None and s.get("h_e") != he:
        rep.add("R.signature", "statement names another H_E", where=where)
    elif s.get("format_major") != READER_MAJOR:
        rep.add("R.signature", "statement names another format major", where=where)


# ---------------------------------------------------------------------------------------------
# --check: schema table, vectors, golden records
# ---------------------------------------------------------------------------------------------

def check_schema_table(path):
    """Our transcription against test/egrf/schema.json (from the compiled descriptor)."""
    with open(path, encoding="utf-8") as fh:
        table = json.load(fh)
    problems = []
    theirs = {m["name"]: m for m in table["messages"]}
    ours = {n: m for n, m in SCHEMA.items() if n != TS}
    if set(theirs) != set(ours):
        problems.append(f"messages differ: only in schema.json {sorted(set(theirs) - set(ours))}, "
                        f"only here {sorted(set(ours) - set(theirs))}")
    for name in sorted(set(theirs) & set(ours)):
        tm, om = theirs[name], ours[name]
        if set(tm.get("reserved", [])) != om.reserved:
            problems.append(f"{name}: reserved {tm.get('reserved')} vs {sorted(om.reserved)}")
        tf = {f["number"]: f for f in tm["fields"]}
        if set(tf) != set(om.fields):
            problems.append(f"{name}: field numbers {sorted(tf)} vs {sorted(om.fields)}")
            continue
        for n, f in tf.items():
            o = om.fields[n]
            ref = f.get("typeName", "").rsplit(".", 1)[-1] or None
            oref = o.ref.rsplit(".", 1)[-1] if o.ref else None
            mine = (o.name, o.type, "repeated" if o.repeated else "optional", oref if o.type in (MSG, ENUM) else None,
                    o.width, o.wm, bool(o.omit), o.oneof)
            theirs_t = (f["name"], f["type"], f["label"], ref if f["type"] in (MSG, ENUM) else None,
                        f.get("width"), f.get("widthMultiple"), bool(f.get("omittable")), f.get("oneof"))
            if mine != theirs_t:
                problems.append(f"{name}.{n}: {mine} vs {theirs_t}")
    tenums = {e["name"]: {v["number"]: v["name"] for v in e["values"]} for e in table["enums"]}
    if tenums != ENUMS:
        problems.append(f"enums differ: {tenums} vs {ENUMS}")
    return problems


def check_vector_item(kind, hexstr, minor):
    """The verdict on one vector: None when canonical, else the rule or code."""
    buf = bytes.fromhex(hexstr)
    ctx = Ctx(minor)
    try:
        if kind == "segmentHeader":
            check_segment_header(buf, ctx)
            return None
        member, _, value = check_item(buf, ctx)
        if kind == "signedStatement":
            check_signed_statement(member, value, ctx)
        return None
    except Fail as e:
        return e.rule
    except RecordFail as e:
        return e.rule if e.code == "R.container" else e.code


def run_check(repo):
    failures = []
    egrf = os.path.join(repo, "test", "egrf")
    for p in check_schema_table(os.path.join(egrf, "schema.json")):
        failures.append(f"schema: {p}")
    with open(os.path.join(egrf, "vectors", "items.json"), encoding="utf-8") as fh:
        items = json.load(fh)
    for v in items["items"]:
        buf = bytes.fromhex(v["hex"])
        verdict = check_vector_item("signedStatement" if int(v["member"]) in STATEMENT_MEMBERS else "item",
                                    v["hex"], items["formatMinor"])
        if verdict is not None:
            failures.append(f"items: {v['name']} rejected ({verdict})")
        if leaf_hash(buf).hex() != v["leafHash"]:
            failures.append(f"items: {v['name']} leaf hash")
        try:
            if json_line_to_bytes(v["json"].encode("utf-8"), "RecordItem", Ctx(items["formatMinor"])) != buf:
                failures.append(f"items: {v['name']} JSON does not encode to the item")
        except JsonFail as e:
            failures.append(f"items: {v['name']} JSON: {e}")
    sh = items["segmentHeader"]
    if check_vector_item("segmentHeader", sh["hex"], 0) is not None:
        failures.append("items: segment header rejected")
    if json_line_to_bytes(sh["json"].encode("utf-8"), "SegmentHeader", Ctx()) != bytes.fromhex(sh["hex"]):
        failures.append("items: segment header JSON")
    for v in items["newerMinor"]:
        ctx = Ctx(int(v["recordMinor"]))
        try:
            check_item(bytes.fromhex(v["hex"]), ctx)
            if not ctx.unknown:
                failures.append(f"newer minor: {v['name']}: no unknown content reported")
        except Fail as e:
            failures.append(f"newer minor: {v['name']} rejected ({e.rule}: {e.message})")
    with open(os.path.join(egrf, "vectors", "negatives.json"), encoding="utf-8") as fh:
        negatives = json.load(fh)
    for v in negatives["vectors"]:
        verdict = check_vector_item(v["kind"], v["hex"], int(v["recordMinor"]))
        if verdict != v["rule"]:
            failures.append(f"negatives: {v['name']}: expected {v['rule']}, got {verdict}")
    with open(os.path.join(egrf, "vectors", "merkle-rfc9162.json"), encoding="utf-8") as fh:
        mk = json.load(fh)
    leaves = [leaf_hash(bytes.fromhex(x)) for x in mk["leafInputs"]]
    for n, root in enumerate(mk["rootsBySize"]):
        if mth(leaves[:n]).hex() != root:
            failures.append(f"merkle: root of {n} leaves")
    for t in mk["inclusion"]:
        path = [bytes.fromhex(p) for p in t["proof"]]
        if [p.hex() for p in inclusion_path(t["leafIdx"], leaves[:t["treeSize"]])] != t["proof"] or \
                not verify_inclusion(bytes.fromhex(t["leafHash"]), t["leafIdx"], t["treeSize"],
                                     bytes.fromhex(t["root"]), path):
            failures.append(f"merkle: inclusion {t['source']}")
    for t in mk["consistency"]:
        if [p.hex() for p in consistency_proof(t["size1"], leaves[:t["size2"]])] != t["proof"]:
            failures.append(f"merkle: consistency {t['source']}")
    records = os.path.join(egrf, "records")
    index = os.path.join(records, "index.json")
    nrec = 0
    if os.path.exists(index):
        with open(index, encoding="utf-8") as fh:
            idx = json.load(fh)
        for r in idx["records"]:
            nrec += 1
            got = read_record(os.path.join(records, *r["path"].split("/")))
            if got["codes"] != sorted(r["codes"]):
                failures.append(f"records: {r['path']}: codes {got['codes']}, expected {sorted(r['codes'])}")
            if r.get("phaseRoots") and got.get("phaseRoots") != r["phaseRoots"]:
                failures.append(f"records: {r['path']}: phase roots differ")
            # Completeness is compared on every record: false for content of a newer minor, and for a
            # record whose read stopped (refused at open, or at no phase).
            if got["complete"] != r["complete"]:
                failures.append(f"records: {r['path']}: complete {got['complete']}, expected {r['complete']}")
    for f in failures:
        print("FAIL", f)
    print(f"egrf_ref --check: {len(items['items'])} items, {len(negatives['vectors'])} negatives, "
          f"{len(mk['inclusion'])} inclusion and {len(mk['consistency'])} consistency proofs, {nrec} records; "
          f"{len(failures)} failure(s)")
    return 1 if failures else 0


def main(argv):
    args = argv[1:]
    try:
        if args and args[0] == "--check":
            root = args[args.index("--root") + 1] if "--root" in args else \
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            return run_check(root)
        if len(args) >= 2 and args[0] == "read":
            result = read_record(args[1])
            if "--json" in args:
                print(json.dumps(result, indent=1, sort_keys=True))
            else:
                print(f"{result['path']}: phase {result.get('phase')}, root {result.get('root')}")
                for f in result["findings"]:
                    print(f"  {f['code']} {f.get('rule', '')} {f.get('where', '')}: {f['message']}")
                print("passed" if result["passed"] else "failed",
                      "" if result["complete"] else "(incomplete: content of a newer minor skipped)")
            if not result["passed"]:
                return 1
            return 0 if result["complete"] else 2
        if len(args) >= 2 and args[0] == "item":
            minor = int(args[args.index("--minor") + 1]) if "--minor" in args else READER_MINOR
            v = check_vector_item("item", args[1], minor)
            print("canonical" if v is None else v)
            return 0 if v is None else 1
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    print(__doc__, file=sys.stderr)
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
