using ElectionGuard.Core.RecordFormat;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using System.Text.Json;
using System.Text.Json.Nodes;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// Generates the canonicality vectors committed under test/egrf/vectors/ (design §5.7): one golden
/// item per <c>RecordItem</c> member and a segment header (canonical bytes, leaf hash, proto3 JSON),
/// newer-minor items (unknown content a reader of minor 0 must accept, report and re-encode
/// unchanged), and one negative vector per profile rule. Every value is a deterministic byte pattern,
/// not real cryptography, so the files never churn; the vectors test the format, not the election.
/// The feasibility run's vectors (2026-10-09) were built against the draft schema (RecordHeader
/// field 3 and RecordItem 2047 still live, no member 16), so these are regenerated from the current
/// schema; the negative cases follow the same rule list.
/// </summary>
internal static class EgrfVectors
{
    public const string ItemsFile = "items.json";
    public const string NegativesFile = "negatives.json";

    /// <summary>A deterministic fill: byte i is (seed + 7i) mod 256, so no two fields look alike.</summary>
    public static byte[] Fill(int length, int seed) => Enumerable.Range(0, length).Select(i => (byte)(seed + 7 * i)).ToArray();

    private static ByteString B(int length, int seed) => ByteString.CopyFrom(Fill(length, seed));

    private static Timestamp Time(long seconds, int millis) => new() { Seconds = seconds, Nanos = millis * 1_000_000 };

    private static Pb.BallotLocator Locator(int position) => new() { Kind = Pb.DeviceKind.Regular, HDi = B(32, 9), Position = (ulong)position };

    private static Pb.HashedCiphertext Hashed(int c1Blocks, int seed) => new() { C0 = B(512, seed), C1 = B(32 * c1Blocks, seed + 1), C2 = B(64, seed + 2) };

    private static Pb.EncryptedContest Contest(uint index, int seed) => new()
    {
        Index = index,
        Fields = { new Pb.EncryptedField { Alpha = B(512, seed), Beta = B(512, seed + 1), RangeProof = B(128, seed + 2) } },
        LimitProof = B(128, seed + 3),
        ContestHash = B(32, seed + 4),
    };

    /// <summary>The golden items, by name; each is a canonical RecordItem.</summary>
    public static IReadOnlyList<(string Name, Pb.RecordItem Item)> GoldenItems()
    {
        var withData = Contest(2, 60);
        withData.UndervoteDifferenceProof = B(64, 70);
        withData.NullVoteProof = B(128, 71);
        withData.ContestData = Hashed(2, 72);

        return
        [
            ("record_header", new() { RecordHeader = new() { FormatMajor = 2 } }),
            ("parameters", new() { Parameters = new() { Version = ByteString.CopyFrom([.. "v2.1.0"u8, .. new byte[26]]), P = B(512, 1), Q = B(32, 2), R = B(512, 3), G = B(512, 4), N = 3, K = 2, HP = B(32, 5) } }),
            ("manifest_file", new() { ManifestFile = new() { MediaType = "application/vnd.electionguard.manifest+json;format=1", Content = ByteString.CopyFromUtf8("{\"electionId\":\"e\", \"x-vendor\": [1, 2]}"), HB = B(32, 6) } }),
            ("guardian_public_key", new() { GuardianPublicKey = new() { Index = 1, VoteCommitments = B(1024, 7), DataCommitments = B(1024, 8), Kappa = B(512, 9), VoteProof = B(96, 10), DataProof = B(96, 11) } }),
            ("election_keys", new() { ElectionKeys = new() { K = B(512, 12), KHat = B(512, 13), HE = B(32, 14) } }),
            ("device_header", new() { DeviceHeader = new() { Kind = Pb.DeviceKind.Regular, DeviceId = "device-1", HDi = B(32, 9), ChainingMode = 1, InitialHash = B(32, 15) } }),
            ("encrypted_ballot", new() { EncryptedBallot = new() { IdB = B(32, 16), HI = B(32, 17), BallotStyle = "style-1", Status = Pb.BallotStatus.Cast, Weight = 1, EncryptedAt = Time(1_791_000_000, 412), Contests = { Contest(1, 40), withData }, ConfirmationCode = B(32, 18), ChainingField = B(36, 19), EncryptedBallotNonce = Hashed(1, 20), BallotRef = "paper-0001" } }),
            ("pre_encrypted_cast_ballot", new() { PreEncryptedCastBallot = new() { IdB = B(32, 21), HI = B(32, 22), BallotStyle = "style-1", Weight = 1, Contests = { new Pb.PreEncryptedCastContest { Contest = Contest(1, 80), SelectionHashes = B(96, 81), Selected = { new Pb.SelectedVector { Vector = B(2048, 82), Psi = B(32, 83), ShortCode = "A7" } } } }, ConfirmationCode = B(32, 23), ChainingField = B(36, 24), EncryptedBallotNonce = Hashed(1, 25) } }),
            ("pre_encrypted_uncast_ballot", new() { PreEncryptedUncastBallot = new() { IdB = B(32, 26), HI = B(32, 27), BallotStyle = "style-1", Contests = { new Pb.UncastContest { Index = 1, Label = "contest-1", Selections = { new Pb.UncastSelection { SelectionIndex = 1, OptionLabel = "option-1", Vector = B(1024, 84), Psi = B(32, 85), ShortCode = "B2" }, new Pb.UncastSelection { SelectionIndex = 2, Vector = B(1024, 86), Psi = B(32, 87), ShortCode = "C3" } }, ContestHash = B(32, 88) } }, ConfirmationCode = B(32, 28), ChainingField = B(36, 29), EncryptedBallotNonce = Hashed(1, 30) } }),
            ("device_close", new() { DeviceClose = new() { BallotCount = 412, ClosingChainingField = B(36, 31), ClosingHash = B(32, 32), ClosedAt = Time(1_791_036_000, 0) } }),
            ("device_attestation", new() { DeviceAttestation = new() { Statement = ChainClose().ToByteString(), Algorithm = "ecdsa-p256-sha256", KeyId = B(8, 33), Signature = B(72, 34) } }),
            ("pre_encrypted_compact_uncast_ballot", new() { PreEncryptedCompactUncastBallot = new() { IdB = B(32, 35), HI = B(32, 36), BallotStyle = "style-1", Contests = { new Pb.CompactUncastContest { Index = 1, ContestHash = B(32, 37) } }, ConfirmationCode = B(32, 38), ChainingField = B(36, 39), EncryptedBallotNonce = Hashed(1, 41) } }),
            ("encrypted_tally_header", new() { EncryptedTallyHeader = new() { CastBallotCount = 1000, TotalCastWeight = 1003 } }),
            ("encrypted_tally_contest", new() { EncryptedTallyContest = new() { Index = 1, Fields = B(2048, 42), CastWeight = 1003 } }),
            ("contest_data_request", new() { ContestDataRequest = new() { Ballot = Locator(3), HI = B(32, 43), ContestIndex = 2 } }),
            ("decrypted_tally_contest", new() { DecryptedTallyContest = new() { Index = 1, Label = "contest-1", Fields = { new Pb.DecryptedTallyField { Index = 1, Label = "option-1", Tally = 512, EncodedTally = B(512, 44), Proof = B(64, 45) }, new Pb.DecryptedTallyField { Index = 2, Label = "option-2", EncodedTally = B(512, 46), Proof = B(64, 47) } } } }),
            ("challenged_ballot_decryption", new() { ChallengedBallotDecryption = new() { Ballot = Locator(4), HI = B(32, 48), Contests = { new Pb.DecryptedContest { Index = 1, Label = "contest-1", Fields = { new Pb.DecryptedField { Index = 1, Label = "option-1", Value = 1, Nonce = B(32, 49) }, new Pb.DecryptedField { Index = 2, Label = "option-2", Nonce = B(32, 50) } }, ContestData = new Pb.ReleasedContestData { Nonce = B(32, 51), Data = B(64, 52) } } } } }),
            ("contest_data_decryption", new() { ContestDataDecryption = new() { Ballot = Locator(3), HI = B(32, 43), ContestIndex = 2, Beta = B(512, 53), Proof = B(64, 54), Data = B(64, 55) } }),
            ("uncast_nonce_release", new() { UncastNonceRelease = new() { Ballot = new Pb.BallotLocator { Kind = Pb.DeviceKind.PreEncrypting, HDi = B(32, 56), Position = 2 }, HI = B(32, 57), BallotNonce = B(32, 58) } }),
            ("chain_close_statement", ChainClose()),
            ("section_seal_statement", new() { SectionSealStatement = new() { HE = B(32, 14), DeviceKey = ByteString.CopyFrom([1, .. Fill(32, 9)]), ItemCount = 414, SectionRoot = B(32, 59) } }),
            ("prefix_checkpoint_statement", new() { PrefixCheckpointStatement = new() { HE = B(32, 14), DeviceKey = ByteString.CopyFrom([1, .. Fill(32, 9)]), BallotCount = 100, CodesRoot = B(32, 61), At = Time(1_791_010_000, 5) } }),
            ("record_statement", RecordStatement()),
            ("record_signature", new() { RecordSignature = new() { Statement = RecordStatement().ToByteString(), Algorithm = "ecdsa-p256-sha256", KeyId = B(8, 62), SignerKey = B(91, 63), Signature = B(71, 64), TimestampToken = B(40, 65) } }),
            ("toc_entry", new() { TocEntry = new() { SectionType = Pb.SectionType.Device, Key = ByteString.CopyFrom([1, .. Fill(32, 9)]), Critical = true, ItemCount = 414, Root = B(32, 66) } }),
            ("confirmation_code_leaf", new() { ConfirmationCodeLeaf = new() { Code = B(32, 18) } }),
            ("vendor_item", new() { VendorItem = new() { TypeUrl = "example.com/vendor.Note", Value = ByteString.CopyFromUtf8("opaque") } }),
        ];
    }

    private static Pb.RecordItem ChainClose() => new() { ChainCloseStatement = new() { HE = B(32, 14), DeviceKey = ByteString.CopyFrom([1, .. Fill(32, 9)]), DeviceId = "device-1", ChainingMode = 1, BallotCount = 412, CodesRoot = B(32, 67), ClosingHash = B(32, 32), ClosedAt = Time(1_791_036_000, 0) } };

    private static Pb.RecordItem RecordStatement() => new() { RecordStatement = new() { Phase = Pb.RecordPhase.Final, Root = B(32, 68), HE = B(32, 14), FormatMajor = 2, SignedAt = Time(1_791_100_000, 250), SignerRole = "administrator" } };

    public static Pb.SegmentHeader GoldenSegmentHeader() => new() { Magic = "EGRF", FormatMajor = 2, SectionType = Pb.SectionType.Device, Key = ByteString.CopyFrom([1, .. Fill(32, 9)]), FirstOrdinal = 256 };

    // ---- raw wire building, for vectors no serializer would write --------------------------------

    public static byte[] Varint(ulong value)
    {
        var bytes = new List<byte>();
        do
        {
            byte b = (byte)(value & 0x7F);
            value >>= 7;
            bytes.Add(value != 0 ? (byte)(b | 0x80) : b);
        }
        while (value != 0);
        return [.. bytes];
    }

    public static byte[] Tag(int number, int wireType) => Varint(((ulong)number << 3) | (uint)wireType);

    public static byte[] V(int number, ulong value) => [.. Tag(number, 0), .. Varint(value)];

    public static byte[] L(int number, params byte[][] payload)
    {
        byte[] body = payload.SelectMany(x => x).ToArray();
        return [.. Tag(number, 2), .. Varint((ulong)body.Length), .. body];
    }

    public static byte[] S(int number, string text) => L(number, System.Text.Encoding.UTF8.GetBytes(text));

    public static byte[] Cat(params byte[][] parts) => parts.SelectMany(x => x).ToArray();

    /// <summary>A RecordItem with one member <paramref name="member"/> holding <paramref name="fields"/>.</summary>
    public static byte[] Item(int member, params byte[][] fields) => L(member, fields);

    // A minimal DeviceHeader (member 10): kind 1, device_id "d", h_di.
    private static byte[] Kind => V(1, 1);
    private static byte[] DeviceId => S(2, "d");
    private static byte[] HDi => L(3, Fill(32, 9));

    // A minimal EncryptedBallot (member 11), as raw fields, so a vector can change one of them.
    private static byte[] IdB => L(1, Fill(32, 16));
    private static byte[] HI => L(2, Fill(32, 17));
    private static byte[] Style => S(3, "s");
    private static byte[] Status => V(4, 1);
    private static byte[] Weight => V(5, 1);
    private static byte[] Field => L(2, L(1, Fill(512, 1)), L(2, Fill(512, 2)), L(3, Fill(128, 3)));
    private static byte[] ContestOne => L(7, V(1, 1), Field, L(3, Fill(128, 4)), L(7, Fill(32, 5)));
    private static byte[] ContestTwo => L(7, V(1, 2), Field, L(3, Fill(128, 6)), L(7, Fill(32, 7)));
    private static byte[] Code => L(8, Fill(32, 18));
    private static byte[] Chaining => L(9, Fill(36, 19));
    private static byte[] Nonce => L(10, L(1, Fill(512, 20)), L(2, Fill(32, 21)), L(3, Fill(64, 22)));

    public static byte[] Ballot(params byte[][] fields) => Item(11, fields);

    public static byte[][] BallotFields() => [IdB, HI, Style, Status, Weight, ContestOne, Code, Chaining, Nonce];

    public static byte[] Timestamped(byte[] timestamp) => Ballot(IdB, HI, Style, Status, Weight, L(6, timestamp), ContestOne, Code, Chaining, Nonce);

    public static byte[] HeaderItem(params byte[][] fields) => Item(1, fields);

    /// <summary>One vector: what it is, the rule it breaks (null: canonical), the record's minor, which check applies, its bytes.</summary>
    public sealed record Vector(string Name, string? Rule, int RecordMinor, string Kind, byte[] Bytes);

    /// <summary>Newer-minor items: canonical for a reader of minor 0 reading a minor-1 record, with content it reports.</summary>
    public static IReadOnlyList<Vector> NewerMinor() =>
    [
        new("RecordHeader with unknown fields 4 (VARINT) and 5 (LEN), ascending", null, 1, "item", HeaderItem(V(1, 2), V(2, 1), V(4, 7), L(5, [0x61, 0x62]))),
        new("RecordHeader with an unknown LEN field repeated contiguously", null, 1, "item", HeaderItem(V(1, 2), V(2, 1), L(5, [0x61]), L(5, [0x62]))),
        new("EncryptedBallot with unknown field 12 after ballot_ref's place", null, 1, "item", Ballot([.. BallotFields(), L(12, [1, 2, 3])])),
        new("EncryptedField with unknown field 4 inside a contest", null, 1, "item", Ballot(IdB, HI, Style, Status, Weight, L(7, V(1, 1), L(2, L(1, Fill(512, 1)), L(2, Fill(512, 2)), L(3, Fill(128, 3)), V(4, 9)), L(3, Fill(128, 4)), L(7, Fill(32, 5))), Code, Chaining, Nonce)),
        new("RecordItem member 60, an item type this reader does not know", null, 1, "item", Item(60, V(1, 5))),
        new("EncryptedBallot with status 4, an enum value a later minor declares", null, 1, "item", Ballot(IdB, HI, Style, V(4, 4), Weight, ContestOne, Code, Chaining, Nonce)),
    ];

    /// <summary>Negative vectors: one or more per profile rule, each breaking exactly that rule.</summary>
    public static IReadOnlyList<Vector> Negatives()
    {
        var reorderedBallot = BallotFields().ToArray();
        (reorderedBallot[0], reorderedBallot[1]) = (reorderedBallot[1], reorderedBallot[0]);
        byte[] statement = ChainClose().ToByteArray();

        return
        [
            // W1 order
            new("fields out of order (format_minor before format_major)", "W1", 0, "item", HeaderItem(V(2, 1), V(1, 2))),
            new("fields out of order (h_i before id_b)", "W1", 0, "item", Ballot(reorderedBallot)),
            new("repeated contests not contiguous", "W1", 0, "item", Ballot(IdB, HI, Style, Status, Weight, ContestOne, Code, ContestTwo, Chaining, Nonce)),
            // W2 presence
            new("explicit default format_minor = 0", "W2", 0, "item", HeaderItem(V(1, 2), V(2, 0))),
            new("explicit default chaining_mode = 0", "W2", 0, "item", Item(10, Kind, DeviceId, HDi, V(4, 0))),
            new("explicit empty string device_id", "W2", 0, "item", Item(10, Kind, S(2, ""), HDi)),
            new("explicit empty bytes initial_hash", "W2", 0, "item", Item(10, Kind, DeviceId, HDi, L(5))),
            new("singular field written twice (h_di)", "W2", 0, "item", Item(10, Kind, DeviceId, HDi, HDi)),
            new("singular message written twice (encrypted_ballot_nonce)", "W2", 0, "item", Ballot([.. BallotFields(), Nonce])),
            new("oneof member written twice (record_header)", "W2", 0, "item", Cat(HeaderItem(V(1, 2)), HeaderItem(V(1, 2)))),
            new("explicit default nanos = 0 inside a Timestamp", "W2", 0, "item", Timestamped(Cat(V(1, 1_791_000_000), V(2, 0)))),
            new("unknown VARINT field of value 0", "W2", 1, "item", HeaderItem(V(1, 2), V(4, 0))),
            // W3 wire types
            new("weight written as LEN", "W3", 0, "item", Ballot(IdB, HI, Style, Status, L(5, [1]), ContestOne, Code, Chaining, Nonce)),
            new("id_b written as VARINT", "W3", 0, "item", Ballot(V(1, 7), HI, Style, Status, Weight, ContestOne, Code, Chaining, Nonce)),
            new("id_b written as I64", "W3", 0, "item", Ballot([.. Tag(1, 1), .. new byte[8]], HI, Style, Status, Weight, ContestOne, Code, Chaining, Nonce)),
            new("unknown field of wire type I64", "W3", 1, "item", HeaderItem(V(1, 2), [.. Tag(4, 1), .. new byte[8]])),
            new("unknown field of wire type I32", "W3", 1, "item", HeaderItem(V(1, 2), [.. Tag(4, 5), .. new byte[4]])),
            new("tag with field number 0", "W3", 0, "item", HeaderItem(V(1, 2), [0x00, 0x01])),
            // W4 minimal varints
            new("overlong varint in a tag", "W4", 0, "item", HeaderItem([0x88, 0x00, 0x02])),
            new("overlong varint in a length", "W4", 0, "item", [.. Tag(1, 2), 0x82, 0x00, .. V(1, 2)]),
            new("overlong varint in a value (weight 1 as 0x81 0x00)", "W4", 0, "item", Ballot(IdB, HI, Style, Status, [.. Tag(5, 0), 0x81, 0x00], ContestOne, Code, Chaining, Nonce)),
            new("bool written as 0x02 (critical)", "W4", 0, "item", Item(50, V(1, 257), L(2, [1, .. Fill(32, 9)]), V(3, 2), V(4, 3), L(5, Fill(32, 1)))),
            new("non-minimal varint inside an unknown field", "W4", 1, "item", HeaderItem(V(1, 2), [.. Tag(4, 0), 0x87, 0x00])),
            new("varint longer than 64 bits", "W4", 0, "item", HeaderItem([.. Tag(1, 0), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F])),
            // W5 lengths
            new("length past the end of the item", "W5", 0, "item", [.. Tag(1, 2), 0x05, .. V(1, 2)]),
            new("varint cut short at the end", "W5", 0, "item", HeaderItem(V(1, 2), [.. Tag(2, 0), 0x81])),
            // W6 unknown fields
            new("unknown field in a record of the reader's minor", "W6", 0, "item", HeaderItem(V(1, 2), V(4, 7))),
            new("unknown item type in a record of the reader's minor", "W6", 0, "item", Item(60, V(1, 5))),
            new("unknown field before a known field", "W6", 1, "item", HeaderItem(V(1, 2), V(4, 7), V(2, 1))),
            new("unknown fields in descending order", "W6", 1, "item", HeaderItem(V(1, 2), L(5, [0x61]), V(4, 7))),
            new("unknown number inside the declared range (a reserved number)", "W6", 1, "item", HeaderItem(V(1, 2), V(3, 7))),
            new("unknown number inside a reserved range of PreEncryptedCastBallot", "W6", 1, "item", Item(12, L(1, Fill(32, 16)), L(2, Fill(32, 17)), S(3, "s"), V(5, 1), L(8, Fill(32, 18)), L(9, Fill(36, 19)), Nonce, V(4, 1))),
            new("unknown item type at the reserved number 2047", "W6", 1, "item", Item(2047, V(1, 1))),
            new("unknown VARINT field repeated", "W6", 1, "item", HeaderItem(V(1, 2), V(4, 7), V(4, 8))),
            // W8 strings
            new("ill-formed UTF-8 in a string (overlong C0 AF)", "W8", 0, "item", Item(10, Kind, L(2, [0x64, 0xC0, 0xAF]), HDi)),
            new("ill-formed UTF-8 in a string (encoded surrogate ED A0 80)", "W8", 0, "item", Item(10, Kind, L(2, [0xED, 0xA0, 0x80]), HDi)),
            // D1 widths
            new("wrong width (h_di of 31 bytes)", "D1", 0, "item", Item(10, Kind, DeviceId, L(3, Fill(31, 9)))),
            new("wrong width multiple (range_proof of 100 bytes)", "D1", 0, "item", Ballot(IdB, HI, Style, Status, Weight, L(7, V(1, 1), L(2, L(1, Fill(512, 1)), L(2, Fill(512, 2)), L(3, Fill(100, 3))), L(3, Fill(128, 4)), L(7, Fill(32, 5))), Code, Chaining, Nonce)),
            new("absent width field that is not omittable (h_di)", "D1", 0, "item", Item(10, Kind, DeviceId)),
            // D2 enums
            new("undeclared enum value (status 7)", "D2", 0, "item", Ballot(IdB, HI, Style, V(4, 7), Weight, ContestOne, Code, Chaining, Nonce)),
            new("enum absent, so UNSPECIFIED (status)", "D2", 0, "item", Ballot(IdB, HI, Style, Weight, ContestOne, Code, Chaining, Nonce)),
            new("enum value that is no int32 (status 2^31), even for a reader older than the record", "D2", 1, "item", Ballot(IdB, HI, Style, V(4, 1UL << 31), Weight, ContestOne, Code, Chaining, Nonce)),
            new("enum absent, so UNSPECIFIED (device kind)", "D2", 0, "item", Item(10, DeviceId, HDi)),
            // D3 timestamps
            new("timestamp with sub-millisecond nanos", "D3", 0, "item", Timestamped(Cat(V(1, 1_791_000_000), V(2, 1_500_000)))),
            new("timestamp with negative seconds", "D3", 0, "item", Timestamped(V(1, unchecked((ulong)-1L)))),
            new("timestamp with negative nanos", "D3", 0, "item", Timestamped(Cat(V(1, 1_791_000_000), V(2, unchecked((ulong)-1_000_000L))))),
            new("timestamp after 9999-12-31", "D3", 0, "item", Timestamped(V(1, 253_402_300_800))),
            // D4 integer bounds
            new("uint32 at 2^31 (weight)", "D4", 0, "item", Ballot(IdB, HI, Style, Status, V(5, 1UL << 31), ContestOne, Code, Chaining, Nonce)),
            new("uint64 at 2^63 (ballot_count)", "D4", 0, "item", Item(14, V(1, 1UL << 63))),
            // D5 envelope
            new("empty RecordItem", "D5", 0, "item", []),
            new("RecordItem with two members", "D5", 0, "item", Cat(HeaderItem(V(1, 2)), Item(14, V(1, 1)))),
            new("RecordItem with a known and an unknown member", "D5", 1, "item", Cat(HeaderItem(V(1, 2)), Item(60, V(1, 1)))),
            // D6 segment header
            new("segment header with another magic", "D6", 0, "segmentHeader", Cat(S(1, "EGRX"), V(2, 2), V(3, 257))),
            new("segment header of format major 3", "D6", 0, "segmentHeader", Cat(S(1, "EGRF"), V(2, 3), V(3, 257))),
            new("non-canonical segment header (fields out of order)", "D6", 0, "segmentHeader", Cat(V(2, 2), S(1, "EGRF"), V(3, 257))),
            new("segment header without a section type", "D6", 0, "segmentHeader", Cat(S(1, "EGRF"), V(2, 2))),
            // A new section kind comes only with a new format major (user decision NQ-7), so an
            // undeclared non-vendor SectionType is D2 even for a reader older than the record.
            new("segment header naming section type 0x0203 in a newer-minor record", "D6", 1, "segmentHeader", Cat(S(1, "EGRF"), V(2, 2), V(3, 0x0203))),
            new("toc_entry naming section type 0x0203 in a newer-minor record", "D2", 1, "item", Item(50, V(1, 0x0203), V(4, 1), L(5, Fill(32, 9)))),
            // §4.9 signed statements
            new("device attestation over a non-canonical statement", "R.attestation", 0, "signedStatement", Item(15, L(1, [.. statement, .. V(9, 0)]), S(2, "ecdsa-p256-sha256"))),
            new("device attestation over a non-statement member (record_header)", "R.attestation", 0, "signedStatement", Item(15, L(1, HeaderItem(V(1, 2))), S(2, "ecdsa-p256-sha256"))),
            new("record signature over a chain-close statement", "R.signature", 0, "signedStatement", Item(44, L(1, statement), S(2, "ecdsa-p256-sha256"))),
        ];
    }

    // ---- the committed files -------------------------------------------------------------------

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public static string ItemsJson()
    {
        var items = new JsonArray();
        foreach (var (name, item) in GoldenItems())
        {
            byte[] bytes = item.ToByteArray();
            items.Add(new JsonObject
            {
                ["name"] = name,
                ["member"] = (int)item.ItemCase,
                ["hex"] = Convert.ToHexStringLower(bytes),
                ["leafHash"] = MerkleTree.LeafHash(bytes).ToString(),
                ["json"] = JsonFormatter.Default.Format(item),
            });
        }

        var header = GoldenSegmentHeader();
        var newer = new JsonArray();
        foreach (var vector in NewerMinor())
        {
            newer.Add(new JsonObject
            {
                ["name"] = vector.Name,
                ["kind"] = vector.Kind,
                ["recordMinor"] = vector.RecordMinor,
                ["hex"] = Convert.ToHexStringLower(vector.Bytes),
                ["verdict"] = "canonical; unknown content reported; re-encodes to the same bytes",
            });
        }

        var root = new JsonObject
        {
            ["description"] = "EGRF v2 golden vectors (design §5.7), generated by ElectionGuard.Core.UnitTests EgrfVectors from proto/electionguard/egrf/v2/egrf.proto. Values are deterministic byte patterns, not cryptography. 'hex' is the canonical RecordItem; 'leafHash' = SHA-256(0x00 || bytes); 'json' is the proto3 JSON mapping as C# JsonFormatter writes it (compare it by structure, not text, design §5.5). 'newerMinor' items are canonical for a reader of format minor 0 reading a record of the given minor: it accepts them, reports their unknown content and re-encodes them unchanged. Regenerate with EGRF_WRITE_VECTORS=1.",
            ["formatMajor"] = 2,
            ["formatMinor"] = 0,
            ["items"] = items,
            ["segmentHeader"] = new JsonObject
            {
                ["hex"] = Convert.ToHexStringLower(header.ToByteArray()),
                ["json"] = JsonFormatter.Default.Format(header),
            },
            ["newerMinor"] = newer,
        };

        return root.ToJsonString(Indented).Replace("\r\n", "\n") + "\n";
    }

    public static string NegativesJson()
    {
        var vectors = new JsonArray();
        foreach (var vector in Negatives())
        {
            vectors.Add(new JsonObject
            {
                ["name"] = vector.Name,
                ["rule"] = vector.Rule,
                ["kind"] = vector.Kind,
                ["recordMinor"] = vector.RecordMinor,
                ["hex"] = Convert.ToHexStringLower(vector.Bytes),
            });
        }

        var root = new JsonObject
        {
            ["description"] = "EGRF v2 negative vectors (design §4.2-§4.4, §4.9, §5.7), generated by ElectionGuard.Core.UnitTests EgrfVectors. Each breaks exactly one profile rule; 'rule' is the rule Method A names (for a segment header, D6 with the inner rule in the message; for a signed statement, R.attestation or R.signature). 'kind': item (a RecordItem), segmentHeader, or signedStatement (a RecordItem whose statement is checked too). 'recordMinor' is the record's format minor; the reader is of minor 0, so 1 means a reader older than the record (W6's unknown-field branch). Layout, framing and carrier negatives come with the carriers (S10b-6/7). Regenerate with EGRF_WRITE_VECTORS=1.",
            ["vectors"] = vectors,
        };

        return root.ToJsonString(Indented).Replace("\r\n", "\n") + "\n";
    }
}
