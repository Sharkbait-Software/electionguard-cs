using ElectionGuard.Core.RecordFormat;
using Google.Protobuf;
using System.Text.Json.Nodes;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-3: the canonical protobuf profile check (design §4.2-§4.4, §4.9). The vectors are generated
/// by <see cref="EgrfVectors"/> and committed under test/egrf/vectors/; to accept a change, run the
/// tests with EGRF_WRITE_VECTORS=1 and review the diff.
/// </summary>
public class CanonicalProtobufTests
{
    private const string WriteVariable = "EGRF_WRITE_VECTORS";

    private static CanonicalCheck CheckKind(string kind, byte[] bytes, ushort minor) => kind switch
    {
        "item" => CanonicalProtobuf.Check(bytes, minor),
        "segmentHeader" => CanonicalProtobuf.CheckSegmentHeader(bytes, minor),
        "signedStatement" => CanonicalProtobuf.CheckSignedStatement(bytes, minor),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static string MessageOf(string kind) => kind == "segmentHeader" ? "electionguard.egrf.v2.SegmentHeader" : "electionguard.egrf.v2.RecordItem";

    private static MessageParser ParserOf(string kind) => kind == "segmentHeader" ? Pb.SegmentHeader.Parser : Pb.RecordItem.Parser;

    [Fact]
    public void CommittedVectors_AreTheGeneratedOnes()
    {
        EgrfTestFiles.AssertCommitted(EgrfTestFiles.Vector(EgrfVectors.ItemsFile), EgrfVectors.ItemsJson(), WriteVariable);
        EgrfTestFiles.AssertCommitted(EgrfTestFiles.Vector(EgrfVectors.NegativesFile), EgrfVectors.NegativesJson(), WriteVariable);
    }

    /// <summary>
    /// Every golden item, read from the committed file, is canonical by both methods, re-encodes to
    /// itself, has the committed leaf hash, and its proto3 JSON parses back to the same bytes.
    /// </summary>
    [Fact]
    public void GoldenItems_AreCanonical_ByBothMethods()
    {
        var file = JsonNode.Parse(EgrfTestFiles.ReadText(EgrfTestFiles.Vector(EgrfVectors.ItemsFile)))!.AsObject();
        var items = file["items"]!.AsArray();
        Assert.Equal(Enum.GetValues<Pb.RecordItem.ItemOneofCase>().Length - 1, items.Count);

        foreach (var item in items)
        {
            byte[] bytes = Convert.FromHexString((string)item!["hex"]!);
            string name = (string)item["name"]!;

            Assert.Equal(new CanonicalCheck(true, null, false), CanonicalProtobuf.Check(bytes, 0));
            Assert.True(CanonicalProtobuf.MethodA(bytes).IsCanonical, name);
            Assert.True(CanonicalProtobuf.MethodB(bytes).IsCanonical, name);
            Assert.Equal(bytes, Pb.RecordItem.Parser.ParseFrom(bytes).ToByteArray());
            Assert.Equal((string)item["leafHash"]!, MerkleTree.LeafHash(bytes).ToString());
            Assert.Equal(bytes, JsonParser.Default.Parse<Pb.RecordItem>((string)item["json"]!).ToByteArray());
            Assert.Equal((int)item["member"]!, (int)Pb.RecordItem.Parser.ParseFrom(bytes).ItemCase);
        }

        byte[] header = Convert.FromHexString((string)file["segmentHeader"]!["hex"]!);
        Assert.Equal(new CanonicalCheck(true, null, false), CanonicalProtobuf.CheckSegmentHeader(header, 0));
    }

    /// <summary>The signed statements among the golden items pass the §4.9 statement check.</summary>
    [Fact]
    public void GoldenSignedStatements_PassTheStatementCheck()
    {
        foreach (var (name, item) in EgrfVectors.GoldenItems().Where(x => x.Name is "device_attestation" or "record_signature"))
        {
            Assert.True(CanonicalProtobuf.CheckSignedStatement(item.ToByteArray(), 0).IsCanonical, name);
        }
    }

    /// <summary>
    /// Each negative vector is rejected by both methods, and Method A (so <see cref="CanonicalProtobuf.Check"/>)
    /// names its rule.
    /// </summary>
    [Fact]
    public void NegativeVectors_AreRejected_WithTheirRule_ByBothMethods()
    {
        var vectors = JsonNode.Parse(EgrfTestFiles.ReadText(EgrfTestFiles.Vector(EgrfVectors.NegativesFile)))!["vectors"]!.AsArray();
        var rules = new HashSet<string>();
        foreach (var vector in vectors)
        {
            string name = (string)vector!["name"]!, rule = (string)vector["rule"]!, kind = (string)vector["kind"]!;
            ushort minor = (ushort)(int)vector["recordMinor"]!;
            byte[] bytes = Convert.FromHexString((string)vector["hex"]!);
            rules.Add(rule);

            var check = CheckKind(kind, bytes, minor);
            Assert.False(check.IsCanonical, name);
            Assert.True(rule == check.Rule, $"{name}: expected {rule}, got {check.Rule}: {check.Message}");
            Assert.False(string.IsNullOrEmpty(check.Message), name);

            if (kind == "item")
            {
                var a = CanonicalProtobuf.MethodA(bytes, readerOlder: minor > 0);
                var b = CanonicalProtobuf.MethodB(bytes, readerOlder: minor > 0);
                Assert.True(rule == a.Rule, $"{name}: Method A named {a.Rule}: {a.Message}");
                Assert.False(b.IsCanonical, $"{name}: Method B accepted it");
            }
        }

        // One rule at least per wire rule (W7 is a schema property: no repeated scalar exists, S3)
        // and decode rule, plus the statement codes.
        foreach (var rule in new[] { "W1", "W2", "W3", "W4", "W5", "W6", "W8", "D1", "D2", "D3", "D4", "D5", "D6", "R.attestation", "R.signature" })
        {
            Assert.Contains(rule, rules);
        }
    }

    /// <summary>
    /// NQ-1: a reader of minor 0 accepts a newer-minor item whose unknown content follows W6,
    /// reports it, and keeps it when it re-encodes, so every digest survives; a reader that knows the
    /// record's minor (here: the record claims minor 0) rejects the same bytes.
    /// </summary>
    [Fact]
    public void NewerMinorItems_AreAccepted_Reported_AndReEncodedUnchanged()
    {
        var newer = JsonNode.Parse(EgrfTestFiles.ReadText(EgrfTestFiles.Vector(EgrfVectors.ItemsFile)))!["newerMinor"]!.AsArray();
        Assert.NotEmpty(newer);
        foreach (var vector in newer)
        {
            string name = (string)vector!["name"]!, kind = (string)vector["kind"]!;
            byte[] bytes = Convert.FromHexString((string)vector["hex"]!);
            ushort minor = (ushort)(int)vector["recordMinor"]!;

            Assert.Equal(new CanonicalCheck(true, null, true), CheckKind(kind, bytes, minor));
            Assert.True(CanonicalProtobuf.MethodA(bytes, MessageOf(kind), readerOlder: true).IsCanonical, name);
            Assert.True(CanonicalProtobuf.MethodB(bytes, MessageOf(kind), ParserOf(kind), readerOlder: true).IsCanonical, name);
            Assert.Equal(bytes, ParserOf(kind).ParseFrom(bytes).ToByteArray());

            Assert.False(CheckKind(kind, bytes, 0).IsCanonical, $"{name} at the reader's own minor");
        }
    }

    /// <summary>Encoding any golden value and checking it always passes: the writer's output is canonical (property).</summary>
    [Fact]
    public void EncodeThenCheck_AlwaysPasses_ForEveryGoldenMessageWithFieldsCleared()
    {
        foreach (var (name, item) in EgrfVectors.GoldenItems())
        {
            // The item, and the item with each optional (omittable or message) field cleared in turn,
            // where the schema allows it: whatever the writer emits for a valid value is canonical.
            Assert.True(CanonicalProtobuf.Check(item.ToByteArray(), 0).IsCanonical, name);
            var copy = item.Clone();
            if (copy.ItemCase == Pb.RecordItem.ItemOneofCase.EncryptedBallot)
            {
                copy.EncryptedBallot.EncryptedAt = null;
                copy.EncryptedBallot.BallotRef = "";
                copy.EncryptedBallot.Contests[1].ContestData = null;
                copy.EncryptedBallot.Contests[1].NullVoteProof = ByteString.Empty;
                Assert.True(CanonicalProtobuf.Check(copy.ToByteArray(), 0).IsCanonical, name + " (optional fields cleared)");
            }
        }
    }

    /// <summary>
    /// Design §9.2 S10b-3 property: every single-byte mutation of a golden item (three masks per byte)
    /// is judged the same way by Method A and Method B, for a reader at the record's minor and for one
    /// older than the record. A mutation both accept differs in bytes from the original, so it is
    /// another item (canonical encodings are unique).
    /// </summary>
    [Fact]
    public void SingleByteMutations_MethodsAAndBNeverDisagree()
    {
        var disagreements = new List<string>();
        foreach (var (name, item) in EgrfVectors.GoldenItems())
        {
            byte[] original = item.ToByteArray();
            foreach (bool older in new[] { false, true })
            {
                for (int i = 0; i < original.Length; i++)
                {
                    foreach (byte mask in new byte[] { 0x01, 0x80, 0xFF })
                    {
                        byte[] mutated = original.ToArray();
                        mutated[i] ^= mask;
                        var a = CanonicalProtobuf.MethodA(mutated, readerOlder: older);
                        var b = CanonicalProtobuf.MethodB(mutated, readerOlder: older);
                        if (a.IsCanonical != b.IsCanonical || (a.IsCanonical && a.HasUnknownContent != b.HasUnknownContent))
                        {
                            disagreements.Add($"{name} byte {i} ^ 0x{mask:x2} older={older}: A {a.IsCanonical}/{a.Rule}/{a.HasUnknownContent}, B {b.IsCanonical}/{b.Rule}/{b.HasUnknownContent}: {a.Message ?? b.Message}");
                        }
                    }
                }
            }
        }

        Assert.True(disagreements.Count == 0, string.Join("\n", disagreements.Take(20)));
    }

    /// <summary>The same property on the hand-built negative and newer-minor vectors, at both reader ages.</summary>
    [Fact]
    public void HandBuiltVectors_MethodsAAndBNeverDisagree()
    {
        foreach (var vector in EgrfVectors.Negatives().Concat(EgrfVectors.NewerMinor()).Where(x => x.Kind != "signedStatement"))
        {
            foreach (bool older in new[] { false, true })
            {
                var a = CanonicalProtobuf.MethodA(vector.Bytes, MessageOf(vector.Kind), older);
                var b = CanonicalProtobuf.MethodB(vector.Bytes, MessageOf(vector.Kind), ParserOf(vector.Kind), older);
                Assert.True(a.IsCanonical == b.IsCanonical, $"{vector.Name} older={older}: A {a.Rule} {a.Message}; B {b.Rule} {b.Message}");
            }
        }
    }

    /// <summary>Range is not a format rule (user decision #11): a 512-byte value of all 0xFF bytes, above p, is canonical.</summary>
    [Fact]
    public void OutOfRangeValues_AreCanonical()
    {
        var keys = new Pb.RecordItem { ElectionKeys = new Pb.ElectionKeys { K = ByteString.CopyFrom(Enumerable.Repeat((byte)0xFF, 512).ToArray()), KHat = ByteString.CopyFrom(new byte[512]), HE = ByteString.CopyFrom(new byte[32]) } };
        Assert.True(CanonicalProtobuf.Check(keys.ToByteArray(), 0).IsCanonical);
    }
}
