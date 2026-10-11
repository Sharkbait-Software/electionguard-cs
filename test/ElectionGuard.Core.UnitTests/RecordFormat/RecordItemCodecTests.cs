using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;
using Google.Protobuf;
using System.Text;
using System.Text.Json.Nodes;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-16: <see cref="RecordItemCodec"/>, the public item codec that replaced the protobuf-net and
/// System.Text.Json ballot serializers (<c>IEncryptedBallotSerializer</c>), and the S10a record tests
/// of <c>ElectionRecordSerializationTests</c> that were about the domain rather than the retired JSON
/// documents (the decryption bound restored from a published cast weight, forged weights, values
/// that decode and fail their verification), now driven through the record's items. What the retired
/// tests pinned about JSON text (base64 spellings, lone surrogates, BOMs, unknown and repeated
/// members) is the JSON projection's (<c>RecordJsonProjectionTests</c>, the §5.7 negatives); what they
/// pinned about ranges and widths is the mappers' and the canonicality check's (<c>RecordMapperTests</c>,
/// <c>CanonicalProtobufTests</c>).
/// </summary>
public class RecordItemCodecTests
{
    public RecordItemCodecTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private const string WriteIn = "Write-in: Ada Lovelace";
    private const string DeviceId = "device-1";

    private sealed class Election
    {
        public required ElectionFixtureBuilder.GuardianSetResult GuardianSet { get; init; }
        public required EncryptionRecord Record { get; init; }
        public required List<EncryptedBallot> Ballots { get; init; }
        public required EncryptedTally Tally { get; init; }
        public required DecryptedTally Decrypted { get; init; }

        public Manifest Manifest => Record.Manifest;
    }

    /// <summary>
    /// Every supplemental field kind, write-ins and contest data: two cast ballots (one of weight 2),
    /// a spoiled and a challenged one, the tally and its decryption.
    /// </summary>
    private static readonly Lazy<Election> Shared = new(() =>
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true, selectionLimit: 2, supplementalFields: ElectionFixtureBuilder.AllSupplementalFields);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var record = records.EncryptionRecord;
        var deviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, DeviceId);

        EncryptedBallot Encrypt(string id, int choice1, BallotStatus status, int weight = 1)
        {
            var encrypted = ElectionFixtureBuilder.CreateEncryptedBallot(record, DeviceId, deviceHash,
                ElectionFixtureBuilder.CreateBallot(manifest, id, new Dictionary<string, int> { ["choice-1"] = choice1 }, numWriteinsSelected: 1, contestData: WriteIn),
                status: BallotStatus.Unrecorded);
            return TallyDecryptionElection.WithWeight(encrypted, weight, status);
        }

        var ballots = new List<EncryptedBallot>
        {
            Encrypt("ballot-1", 1, BallotStatus.Cast),
            Encrypt("ballot-2", 1, BallotStatus.Cast, weight: 2),
            Encrypt("ballot-3", 0, BallotStatus.Spoiled),
            Encrypt("ballot-4", 0, BallotStatus.Challenged),
        };

        var tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, ballots.ToArray());
        return new Election
        {
            GuardianSet = guardianSet,
            Record = record,
            Ballots = ballots,
            Tally = tally,
            Decrypted = new TallyAdmin().Decrypt(ElectionFixtureBuilder.TallyGuardians(guardianSet), tally, record),
        };
    });

    private static IReadOnlyList<TallyGuardian> Guardians => ElectionFixtureBuilder.TallyGuardians(Shared.Value.GuardianSet);

    private static ByteString NotBelowP => ByteString.CopyFrom(EGParameters.P.ToBigEndianPadded(512));

    private static ByteString NotBelowQ => ByteString.CopyFrom(EGParameters.Q.ToBigEndianPadded(32));

    private static void Verify5To8(EncryptedBallot ballot, EncryptionRecord record)
    {
        new SelectionEncryptionIdentifierVerification().Verify(ballot.SelectionEncryptionIdentifier, ballot.SelectionEncryptionIdentifierHash, record.ExtendedBaseHash);
        new SelectionEncryptionsWellFormedVerification().Verify(ballot, record);
        new AdherenceToVoteLimitsVerification().Verify(ballot, record);
        new ConfirmationCodeVerification().Verify(ballot, record);
    }

    // ---- the codec ------------------------------------------------------------------------------

    /// <summary>
    /// Each status, both representations: the decoded ballot carries every value (supplemental fields
    /// with their relation proofs, contest data, the ballot nonce, the chaining field), passes
    /// Verifications 5-8, and encodes to the same canonical bytes; the JSON line reads back into them.
    /// </summary>
    [Fact]
    public void Ballots_RoundTrip_InBothRepresentations_AndPassVerifications5To8()
    {
        var election = Shared.Value;
        foreach (var ballot in election.Ballots)
        {
            byte[] item = RecordItemCodec.EncodeBallot(ballot, election.Manifest);
            byte[] line = RecordItemCodec.EncodeBallotJson(ballot, election.Manifest);
            Assert.True(CanonicalProtobuf.Check(item, 0).IsCanonical);
            Assert.Equal(item, RecordItemCodec.FromJson(line));
            Assert.Equal(line, RecordItemCodec.ToJson(item));
            AssertNoNonce(ballot, item, line);

            foreach (var decoded in new[] { RecordItemCodec.DecodeBallot(item, election.Manifest, DeviceId), RecordItemCodec.DecodeBallotJson(line, election.Manifest, DeviceId) })
            {
                Assert.Equal((ballot.Id, ballot.Status, ballot.Weight, DeviceId), (decoded.Id, decoded.Status, decoded.Weight, decoded.DeviceId));
                Assert.Equal(ballot.SelectionEncryptionIdentifier, decoded.SelectionEncryptionIdentifier);
                Assert.Equal(ballot.ChainingField, decoded.ChainingField);
                Assert.Equal(ballot.EncryptedBallotNonce.C0, decoded.EncryptedBallotNonce.C0);
                var (contest, read) = (ballot.Contests[0], decoded.Contests[0]);
                Assert.Equal(contest.SupplementalFields.Select(x => (x.FieldId, x.Alpha, x.Beta)), read.SupplementalFields.Select(x => (x.FieldId, x.Alpha, x.Beta)));
                Assert.Equal(contest.UndervoteDifferenceProof!.Length, read.UndervoteDifferenceProof!.Length);
                Assert.Equal(contest.NullVoteProof!.Length, read.NullVoteProof!.Length);
                Assert.Equal(contest.ContestData!.C1, read.ContestData!.C1);
                Assert.Equal(item, RecordItemCodec.EncodeBallot(decoded, election.Manifest));
                Verify5To8(decoded, election.Record);
            }
        }
    }

    /// <summary>A cast pre-encrypted ballot is the <c>pre_encrypted_cast_ballot</c> item, with its §4.4 extras.</summary>
    [Fact]
    public void PreEncryptedCastBallot_RoundTrips()
    {
        var election = RecordCarrierElections.PreEncryptedRecord.Value;
        var cast = election.Device.Select(x => x.Cast).OfType<EncryptedBallot>().First();
        var manifest = election.Record.Manifest;

        byte[] item = RecordItemCodec.EncodeBallot(cast, manifest);
        var decoded = RecordItemCodec.DecodeBallot(item, manifest, cast.DeviceId);

        Assert.Equal(Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot, Pb.RecordItem.Parser.ParseFrom(item).ItemCase);
        Assert.True(decoded.IsPreEncrypted);
        Assert.Equal(cast.PreEncryptedContests!.Select(x => x.SelectionHashes.Count), decoded.PreEncryptedContests!.Select(x => x.SelectionHashes.Count));
        Assert.Equal(item, RecordItemCodec.EncodeBallot(decoded, manifest));
        byte[] line = RecordItemCodec.EncodeBallotJson(cast, manifest);
        Assert.Equal(item, RecordItemCodec.FromJson(line));
        AssertNoNonce(cast, item, line);
    }

    /// <summary>
    /// S10b-0's wire check, on the codec's output: no encryption nonce ξ_{i,j} of an option or a
    /// supplemental field (for a cast pre-encrypted ballot, the combined vectors' summed nonces)
    /// occurs in the item bytes, nor its base64 in the JSON line. <c>RecordCompletenessTests.NoSchemaField_CanHoldASecret</c>
    /// checks the schema's field names; this checks the bytes a mapper actually writes, the free-text
    /// <c>ballot_ref</c> included. The nonces must be present on the domain ballot, or the check
    /// would search for nothing.
    /// </summary>
    private static void AssertNoNonce(EncryptedBallot ballot, byte[] item, byte[] line)
    {
        var nonces = ballot.Contests
            .SelectMany(contest => contest.Choices.Select(x => x.EncryptionNonce).Concat(contest.SupplementalFields.Select(x => x.EncryptionNonce)))
            .ToList();
        Assert.NotEmpty(nonces);
        Assert.All(nonces, x => Assert.NotNull(x));
        string text = Encoding.UTF8.GetString(line);
        foreach (var nonce in nonces)
        {
            byte[] bytes = nonce!.Value.ToByteArray();
            Assert.Equal(-1, item.AsSpan().IndexOf(bytes));
            Assert.DoesNotContain(Convert.ToBase64String(bytes), text, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// What the codec does with an item that leaves out the optional <c>ballot_ref</c> (proto: free
    /// text, bound by no hash): the decoded ballot's id is the lowercase hex of id_B, and encoding
    /// that ballot writes the id back as <c>ballot_ref</c>, so the bytes differ from the sender's.
    /// The record holds a ballot as this library re-encodes it from the domain ballot (the writer has
    /// no bytes-level append); this pins that limitation (S10b-F review round 1).
    /// </summary>
    [Fact]
    public void ItemWithoutBallotRef_DecodesWithTheHexOfIdB_AndReEncodesWithIt()
    {
        var election = Shared.Value;
        var item = BallotMapper.ToItem(election.Ballots[0], election.Manifest);
        item.EncryptedBallot.BallotRef = string.Empty;
        byte[] sent = item.ToByteArray();

        var decoded = RecordItemCodec.DecodeBallot(sent, election.Manifest, DeviceId);
        Assert.Equal(Convert.ToHexStringLower(item.EncryptedBallot.IdB.Span), decoded.Id);

        byte[] reEncoded = RecordItemCodec.EncodeBallot(decoded, election.Manifest);
        Assert.NotEqual(sent, reEncoded);
        var parsed = Pb.RecordItem.Parser.ParseFrom(reEncoded).EncryptedBallot;
        Assert.Equal(decoded.Id, parsed.BallotRef);
        parsed.BallotRef = string.Empty;
        Assert.Equal(sent, new Pb.RecordItem { EncryptedBallot = parsed }.ToByteArray());
    }

    public static TheoryData<string> NonCanonicalBallots() => new()
    {
        "a trailing byte",
        "alpha padded to 513 bytes",
        "id_B of 31 bytes",
        "chaining field of 35 bytes",
        "chaining field of 37 bytes",
        "a range proof of 63 bytes",
        "an UNSPECIFIED status",
        "two items in the envelope",
        "a device header, not a ballot",
        "a weight of 2^31",
    };

    /// <summary>
    /// S10a's strict decoding (G23), as the record's canonical form states it: a width (D1), an enum
    /// (D2), an integer's range (D4: a weight of 2^31 or more is refused, so the mapper's clamp to
    /// <see cref="int.MaxValue"/> never changes an item it accepts), the envelope (D5), the wire
    /// (W1-W8). A non-canonical item is a
    /// <see cref="NonCanonicalEncodingException"/>, never a reduced or padded value.
    /// </summary>
    [Theory]
    [MemberData(nameof(NonCanonicalBallots))]
    public void NonCanonicalItem_IsRefused(string tamper)
    {
        var election = Shared.Value;
        var item = BallotMapper.ToItem(election.Ballots[0], election.Manifest);
        var ballot = item.EncryptedBallot;
        byte[] bytes = tamper switch
        {
            "a trailing byte" => [.. item.ToByteArray(), 0],
            "alpha padded to 513 bytes" => Edit(item, () => ballot.Contests[0].Fields[0].Alpha = ByteString.CopyFrom([0, .. ballot.Contests[0].Fields[0].Alpha.Span])),
            "id_B of 31 bytes" => Edit(item, () => ballot.IdB = ByteString.CopyFrom(ballot.IdB.Span[1..])),
            "chaining field of 35 bytes" => Edit(item, () => ballot.ChainingField = ByteString.CopyFrom(ballot.ChainingField.Span[1..])),
            "chaining field of 37 bytes" => Edit(item, () => ballot.ChainingField = ByteString.CopyFrom([.. ballot.ChainingField.Span, 0])),
            "a range proof of 63 bytes" => Edit(item, () => ballot.Contests[0].Fields[0].RangeProof = ByteString.CopyFrom(ballot.Contests[0].Fields[0].RangeProof.Span[1..])),
            "an UNSPECIFIED status" => Edit(item, () => ballot.Status = Pb.BallotStatus.Unspecified),
            "two items in the envelope" => [.. item.ToByteArray(), .. new Pb.RecordItem { DeviceClose = new Pb.DeviceClose { BallotCount = 1 } }.ToByteArray()],
            "a weight of 2^31" => Edit(item, () => ballot.Weight = 1u << 31),
            "a device header, not a ballot" => new Pb.RecordItem { DeviceHeader = new Pb.DeviceHeader { Kind = Pb.DeviceKind.Regular, DeviceId = DeviceId, HDi = ByteString.CopyFrom(new byte[32]), InitialHash = ByteString.CopyFrom(new byte[32]) } }.ToByteArray(),
            _ => throw new ArgumentOutOfRangeException(nameof(tamper)),
        };

        Assert.Throws<NonCanonicalEncodingException>(() => RecordItemCodec.DecodeBallot(bytes, election.Manifest, DeviceId));
        if (tamper == "a weight of 2^31")
        {
            Assert.Equal("D4", CanonicalProtobuf.Check(bytes, 0).Rule);
        }
    }

    private static byte[] Edit(Pb.RecordItem item, Action edit)
    {
        edit();
        return item.ToByteArray();
    }

    public static TheoryData<string, string> OutOfRange() => new()
    {
        { "alpha = p", "6.A" },
        { "range proof c = q", "6.B" },
        { "range proof v = q", "6.C" },
        { "limit proof v = q", "7.C" },
        { "contest data C0 = p", "8.structure" },
        { "ballot nonce C0 = p", "13.structure" },
    };

    /// <summary>
    /// Range is not a format rule (design §4.8): the item is canonical, and the value is reported
    /// under the sub-section of the verification that owns it, never reduced.
    /// </summary>
    [Theory]
    [MemberData(nameof(OutOfRange))]
    public void ValueOutOfRange_IsAVerificationFailure_UnderItsCode(string tamper, string expected)
    {
        var election = Shared.Value;
        var item = BallotMapper.ToItem(election.Ballots[0], election.Manifest);
        var contest = item.EncryptedBallot.Contests[0];
        switch (tamper)
        {
            case "alpha = p": contest.Fields[0].Alpha = NotBelowP; break;
            case "range proof c = q": contest.Fields[0].RangeProof = ByteString.CopyFrom([.. NotBelowQ.Span, .. contest.Fields[0].RangeProof.Span[32..]]); break;
            case "range proof v = q": contest.Fields[0].RangeProof = ByteString.CopyFrom([.. contest.Fields[0].RangeProof.Span[..32], .. NotBelowQ.Span, .. contest.Fields[0].RangeProof.Span[64..]]); break;
            case "limit proof v = q": contest.LimitProof = ByteString.CopyFrom([.. contest.LimitProof.Span[..32], .. NotBelowQ.Span, .. contest.LimitProof.Span[64..]]); break;
            case "contest data C0 = p": contest.ContestData.C0 = NotBelowP; break;
            case "ballot nonce C0 = p": item.EncryptedBallot.EncryptedBallotNonce.C0 = NotBelowP; break;
        }

        byte[] bytes = item.ToByteArray();
        Assert.True(CanonicalProtobuf.Check(bytes, 0).IsCanonical);

        Assert.Equal(expected, Assert.Throws<VerificationFailedException>(() => RecordItemCodec.DecodeBallot(bytes, election.Manifest, DeviceId)).SubSection);
    }

    public static TheoryData<string, int, string> MissingLists() => new()
    {
        { "contests", 6, "6.structure" },
        { "a contest's fields", 6, "6.structure" },
        { "a contest's fields", 9, "9.structure" },
        { "the ballot nonce", 6, "6.structure" },
        { "the ballot nonce", 9, "9.structure" },
        { "a contest's contest data", 6, "6.structure" },
        { "a contest's contest data", 9, "9.structure" },
    };

    /// <summary>
    /// S10a's typed-error contract for malformed documents, as the record states it: a list the item
    /// leaves out is canonical and decodes empty (protobuf has no null), and the verification that
    /// reads it reports it as structure ("N.structure"); never a <see cref="NullReferenceException"/>.
    /// The same holds for a required message field the item leaves out: C_ξB (§3.3.4, G17), which
    /// every ballot carries, and a contest's contest data where the manifest declares b_Λ &gt; 0
    /// (§3.3.10). Neither carries a width option, so its absence is canonical (W2), and it decodes
    /// as null for <c>BallotStructure</c> to report (S10a refused a missing C_ξB at decode).
    /// A missing proof is not such a list: see <see cref="MissingProof_IsD1_AndTheCodecRefusesIt"/>.
    /// </summary>
    [Theory]
    [MemberData(nameof(MissingLists))]
    public void MissingList_DecodesEmpty_AndIsReportedByItsVerification(string missing, int verification, string expected)
    {
        var election = Shared.Value;
        var item = BallotMapper.ToItem(election.Ballots[0], election.Manifest);
        var ballot = item.EncryptedBallot;
        switch (missing)
        {
            case "contests": ballot.Contests.Clear(); break;
            case "a contest's fields": ballot.Contests[0].Fields.Clear(); break;
            case "the ballot nonce": ballot.EncryptedBallotNonce = null; break;
            case "a contest's contest data":
                Assert.True(election.Manifest.Contests[0].ContestDataBlocks > 0);
                ballot.Contests[0].ContestData = null;
                break;
        }

        var check = CanonicalProtobuf.Check(item.ToByteArray(), 0);
        Assert.True(check.IsCanonical, $"{missing}: {check.Rule} {check.Message}");

        var decoded = RecordItemCodec.DecodeBallot(item.ToByteArray(), election.Manifest, DeviceId);
        if (missing == "the ballot nonce")
        {
            Assert.Null(decoded.EncryptedBallotNonce);
        }

        var exception = Assert.Throws<VerificationFailedException>(() =>
        {
            switch (verification)
            {
                case 6: new SelectionEncryptionsWellFormedVerification().Verify(decoded, election.Record); break;
                default: new EncryptedTally(election.Manifest).AddBallot(decoded); break;
            }
        });

        Assert.Equal(expected, exception.SubSection);
    }

    /// <summary>
    /// A proof the item leaves out is a width failure, not an empty proof list: <c>limit_proof</c>
    /// and <c>range_proof</c> carry a <c>width_multiple</c> and are not omittable, so their absence is
    /// decode rule D1 and the codec refuses the item (<see cref="NonCanonicalEncodingException"/>)
    /// before any verification reads it. A proof of the wrong length that is still a whole number of
    /// pairs, or an omitted relation proof, is canonical and reaches its verification's proof count:
    /// see <see cref="ProofOfTheWrongCount_IsCanonical_AndFailsTheProofCount"/>. Only a null proof
    /// list or a null entry is reachable in memory alone
    /// (<c>SupplementalFieldVerificationTests.BallotWithANullProofListOrEntry_*</c>).
    /// </summary>
    [Theory]
    [InlineData("the limit proof")]
    [InlineData("a field's range proof")]
    public void MissingProof_IsD1_AndTheCodecRefusesIt(string missing)
    {
        var election = Shared.Value;
        var item = BallotMapper.ToItem(election.Ballots[0], election.Manifest);
        var contest = item.EncryptedBallot.Contests[0];
        switch (missing)
        {
            case "the limit proof": contest.LimitProof = ByteString.Empty; break;
            case "a field's range proof": contest.Fields[0].RangeProof = ByteString.Empty; break;
        }

        var check = CanonicalProtobuf.Check(item.ToByteArray(), 0);
        Assert.False(check.IsCanonical, missing);
        Assert.Equal("D1", check.Rule);
        Assert.Throws<NonCanonicalEncodingException>(() => RecordItemCodec.DecodeBallot(item.ToByteArray(), election.Manifest, DeviceId));
    }

    /// <summary>
    /// S10a's proof-count failures ("6", "7"), reached from canonical items: D1 requires only a
    /// whole number of (c, v) pairs, and the relation proofs are <c>(omittable)</c>, so a proof one
    /// pair short, or a relation proof the item leaves out although its field is declared (Q15, Q17),
    /// decodes and fails the count of the verification that reads it, after 6.A/7.A pass on its
    /// valid ciphertexts.
    /// </summary>
    [Theory]
    [InlineData("a field's range proof one pair short", 6, "6")]
    [InlineData("the limit proof one pair short", 7, "7")]
    [InlineData("the undervote difference proof left out", 7, "7")]
    [InlineData("the null-vote proof left out", 7, "7")]
    public void ProofOfTheWrongCount_IsCanonical_AndFailsTheProofCount(string tamper, int verification, string expected)
    {
        var election = Shared.Value;
        var item = BallotMapper.ToItem(election.Ballots[0], election.Manifest);
        var contest = item.EncryptedBallot.Contests[0];
        switch (tamper)
        {
            case "a field's range proof one pair short": contest.Fields[0].RangeProof = ByteString.CopyFrom(contest.Fields[0].RangeProof.Span[64..]); break;
            case "the limit proof one pair short": contest.LimitProof = ByteString.CopyFrom(contest.LimitProof.Span[64..]); break;
            case "the undervote difference proof left out": contest.UndervoteDifferenceProof = ByteString.Empty; break;
            case "the null-vote proof left out": contest.NullVoteProof = ByteString.Empty; break;
        }

        var check = CanonicalProtobuf.Check(item.ToByteArray(), 0);
        Assert.True(check.IsCanonical, $"{tamper}: {check.Rule} {check.Message}");

        var decoded = RecordItemCodec.DecodeBallot(item.ToByteArray(), election.Manifest, DeviceId);
        var exception = Assert.Throws<VerificationFailedException>(() =>
        {
            switch (verification)
            {
                case 6: new SelectionEncryptionsWellFormedVerification().Verify(decoded, election.Record); break;
                default: new AdherenceToVoteLimitsVerification().Verify(decoded, election.Record); break;
            }
        });

        Assert.Equal(expected, exception.SubSection);
    }

    /// <summary>The JSON projection's own refusals reach the codec as <see cref="NonCanonicalEncodingException"/>.</summary>
    [Theory]
    [InlineData("a member named twice")]
    [InlineData("an unknown member")]
    [InlineData("not JSON")]
    [InlineData("a byte order mark")]
    [InlineData("base64 without padding")]
    public void Json_TheProjectionRefuses_IsNonCanonical(string tamper)
    {
        var election = Shared.Value;
        string line = Encoding.UTF8.GetString(RecordItemCodec.EncodeBallotJson(election.Ballots[0], election.Manifest));
        string idB = JsonNode.Parse(line)!["encryptedBallot"]!["idB"]!.GetValue<string>();
        Assert.EndsWith("=", idB);
        byte[] tampered = tamper switch
        {
            "a member named twice" => Encoding.UTF8.GetBytes(line.Replace("\"idB\":", $"\"idB\":\"{idB}\",\"idB\":")),
            "an unknown member" => Encoding.UTF8.GetBytes(line.Replace("\"idB\":", "\"extra\":1,\"idB\":")),
            "not JSON" => Encoding.UTF8.GetBytes(line[..^1]),
            "a byte order mark" => [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes(line)],
            "base64 without padding" => Encoding.UTF8.GetBytes(line.Replace(idB, idB.TrimEnd('='))),
            _ => throw new ArgumentOutOfRangeException(nameof(tamper)),
        };

        Assert.Throws<NonCanonicalEncodingException>(() => RecordItemCodec.DecodeBallotJson(tampered, election.Manifest, DeviceId));
    }

    [Fact]
    public void Encode_RefusesAnUnrecordedBallot_AndToJsonRefusesNonCanonicalBytes()
    {
        var election = Shared.Value;
        var ballot = election.Ballots[0];
        var unrecorded = TallyDecryptionElection.WithWeight(ballot, 1, BallotStatus.Unrecorded);

        byte[] trailing = [.. RecordItemCodec.EncodeBallot(ballot, election.Manifest), 0];

        Assert.Throws<ArgumentException>(() => RecordItemCodec.EncodeBallot(unrecorded, election.Manifest));
        Assert.Throws<NonCanonicalEncodingException>(() => RecordItemCodec.ToJson(trailing));
    }

    // ---- the tally: the decryption bound from a published cast weight (S4 R1/F2, S10a) --------------

    /// <summary>The encrypted tally as a reader of its items decodes it, after <paramref name="edit"/>.</summary>
    private static RecordDecoded<EncryptedTally> ReadTally(Action<List<Pb.RecordItem>>? edit = null)
    {
        var election = Shared.Value;
        var items = TallyMapper.ToItems(election.Tally).Select(x => x.Clone()).ToList();
        edit?.Invoke(items);
        var read = items.Select(x => Pb.RecordItem.Parser.ParseFrom(x.ToByteArray())).ToList();
        return TallyMapper.FromItems(read[0].EncryptedTallyHeader, read.Skip(1).Select(x => x.EncryptedTallyContest), election.Manifest);
    }

    private static void SetCastWeight(List<Pb.RecordItem> items, ulong castWeight) => items[1].EncryptedTallyContest.CastWeight = castWeight;

    /// <summary>
    /// A tally read back from its items restores each option's decryption bound from its contest's
    /// published cast weight (here 3: one ballot of weight 1, one of weight 2), passes Verification 9
    /// and decrypts to the same counts.
    /// </summary>
    [Fact]
    public void EncryptedTally_ReadBack_RestoresTheDecryptionBound_PassesVerification9_AndDecrypts()
    {
        var election = Shared.Value;
        var read = ReadTally().Value!;

        Assert.Equal(3, read.Contests["contest-1"].CastWeight);
        Assert.Equal(election.Tally.Contests["contest-1"].Choices.Values.Select(x => x.MaximumCount), read.Contests["contest-1"].Choices.Values.Select(x => x.MaximumCount));
        Assert.All(read.Contests["contest-1"].Choices.Values, x => Assert.True(x.MaximumCount > 0));
        new BallotAggregationVerification().Verify(election.Ballots, election.Manifest, read);
        var decrypted = new TallyAdmin().Decrypt(Guardians, read, election.Record);
        Assert.Equal(election.Decrypted.Contests["contest-1"].Choices.Select(x => (x.Key, x.Value.VoteCount)), decrypted.Contests["contest-1"].Choices.Select(x => (x.Key, x.Value.VoteCount)));
    }

    /// <summary>
    /// A published cast weight other than the cast ballots' fails Verification 9 after 9.A/9.B; a
    /// smaller one would make the administrator's search miss the count (it fails closed), a larger
    /// one would widen it.
    /// </summary>
    [Theory]
    [InlineData(2UL)]
    [InlineData(4UL)]
    [InlineData(1_000_000_000UL)]
    public void EncryptedTally_WrongCastWeight_FailsVerification9Structure(ulong castWeight)
    {
        var election = Shared.Value;
        var read = ReadTally(items => SetCastWeight(items, castWeight)).Value!;

        var exception = Assert.Throws<VerificationFailedException>(() => new BallotAggregationVerification().Verify(election.Ballots, election.Manifest, read));

        Assert.Equal("9.structure", exception.SubSection);
        Assert.Contains("cast weight", exception.Message);
    }

    /// <summary>
    /// The search is bounded by the largest option or field bound: here the undervote difference count
    /// (L = 2) times the cast weight. A weight of 1 bounds it at 2, below the count 3 of choice-1.
    /// </summary>
    [Fact]
    public void EncryptedTally_TooSmallCastWeight_DecryptionFailsClosed()
    {
        var election = Shared.Value;
        var read = ReadTally(items => SetCastWeight(items, 1)).Value!;
        Assert.Equal(2, read.Contests["contest-1"].Choices.Values.Max(x => x.MaximumCount));

        Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().Decrypt(Guardians, read, election.Record));
    }

    /// <summary>
    /// A tally decrypted without Verification 9 first (the documented misuse) with a forged weight is
    /// refused with a typed error naming the search limit, never an untyped exception from the
    /// discrete-log search.
    /// </summary>
    [Theory]
    [InlineData(2UL * int.MaxValue)]
    [InlineData((ulong)long.MaxValue)]
    public void EncryptedTally_ForgedCastWeightDecryptedWithoutVerification9_IsRefusedWithTallyDecryptionException(ulong castWeight)
    {
        var election = Shared.Value;
        var read = ReadTally(items => SetCastWeight(items, castWeight)).Value!;
        Assert.True(read.Contests["contest-1"].Choices.Values.Max(x => x.MaximumCount) > int.MaxValue);

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().Decrypt(Guardians, read, election.Record));

        Assert.Contains("beyond the discrete-log search", exception.Message);
    }

    /// <summary>
    /// S10a review round 1: MaximumCount saturates rather than wrapping. Before, a weight of
    /// long.MaxValue with MaximumValue 2 gave -2, and 2^62 gave long.MinValue; a negative bound then
    /// reached BoundedDiscreteLog as an untyped ArgumentOutOfRangeException.
    /// </summary>
    [Theory]
    [InlineData(long.MaxValue, 2, long.MaxValue)]
    [InlineData(4611686018427387904L, 2, long.MaxValue)]
    [InlineData(4611686018427387903L, 2, 9223372036854775806L)]
    [InlineData(long.MaxValue, 0, 0L)]
    [InlineData(3L, 5, 15L)]
    public void MaximumCount_Saturates_InsteadOfWrapping(long castWeight, int maximumValue, long expected)
    {
        var contest = new EncryptedTally.EncryptedAggregateContest { ContestId = "contest-1", Choices = [], CastWeight = castWeight };
        var choice = new EncryptedTally.EncryptedAggregateChoice { ChoiceId = "choice-1", MaximumValue = maximumValue, Contest = contest, A = new IntegerModP(1), B = new IntegerModP(1) };

        Assert.Equal(expected, choice.MaximumCount);
    }

    /// <summary>With a saturated bound (a weight set in process), decryption still fails with the typed error.</summary>
    [Fact]
    public void EncryptedTally_SaturatedBound_DecryptionRefusesWithTallyDecryptionException()
    {
        var election = Shared.Value;
        var read = ReadTally().Value!;
        read.Contests["contest-1"].CastWeight = long.MaxValue;
        Assert.All(read.Contests["contest-1"].Choices.Values.Where(x => x.MaximumValue > 0), x => Assert.Equal(long.MaxValue, x.MaximumCount));

        Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().Decrypt(Guardians, read, election.Record));
    }

    /// <summary>The items' fields are kept as read, so Verification 9 still sees a field the manifest lacks.</summary>
    [Fact]
    public void EncryptedTally_ExtraField_DecodesAndFailsVerification9Structure()
    {
        var election = Shared.Value;
        var decoded = ReadTally(items =>
        {
            var contest = items[1].EncryptedTallyContest;
            contest.Fields = ByteString.CopyFrom([.. contest.Fields.Span, .. contest.Fields.Span[..1024]]);
        });

        Assert.Equal("9.structure", Assert.Throws<VerificationFailedException>(() => new BallotAggregationVerification().Verify(election.Ballots, election.Manifest, decoded.Value!)).SubSection);
    }

    /// <summary>A published count other than the decrypted one decodes as published, so T = K^t fails for it: 10.C.</summary>
    [Fact]
    public void DecryptedTally_AnotherCount_DecodesAndFails10C()
    {
        var election = Shared.Value;
        var items = TallyMapper.ToItems(election.Decrypted).Select(x => x.Clone()).ToList();
        items[0].DecryptedTallyContest.Fields[0].Tally += 1;

        var read = TallyMapper.FromItems(items.Select(x => Pb.RecordItem.Parser.ParseFrom(x.ToByteArray()).DecryptedTallyContest));

        Assert.Empty(read.Findings);
        Assert.Equal("10.C", Assert.Throws<VerificationFailedException>(() => new TallyDecryptionVerification().Verify(election.Record, election.Tally, read.Value!)).SubSection);
    }
}
