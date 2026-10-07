using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Testing.Common;
using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;
using static ElectionGuard.Core.Serialization.ProtobufEncryptedBallotSerializer;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// G23: published values decode strictly (§5.1.1, §5.1.2, eq. 32). An element of Z_p is exactly 512
/// big-endian bytes below p, an element of Z_q exactly 32 bytes below q, and id_B exactly 32 bytes.
/// The reducing constructors would accept p as 0, q as 0, or a padded encoding as its value, which
/// leaves the 0 &lt;= x &lt; p and 0 &lt;= x &lt; q halves of 2.A/2.B, 6.A-6.C and 7.A-7.C unenforceable
/// on anything read from a record. A non-canonical encoding is a
/// <see cref="NonCanonicalEncodingException"/> at decode time.
/// </summary>
public class StrictDecodingTests
{
    public StrictDecodingTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static byte[] Encode(BigInteger value, int length) => value.ToBigEndianPadded(length);

    [Fact]
    public void IntegerModP_FromCanonicalBytes_AcceptsExactlyZeroToPMinusOne()
    {
        BigInteger p = EGParameters.P;

        Assert.Equal(new IntegerModP(p - 1), IntegerModP.FromCanonicalBytes(Encode(p - 1, 512)));
        Assert.Equal(new IntegerModP(0), IntegerModP.FromCanonicalBytes(new byte[512]));
        Assert.Equal(new IntegerModP(12345), IntegerModP.FromCanonicalBytes(Encode(12345, 512)));
    }

    [Fact]
    public void IntegerModP_FromCanonicalBytes_RejectsPAndAbove()
    {
        BigInteger p = EGParameters.P;

        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModP.FromCanonicalBytes(Encode(p, 512)));
        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModP.FromCanonicalBytes(Encode(p + 1, 512)));
        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModP.FromCanonicalBytes(Enumerable.Repeat((byte)0xFF, 512).ToArray()));

        // What the reducing constructor does with the same bytes: p decodes as 0.
        Assert.Equal(new IntegerModP(0), new IntegerModP(Encode(p, 512)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32)]
    [InlineData(511)]
    [InlineData(513)]
    public void IntegerModP_FromCanonicalBytes_RejectsAnyOtherLength(int length)
    {
        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModP.FromCanonicalBytes(new byte[length]));
    }

    [Fact]
    public void IntegerModQ_FromCanonicalBytes_AcceptsExactlyZeroToQMinusOne()
    {
        BigInteger q = EGParameters.Q;

        Assert.Equal(new IntegerModQ(q - 1), IntegerModQ.FromCanonicalBytes(Encode(q - 1, 32)));
        Assert.Equal(new IntegerModQ(0), IntegerModQ.FromCanonicalBytes(new byte[32]));
    }

    [Fact]
    public void IntegerModQ_FromCanonicalBytes_RejectsQAndAbove()
    {
        BigInteger q = EGParameters.Q;

        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModQ.FromCanonicalBytes(Encode(q, 32)));
        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModQ.FromCanonicalBytes(Encode(q + 188, 32)));

        // What the reducing constructor does with the same bytes: q decodes as 0.
        Assert.Equal(new IntegerModQ(0), new IntegerModQ(Encode(q, 32)));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(512)]
    public void IntegerModQ_FromCanonicalBytes_RejectsAnyOtherLength(int length)
    {
        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModQ.FromCanonicalBytes(Encode(5, length)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void SelectionEncryptionIdentifier_FromCanonicalBytes_RejectsAnyLengthButThirtyTwo(int length)
    {
        Assert.Throws<NonCanonicalEncodingException>(() => SelectionEncryptionIdentifier.FromCanonicalBytes(new byte[length]));
    }

    /// <summary>
    /// A missing protobuf field decodes as a null array. That is a length-0 encoding like any other,
    /// so it is a <see cref="NonCanonicalEncodingException"/>, as it is for IntegerModP and IntegerModQ.
    /// </summary>
    [Fact]
    public void SelectionEncryptionIdentifier_FromCanonicalBytes_RejectsNull()
    {
        byte[]? missing = null;

        Assert.Throws<NonCanonicalEncodingException>(() => SelectionEncryptionIdentifier.FromCanonicalBytes(missing));
    }

    [Fact]
    public void SelectionEncryptionIdentifier_FromCanonicalBytes_AcceptsThirtyTwoBytes()
    {
        byte[] bytes = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

        Assert.Equal(new SelectionEncryptionIdentifier(bytes), SelectionEncryptionIdentifier.FromCanonicalBytes(bytes));
    }

    // The serializers.

    /// <summary>
    /// A ballot that has every strictly decoded site, contest data included: the encryptor emits
    /// <see cref="EncryptedData"/> only for a contest that has some.
    /// </summary>
    private static readonly Lazy<EncryptedBallot> Ballot = new(() =>
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, "device-1");
        var ballot = ElectionFixtureBuilder.CreateBallot(
            manifest, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 }, contestData: "strict decoding");
        return ElectionFixtureBuilder.CreateEncryptedBallot(records.EncryptionRecord, "device-1", deviceHash, ballot);
    });

    /// <summary>Each non-canonical encoding, applied to a ballot's alpha, a response, or id_B.</summary>
    public static TheoryData<string> JsonTamperings() => new() { "alpha padded to 513 bytes", "alpha = p", "response = q", "response padded to 33 bytes", "id_B of 31 bytes", "contest data C0 = p" };

    private static byte[] Tamper(string tampering, byte[] original) => tampering switch
    {
        "alpha padded to 513 bytes" or "response padded to 33 bytes" => [0, .. original],
        "alpha = p" or "contest data C0 = p" => Encode(EGParameters.P, 512),
        "response = q" => Encode(EGParameters.Q, 32),
        "id_B of 31 bytes" => original[1..],
        _ => throw new ArgumentOutOfRangeException(nameof(tampering)),
    };

    /// <summary>
    /// The JSON path decodes through one converter per type (IntegerModP, IntegerModQ, id_B), and the
    /// converter applies to every property of its type, so one site per converter covers them all.
    /// </summary>
    [Theory]
    [MemberData(nameof(JsonTamperings))]
    public void Json_NonCanonicalEncoding_IsRejected(string tampering)
    {
        var serializer = new JsonEncryptedBallotSerializer();
        using var original = new MemoryStream();
        serializer.Serialize(original, Ballot.Value);
        var json = JsonNode.Parse(original.ToArray())!;

        JsonNode owner = tampering switch
        {
            "id_B of 31 bytes" => json,
            "alpha padded to 513 bytes" or "alpha = p" => json["contests"]![0]!["choices"]![0]!,
            "contest data C0 = p" => json["contests"]![0]!["contestData"]!,
            _ => json["contests"]![0]!["choices"]![0]!["proof"]![0]!,
        };
        string property = tampering switch
        {
            "id_B of 31 bytes" => "selectionEncryptionIdentifier",
            "alpha padded to 513 bytes" or "alpha = p" => "alpha",
            "contest data C0 = p" => "c0",
            _ => "v",
        };
        byte[] bytes = Convert.FromBase64String(owner[property]!.GetValue<string>());
        owner[property] = Convert.ToBase64String(Tamper(tampering, bytes));

        // The untampered document decodes.
        Assert.NotNull(serializer.Deserialize(new MemoryStream(original.ToArray())));

        using var tampered = new MemoryStream(Encoding.UTF8.GetBytes(json.ToJsonString()));
        Assert.Throws<NonCanonicalEncodingException>(() => serializer.Deserialize(tampered));
    }

    // The protobuf path maps every field by hand, so each mapped site is tampered on its own: a site
    // that slipped back to a reducing constructor would decode p or q as 0 and pass.

    private static byte[] NotBelowP => Encode(EGParameters.P, 512);

    private static byte[] NotBelowQ => Encode(EGParameters.Q, 32);

    private static ProtobufChallengeResponsePair[] WithFirstProof(ProtobufChallengeResponsePair[] proofs, Func<ProtobufChallengeResponsePair, ProtobufChallengeResponsePair> change)
    {
        var copy = (ProtobufChallengeResponsePair[])proofs.Clone();
        copy[0] = change(copy[0]);
        return copy;
    }

    /// <summary>
    /// One component of an encrypted value made non-canonical: alpha or beta set to p, or its first
    /// proof's challenge or response set to q. `with` keeps the runtime type, so a selection stays a
    /// selection.
    /// </summary>
    private static ProtobufEncryptedValueWithProofs WithComponent(ProtobufEncryptedValueWithProofs value, string component) => component switch
    {
        "alpha" => value with { Alpha = NotBelowP },
        "beta" => value with { Beta = NotBelowP },
        "proof challenge" => value with { Proofs = WithFirstProof(value.Proofs, p => p with { Challenge = NotBelowQ }) },
        "proof response" => value with { Proofs = WithFirstProof(value.Proofs, p => p with { Response = NotBelowQ }) },
        _ => throw new ArgumentOutOfRangeException(nameof(component)),
    };

    /// <summary>The contest with its supplemental field of <paramref name="kind"/> made non-canonical at <paramref name="component"/>.</summary>
    private static ProtobufEncryptedContest WithField(ProtobufEncryptedContest contest, SupplementalFieldKind kind, string component)
    {
        var id = ElectionFixtureBuilder.SupplementalFieldId(kind);
        return contest with
        {
            SupplementalFields = contest.SupplementalFields!
                .Select(field => field.FieldId == id ? (ProtobufEncryptedSupplementalField)WithComponent(field, component) : field)
                .ToList(),
        };
    }

    private static ProtobufEncryptedBallot WithFirstContest(ProtobufEncryptedBallot dto, Func<ProtobufEncryptedContest, ProtobufEncryptedContest> change)
    {
        dto.Contests[0] = change(dto.Contests[0]);
        return dto;
    }

    private static ProtobufEncryptedBallot WithFirstSelection(ProtobufEncryptedBallot dto, Func<ProtobufEncryptedSelection, ProtobufEncryptedSelection> change) =>
        WithFirstContest(dto, c => c with { Choices = [change(c.Choices[0]), .. c.Choices.Skip(1)] });

    private static ProtobufEncryptedBallot WithIdentifier(ProtobufEncryptedBallot dto, byte[]? identifier) => new()
    {
        Id = dto.Id,
        SelectionEncryptionIdentifier = identifier!,
        SelectionEncryptionIdentifierHash = dto.SelectionEncryptionIdentifierHash,
        BallotStyleId = dto.BallotStyleId,
        DeviceId = dto.DeviceId,
        Contests = dto.Contests,
        ConfirmationCode = dto.ConfirmationCode,
        Weight = dto.Weight,
        Status = dto.Status,
    };

    private static ProtobufEncryptedData WithContestData(ProtobufEncryptedData data, byte[]? challenge = null, byte[]? response = null, byte[]? c0 = null, Func<byte[], byte[]?>? c1 = null) => new()
    {
        C0 = c0 ?? data.C0,
        C1 = c1 is null ? data.C1 : c1(data.C1)!,
        Challenge = challenge ?? data.Challenge,
        Response = response ?? data.Response,
    };

    /// <summary>Every strictly decoded site of the protobuf mapping, each made non-canonical.</summary>
    private static readonly Dictionary<string, Func<ProtobufEncryptedBallot, ProtobufEncryptedBallot>> ProtobufSites = BuildProtobufSites();

    private static Dictionary<string, Func<ProtobufEncryptedBallot, ProtobufEncryptedBallot>> BuildProtobufSites()
    {
        var sites = new Dictionary<string, Func<ProtobufEncryptedBallot, ProtobufEncryptedBallot>>
        {
            ["id_B of 31 bytes"] = dto => WithIdentifier(dto, dto.SelectionEncryptionIdentifier[1..]),
            // Left out of the wire entirely: protobuf-net leaves the array null.
            ["id_B missing"] = dto => WithIdentifier(dto, null),
            ["selection alpha padded to 513 bytes"] = dto => WithFirstSelection(dto, s => s with { Alpha = [0, .. s.Alpha] }),
            ["selection proof response padded to 33 bytes"] = dto => WithFirstSelection(dto, s => s with { Proofs = WithFirstProof(s.Proofs, p => p with { Response = [0, .. p.Response] }) }),
            ["contest proof challenge = q"] = dto => WithFirstContest(dto, c => c with { Proofs = WithFirstProof(c.Proofs, p => p with { Challenge = NotBelowQ }) }),
            ["contest proof response = q"] = dto => WithFirstContest(dto, c => c with { Proofs = WithFirstProof(c.Proofs, p => p with { Response = NotBelowQ }) }),
            ["contest data challenge = q"] = dto => WithFirstContest(dto, c => c with { ContestData = WithContestData(c.ContestData!, challenge: NotBelowQ) }),
            ["contest data response = q"] = dto => WithFirstContest(dto, c => c with { ContestData = WithContestData(c.ContestData!, response: NotBelowQ) }),
            // S6: C_0 is an element of Z_p, decoded strictly; C_1 is a whole, nonzero number of
            // 32-byte blocks (BallotStructure then requires exactly 32·b_Λ).
            ["contest data C0 = p"] = dto => WithFirstContest(dto, c => c with { ContestData = WithContestData(c.ContestData!, c0: NotBelowP) }),
            ["contest data C0 padded to 513 bytes"] = dto => WithFirstContest(dto, c => c with { ContestData = WithContestData(c.ContestData!, c0: [0, .. c.ContestData!.C0]) }),
            ["contest data C1 of 31 bytes"] = dto => WithFirstContest(dto, c => c with { ContestData = WithContestData(c.ContestData!, c1: x => x[1..32]) }),
            ["contest data C1 one byte over a block"] = dto => WithFirstContest(dto, c => c with { ContestData = WithContestData(c.ContestData!, c1: x => [.. x, 0]) }),
            ["contest data C1 missing"] = dto => WithFirstContest(dto, c => c with { ContestData = WithContestData(c.ContestData!, c1: _ => null) }),
            ["undervote difference proof challenge = q"] = dto => WithFirstContest(dto, c => c with { UndervoteDifferenceProof = WithFirstProof(c.UndervoteDifferenceProof!, p => p with { Challenge = NotBelowQ }) }),
            ["undervote difference proof response = q"] = dto => WithFirstContest(dto, c => c with { UndervoteDifferenceProof = WithFirstProof(c.UndervoteDifferenceProof!, p => p with { Response = NotBelowQ }) }),
            ["null-vote proof challenge = q"] = dto => WithFirstContest(dto, c => c with { NullVoteProof = WithFirstProof(c.NullVoteProof!, p => p with { Challenge = NotBelowQ }) }),
            ["null-vote proof response = q"] = dto => WithFirstContest(dto, c => c with { NullVoteProof = WithFirstProof(c.NullVoteProof!, p => p with { Response = NotBelowQ }) }),
            ["supplemental field alpha padded to 513 bytes"] = dto => WithFirstContest(dto, c => c with
            {
                SupplementalFields = [c.SupplementalFields![0] with { Alpha = [0, .. c.SupplementalFields[0].Alpha] }, .. c.SupplementalFields.Skip(1)],
            }),
        };

        foreach (var component in new[] { "alpha", "beta", "proof challenge", "proof response" })
        {
            string bound = component is "alpha" or "beta" ? "p" : "q";
            sites[$"selection {component} = {bound}"] = dto => WithFirstSelection(dto, s => (ProtobufEncryptedSelection)WithComponent(s, component));
            sites[$"overvote {component} = {bound}"] = dto => WithFirstContest(dto, c => WithField(c, SupplementalFieldKind.OvervoteIndicator, component));
            sites[$"nullvote {component} = {bound}"] = dto => WithFirstContest(dto, c => WithField(c, SupplementalFieldKind.NullVoteIndicator, component));
            sites[$"undervote {component} = {bound}"] = dto => WithFirstContest(dto, c => WithField(c, SupplementalFieldKind.UndervoteDifferenceCount, component));
            sites[$"undervote indicator {component} = {bound}"] = dto => WithFirstContest(dto, c => WithField(c, SupplementalFieldKind.UndervoteIndicator, component));
            sites[$"write-in {component} = {bound}"] = dto => WithFirstContest(dto, c => WithField(c, SupplementalFieldKind.WriteInCount, component));
        }

        return sites;
    }

    public static TheoryData<string> ProtobufTamperings()
    {
        var data = new TheoryData<string>();
        foreach (var site in ProtobufSites.Keys)
        {
            data.Add(site);
        }

        return data;
    }

    private static ProtobufEncryptedBallot ReadDto(MemoryStream encoded)
    {
        encoded.Position = 0;
        return ProtoBuf.Serializer.Deserialize<ProtobufEncryptedBallot>(encoded);
    }

    [Theory]
    [MemberData(nameof(ProtobufTamperings))]
    public void Protobuf_NonCanonicalEncoding_IsRejected(string site)
    {
        var serializer = new ProtobufEncryptedBallotSerializer();
        using var original = new MemoryStream();
        serializer.Serialize(original, Ballot.Value);

        // Every site exists on this ballot, so no tampering below is a no-op.
        var contest = ReadDto(original).Contests[0];
        Assert.NotNull(contest.ContestData);
        Assert.NotEmpty(contest.Choices[0].Proofs);
        Assert.NotEmpty(contest.Proofs);
        Assert.All(
            ElectionFixtureBuilder.AllSupplementalFields
                .Select(kind => contest.SupplementalFields!.Single(field => field.FieldId == ElectionFixtureBuilder.SupplementalFieldId(kind))),
            value => Assert.NotEmpty(value.Proofs));
        Assert.NotEmpty(contest.UndervoteDifferenceProof!);
        Assert.NotEmpty(contest.NullVoteProof!);

        // The untampered encoding decodes.
        original.Position = 0;
        Assert.NotNull(serializer.Deserialize(original));

        using var tampered = new MemoryStream();
        ProtoBuf.Serializer.Serialize(tampered, ProtobufSites[site](ReadDto(original)));
        if (site == "id_B missing")
        {
            // What the decoder is handed for a field absent from the wire: null, not an empty array.
            Assert.Null(ReadDto(tampered).SelectionEncryptionIdentifier);
        }

        tampered.Position = 0;
        Assert.Throws<NonCanonicalEncodingException>(() => serializer.Deserialize(tampered));
    }
}
