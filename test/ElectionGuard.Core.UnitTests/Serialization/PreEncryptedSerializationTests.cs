using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.UnitTests.PreEncryption;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Testing.Common;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using static ElectionGuard.Core.Serialization.ProtobufEncryptedBallotSerializer;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// The records of pre-encrypted ballots on the wire (§4.4): a cast ballot's record travels with the
/// encrypted ballots (JSON and protobuf, field 12 flagged by 13), an uncast one and a pre-encrypted
/// ballot as JSON. Round trips keep everything the verifications read, no nonce of a cast ballot is
/// written, regular ballots encode as before, and the decoders refuse malformed values.
/// </summary>
public class PreEncryptedSerializationTests
{
    public PreEncryptedSerializationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static PreEncryptedElection Election => PreEncryptedElection.Get();

    private static byte[] Write(IEncryptedBallotSerializer serializer, EncryptedBallot ballot)
    {
        using var stream = new MemoryStream();
        serializer.Serialize(stream, ballot);
        return stream.ToArray();
    }

    private static EncryptedBallot Read(IEncryptedBallotSerializer serializer, byte[] bytes)
    {
        using var stream = new MemoryStream(bytes);
        return serializer.Deserialize(stream)!;
    }

    public static IEnumerable<object[]> Serializers() =>
    [
        [new JsonEncryptedBallotSerializer()],
        [new ProtobufEncryptedBallotSerializer()],
    ];

    [Theory]
    [MemberData(nameof(Serializers))]
    public void CastRecord_RoundTrips_AndVerifies(IEncryptedBallotSerializer serializer)
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [2], [1, 3]);

        var read = Read(serializer, Write(serializer, cast));

        Assert.True(read.IsPreEncrypted);
        Assert.Equal(BallotStatus.Cast, read.Status);
        for (int i = 0; i < cast.PreEncryptedContests!.Count; i++)
        {
            var expected = cast.PreEncryptedContests[i];
            var actual = read.PreEncryptedContests![i];
            Assert.Equal(expected.ContestId, actual.ContestId);
            Assert.Equal(expected.SelectionHashes, actual.SelectionHashes);
            Assert.Equal(expected.SelectedVectors.Select(x => (x.SelectionHash, x.ShortCode)), actual.SelectedVectors.Select(x => (x.SelectionHash, x.ShortCode)));
            Assert.Equal(expected.SelectedVectors.SelectMany(x => x.Vector).Select(x => (x.Alpha, x.Beta)), actual.SelectedVectors.SelectMany(x => x.Vector).Select(x => (x.Alpha, x.Beta)));
            Assert.All(actual.SelectedVectors.SelectMany(x => x.Vector), x => Assert.Null(x.EncryptionNonce));
        }

        Assert.All(read.Contests.SelectMany(x => x.Choices), x => Assert.Null(x.EncryptionNonce));
        new SelectionEncryptionsWellFormedVerification().Verify(read, election.Record);
        new AdherenceToVoteLimitsVerification().Verify(read, election.Record);
        new SelectionVectorAccumulationVerification().Verify(read, election.Record);
        new PreEncryptedConfirmationCodeVerification().Verify(read, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(read, election.Record);
    }

    /// <summary>The summed nonces of a cast ballot's combined vector would decrypt the vote: no encoder writes them.</summary>
    [Fact]
    public void CastRecord_Json_WritesNoNonce()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [2], [1, 3]);
        Assert.NotNull(cast.Contests[0].Choices[0].EncryptionNonce);

        string json = Encoding.UTF8.GetString(Write(new JsonEncryptedBallotSerializer(), cast));

        Assert.Contains("\"preEncryptedContests\"", json);
        Assert.DoesNotContain("nonce\"", json.Replace("\"encryptedBallotNonce\"", ""), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A regular ballot carries no pre-encryption data: JSON writes no property and protobuf no field 12 or 13.</summary>
    [Fact]
    public void RegularBallot_EncodesNoPreEncryptionData()
    {
        var election = Election;
        var deviceHash = new VotingDeviceInformationHash(election.Record.ExtendedBaseHash, "regular-device");
        var regular = ElectionFixtureBuilder.CreateEncryptedBallot(election.Record, "regular-device", deviceHash, election.Selections("regular-1", [1], [2]));

        string json = Encoding.UTF8.GetString(Write(new JsonEncryptedBallotSerializer(), regular));
        var fromProtobuf = Read(new ProtobufEncryptedBallotSerializer(), Write(new ProtobufEncryptedBallotSerializer(), regular));

        Assert.DoesNotContain("preEncrypted", json, StringComparison.OrdinalIgnoreCase);
        Assert.False(Read(new JsonEncryptedBallotSerializer(), Encoding.UTF8.GetBytes(json)).IsPreEncrypted);
        Assert.False(fromProtobuf.IsPreEncrypted);
        Assert.Null(fromProtobuf.PreEncryptedContests);
    }

    [Theory]
    [MemberData(nameof(Serializers))]
    public void CastRecord_ShortSelectionHash_IsRefused(IEncryptedBallotSerializer serializer)
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [2], [1, 3]);
        var contests = cast.PreEncryptedContests!.ToList();
        contests[0] = contests[0] with { SelectionHashes = [new SelectionHash(new byte[31]), .. contests[0].SelectionHashes.Skip(1)] };
        var malformed = new EncryptedBallot
        {
            Id = cast.Id,
            BallotStyleId = cast.BallotStyleId,
            DeviceId = cast.DeviceId,
            SelectionEncryptionIdentifier = cast.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = cast.SelectionEncryptionIdentifierHash,
            Contests = cast.Contests,
            ConfirmationCode = cast.ConfirmationCode,
            ChainingField = cast.ChainingField,
            EncryptedBallotNonce = cast.EncryptedBallotNonce,
            Weight = cast.Weight,
            Status = cast.Status,
            PreEncryptedContests = contests,
        };

        var bytes = Write(serializer, malformed);

        Assert.Throws<NonCanonicalEncodingException>(() => Read(serializer, bytes));
    }

    // --- Strict decoding of a cast record's pre-encryption data (protobuf DTO and JSON) ------------

    private static byte[] NotBelowP => EGParameters.P.ToBigEndianPadded(512);

    private static ProtobufEncryptedBallot ReadDto(byte[] bytes) => ProtoBuf.Serializer.Deserialize<ProtobufEncryptedBallot>(new MemoryStream(bytes));

    private static byte[] WriteDto(ProtobufEncryptedBallot dto)
    {
        using var stream = new MemoryStream();
        ProtoBuf.Serializer.Serialize(stream, dto);
        return stream.ToArray();
    }

    /// <summary>The ballot with its field 12 replaced by <paramref name="contests"/> and its field-13 flag by <paramref name="isPreEncrypted"/>.</summary>
    private static ProtobufEncryptedBallot WithPreEncryption(ProtobufEncryptedBallot dto, List<ProtobufPreEncryptedCastContest>? contests, bool isPreEncrypted) => new()
    {
        Id = dto.Id,
        SelectionEncryptionIdentifier = dto.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = dto.SelectionEncryptionIdentifierHash,
        BallotStyleId = dto.BallotStyleId,
        DeviceId = dto.DeviceId,
        Contests = dto.Contests,
        ConfirmationCode = dto.ConfirmationCode,
        Weight = dto.Weight,
        Status = dto.Status,
        EncryptedBallotNonce = dto.EncryptedBallotNonce,
        ChainingField = dto.ChainingField,
        PreEncryptedContests = contests,
        IsPreEncrypted = isPreEncrypted,
    };

    /// <summary>The ballot with the first selected vector of its first contest replaced by <paramref name="change"/>'s result.</summary>
    private static ProtobufEncryptedBallot WithFirstSelectedVector(ProtobufEncryptedBallot dto, Func<ProtobufPreEncryptedCastSelection, ProtobufPreEncryptedCastSelection> change)
    {
        var contests = dto.PreEncryptedContests!.ToList();
        var first = contests[0];
        contests[0] = new ProtobufPreEncryptedCastContest
        {
            ContestId = first.ContestId,
            SelectionHashes = first.SelectionHashes,
            SelectedVectors = [change(first.SelectedVectors![0]), .. first.SelectedVectors.Skip(1)],
        };
        return WithPreEncryption(dto, contests, dto.IsPreEncrypted);
    }

    public static IEnumerable<object[]> MalformedProtobufCastRecords()
    {
        // Field 12 without the field-13 flag: an encoder that forgot the flag would otherwise decode
        // a cast record as a regular ballot, which Verification 8 then fails far from the cause.
        yield return ["pre-encryption data not flagged", new Func<ProtobufEncryptedBallot, ProtobufEncryptedBallot>(dto => WithPreEncryption(dto, dto.PreEncryptedContests, isPreEncrypted: false))];
        yield return ["a selected vector with no short code", new Func<ProtobufEncryptedBallot, ProtobufEncryptedBallot>(dto => WithFirstSelectedVector(dto, v => new ProtobufPreEncryptedCastSelection { Vector = v.Vector, SelectionHash = v.SelectionHash, ShortCode = null }))];
        yield return ["alpha = p in a selected vector", new Func<ProtobufEncryptedBallot, ProtobufEncryptedBallot>(dto => WithFirstSelectedVector(dto, v => new ProtobufPreEncryptedCastSelection { Vector = [new ProtobufCiphertext { Alpha = NotBelowP, Beta = v.Vector![0].Beta }, .. v.Vector.Skip(1)], SelectionHash = v.SelectionHash, ShortCode = v.ShortCode }))];
        yield return ["beta = p in a selected vector", new Func<ProtobufEncryptedBallot, ProtobufEncryptedBallot>(dto => WithFirstSelectedVector(dto, v => new ProtobufPreEncryptedCastSelection { Vector = [new ProtobufCiphertext { Alpha = v.Vector![0].Alpha, Beta = NotBelowP }, .. v.Vector.Skip(1)], SelectionHash = v.SelectionHash, ShortCode = v.ShortCode }))];
    }

    [Theory]
    [MemberData(nameof(MalformedProtobufCastRecords))]
    public void CastRecord_Protobuf_MalformedPreEncryptionData_IsRefused(string description, Func<ProtobufEncryptedBallot, ProtobufEncryptedBallot> malform)
    {
        _ = description;
        var serializer = new ProtobufEncryptedBallotSerializer();
        var (_, cast) = Election.Cast("cast-1", [2], [1, 3]);
        byte[] original = Write(serializer, cast);
        var dto = ReadDto(original);
        Assert.True(dto.IsPreEncrypted);
        Assert.NotEmpty(dto.PreEncryptedContests!);

        // The untampered DTO, written back, decodes.
        Assert.True(Read(serializer, WriteDto(dto)).IsPreEncrypted);

        byte[] tampered = WriteDto(malform(dto));

        Assert.Throws<NonCanonicalEncodingException>(() => Read(serializer, tampered));
    }

    public static IEnumerable<object[]> MalformedCastJson()
    {
        yield return ["no short code", new Func<JsonNode, JsonNode>(n => { n["preEncryptedContests"]![0]!["selectedVectors"]![0]!.AsObject().Remove("shortCode"); return n; })];
        yield return ["a null short code", new Func<JsonNode, JsonNode>(n => { n["preEncryptedContests"]![0]!["selectedVectors"]![0]!["shortCode"] = null; return n; })];
        yield return ["alpha = p in a selected vector", new Func<JsonNode, JsonNode>(n => { n["preEncryptedContests"]![0]!["selectedVectors"]![0]!["vector"]![0]!["alpha"] = Convert.ToBase64String(NotBelowP); return n; })];
        yield return ["beta = p in a selected vector", new Func<JsonNode, JsonNode>(n => { n["preEncryptedContests"]![0]!["selectedVectors"]![0]!["vector"]![0]!["beta"] = Convert.ToBase64String(NotBelowP); return n; })];
    }

    [Theory]
    [MemberData(nameof(MalformedCastJson))]
    public void CastRecord_Json_MalformedPreEncryptionData_IsRefused(string description, Func<JsonNode, JsonNode> malform)
    {
        var serializer = new JsonEncryptedBallotSerializer();
        var (_, cast) = Election.Cast("cast-1", [2], [1, 3]);
        var node = JsonNode.Parse(Write(serializer, cast))!;
        Assert.NotNull(node["preEncryptedContests"]![0]!["selectedVectors"]![0]!["shortCode"]);

        var bytes = Encoding.UTF8.GetBytes(malform(node).ToJsonString());

        var exception = Record.Exception(() => Read(serializer, bytes));
        Assert.True(
            description.Contains("= p") ? exception is NonCanonicalEncodingException : exception is JsonException,
            $"{description}: {exception}");
    }

    private static byte[] WriteUncast(PreEncryptedUncastBallot uncast)
    {
        using var stream = new MemoryStream();
        new JsonPreEncryptedBallotSerializer().Serialize(stream, uncast);
        return stream.ToArray();
    }

    private static PreEncryptedUncastBallot ReadUncast(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes);
        return new JsonPreEncryptedBallotSerializer().DeserializeUncastBallot(stream)!;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UncastRecord_Json_RoundTrips_AndVerifies(bool releaseBallotNonce)
    {
        var election = Election;
        var uncast = election.Uncast("uncast-1", releaseBallotNonce);

        var read = ReadUncast(WriteUncast(uncast));

        Assert.Equal(releaseBallotNonce, read.BallotNonce is not null);
        if (releaseBallotNonce)
        {
            Assert.Equal(uncast.BallotNonce!.Value.ToByteArray(), read.BallotNonce!.Value.ToByteArray());
        }

        Assert.Equal(uncast.Contests.SelectMany(c => c.Selections.SelectMany(s => s.Nonces)), read.Contests.SelectMany(c => c.Selections.SelectMany(s => s.Nonces)));
        new PreEncryptedConfirmationCodeVerification().Verify(read.Ballot, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(read.Ballot, election.Record);
        new UncastBallotEncryptionVerification().Verify(read, election.Record);
        new UncastBallotContentVerification().Verify(election.Manifest, read);
    }

    [Fact]
    public void PreEncryptedBallot_Json_RoundTrips_AndVerifies()
    {
        var election = Election;
        var ballot = election.PreEncrypt("printed-1");

        using var stream = new MemoryStream();
        new JsonPreEncryptedBallotSerializer().Serialize(stream, ballot);
        stream.Position = 0;
        var read = new JsonPreEncryptedBallotSerializer().DeserializeBallot(stream)!;

        Assert.All(read.Contests.SelectMany(c => c.Selections).SelectMany(s => s.Vector), x => Assert.Null(x.EncryptionNonce));
        new PreEncryptedConfirmationCodeVerification().Verify(read, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(read, election.Record);

        // The ballot as read back regenerates from ξ_B (eq. 121) and records as cast.
        var cast = PreEncryptedBallotFixtures.RecordCast(election.Record, read, election.BallotNonceOf(read), election.Selections("printed-1", [1], [2]));
        new SelectionVectorAccumulationVerification().Verify(cast, election.Record);
    }

    public static IEnumerable<object[]> MalformedUncastJson()
    {
        // A 31-byte released ballot nonce.
        yield return ["short ballot nonce", new Func<JsonNode, JsonNode>(n => { n["ballotNonce"] = Convert.ToBase64String(new byte[31]); return n; })];
        // A released nonce that is not below q.
        yield return ["nonce not below q", new Func<JsonNode, JsonNode>(n => { n["contests"]![0]!["selections"]![0]!["nonces"]![0] = Convert.ToBase64String(Enumerable.Repeat((byte)0xFF, 32).ToArray()); return n; })];
        // A 31-byte selection hash.
        yield return ["short selection hash", new Func<JsonNode, JsonNode>(n => { n["ballot"]!["contests"]![0]!["selections"]![0]!["selectionHash"] = Convert.ToBase64String(new byte[31]); return n; })];
        // A short code left out.
        yield return ["no short code", new Func<JsonNode, JsonNode>(n => { n["ballot"]!["contests"]![0]!["selections"]![0]!.AsObject().Remove("shortCode"); return n; })];
        // A released nonce list left out.
        yield return ["no nonces", new Func<JsonNode, JsonNode>(n => { n["contests"]![0]!["selections"]![0]!.AsObject().Remove("nonces"); return n; })];
        // S9 review round 3: a group element of the printed ballot that is not below p.
        yield return ["alpha = p in a printed vector", new Func<JsonNode, JsonNode>(n => Replace(n["ballot"]!["contests"]![0]!["selections"]![0]!["vector"]![0]!, "alpha", Convert.ToBase64String(NotBelowP), n))];
        yield return ["beta = p in a printed vector", new Func<JsonNode, JsonNode>(n => Replace(n["ballot"]!["contests"]![0]!["selections"]![0]!["vector"]![0]!, "beta", Convert.ToBase64String(NotBelowP), n))];
    }

    /// <summary>
    /// Replaces the existing property <paramref name="name"/> of <paramref name="parent"/>: assigning
    /// to a property that is not there would add one, and the tampering would test nothing.
    /// </summary>
    private static JsonNode Replace(JsonNode parent, string name, string value, JsonNode root)
    {
        Assert.NotNull(parent[name]);
        parent[name] = value;
        return root;
    }

    /// <summary>
    /// A non-canonical group element or Z_q value is refused as such; any other malformation as
    /// invalid JSON or a non-canonical encoding (a wrong-width value). Since S10a review round 1 no
    /// reader lets a bare <see cref="FormatException"/> out (<see cref="NonCanonicalEncodingException"/>
    /// is one, and is still accepted here).
    /// </summary>
    private static void AssertRefused(string description, Exception? exception)
    {
        Assert.True(
            description.Contains("= p") || description.Contains("not below q")
                ? exception is NonCanonicalEncodingException
                : exception is JsonException or NonCanonicalEncodingException,
            $"{description}: {exception}");
    }

    /// <summary>
    /// S10a review round 1: both pre-encrypted readers refuse what <see cref="StrictJson"/> refuses
    /// (an unknown member, a member named twice, a leading byte order mark, a member name that is not
    /// valid text) with <see cref="JsonException"/>, and base64 that is not in its canonical form with
    /// <see cref="NonCanonicalEncodingException"/>. The unknown member is not a name the model has at
    /// all: a member the model marks <c>[JsonIgnore]</c> would be skipped rather than refused.
    /// </summary>
    [Theory]
    [InlineData("printed", "unknown property")]
    [InlineData("printed", "property named twice")]
    [InlineData("printed", "leading byte order mark")]
    [InlineData("printed", "property name a lone surrogate")]
    [InlineData("printed", "base64 with whitespace")]
    [InlineData("uncast", "unknown property")]
    [InlineData("uncast", "property named twice")]
    [InlineData("uncast", "leading byte order mark")]
    [InlineData("uncast", "property name a lone surrogate")]
    [InlineData("uncast", "base64 with whitespace")]
    public void Json_AmbiguousOrNonCanonicalDocument_IsRefused(string reader, string tampering)
    {
        var election = Election;
        var serializer = new JsonPreEncryptedBallotSerializer();
        using var written = new MemoryStream();
        if (reader == "printed")
        {
            serializer.Serialize(written, election.PreEncrypt("printed-1"));
        }
        else
        {
            serializer.Serialize(written, election.Uncast("uncast-1", releaseBallotNonce: true));
        }

        byte[] bytes = written.ToArray();
        string text = Encoding.UTF8.GetString(bytes);
        // A top-level member each document has exactly once at the top level.
        string member = reader == "printed" ? "chainingField" : "ballotNonce";
        Assert.Contains($"\"{member}\":", text);
        byte[] tampered = tampering switch
        {
            "unknown property" => Encoding.UTF8.GetBytes(Tamper(text, n => n["notAMemberOfTheModel"] = 1)),
            "property named twice" => Encoding.UTF8.GetBytes(text.Replace($"\"{member}\":", $"\"{member}\": null, \"{member}\":")),
            "leading byte order mark" => [0xEF, 0xBB, 0xBF, .. bytes],
            "property name a lone surrogate" => Encoding.UTF8.GetBytes(text.Replace($"\"{member}\":", "\"\\uD800\":")),
            "base64 with whitespace" => Encoding.UTF8.GetBytes(Tamper(text, n => n[member] = ((string)n[member]!).Insert(4, "    "))),
            _ => throw new ArgumentOutOfRangeException(nameof(tampering)),
        };

        // The untampered bytes read back, so each refusal is the tampering's.
        Assert.Null(Record.Exception(() => Deserialize(serializer, reader, bytes)));
        var exception = Record.Exception(() => Deserialize(serializer, reader, tampered));

        Assert.True(
            tampering == "base64 with whitespace" ? exception is NonCanonicalEncodingException : exception is JsonException,
            $"{reader}, {tampering}: {exception}");
    }

    private static string Tamper(string json, Action<JsonNode> edit)
    {
        var node = JsonNode.Parse(json)!;
        edit(node);
        return node.ToJsonString();
    }

    private static object? Deserialize(JsonPreEncryptedBallotSerializer serializer, string reader, byte[] bytes)
    {
        using var stream = new MemoryStream(bytes);
        return reader == "printed" ? serializer.DeserializeBallot(stream) : serializer.DeserializeUncastBallot(stream);
    }

    [Theory]
    [MemberData(nameof(MalformedUncastJson))]
    public void UncastRecord_Json_MalformedValue_IsRefused(string description, Func<JsonNode, JsonNode> malform)
    {
        _ = description;
        var election = Election;
        var node = JsonNode.Parse(WriteUncast(election.Uncast("uncast-1", releaseBallotNonce: true)))!;
        if (description == "short ballot nonce")
        {
            Assert.NotNull(node["ballotNonce"]);
        }

        var bytes = Encoding.UTF8.GetBytes(malform(node).ToJsonString());

        AssertRefused(description, Record.Exception(() => ReadUncast(bytes)));
    }

    public static IEnumerable<object[]> MalformedPrintedBallotJson()
    {
        yield return ["alpha = p in a printed vector", new Func<JsonNode, JsonNode>(n => Replace(n["contests"]![0]!["selections"]![0]!["vector"]![0]!, "alpha", Convert.ToBase64String(NotBelowP), n))];
        yield return ["beta = p in a printed vector", new Func<JsonNode, JsonNode>(n => Replace(n["contests"]![0]!["selections"]![0]!["vector"]![0]!, "beta", Convert.ToBase64String(NotBelowP), n))];
        yield return ["ballot nonce C0 = p", new Func<JsonNode, JsonNode>(n => Replace(n["encryptedBallotNonce"]!, "c0", Convert.ToBase64String(NotBelowP), n))];
        yield return ["short selection hash", new Func<JsonNode, JsonNode>(n => Replace(n["contests"]![0]!["selections"]![0]!, "selectionHash", Convert.ToBase64String(new byte[31]), n))];
        yield return ["no short code", new Func<JsonNode, JsonNode>(n => { Assert.True(n["contests"]![0]!["selections"]![0]!.AsObject().Remove("shortCode")); return n; })];
        yield return ["chaining field of 35 bytes", new Func<JsonNode, JsonNode>(n => Replace(n, "chainingField", Convert.ToBase64String(new byte[35]), n))];
    }

    /// <summary>
    /// S9 review round 3: the printed ballot read on its own (<see cref="JsonPreEncryptedBallotSerializer.DeserializeBallot"/>,
    /// what a recording tool reads) is decoded as strictly as inside an uncast record.
    /// </summary>
    [Theory]
    [MemberData(nameof(MalformedPrintedBallotJson))]
    public void PreEncryptedBallot_Json_MalformedValue_IsRefused(string description, Func<JsonNode, JsonNode> malform)
    {
        var serializer = new JsonPreEncryptedBallotSerializer();
        using var written = new MemoryStream();
        serializer.Serialize(written, Election.PreEncrypt("printed-1"));
        var node = JsonNode.Parse(written.ToArray())!;

        using var tampered = new MemoryStream(Encoding.UTF8.GetBytes(malform(node).ToJsonString()));

        AssertRefused(description, Record.Exception(() => serializer.DeserializeBallot(tampered)));
    }

    /// <summary>
    /// S9 review round 3 (kept from the removed recording-tool tests in S9c review round 1): a printed
    /// ballot whose JSON writes <c>"deviceId": null</c>. The property is required, but the reader does
    /// not enforce nullable annotations, so the ballot comes back without a device id; H_DI (eq. 119)
    /// cannot be formed, and Verification 16 reports it as malformed (<c>16.structure</c>) rather than
    /// failing with an <see cref="ArgumentNullException"/> or a wrong-hash sub-section.
    /// </summary>
    [Fact]
    public void PreEncryptedBallot_Json_NullDeviceId_ReadsAsNull_AndVerification16FailsStructure()
    {
        var election = Election;
        var ballot = election.PreEncrypt("printed-1");
        var serializer = new JsonPreEncryptedBallotSerializer();
        using var written = new MemoryStream();
        serializer.Serialize(written, ballot);
        var node = JsonNode.Parse(written.ToArray())!;
        Assert.Equal(ballot.DeviceId, (string?)node["deviceId"]);
        node["deviceId"] = null;

        using var tampered = new MemoryStream(Encoding.UTF8.GetBytes(node.ToJsonString()));
        var bad = serializer.DeserializeBallot(tampered)!;

        Assert.Null(bad.DeviceId);
        Assert.Equal("16.structure", Assert.Throws<VerificationFailedException>(
            () => new PreEncryptedConfirmationCodeVerification().Verify(bad, election.DeviceHash, election.Record, null)).SubSection);
    }
}
