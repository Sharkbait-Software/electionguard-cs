using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Testing.Common;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using static ElectionGuard.Core.Serialization.ProtobufEncryptedBallotSerializer;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// G40 (S10a): §3.7 lists "the date and time of the ballot encryption" among a ballot's record
/// items. The encryptor reads it from an injectable clock, in UTC to the millisecond; it is optional
/// in both encodings and is not a hash input (eq. 71 hashes the contest hashes and B_C only).
/// </summary>
public class EncryptionTimestampTests
{
    public EncryptionTimestampTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class Election
    {
        public required Manifest Manifest { get; init; }
        public required EncryptionRecord Record { get; init; }
        public required VotingDeviceInformationHash DeviceHash { get; init; }
    }

    private static readonly Lazy<Election> Shared = new(() =>
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        return new Election
        {
            Manifest = manifest,
            Record = records.EncryptionRecord,
            DeviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, "device-1"),
        };
    });

    /// <summary>2026-10-08 12:34:56.789 and 4,567 ticks, at +02:00.</summary>
    private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 10, 8, 14, 34, 56, 789, TimeSpan.FromHours(2)).AddTicks(4567);

    private static EncryptedBallot Encrypt(TimeProvider? clock, byte idSeed = 1, byte nonceSeed = 2)
    {
        var election = Shared.Value;
        return new BallotEncryptor(election.Record, "device-1", election.DeviceHash, clock).Encrypt(
            ElectionFixtureBuilder.CreateBallot(election.Manifest, "ballot-1", new Dictionary<string, int> { ["choice-1"] = 1 }),
            null,
            new SelectionEncryptionIdentifier(Enumerable.Repeat(idSeed, 32).ToArray()),
            new BallotNonce(Enumerable.Repeat(nonceSeed, 32).ToArray()));
    }

    [Fact]
    public void Encrypt_RecordsTheClocksTime_InUtc_ToTheMillisecond()
    {
        var ballot = Encrypt(new FixedClock(Now));

        Assert.Equal(new DateTimeOffset(2026, 10, 8, 12, 34, 56, 789, TimeSpan.Zero), ballot.EncryptionTimestamp);
        Assert.Equal(TimeSpan.Zero, ballot.EncryptionTimestamp!.Value.Offset);
    }

    [Fact]
    public void Encrypt_WithoutAClock_ReadsTheSystemClock()
    {
        var before = DateTimeOffset.UtcNow.AddMilliseconds(-1);
        var ballot = Encrypt(null);
        var after = DateTimeOffset.UtcNow;

        Assert.InRange(ballot.EncryptionTimestamp!.Value, before, after);
    }

    /// <summary>Not a hash input: the same id_B, ξ_B and selections at two times give the same ciphertexts, contest hashes and confirmation code.</summary>
    [Fact]
    public void EncryptionTimestamp_IsNotAHashInput()
    {
        var early = Encrypt(new FixedClock(Now));
        var late = Encrypt(new FixedClock(Now.AddDays(400)));

        Assert.NotEqual(early.EncryptionTimestamp, late.EncryptionTimestamp);
        Assert.Equal(early.ConfirmationCode, late.ConfirmationCode);
        Assert.Equal(early.Contests[0].ContestHash, late.Contests[0].ContestHash);
        Assert.Equal(early.Contests[0].Choices.Select(x => x.Beta), late.Contests[0].Choices.Select(x => x.Beta));
    }

    [Fact]
    public void EncryptionTimestamp_RefusesAnOffsetOrSubMillisecondValue()
    {
        var ballot = Encrypt(new FixedClock(Now));

        Assert.Throws<ArgumentException>(() => Copy(ballot, Now));
        Assert.Throws<ArgumentException>(() => Copy(ballot, new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero).AddTicks(1)));
        Assert.Null(Copy(ballot, null).EncryptionTimestamp);
    }

    private static EncryptedBallot Copy(EncryptedBallot ballot, DateTimeOffset? timestamp) => new()
    {
        Id = ballot.Id,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        BallotStyleId = ballot.BallotStyleId,
        Contests = ballot.Contests,
        ConfirmationCode = ballot.ConfirmationCode,
        ChainingField = ballot.ChainingField,
        EncryptedBallotNonce = ballot.EncryptedBallotNonce,
        Weight = ballot.Weight,
        DeviceId = ballot.DeviceId,
        Status = ballot.Status,
        EncryptionTimestamp = timestamp,
    };

    public static TheoryData<IEncryptedBallotSerializer> Serializers() => new()
    {
        new JsonEncryptedBallotSerializer(),
        new ProtobufEncryptedBallotSerializer(),
    };

    private static EncryptedBallot RoundTrip(IEncryptedBallotSerializer serializer, EncryptedBallot ballot)
    {
        using var encoded = new MemoryStream();
        serializer.Serialize(encoded, ballot);
        encoded.Position = 0;
        return serializer.Deserialize(encoded)!;
    }

    [Theory]
    [MemberData(nameof(Serializers))]
    public void EncryptionTimestamp_RoundTrips_AndAbsentStaysAbsent(IEncryptedBallotSerializer serializer)
    {
        var ballot = Encrypt(new FixedClock(Now));

        Assert.Equal(ballot.EncryptionTimestamp, RoundTrip(serializer, ballot).EncryptionTimestamp);
        Assert.Null(RoundTrip(serializer, Copy(ballot, null)).EncryptionTimestamp);
        var earliest = new DateTimeOffset(1, 1, 1, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal(earliest, RoundTrip(serializer, Copy(ballot, earliest)).EncryptionTimestamp);
    }

    [Fact]
    public void Json_WritesTheDocumentedForm_AndOmitsAnAbsentTimestamp()
    {
        var ballot = Encrypt(new FixedClock(Now));
        var serializer = new JsonEncryptedBallotSerializer();
        using var encoded = new MemoryStream();
        serializer.Serialize(encoded, ballot);
        using var withoutEncoded = new MemoryStream();
        serializer.Serialize(withoutEncoded, Copy(ballot, null));

        Assert.Equal("2026-10-08T12:34:56.789Z", JsonNode.Parse(encoded.ToArray())!["encryptionTimestamp"]!.GetValue<string>());
        Assert.False(JsonNode.Parse(withoutEncoded.ToArray())!.AsObject().ContainsKey("encryptionTimestamp"));
    }

    [Theory]
    [InlineData("2026-10-08T12:34:56Z")]
    [InlineData("2026-10-08T12:34:56.7890Z")]
    [InlineData("2026-10-08T14:34:56.789+02:00")]
    [InlineData("2026-10-08T12:34:56.789")]
    [InlineData("2026-10-08 12:34:56.789Z")]
    [InlineData(" 2026-10-08T12:34:56.789Z")]
    [InlineData("2026-13-08T12:34:56.789Z")]
    public void Json_TimestampNotInTheDocumentedForm_IsRefused(string text)
    {
        var exception = Record.Exception(() => ReadJsonWithTimestamp(JsonValue.Create(text)));

        Assert.IsType<NonCanonicalEncodingException>(exception);
    }

    [Fact]
    public void Json_TimestampAsANumber_IsRefused()
    {
        Assert.IsAssignableFrom<JsonException>(Record.Exception(() => ReadJsonWithTimestamp(JsonValue.Create(1_759_926_896_789L))));
    }

    private static EncryptedBallot? ReadJsonWithTimestamp(JsonNode value)
    {
        var serializer = new JsonEncryptedBallotSerializer();
        using var encoded = new MemoryStream();
        serializer.Serialize(encoded, Encrypt(new FixedClock(Now)));
        var document = JsonNode.Parse(encoded.ToArray())!;
        document["encryptionTimestamp"] = value;
        return serializer.Deserialize(new MemoryStream(Encoding.UTF8.GetBytes(document.ToJsonString())));
    }

    [Theory]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void Protobuf_TimestampOutsideTheRepresentableYears_IsRefused(long unixMilliseconds)
    {
        using var encoded = new MemoryStream();
        new ProtobufEncryptedBallotSerializer().Serialize(encoded, Encrypt(new FixedClock(Now)));
        encoded.Position = 0;
        var dto = ProtoBuf.Serializer.Deserialize<ProtobufEncryptedBallot>(encoded);
        Assert.Equal(Now.ToUnixTimeMilliseconds(), dto.EncryptionTimestamp);
        typeof(ProtobufEncryptedBallot).GetProperty(nameof(ProtobufEncryptedBallot.EncryptionTimestamp))!.SetValue(dto, unixMilliseconds);
        using var tampered = new MemoryStream();
        ProtoBuf.Serializer.Serialize(tampered, dto);
        tampered.Position = 0;

        Assert.Throws<NonCanonicalEncodingException>(() => new ProtobufEncryptedBallotSerializer().Deserialize(tampered));
    }
}
