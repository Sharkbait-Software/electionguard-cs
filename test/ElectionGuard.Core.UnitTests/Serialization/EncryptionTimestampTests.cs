using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Testing.Common;
using Google.Protobuf;
using System.Text.Json.Nodes;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// G40 (S10a): §3.7 lists "the date and time of the ballot encryption" among a ballot's record
/// items. The encryptor reads it from an injectable clock, in UTC to the millisecond; it is optional
/// in the record (the ballot item's <c>encrypted_at</c>, S10b) and is not a hash input (eq. 71
/// hashes the contest hashes and B_C only).
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

    private static EncryptedBallot Cast(TimeProvider? clock)
    {
        var ballot = Encrypt(clock);
        ballot.RecordStatus(BallotStatus.Cast);
        return ballot;
    }

    private static EncryptedBallot RoundTrip(EncryptedBallot ballot, bool json)
    {
        var manifest = Shared.Value.Manifest;
        return json
            ? RecordItemCodec.DecodeBallotJson(RecordItemCodec.EncodeBallotJson(ballot, manifest), manifest, "device-1")
            : RecordItemCodec.DecodeBallot(RecordItemCodec.EncodeBallot(ballot, manifest), manifest, "device-1");
    }

    /// <summary>
    /// S10b-16: the ballot item's <c>encrypted_at</c> carries the timestamp in both representations
    /// (S10a's protobuf-net field 14 and JSON member retired with their serializers); absent stays
    /// absent. D3 limits it to 1970-01-01T00:00:00Z onwards, so an earlier time cannot be recorded.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EncryptionTimestamp_RoundTrips_AndAbsentStaysAbsent(bool json)
    {
        var ballot = Cast(new FixedClock(Now));

        Assert.Equal(ballot.EncryptionTimestamp, RoundTrip(ballot, json).EncryptionTimestamp);
        Assert.Null(RoundTrip(Copy(ballot, null), json).EncryptionTimestamp);
        var earliest = DateTimeOffset.UnixEpoch;
        Assert.Equal(earliest, RoundTrip(Copy(ballot, earliest), json).EncryptionTimestamp);
        Assert.Throws<ArgumentException>(() => RecordItemCodec.EncodeBallot(Copy(ballot, earliest.AddMilliseconds(-1)), Shared.Value.Manifest));
    }

    [Fact]
    public void Json_WritesTheMappingsForm_AndOmitsAnAbsentTimestamp()
    {
        var ballot = Cast(new FixedClock(Now));
        var manifest = Shared.Value.Manifest;

        var line = JsonNode.Parse(RecordItemCodec.EncodeBallotJson(ballot, manifest))!["encryptedBallot"]!;
        var without = JsonNode.Parse(RecordItemCodec.EncodeBallotJson(Copy(ballot, null), manifest))!["encryptedBallot"]!;

        Assert.Equal("2026-10-08T12:34:56.789Z", line["encryptedAt"]!.GetValue<string>());
        Assert.False(without.AsObject().ContainsKey("encryptedAt"));
    }

    /// <summary>
    /// D3 on the item: seconds in [0, 253402300799] and whole milliseconds. Anything else is not
    /// canonical, refused when the item is decoded (S10a refused the same in its two serializers).
    /// </summary>
    [Theory]
    [InlineData(-1L, 0)]
    [InlineData(253402300800L, 0)]
    [InlineData(1_759_926_896L, 1)]
    [InlineData(1_759_926_896L, 789_000_001)]
    public void Item_TimestampOutsideD3_IsRefused(long seconds, int nanos)
    {
        var manifest = Shared.Value.Manifest;
        var item = BallotMapper.ToItem(Cast(new FixedClock(Now)), manifest);
        item.EncryptedBallot.EncryptedAt = new Google.Protobuf.WellKnownTypes.Timestamp { Seconds = seconds, Nanos = nanos };

        Assert.Throws<NonCanonicalEncodingException>(() => RecordItemCodec.DecodeBallot(item.ToByteArray(), manifest, "device-1"));
    }
}
