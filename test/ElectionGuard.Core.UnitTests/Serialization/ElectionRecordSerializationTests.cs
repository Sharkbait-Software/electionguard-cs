using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.KeyGeneration;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// S10a: every record item Core produces round-trips through <see cref="JsonElectionRecordSerializer"/>
/// byte for byte, the copy read back passes the verifications that check it, and a tampered
/// document is refused with a typed exception (or, for a value that decodes, fails its
/// verification).
/// </summary>
public class ElectionRecordSerializationTests
{
    public ElectionRecordSerializationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private const string WriteIn = "Write-in: Ada Lovelace";

    private static readonly JsonElectionRecordSerializer Serializer = new();

    private sealed class Election
    {
        public required ElectionFixtureBuilder.GuardianSetResult GuardianSet { get; init; }
        public required EncryptionRecord Record { get; init; }
        public required List<EncryptedBallot> Ballots { get; init; }
        public required EncryptedTally Tally { get; init; }
        public required DecryptedTally Decrypted { get; init; }
        public required List<DecryptedContestData> ContestData { get; init; }
        public required List<DecryptedChallengedBallot> Challenged { get; init; }

        public Manifest Manifest => Record.Manifest;
    }

    /// <summary>Two cast ballots (one of weight 2) and one challenged ballot, with write-ins and contest data.</summary>
    private static readonly Lazy<Election> Shared = new(() =>
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var record = records.EncryptionRecord;
        var deviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, "device-1");

        EncryptedBallot Encrypt(string id, int choice1, BallotStatus status) => ElectionFixtureBuilder.CreateEncryptedBallot(
            record, "device-1", deviceHash,
            ElectionFixtureBuilder.CreateBallot(manifest, id, new Dictionary<string, int> { ["choice-1"] = choice1 }, numWriteinsSelected: 0, contestData: WriteIn),
            status: status);

        var first = Encrypt("ballot-1", 1, BallotStatus.Cast);
        var heavy = Encrypt("ballot-2", 1, BallotStatus.NotSubmitted);
        var weighted = new EncryptedBallot
        {
            Id = heavy.Id,
            SelectionEncryptionIdentifier = heavy.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = heavy.SelectionEncryptionIdentifierHash,
            BallotStyleId = heavy.BallotStyleId,
            Contests = heavy.Contests,
            ConfirmationCode = heavy.ConfirmationCode,
            ChainingField = heavy.ChainingField,
            EncryptedBallotNonce = heavy.EncryptedBallotNonce,
            DeviceId = heavy.DeviceId,
            Weight = 2,
            Status = BallotStatus.Cast,
        };
        var challenged = Encrypt("ballot-3", 0, BallotStatus.Challenged);
        var ballots = new List<EncryptedBallot> { first, weighted, challenged };

        var tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, ballots.ToArray());
        var guardians = ElectionFixtureBuilder.TallyGuardians(guardianSet);
        var admin = new TallyAdmin();
        var decrypted = admin.Decrypt(guardians, tally, record);
        var contestData = new[] { first, weighted }
            .Select(ballot => admin.DecryptContestData(guardians, ballot, "contest-1", record))
            .ToList();
        var challengedRecord = admin.DecryptChallengedBallot(guardians, challenged, record, PublishedCastBallots.FromRecord(record.ExtendedBaseHash, ballots));

        return new Election
        {
            GuardianSet = guardianSet,
            Record = record,
            Ballots = ballots,
            Tally = tally,
            Decrypted = decrypted,
            ContestData = contestData,
            Challenged = [challengedRecord],
        };
    });

    private static byte[] Write(Action<Stream> write)
    {
        using var stream = new MemoryStream();
        write(stream);
        return stream.ToArray();
    }

    private static T Read<T>(byte[] bytes, Func<Stream, T> read) => read(new MemoryStream(bytes));

    private static byte[] Edit(byte[] bytes, Action<JsonNode> edit)
    {
        var node = JsonNode.Parse(bytes)!;
        edit(node);
        return Encoding.UTF8.GetBytes(node.ToJsonString());
    }

    private static string Base64(byte[] bytes) => Convert.ToBase64String(bytes);

    private static string NotBelowP => Base64(EGParameters.P.ToBigEndianPadded(IntegerModP.ByteLength));

    private static string NotBelowQ => Base64(EGParameters.Q.ToBigEndianPadded(IntegerModQ.ByteLength));

    /// <summary>Text that is not base64 at all.</summary>
    private const string NotBase64 = "!!!!";

    /// <summary>
    /// The value's canonical base64 with four spaces inside it: <see cref="Convert.FromBase64String"/>
    /// and <see cref="Utf8JsonReader.GetBytesFromBase64"/> both skip them and decode the same bytes.
    /// </summary>
    private static string WithWhitespace(JsonNode? value) => ((string)value!).Insert(4, "    ");

    /// <summary>
    /// The canonical base64 of 32 zero bytes with an unused trailing bit set ("...AB=" for "...AA="):
    /// it decodes to the same 32 bytes, so it is a second spelling of one value.
    /// </summary>
    private static string ZeroHashWithUnusedBitSet()
    {
        string canonical = Base64(new byte[32]);
        Assert.Equal('=', canonical[^1]);
        string respelled = canonical[..^2] + "B=";
        Assert.Equal(new byte[32], Convert.FromBase64String(respelled));
        return respelled;
    }

    /// <summary>The document with the property name <paramref name="name"/> written as an escaped lone surrogate.</summary>
    private static byte[] WithLoneSurrogateName(byte[] written, string name, string surrogate = "\\uD800")
    {
        string text = Encoding.UTF8.GetString(written);
        Assert.Contains($"\"{name}\":", text);
        return Encoding.UTF8.GetBytes(text.Replace($"\"{name}\":", $"\"{surrogate}\":"));
    }

    /// <summary>The document with the property name <paramref name="name"/> replaced by the invalid UTF-8 byte 0xFF.</summary>
    private static byte[] WithInvalidUtf8Name(byte[] written, string name)
    {
        string text = Encoding.UTF8.GetString(written);
        Assert.DoesNotContain("#", text);
        byte[] bytes = Encoding.UTF8.GetBytes(text.Replace($"\"{name}\":", "\"#\":"));
        bytes[Array.IndexOf(bytes, (byte)'#')] = 0xFF;
        return bytes;
    }

    // --- Encryption record ---------------------------------------------------------------------------

    [Fact]
    public void EncryptionRecord_RoundTripsByteForByte_AndVerifications1To4Pass()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Record));

        var read = Read(written, Serializer.DeserializeEncryptionRecord);

        Assert.Equal(written, Write(s => Serializer.Serialize(s, read)));
        Assert.DoesNotContain("{}", Encoding.UTF8.GetString(written));
        Assert.Null(JsonNode.Parse(written)!["manifest"]);
        Assert.Equal(election.Record.ManifestFile.Bytes, read.ManifestFile.Bytes);
        Assert.Equal(ManifestSerializer.Serialize(election.Manifest), ManifestSerializer.Serialize(read.Manifest));
        Assert.Equal((byte[])election.Record.ExtendedBaseHash, (byte[])read.ExtendedBaseHash);
        Assert.Equal(election.Record.ElectionPublicKeys.VoteEncryptionKey, read.ElectionPublicKeys.VoteEncryptionKey);
        Assert.Equal(election.Record.CryptographicParameters.P, read.CryptographicParameters.P);
        Assert.Equal(election.Record.CryptographicParameters.R, read.CryptographicParameters.R);

        Assert.Null(Record.Exception(() =>
        {
            new ParameterVerification().Verify(read);
            new GuardianPublicKeyVerification().Verify(read.Guardians);
            new ElectionPublicKeyVerification().Verify(read.Guardians, read.ElectionPublicKeys);
            new ExtendedBaseHashVerification().Verify(read.ExtendedBaseHash, read.ElectionBaseHash, read.ElectionPublicKeys);
        }));
    }

    /// <summary>
    /// The hash claims are kept as read, not recomputed: a changed H_B (still 32 bytes) decodes and
    /// fails 1.F, and a changed H_E fails 4.A. A changed commitment (still below p) decodes and fails
    /// Verification 2 or 3.
    /// </summary>
    [Fact]
    public void EncryptionRecord_TamperedClaims_DecodeAndFailTheirVerification()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Record));
        string otherHash = Base64(Enumerable.Repeat((byte)0x5A, 32).ToArray());

        var withOtherBaseHash = Read(Edit(written, n => n["electionBaseHash"] = otherHash), Serializer.DeserializeEncryptionRecord);
        Assert.Equal("1.F", Assert.Throws<VerificationFailedException>(() => new ParameterVerification().Verify(withOtherBaseHash)).SubSection);

        var withOtherExtendedHash = Read(Edit(written, n => n["extendedBaseHash"] = otherHash), Serializer.DeserializeEncryptionRecord);
        Assert.Throws<VerificationFailedException>(() => new ExtendedBaseHashVerification().Verify(withOtherExtendedHash.ExtendedBaseHash, withOtherExtendedHash.ElectionBaseHash, withOtherExtendedHash.ElectionPublicKeys));

        var withOtherKey = Read(Edit(written, n => n["electionPublicKeys"]!["voteEncryptionKey"] = Base64(new IntegerModP(2).ToByteArray())), Serializer.DeserializeEncryptionRecord);
        Assert.Throws<VerificationFailedException>(() => new ElectionPublicKeyVerification().Verify(withOtherKey.Guardians, withOtherKey.ElectionPublicKeys));
    }

    public static TheoryData<string, Type> EncryptionRecordTamperings() => new()
    {
        { "commitment = p", typeof(NonCanonicalEncodingException) },
        { "commitment of 513 bytes", typeof(NonCanonicalEncodingException) },
        { "proof response = q", typeof(NonCanonicalEncodingException) },
        { "H_E of 31 bytes", typeof(NonCanonicalEncodingException) },
        { "H_P of 33 bytes", typeof(NonCanonicalEncodingException) },
        { "p of 511 bytes", typeof(NonCanonicalEncodingException) },
        { "q of 33 bytes", typeof(NonCanonicalEncodingException) },
        { "unknown property", typeof(JsonException) },
        { "a manifest property", typeof(JsonException) },
        { "property named twice", typeof(JsonException) },
        { "null H_B", typeof(JsonException) },
        { "missing guardian list", typeof(JsonException) },
        { "null guardian entry", typeof(JsonException) },
        { "guardian index 0", typeof(JsonException) },
        { "k above n", typeof(JsonException) },
        { "manifest file that is not a manifest", typeof(InvalidManifestException) },
        { "H_E not base64", typeof(NonCanonicalEncodingException) },
        { "H_E base64 with whitespace", typeof(NonCanonicalEncodingException) },
        { "H_E base64 with an unused bit set", typeof(NonCanonicalEncodingException) },
        { "manifest file base64 with whitespace", typeof(NonCanonicalEncodingException) },
        { "property name a lone surrogate", typeof(JsonException) },
        { "property name not UTF-8", typeof(JsonException) },
    };

    [Theory]
    [MemberData(nameof(EncryptionRecordTamperings))]
    public void EncryptionRecord_MalformedDocument_IsRefused(string tampering, Type expected)
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Record));
        byte[] tampered = tampering switch
        {
            "commitment = p" => Edit(written, n => n["guardians"]![0]!["voteEncryptionCommitments"]![0] = NotBelowP),
            "commitment of 513 bytes" => Edit(written, n => n["guardians"]![0]!["voteEncryptionCommitments"]![0] = Base64(new byte[513])),
            "proof response = q" => Edit(written, n => n["guardians"]![0]!["voteEncryptionProof"]!["responses"]![0] = NotBelowQ),
            "H_E of 31 bytes" => Edit(written, n => n["extendedBaseHash"] = Base64(new byte[31])),
            "H_P of 33 bytes" => Edit(written, n => n["parameterBaseHash"] = Base64(new byte[33])),
            "p of 511 bytes" => Edit(written, n => n["cryptographicParameters"]!["p"] = Base64(new byte[511])),
            "q of 33 bytes" => Edit(written, n => n["cryptographicParameters"]!["q"] = Base64(new byte[33])),
            "unknown property" => Edit(written, n => n["extra"] = 1),
            "a manifest property" => Edit(written, n => n["manifest"] = JsonNode.Parse(ManifestSerializer.Serialize(election.Manifest))),
            "property named twice" => Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(written).Replace("\"extendedBaseHash\":", "\"extendedBaseHash\": \"AAAA\", \"extendedBaseHash\":")),
            "null H_B" => Edit(written, n => n["electionBaseHash"] = null),
            "missing guardian list" => Edit(written, n => n.AsObject().Remove("guardians")),
            "null guardian entry" => Edit(written, n => n["guardians"]![1] = null),
            "guardian index 0" => Edit(written, n => n["guardians"]![0]!["index"] = 0),
            "k above n" => Edit(written, n => n["guardianParameters"]!["k"] = 4),
            "manifest file that is not a manifest" => Edit(written, n => n["manifestFile"] = Base64(Encoding.UTF8.GetBytes("{\"election\":\"kat\"}"))),
            "H_E not base64" => Edit(written, n => n["extendedBaseHash"] = NotBase64),
            "H_E base64 with whitespace" => Edit(written, n => n["extendedBaseHash"] = WithWhitespace(n["extendedBaseHash"])),
            "H_E base64 with an unused bit set" => Edit(written, n => n["extendedBaseHash"] = ZeroHashWithUnusedBitSet()),
            "manifest file base64 with whitespace" => Edit(written, n => n["manifestFile"] = WithWhitespace(n["manifestFile"])),
            "property name a lone surrogate" => WithLoneSurrogateName(written, "extendedBaseHash"),
            "property name not UTF-8" => WithInvalidUtf8Name(written, "extendedBaseHash"),
            _ => throw new ArgumentOutOfRangeException(nameof(tampering)),
        };

        var exception = Record.Exception(() => Read(tampered, Serializer.DeserializeEncryptionRecord));

        Assert.NotNull(exception);
        Assert.IsAssignableFrom(expected, exception);
    }

    // --- Guardian record -----------------------------------------------------------------------------

    [Fact]
    public void GuardianRecord_RoundTripsByteForByte_AndEveryGuardianVerifiesTheCopy()
    {
        var election = Shared.Value;
        var original = election.GuardianSet.GuardianRecord;
        byte[] written = Write(s => Serializer.Serialize(s, original));

        var read = Read(written, Serializer.DeserializeGuardianRecord);

        Assert.Equal(written, Write(s => Serializer.Serialize(s, read)));
        foreach (var guardian in election.GuardianSet.Guardians)
        {
            Assert.Null(Record.Exception(() => guardian.Verify(read, election.Record.ManifestFile)));
        }

        var tampered = Edit(written, n => n["guardians"]![0]!["communicationPublicKey"] = NotBelowP);
        Assert.Throws<NonCanonicalEncodingException>(() => Read(tampered, Serializer.DeserializeGuardianRecord));
        var notBase64 = Edit(written, n => n["guardians"]![0]!["communicationPublicKey"] = NotBase64);
        Assert.Throws<NonCanonicalEncodingException>(() => Read(notBase64, Serializer.DeserializeGuardianRecord));
        var spaced = Edit(written, n => n["guardians"]![0]!["communicationPublicKey"] = WithWhitespace(n["guardians"]![0]!["communicationPublicKey"]));
        Assert.Throws<NonCanonicalEncodingException>(() => Read(spaced, Serializer.DeserializeGuardianRecord));
    }

    // --- Encrypted tally -----------------------------------------------------------------------------

    /// <summary>
    /// The S4 R1/F2 carry-over: a tally read back from a record restores each option's decryption
    /// bound from its contest's published cast weight (here 3: one ballot of weight 1, one of
    /// weight 2), passes Verification 9 and decrypts to the same counts.
    /// </summary>
    [Fact]
    public void EncryptedTally_RoundTrips_RestoresTheDecryptionBound_PassesVerification9_AndDecrypts()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Tally));

        var read = Read(written, s => Serializer.DeserializeEncryptedTally(s, election.Manifest));

        Assert.Equal(written, Write(s => Serializer.Serialize(s, read)));
        Assert.Equal(3, read.Contests["contest-1"].CastWeight);
        Assert.Equal(2, read.BallotsCast);
        foreach (var (contestId, contest) in election.Tally.Contests)
        {
            foreach (var (choiceId, choice) in contest.Choices)
            {
                var readChoice = read.Contests[contestId].Choices[choiceId];
                Assert.Equal(choice.A, readChoice.A);
                Assert.Equal(choice.B, readChoice.B);
                Assert.Equal(choice.MaximumCount, readChoice.MaximumCount);
                Assert.True(readChoice.MaximumCount > 0);
            }
        }

        Assert.Null(Record.Exception(() => new BallotAggregationVerification().Verify(election.Ballots, election.Manifest, read)));
        var decrypted = new TallyAdmin().Decrypt(ElectionFixtureBuilder.TallyGuardians(election.GuardianSet), read, election.Record);
        Assert.Equal(3, decrypted.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(election.Decrypted.Contests["contest-1"].Choices.Select(x => (x.Key, x.Value.VoteCount)), decrypted.Contests["contest-1"].Choices.Select(x => (x.Key, x.Value.VoteCount)));
    }

    /// <summary>
    /// A published cast weight other than the cast ballots' fails Verification 9 after 9.A/9.B; a
    /// smaller one would make the administrator's search miss the count (it fails closed), a larger
    /// one would widen it.
    /// </summary>
    [Theory]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(1_000_000_000)]
    public void EncryptedTally_WrongCastWeight_FailsVerification9Structure(long castWeight)
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Tally));
        var read = Read(Edit(written, n => n["contests"]!["contest-1"]!["castWeight"] = castWeight), s => Serializer.DeserializeEncryptedTally(s, election.Manifest));

        var exception = Assert.Throws<VerificationFailedException>(() => new BallotAggregationVerification().Verify(election.Ballots, election.Manifest, read));

        Assert.Equal("9.structure", exception.SubSection);
        Assert.Contains("cast weight", exception.Message);
    }

    [Fact]
    public void EncryptedTally_TooSmallCastWeight_DecryptionFailsClosed()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Tally));
        var read = Read(Edit(written, n => n["contests"]!["contest-1"]!["castWeight"] = 2), s => Serializer.DeserializeEncryptedTally(s, election.Manifest));

        Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().Decrypt(ElectionFixtureBuilder.TallyGuardians(election.GuardianSet), read, election.Record));
    }

    /// <summary>
    /// S10a review round 1: a cast weight is a sum of at most ballotsCast weights, each an int, so a
    /// larger one is refused when the tally is read.
    /// </summary>
    [Fact]
    public void EncryptedTally_CastWeightAboveWhatTheBallotsCastCanGive_IsRefused()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Tally));
        long cap = 2L * int.MaxValue;

        var atCap = Read(Edit(written, n => n["contests"]!["contest-1"]!["castWeight"] = cap), s => Serializer.DeserializeEncryptedTally(s, election.Manifest));
        Assert.Equal(cap, atCap.Contests["contest-1"].CastWeight);
        Assert.Throws<JsonException>(() => Read(Edit(written, n => n["contests"]!["contest-1"]!["castWeight"] = cap + 1), s => Serializer.DeserializeEncryptedTally(s, election.Manifest)));
        Assert.Throws<JsonException>(() => Read(Edit(written, n => n["contests"]!["contest-1"]!["castWeight"] = long.MaxValue), s => Serializer.DeserializeEncryptedTally(s, election.Manifest)));
    }

    /// <summary>
    /// S10a review round 1: a tally decrypted without Verification 9 first (the documented misuse)
    /// with a forged weight the reader accepts is refused with a typed error naming the search limit,
    /// never an untyped exception from the discrete-log search.
    /// </summary>
    [Fact]
    public void EncryptedTally_ForgedCastWeightDecryptedWithoutVerification9_IsRefusedWithTallyDecryptionException()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Tally));
        var read = Read(Edit(written, n => n["contests"]!["contest-1"]!["castWeight"] = 2L * int.MaxValue), s => Serializer.DeserializeEncryptedTally(s, election.Manifest));
        Assert.True(read.Contests["contest-1"].Choices.Values.Max(x => x.MaximumCount) > int.MaxValue);

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().Decrypt(ElectionFixtureBuilder.TallyGuardians(election.GuardianSet), read, election.Record));

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

    /// <summary>
    /// S10a review round 1: with a saturated bound (a weight set in process, beyond what the reader
    /// accepts), decryption still fails with the typed error.
    /// </summary>
    [Fact]
    public void EncryptedTally_SaturatedBound_DecryptionRefusesWithTallyDecryptionException()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Tally));
        var read = Read(written, s => Serializer.DeserializeEncryptedTally(s, election.Manifest));
        read.Contests["contest-1"].CastWeight = long.MaxValue;
        Assert.All(read.Contests["contest-1"].Choices.Values.Where(x => x.MaximumValue > 0), x => Assert.Equal(long.MaxValue, x.MaximumCount));

        Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().Decrypt(ElectionFixtureBuilder.TallyGuardians(election.GuardianSet), read, election.Record));
    }

    /// <summary>The document's keys are kept, so Verification 9 still sees an option the manifest lacks.</summary>
    [Fact]
    public void EncryptedTally_ExtraOption_DecodesAndFailsVerification9Structure()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Tally));
        var read = Read(Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-9"] = JsonNode.Parse(n["contests"]!["contest-1"]!["choices"]!["choice-1"]!.ToJsonString())), s => Serializer.DeserializeEncryptedTally(s, election.Manifest));

        Assert.Equal("9.structure", Assert.Throws<VerificationFailedException>(() => new BallotAggregationVerification().Verify(election.Ballots, election.Manifest, read)).SubSection);
    }

    public static TheoryData<string, Type> EncryptedTallyTamperings() => new()
    {
        { "A = p", typeof(NonCanonicalEncodingException) },
        { "B of 511 bytes", typeof(NonCanonicalEncodingException) },
        { "negative cast weight", typeof(JsonException) },
        { "negative ballot count", typeof(JsonException) },
        { "missing cast weight", typeof(JsonException) },
        { "null option", typeof(JsonException) },
        { "unknown property", typeof(JsonException) },
        { "option named twice", typeof(JsonException) },
        { "A not base64", typeof(NonCanonicalEncodingException) },
        { "A base64 with whitespace", typeof(NonCanonicalEncodingException) },
        { "property name a lone surrogate", typeof(JsonException) },
        { "contest id a lone surrogate", typeof(JsonException) },
        { "property name not UTF-8", typeof(JsonException) },
    };

    [Theory]
    [MemberData(nameof(EncryptedTallyTamperings))]
    public void EncryptedTally_MalformedDocument_IsRefused(string tampering, Type expected)
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Tally));
        byte[] tampered = tampering switch
        {
            "A = p" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["a"] = NotBelowP),
            "B of 511 bytes" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["b"] = Base64(new byte[511])),
            "negative cast weight" => Edit(written, n => n["contests"]!["contest-1"]!["castWeight"] = -1),
            "negative ballot count" => Edit(written, n => n["ballotsCast"] = -1),
            "missing cast weight" => Edit(written, n => n["contests"]!["contest-1"]!.AsObject().Remove("castWeight")),
            "null option" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"] = null),
            "unknown property" => Edit(written, n => n["contests"]!["contest-1"]!["maximumCount"] = 3),
            "option named twice" => Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(written).Replace("\"choice-2\":", "\"choice-1\":")),
            "A not base64" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["a"] = NotBase64),
            "A base64 with whitespace" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["a"] = WithWhitespace(n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["a"])),
            "property name a lone surrogate" => WithLoneSurrogateName(written, "ballotsCast", "\\uDC00"),
            "contest id a lone surrogate" => WithLoneSurrogateName(written, "contest-1"),
            "property name not UTF-8" => WithInvalidUtf8Name(written, "ballotsCast"),
            _ => throw new ArgumentOutOfRangeException(nameof(tampering)),
        };

        var exception = Record.Exception(() => Read(tampered, s => Serializer.DeserializeEncryptedTally(s, election.Manifest)));

        Assert.NotNull(exception);
        Assert.IsAssignableFrom(expected, exception);
    }

    // --- Decrypted tally -----------------------------------------------------------------------------

    [Fact]
    public void DecryptedTally_RoundTrips_AndVerifications10And11Pass()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Decrypted));

        var read = Read(written, Serializer.DeserializeDecryptedTally);

        Assert.Equal(written, Write(s => Serializer.Serialize(s, read)));
        var choice = read.Contests["contest-1"].Choices["choice-1"];
        Assert.Equal(3, choice.VoteCount);
        Assert.Equal(1, read.Contests["contest-1"].ContestIndex);
        Assert.Equal(1, choice.ChoiceIndex);
        Assert.Null(Record.Exception(() =>
        {
            new TallyDecryptionVerification().Verify(election.Record, election.Tally, read);
            new TallyContentsVerification().Verify(election.Manifest, read, election.Ballots);
        }));
    }

    public static TheoryData<string, Type?> DecryptedTallyTamperings() => new()
    {
        { "T = p", typeof(NonCanonicalEncodingException) },
        { "response = q", typeof(NonCanonicalEncodingException) },
        { "missing vote count", typeof(JsonException) },
        { "null contest", typeof(JsonException) },
        { "unknown property", typeof(JsonException) },
        { "response not base64", typeof(NonCanonicalEncodingException) },
        { "T base64 with whitespace", typeof(NonCanonicalEncodingException) },
        { "option id a lone surrogate", typeof(JsonException) },
        { "another count", null },
    };

    [Theory]
    [MemberData(nameof(DecryptedTallyTamperings))]
    public void DecryptedTally_MalformedDocument_IsRefused_OrFailsVerification10(string tampering, Type? expected)
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Decrypted));
        byte[] tampered = tampering switch
        {
            "T = p" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["t"] = NotBelowP),
            "response = q" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["response"] = NotBelowQ),
            "missing vote count" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!.AsObject().Remove("voteCount")),
            "null contest" => Edit(written, n => n["contests"]!["contest-1"] = null),
            "unknown property" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["extra"] = 1),
            "response not base64" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["response"] = NotBase64),
            "T base64 with whitespace" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["t"] = WithWhitespace(n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["t"])),
            "option id a lone surrogate" => WithLoneSurrogateName(written, "choice-1"),
            "another count" => Edit(written, n => n["contests"]!["contest-1"]!["choices"]!["choice-1"]!["voteCount"] = 2),
            _ => throw new ArgumentOutOfRangeException(nameof(tampering)),
        };

        if (expected is null)
        {
            // The count decodes as published, so T = K^t fails for it: 10.C, not a structural failure.
            var read = Read(tampered, Serializer.DeserializeDecryptedTally);
            var failure = Assert.Throws<VerificationFailedException>(() => new TallyDecryptionVerification().Verify(election.Record, election.Tally, read));
            Assert.Equal("10.C", failure.SubSection);
            return;
        }

        var exception = Record.Exception(() => Read(tampered, Serializer.DeserializeDecryptedTally));
        Assert.NotNull(exception);
        Assert.IsAssignableFrom(expected, exception);
    }

    // --- Decrypted contest data ----------------------------------------------------------------------

    [Fact]
    public void ContestData_RoundTrips_AndVerification12Passes()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.ContestData));

        var read = Read(written, Serializer.DeserializeDecryptedContestData);

        Assert.Equal(written, Write(s => Serializer.Serialize(s, read)));
        Assert.Equal(2, read.Count);
        foreach (var decrypted in read)
        {
            Assert.Equal(WriteIn, decrypted.DecodeText());
            var ballot = election.Ballots.Single(x => x.Id == decrypted.BallotId);
            Assert.Null(Record.Exception(() => new ContestDataDecryptionVerification().Verify(election.Record, ballot, decrypted)));
        }
    }

    [Theory]
    [InlineData("beta = p")]
    [InlineData("challenge of 31 bytes")]
    [InlineData("null entry")]
    [InlineData("null data")]
    [InlineData("other data")]
    [InlineData("data not base64")]
    [InlineData("beta base64 with whitespace")]
    [InlineData("property name a lone surrogate")]
    public void ContestData_MalformedDocument_IsRefused_OrFailsVerification12(string tampering)
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.ContestData));
        byte[] tampered = tampering switch
        {
            "beta = p" => Edit(written, n => n[0]!["beta"] = NotBelowP),
            "challenge of 31 bytes" => Edit(written, n => n[0]!["challenge"] = Base64(new byte[31])),
            "null entry" => Edit(written, n => n[1] = null),
            "null data" => Edit(written, n => n[0]!["data"] = null),
            "other data" => Edit(written, n => n[0]!["data"] = Base64(new byte[64])),
            "data not base64" => Edit(written, n => n[0]!["data"] = NotBase64),
            "beta base64 with whitespace" => Edit(written, n => n[0]!["beta"] = WithWhitespace(n[0]!["beta"])),
            "property name a lone surrogate" => WithLoneSurrogateName(written, "beta"),
            _ => throw new ArgumentOutOfRangeException(nameof(tampering)),
        };

        if (tampering == "other data")
        {
            // D of the right length (b_Λ = 2 blocks) but not C_1 XOR k: the proof still holds, 12.C fails.
            var read = Read(tampered, Serializer.DeserializeDecryptedContestData);
            var ballot = election.Ballots.Single(x => x.Id == read[0].BallotId);
            var failure = Assert.Throws<VerificationFailedException>(() => new ContestDataDecryptionVerification().Verify(election.Record, ballot, read[0]));
            Assert.Equal("12.C", failure.SubSection);
            return;
        }

        var exception = Record.Exception(() => Read(tampered, Serializer.DeserializeDecryptedContestData));
        Assert.True(exception is JsonException or NonCanonicalEncodingException, exception?.ToString());
    }

    // --- Decrypted challenged ballots ----------------------------------------------------------------

    [Fact]
    public void ChallengedBallots_RoundTrip_AndVerifications13And14Pass()
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Challenged));

        var read = Read(written, Serializer.DeserializeDecryptedChallengedBallots);

        Assert.Equal(written, Write(s => Serializer.Serialize(s, read)));
        var decrypted = Assert.Single(read);
        var ballot = election.Ballots.Single(x => x.Id == decrypted.BallotId);
        Assert.Equal(WriteIn, decrypted.Contests[0].ContestData!.DecodeText());
        Assert.Null(Record.Exception(() =>
        {
            new ChallengedBallotDecryptionVerification().Verify(election.Record, ballot, decrypted);
            new ChallengedBallotWellFormednessVerification().Verify(election.Manifest, ballot, decrypted);
        }));
    }

    [Theory]
    [InlineData("nonce = q")]
    [InlineData("null contest entry")]
    [InlineData("null option entry")]
    [InlineData("null supplemental field list")]
    [InlineData("unknown property")]
    [InlineData("other value")]
    [InlineData("nonce not base64")]
    [InlineData("nonce base64 with whitespace")]
    [InlineData("property name a lone surrogate")]
    public void ChallengedBallots_MalformedDocument_IsRefused_OrFailsVerification13(string tampering)
    {
        var election = Shared.Value;
        byte[] written = Write(s => Serializer.Serialize(s, election.Challenged));
        byte[] tampered = tampering switch
        {
            "nonce = q" => Edit(written, n => n[0]!["contests"]![0]!["choices"]![0]!["encryptionNonce"] = NotBelowQ),
            "null contest entry" => Edit(written, n => n[0]!["contests"]![0] = null),
            "null option entry" => Edit(written, n => n[0]!["contests"]![0]!["choices"]![1] = null),
            "null supplemental field list" => Edit(written, n => n[0]!["contests"]![0]!["supplementalFields"] = null),
            "unknown property" => Edit(written, n => n[0]!["ballotNonce"] = Base64(new byte[32])),
            "other value" => Edit(written, n => n[0]!["contests"]![0]!["choices"]![0]!["value"] = 1),
            "nonce not base64" => Edit(written, n => n[0]!["contests"]![0]!["choices"]![0]!["encryptionNonce"] = NotBase64),
            "nonce base64 with whitespace" => Edit(written, n => n[0]!["contests"]![0]!["choices"]![0]!["encryptionNonce"] = WithWhitespace(n[0]!["contests"]![0]!["choices"]![0]!["encryptionNonce"])),
            "property name a lone surrogate" => WithLoneSurrogateName(written, "ballotId"),
            _ => throw new ArgumentOutOfRangeException(nameof(tampering)),
        };

        if (tampering == "other value")
        {
            // A released value that is not the encrypted one recomputes another (alpha, beta), so another
            // contest hash and H_C: 13.B (13.A covers contest data only).
            var read = Read(tampered, Serializer.DeserializeDecryptedChallengedBallots);
            var ballot = election.Ballots.Single(x => x.Id == read[0].BallotId);
            var failure = Assert.Throws<VerificationFailedException>(() => new ChallengedBallotDecryptionVerification().Verify(election.Record, ballot, read[0]));
            Assert.Equal("13.B", failure.SubSection);
            return;
        }

        var exception = Record.Exception(() => Read(tampered, Serializer.DeserializeDecryptedChallengedBallots));
        Assert.True(exception is JsonException or NonCanonicalEncodingException, exception?.ToString());
    }

    // --- Device chains and pre-encrypted records, tightened in S10a ----------------------------------

    [Theory]
    [InlineData("confirmation code of 31 bytes")]
    [InlineData("device information hash of 33 bytes")]
    [InlineData("unknown property")]
    [InlineData("null device id")]
    [InlineData("null entry")]
    [InlineData("property named twice")]
    [InlineData("confirmation code not base64")]
    [InlineData("device information hash base64 with whitespace")]
    [InlineData("property name a lone surrogate")]
    [InlineData("leading byte order mark")]
    public void DeviceChainRecord_MalformedDocument_IsRefused(string tampering)
    {
        var election = Shared.Value;
        var chain = new DeviceChain(election.Record, "device-1");
        foreach (var ballot in election.Ballots)
        {
            chain.Append(ballot);
        }

        var serializer = new JsonDeviceChainRecordSerializer();
        byte[] written = Write(s => serializer.Serialize(s, [chain.Close()]));
        Assert.Single(Read(written, serializer.Deserialize)!);
        byte[] tampered = tampering switch
        {
            "confirmation code of 31 bytes" => Edit(written, n => n[0]!["confirmationCodes"]![0] = Base64(new byte[31])),
            "device information hash of 33 bytes" => Edit(written, n => n[0]!["deviceInformationHash"] = Base64(new byte[33])),
            "unknown property" => Edit(written, n => n[0]!["extra"] = 1),
            "null device id" => Edit(written, n => n[0]!["deviceId"] = null),
            "null entry" => Edit(written, n => n.AsArray().Add(null)),
            "property named twice" => Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(written).Replace("\"deviceId\":", "\"deviceId\": \"x\", \"deviceId\":")),
            "confirmation code not base64" => Edit(written, n => n[0]!["confirmationCodes"]![0] = NotBase64),
            "device information hash base64 with whitespace" => Edit(written, n => n[0]!["deviceInformationHash"] = WithWhitespace(n[0]!["deviceInformationHash"])),
            "property name a lone surrogate" => WithLoneSurrogateName(written, "deviceId"),
            "leading byte order mark" => [0xEF, 0xBB, 0xBF, .. written],
            _ => throw new ArgumentOutOfRangeException(nameof(tampering)),
        };

        var exception = Record.Exception(() => Read(tampered, serializer.Deserialize));
        Assert.True(exception is JsonException or NonCanonicalEncodingException, exception?.ToString());
    }
}
