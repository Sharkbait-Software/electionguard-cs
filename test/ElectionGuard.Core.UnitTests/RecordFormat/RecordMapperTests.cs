using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.PreEncryption;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.KeyGeneration;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;
using Google.Protobuf;
using DeviceHeader = ElectionGuard.Core.RecordFormat.DeviceHeader;
using DeviceClose = ElectionGuard.Core.RecordFormat.DeviceClose;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-4: the domain mappers. Each record item round-trips domain -> protobuf -> canonical bytes ->
/// protobuf -> domain, the bytes pass the canonicality check, re-encoding the decoded object gives
/// the same bytes, and the decoded object passes the verifications that read it. Per type, a value
/// out of Z_p or Z_q decodes and is reported under design §4.8's code, by the verification it
/// belongs to; the others are not evaluable on that item.
/// </summary>
public class RecordMapperTests
{
    public RecordMapperTests()
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
        public required List<DecryptedContestData> ContestData { get; init; }
        public required DecryptedChallengedBallot Challenged { get; init; }
        public required DeviceChainRecord Device { get; init; }
        public required RecordBallotIndex Index { get; init; }

        public Manifest Manifest => Record.Manifest;
        public EncryptedBallot ChallengedBallot => Ballots.Single(x => x.Status == BallotStatus.Challenged);
    }

    /// <summary>
    /// Under simple chaining: a cast ballot with a timestamp, a cast ballot of weight 2, a spoiled
    /// ballot and a challenged one, all with write-ins and contest data; the tally, its decryption,
    /// the contest data of the cast ballots and the challenged ballot's decryption.
    /// </summary>
    private static readonly Lazy<Election> Shared = new(() =>
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true, chainingMode: ChainingMode.Simple);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        var chain = new DeviceChain(record, DeviceId);

        EncryptedBallot Encrypt(string id, int choice1, BallotStatus status, int weight = 1, DateTimeOffset? at = null)
        {
            var ballot = ElectionFixtureBuilder.CreateEncryptedBallot(record, DeviceId, chain.DeviceInformationHash,
                ElectionFixtureBuilder.CreateBallot(manifest, id, new Dictionary<string, int> { ["choice-1"] = choice1 }, numWriteinsSelected: 0, contestData: WriteIn),
                chain.PreviousConfirmationCode, BallotStatus.Unrecorded);
            var copy = new EncryptedBallot
            {
                Id = ballot.Id,
                SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
                SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
                BallotStyleId = ballot.BallotStyleId,
                Contests = ballot.Contests,
                ConfirmationCode = ballot.ConfirmationCode,
                ChainingField = ballot.ChainingField,
                EncryptedBallotNonce = ballot.EncryptedBallotNonce,
                DeviceId = ballot.DeviceId,
                Weight = weight,
                EncryptionTimestamp = at,
                Status = status,
            };
            chain.Append(copy);
            return copy;
        }

        var ballots = new List<EncryptedBallot>
        {
            Encrypt("ballot-1", 1, BallotStatus.Cast, at: new DateTimeOffset(2026, 11, 3, 14, 3, 7, 412, TimeSpan.Zero)),
            Encrypt("ballot-2", 1, BallotStatus.Cast, weight: 2),
            Encrypt("ballot-3", 0, BallotStatus.Spoiled),
            Encrypt("ballot-4", 0, BallotStatus.Challenged),
        };
        var device = chain.Close();

        var tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, ballots.ToArray());
        var guardians = ElectionFixtureBuilder.TallyGuardians(guardianSet);
        var admin = new TallyAdmin();
        var index = new RecordBallotIndex();
        index.AddDevice(new DeviceKey(DeviceChainBallotKind.Encrypted, chain.DeviceInformationHash), ballots.Select(x => (x.Id, x.SelectionEncryptionIdentifierHash)));

        return new Election
        {
            GuardianSet = guardianSet,
            Record = record,
            Ballots = ballots,
            Tally = tally,
            Decrypted = admin.Decrypt(guardians, tally, record),
            ContestData = ballots.Take(2).Select(ballot => admin.DecryptContestData(guardians, ballot, "contest-1", record)).ToList(),
            Challenged = admin.DecryptChallengedBallot(guardians, ballots[3], record, PublishedCastAndSpoiledBallots.FromRecord(record.ExtendedBaseHash, ballots)),
            Device = device,
            Index = index,
        };
    });

    /// <summary>Canonical bytes of an item, checked, then parsed back: what a reader of the stored bytes sees.</summary>
    private static Pb.RecordItem ThroughBytes(Pb.RecordItem item)
    {
        byte[] bytes = item.ToByteArray();
        var check = CanonicalProtobuf.Check(bytes, 0);
        Assert.True(check.IsCanonical, $"{item.ItemCase}: {check.Rule} {check.Message}");
        return Pb.RecordItem.Parser.ParseFrom(bytes);
    }

    /// <summary>A ballot of the shared election as a reader of its record item decodes it.</summary>
    private static RecordDecoded<EncryptedBallot> DecodedBallot(EncryptedBallot ballot) =>
        BallotMapper.FromItem(ThroughBytes(BallotMapper.ToItem(ballot, Shared.Value.Manifest)), Shared.Value.Manifest, DeviceId);

    private static ByteString NotBelowP =>ByteString.CopyFrom(EGParameters.P.ToBigEndianPadded(512));

    private static ByteString NotBelowQ => ByteString.CopyFrom(EGParameters.Q.ToBigEndianPadded(32));

    private static ByteString WithFirstHalf(ByteString pair, ByteString half) => ByteString.CopyFrom([.. half.Span, .. pair.Span[32..]]);

    private static ByteString WithSecondHalf(ByteString pair, ByteString half) => ByteString.CopyFrom([.. pair.Span[..32], .. half.Span]);

    // ---- setup ----------------------------------------------------------------------------------

    [Fact]
    public void Setup_RoundTrips_AndPassesVerifications1To4()
    {
        var election = Shared.Value;
        var setup = RecordSetup.FromEncryptionRecord(election.Record);
        var items = SetupMapper.ToItems(setup);
        Assert.Equal(4 + election.Record.Guardians.Count, items.Count);

        var decoded = SetupMapper.FromItems(items.Select(ThroughBytes).ToList());
        var value = Assert.IsType<RecordSetup>(decoded.Value);

        Assert.Equal(items.Select(x => x.ToByteArray()), SetupMapper.ToItems(value).Select(x => x.ToByteArray()));
        Assert.Equal(RecordFormatVersion.V2_0, value.Format);
        Assert.Equal(election.Record.ManifestFile.Bytes, value.ManifestFile.Bytes);
        Assert.Equal(RecordSetup.ManifestMediaTypeFormat1, value.ManifestMediaType);
        Assert.Equal(EGParameters.P, value.Parameters.P);
        Assert.Equal(EGParameters.Q, value.Parameters.Q);

        new ParameterVerification().Verify(decoded);
        new GuardianPublicKeyVerification().Verify(decoded);
        new ElectionPublicKeyVerification().Verify(decoded);
        var rebuilt = value.ToEncryptionRecord();
        new ParameterVerification().Verify(rebuilt);
        new ExtendedBaseHashVerification().Verify(rebuilt.ExtendedBaseHash, rebuilt.ElectionBaseHash, rebuilt.ElectionPublicKeys);
        Assert.Equal(ElectionGuard.Core.Serialization.ManifestSerializer.Serialize(election.Manifest), ElectionGuard.Core.Serialization.ManifestSerializer.Serialize(rebuilt.Manifest));
    }

    /// <summary>#19: the manifest is stored byte for byte as entered: whitespace, member order and vendor properties survive.</summary>
    [Fact]
    public void Setup_ManifestBytes_SurviveByteForByte()
    {
        var election = Shared.Value;
        byte[] entered = System.Text.Encoding.UTF8.GetBytes("{\n  \"x-vendor\": {\"precincts\": [1, 2]},\n" + System.Text.Encoding.UTF8.GetString(election.Record.ManifestFile.Bytes)[1..]);
        var setup = RecordSetup.FromEncryptionRecord(election.Record) with { ManifestFile = new ManifestFile { Bytes = entered } };

        var decoded = SetupMapper.FromItems(SetupMapper.ToItems(setup).Select(ThroughBytes).ToList()).Value!;

        Assert.Equal(entered, decoded.ManifestFile.Bytes);
        Assert.Equal(ElectionGuard.Core.Serialization.ManifestSerializer.Serialize(election.Manifest), ElectionGuard.Core.Serialization.ManifestSerializer.Serialize(decoded.ToEncryptionRecord().Manifest));
    }

    [Fact]
    public void GuardianRecord_RoundTrips_ThroughTheSetupItems()
    {
        var election = Shared.Value;
        var guardianRecord = election.GuardianSet.GuardianRecord;
        var setup = RecordSetup.FromGuardianRecord(guardianRecord, election.Record.ExtendedBaseHash);

        var decoded = SetupMapper.FromItems(SetupMapper.ToItems(setup).Select(ThroughBytes).ToList()).Value!.ToGuardianRecord();

        new ParameterVerification().Verify(decoded);
        new GuardianPublicKeyVerification().Verify(decoded.Guardians);
        Assert.Equal(guardianRecord.ManifestFile.Bytes, decoded.ManifestFile.Bytes);
        Assert.Equal((byte[])guardianRecord.ElectionBaseHash, (byte[])decoded.ElectionBaseHash);
        Assert.Equal(guardianRecord.Guardians.Select(x => x.Index.Index), decoded.Guardians.Select(x => x.Index.Index));
    }

    public static TheoryData<string, string> SetupTampers() => new()
    {
        { "commitment K_i,0", "2.A" },
        { "commitment", "2.A" },
        { "kappa", "2.A" },
        { "guardian index 0", "2.A" },
        { "response", "2.B" },
        { "challenge", "2.C" },
        { "K", "3.A" },
        { "K-hat", "3.B" },
        { "version", "1.A" },
        { "n below k", "1.structure" },
    };

    /// <summary>
    /// The items each setup verification reads, written out from design §4.8 rather than taken from
    /// <see cref="SetupMapper"/>, so that a change to the production read sets fails a test instead
    /// of moving the expectations with it.
    /// </summary>
    private static readonly Dictionary<int, string[]> SetupReads = new()
    {
        [1] = ["parameters", "manifest_file"],
        [2] = ["guardian_public_key"],
        [3] = ["guardian_public_key", "election_keys"],
    };

    [Fact]
    public void Setup_ReadSets_AreTheDesigns()
    {
        Assert.Equal(SetupReads[1].Order(StringComparer.Ordinal), SetupMapper.ReadByVerification1.Order(StringComparer.Ordinal));
        Assert.Equal(SetupReads[2].Order(StringComparer.Ordinal), SetupMapper.ReadByVerification2.Order(StringComparer.Ordinal));
        Assert.Equal(SetupReads[3].Order(StringComparer.Ordinal), SetupMapper.ReadByVerification3.Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// Design §4.8 per item: the setup is several record items, and a finding leaves another
    /// verification not evaluable only if it reads that item. Verification 1 reads the parameters
    /// and the manifest, 2 the guardian keys, 3 the guardian keys and the election keys
    /// (<see cref="SetupReads"/>); the verifications that read nothing of the tampered item still run
    /// and pass. K_i,0 is the commitment Verification 3 multiplies into K, so if 3 stopped reading the
    /// guardian item it would fail on the placeholder there rather than be not evaluable.
    /// </summary>
    [Theory]
    [MemberData(nameof(SetupTampers))]
    public void Setup_ValueOutOfRange_IsReportedUnderItsCode(string tamper, string expected)
    {
        var election = Shared.Value;
        var items = SetupMapper.ToItems(RecordSetup.FromEncryptionRecord(election.Record)).Select(x => x.Clone()).ToList();
        var guardian = items[3].GuardianPublicKey;
        string item = "guardian_public_key";
        switch (tamper)
        {
            case "commitment K_i,0": guardian.VoteCommitments = ByteString.CopyFrom([.. NotBelowP.Span, .. guardian.VoteCommitments.Span[512..]]); break;
            case "commitment": guardian.VoteCommitments = ByteString.CopyFrom([.. guardian.VoteCommitments.Span[..512], .. NotBelowP.Span]); break;
            case "kappa": guardian.Kappa = NotBelowP; break;
            case "guardian index 0": guardian.Index = 0; break;
            case "response": guardian.DataProof = ByteString.CopyFrom([.. guardian.DataProof.Span[..32], .. NotBelowQ.Span, .. guardian.DataProof.Span[64..]]); break;
            case "challenge": guardian.VoteProof = ByteString.CopyFrom([.. NotBelowQ.Span, .. guardian.VoteProof.Span[32..]]); break;
            case "K": items[^1].ElectionKeys.K = NotBelowP; item = "election_keys"; break;
            case "K-hat": items[^1].ElectionKeys.KHat = NotBelowP; item = "election_keys"; break;
            case "version": items[1].Parameters.Version = ByteString.CopyFrom([.. "v2.1.0"u8, 0, (byte)'x', .. new byte[24]]); item = "parameters"; break;
            case "n below k": items[1].Parameters.K = 4; item = "parameters"; break;
        }

        var decoded = SetupMapper.FromItems(items.Select(ThroughBytes).ToList());

        Assert.Null(decoded.Value);
        var finding = Assert.Single(decoded.Findings);
        Assert.Equal((expected, item), (finding.SubSection, finding.Item));
        var verifications = new (int Number, IReadOnlyCollection<string> Reads, Action Verify)[]
        {
            (1, SetupReads[1], () => new ParameterVerification().Verify(decoded)),
            (2, SetupReads[2], () => new GuardianPublicKeyVerification().Verify(decoded)),
            (3, SetupReads[3], () => new ElectionPublicKeyVerification().Verify(decoded)),
        };
        foreach (var (number, reads, verify) in verifications)
        {
            if (expected.StartsWith($"{number}.", StringComparison.Ordinal))
            {
                Assert.Equal(expected, Assert.Throws<VerificationFailedException>(verify).SubSection);
            }
            else if (reads.Contains(item))
            {
                Assert.Equal(expected, Assert.Throws<RecordItemNotEvaluableException>(verify).Cause.SubSection);
            }
            else
            {
                verify();
            }
        }
    }

    // ---- ballots --------------------------------------------------------------------------------

    /// <summary>Every status, a weight of 2, a timestamp, contest data and supplemental fields; the device id comes from the section.</summary>
    [Fact]
    public void EncryptedBallots_RoundTrip_AndPassVerifications5To8()
    {
        var election = Shared.Value;
        foreach (var ballot in election.Ballots)
        {
            var item = BallotMapper.ToItem(ballot, election.Manifest);
            var decoded = BallotMapper.FromItem(ThroughBytes(item), election.Manifest, DeviceId);
            var value = Assert.IsType<EncryptedBallot>(decoded.Value);

            Assert.Equal(item.ToByteArray(), BallotMapper.ToItem(value, election.Manifest).ToByteArray());
            Assert.Equal((ballot.Id, ballot.Status, ballot.Weight, ballot.EncryptionTimestamp, DeviceId), (value.Id, value.Status, value.Weight, value.EncryptionTimestamp, value.DeviceId));
            Assert.Equal(ballot.Contests.Single().Choices.Select(x => x.ChoiceId), value.Contests.Single().Choices.Select(x => x.ChoiceId));
            Assert.Equal(ballot.Contests.Single().SupplementalFields.Select(x => x.FieldId), value.Contests.Single().SupplementalFields.Select(x => x.FieldId));
            Assert.Equal(ballot.Contests.Single().ContestData!.C1, value.Contests.Single().ContestData!.C1);

            new SelectionEncryptionIdentifierVerification().Verify(value.SelectionEncryptionIdentifier, value.SelectionEncryptionIdentifierHash, election.Record.ExtendedBaseHash);
            new SelectionEncryptionsWellFormedVerification().Verify(decoded, election.Record);
            new AdherenceToVoteLimitsVerification().Verify(decoded, election.Record);
            new ConfirmationCodeVerification().Verify(decoded, election.Record);
        }

        var decodedAll = election.Ballots.Select(x => BallotMapper.FromItem(ThroughBytes(BallotMapper.ToItem(x, election.Manifest)), election.Manifest, DeviceId).Value!).ToList();
        new ConfirmationCodeVerification().VerifyDevice(election.Device, decodedAll, election.Record);
    }

    /// <summary>A ballot without a ballot_ref decodes under the hex of its id_B, which no hash binds either.</summary>
    [Fact]
    public void EncryptedBallot_WithoutBallotRef_IsNamedByItsIdentifier()
    {
        var election = Shared.Value;
        var item = BallotMapper.ToItem(election.Ballots[0], election.Manifest);
        item.EncryptedBallot.BallotRef = "";

        var value = BallotMapper.FromItem(ThroughBytes(item), election.Manifest, DeviceId).Value!;

        Assert.Equal(Convert.ToHexStringLower((byte[])election.Ballots[0].SelectionEncryptionIdentifier), value.Id);
        new SelectionEncryptionsWellFormedVerification().Verify(value, election.Record);
    }

    [Fact]
    public void EncryptedBallot_TheWriterRefusesWhatTheRecordCannotCarry()
    {
        var election = Shared.Value;
        var ballot = election.Ballots[0];
        EncryptedBallot With(BallotStatus status, int weight = 1, DateTimeOffset? at = null) => new()
        {
            Id = ballot.Id, SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier, SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
            BallotStyleId = ballot.BallotStyleId, Contests = ballot.Contests, ConfirmationCode = ballot.ConfirmationCode, ChainingField = ballot.ChainingField,
            EncryptedBallotNonce = ballot.EncryptedBallotNonce, DeviceId = ballot.DeviceId, Weight = weight, Status = status, EncryptionTimestamp = at,
        };

        Assert.Throws<ArgumentException>(() => BallotMapper.ToItem(With(BallotStatus.Unrecorded), election.Manifest));
        Assert.Throws<ArgumentException>(() => BallotMapper.ToItem(With(BallotStatus.Cast, weight: 0), election.Manifest));
        Assert.Throws<ArgumentException>(() => BallotMapper.ToItem(With(BallotStatus.Cast, at: new DateTimeOffset(1969, 12, 31, 23, 59, 59, TimeSpan.Zero)), election.Manifest));
    }

    public static TheoryData<string, string> BallotTampers() => new()
    {
        { "alpha", "6.A" },
        { "beta", "6.A" },
        { "range proof c", "6.B" },
        { "range proof v", "6.C" },
        { "limit proof c", "7.B" },
        { "limit proof v", "7.C" },
        { "undervote difference proof c", "7.B" },
        { "null-vote proof v", "7.C" },
        { "contest data C0", "8.structure" },
        { "contest data v", "8.structure" },
        { "ballot nonce C0", "13.structure" },
        { "ballot nonce c_B", "13.structure" },
        { "ballot nonce v_B", "13.structure" },
    };

    /// <summary>
    /// Design §4.8: a value ≥ p or ≥ q decodes (the format checks widths only, user decision #11),
    /// and is reported under its lettered check by the verification it belongs to; the item is then
    /// not handed to any domain verifier, so the other verifications that read it (6, 7, 8, and 12 and
    /// 13 through the decryptions that open it) are not evaluable on it.
    /// </summary>
    [Theory]
    [MemberData(nameof(BallotTampers))]
    public void EncryptedBallot_ValueOutOfRange_IsReportedUnderItsCode(string tamper, string expected)
    {
        var election = Shared.Value;

        // C_ξB is read by Verification 13, which runs on challenged ballots: tamper that one there.
        var item = BallotMapper.ToItem(expected.StartsWith("13.", StringComparison.Ordinal) ? election.ChallengedBallot : election.Ballots[0], election.Manifest);
        var nonce = item.EncryptedBallot.EncryptedBallotNonce;
        var contest = item.EncryptedBallot.Contests[0];
        var field = contest.Fields[0];
        switch (tamper)
        {
            case "alpha": field.Alpha = NotBelowP; break;
            case "beta": field.Beta = NotBelowP; break;
            case "range proof c": field.RangeProof = WithFirstHalf(field.RangeProof, NotBelowQ); break;
            case "range proof v": field.RangeProof = ByteString.CopyFrom([.. field.RangeProof.Span[..32], .. NotBelowQ.Span, .. field.RangeProof.Span[64..]]); break;
            case "limit proof c": contest.LimitProof = WithFirstHalf(contest.LimitProof, NotBelowQ); break;
            case "limit proof v": contest.LimitProof = ByteString.CopyFrom([.. contest.LimitProof.Span[..32], .. NotBelowQ.Span, .. contest.LimitProof.Span[64..]]); break;
            case "undervote difference proof c": contest.UndervoteDifferenceProof = WithFirstHalf(contest.UndervoteDifferenceProof, NotBelowQ); break;
            case "null-vote proof v": contest.NullVoteProof = ByteString.CopyFrom([.. contest.NullVoteProof.Span[..32], .. NotBelowQ.Span, .. contest.NullVoteProof.Span[64..]]); break;
            case "contest data C0": contest.ContestData.C0 = NotBelowP; break;
            case "contest data v": contest.ContestData.C2 = WithSecondHalf(contest.ContestData.C2, NotBelowQ); break;
            case "ballot nonce C0": nonce.C0 = NotBelowP; break;
            case "ballot nonce c_B": nonce.C2 = WithFirstHalf(nonce.C2, NotBelowQ); break;
            case "ballot nonce v_B": nonce.C2 = WithSecondHalf(nonce.C2, NotBelowQ); break;
        }

        Assert.False(contest.UndervoteDifferenceProof.IsEmpty || contest.NullVoteProof.IsEmpty, "the fixture tracks the undervote difference and the null vote");
        var decoded = BallotMapper.FromItem(ThroughBytes(item), election.Manifest, DeviceId);

        Assert.Null(decoded.Value);
        Assert.Equal(expected, Assert.Single(decoded.Findings).SubSection);
        var contestData = DecryptionMapper.FromItem(ThroughBytes(DecryptionMapper.ToItem(election.ContestData[0], election.Ballots[0], election.Index)).ContestDataDecryption, election.Index, election.Manifest);
        var challenged = DecryptionMapper.FromItem(ThroughBytes(DecryptionMapper.ToItem(election.Challenged, election.ChallengedBallot, election.Index, election.Manifest)).ChallengedBallotDecryption, election.Index, election.Manifest);
        var verifications = new Dictionary<int, Action>
        {
            [6] = () => new SelectionEncryptionsWellFormedVerification().Verify(decoded, election.Record),
            [7] = () => new AdherenceToVoteLimitsVerification().Verify(decoded, election.Record),
            [8] = () => new ConfirmationCodeVerification().Verify(decoded, election.Record),
            [12] = () => new ContestDataDecryptionVerification().Verify(election.Record, decoded, contestData),
            [13] = () => new ChallengedBallotDecryptionVerification().Verify(election.Record, decoded, challenged),
        };
        foreach (var (number, verify) in verifications)
        {
            if (expected.StartsWith($"{number}.", StringComparison.Ordinal))
            {
                Assert.Equal(expected, Assert.Throws<VerificationFailedException>(verify).SubSection);
            }
            else
            {
                Assert.Equal(expected, Assert.Throws<RecordItemNotEvaluableException>(verify).Cause.SubSection);
            }
        }
    }

    /// <summary>
    /// The manifest never makes decoding fail: a contest index it lacks and a field past its own
    /// decode under ids that are not text, and Verification 6's structure check reports them.
    /// </summary>
    [Fact]
    public void EncryptedBallot_ContestOrFieldTheManifestLacks_DecodesAndFailsStructure()
    {
        var election = Shared.Value;
        var item = BallotMapper.ToItem(election.Ballots[0], election.Manifest);
        item.EncryptedBallot.Contests[0].Fields.Add(item.EncryptedBallot.Contests[0].Fields[0].Clone());
        var extraField = BallotMapper.FromItem(ThroughBytes(item), election.Manifest, DeviceId).Value!;
        Assert.Equal("6.structure", Assert.Throws<VerificationFailedException>(() => new SelectionEncryptionsWellFormedVerification().Verify(extraField, election.Record)).SubSection);

        var other = BallotMapper.ToItem(election.Ballots[0], election.Manifest);
        other.EncryptedBallot.Contests[0].Index = 9;
        var unknownContest = BallotMapper.FromItem(ThroughBytes(other), election.Manifest, DeviceId).Value!;
        Assert.StartsWith("\0contest-9", unknownContest.Contests[0].Id, StringComparison.Ordinal);
        Assert.Equal("6.structure", Assert.Throws<VerificationFailedException>(() => new SelectionEncryptionsWellFormedVerification().Verify(unknownContest, election.Record)).SubSection);
    }

    // ---- pre-encrypted ballots ------------------------------------------------------------------

    [Fact]
    public void PreEncryptedCastBallot_RoundTrips_AndPassesVerifications6_7And15()
    {
        var election = PreEncryptedElection.Get();
        var (_, cast) = election.Cast("p-map-1", [2], [1]);

        var item = BallotMapper.ToItem(cast, election.Manifest);
        Assert.Equal(Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot, item.ItemCase);
        var decoded = BallotMapper.FromItem(ThroughBytes(item), election.Manifest, PreEncryptedElection.DeviceId);
        var value = decoded.Value!;

        Assert.True(value.IsPreEncrypted);
        Assert.Equal(BallotStatus.Cast, value.Status);
        Assert.Equal(item.ToByteArray(), BallotMapper.ToItem(value, election.Manifest).ToByteArray());
        new SelectionEncryptionsWellFormedVerification().Verify(decoded, election.Record);
        new AdherenceToVoteLimitsVerification().Verify(decoded, election.Record);
        new SelectionVectorAccumulationVerification().Verify(value, election.Record);
        new ShortCodeVerification().Verify(value, election.Record);
    }

    public static TheoryData<string, string> PreEncryptedCastTampers() => new()
    {
        { "selected vector alpha", "6.A" },
        { "selected vector beta", "6.A" },
        { "combined field alpha", "6.A" },
        { "combined range proof c", "6.B" },
        { "combined range proof v", "6.C" },
        { "combined limit proof c", "7.B" },
    };

    /// <summary>
    /// Design §4.8 for a cast pre-encrypted ballot: the combined vectors and the selected vectors are
    /// selection encryptions (§4.5 p.64, "including all individual selection encryptions within the
    /// selection vectors on pre-encrypted ballots"), so a value ≥ p is 6.A, and the combined
    /// vectors' proofs are 6.B/6.C and 7.B like a regular ballot's. Verification 8 does not apply to a
    /// pre-encrypted ballot (16 does, and is the device pass's).
    /// </summary>
    [Theory]
    [MemberData(nameof(PreEncryptedCastTampers))]
    public void PreEncryptedCastBallot_ValueOutOfRange_IsReportedUnderItsCode(string tamper, string expected)
    {
        var election = PreEncryptedElection.Get();
        var (_, cast) = election.Cast($"p-map-{tamper.GetHashCode():x}", [2], [1]);
        var item = BallotMapper.ToItem(cast, election.Manifest);
        var contest = item.PreEncryptedCastBallot.Contests[0];
        var selected = contest.Selected[0];
        var field = contest.Contest.Fields[0];
        switch (tamper)
        {
            case "selected vector alpha": selected.Vector = ByteString.CopyFrom([.. NotBelowP.Span, .. selected.Vector.Span[512..]]); break;
            case "selected vector beta": selected.Vector = ByteString.CopyFrom([.. selected.Vector.Span[..512], .. NotBelowP.Span, .. selected.Vector.Span[1024..]]); break;
            case "combined field alpha": field.Alpha = NotBelowP; break;
            case "combined range proof c": field.RangeProof = WithFirstHalf(field.RangeProof, NotBelowQ); break;
            case "combined range proof v": field.RangeProof = ByteString.CopyFrom([.. field.RangeProof.Span[..32], .. NotBelowQ.Span, .. field.RangeProof.Span[64..]]); break;
            case "combined limit proof c": contest.Contest.LimitProof = WithFirstHalf(contest.Contest.LimitProof, NotBelowQ); break;
        }

        var decoded = BallotMapper.FromItem(ThroughBytes(item), election.Manifest, PreEncryptedElection.DeviceId);

        Assert.Null(decoded.Value);
        Assert.Equal(expected, Assert.Single(decoded.Findings).SubSection);
        var six = () => new SelectionEncryptionsWellFormedVerification().Verify(decoded, election.Record);
        var seven = () => new AdherenceToVoteLimitsVerification().Verify(decoded, election.Record);
        bool isSix = expected.StartsWith("6.", StringComparison.Ordinal);
        Assert.Equal(expected, Assert.Throws<VerificationFailedException>(isSix ? six : seven).SubSection);
        Assert.Equal(expected, Assert.Throws<RecordItemNotEvaluableException>(isSix ? seven : six).Cause.SubSection);
    }

    /// <summary>
    /// Verification 6 covers a cast pre-encrypted ballot's selected vectors (§4.5 p.64), not only the
    /// combined vector. Negating the same entry of both of contest 2's selected vectors (L = 2) puts
    /// two in-range non-members on the record whose product is the combined vector's member, so
    /// Verification 15 still passes, as do 6.B-6.D on the combined vector; only the selected vectors'
    /// own 6.A catches them. Rows: an α, a β, and an entry past the first option. The last row also
    /// breaks contest 1's combined range proof (a challenge changed but still below q, so the
    /// decoder and the structural checks pass and the fused path runs): 6.A must still come first
    /// (CLAUDE.md), which holds only while the selected vectors are checked before the combined
    /// vectors' proofs.
    /// </summary>
    [Theory]
    [InlineData(0, false, false)]
    [InlineData(0, true, false)]
    [InlineData(3, true, false)]
    [InlineData(0, false, true)]
    public void PreEncryptedCastBallot_Verification6_ChecksEverySelectedVectorEntryIsInTheSubgroup(int k, bool beta, bool breakEarlierProof)
    {
        var election = PreEncryptedElection.Get();
        var (_, cast) = election.Cast($"p-map-six-{k}-{beta}-{breakEarlierProof}", [2], [1]);
        var item = BallotMapper.ToItem(cast, election.Manifest);
        if (breakEarlierProof)
        {
            // c_0 of contest 1's first combined field, low bit flipped: c is uniform in Z_q, so it stays below q.
            var field = item.PreEncryptedCastBallot.Contests[0].Contest.Fields[0];
            byte[] proof = field.RangeProof.ToByteArray();
            proof[31] ^= 1;
            field.RangeProof = ByteString.CopyFrom(proof);
        }

        var contest = item.PreEncryptedCastBallot.Contests[1];
        Assert.Equal(2, contest.Selected.Count);
        int offset = k * 1024 + (beta ? 512 : 0);
        foreach (var selected in contest.Selected)
        {
            // p - x: below p, but -1 has order 2, so -x is not in the order-q subgroup.
            byte[] negated = (EGParameters.P - new System.Numerics.BigInteger(selected.Vector.Span[offset..(offset + 512)], isUnsigned: true, isBigEndian: true)).ToBigEndianPadded(512);
            selected.Vector = ByteString.CopyFrom([.. selected.Vector.Span[..offset], .. negated, .. selected.Vector.Span[(offset + 512)..]]);
        }

        var decoded = BallotMapper.FromItem(ThroughBytes(item), election.Manifest, PreEncryptedElection.DeviceId);

        Assert.Empty(decoded.Findings);
        new SelectionVectorAccumulationVerification().Verify(decoded.Value!, election.Record);
        new AdherenceToVoteLimitsVerification().Verify(decoded, election.Record);
        var failure = Assert.Throws<VerificationFailedException>(() => new SelectionEncryptionsWellFormedVerification().Verify(decoded, election.Record));
        Assert.Equal("6.A", failure.SubSection);
        Assert.Contains($"{(beta ? "β" : "α")}_{k + 1}", failure.Message, StringComparison.Ordinal);
        Assert.Equal("6.A", Assert.Throws<VerificationFailedException>(() => new SelectionEncryptionsWellFormedVerification().Verify(decoded.Value!, election.Record)).SubSection);
    }

    /// <summary>
    /// User decision R-1: the printed form follows from what is released. Without ξ_B, the full item
    /// and the per-selection nonces; the joined ballot passes Verifications 16, 18 and 19 and
    /// splits back to the same bytes.
    /// </summary>
    [Fact]
    public void UncastBallot_FullForm_SplitsAndJoins()
    {
        var election = PreEncryptedElection.Get();
        var uncast = election.Uncast("u-map-full");
        var locator = new BallotLocator(new DeviceKey(DeviceChainBallotKind.PreEncrypted, election.DeviceHash), 3);

        var (printed, release) = UncastMapper.Split(uncast, locator);
        Assert.Equal(Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot, printed.ItemCase);
        Assert.True(release.UncastNonceRelease.BallotNonce.IsEmpty);
        var joined = UncastMapper.Join(ThroughBytes(printed), ThroughBytes(release), election.Record, PreEncryptedElection.DeviceId);
        var value = joined.Value!;

        var (printedAgain, releaseAgain) = UncastMapper.Split(value, locator);
        Assert.Equal(printed.ToByteArray(), printedAgain.ToByteArray());
        Assert.Equal(release.ToByteArray(), releaseAgain.ToByteArray());
        new UncastBallotEncryptionVerification().Verify(joined, election.Record);
        new UncastBallotContentVerification().Verify(election.Manifest, value);
        new PreEncryptedConfirmationCodeVerification().Verify(joined, election.DeviceHash, election.Record, null);
    }

    /// <summary>
    /// NQ-2 and R-1: with ξ_B released, the compact item (index and χ per contest, H_C, B_C) and a
    /// release of ξ_B alone. The verifier regenerates the vectors from ξ_B; the joined ballot passes
    /// Verifications 16 and 18 and splits back to the same bytes, which shows the compact form loses
    /// nothing the record needs.
    /// </summary>
    [Fact]
    public void UncastBallot_CompactForm_SplitsAndJoinsByRegeneratingFromTheBallotNonce()
    {
        var election = PreEncryptedElection.Get();
        var uncast = election.Uncast("u-map-compact", releaseBallotNonce: true);
        var locator = new BallotLocator(new DeviceKey(DeviceChainBallotKind.PreEncrypted, election.DeviceHash), 4);

        var (printed, release) = UncastMapper.Split(uncast, locator);
        Assert.Equal(Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot, printed.ItemCase);
        Assert.Empty(release.UncastNonceRelease.Contests);
        Assert.True(printed.CalculateSize() < UncastMapper.ToPrintedItem(uncast.Ballot, compact: false).CalculateSize() / 10);
        var joined = UncastMapper.Join(ThroughBytes(printed), ThroughBytes(release), election.Record, PreEncryptedElection.DeviceId);
        var value = joined.Value!;

        var (printedAgain, releaseAgain) = UncastMapper.Split(value, locator);
        Assert.Equal(printed.ToByteArray(), printedAgain.ToByteArray());
        Assert.Equal(release.ToByteArray(), releaseAgain.ToByteArray());
        Assert.Equal(UncastMapper.ToPrintedItem(uncast.Ballot, compact: false).ToByteArray(), UncastMapper.ToPrintedItem(value.Ballot, compact: false).ToByteArray());
        new UncastBallotEncryptionVerification().Verify(joined, election.Record);
        new PreEncryptedConfirmationCodeVerification().Verify(joined, election.DeviceHash, election.Record, null);
    }

    /// <summary>A compact item whose sealed χ is not the one ξ_B regenerates fails Verification 16 (the regenerated ψ do not hash to it).</summary>
    [Fact]
    public void UncastBallot_CompactItemWithAnotherContestHash_Fails16()
    {
        var election = PreEncryptedElection.Get();
        var uncast = election.Uncast("u-map-chi", releaseBallotNonce: true);
        var (printed, release) = UncastMapper.Split(uncast, new BallotLocator(new DeviceKey(DeviceChainBallotKind.PreEncrypted, election.DeviceHash), 1));
        printed.PreEncryptedCompactUncastBallot.Contests[0].ContestHash = ByteString.CopyFrom(new byte[32]);

        var joined = UncastMapper.Join(ThroughBytes(printed), ThroughBytes(release), election.Record, PreEncryptedElection.DeviceId);

        Assert.StartsWith("16.", Assert.Throws<VerificationFailedException>(() => new PreEncryptedConfirmationCodeVerification().Verify(joined, election.DeviceHash, election.Record, null)).SubSection);
    }

    public static TheoryData<string, string> UncastTampers() => new()
    {
        { "full item, release carries xi_B", "18.structure" },
        { "compact item, release carries nonces", "18.structure" },
        { "compact item, release lacks xi_B", "18.structure" },
        { "release names another H_I", "18.structure" },
        { "released nonce not below q", "18.structure" },
        { "encrypted ballot nonce C0 not below p", "18.structure" },
        { "printed alpha not below p", "6.A" },
        { "compact item of an unknown style", "16.structure" },
        { "printed contests out of index order", "16.structure" },
        { "printed vectors out of selection-index order", "16.structure" },
        { "released contests out of index order", "18.structure" },
        { "compact item, contests out of index order", "16.structure" },
    };

    [Theory]
    [MemberData(nameof(UncastTampers))]
    public void UncastBallot_ReleaseOrValueOutOfShape_IsReportedUnderItsCode(string tamper, string expected)
    {
        var election = PreEncryptedElection.Get();
        bool compact = tamper.StartsWith("compact", StringComparison.Ordinal);
        var uncast = election.Uncast($"u-map-{tamper.GetHashCode():x}", releaseBallotNonce: compact);
        var (printed, release) = UncastMapper.Split(uncast, new BallotLocator(new DeviceKey(DeviceChainBallotKind.PreEncrypted, election.DeviceHash), 2));
        var opening = release.UncastNonceRelease;
        switch (tamper)
        {
            case "full item, release carries xi_B": opening.BallotNonce = ByteString.CopyFrom(new byte[32]); break;
            case "compact item, release carries nonces": opening.Contests.Add(new Pb.UncastContestNonces { Index = 1, Nonces = ByteString.CopyFrom(new byte[32]) }); break;
            case "compact item, release lacks xi_B": opening.BallotNonce = ByteString.Empty; break;
            case "encrypted ballot nonce C0 not below p": printed.PreEncryptedUncastBallot.EncryptedBallotNonce.C0 = NotBelowP; break;
            case "release names another H_I": opening.HI = ByteString.CopyFrom(new byte[32]); break;
            case "released nonce not below q": opening.Contests[0].Nonces = ByteString.CopyFrom([.. NotBelowQ.Span, .. opening.Contests[0].Nonces.Span[32..]]); break;
            case "printed alpha not below p":
                var selection = printed.PreEncryptedUncastBallot.Contests[0].Selections[0];
                selection.Vector = ByteString.CopyFrom([.. NotBelowP.Span, .. selection.Vector.Span[512..]]);
                break;
            case "compact item of an unknown style": printed.PreEncryptedCompactUncastBallot.BallotStyle = "no-such-style"; break;
            case "printed contests out of index order": Swap(printed.PreEncryptedUncastBallot.Contests); break;
            case "printed vectors out of selection-index order": Swap(printed.PreEncryptedUncastBallot.Contests[0].Selections); break;
            case "released contests out of index order": Swap(opening.Contests); break;
            case "compact item, contests out of index order": Swap(printed.PreEncryptedCompactUncastBallot.Contests); break;
        }

        static void Swap<T>(Google.Protobuf.Collections.RepeatedField<T> list) => (list[0], list[1]) = (list[1], list[0]);

        var joined = UncastMapper.Join(ThroughBytes(printed), ThroughBytes(release), election.Record, PreEncryptedElection.DeviceId);

        Assert.Null(joined.Value);
        Assert.Equal(expected, Assert.Single(joined.Findings).SubSection);
        var verifications = new Dictionary<int, Action>
        {
            [6] = () => new SelectionEncryptionsWellFormedVerification().Verify(joined),
            [16] = () => new PreEncryptedConfirmationCodeVerification().Verify(joined, election.DeviceHash, election.Record, null),
            [18] = () => new UncastBallotEncryptionVerification().Verify(joined, election.Record),
        };
        foreach (var (number, verify) in verifications)
        {
            if (expected.StartsWith($"{number}.", StringComparison.Ordinal))
            {
                Assert.Equal(expected, Assert.Throws<VerificationFailedException>(verify).SubSection);
            }
            else
            {
                Assert.Equal(expected, Assert.Throws<RecordItemNotEvaluableException>(verify).Cause.SubSection);
            }
        }
    }

    /// <summary>
    /// Verification 6 covers an uncast ballot's pre-encryption vectors (§4.5 p.64): with every value
    /// in range, the joined ballot passes it, and a vector entry in range but outside Z_p^r fails 6.A
    /// (Verification 18 fails too: the entry is not g^ξ). Rows: an α and a β of the first vector of
    /// the first contest, an entry past the first option, and the last vector of the last contest.
    /// </summary>
    [Theory]
    [InlineData("first contest, first vector, α_1", false, false, 0, false)]
    [InlineData("first contest, first vector, β_1", false, false, 0, true)]
    [InlineData("first contest, first vector, β_3", false, false, 2, true)]
    [InlineData("last contest, last vector, α_4", true, true, 3, false)]
    public void UncastBallot_Verification6_ChecksEveryVectorEntryIsInTheSubgroup(string row, bool lastContest, bool lastVector, int k, bool beta)
    {
        var election = PreEncryptedElection.Get();
        var uncast = election.Uncast($"u-map-six-{row.GetHashCode():x}");
        var (printed, release) = UncastMapper.Split(uncast, new BallotLocator(new DeviceKey(DeviceChainBallotKind.PreEncrypted, election.DeviceHash), 5));
        var joined = UncastMapper.Join(ThroughBytes(printed), ThroughBytes(release), election.Record, PreEncryptedElection.DeviceId);
        new SelectionEncryptionsWellFormedVerification().Verify(joined);

        var contests = printed.PreEncryptedUncastBallot.Contests;
        var contest = lastContest ? contests[^1] : contests[0];
        var selection = lastVector ? contest.Selections[^1] : contest.Selections[0];
        int offset = k * 1024 + (beta ? 512 : 0);
        Assert.True(selection.Vector.Length >= offset + 512, row);
        // p - x: below p, but -1 has order 2, so -x is not in the order-q subgroup.
        byte[] negated = (EGParameters.P - new System.Numerics.BigInteger(selection.Vector.Span[offset..(offset + 512)], isUnsigned: true, isBigEndian: true)).ToBigEndianPadded(512);
        selection.Vector = ByteString.CopyFrom([.. selection.Vector.Span[..offset], .. negated, .. selection.Vector.Span[(offset + 512)..]]);
        var nonMember = UncastMapper.Join(ThroughBytes(printed), ThroughBytes(release), election.Record, PreEncryptedElection.DeviceId);

        Assert.Empty(nonMember.Findings);
        var failure = Assert.Throws<VerificationFailedException>(() => new SelectionEncryptionsWellFormedVerification().Verify(nonMember));
        Assert.Equal("6.A", failure.SubSection);
        Assert.Contains($"contest {contest.Label}, vector {selection.SelectionIndex}: {(beta ? "β" : "α")}_{k + 1}", failure.Message, StringComparison.Ordinal);
        Assert.StartsWith("18.", Assert.Throws<VerificationFailedException>(() => new UncastBallotEncryptionVerification().Verify(nonMember, election.Record)).SubSection);
    }

    // ---- device sections ------------------------------------------------------------------------

    [Fact]
    public void DeviceChainRecord_RoundTripsAsHeaderAndClose_WithTheCodesFromTheSection()
    {
        var election = Shared.Value;
        var closedAt = new DateTimeOffset(2026, 11, 3, 20, 0, 0, 5, TimeSpan.Zero);
        var (header, close) = DeviceMapper.ToItems(election.Device, closedAt);

        var decodedHeader = DeviceMapper.FromItem(ThroughBytes(header).DeviceHeader);
        var decodedClose = DeviceMapper.FromItem(ThroughBytes(close).DeviceClose);
        var record = DeviceMapper.FromItems(decodedHeader, decodedClose, election.Ballots.Select(x => x.ConfirmationCode));

        Assert.Equal(DeviceChainBallotKind.Encrypted, decodedHeader.Kind);
        Assert.Equal(1, (int)header.DeviceHeader.Kind);
        Assert.Equal(election.Ballots.Count, decodedClose.BallotCount);
        Assert.Equal(closedAt, decodedClose.ClosedAt);
        Assert.Equal(header.ToByteArray(), DeviceMapper.ToItem(decodedHeader).ToByteArray());
        Assert.Equal(close.ToByteArray(), DeviceMapper.ToItem(decodedClose).ToByteArray());
        new ConfirmationCodeVerification().VerifyDevice(record, election.Ballots, election.Record);

        // Under no chaining the omittable fields are absent and the mode is 0, so not written (W2).
        var none = new DeviceHeader(DeviceChainBallotKind.PreEncrypted, "printer", election.Device.DeviceInformationHash, ChainingMode.None, null);
        var noneItem = ThroughBytes(DeviceMapper.ToItem(none));
        Assert.Equal(none, DeviceMapper.FromItem(noneItem.DeviceHeader));
        Assert.Equal(2, (int)noneItem.DeviceHeader.Kind);
        Assert.Equal(new DeviceClose(0, null, null, null), DeviceMapper.FromItem(ThroughBytes(DeviceMapper.ToItem(new DeviceClose(0, null, null, null))).DeviceClose));
    }

    [Fact]
    public void BallotLocatorsAndContestDataRequests_RoundTrip()
    {
        var election = Shared.Value;
        var (locator, identifierHash) = election.Index.Locate(election.Ballots[1].SelectionEncryptionIdentifierHash);
        Assert.Equal(2, locator.Position);
        var request = new ContestDataRequest(locator, identifierHash, 1);

        var decoded = DecryptionMapper.FromItem(ThroughBytes(DecryptionMapper.ToItem(request)).ContestDataRequest).Value!;

        Assert.Equal(request.Ballot, decoded.Ballot);
        Assert.Equal((byte[])request.IdentifierHash, (byte[])decoded.IdentifierHash);
        Assert.Equal(request.ContestIndex, decoded.ContestIndex);
        Assert.Throws<ArgumentOutOfRangeException>(() => DeviceMapper.ToItem(locator with { Position = 0 }));

        // A request that names no ballot is canonical (D1/D2 cover no absent message), so it is a
        // finding under the request join rule's code, not a decoder exception.
        var unnamed = DecryptionMapper.ToItem(request);
        unnamed.ContestDataRequest.Ballot = null;
        var orphan = DecryptionMapper.FromItem(ThroughBytes(unnamed).ContestDataRequest);
        Assert.Null(orphan.Value);
        Assert.Equal("12.structure", Assert.Single(orphan.Findings).SubSection);
    }

    // ---- tallies --------------------------------------------------------------------------------

    [Fact]
    public void EncryptedTally_RoundTrips_AndPassesVerification9()
    {
        var election = Shared.Value;
        var items = TallyMapper.ToItems(election.Tally).Select(ThroughBytes).ToList();

        var header = TallyMapper.Header(items[0].EncryptedTallyHeader);
        var decoded = TallyMapper.FromItems(items[0].EncryptedTallyHeader, items.Skip(1).Select(x => x.EncryptedTallyContest), election.Manifest);
        var value = decoded.Value!;

        Assert.Equal(new EncryptedTallyHeader(2, 3), header);
        Assert.Equal((2, 3L), (value.BallotsCast, value.TotalCastWeight));
        Assert.Equal(items.Select(x => x.ToByteArray()), TallyMapper.ToItems(value).Select(x => x.ToByteArray()));
        Assert.Equal(election.Tally.Contests.Values.SelectMany(x => x.Choices.Values).Select(x => x.MaximumCount), value.Contests.Values.SelectMany(x => x.Choices.Values).Select(x => x.MaximumCount));
        new BallotAggregationVerification().Verify(election.Ballots.Select(DecodedBallot), election.Manifest, decoded);
    }

    /// <summary>
    /// Design §4.8, a verification gates every item it reads: a cast ballot item with a range finding
    /// has no domain object, so the recomputed aggregate would miss a factor, and Verification 9 is
    /// not evaluable rather than failing 9.A falsely. A spoiled ballot's finding does not matter to it.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(-1)]
    public void Verification9_ACastBallotItemWithAFinding_IsNotEvaluable_ASpoiledOneIsLeftOut(int maxDegreeOfParallelism)
    {
        var election = Shared.Value;
        var items = TallyMapper.ToItems(election.Tally).Select(ThroughBytes).ToList();
        var tally = TallyMapper.FromItems(items[0].EncryptedTallyHeader, items.Skip(1).Select(x => x.EncryptedTallyContest), election.Manifest);
        RecordDecoded<EncryptedBallot> Decode(EncryptedBallot ballot, bool tamper)
        {
            var item = BallotMapper.ToItem(ballot, election.Manifest);
            if (tamper)
            {
                item.EncryptedBallot.Contests[0].Fields[0].Alpha = NotBelowP;
            }

            return BallotMapper.FromItem(ThroughBytes(item), election.Manifest, DeviceId);
        }

        new BallotAggregationVerification().Verify(election.Ballots.Select(x => Decode(x, x.Status == BallotStatus.Spoiled)), election.Manifest, tally, maxDegreeOfParallelism);

        var exception = Assert.Throws<RecordItemNotEvaluableException>(() => new BallotAggregationVerification().Verify(election.Ballots.Select(x => Decode(x, x == election.Ballots[1])), election.Manifest, tally, maxDegreeOfParallelism));
        Assert.Equal((9, "6.A"), (exception.Verification, exception.Cause.SubSection));
    }

    /// <summary>
    /// Design §6.1 step E: the encrypted tally header's counts (#17) against the recounted cast
    /// ballots and weight, "R.summary". A false header decodes without a finding and still passes
    /// Verification 9 (the spec publishes neither number, and nothing is computed from them), so
    /// only the summary check catches it, and it is a record-level code, not a V9 sub-section.
    /// </summary>
    [Theory]
    [InlineData("as written", null)]
    [InlineData("cast ballot count one more", "R.summary")]
    [InlineData("cast ballot count one fewer", "R.summary")]
    [InlineData("total cast weight one more", "R.summary")]
    [InlineData("total cast weight one fewer", "R.summary")]
    public void EncryptedTallyHeader_IsCheckedAgainstTheRecount_AsRSummary(string tamper, string? expected)
    {
        var election = Shared.Value;
        var items = TallyMapper.ToItems(election.Tally).Select(x => x.Clone()).ToList();
        var header = items[0].EncryptedTallyHeader;
        switch (tamper)
        {
            case "cast ballot count one more": header.CastBallotCount++; break;
            case "cast ballot count one fewer": header.CastBallotCount--; break;
            case "total cast weight one more": header.TotalCastWeight++; break;
            case "total cast weight one fewer": header.TotalCastWeight--; break;
        }

        var tally = TallyMapper.FromItems(ThroughBytes(items[0]).EncryptedTallyHeader, items.Skip(1).Select(x => ThroughBytes(x).EncryptedTallyContest), election.Manifest);

        Assert.Empty(tally.Findings);
        new BallotAggregationVerification().Verify(election.Ballots.Select(DecodedBallot), election.Manifest, tally);
        var verifier = new BallotAggregationVerifier(election.Manifest);
        verifier.AddBallots(election.Ballots);
        Assert.Equal((2, 3L), (verifier.BallotsAdded, verifier.WeightAdded));
        if (expected is null)
        {
            verifier.VerifySummary(tally.Value!);
        }
        else
        {
            Assert.Equal(expected, Assert.Throws<VerificationFailedException>(() => verifier.VerifySummary(tally.Value!)).SubSection);
        }
    }

    [Fact]
    public void DecryptedTally_RoundTrips_AndPassesVerifications10And11()
    {
        var election = Shared.Value;
        var encrypted = TallyMapper.ToItems(election.Tally).Select(ThroughBytes).ToList();
        var decodedEncrypted = TallyMapper.FromItems(encrypted[0].EncryptedTallyHeader, encrypted.Skip(1).Select(x => x.EncryptedTallyContest), election.Manifest);
        var items = TallyMapper.ToItems(election.Decrypted).Select(ThroughBytes).ToList();

        var decoded = TallyMapper.FromItems(items.Select(x => x.DecryptedTallyContest));

        Assert.Equal(items.Select(x => x.ToByteArray()), TallyMapper.ToItems(decoded.Value!).Select(x => x.ToByteArray()));
        new TallyDecryptionVerification().Verify(election.Record, decodedEncrypted, decoded);
        new TallyContentsVerification().Verify(election.Manifest, decoded.Value!, election.Ballots);
        Assert.Equal(3, decoded.Value!.Contests["contest-1"].Choices["choice-1"].VoteCount);
    }

    public static TheoryData<string, string> TallyTampers() => new()
    {
        { "A", "9.A" },
        { "B", "9.B" },
        { "T", "10.C" },
        { "c", "10.B" },
        { "v", "10.A" },
        { "cast ballot count above 2^31 - 1", "9.structure" },
        { "encrypted contest listed twice", "9.structure" },
        { "decrypted count above 2^31 - 1", "10.structure" },
        { "decrypted contest label listed twice", "11.structure" },
        { "decrypted field label listed twice", "11.structure" },
    };

    /// <summary>
    /// Design §4.8 for the tallies: Verification 9 reads the encrypted tally, 10 both tallies, 11 the
    /// decrypted tally. A finding is its own verification's failure, leaves the others that read its
    /// item not evaluable, and leaves the one that does not read it running (and passing).
    /// </summary>
    [Theory]
    [MemberData(nameof(TallyTampers))]
    public void Tallies_ValueOutOfRange_IsReportedUnderItsCode(string tamper, string expected)
    {
        var election = Shared.Value;
        var encrypted = TallyMapper.ToItems(election.Tally).Select(x => x.Clone()).ToList();
        var decrypted = TallyMapper.ToItems(election.Decrypted).Select(x => x.Clone()).ToList();
        var fields = encrypted[1].EncryptedTallyContest;
        var field = decrypted[0].DecryptedTallyContest.Fields[0];
        switch (tamper)
        {
            case "A": fields.Fields = ByteString.CopyFrom([.. NotBelowP.Span, .. fields.Fields.Span[512..]]); break;
            case "B": fields.Fields = ByteString.CopyFrom([.. fields.Fields.Span[..512], .. NotBelowP.Span, .. fields.Fields.Span[1024..]]); break;
            case "T": field.EncodedTally = NotBelowP; break;
            case "c": field.Proof = WithFirstHalf(field.Proof, NotBelowQ); break;
            case "v": field.Proof = WithSecondHalf(field.Proof, NotBelowQ); break;
            case "cast ballot count above 2^31 - 1": encrypted[0].EncryptedTallyHeader.CastBallotCount = (ulong)int.MaxValue + 1; break;
            case "encrypted contest listed twice": encrypted.Add(encrypted[1].Clone()); break;
            case "decrypted count above 2^31 - 1": field.Tally = (ulong)int.MaxValue + 1; break;
            case "decrypted contest label listed twice": decrypted.Add(decrypted[0].Clone()); break;
            case "decrypted field label listed twice": decrypted[0].DecryptedTallyContest.Fields.Add(field.Clone()); break;
        }

        var decodedEncrypted = TallyMapper.FromItems(ThroughBytes(encrypted[0]).EncryptedTallyHeader, encrypted.Skip(1).Select(x => ThroughBytes(x).EncryptedTallyContest), election.Manifest);
        var decodedDecrypted = TallyMapper.FromItems(decrypted.Select(x => ThroughBytes(x).DecryptedTallyContest));

        Assert.Equal(expected, Assert.Single(decodedEncrypted.Findings.Concat(decodedDecrypted.Findings)).SubSection);
        var contestIds = election.Ballots.SelectMany(x => x.Contests).Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        var verifications = new (int Number, bool ReadsEncrypted, bool ReadsDecrypted, Action Verify)[]
        {
            (9, true, false, () => new BallotAggregationVerification().Verify(election.Ballots.Select(DecodedBallot), election.Manifest, decodedEncrypted)),
            (10, true, true, () => new TallyDecryptionVerification().Verify(election.Record, decodedEncrypted, decodedDecrypted)),
            (11, false, true, () => new TallyContentsVerification().Verify(election.Manifest, decodedDecrypted, contestIds)),
        };
        bool onEncrypted = decodedEncrypted.Findings.Count > 0;
        foreach (var (number, readsEncrypted, readsDecrypted, verify) in verifications)
        {
            if (expected.StartsWith($"{number}.", StringComparison.Ordinal))
            {
                Assert.Equal(expected, Assert.Throws<VerificationFailedException>(verify).SubSection);
            }
            else if (onEncrypted ? readsEncrypted : readsDecrypted)
            {
                Assert.Equal(expected, Assert.Throws<RecordItemNotEvaluableException>(verify).Cause.SubSection);
            }
            else
            {
                verify();
            }
        }
    }

    /// <summary>
    /// The header's total cast weight is the tally's (#17); a tally restored without its header (as
    /// S10a's retired JSON record format restored one, which did not publish it) would write 0 under
    /// a nonzero count, so the writer refuses it. Aggregating the ballots again gives the total.
    /// </summary>
    [Fact]
    public void EncryptedTally_WithoutItsTotalCastWeight_IsRefusedByTheWriter()
    {
        var election = Shared.Value;
        var restored = EncryptedTally.Restore(election.Manifest, election.Tally.BallotsCast, election.Tally.Contests.Values.Select(contest =>
            (contest.ContestId, contest.CastWeight, contest.Choices.Values.Select(choice => (choice.ChoiceId, choice.A, choice.B)))));

        Assert.Equal((2, 0L), (restored.BallotsCast, restored.TotalCastWeight));
        Assert.Throws<ArgumentException>(() => TallyMapper.ToItems(restored));
        Assert.Equal(3UL, TallyMapper.ToItems(ElectionFixtureBuilder.CreateEncryptedTally(election.Manifest, election.Ballots.ToArray()))[0].EncryptedTallyHeader.TotalCastWeight);
    }

    // ---- decryptions ----------------------------------------------------------------------------

    [Fact]
    public void ContestDataDecryptions_RoundTrip_AndPassVerification12()
    {
        var election = Shared.Value;
        foreach (var decrypted in election.ContestData)
        {
            var ballot = election.Ballots.Single(x => x.Id == decrypted.BallotId);
            var item = DecryptionMapper.ToItem(decrypted, ballot, election.Index);
            var decoded = DecryptionMapper.FromItem(ThroughBytes(item).ContestDataDecryption, election.Index, election.Manifest);

            Assert.Equal((decrypted.BallotId, decrypted.ContestId, WriteIn), (decoded.Value!.BallotId, decoded.Value.ContestId, decoded.Value.DecodeText()));
            Assert.Equal(item.ToByteArray(), DecryptionMapper.ToItem(decoded.Value, ballot, election.Index).ToByteArray());
            new ContestDataDecryptionVerification().Verify(election.Record, DecodedBallot(ballot), decoded);
        }
    }

    public static TheoryData<string, string> ContestDataTampers() => new()
    {
        { "beta", "12.structure" },
        { "c", "12.B" },
        { "v", "12.A" },
        { "another H_I", "12.structure" },
        { "a position the device does not have", "12.structure" },
        { "no locator", "12.structure" },
    };

    [Theory]
    [MemberData(nameof(ContestDataTampers))]
    public void ContestDataDecryption_ValueOutOfRangeOrUnbound_IsReportedUnderItsCode(string tamper, string expected)
    {
        var election = Shared.Value;
        var item = DecryptionMapper.ToItem(election.ContestData[0], election.Ballots[0], election.Index).ContestDataDecryption;
        switch (tamper)
        {
            case "beta": item.Beta = NotBelowP; break;
            case "c": item.Proof = WithFirstHalf(item.Proof, NotBelowQ); break;
            case "v": item.Proof = WithSecondHalf(item.Proof, NotBelowQ); break;
            case "another H_I": item.HI = ByteString.CopyFrom(new byte[32]); break;
            case "a position the device does not have": item.Ballot.Position = 99; break;
            case "no locator": item.Ballot = null; break; // canonical: D1/D2 cover no absent message
        }

        var decoded = DecryptionMapper.FromItem(ThroughBytes(new Pb.RecordItem { ContestDataDecryption = item }).ContestDataDecryption, election.Index, election.Manifest);

        Assert.Equal(expected, Assert.Single(decoded.Findings).SubSection);
        Assert.Equal(expected, Assert.Throws<VerificationFailedException>(() => new ContestDataDecryptionVerification().Verify(election.Record, DecodedBallot(election.Ballots[0]), decoded)).SubSection);
    }

    [Fact]
    public void ChallengedBallotDecryption_RoundTrips_AndPassesVerifications13And14()
    {
        var election = Shared.Value;
        var item = DecryptionMapper.ToItem(election.Challenged, election.ChallengedBallot, election.Index, election.Manifest);

        var decoded = DecryptionMapper.FromItem(ThroughBytes(item).ChallengedBallotDecryption, election.Index, election.Manifest);
        var value = decoded.Value!;

        Assert.Equal(election.Challenged.BallotId, value.BallotId);
        Assert.Equal(item.ToByteArray(), DecryptionMapper.ToItem(value, election.ChallengedBallot, election.Index, election.Manifest).ToByteArray());
        Assert.Equal(election.Challenged.Contests[0].SupplementalFields.Select(x => (x.Id, x.Value)), value.Contests[0].SupplementalFields.Select(x => (x.Id, x.Value)));
        new ChallengedBallotDecryptionVerification().Verify(election.Record, DecodedBallot(election.ChallengedBallot), decoded);
        new ChallengedBallotWellFormednessVerification().Verify(election.Manifest, election.ChallengedBallot, value);
    }

    [Theory]
    [InlineData("field nonce")]
    [InlineData("contest data nonce")]
    [InlineData("another H_I")]
    [InlineData("no locator")]
    public void ChallengedBallotDecryption_NonceOutOfRangeOrUnbound_Fails13Structure(string tamper)
    {
        var election = Shared.Value;
        var item = DecryptionMapper.ToItem(election.Challenged, election.ChallengedBallot, election.Index, election.Manifest).ChallengedBallotDecryption;
        switch (tamper)
        {
            case "field nonce": item.Contests[0].Fields[0].Nonce = NotBelowQ; break;
            case "contest data nonce": item.Contests[0].ContestData.Nonce = NotBelowQ; break;
            case "another H_I": item.HI = ByteString.CopyFrom(new byte[32]); break;
            case "no locator": item.Ballot = null; break; // canonical: D1/D2 cover no absent message
        }

        var decoded = DecryptionMapper.FromItem(ThroughBytes(new Pb.RecordItem { ChallengedBallotDecryption = item }).ChallengedBallotDecryption, election.Index, election.Manifest);

        Assert.Equal("13.structure", Assert.Single(decoded.Findings).SubSection);
        Assert.Equal("13.structure", Assert.Throws<VerificationFailedException>(() => new ChallengedBallotDecryptionVerification().Verify(election.Record, DecodedBallot(election.ChallengedBallot), decoded)).SubSection);
    }

    public static TheoryData<string, string?, string> ChallengedIndexTampers() => new()
    {
        { "two fields' indices swapped, labels kept", "13.B", "14.structure" },
        { "two fields' labels swapped, indices kept", null, "14.structure" },
        { "a field's label unknown, index kept", null, "14.C" },
        { "a field index the manifest lacks", "13.structure", "14.structure" },
        // Pending the user's answer: 14.structure here rests on the implementer's reading under the V14
        // decision (tracker, Decisions, V14 "implementer reading, awaiting acceptance": 14.C/14.D
        // compare options and supplemental fields together). Under option (c) it would stay 14.C, and
        // under (b) the decoder changes; re-derive it from that answer, do not re-capture the output.
        { "the contest's index unknown, label kept", "13.structure", "14.structure" },
    };

    /// <summary>
    /// Design §4.6: the item's indices drive Verification 13's ciphertext lookup and its labels are
    /// compared in Verification 14, so a verifier that looks up by index agrees with this one. A
    /// mislabelled field opens the right ciphertexts (13 passes) and fails 14.C (a label the manifest
    /// lacks) or 14.structure (a manifest label at another index, user decision 2026-10-10); an index
    /// moved to another field opens the wrong one (13.B) and fails 14.structure too.
    /// </summary>
    [Theory]
    [MemberData(nameof(ChallengedIndexTampers))]
    public void ChallengedBallotDecryption_IndicesDriveVerification13_LabelsVerification14(string tamper, string? expected13, string expected14)
    {
        var election = Shared.Value;
        var item = DecryptionMapper.ToItem(election.Challenged, election.ChallengedBallot, election.Index, election.Manifest).ChallengedBallotDecryption;
        var contest = item.Contests[0];
        var (first, second) = (contest.Fields[0], contest.Fields[1]);
        Assert.Equal((1u, 2u), (first.Index, second.Index));
        switch (tamper)
        {
            case "two fields' indices swapped, labels kept": (first.Index, second.Index) = (second.Index, first.Index); break;
            case "two fields' labels swapped, indices kept": (first.Label, second.Label) = (second.Label, first.Label); break;
            case "a field's label unknown, index kept": second.Label = "choice-x"; break;
            case "a field index the manifest lacks": second.Index = 99; break;
            case "the contest's index unknown, label kept": contest.Index = 9; break;
        }

        var decoded = DecryptionMapper.FromItem(ThroughBytes(new Pb.RecordItem { ChallengedBallotDecryption = item }).ChallengedBallotDecryption, election.Index, election.Manifest);
        var value = decoded.Value!;
        Assert.Equal(((int)contest.Index, (int)first.Index, first.Label), (value.Contests[0].Index, value.Contests[0].Choices[0].Index, value.Contests[0].Choices[0].Id));

        var thirteen = () => new ChallengedBallotDecryptionVerification().Verify(election.Record, DecodedBallot(election.ChallengedBallot), decoded);
        if (expected13 is null)
        {
            thirteen();
        }
        else
        {
            Assert.Equal(expected13, Assert.Throws<VerificationFailedException>(thirteen).SubSection);
        }

        Assert.Equal(expected14, Assert.Throws<VerificationFailedException>(() => new ChallengedBallotWellFormednessVerification().Verify(election.Manifest, election.ChallengedBallot, value)).SubSection);
    }

    public static TheoryData<string> ChallengedWriterRefusals() => new()
    {
        "contest index and label not a manifest pair",
        "field label not the manifest's at its index",
        "a declared field missing",
        "a field the manifest does not declare",
        "a decryption of another ballot",
    };

    /// <summary>
    /// The writer refuses a challenged decryption the record cannot state honestly: its indices and
    /// labels must be the manifest's pairs, and it releases exactly the declared fields of each
    /// contest it decrypts (an honest decryption always does). It names the ballot it is given.
    /// </summary>
    [Theory]
    [MemberData(nameof(ChallengedWriterRefusals))]
    public void ChallengedBallotDecryption_TheWriterRefusesAMislabelledOrIncompleteDecryption(string tamper)
    {
        var election = Shared.Value;
        var original = election.Challenged;
        var contest = original.Contests[0];
        var choices = contest.Choices.ToList();
        var fields = contest.SupplementalFields.ToList();
        int contestIndex = contest.Index;
        var ballot = election.ChallengedBallot;
        switch (tamper)
        {
            case "contest index and label not a manifest pair": contestIndex = 9; break;
            case "field label not the manifest's at its index": choices[0] = Field(choices[0], choices[1].Id); break;
            case "a declared field missing": choices.RemoveAt(0); break;
            case "a field the manifest does not declare": choices.Add(Field(choices[0], "choice-x", index: 99)); break;
            case "a decryption of another ballot": ballot = election.Ballots[0]; break;
        }

        var tampered = new DecryptedChallengedBallot
        {
            BallotId = original.BallotId,
            Contests =
            [
                new DecryptedChallengedContest
                {
                    Index = contestIndex,
                    ContestId = contest.ContestId,
                    Choices = choices,
                    SupplementalFields = fields,
                    ContestData = contest.ContestData,
                },
            ],
        };

        Assert.Throws<ArgumentException>(() => DecryptionMapper.ToItem(tampered, ballot, election.Index, election.Manifest));

        static DecryptedChallengedField Field(DecryptedChallengedField field, string id, int? index = null) => new()
        {
            Index = index ?? field.Index,
            Id = id,
            Value = field.Value,
            EncryptionNonce = field.EncryptionNonce,
        };
    }

    public static TheoryData<string, string> OutOfOrderItems() => new()
    {
        { "regular ballot", "8.structure" },
        { "cast pre-encrypted ballot", "16.structure" },
        { "challenged ballot decryption", "13.structure" },
    };

    /// <summary>
    /// The schema's "ascending index" inside an item (design §4.6): out of order, the same content
    /// would have a second encoding and leaf hash, which a verifier enforcing the schema refuses. It is
    /// reported under the structure code of the verification that hashes or reads the list in that
    /// order (H_C: 8 for a regular ballot, 16 for a pre-encrypted one; 13 for the decryption), and the
    /// other verifications that read the item are not evaluable on it.
    /// </summary>
    [Theory]
    [MemberData(nameof(OutOfOrderItems))]
    public void Items_ContestsOutOfIndexOrder_AreReportedUnderTheirStructureCode(string kind, string expected)
    {
        var election = Shared.Value;
        switch (kind)
        {
            case "regular ballot":
            {
                var item = BallotMapper.ToItem(election.Ballots[0], election.Manifest);
                var contests = item.EncryptedBallot.Contests;
                var higher = contests[0].Clone();
                higher.Index++;
                contests.Insert(0, higher);
                var decoded = BallotMapper.FromItem(ThroughBytes(item), election.Manifest, DeviceId);

                Assert.Equal(expected, Assert.Single(decoded.Findings).SubSection);
                Assert.Equal(expected, Assert.Throws<VerificationFailedException>(() => new ConfirmationCodeVerification().Verify(decoded, election.Record)).SubSection);
                Assert.Equal(expected, Assert.Throws<RecordItemNotEvaluableException>(() => new SelectionEncryptionsWellFormedVerification().Verify(decoded, election.Record)).Cause.SubSection);
                Assert.Equal(expected, Assert.Throws<RecordItemNotEvaluableException>(() => new AdherenceToVoteLimitsVerification().Verify(decoded, election.Record)).Cause.SubSection);
                break;
            }

            case "cast pre-encrypted ballot":
            {
                var preEncrypted = PreEncryptedElection.Get();
                var (_, cast) = preEncrypted.Cast("p-map-order", [2], [1]);
                var item = BallotMapper.ToItem(cast, preEncrypted.Manifest);
                var contests = item.PreEncryptedCastBallot.Contests;
                (contests[0], contests[1]) = (contests[1], contests[0]);
                var decoded = BallotMapper.FromItem(ThroughBytes(item), preEncrypted.Manifest, PreEncryptedElection.DeviceId);

                Assert.Equal(expected, Assert.Single(decoded.Findings).SubSection);
                Assert.Equal(expected, Assert.Throws<RecordItemNotEvaluableException>(() => new SelectionEncryptionsWellFormedVerification().Verify(decoded, preEncrypted.Record)).Cause.SubSection);
                Assert.Equal(expected, Assert.Throws<RecordItemNotEvaluableException>(() => new AdherenceToVoteLimitsVerification().Verify(decoded, preEncrypted.Record)).Cause.SubSection);
                break;
            }

            case "challenged ballot decryption":
            {
                var item = DecryptionMapper.ToItem(election.Challenged, election.ChallengedBallot, election.Index, election.Manifest).ChallengedBallotDecryption;
                var higher = item.Contests[0].Clone();
                higher.Index++;
                item.Contests.Insert(0, higher);
                var decoded = DecryptionMapper.FromItem(ThroughBytes(new Pb.RecordItem { ChallengedBallotDecryption = item }).ChallengedBallotDecryption, election.Index, election.Manifest);

                Assert.Equal(expected, Assert.Single(decoded.Findings).SubSection);
                Assert.Equal(expected, Assert.Throws<VerificationFailedException>(() => new ChallengedBallotDecryptionVerification().Verify(election.Record, DecodedBallot(election.ChallengedBallot), decoded)).SubSection);
                break;
            }
        }
    }

    /// <summary>
    /// Devices may number their paper independently, so two ballots can share <c>ballot_ref</c>, an
    /// unverified free text. The index never joins on it: a reader resolves each item's locator to
    /// its own ballot (H_I still binding), and a writer locates a ballot by H_I.
    /// </summary>
    [Fact]
    public void BallotIndex_TwoDevicesWithTheSameBallotRef_StillJoinEveryItem()
    {
        var election = Shared.Value;
        var (one, other) = (election.Ballots[0], election.Ballots[1]);
        var first = new DeviceKey(DeviceChainBallotKind.Encrypted, election.Device.DeviceInformationHash);
        var second = new DeviceKey(DeviceChainBallotKind.Encrypted, VotingDeviceInformationHash.FromCanonicalBytes(new byte[32]));
        var index = new RecordBallotIndex();
        index.AddDevice(first, [("0001", one.SelectionEncryptionIdentifierHash)]);
        index.AddDevice(second, [("0001", other.SelectionEncryptionIdentifierHash)]);

        Assert.Equal(new BallotLocator(first, 1), index.Locate(one.SelectionEncryptionIdentifierHash).Locator);
        Assert.Equal(new BallotLocator(second, 1), index.Locate(other.SelectionEncryptionIdentifierHash).Locator);
        foreach (var (locator, ballot) in new[] { (new BallotLocator(first, 1), one), (new BallotLocator(second, 1), other) })
        {
            var context = new RecordDecodeContext();
            Assert.Equal("0001", index.Resolve(locator, ByteString.CopyFrom((byte[])ballot.SelectionEncryptionIdentifierHash), context, "13.structure"));
            Assert.Empty(context.Findings);
        }

        // The H_I is still a binding: the other ballot's H_I at this locator is a finding.
        var crossed = new RecordDecodeContext();
        index.Resolve(new BallotLocator(first, 1), ByteString.CopyFrom((byte[])other.SelectionEncryptionIdentifierHash), crossed, "13.structure");
        Assert.Equal("13.structure", Assert.Single(crossed.Findings).SubSection);

        // Two ballots sharing id_B (a 5.A failure) cannot be located by H_I.
        index.AddDevice(new DeviceKey(DeviceChainBallotKind.PreEncrypted, election.Device.DeviceInformationHash), [("0002", one.SelectionEncryptionIdentifierHash)]);
        Assert.Throws<ArgumentException>(() => index.Locate(one.SelectionEncryptionIdentifierHash));
        Assert.Throws<ArgumentException>(() => index.Locate(election.ChallengedBallot.SelectionEncryptionIdentifierHash));
    }

    // ---- RawZp / RawZq --------------------------------------------------------------------------

    [Fact]
    public void RawValues_NeverReduce()
    {
        Assert.False(new RawZp(EGParameters.P.ToBigEndianPadded(512)).TryToModP(out _));
        Assert.True(new RawZp((EGParameters.P - 1).ToBigEndianPadded(512)).TryToModP(out var below));
        Assert.Equal(new IntegerModP(EGParameters.P - 1), below);
        Assert.False(new RawZq(EGParameters.Q.ToBigEndianPadded(32)).TryToModQ(out _));
        Assert.True(new RawZq(new byte[32]).TryToModQ(out var zero));
        Assert.Equal(new IntegerModQ(0), zero);
        Assert.Throws<ElectionGuard.Core.Serialization.NonCanonicalEncodingException>(() => new RawZp(new byte[511]));
        Assert.Throws<ElectionGuard.Core.Serialization.NonCanonicalEncodingException>(() => new RawZq(new byte[33]));
        Assert.Equal(new RawZq(new byte[32]), new RawZq(new byte[32]));
    }
}
