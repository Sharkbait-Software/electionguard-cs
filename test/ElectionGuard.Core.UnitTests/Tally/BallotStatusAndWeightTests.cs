using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.Tally;

/// <summary>
/// G21 (cast/challenged status; S10b-1 adds spoiled and renames the in-memory zero value to
/// unrecorded), G30 (weights below 1) and G20 (Verification 9 compares the manifest's options, all
/// of them and nothing else).
/// </summary>
public class BallotStatusAndWeightTests
{
    public BallotStatusAndWeightTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly (int, int)[] TwoOneVotes = [(1, 0), (1, 0), (0, 1)];

    private static Manifest Manifest() => ElectionFixtureBuilder.CreateMinimalManifest().Manifest;

    private static EncryptedBallot Placeholder(int weight = 1, BallotStatus status = BallotStatus.Cast) =>
        TallyDecryptionProtocolTests.PlaceholderBallot(weight, status);

    // --- G21: status ----------------------------------------------------------------------------

    [Fact]
    public void Encryptor_LeavesTheStatusUnrecorded()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var guardians = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardians, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1");

        var encrypted = new BallotEncryptor(record.EncryptionRecord, "device-1", deviceHash).Encrypt(ElectionFixtureBuilder.CreateBallot(manifest), null);

        Assert.Equal(BallotStatus.Unrecorded, encrypted.Status);
    }

    /// <summary>The status is recorded once, whichever of the three it is, and never changes afterwards.</summary>
    [Theory]
    [InlineData(BallotStatus.Cast)]
    [InlineData(BallotStatus.Challenged)]
    [InlineData(BallotStatus.Spoiled)]
    public void RecordStatus_IsFinal(BallotStatus first)
    {
        var ballot = Placeholder(status: BallotStatus.Unrecorded);

        ballot.RecordStatus(first);

        Assert.Equal(first, ballot.Status);
        Assert.Throws<InvalidOperationException>(() => ballot.RecordStatus(BallotStatus.Cast));
        Assert.Throws<InvalidOperationException>(() => ballot.RecordStatus(BallotStatus.Challenged));
        Assert.Throws<InvalidOperationException>(() => ballot.RecordStatus(BallotStatus.Spoiled));
        Assert.Equal(first, ballot.Status);
    }

    /// <summary>
    /// The values are the election record's BallotStatus enum numbers (EGRF v2: UNSPECIFIED 0, CAST
    /// 1, CHALLENGED 2, SPOILED 3), and both ballot serializers write these numbers.
    /// </summary>
    [Fact]
    public void BallotStatus_Values_AreTheRecordFormatsEnumNumbers()
    {
        Assert.Equal(0, (int)BallotStatus.Unrecorded);
        Assert.Equal(1, (int)BallotStatus.Cast);
        Assert.Equal(2, (int)BallotStatus.Challenged);
        Assert.Equal(3, (int)BallotStatus.Spoiled);
        Assert.Equal(4, Enum.GetValues<BallotStatus>().Length);
    }

    /// <summary>
    /// S10b-1: a spoiled ballot was submitted (user decision S10b #4), so it stays in its device's
    /// chain and Verifications 5 to 8 check it like any other ballot, per ballot and per device,
    /// and it is left out of the tally. A spoiled ballot with a broken range proof or confirmation
    /// code fails 6.D, 7.D and 8.B, so skipping spoiled ballots in V6 to V8 fails this test. That its contests count for 11.D is
    /// TallyContentsVerificationTests.Verify_ContestIdsFromSpoiledBallotsCount. 5.A takes
    /// identifiers, not ballots, so it has no status to filter on; the record verifier (S10b-9)
    /// collects them and tests that a spoiled ballot's id_B is among them.
    /// </summary>
    [Fact]
    public void SpoiledBallot_InTheChain_PassesVerifications5To8_AndIsNotTallied()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(chainingMode: ChainingMode.Simple);
        var guardians = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardians, manifest, manifestFile).EncryptionRecord;
        var deviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1");
        var chain = new DeviceChain(record, "device-1");
        var ballots = new List<EncryptedBallot>();
        foreach (var status in new[] { BallotStatus.Cast, BallotStatus.Spoiled, BallotStatus.Cast })
        {
            var ballot = ElectionFixtureBuilder.CreateEncryptedBallot(record, "device-1", deviceHash, ElectionFixtureBuilder.CreateBallot(manifest), chain.PreviousConfirmationCode, status);
            chain.Append(ballot);
            ballots.Add(ballot);
        }

        var spoiled = ballots[1];
        Assert.Equal(BallotStatus.Spoiled, spoiled.Status);
        new SelectionEncryptionIdentifierVerification().Verify(ballots.Select(x => x.SelectionEncryptionIdentifier).ToList());
        new SelectionEncryptionIdentifierVerification().Verify(spoiled.SelectionEncryptionIdentifier, spoiled.SelectionEncryptionIdentifierHash, record.ExtendedBaseHash);
        new SelectionEncryptionsWellFormedVerification().Verify(spoiled, record);
        new AdherenceToVoteLimitsVerification().Verify(spoiled, record);
        new ConfirmationCodeVerification().Verify(spoiled, record);
        new ConfirmationCodeVerification().VerifyDevices([chain.Close()], ballots, record);

        // S10b-A review round 2: and a broken spoiled ballot fails them. Each check above would also
        // pass if the verifications skipped spoiled ballots; these fail then.
        var badSelectionProof = Relabel(spoiled, spoiled.Status, contests: WithFirstContest(spoiled, c => c with
        {
            Choices = [c.Choices[0] with { Proofs = [c.Choices[0].Proofs[0] with { Response = c.Choices[0].Proofs[0].Response + 1 }, .. c.Choices[0].Proofs[1..]] }, .. c.Choices[1..]],
        }));
        Assert.Equal("6.D", Assert.Throws<VerificationFailedException>(() => new SelectionEncryptionsWellFormedVerification().Verify(badSelectionProof, record)).SubSection);
        var badContestProof = Relabel(spoiled, spoiled.Status, contests: WithFirstContest(spoiled, c => c with
        {
            Proofs = [c.Proofs[0] with { Challenge = c.Proofs[0].Challenge + 1 }, .. c.Proofs[1..]],
        }));
        Assert.Equal("7.D", Assert.Throws<VerificationFailedException>(() => new AdherenceToVoteLimitsVerification().Verify(badContestProof, record)).SubSection);
        byte[] code = [.. (byte[])spoiled.ConfirmationCode];
        code[0] ^= 0xFF;
        var badCode = Relabel(spoiled, spoiled.Status, confirmationCode: new ConfirmationCode(code));
        Assert.Equal("8.B", Assert.Throws<VerificationFailedException>(() => new ConfirmationCodeVerification().Verify(badCode, record)).SubSection);

        var tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, [.. ballots]);
        Assert.Equal(2, tally.BallotsCast);
        new BallotAggregationVerification().Verify(ballots, manifest, tally);

        // A tally that counts the spoiled ballot as cast: V9, which aggregates cast ballots only,
        // finds the first option's A differs (9.A comes before the cast-weight check).
        var countedAsCast = ElectionFixtureBuilder.CreateEncryptedTally(manifest, ballots[0], ballots[2], Relabel(spoiled, BallotStatus.Cast));
        Assert.Equal("9.A", Assert.Throws<VerificationFailedException>(() => new BallotAggregationVerification().Verify(ballots, manifest, countedAsCast)).SubSection);
    }

    private static List<EncryptedContest> WithFirstContest(EncryptedBallot ballot, Func<EncryptedContest, EncryptedContest> mutate) =>
        [mutate(ballot.Contests[0]), .. ballot.Contests.Skip(1)];

    private static EncryptedBallot Relabel(EncryptedBallot ballot, BallotStatus status, List<EncryptedContest>? contests = null, ConfirmationCode? confirmationCode = null) => new()
    {
        Id = ballot.Id,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        BallotStyleId = ballot.BallotStyleId,
        DeviceId = ballot.DeviceId,
        Contests = contests ?? ballot.Contests,
        ConfirmationCode = confirmationCode ?? ballot.ConfirmationCode,
        ChainingField = ballot.ChainingField,
        EncryptedBallotNonce = ballot.EncryptedBallotNonce,
        Weight = ballot.Weight,
        Status = status,
    };

    [Theory]
    [InlineData(BallotStatus.Unrecorded)]
    [InlineData((BallotStatus)7)]
    public void RecordStatus_AcceptsOnlyCastChallengedOrSpoiled(BallotStatus status)
    {
        var ballot = Placeholder(status: BallotStatus.Unrecorded);

        Assert.Throws<ArgumentOutOfRangeException>(() => ballot.RecordStatus(status));
        Assert.Equal(BallotStatus.Unrecorded, ballot.Status);
    }

    [Theory]
    [InlineData(BallotStatus.Challenged)]
    [InlineData(BallotStatus.Spoiled)]
    public void AddBallot_SkipsAChallengedOrSpoiledBallot(BallotStatus status)
    {
        var tally = new EncryptedTally(Manifest());
        var challenged = Placeholder(status: status);
        challenged.Contests[0].Choices[0] = challenged.Contests[0].Choices[0] with { Alpha = 5, Beta = 7 };

        tally.AddBallot(challenged);

        Assert.Equal(0, tally.BallotsCast);
        Assert.True(tally.Contests["contest-1"].Choices["choice-1"].IsZero());
        Assert.Equal(0, tally.Contests["contest-1"].Choices["choice-1"].MaximumCount);
    }

    [Theory]
    [InlineData(BallotStatus.Unrecorded)]
    [InlineData((BallotStatus)4)]
    public void AddBallot_WithNoRecordedStatus_FailsStructureAndAddsNothing(BallotStatus status)
    {
        var tally = new EncryptedTally(Manifest());

        var exception = Assert.Throws<VerificationFailedException>(() => tally.AddBallot(Placeholder(status: status)));

        Assert.Equal("9.structure", exception.SubSection);
        Assert.Equal(0, tally.BallotsCast);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(4)]
    public void Decrypt_CountsOnlyCastBallots(int maxDegreeOfParallelism)
    {
        // Ballot 0 (choice-1) is challenged: choice-1 counts 1, not 2. Enough copies of the cast
        // ballots for AddBallots to split the work across workers.
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var ballots = election.Ballots
            .Select((ballot, i) => TallyDecryptionElection.WithWeight(ballot, 1, i == 0 ? BallotStatus.Challenged : BallotStatus.Cast))
            .ToList();
        var many = Enumerable.Range(0, 10).SelectMany(_ => ballots).ToList();
        var tally = new EncryptedTally(election.Manifest);

        tally.AddBallots(many, maxDegreeOfParallelism);

        Assert.Equal(20, tally.BallotsCast);
        var decrypted = new TallyAdmin().Decrypt(election.Guardians(0, 1), tally, election.EncryptionRecord);
        Assert.Equal(10, election.Count(decrypted, "choice-1"));
        Assert.Equal(10, election.Count(decrypted, "choice-2"));
    }

    [Theory]
    [InlineData(BallotStatus.Challenged)]
    [InlineData(BallotStatus.Spoiled)]
    public void Verification9_LeavesChallengedAndSpoiledBallotsOut(BallotStatus status)
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var record = election.Ballots
            .Select((ballot, i) => TallyDecryptionElection.WithWeight(ballot, 1, i == 0 ? status : BallotStatus.Cast))
            .ToList();
        var castOnly = ElectionFixtureBuilder.CreateEncryptedTally(election.Manifest, record.Skip(1).ToArray());

        // The record holds all three ballots; the tally of the two cast ones verifies.
        new BallotAggregationVerification().Verify(record, election.Manifest, castOnly);

        // A tally that also counted the challenged ballot does not.
        var exception = Assert.Throws<VerificationFailedException>(() => new BallotAggregationVerification().Verify(record, election.Manifest, election.Tally));
        Assert.Equal("9.A", exception.SubSection);
    }

    [Fact]
    public void Verification9_ABallotWithNoStatus_FaultsTheVerifier()
    {
        var verifier = new BallotAggregationVerifier(Manifest());

        var exception = Assert.Throws<VerificationFailedException>(() => verifier.AddBallot(Placeholder(status: BallotStatus.Unrecorded)));

        Assert.Equal("9.structure", exception.SubSection);
        Assert.Throws<InvalidOperationException>(() => verifier.Verify(new EncryptedTally(Manifest())));
    }

    // --- G30: weights -------------------------------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void AddBallot_AWeightBelowOne_FailsStructureAndAddsNothing(int weight)
    {
        // Eq. (80): weights are positive. A weight of 0 or less used to be counted as 1.
        var tally = new EncryptedTally(Manifest());

        var exception = Assert.Throws<VerificationFailedException>(() => tally.AddBallot(Placeholder(weight)));

        Assert.Equal("9.structure", exception.SubSection);
        Assert.Equal(0, tally.BallotsCast);
    }

    [Fact]
    public void Verification9_AWeightBelowOne_FaultsTheVerifier()
    {
        var verifier = new BallotAggregationVerifier(Manifest());

        var exception = Assert.Throws<VerificationFailedException>(() => verifier.AddBallots([Placeholder(1), Placeholder(0)], maxDegreeOfParallelism: 1));

        Assert.Equal("9.structure", exception.SubSection);
        Assert.Throws<InvalidOperationException>(() => verifier.Verify(new EncryptedTally(Manifest())));
    }

    // --- Serialization ------------------------------------------------------------------------

    public static TheoryData<BallotStatus, int> StatusesAndWeights => new()
    {
        { BallotStatus.Cast, 1 },
        { BallotStatus.Challenged, 1 },
        { BallotStatus.Spoiled, 1 },
        { BallotStatus.Unrecorded, 1 },
        { BallotStatus.Cast, 3 },
        { BallotStatus.Cast, 0 },
    };

    [Theory]
    [MemberData(nameof(StatusesAndWeights))]
    public void Json_RoundTripsStatusAndWeight(BallotStatus status, int weight)
    {
        var decoded = RoundTrip(new JsonEncryptedBallotSerializer(), status, weight);

        Assert.Equal(status, decoded.Status);
        Assert.Equal(weight, decoded.Weight);
    }

    [Theory]
    [MemberData(nameof(StatusesAndWeights))]
    public void Protobuf_RoundTripsStatusAndWeight(BallotStatus status, int weight)
    {
        // 0 is protobuf's default and is left off the wire, so Unrecorded and weight 0 are also
        // what a ballot without the field decodes to.
        var decoded = RoundTrip(new ProtobufEncryptedBallotSerializer(), status, weight);

        Assert.Equal(status, decoded.Status);
        Assert.Equal(weight, decoded.Weight);
    }

    [Fact]
    public void Protobuf_ABallotWithoutStatusOrWeight_DecodesFaithfully_AndIsRejectedWhenTallied()
    {
        // A decoder decodes; Verification 9 judges. Weight 0 and no status are both rejected there.
        var tally = new EncryptedTally(Manifest());

        var noStatus = RoundTrip(new ProtobufEncryptedBallotSerializer(), BallotStatus.Unrecorded, 1);
        var noWeight = RoundTrip(new ProtobufEncryptedBallotSerializer(), BallotStatus.Cast, 0);

        Assert.Equal("9.structure", Assert.Throws<VerificationFailedException>(() => tally.AddBallot(noStatus)).SubSection);
        Assert.Equal("9.structure", Assert.Throws<VerificationFailedException>(() => tally.AddBallot(noWeight)).SubSection);
    }

    private static EncryptedBallot RoundTrip(IEncryptedBallotSerializer serializer, BallotStatus status, int weight)
    {
        // A real ballot, so that every value decodes strictly.
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var guardians = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardians, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1");
        var encrypted = ElectionFixtureBuilder.CreateEncryptedBallot(record.EncryptionRecord, "device-1", deviceHash, ElectionFixtureBuilder.CreateBallot(manifest), status: BallotStatus.Unrecorded);
        var ballot = TallyDecryptionElection.WithWeight(encrypted, weight, status);

        using var stream = new MemoryStream();
        serializer.Serialize(stream, ballot);
        stream.Position = 0;
        return serializer.Deserialize(stream)!;
    }

    // --- G20: Verification 9 compares exactly the manifest's options --------------------------

    private static (BallotAggregationVerifier Verifier, EncryptedTally Claimed) HonestPair()
    {
        var manifest = Manifest();
        var ballots = new[] { Placeholder(), Placeholder() };
        var verifier = new BallotAggregationVerifier(manifest);
        verifier.AddBallots(ballots);
        return (verifier, ElectionFixtureBuilder.CreateEncryptedTally(manifest, ballots));
    }

    [Fact]
    public void Verification9_ClaimedTallyMissingAnOption_FailsStructure()
    {
        // Used to pass: V9 walked the claimed tally's keys, so an option left out was never compared.
        var (verifier, claimed) = HonestPair();
        claimed.Contests["contest-1"].Choices.Remove("choice-2");

        Assert.Equal("9.structure", Assert.Throws<VerificationFailedException>(() => verifier.Verify(claimed)).SubSection);
    }

    [Fact]
    public void Verification9_EmptyClaimedTally_FailsStructure()
    {
        var (verifier, claimed) = HonestPair();
        claimed.Contests.Clear();

        Assert.Equal("9.structure", Assert.Throws<VerificationFailedException>(() => verifier.Verify(claimed)).SubSection);
    }

    [Fact]
    public void Verification9_ClaimedTallyWithAnExtraOption_FailsStructure_NotKeyNotFound()
    {
        var (verifier, claimed) = HonestPair();
        claimed.Contests["contest-1"].Choices["choice-9"] = new EncryptedTally.EncryptedAggregateChoice { ChoiceId = "choice-9", A = 1, B = 1 };

        Assert.Equal("9.structure", Assert.Throws<VerificationFailedException>(() => verifier.Verify(claimed)).SubSection);
    }

    [Fact]
    public void Verification9_ClaimedTallyWithAnExtraContest_FailsStructure_NotKeyNotFound()
    {
        var (verifier, claimed) = HonestPair();
        claimed.Contests["contest-9"] = new EncryptedTally.EncryptedAggregateContest
        {
            ContestId = "contest-9",
            Choices = new Dictionary<string, EncryptedTally.EncryptedAggregateChoice>(),
        };

        Assert.Equal("9.structure", Assert.Throws<VerificationFailedException>(() => verifier.Verify(claimed)).SubSection);
    }

    [Fact]
    public void Verification9_HonestPair_Passes()
    {
        var (verifier, claimed) = HonestPair();

        verifier.Verify(claimed);
    }
}
