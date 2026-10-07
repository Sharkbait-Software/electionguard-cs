using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Tally;

/// <summary>
/// One small election, encrypted, tallied and ready to decrypt: the minimal one-contest manifest
/// with the given limits, and ballots giving the given selections.
/// </summary>
internal sealed class TallyDecryptionElection
{
    public required ElectionFixtureBuilder.GuardianSetResult GuardianSet { get; init; }
    public required Manifest Manifest { get; init; }
    public required EncryptionRecord EncryptionRecord { get; init; }
    public required List<EncryptedBallot> Ballots { get; init; }
    public required EncryptedTally Tally { get; init; }

    /// <summary>
    /// Ballots give choice-1 and choice-2 the values listed. EGParameters is left as the caller set
    /// it, so the guardian set uses its n and k.
    /// </summary>
    public static TallyDecryptionElection Build(
        (int Choice1, int Choice2)[] ballots,
        int selectionLimit = 1,
        int optionSelectionLimit = 1,
        int weight = 1)
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(optionSelectionLimit: optionSelectionLimit, selectionLimit: selectionLimit);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(EGParameters.GuardianParameters.N, EGParameters.GuardianParameters.K, manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1");

        var encrypted = ballots.Select((values, i) =>
        {
            var ballot = ElectionFixtureBuilder.CreateBallot(manifest, $"ballot-{i}", new Dictionary<string, int>
            {
                ["choice-1"] = values.Choice1,
                ["choice-2"] = values.Choice2,
            });
            var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(record.EncryptionRecord, "device-1", deviceHash, ballot);
            return weight == 1 ? encryptedBallot : WithWeight(encryptedBallot, weight);
        }).ToList();

        return new TallyDecryptionElection
        {
            GuardianSet = guardianSet,
            Manifest = manifest,
            EncryptionRecord = record.EncryptionRecord,
            Ballots = encrypted,
            Tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, encrypted.ToArray()),
        };
    }

    public static EncryptedBallot WithWeight(EncryptedBallot ballot, int weight, BallotStatus? status = null) => new()
    {
        Id = ballot.Id,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        BallotStyleId = ballot.BallotStyleId,
        Contests = ballot.Contests,
        ConfirmationCode = ballot.ConfirmationCode,
        EncryptedBallotNonce = ballot.EncryptedBallotNonce,
        Weight = weight,
        Status = status ?? ballot.Status,
        DeviceId = ballot.DeviceId,
    };

    public List<TallyGuardian> Guardians(params int[] positions) =>
        positions.Select(i => new TallyGuardian(GuardianSet.Guardians[i].Index, GuardianSet.SecretShares[GuardianSet.Guardians[i].Index])).ToList();

    public DecryptedTally Decrypt(params int[] positions) =>
        new TallyAdmin().Decrypt(Guardians(positions), Tally, EncryptionRecord);

    public int Count(DecryptedTally tally, string choiceId) => tally.Contests["contest-1"].Choices[choiceId].VoteCount;
}

/// <summary>
/// §3.6.5 verifiable decryption: the three guardian rounds, the administrator's checks, and the
/// attacks they stop. The KAT (KnownAnswerTests.TallyDecryptionProof_Eq86To93_AndVerification10)
/// pins the bytes; these pin the behavior.
/// </summary>
public class TallyDecryptionProtocolTests
{
    public TallyDecryptionProtocolTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly (int, int)[] TwoOneVotes = [(1, 0), (1, 0), (0, 1)];

    [Theory]
    [InlineData(0, 1)]
    [InlineData(0, 2)]
    [InlineData(1, 2)]
    public void Decrypt_AnyQuorum_PublishesAProofThatVerification10Accepts(int first, int second)
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);

        var decrypted = election.Decrypt(first, second);

        Assert.Equal(2, election.Count(decrypted, "choice-1"));
        Assert.Equal(1, election.Count(decrypted, "choice-2"));
        new TallyDecryptionVerification().Verify(election.EncryptionRecord, election.Tally, decrypted);
        new TallyContentsVerification().Verify(election.Manifest, decrypted, election.Ballots);
    }

    [Fact]
    public void Decrypt_AllThreeGuardians_PublishesTheSameCountsAndAValidProof()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);

        var decrypted = election.Decrypt(0, 1, 2);

        Assert.Equal(2, election.Count(decrypted, "choice-1"));
        Assert.Equal(1, election.Count(decrypted, "choice-2"));
        new TallyDecryptionVerification().Verify(election.EncryptionRecord, election.Tally, decrypted);
    }

    [Fact]
    public void Decrypt_PublishesTheManifestIndicesAndTEqualToKToTheCount()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);

        var decrypted = election.Decrypt(0, 1);

        var contest = decrypted.Contests["contest-1"];
        Assert.Equal(1, contest.ContestIndex);
        Assert.Equal(1, contest.Choices["choice-1"].ChoiceIndex);
        Assert.Equal(2, contest.Choices["choice-2"].ChoiceIndex);
        var k = election.EncryptionRecord.ElectionPublicKeys.VoteEncryptionKey;
        Assert.Equal(IntegerModP.PowModP(k, new BigInteger(2)), contest.Choices["choice-1"].T);
        Assert.Equal(IntegerModP.PowModP(k, new BigInteger(1)), contest.Choices["choice-2"].T);
    }

    [Fact]
    public void Decrypt_TwoRunsWithTheSameGuardians_UseFreshCommitments()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1);

        var first = new TallyAdmin().Decrypt(guardians, election.Tally, election.EncryptionRecord);
        var second = new TallyAdmin().Decrypt(guardians, election.Tally, election.EncryptionRecord);

        // Same T, fresh u_i: a different proof each time.
        Assert.Equal(first.Contests["contest-1"].Choices["choice-1"].T, second.Contests["contest-1"].Choices["choice-1"].T);
        Assert.NotEqual(first.Contests["contest-1"].Choices["choice-1"].Challenge, second.Contests["contest-1"].Choices["choice-1"].Challenge);
    }

    [Fact]
    public void Commit_DrawsAFreshSecretForEveryOptionAndGuardian()
    {
        // One u_i answering two challenges c, c' gives v_i - v_i' = (c' - c)·w_i·z_i and so reveals
        // the guardian's share z_i. Each option's challenge differs anyway (it hashes ind_o, A and B),
        // so only the commitments themselves show whether u_i was drawn once per option. No nonce
        // source is passed: the random path is what is under test.
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1, 2);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.Commit(election.Tally, election.EncryptionRecord, participants)).ToList();
        var reveals = guardians.Select(x => x.Reveal(commitments)).ToList();
        var responses = guardians.Select(x => x.Respond(reveals)).ToList();

        var commitmentsA = reveals.SelectMany(r => r.Contests.Values.SelectMany(c => c.Choices.Values)).Select(x => x.CommitmentA).ToList();
        var commitmentsB = reveals.SelectMany(r => r.Contests.Values.SelectMany(c => c.Choices.Values)).Select(x => x.CommitmentB).ToList();
        var responseValues = responses.SelectMany(r => r.Contests.Values.SelectMany(c => c.Choices.Values)).Select(x => x.Response).ToList();

        // 3 guardians x 6 verifiable fields (2 options and the 4 declared supplemental fields, G29).
        Assert.Equal(3 * (2 + ElectionFixtureBuilder.DefaultSupplementalFields.Count), commitmentsA.Count);
        Assert.Equal(commitmentsA.Count, commitmentsA.Distinct().Count());
        Assert.Equal(commitmentsB.Count, commitmentsB.Distinct().Count());
        Assert.Equal(responseValues.Count, responseValues.Distinct().Count());

        // And the proof built from them still holds.
        var decrypted = new TallyAdmin().Combine(election.Tally, election.EncryptionRecord, commitments, reveals, responses);
        new TallyDecryptionVerification().Verify(election.EncryptionRecord, election.Tally, decrypted);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public void Decrypt_LimitedParallelism_PublishesAValidProof(int maxDegreeOfParallelism)
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);

        var decrypted = new TallyAdmin().Decrypt(election.Guardians(0, 2), election.Tally, election.EncryptionRecord, maxDegreeOfParallelism);

        Assert.Equal(2, election.Count(decrypted, "choice-1"));
        new TallyDecryptionVerification().Verify(election.EncryptionRecord, election.Tally, decrypted, maxDegreeOfParallelism);
    }

    // --- G28: k = 1 -------------------------------------------------------------------------

    [Theory]
    [InlineData(1, 0)]
    [InlineData(3, 0)]
    [InlineData(3, 2)]
    public void Decrypt_ThresholdOne_ASingleGuardianDecrypts(int n, int position)
    {
        // Eq. (85) over U = {i} is an empty product, so w_i = 1. The seedless product used to throw
        // InvalidOperationException here (G28).
        using var scope = EGParameters.OverrideScope(new CryptographicParameters(), new GuardianParameters(n, 1));
        var election = TallyDecryptionElection.Build(TwoOneVotes);

        var decrypted = election.Decrypt(position);

        Assert.Equal(2, election.Count(decrypted, "choice-1"));
        Assert.Equal(1, election.Count(decrypted, "choice-2"));
        new TallyDecryptionVerification().Verify(election.EncryptionRecord, election.Tally, decrypted);
    }

    [Fact]
    public void LagrangeCoefficient_OfASingleParticipant_IsOne()
    {
        var only = new GuardianIndex(2);

        Assert.Equal(new IntegerModQ(1), TallyDecryptionHashes.LagrangeCoefficient(only, [only]));
    }

    [Fact]
    public void LagrangeCoefficients_InterpolateAtZero()
    {
        // For U = {1, 3}: w_1 = 3/(3-1) = 3/2 and w_3 = 1/(1-3) = -1/2, so w_1·1 + w_3·3 = 0 and
        // w_1 + w_3 = 1 (the constant polynomial 1).
        List<GuardianIndex> participants = [new(1), new(3)];
        var w1 = TallyDecryptionHashes.LagrangeCoefficient(participants[0], participants);
        var w3 = TallyDecryptionHashes.LagrangeCoefficient(participants[1], participants);

        Assert.Equal(new IntegerModQ(1), w1 + w3);
        Assert.Equal(new IntegerModQ(0), w1 + w3 * new IntegerModQ(3));
        Assert.Equal(new IntegerModQ(3) / new IntegerModQ(2), w1);
    }

    // --- G16: the search bound ----------------------------------------------------------------

    [Fact]
    public void Decrypt_OptionSelectionLimitTwo_RecoversACountAboveTheBallotsCast()
    {
        // R = 2 and L = 2, one ballot giving 2 to choice-1: a count of 2 from 1 ballot. The search
        // used to stop at BallotsCast = 1 and throw (G16). (With L = 1 a value of 2 is an overvote
        // under the spec; that, and the encryptor's L·R threshold, is G10 in stage S5.)
        var election = TallyDecryptionElection.Build([(2, 0)], selectionLimit: 2, optionSelectionLimit: 2);
        Assert.Equal(1, election.Tally.BallotsCast);
        Assert.Equal(2, election.Tally.Contests["contest-1"].Choices["choice-1"].MaximumCount);

        var decrypted = election.Decrypt(0, 1);

        Assert.Equal(2, election.Count(decrypted, "choice-1"));
        Assert.Equal(0, election.Count(decrypted, "choice-2"));
        new TallyDecryptionVerification().Verify(election.EncryptionRecord, election.Tally, decrypted);
    }

    [Fact]
    public void Decrypt_WeightedBallots_RecoverTheWeightedCount()
    {
        // Two ballots of weight 3 (eq. 80): choice-1 counts 6 from 2 ballots cast.
        var election = TallyDecryptionElection.Build([(1, 0), (1, 0)], weight: 3);
        Assert.Equal(2, election.Tally.BallotsCast);
        Assert.Equal(6, election.Tally.Contests["contest-1"].Choices["choice-1"].MaximumCount);

        var decrypted = election.Decrypt(0, 1);

        Assert.Equal(6, election.Count(decrypted, "choice-1"));
        Assert.Equal(0, election.Count(decrypted, "choice-2"));
        new TallyDecryptionVerification().Verify(election.EncryptionRecord, election.Tally, decrypted);
    }

    [Theory]
    [InlineData(1, 1, 1)]
    [InlineData(2, 2, 2)]
    [InlineData(3, 2, 2)]
    [InlineData(2, 3, 2)]
    [InlineData(1, 5, 1)]
    public void MaximumCount_IsWeightTimesTheSmallerOfTheLimits(int selectionLimit, int optionSelectionLimit, int perBallot)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(optionSelectionLimit: optionSelectionLimit, selectionLimit: selectionLimit);
        var tally = new EncryptedTally(manifest);
        var ballot = PlaceholderBallot(weight: 1);
        var heavy = PlaceholderBallot(weight: 4);

        tally.AddBallot(ballot);
        tally.AddBallot(heavy);

        Assert.Equal(5L * perBallot, tally.Contests["contest-1"].Choices["choice-1"].MaximumCount);
        Assert.Equal(5L * perBallot, tally.Contests["contest-1"].Choices["choice-2"].MaximumCount);
        Assert.Equal(2, tally.BallotsCast);
    }

    [Theory]
    [InlineData(200, -1)]
    [InlineData(200, 3)]
    public void MaximumCount_AfterParallelAddBallots_MatchesOneAtATime(int ballotCount, int maxDegreeOfParallelism)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(optionSelectionLimit: 2, selectionLimit: 3);
        var ballots = Enumerable.Range(0, ballotCount).Select(i => PlaceholderBallot(weight: 1 + i % 3)).ToList();
        var parallel = new EncryptedTally(manifest);
        var sequential = new EncryptedTally(manifest);

        parallel.AddBallots(ballots, maxDegreeOfParallelism);
        foreach (var ballot in ballots)
        {
            sequential.AddBallot(ballot);
        }

        long expected = ballots.Sum(x => (long)x.Weight) * 2;
        Assert.Equal(expected, sequential.Contests["contest-1"].Choices["choice-1"].MaximumCount);
        Assert.Equal(expected, parallel.Contests["contest-1"].Choices["choice-1"].MaximumCount);
        Assert.Equal(expected, parallel.Contests["contest-1"].Choices["choice-2"].MaximumCount);
    }

    internal static EncryptedBallot PlaceholderBallot(int weight, BallotStatus status = BallotStatus.Cast, string id = "placeholder")
    {
        var proofs = Array.Empty<ChallengeResponsePair>();
        var counter = new EncryptedValueWithProofs { Alpha = 1, Beta = 1, Proofs = proofs };
        return new EncryptedBallot
        {
            Id = id,
            SelectionEncryptionIdentifier = new SelectionEncryptionIdentifier(new byte[] { 0x02 }),
            SelectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(new byte[] { 0x03 }),
            EncryptedBallotNonce = ElectionFixtureBuilder.PlaceholderBallotNonce,
            BallotStyleId = "ballot-style-1",
            Contests =
            [
                new EncryptedContest
                {
                    Id = "contest-1",
                    Choices =
                    [
                        new EncryptedSelection { ChoiceId = "choice-1", Alpha = 1, Beta = 1, Proofs = proofs },
                        new EncryptedSelection { ChoiceId = "choice-2", Alpha = 1, Beta = 1, Proofs = proofs },
                    ],
                    Proofs = proofs,
                    SupplementalFields = counter.AsFields([.. ElectionFixtureBuilder.DefaultSupplementalFields]),
                    ContestData = null,
                    ContestHash = new ContestHash(new byte[] { 0x01 }),
                },
            ],
            ConfirmationCode = new ConfirmationCode(new byte[] { 0x04 }),
            Weight = weight,
            DeviceId = "device-1",
            Status = status,
        };
    }

    // --- Attacks and protocol violations ------------------------------------------------------

    [Fact]
    public void DishonestGuardian_ShiftingTheCountWithAConsistentWrongShare_IsNamedBeforeAnythingIsPublished()
    {
        // The audit's attack: the Lagrange coefficients are public, so guardian 1 can send
        // M_1' = M_1·K^(-δ/w_1), hashed consistently into d_1, and shift choice-1's count by δ.
        // Every d_j checks, but the combined proof does not, and Note 3.7 names guardian 1.
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1);
        guardians[0].PartialDecryptionTamperForTesting = ShiftBy(election, guardians, delta: 1);

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().Decrypt(guardians, election.Tally, election.EncryptionRecord));

        Assert.Equal(guardians[0].Index, exception.OffendingGuardian);
        Assert.Contains("Note 3.7", exception.Message);
    }

    [Fact]
    public void DishonestGuardian_PublishedWithoutTheAdministratorsCheck_ShiftsTheCountAndFailsVerification10B()
    {
        // The same attack against an administrator that does not check the proof before publishing:
        // the count really is shifted, and Verification 10.B catches it.
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1);
        guardians[0].PartialDecryptionTamperForTesting = ShiftBy(election, guardians, delta: 1);

        var decrypted = new TallyAdmin { VerifyBeforePublishing = false }.Decrypt(guardians, election.Tally, election.EncryptionRecord);

        Assert.Equal(2 + 1, election.Count(decrypted, "choice-1"));
        Assert.Equal(1, election.Count(decrypted, "choice-2"));
        var exception = Assert.Throws<VerificationFailedException>(() => new TallyDecryptionVerification().Verify(election.EncryptionRecord, election.Tally, decrypted));
        Assert.Equal("10.B", exception.SubSection);
    }

    /// <summary>M_1 ↦ M_1·K^(-δ/w_1) for choice-1 (option index 1), so that M = A^s·K^(-δ) and T = K^(t+δ).</summary>
    private static Func<int, int, IntegerModP, IntegerModP> ShiftBy(TallyDecryptionElection election, List<TallyGuardian> guardians, int delta)
    {
        var participants = guardians.Select(x => x.Index).ToList();
        var w1 = TallyDecryptionHashes.LagrangeCoefficient(guardians[0].Index, participants);
        var k = election.EncryptionRecord.ElectionPublicKeys.VoteEncryptionKey;
        var shift = MontgomeryModP.PowModP(k, new IntegerModQ(0) - new IntegerModQ(delta) / w1);
        return (contestIndex, optionIndex, mi) => optionIndex == 1 ? mi * shift : mi;
    }

    [Fact]
    public void RevealAlteredInTransit_IsCaughtByTheOtherGuardians_NamingTheSender()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1, 2);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.Commit(election.Tally, election.EncryptionRecord, participants)).ToList();
        var reveals = guardians.Select(x => x.Reveal(commitments)).ToList();

        // Guardian 3's b_3 for choice-2, altered on its way to guardian 1.
        var altered = new TallyDecryptionCommitmentReveal
        {
            GuardianIndex = reveals[2].GuardianIndex,
            Contests = reveals[2].Contests.ToDictionary(x => x.Key, x => new TallyDecryptionCommitmentReveal.ContestReveal
            {
                Choices = x.Value.Choices.ToDictionary(y => y.Key, y => y.Key == "choice-2"
                    ? new TallyDecryptionCommitmentReveal.ChoiceReveal { CommitmentA = y.Value.CommitmentA, CommitmentB = y.Value.CommitmentB * 2 }
                    : y.Value),
            }),
        };

        var exception = Assert.Throws<TallyDecryptionException>(() => guardians[0].Respond([reveals[0], reveals[1], altered]));

        Assert.Equal(guardians[2].Index, exception.OffendingGuardian);
        Assert.Contains("eq. 88", exception.Message);

        // The others, who received it intact, respond; the administrator, given the altered one, also
        // names guardian 3.
        var responses = new[] { guardians[1].Respond(reveals), guardians[2].Respond(reveals) };
        var adminException = Assert.Throws<TallyDecryptionException>(() =>
            new TallyAdmin().Combine(election.Tally, election.EncryptionRecord, commitments, [reveals[0], reveals[1], altered], responses));
        Assert.Equal(guardians[2].Index, adminException.OffendingGuardian);
    }

    [Fact]
    public void GuardiansShownDifferentTallies_HaltTheProtocol()
    {
        // An administrator that shows guardian 2 a different aggregate than guardian 1: each
        // guardian checks the others' d_j against its own A and B, so guardian 2 rejects d_1.
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var other = TallyDecryptionElection.Build([(0, 1)]);
        var forged = new EncryptedTally(election.Manifest);
        forged.Contests["contest-1"].Choices["choice-1"].A = other.Tally.Contests["contest-1"].Choices["choice-1"].A;
        forged.Contests["contest-1"].Choices["choice-1"].B = other.Tally.Contests["contest-1"].Choices["choice-1"].B;

        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = new[]
        {
            guardians[0].Commit(election.Tally, election.EncryptionRecord, participants),
            guardians[1].Commit(forged, election.EncryptionRecord, participants),
        };
        var reveals = guardians.Select(x => x.Reveal(commitments)).ToList();

        var exception = Assert.Throws<TallyDecryptionException>(() => guardians[1].Respond(reveals));

        Assert.Equal(guardians[0].Index, exception.OffendingGuardian);
    }

    [Fact]
    public void Reveal_BeforeEveryParticipantHasCommitted_Refuses_NamingTheMissingGuardian()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1, 2);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.Commit(election.Tally, election.EncryptionRecord, participants)).ToList();

        var exception = Assert.Throws<TallyDecryptionException>(() => guardians[0].Reveal([commitments[0], commitments[1]]));

        Assert.Equal(guardians[2].Index, exception.OffendingGuardian);
    }

    [Fact]
    public void Reveal_WithACommitmentFromOutsideU_Refuses_NamingTheSender()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1, 2);
        List<GuardianIndex> participants = [guardians[0].Index, guardians[1].Index];
        var commitments = guardians.Take(2).Select(x => x.Commit(election.Tally, election.EncryptionRecord, participants)).ToList();
        var outsider = guardians[2].Commit(election.Tally, election.EncryptionRecord, [guardians[1].Index, guardians[2].Index]);

        var exception = Assert.Throws<TallyDecryptionException>(() => guardians[0].Reveal([commitments[0], commitments[1], outsider]));

        Assert.Equal(guardians[2].Index, exception.OffendingGuardian);
    }

    [Fact]
    public void Reveal_WithTheGuardiansOwnCommitmentAltered_Refuses()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.Commit(election.Tally, election.EncryptionRecord, participants)).ToList();
        var replacement = guardians[0].Commit(election.Tally, election.EncryptionRecord, participants);
        _ = guardians[0].Commit(election.Tally, election.EncryptionRecord, participants);

        // replacement is a commitment guardian 1 made in an earlier, discarded session.
        Assert.Throws<TallyDecryptionException>(() => guardians[0].Reveal([replacement, commitments[1]]));
    }

    [Fact]
    public void Respond_IsSingleUse()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.Commit(election.Tally, election.EncryptionRecord, participants)).ToList();
        var reveals = guardians.Select(x => x.Reveal(commitments)).ToList();

        guardians[0].Respond(reveals);

        // A second response with the same u_i, to a challenge the caller might choose, would leak
        // z_i; there is no second response.
        Assert.Throws<InvalidOperationException>(() => guardians[0].Respond(reveals));
        Assert.Throws<InvalidOperationException>(() => guardians[0].Reveal(commitments));
    }

    [Fact]
    public void Rounds_OutOfOrder_Throw()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();

        Assert.Throws<InvalidOperationException>(() => guardians[0].Reveal([]));
        Assert.Throws<InvalidOperationException>(() => guardians[0].Respond([]));

        var commitments = guardians.Select(x => x.Commit(election.Tally, election.EncryptionRecord, participants)).ToList();
        Assert.Throws<InvalidOperationException>(() => guardians[0].Respond([]));
        guardians[0].Reveal(commitments);
        Assert.Throws<InvalidOperationException>(() => guardians[0].Reveal(commitments));
    }

    public static TheoryData<int[]> InvalidParticipants => new()
    {
        { new[] { 1 } },        // below k = 2
        { new[] { 2, 3 } },     // without guardian 1, who is asked to commit
        { new[] { 1, 4 } },     // 4 > n = 3
        { new[] { 1, 1, 2 } },  // repeated
    };

    [Theory]
    [MemberData(nameof(InvalidParticipants))]
    public void Commit_RequiresAQuorumIncludingThisGuardian(int[] indices)
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardian = election.Guardians(0)[0];

        Assert.Throws<ArgumentException>(() => guardian.Commit(election.Tally, election.EncryptionRecord, indices.Select(x => new GuardianIndex(x)).ToList()));
    }

    [Fact]
    public void Combine_WithAResponseMissing_Throws_NamingTheGuardian()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.Commit(election.Tally, election.EncryptionRecord, participants)).ToList();
        var reveals = guardians.Select(x => x.Reveal(commitments)).ToList();
        var responses = new[] { guardians[0].Respond(reveals) };

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().Combine(election.Tally, election.EncryptionRecord, commitments, reveals, responses));

        Assert.Equal(guardians[1].Index, exception.OffendingGuardian);
    }

    [Fact]
    public void Combine_WithTwoRound1MessagesFromOneGuardian_Throws_NamingTheGuardian()
    {
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.Commit(election.Tally, election.EncryptionRecord, participants)).ToList();
        var reveals = guardians.Select(x => x.Reveal(commitments)).ToList();
        var responses = guardians.Select(x => x.Respond(reveals)).ToList();

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().Combine(election.Tally, election.EncryptionRecord, [commitments[0], commitments[1], commitments[1]], reveals, responses));

        Assert.Equal(guardians[1].Index, exception.OffendingGuardian);
    }

    [Fact]
    public void Combine_WithAWrongResponse_Throws_NamingTheGuardian()
    {
        // A response that is not u_i - c·w_i·z_i: every d_j checks, the combined proof fails, and
        // Note 3.7 (eqs. 94, 95) finds guardian 2.
        var election = TallyDecryptionElection.Build(TwoOneVotes);
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.Commit(election.Tally, election.EncryptionRecord, participants)).ToList();
        var reveals = guardians.Select(x => x.Reveal(commitments)).ToList();
        var responses = guardians.Select(x => x.Respond(reveals)).ToList();
        var wrong = responses[1].Contests["contest-1"].Choices["choice-1"].Response + new IntegerModQ(1);
        responses[1].Contests["contest-1"].Choices["choice-1"] = new TallyDecryptionResponse.ChoiceResponse { Response = wrong };

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().Combine(election.Tally, election.EncryptionRecord, commitments, reveals, responses));

        Assert.Equal(guardians[1].Index, exception.OffendingGuardian);
    }
}
