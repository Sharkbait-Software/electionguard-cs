using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Tally;
using System.Numerics;
using static ElectionGuard.Core.Tally.DecryptedTally;

namespace ElectionGuard.Core.UnitTests.Verify.Tally;

/// <summary>Verification 10 (10.A-10.C), p.49 / p.89.</summary>
public class TallyDecryptionVerificationTests
{
    public TallyDecryptionVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static (TallyDecryptionElection Election, DecryptedTally Decrypted) Decrypted()
    {
        var election = TallyDecryptionElection.Build([(1, 0), (1, 0), (0, 1)]);
        return (election, election.Decrypt(0, 1));
    }

    private static void Verify(TallyDecryptionElection election, DecryptedTally decrypted) =>
        new TallyDecryptionVerification().Verify(election.EncryptionRecord, election.Tally, decrypted);

    private static VerificationFailedException Fails(TallyDecryptionElection election, DecryptedTally decrypted) =>
        Assert.Throws<VerificationFailedException>(() => Verify(election, decrypted));

    /// <summary>Replaces choice <paramref name="choiceId"/> of contest-1 with a copy changed by <paramref name="change"/>.</summary>
    private static void Replace(DecryptedTally decrypted, string choiceId, Func<DecryptedChoice, DecryptedChoice> change)
    {
        var choices = decrypted.Contests["contest-1"].Choices;
        choices[choiceId] = change(choices[choiceId]);
    }

    private static DecryptedChoice Copy(DecryptedChoice x, int? voteCount = null, IntegerModP? t = null, IntegerModQ? challenge = null, IntegerModQ? response = null, int? choiceIndex = null) => new()
    {
        ChoiceIndex = choiceIndex ?? x.ChoiceIndex,
        VoteCount = voteCount ?? x.VoteCount,
        T = t ?? x.T,
        Challenge = challenge ?? x.Challenge,
        Response = response ?? x.Response,
    };

    [Fact]
    public void Verify_HonestDecryption_Passes()
    {
        var (election, decrypted) = Decrypted();

        Assert.Null(Record.Exception(() => Verify(election, decrypted)));
    }

    [Fact]
    public void Verify_WrongCount_Fails10C()
    {
        // The count alone changed: T, c and v still agree, but T != K^t.
        var (election, decrypted) = Decrypted();
        Replace(decrypted, "choice-2", x => Copy(x, voteCount: x.VoteCount + 1));

        Assert.Equal("10.C", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_NegativeCount_Fails10C()
    {
        var (election, decrypted) = Decrypted();
        Replace(decrypted, "choice-2", x => Copy(x, voteCount: -1));

        Assert.Equal("10.C", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_CountShiftedWithAMatchingT_Fails10B()
    {
        // The delta-shift as a published record shows it: T·K^δ and t + δ agree with each other
        // (10.C holds), but M = B·T^-1 is then A^s·K^-δ, and the proof no longer verifies.
        var (election, decrypted) = Decrypted();
        var k = election.EncryptionRecord.ElectionPublicKeys.VoteEncryptionKey;
        Replace(decrypted, "choice-1", x => Copy(x, voteCount: x.VoteCount + 3, t: x.T * IntegerModP.PowModP(k, new BigInteger(3))));

        Assert.Equal("10.B", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_TamperedChallenge_Fails10B()
    {
        var (election, decrypted) = Decrypted();
        Replace(decrypted, "choice-1", x => Copy(x, challenge: x.Challenge + new IntegerModQ(1)));

        Assert.Equal("10.B", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_TamperedResponse_Fails10B()
    {
        var (election, decrypted) = Decrypted();
        Replace(decrypted, "choice-2", x => Copy(x, response: x.Response + new IntegerModQ(1)));

        Assert.Equal("10.B", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_ProofFromAnotherOption_Fails10B()
    {
        // (c, v) of choice-1 published for choice-2: eq. (90) hashes ind_o and the option's own A, B.
        var (election, decrypted) = Decrypted();
        var choice1 = decrypted.Contests["contest-1"].Choices["choice-1"];
        Replace(decrypted, "choice-2", x => Copy(x, challenge: choice1.Challenge, response: choice1.Response));

        Assert.Equal("10.B", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_AgainstAnotherAggregate_Fails10B()
    {
        // The proof binds (A, B): verified against a tally whose B differs, it fails.
        var (election, decrypted) = Decrypted();
        election.Tally.Contests["contest-1"].Choices["choice-1"].B = election.Tally.Contests["contest-1"].Choices["choice-1"].B * 2;

        Assert.Equal("10.B", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_ZeroT_Fails10C()
    {
        var (election, decrypted) = Decrypted();
        Replace(decrypted, "choice-1", x => Copy(x, t: new IntegerModP(0)));

        Assert.Equal("10.C", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_FailuresAreReportedInManifestOrder()
    {
        // choice-2's count is wrong (10.C) and choice-1's challenge is wrong (10.B): choice-1 is
        // first in the manifest, so 10.B is reported, whatever order the dictionary holds them in.
        var (election, decrypted) = Decrypted();
        Replace(decrypted, "choice-2", x => Copy(x, voteCount: x.VoteCount + 1));
        Replace(decrypted, "choice-1", x => Copy(x, challenge: x.Challenge + new IntegerModQ(1)));

        var exception = Fails(election, decrypted);

        Assert.Equal("10.B", exception.SubSection);
        Assert.Contains("choice-1", exception.Message);
    }

    [Fact]
    public void Verify_PublishedOptionIndexDiffersFromTheManifest_FailsStructure()
    {
        var (election, decrypted) = Decrypted();
        Replace(decrypted, "choice-1", x => Copy(x, choiceIndex: 2));

        Assert.Equal("10.structure", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_PublishedContestIndexDiffersFromTheManifest_FailsStructure()
    {
        var (election, decrypted) = Decrypted();
        var contest = decrypted.Contests["contest-1"];
        decrypted.Contests["contest-1"] = new DecryptedContest { ContestIndex = 2, Choices = contest.Choices };

        Assert.Equal("10.structure", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_OptionNotInTheManifest_FailsStructure()
    {
        var (election, decrypted) = Decrypted();
        decrypted.Contests["contest-1"].Choices["choice-3"] = decrypted.Contests["contest-1"].Choices["choice-1"];

        Assert.Equal("10.structure", Fails(election, decrypted).SubSection);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void Verify_LimitedParallelism_GivesTheSameResults(int maxDegreeOfParallelism)
    {
        var (election, decrypted) = Decrypted();
        var verification = new TallyDecryptionVerification();

        verification.Verify(election.EncryptionRecord, election.Tally, decrypted, maxDegreeOfParallelism);
        Replace(decrypted, "choice-2", x => Copy(x, voteCount: x.VoteCount + 1));
        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(election.EncryptionRecord, election.Tally, decrypted, maxDegreeOfParallelism));
        Assert.Equal("10.C", exception.SubSection);
    }
}

/// <summary>Verification 11 (11.A-11.D), p.49 / p.90.</summary>
public class TallyContentsVerificationTests
{
    public TallyContentsVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static (TallyDecryptionElection Election, DecryptedTally Decrypted) Decrypted()
    {
        var election = TallyDecryptionElection.Build([(1, 0), (0, 1)]);
        return (election, election.Decrypt(0, 1));
    }

    private static VerificationFailedException Fails(TallyDecryptionElection election, DecryptedTally decrypted) =>
        Assert.Throws<VerificationFailedException>(() => new TallyContentsVerification().Verify(election.Manifest, decrypted, election.Ballots));

    [Fact]
    public void Verify_HonestTally_Passes()
    {
        var (election, decrypted) = Decrypted();

        new TallyContentsVerification().Verify(election.Manifest, decrypted, election.Ballots);
        new TallyContentsVerification().Verify(election.Manifest, decrypted, ["contest-1"]);
    }

    [Fact]
    public void Verify_ContestNotInTheManifest_Fails11A()
    {
        var (election, decrypted) = Decrypted();
        decrypted.Contests["contest-9"] = decrypted.Contests["contest-1"];

        Assert.Equal("11.A", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_OptionNotInTheManifestContest_Fails11B()
    {
        var (election, decrypted) = Decrypted();
        decrypted.Contests["contest-1"].Choices["choice-9"] = decrypted.Contests["contest-1"].Choices["choice-1"];

        Assert.Equal("11.B", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_ManifestOptionMissingFromTheTally_Fails11C()
    {
        var (election, decrypted) = Decrypted();
        decrypted.Contests["contest-1"].Choices.Remove("choice-2");

        Assert.Equal("11.C", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_ContestOnASubmittedBallotMissingFromTheTally_Fails11D()
    {
        var (election, decrypted) = Decrypted();
        decrypted.Contests.Remove("contest-1");

        Assert.Equal("11.D", Fails(election, decrypted).SubSection);
    }

    [Fact]
    public void Verify_ContestOnNoSubmittedBallot_MayBeAbsent()
    {
        // 11.D asks only for contests that occur on a submitted ballot, and 11.A-11.C only about
        // contests the tally lists.
        var (election, decrypted) = Decrypted();
        decrypted.Contests.Remove("contest-1");

        new TallyContentsVerification().Verify(election.Manifest, decrypted, Array.Empty<string>());
    }

    [Fact]
    public void Verify_ContestIdsFromChallengedBallotsCount()
    {
        // "Submitted" is cast or challenged: a contest seen only on a challenged ballot must still
        // be in the tally.
        var (election, decrypted) = Decrypted();
        decrypted.Contests.Remove("contest-1");
        var challenged = TallyDecryptionElection.WithWeight(election.Ballots[0], 1, ElectionGuard.Core.BallotEncryption.BallotStatus.Challenged);

        var exception = Assert.Throws<VerificationFailedException>(() => new TallyContentsVerification().Verify(election.Manifest, decrypted, [challenged]));
        Assert.Equal("11.D", exception.SubSection);
    }
}
