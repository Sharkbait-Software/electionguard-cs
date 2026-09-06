using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.TestFixtures;

namespace ElectionGuard.Core.UnitTests.Tally;

/// <summary>
/// Shared bootstrap for TallyGuardianTests/TallyAdminTests: a full N=3/K=2 guardian set, a
/// 1-contest/2-choice manifest, and 3 encrypted ballots with a KNOWN plaintext vote distribution
/// (choice-1: 2 votes from ballot-1/ballot-2, choice-2: 1 vote from ballot-3), tallied into a
/// single EncryptedTally. This lets TallyAdminTests assert exact recovered vote counts rather than
/// just "does not throw".
/// </summary>
file static class TallyTestScenario
{
    public sealed class Result
    {
        public required ElectionFixtureBuilder.GuardianSetResult GuardianSet { get; init; }
        public required List<EncryptedBallot> EncryptedBallots { get; init; }
        public required EncryptedTally Tally { get; init; }
    }

    public static Result Build()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());

        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");

        var ballot1 = ElectionFixtureBuilder.CreateBallot(manifest, "ballot-1", new Dictionary<string, int>
        {
            ["choice-1"] = 1,
            ["choice-2"] = 0,
        });
        var ballot2 = ElectionFixtureBuilder.CreateBallot(manifest, "ballot-2", new Dictionary<string, int>
        {
            ["choice-1"] = 1,
            ["choice-2"] = 0,
        });
        var ballot3 = ElectionFixtureBuilder.CreateBallot(manifest, "ballot-3", new Dictionary<string, int>
        {
            ["choice-1"] = 0,
            ["choice-2"] = 1,
        });

        var encryptedBallots = new List<EncryptedBallot>
        {
            ElectionFixtureBuilder.CreateEncryptedBallot(encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot1),
            ElectionFixtureBuilder.CreateEncryptedBallot(encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot2),
            ElectionFixtureBuilder.CreateEncryptedBallot(encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot3),
        };

        var tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, encryptedBallots.ToArray());

        return new Result
        {
            GuardianSet = guardianSet,
            EncryptedBallots = encryptedBallots,
            Tally = tally,
        };
    }

    public static PartialTallyDecryption DecryptFor(Result scenario, GuardianIndex guardianIndex)
    {
        var shares = scenario.GuardianSet.SecretShares[guardianIndex];
        var tallyGuardian = new TallyGuardian(guardianIndex, shares);
        return tallyGuardian.Decrypt(scenario.Tally);
    }
}

public class TallyGuardianTests
{
    [Fact]
    public void Decrypt_ProducesPartialDecryptionForEachContestChoice()
    {
        var scenario = TallyTestScenario.Build();
        var guardian = scenario.GuardianSet.Guardians[0];

        var partial = TallyTestScenario.DecryptFor(scenario, guardian.Index);

        Assert.Equal(guardian.Index, partial.GuardianIndex);
        var contest = Assert.Single(partial.Contests);
        Assert.Equal("contest-1", contest.Key);
        Assert.Equal(2, contest.Value.Choices.Count);
        Assert.Contains("choice-1", contest.Value.Choices.Keys);
        Assert.Contains("choice-2", contest.Value.Choices.Keys);

        // Secondary observable, beyond structure: Mi must be the *exact* A^share value (TallyGuardian.Decrypt),
        // not merely present -- pins the exponent base (A, not B) and the exponent itself (this guardian's
        // VoteEncryptionKeyShare) so a swapped base or wrong share would be caught even in isolation from
        // TallyAdminTests' end-to-end vote-count assertions.
        var shares = scenario.GuardianSet.SecretShares[guardian.Index];
        var expectedMi = IntegerModP.PowModP(scenario.Tally.Contests["contest-1"].Choices["choice-1"].A, shares.VoteEncryptionKeyShare);
        Assert.Equal(expectedMi, partial.Contests["contest-1"].Choices["choice-1"].Mi);
    }

    [Fact]
    public void Decrypt_DifferentGuardians_ProduceDifferentPartialShares()
    {
        var scenario = TallyTestScenario.Build();
        var guardian1 = scenario.GuardianSet.Guardians[0];
        var guardian2 = scenario.GuardianSet.Guardians[1];

        var partial1 = TallyTestScenario.DecryptFor(scenario, guardian1.Index);
        var partial2 = TallyTestScenario.DecryptFor(scenario, guardian2.Index);

        var mi1 = partial1.Contests["contest-1"].Choices["choice-1"].Mi;
        var mi2 = partial2.Contests["contest-1"].Choices["choice-1"].Mi;

        Assert.NotEqual(mi1, mi2);
    }
}

public class TallyAdminTests
{
    [Fact]
    public void Decrypt_ThresholdManyShares_RecoversCorrectVoteCounts()
    {
        var scenario = TallyTestScenario.Build();

        // GuardianParameters is hardcoded N=3/K=2 (CLAUDE.md) -- use exactly K=2 of the 3
        // guardians' partial decryptions (guardians 1 and 2) to prove threshold combination
        // works with fewer than all N shares.
        var guardian1 = scenario.GuardianSet.Guardians[0];
        var guardian2 = scenario.GuardianSet.Guardians[1];
        var partials = new List<PartialTallyDecryption>
        {
            TallyTestScenario.DecryptFor(scenario, guardian1.Index),
            TallyTestScenario.DecryptFor(scenario, guardian2.Index),
        };

        var tallyAdmin = new TallyAdmin();
        var decryptedTally = tallyAdmin.Decrypt(partials, scenario.Tally, scenario.GuardianSet.ElectionPublicKeys);

        // Known plaintext distribution: choice-1 got 2 votes (ballot-1, ballot-2),
        // choice-2 got 1 vote (ballot-3). This must be exact, not just "did not throw".
        Assert.Equal(2, decryptedTally.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(1, decryptedTally.Contests["contest-1"].Choices["choice-2"].VoteCount);
    }

    [Fact]
    public void Decrypt_LagrangeCoefficients_CombineCorrectly()
    {
        var scenario = TallyTestScenario.Build();
        var tallyAdmin = new TallyAdmin();

        // First subset: guardians 1 & 2.
        var subsetA = new List<PartialTallyDecryption>
        {
            TallyTestScenario.DecryptFor(scenario, scenario.GuardianSet.Guardians[0].Index),
            TallyTestScenario.DecryptFor(scenario, scenario.GuardianSet.Guardians[1].Index),
        };
        var resultA = tallyAdmin.Decrypt(subsetA, scenario.Tally, scenario.GuardianSet.ElectionPublicKeys);

        // Second, different subset: guardians 2 & 3 (NOT 1 & 3 -- see
        // Decrypt_IndexGapOfTwoSubset_PinsTruncatingLagrangeCoefficientBug below for why that
        // particular subset currently fails). Lagrange interpolation should be
        // subset-independent -- both K-of-N combinations must recover the same vote counts.
        var subsetB = new List<PartialTallyDecryption>
        {
            TallyTestScenario.DecryptFor(scenario, scenario.GuardianSet.Guardians[1].Index),
            TallyTestScenario.DecryptFor(scenario, scenario.GuardianSet.Guardians[2].Index),
        };
        var resultB = tallyAdmin.Decrypt(subsetB, scenario.Tally, scenario.GuardianSet.ElectionPublicKeys);

        Assert.Equal(2, resultA.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(1, resultA.Contests["contest-1"].Choices["choice-2"].VoteCount);
        Assert.Equal(resultA.Contests["contest-1"].Choices["choice-1"].VoteCount, resultB.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(resultA.Contests["contest-1"].Choices["choice-2"].VoteCount, resultB.Contests["contest-1"].Choices["choice-2"].VoteCount);
    }

    [Fact]
    public void Decrypt_IndexGapOfTwoSubset_PinsTruncatingLagrangeCoefficientBug()
    {
        // PINNED PRODUCTION BUG (newly discovered while implementing this phase, not in the
        // original plan): TallyAdmin.CalculateLagrangeCoefficient computes
        // `ls.Select(x => x.Index).Product()` -- x.Index is `int`, so this resolves to
        // IEnumerableExtensions.Product(IEnumerable<int>), i.e. plain C# int arithmetic, not
        // IntegerModQ. It then does `prodL / prodLMinusI` using truncating integer division
        // instead of a modular inverse in Z_q.
        //
        // For guardian index subsets whose *classical* (non-modular) Lagrange coefficient at
        // x=0 happens to be an exact integer, this accidentally works:
        //   {1,2}: L_1(0) = (0-2)/(1-2) = 2, L_2(0) = (0-1)/(2-1) = -1   (both exact integers)
        //   {2,3}: L_2(0) = (0-3)/(2-3) = 3, L_3(0) = (0-2)/(3-2) = -2  (both exact integers)
        // But for {1,3}, the true coefficients are fractional:
        //   L_1(0) = (0-3)/(1-3) = 1.5, L_3(0) = (0-1)/(3-1) = -0.5
        // which the code truncates to 1 and 0 respectively instead of computing the correct
        // value mod Q (which is what IntegerModQ.operator/ should do via a modular inverse --
        // note IntegerModQ.operator/ itself is ALSO plain truncating BigInteger division, unlike
        // IntegerModP.operator/ which correctly uses a Fermat's-little-theorem modular inverse).
        // The wrong coefficients corrupt the combined `m`, so no candidate `t` in the brute-force
        // range matches and TallyAdmin.Decrypt throws "Tally did not decrypt successfully." This
        // test pins that current (buggy) behavior rather than asserting the idealized
        // subset-independent result -- do not "fix" this test to expect success.
        var scenario = TallyTestScenario.Build();
        var subset = new List<PartialTallyDecryption>
        {
            TallyTestScenario.DecryptFor(scenario, scenario.GuardianSet.Guardians[0].Index),
            TallyTestScenario.DecryptFor(scenario, scenario.GuardianSet.Guardians[2].Index),
        };
        var tallyAdmin = new TallyAdmin();

        var exception = Assert.Throws<Exception>(() => tallyAdmin.Decrypt(subset, scenario.Tally, scenario.GuardianSet.ElectionPublicKeys));
        Assert.Equal("Tally did not decrypt successfully.", exception.Message);
    }

    [Fact]
    public void Decrypt_NoValidCombinationFound_ThrowsException()
    {
        var scenario = TallyTestScenario.Build();
        var guardian1 = scenario.GuardianSet.Guardians[0];
        var guardian2 = scenario.GuardianSet.Guardians[1];

        var partial1 = TallyTestScenario.DecryptFor(scenario, guardian1.Index);
        var partial2 = TallyTestScenario.DecryptFor(scenario, guardian2.Index);

        // Corrupt one guardian's partial decryption share for choice-1 so that no lagrange
        // combination of {corrupted, valid} reproduces a value t = K^i for any i in
        // [0, BallotsCast] -- forcing the brute-force loop in TallyAdmin.Decrypt to fail to find a
        // match (line 109-112).
        partial1.Contests["contest-1"].Choices["choice-1"] = new PartialTallyDecryption.PartialTallyChoiceDecryption
        {
            Mi = new IntegerModP(123456789),
        };

        var partials = new List<PartialTallyDecryption> { partial1, partial2 };
        var tallyAdmin = new TallyAdmin();

        var exception = Assert.Throws<Exception>(() => tallyAdmin.Decrypt(partials, scenario.Tally, scenario.GuardianSet.ElectionPublicKeys));
        Assert.Equal("Tally did not decrypt successfully.", exception.Message);
        // Plain System.Exception, not VerificationFailedException -- TallyAdmin.Decrypt's
        // no-solution case is one of the plain-Exception throw sites documented in research.md.
        Assert.IsType<Exception>(exception);
    }

    [Fact]
    public void Decrypt_ZeroBallotsCast_ThrowsException()
    {
        // Build the guardian set / encryption pipeline but never call AddBallot, leaving every
        // aggregate choice at its EncryptedTally constructor default of A=0, B=0.
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var emptyTally = new EncryptedTally(manifest);
        Assert.Equal(0, emptyTally.BallotsCast);

        var guardian1 = guardianSet.Guardians[0];
        var guardian2 = guardianSet.Guardians[1];
        var partials = new List<PartialTallyDecryption>
        {
            new TallyGuardian(guardian1.Index, guardianSet.SecretShares[guardian1.Index]).Decrypt(emptyTally),
            new TallyGuardian(guardian2.Index, guardianSet.SecretShares[guardian2.Index]).Decrypt(emptyTally),
        };

        var tallyAdmin = new TallyAdmin();

        // PINNED PRODUCTION QUIRK (not in the original plan, discovered while implementing this
        // phase): EncryptedTally's "hasn't been added to yet" sentinel for an aggregate choice is
        // literal IntegerModP(0) for both A and B (the *additive* identity), not the ElGamal
        // ciphertext multiplicative identity (alpha=1, beta=1). When BallotsCast == 0, A stays 0,
        // so each guardian's partial Mi = PowModP(0, share) = 0, the combined m stays 0, and
        // t = B / m evaluates to 0 via IntegerModP's division operator (0 * inverse(0) = 0).
        // t=0 never equals K^0=1 (the only candidate in the [0, BallotsCast=0] brute-force range),
        // so TallyAdmin.Decrypt throws "Tally did not decrypt successfully." instead of returning
        // VoteCount=0 for every choice. This is pinned as current behavior, not fixed.
        var exception = Assert.Throws<Exception>(() => tallyAdmin.Decrypt(partials, emptyTally, guardianSet.ElectionPublicKeys));
        Assert.Equal("Tally did not decrypt successfully.", exception.Message);
    }

    [Fact]
    public void Decrypt_VoteCountEqualsBallotsCast_RecoversAtUpperSearchBoundary()
    {
        // MUTATION-GAP REGRESSION: TallyAdmin.Decrypt's discrete-log brute-force loop is
        // `for (int i = 0; i <= encryptedTally.BallotsCast; i++)`. TallyTestScenario's shared
        // 3-ballot fixture never drives any choice's true vote count up to exactly BallotsCast (the
        // max is 2 out of 3 cast ballots), so it cannot distinguish the inclusive upper bound
        // (`<=`) from an off-by-one exclusive bound (`<`) -- both ranges happen to contain the
        // scenario's actual answers of 2 and 1. Empirically verified: mutating `<=` to `<` in
        // TallyGuardian.cs and re-running the full Tally test file left all existing tests green.
        // Here every ballot votes choice-1, so its true count equals BallotsCast exactly, which is
        // only reachable if the loop's upper bound is inclusive.
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-boundary");

        var ballot1 = ElectionFixtureBuilder.CreateBallot(manifest, "ballot-b1", new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 0 });
        var ballot2 = ElectionFixtureBuilder.CreateBallot(manifest, "ballot-b2", new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 0 });

        var encryptedBallots = new[]
        {
            ElectionFixtureBuilder.CreateEncryptedBallot(encryptionRecordResult.EncryptionRecord, "device-boundary", deviceHash, ballot1),
            ElectionFixtureBuilder.CreateEncryptedBallot(encryptionRecordResult.EncryptionRecord, "device-boundary", deviceHash, ballot2),
        };

        var tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, encryptedBallots);
        Assert.Equal(2, tally.BallotsCast);

        var guardian1 = guardianSet.Guardians[0];
        var guardian2 = guardianSet.Guardians[1];
        var partials = new List<PartialTallyDecryption>
        {
            new TallyGuardian(guardian1.Index, guardianSet.SecretShares[guardian1.Index]).Decrypt(tally),
            new TallyGuardian(guardian2.Index, guardianSet.SecretShares[guardian2.Index]).Decrypt(tally),
        };

        var tallyAdmin = new TallyAdmin();
        var decryptedTally = tallyAdmin.Decrypt(partials, tally, guardianSet.ElectionPublicKeys);

        // choice-1's true count equals BallotsCast exactly -- only reachable with an inclusive
        // upper search bound.
        Assert.Equal(2, decryptedTally.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(0, decryptedTally.Contests["contest-1"].Choices["choice-2"].VoteCount);
    }
}
