using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.TestFixtures;

namespace ElectionGuard.Core.UnitTests.Tally;

public class EncryptedTallyTests
{
    public EncryptedTallyTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    /// <summary>
    /// AddBallot only cares about EncryptedBallot.Contests[*].Choices[*].{Alpha,Beta} and
    /// EncryptedBallot.Weight -- it never touches proofs, ContestHash content, or the confirmation
    /// code chain. So for these accumulation-focused tests we hand-craft a minimal EncryptedBallot
    /// with known Alpha/Beta values rather than running the full guardian/BallotEncryptor pipeline
    /// (that pipeline is exercised by BallotEncryptorTests and the TallyGuardian/TallyAdmin tests
    /// below, which need real ciphertexts).
    /// </summary>
    private static EncryptedBallot CreateHandCraftedBallot(
        string ballotId,
        Dictionary<string, (IntegerModP Alpha, IntegerModP Beta)> choiceValues,
        int weight = 1)
    {
        var placeholderProofs = Array.Empty<ChallengeResponsePair>();
        var placeholderCounter = new EncryptedValueWithProofs
        {
            Alpha = 0,
            Beta = 0,
            Proofs = placeholderProofs,
        };

        var selections = choiceValues.Select(kv => new EncryptedSelection
        {
            ChoiceId = kv.Key,
            Alpha = kv.Value.Alpha,
            Beta = kv.Value.Beta,
            Proofs = placeholderProofs,
        }).ToList();

        var encryptedContest = new EncryptedContest
        {
            Id = "contest-1",
            Choices = selections,
            Proofs = placeholderProofs,
            OvervoteCount = placeholderCounter,
            NullvoteCount = placeholderCounter,
            UndervoteCount = placeholderCounter,
            WriteInVoteCount = placeholderCounter,
            ContestData = null,
            ContestHash = new ContestHash(new byte[] { 0x01 }),
        };

        return new EncryptedBallot
        {
            Id = ballotId,
            SelectionEncryptionIdentifier = new SelectionEncryptionIdentifier(new byte[] { 0x02 }),
            SelectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(new byte[] { 0x03 }),
            BallotStyleId = "ballot-style-1",
            Contests = new List<EncryptedContest> { encryptedContest },
            ConfirmationCode = new ConfirmationCode(new byte[] { 0x04 }),
            Weight = weight,
            DeviceId = "device-1",
        };
    }

    [Fact]
    public void Constructor_FromManifest_InitializesOneAggregateContestPerManifestContest()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var tally = new EncryptedTally(manifest);

        var contest = Assert.Single(tally.Contests);
        Assert.Equal("contest-1", contest.Key);
        Assert.Equal(2, contest.Value.Choices.Count);
        Assert.Contains("choice-1", contest.Value.Choices.Keys);
        Assert.Contains("choice-2", contest.Value.Choices.Keys);
        // Both choices should start at the (0,0) sentinel "not yet initialized" identity.
        foreach (var choice in contest.Value.Choices.Values)
        {
            Assert.True(choice.IsZero());
        }
        Assert.Equal(0, tally.BallotsCast);
    }

    [Fact]
    public void AddBallot_FirstBallot_OverwritesZeroIdentity()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var tally = new EncryptedTally(manifest);

        var ballot = CreateHandCraftedBallot("ballot-1", new()
        {
            ["choice-1"] = (new IntegerModP(7), new IntegerModP(11)),
            ["choice-2"] = (new IntegerModP(13), new IntegerModP(17)),
        });

        tally.AddBallot(ballot);

        var choice1 = tally.Contests["contest-1"].Choices["choice-1"];
        var choice2 = tally.Contests["contest-1"].Choices["choice-2"];
        Assert.Equal(new IntegerModP(7), choice1.A);
        Assert.Equal(new IntegerModP(11), choice1.B);
        Assert.Equal(new IntegerModP(13), choice2.A);
        Assert.Equal(new IntegerModP(17), choice2.B);
    }

    [Fact]
    public void AddBallot_SecondBallot_MultipliesCiphertextsHomomorphically()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var tally = new EncryptedTally(manifest);

        var ballot1 = CreateHandCraftedBallot("ballot-1", new()
        {
            ["choice-1"] = (new IntegerModP(7), new IntegerModP(11)),
            ["choice-2"] = (new IntegerModP(13), new IntegerModP(17)),
        });
        var ballot2 = CreateHandCraftedBallot("ballot-2", new()
        {
            ["choice-1"] = (new IntegerModP(19), new IntegerModP(23)),
            ["choice-2"] = (new IntegerModP(29), new IntegerModP(31)),
        });

        tally.AddBallot(ballot1);
        tally.AddBallot(ballot2);

        var choice1 = tally.Contests["contest-1"].Choices["choice-1"];
        var choice2 = tally.Contests["contest-1"].Choices["choice-2"];

        // ElGamal ciphertext multiplication ⇒ plaintext addition (CLAUDE.md Tally description):
        // hand-verify the product of the two individual ballots' ciphertexts mod P.
        Assert.Equal(new IntegerModP(7) * new IntegerModP(19), choice1.A);
        Assert.Equal(new IntegerModP(11) * new IntegerModP(23), choice1.B);
        Assert.Equal(new IntegerModP(13) * new IntegerModP(29), choice2.A);
        Assert.Equal(new IntegerModP(17) * new IntegerModP(31), choice2.B);
    }

    [Fact]
    public void AddBallot_WeightGreaterThanOne_UsesExponentiationPath()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var tally = new EncryptedTally(manifest);

        // First ballot at weight 1 establishes a known non-zero accumulator so the second
        // ballot's weighted contribution goes through the multiply branch (lines 44-45 -> 56-57),
        // not the IsZero() overwrite branch -- this exercises exponentiation-then-multiply
        // together rather than exponentiation-then-overwrite (covered implicitly by the assertion
        // below since weight is applied before the IsZero() check either way).
        var ballot1 = CreateHandCraftedBallot("ballot-1", new()
        {
            ["choice-1"] = (new IntegerModP(3), new IntegerModP(5)),
            ["choice-2"] = (new IntegerModP(2), new IntegerModP(2)),
        });
        var ballot2 = CreateHandCraftedBallot("ballot-2", new()
        {
            ["choice-1"] = (new IntegerModP(2), new IntegerModP(7)),
            ["choice-2"] = (new IntegerModP(2), new IntegerModP(2)),
        }, weight: 3);

        tally.AddBallot(ballot1);
        tally.AddBallot(ballot2);

        var choice1 = tally.Contests["contest-1"].Choices["choice-1"];

        var expectedA = new IntegerModP(3) * IntegerModP.PowModP(new IntegerModP(2), 3);
        var expectedB = new IntegerModP(5) * IntegerModP.PowModP(new IntegerModP(7), 3);
        Assert.Equal(expectedA, choice1.A);
        Assert.Equal(expectedB, choice1.B);
    }

    [Fact]
    public void AddBallot_WeightGreaterThanOne_AppliedEvenOnFirstOverwriteBallot()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var tally = new EncryptedTally(manifest);

        var ballot = CreateHandCraftedBallot("ballot-1", new()
        {
            ["choice-1"] = (new IntegerModP(3), new IntegerModP(5)),
            ["choice-2"] = (new IntegerModP(3), new IntegerModP(5)),
        }, weight: 2);

        tally.AddBallot(ballot);

        var choice1 = tally.Contests["contest-1"].Choices["choice-1"];
        // Weight is applied to alpha/beta *before* the IsZero() overwrite check, so even the very
        // first ballot on a fresh tally should be raised to the weight power, not stored raw.
        Assert.Equal(IntegerModP.PowModP(new IntegerModP(3), 2), choice1.A);
        Assert.Equal(IntegerModP.PowModP(new IntegerModP(5), 2), choice1.B);
    }

    [Fact]
    public void AddBallot_IncrementsBallotsCast()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var tally = new EncryptedTally(manifest);

        Assert.Equal(0, tally.BallotsCast);

        var ballot1 = CreateHandCraftedBallot("ballot-1", new()
        {
            ["choice-1"] = (new IntegerModP(2), new IntegerModP(3)),
            ["choice-2"] = (new IntegerModP(2), new IntegerModP(3)),
        });
        tally.AddBallot(ballot1);
        Assert.Equal(1, tally.BallotsCast);

        var ballot2 = CreateHandCraftedBallot("ballot-2", new()
        {
            ["choice-1"] = (new IntegerModP(4), new IntegerModP(5)),
            ["choice-2"] = (new IntegerModP(4), new IntegerModP(5)),
        });
        tally.AddBallot(ballot2);
        Assert.Equal(2, tally.BallotsCast);
    }
}
