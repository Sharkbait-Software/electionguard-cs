using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Testing.Common;
using System.Numerics;

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
            SupplementalFields = placeholderCounter.AsFields([.. ElectionFixtureBuilder.DefaultSupplementalFields]),
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
            Status = BallotStatus.Cast,
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
        // G29: one aggregate per verifiable field, the two options and the four supplemental fields
        // the minimal manifest declares.
        Assert.Equal(2 + ElectionFixtureBuilder.DefaultSupplementalFields.Count, contest.Value.Choices.Count);
        Assert.Contains("choice-1", contest.Value.Choices.Keys);
        Assert.Contains("choice-2", contest.Value.Choices.Keys);
        Assert.All(ElectionFixtureBuilder.DefaultSupplementalFields, kind => Assert.Contains(ElectionFixtureBuilder.SupplementalFieldId(kind), contest.Value.Choices.Keys));
        // Every aggregate should start at the (1, 1) "nothing added yet" identity.
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

    /// <summary>Hand-crafted ballots with random ciphertext components and a mix of weights.</summary>
    private static List<EncryptedBallot> CreateRandomBallots(int count, int seed)
    {
        var random = new Random(seed);
        IntegerModP RandomResidue()
        {
            byte[] bytes = new byte[520];
            random.NextBytes(bytes);
            return new IntegerModP(new BigInteger(bytes, isUnsigned: true));
        }

        return Enumerable.Range(0, count)
            .Select(i => CreateHandCraftedBallot($"ballot-{i}", new()
            {
                ["choice-1"] = (RandomResidue(), RandomResidue()),
                ["choice-2"] = (RandomResidue(), RandomResidue()),
            }, weight: i % 5 == 0 ? 3 : 1))
            .ToList();
    }

    [Theory]
    [InlineData(0, -1)]
    [InlineData(5, -1)]
    [InlineData(16, -1)]
    [InlineData(17, -1)]
    [InlineData(200, -1)]
    [InlineData(200, 1)]
    [InlineData(200, 3)]
    public void AddBallots_MatchesAddBallotOneAtATime(int ballotCount, int maxDegreeOfParallelism)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var ballots = CreateRandomBallots(ballotCount, seed: ballotCount);

        var sequential = new EncryptedTally(manifest);
        foreach (var ballot in ballots)
        {
            sequential.AddBallot(ballot);
        }

        var batched = new EncryptedTally(manifest);
        batched.AddBallots(ballots, maxDegreeOfParallelism);

        Assert.Equal(ballotCount, batched.BallotsCast);
        foreach (var choiceId in new[] { "choice-1", "choice-2" })
        {
            var expected = sequential.Contests["contest-1"].Choices[choiceId];
            var actual = batched.Contests["contest-1"].Choices[choiceId];
            Assert.Equal(expected.A, actual.A);
            Assert.Equal(expected.B, actual.B);
        }
    }

    [Fact]
    public void AddBallots_MatchesBigIntegerProduct()
    {
        // Independent of AddBallot: the aggregate is the plain product of every alpha (and beta),
        // each raised to its ballot's weight.
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var ballots = CreateRandomBallots(100, seed: 7);

        var tally = new EncryptedTally(manifest);
        tally.AddBallots(ballots);

        BigInteger p = EGParameters.P;
        BigInteger expectedA = BigInteger.One;
        BigInteger expectedB = BigInteger.One;
        foreach (var ballot in ballots)
        {
            var selection = ballot.Contests[0].Choices.Single(x => x.ChoiceId == "choice-2");
            expectedA = expectedA * BigInteger.ModPow(selection.Alpha, ballot.Weight, p) % p;
            expectedB = expectedB * BigInteger.ModPow(selection.Beta, ballot.Weight, p) % p;
        }

        var choice = tally.Contests["contest-1"].Choices["choice-2"];
        Assert.Equal(expectedA, choice.A.ToBigInteger());
        Assert.Equal(expectedB, choice.B.ToBigInteger());
    }

    [Fact]
    public void AddBallots_AfterAddBallot_Accumulates()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var ballots = CreateRandomBallots(60, seed: 11);

        var sequential = new EncryptedTally(manifest);
        foreach (var ballot in ballots)
        {
            sequential.AddBallot(ballot);
        }

        var mixed = new EncryptedTally(manifest);
        mixed.AddBallot(ballots[0]);
        mixed.AddBallots(ballots.Skip(1).Take(40).ToList());
        mixed.AddBallots(ballots.Skip(41).ToList());

        Assert.Equal(60, mixed.BallotsCast);
        var expected = sequential.Contests["contest-1"].Choices["choice-1"];
        var actual = mixed.Contests["contest-1"].Choices["choice-1"];
        Assert.Equal(expected.A, actual.A);
        Assert.Equal(expected.B, actual.B);
    }

    [Fact]
    public void AggregateSetter_RestartsTheProduct()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var tally = new EncryptedTally(manifest);
        tally.AddBallots(CreateRandomBallots(30, seed: 13));

        var choice = tally.Contests["contest-1"].Choices["choice-1"];
        choice.A = new IntegerModP(7);
        choice.B = new IntegerModP(11);
        Assert.Equal(new IntegerModP(7), choice.A);
        Assert.Equal(new IntegerModP(11), choice.B);

        tally.AddBallot(CreateHandCraftedBallot("ballot-x", new()
        {
            ["choice-1"] = (new IntegerModP(13), new IntegerModP(17)),
            ["choice-2"] = (new IntegerModP(1), new IntegerModP(1)),
        }));
        Assert.Equal(new IntegerModP(7 * 13), choice.A);
        Assert.Equal(new IntegerModP(11 * 17), choice.B);
    }
}
