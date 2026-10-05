using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Testing.Common;

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
        public required EncryptionRecord EncryptionRecord { get; init; }
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
            EncryptionRecord = encryptionRecordResult.EncryptionRecord,
            EncryptedBallots = encryptedBallots,
            Tally = tally,
        };
    }

    public static TallyGuardian TallyGuardian(Result scenario, GuardianIndex guardianIndex)
    {
        return new TallyGuardian(guardianIndex, scenario.GuardianSet.SecretShares[guardianIndex]);
    }

    /// <summary>
    /// The guardian's round-1 message (its partial decryption M_i and d_i) for a decryption by
    /// guardians 1 and 2.
    /// </summary>
    public static PartialTallyDecryption DecryptFor(Result scenario, GuardianIndex guardianIndex)
    {
        var participants = scenario.GuardianSet.Guardians.Take(2).Select(x => x.Index).ToList();
        return TallyGuardian(scenario, guardianIndex).Commit(scenario.Tally, scenario.EncryptionRecord, participants);
    }

    /// <summary>Decrypts the scenario's tally with the guardians at the given 0-based positions of the set.</summary>
    public static DecryptedTally Decrypt(Result scenario, params int[] positions)
    {
        var guardians = positions.Select(i => TallyGuardian(scenario, scenario.GuardianSet.Guardians[i].Index)).ToList();
        return new TallyAdmin().Decrypt(guardians, scenario.Tally, scenario.EncryptionRecord);
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
        // G29: a partial decryption per verifiable field, the two options and the four declared
        // supplemental fields.
        Assert.Equal(2 + ElectionFixtureBuilder.DefaultSupplementalFields.Count, contest.Value.Choices.Count);
        Assert.Contains("choice-1", contest.Value.Choices.Keys);
        Assert.Contains("choice-2", contest.Value.Choices.Keys);
        Assert.All(ElectionFixtureBuilder.DefaultSupplementalFields, kind => Assert.Contains(ElectionFixtureBuilder.SupplementalFieldId(kind), contest.Value.Choices.Keys));

        // Secondary observable, beyond structure: Mi must be the *exact* A^share value (TallyGuardian.Commit),
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
        // guardians (guardians 1 and 2) to prove threshold combination works with fewer than all
        // N shares.
        var decryptedTally = TallyTestScenario.Decrypt(scenario, 0, 1);

        // Known plaintext distribution: choice-1 got 2 votes (ballot-1, ballot-2),
        // choice-2 got 1 vote (ballot-3). This must be exact, not just "did not throw".
        Assert.Equal(2, decryptedTally.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(1, decryptedTally.Contests["contest-1"].Choices["choice-2"].VoteCount);
    }

    [Fact]
    public void Decrypt_LagrangeCoefficients_CombineCorrectly()
    {
        var scenario = TallyTestScenario.Build();

        // First subset: guardians 1 & 2.
        var resultA = TallyTestScenario.Decrypt(scenario, 0, 1);

        // Second, different subset: guardians 2 & 3. Lagrange interpolation should be
        // subset-independent -- both K-of-N combinations must recover the same vote counts.
        var resultB = TallyTestScenario.Decrypt(scenario, 1, 2);

        Assert.Equal(2, resultA.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(1, resultA.Contests["contest-1"].Choices["choice-2"].VoteCount);
        Assert.Equal(resultA.Contests["contest-1"].Choices["choice-1"].VoteCount, resultB.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(resultA.Contests["contest-1"].Choices["choice-2"].VoteCount, resultB.Contests["contest-1"].Choices["choice-2"].VoteCount);
    }

    [Fact]
    public void Decrypt_IndexGapOfTwoSubset_RecoversCorrectVoteCounts()
    {
        // Was a PINNED PRODUCTION BUG: TallyAdmin.CalculateLagrangeCoefficient used to compute
        // `ls.Select(x => x.Index).Product()` -- x.Index is `int`, so this resolved to
        // IEnumerableExtensions.Product(IEnumerable<int>), i.e. plain C# int arithmetic, not
        // IntegerModQ -- then did `prodL / prodLMinusI` using truncating integer division instead
        // of a modular inverse in Z_q.
        //
        // For guardian index subsets whose *classical* (non-modular) Lagrange coefficient at x=0
        // happens to be an exact integer ({1,2}, {2,3}), that accidentally worked. But for {1,3},
        // the true coefficients are fractional (L_1(0) = 1.5, L_3(0) = -0.5), which used to get
        // truncated to 1 and 0 instead of the correct value mod Q.
        //
        // Fixed by computing the whole Lagrange coefficient in IntegerModQ (now
        // TallyDecryptionHashes.LagrangeCoefficient) combined with a corrected IntegerModQ
        // division operator that uses a Fermat's-little-theorem modular inverse (matching
        // IntegerModP.operator/), so this subset now recovers the same subset-independent result
        // as {1,2} and {2,3} (see Decrypt_LagrangeCoefficients_CombineCorrectly).
        var scenario = TallyTestScenario.Build();

        var decryptedTally = TallyTestScenario.Decrypt(scenario, 0, 2);

        Assert.Equal(2, decryptedTally.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(1, decryptedTally.Contests["contest-1"].Choices["choice-2"].VoteCount);
    }

    [Fact]
    public void Decrypt_PartialDecryptionAlteredInTransit_IsCaughtByTheOtherGuardiansCommitmentCheck()
    {
        var scenario = TallyTestScenario.Build();
        var guardian1 = TallyTestScenario.TallyGuardian(scenario, scenario.GuardianSet.Guardians[0].Index);
        var guardian2 = TallyTestScenario.TallyGuardian(scenario, scenario.GuardianSet.Guardians[1].Index);
        var participants = new List<GuardianIndex> { guardian1.Index, guardian2.Index };

        var partial1 = guardian1.Commit(scenario.Tally, scenario.EncryptionRecord, participants);
        var partial2 = guardian2.Commit(scenario.Tally, scenario.EncryptionRecord, participants);

        // Corrupt one guardian's partial decryption share for choice-1, in transit, so that no
        // lagrange combination of {corrupted, valid} reproduces a value t = K^i for any i in
        // [0, BallotsCast]. Guardian 1 still sees its own message as it sent it; guardian 2 sees
        // the corrupted copy.
        var original = partial1.Contests["contest-1"].Choices["choice-1"];
        var corrupted = new PartialTallyDecryption
        {
            GuardianIndex = partial1.GuardianIndex,
            Contests = partial1.Contests.ToDictionary(
                contest => contest.Key,
                contest => new PartialTallyDecryption.PartialTallyContestDecryption
                {
                    Choices = new Dictionary<string, PartialTallyDecryption.PartialTallyChoiceDecryption>(contest.Value.Choices),
                }),
        };
        corrupted.Contests["contest-1"].Choices["choice-1"] = new PartialTallyDecryption.PartialTallyChoiceDecryption
        {
            Mi = new IntegerModP(123456789),
            CommitmentHash = original.CommitmentHash,
        };

        var reveal1 = guardian1.Reveal([partial1, partial2]);
        var reveal2 = guardian2.Reveal([corrupted, partial2]);

        // This used to surface only at the very end, as a plain Exception from the discrete-log
        // search. Now M_1 is bound into d_1 (eq. 88), so guardian 2 halts the protocol before it
        // responds, and names guardian 1 (p.48).
        var exception = Assert.Throws<TallyDecryptionException>(() => guardian2.Respond([reveal1, reveal2]));
        Assert.Equal(guardian1.Index, exception.OffendingGuardian);
        Assert.Contains("eq. 88", exception.Message);

        // The decryption is over for guardian 2: it never responds with that u_2.
        Assert.Throws<InvalidOperationException>(() => guardian2.Respond([reveal1, reveal2]));
    }

    [Fact]
    public void Decrypt_ZeroBallotsCast_ReturnsZeroVoteCountForEveryChoice()
    {
        // Build the guardian set / encryption pipeline but never call AddBallot, leaving every
        // aggregate choice at its EncryptedTally constructor default -- now the ElGamal ciphertext
        // multiplicative identity (alpha=1, beta=1) rather than the additive identity (0, 0) (see
        // EncryptedTally's constructor). With A=1, each guardian's partial Mi = PowModP(1, share) =
        // 1, the combined m stays 1, and t = B / m = 1 / 1 = 1, which correctly matches
        // K^0 = 1 -- the only candidate in the [0, BallotsCast=0] brute-force range -- so
        // TallyAdmin.Decrypt now returns VoteCount=0 for every choice instead of throwing.
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var encryptionRecord = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        var emptyTally = new EncryptedTally(manifest);
        Assert.Equal(0, emptyTally.BallotsCast);

        var decryptedTally = ElectionFixtureBuilder.DecryptTally(guardianSet, emptyTally, encryptionRecord, 2);

        Assert.Equal(0, decryptedTally.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(0, decryptedTally.Contests["contest-1"].Choices["choice-2"].VoteCount);
    }

    [Fact]
    public void Decrypt_VoteCountEqualsBallotsCast_RecoversAtUpperSearchBoundary()
    {
        // MUTATION-GAP REGRESSION: TallyAdmin.Decrypt's discrete-log search covers
        // [0, the bound] inclusive. TallyTestScenario's shared 3-ballot fixture never drives any
        // choice's true vote count up to exactly BallotsCast (the max is 2 out of 3 cast ballots),
        // so it cannot distinguish the inclusive upper bound from an off-by-one exclusive bound --
        // both ranges happen to contain the scenario's actual answers of 2 and 1. Here every ballot
        // votes choice-1, so its true count equals BallotsCast exactly, which is only reachable if
        // the upper bound is inclusive.
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

        var decryptedTally = ElectionFixtureBuilder.DecryptTally(guardianSet, tally, encryptionRecordResult.EncryptionRecord, 2);

        // choice-1's true count equals BallotsCast exactly -- only reachable with an inclusive
        // upper search bound.
        Assert.Equal(2, decryptedTally.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(0, decryptedTally.Contests["contest-1"].Choices["choice-2"].VoteCount);
    }
}

/// <summary>
/// TallyAdmin.Decrypt across the whole [0, BallotsCast] search range. Rather than encrypting a ballot
/// per vote, each aggregate is set directly to an ElGamal encryption of a chosen count v under the
/// election key, (g^xi, K^(v + xi)), so counts at every giant-step boundary of the discrete-log
/// search are cheap to reach. BallotsCast is raised to the bound with placeholder ballots whose
/// ciphertexts the setters then overwrite.
/// </summary>
public class TallyAdminSearchRangeTests
{
    private const int BallotsCast = 40;

    private static EncryptedBallot CreatePlaceholderBallot(string ballotId, IEnumerable<string> choiceIds)
    {
        var placeholderProofs = Array.Empty<ChallengeResponsePair>();
        var placeholderCounter = new EncryptedValueWithProofs { Alpha = 1, Beta = 1, Proofs = placeholderProofs };

        return new EncryptedBallot
        {
            Id = ballotId,
            SelectionEncryptionIdentifier = new SelectionEncryptionIdentifier(new byte[] { 0x02 }),
            SelectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(new byte[] { 0x03 }),
            BallotStyleId = "ballot-style-1",
            Contests = new List<EncryptedContest>
            {
                new EncryptedContest
                {
                    Id = "contest-1",
                    Choices = choiceIds
                        .Select(choiceId => new EncryptedSelection { ChoiceId = choiceId, Alpha = 1, Beta = 1, Proofs = placeholderProofs })
                        .ToList(),
                    Proofs = placeholderProofs,
                    // The manifest below declares no supplemental fields: these tests are about the
                    // search over option counts, and the tamper hook indexes the counts by option index.
                    SupplementalFields = [],
                    ContestData = null,
                    ContestHash = new ContestHash(new byte[] { 0x01 }),
                },
            },
            ConfirmationCode = new ConfirmationCode(new byte[] { 0x04 }),
            Weight = 1,
            DeviceId = "device-1",
            Status = BallotStatus.Cast,
        };
    }

    private static DecryptedTally DecryptCounts(int count1, int count2, int maxDegreeOfParallelism = -1)
    {
        return DecryptCounts([count1, count2], maxDegreeOfParallelism);
    }

    /// <summary>
    /// Decrypts a one-contest tally whose choice-(i+1) encrypts counts[i]. More than two counts adds
    /// choices to the minimal manifest. A null count plants a partial decryption of zero for that
    /// choice instead, as only a corrupt share could.
    /// </summary>
    private static DecryptedTally DecryptCounts(int?[] counts, int maxDegreeOfParallelism = -1)
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(supplementalFields: []);
        var choices = manifest.Contests[0].Choices;
        for (int i = choices.Count; i < counts.Length; i++)
        {
            choices.Add(new Choice { Id = $"choice-{i + 1}", Name = $"Choice {i + 1}", Index = i + 1 });
        }

        var encryptionRecord = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        var choiceIds = choices.Select(x => x.Id).ToList();
        var tally = new EncryptedTally(manifest);
        tally.AddBallots(Enumerable.Range(0, BallotsCast).Select(i => CreatePlaceholderBallot($"ballot-{i}", choiceIds)).ToList());
        Assert.Equal(BallotsCast, tally.BallotsCast);

        IntegerModP k = guardianSet.ElectionPublicKeys.VoteEncryptionKey;
        for (int i = 0; i < counts.Length; i++)
        {
            int nonce = 987654321 + 7919 * i;
            var choice = tally.Contests["contest-1"].Choices[choiceIds[i]];
            choice.A = IntegerModP.PowModP(EGParameters.G, new IntegerModQ(nonce));
            choice.B = IntegerModP.PowModP(k, new IntegerModQ((counts[i] ?? 0) + nonce));
        }

        var guardians = ElectionFixtureBuilder.TallyGuardians(guardianSet, 2);

        // A corrupt guardian 1 that sends M_1 = 0 (and hashes it consistently into d_1) for every
        // null count.
        guardians[0].PartialDecryptionTamperForTesting = (contestIndex, optionIndex, mi) =>
            counts[optionIndex - 1] is null ? new IntegerModP(0) : mi;

        return new TallyAdmin().Decrypt(guardians, tally, encryptionRecord, maxDegreeOfParallelism);
    }

    [Fact]
    public void Decrypt_ManyChoices_RecoversEveryCount()
    {
        // Seven choices, so the batch inversion in TallyAdmin peels several inverses off the shared
        // product rather than the one a two-choice tally needs.
        int?[] counts = [40, 0, 13, 1, 27, 39, 7];

        var decrypted = DecryptCounts(counts);

        for (int i = 0; i < counts.Length; i++)
        {
            Assert.Equal(counts[i], decrypted.Contests["contest-1"].Choices[$"choice-{i + 1}"].VoteCount);
        }
    }

    [Fact]
    public void Decrypt_ZeroPartialDecryption_ThrowsNamingTheGuardian()
    {
        // A zero M has no inverse; it must fail as an undecryptable tally, not with an
        // ArgumentException from the inversion. It used to be a plain Exception; it is now a
        // TallyDecryptionException naming the guardian whose M_i is 0.
        var exception = Assert.Throws<TallyDecryptionException>(() => DecryptCounts([3, null, 5]));

        Assert.StartsWith("Tally did not decrypt successfully", exception.Message, StringComparison.Ordinal);
        Assert.Equal(1, exception.OffendingGuardian?.Index);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(7)]
    public void InvertAll_MatchesIndividualInverses(int count)
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var random = new Random(count);
        var values = Enumerable.Range(0, count).Select(_ =>
        {
            byte[] bytes = new byte[520];
            random.NextBytes(bytes);
            return new IntegerModP(new System.Numerics.BigInteger(bytes, isUnsigned: true) % (EGParameters.P - 1) + 1);
        }).ToArray();

        var inverses = TallyAdmin.InvertAll(values);

        for (int i = 0; i < count; i++)
        {
            Assert.Equal(new IntegerModP(1), values[i] * inverses[i]);
        }
    }

    [Theory]
    [InlineData(0, BallotsCast)]
    [InlineData(1, BallotsCast - 1)]
    [InlineData(9, 10)]
    [InlineData(11, 19)]
    [InlineData(20, 21)]
    [InlineData(29, 30)]
    [InlineData(31, 39)]
    public void Decrypt_CountsAcrossTheSearchRange_AreRecovered(int count1, int count2)
    {
        // Two choices and 41 candidates put the giant step at ceil(sqrt(82)) = 10, so these cover
        // both ends of the range and both sides of several giant-step boundaries.
        var decrypted = DecryptCounts(count1, count2);

        Assert.Equal(count1, decrypted.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(count2, decrypted.Contests["contest-1"].Choices["choice-2"].VoteCount);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void Decrypt_LimitedParallelism_RecoversTheSameCounts(int maxDegreeOfParallelism)
    {
        var decrypted = DecryptCounts(17, 3, maxDegreeOfParallelism);

        Assert.Equal(17, decrypted.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(3, decrypted.Contests["contest-1"].Choices["choice-2"].VoteCount);
    }

    [Theory]
    [InlineData(BallotsCast + 1)]
    [InlineData(BallotsCast + 9)]
    [InlineData(1000)]
    public void Decrypt_CountAboveTheBound_Throws(int count)
    {
        // The placeholder ballots have weight 1 and R = L = 1, so each option's bound is
        // BallotsCast. The proof is valid (the aggregate really encrypts the count), so nothing
        // names a guardian; the count is simply out of range. This used to be a plain Exception.
        var exception = Assert.Throws<TallyDecryptionException>(() => DecryptCounts(5, count));

        Assert.StartsWith("Tally did not decrypt successfully", exception.Message, StringComparison.Ordinal);
        Assert.Null(exception.OffendingGuardian);
    }
}
