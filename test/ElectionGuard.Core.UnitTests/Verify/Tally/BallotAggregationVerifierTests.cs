using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.Verify.Tally;

/// <summary>
/// Verification 9 fed incrementally. The claimed tally in every test is built one ballot at a time
/// by ElectionFixtureBuilder.CreateEncryptedTally -- a different code path from the verifier's own
/// chunked (and, above 16 ballots a chunk, parallel) accumulation -- so passing means the two agree,
/// not merely that one tally was compared with itself.
/// </summary>
public class BallotAggregationVerifierTests
{
    private const int BallotCount = 40;

    private sealed class Scenario
    {
        public required Manifest Manifest { get; init; }
        public required List<EncryptedBallot> Ballots { get; init; }
        public required EncryptedTally Tally { get; init; }
    }

    /// <summary>
    /// Built once for the class: a key ceremony plus eight encryptions costs several seconds in a
    /// Debug build, and every test here only reads the scenario (the verifier never mutates the
    /// tally it checks, and nothing else touches the ballots or the tally).
    /// </summary>
    private static readonly Lazy<Scenario> SharedScenario = new(CreateScenario);

    private static Scenario Build()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        return SharedScenario.Value;
    }

    /// <summary>
    /// Eight independently encrypted ballots (fresh nonces, so eight distinct ciphertexts even where
    /// the plaintext repeats), cycled to 40. Aggregation does not care whether ballots are distinct,
    /// and eight distinct ones are enough that dropping a ballot from any chunk changes the product.
    /// </summary>
    private static Scenario CreateScenario()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");

        var selections = new[]
        {
            new Dictionary<string, int> { ["choice-1"] = 1 },
            new Dictionary<string, int> { ["choice-2"] = 1 },
            new Dictionary<string, int>(),
        };

        var distinct = Enumerable.Range(0, 8)
            .Select(i => ElectionFixtureBuilder.CreateEncryptedBallot(
                encryptionRecordResult.EncryptionRecord,
                "device-1",
                deviceHash,
                ElectionFixtureBuilder.CreateBallot(manifest, $"ballot-{i}", selections[i % selections.Length])))
            .ToList();

        var ballots = Enumerable.Range(0, BallotCount).Select(i => distinct[i % distinct.Count]).ToList();

        return new Scenario
        {
            Manifest = manifest,
            Ballots = ballots,
            Tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, ballots.ToArray()),
        };
    }

    private static IEnumerable<List<EncryptedBallot>> Chunks(List<EncryptedBallot> ballots, int chunkSize) =>
        ballots.Chunk(chunkSize).Select(chunk => chunk.ToList());

    private static void AssertFailsVerification9(BallotAggregationVerifier verifier, EncryptedTally tally)
    {
        var exception = Assert.Throws<VerificationFailedException>(() => verifier.Verify(tally));

        // Same contract as BallotAggregationVerification. Every use here leaves a ballot out, adds
        // one twice or weights one differently, which changes both A and B of the first option;
        // A is compared first (G38: this used to be a plain System.Exception with no sub-section).
        Assert.Equal("9.A", exception.SubSection);
        Assert.StartsWith("Ballot aggregation verification failed", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1, -1)]
    [InlineData(7, -1)]
    [InlineData(7, 1)]
    [InlineData(17, -1)]
    [InlineData(17, 1)]
    [InlineData(17, 4)]
    [InlineData(40, -1)]
    [InlineData(40, 1)]
    [InlineData(40, 4)]
    public void AddBallots_InChunks_MatchesATallyBuiltBallotByBallot(int chunkSize, int maxDegreeOfParallelism)
    {
        var scenario = Build();
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        foreach (var chunk in Chunks(scenario.Ballots, chunkSize))
        {
            verifier.AddBallots(chunk, maxDegreeOfParallelism);
        }

        Assert.Equal(BallotCount, verifier.BallotsAdded);
        Assert.Null(Record.Exception(() => verifier.Verify(scenario.Tally)));
    }

    [Fact]
    public void AddBallot_OneAtATime_MatchesTheTally()
    {
        var scenario = Build();
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        foreach (var ballot in scenario.Ballots)
        {
            verifier.AddBallot(ballot);
        }

        Assert.Equal(BallotCount, verifier.BallotsAdded);
        Assert.Null(Record.Exception(() => verifier.Verify(scenario.Tally)));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    [InlineData(4)]
    public void AddBallots_ABallotMissingFromAnyChunk_FailsVerification(int maxDegreeOfParallelism)
    {
        var scenario = Build();
        var chunks = Chunks(scenario.Ballots, 17).ToList();

        for (int dropFrom = 0; dropFrom < chunks.Count; dropFrom++)
        {
            var verifier = new BallotAggregationVerifier(scenario.Manifest);
            for (int i = 0; i < chunks.Count; i++)
            {
                verifier.AddBallots(i == dropFrom ? chunks[i].Skip(1).ToList() : chunks[i], maxDegreeOfParallelism);
            }

            Assert.Equal(BallotCount - 1, verifier.BallotsAdded);
            AssertFailsVerification9(verifier, scenario.Tally);
        }
    }

    [Fact]
    public void AddBallots_ABallotAddedTwice_FailsVerification()
    {
        var scenario = Build();
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        verifier.AddBallots(scenario.Ballots);
        verifier.AddBallot(scenario.Ballots[0]);

        AssertFailsVerification9(verifier, scenario.Tally);
    }

    [Fact]
    public void Verify_BeforeAnyBallotIsAdded_FailsAgainstANonEmptyTally()
    {
        var scenario = Build();
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        Assert.Equal(0, verifier.BallotsAdded);
        AssertFailsVerification9(verifier, scenario.Tally);
    }

    [Fact]
    public void Verify_BeforeAnyBallotIsAdded_PassesAgainstAnEmptyTally()
    {
        var scenario = Build();
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        Assert.Null(Record.Exception(() => verifier.Verify(new EncryptedTally(scenario.Manifest))));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void AddBallots_AnEmptyChunk_ChangesNothing(int maxDegreeOfParallelism)
    {
        var scenario = Build();
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        verifier.AddBallots([], maxDegreeOfParallelism);
        foreach (var chunk in Chunks(scenario.Ballots, 17))
        {
            verifier.AddBallots(chunk, maxDegreeOfParallelism);
            verifier.AddBallots([], maxDegreeOfParallelism);
        }

        Assert.Equal(BallotCount, verifier.BallotsAdded);
        Assert.Null(Record.Exception(() => verifier.Verify(scenario.Tally)));
    }

    /// <summary>
    /// Verify reads the recomputation without consuming it, so a caller can check a running claim
    /// part-way through a stream and keep adding ballots afterwards.
    /// </summary>
    [Fact]
    public void Verify_PartWayThrough_LeavesTheVerifierUsable()
    {
        var scenario = Build();
        var firstHalf = scenario.Ballots.Take(BallotCount / 2).ToList();
        var secondHalf = scenario.Ballots.Skip(BallotCount / 2).ToList();
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        verifier.AddBallots(firstHalf);
        Assert.Null(Record.Exception(() => verifier.Verify(ElectionFixtureBuilder.CreateEncryptedTally(scenario.Manifest, firstHalf.ToArray()))));
        AssertFailsVerification9(verifier, scenario.Tally);

        verifier.AddBallots(secondHalf);
        Assert.Null(Record.Exception(() => verifier.Verify(scenario.Tally)));
    }

    /// <summary>
    /// A copy of <paramref name="ballot"/> with an extra contest the manifest does not have, after
    /// its real ones: adding it multiplies the real contests in, then throws on the unknown one.
    /// </summary>
    private static EncryptedBallot WithUnknownTrailingContest(EncryptedBallot ballot) => new()
    {
        Id = ballot.Id,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        BallotStyleId = ballot.BallotStyleId,
        Contests = [.. ballot.Contests, ballot.Contests[0] with { Id = "contest-not-in-manifest" }],
        ConfirmationCode = ballot.ConfirmationCode,
        EncryptedBallotNonce = ballot.EncryptedBallotNonce,
        ChainingField = ballot.ChainingField,
        Weight = ballot.Weight,
        Status = ballot.Status,
        DeviceId = ballot.DeviceId,
    };

    private static void AssertFaulted(BallotAggregationVerifier verifier, EncryptedTally tally)
    {
        var exception = Assert.Throws<InvalidOperationException>(() => verifier.Verify(tally));
        Assert.IsNotType<VerificationFailedException>(exception);
    }

    /// <summary>
    /// A malformed ballot throws while its chunk is being added. The structural check rejects it
    /// before any of its own ciphertexts are multiplied in, but depending on chunking and parallelism
    /// some of its neighbours' may already be in the recomputation. Whatever was kept, the verifier
    /// must refuse to reach a verdict afterwards -- against the tally of the well-formed ballots, the
    /// full tally, or anything else -- rather than give one that depends on how the ballots were
    /// grouped. The sequential path (maxDegreeOfParallelism 1, or 16 ballots or fewer) keeps the
    /// ballots before the malformed one; the parallel one drops the whole chunk before merging.
    /// </summary>
    [Theory]
    [InlineData(5, 1)]
    [InlineData(5, -1)]
    [InlineData(40, 1)]
    [InlineData(40, -1)]
    [InlineData(40, 4)]
    public void AddBallots_AMalformedBallot_FaultsTheVerifier(int chunkSize, int maxDegreeOfParallelism)
    {
        var scenario = Build();
        var chunk = scenario.Ballots.Take(chunkSize).ToList();
        chunk[chunkSize / 2] = WithUnknownTrailingContest(chunk[chunkSize / 2]);
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        Assert.ThrowsAny<Exception>(() => verifier.AddBallots(chunk, maxDegreeOfParallelism));

        AssertFaulted(verifier, scenario.Tally);
        AssertFaulted(verifier, ElectionFixtureBuilder.CreateEncryptedTally(scenario.Manifest, scenario.Ballots.Take(chunkSize).ToArray()));
        AssertFaulted(verifier, new EncryptedTally(scenario.Manifest));

        // Adding well-formed ballots afterwards does not clear the fault.
        verifier.AddBallots(scenario.Ballots, maxDegreeOfParallelism);
        AssertFaulted(verifier, scenario.Tally);
    }

    [Fact]
    public void AddBallot_AMalformedBallot_FaultsTheVerifier()
    {
        var scenario = Build();
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        verifier.AddBallot(scenario.Ballots[0]);

        // A contest the manifest lacks is a structural failure (BallotStructure), rejected before any
        // of the ballot's ciphertexts are multiplied in. It used to surface as a KeyNotFoundException
        // from the aggregate's dictionary, after the ballot's earlier contests had been added.
        var exception = Assert.Throws<VerificationFailedException>(() => verifier.AddBallot(WithUnknownTrailingContest(scenario.Ballots[1])));
        Assert.Equal("9.structure", exception.SubSection);

        Assert.Equal(1, verifier.BallotsAdded);
        AssertFaulted(verifier, ElectionFixtureBuilder.CreateEncryptedTally(scenario.Manifest, scenario.Ballots[0]));
        AssertFaulted(verifier, ElectionFixtureBuilder.CreateEncryptedTally(scenario.Manifest, scenario.Ballots[0], scenario.Ballots[1]));
    }

    /// <summary>
    /// A lazily yielded sequence -- deliberately not a list, so AddBallots takes its streaming path
    /// rather than the IReadOnlyList one -- that counts how many times it is enumerated.
    /// </summary>
    private sealed class LazyBallots(IEnumerable<EncryptedBallot> ballots) : IEnumerable<EncryptedBallot>
    {
        public int Enumerations { get; private set; }

        public IEnumerator<EncryptedBallot> GetEnumerator()
        {
            Enumerations++;
            foreach (var ballot in ballots)
            {
                yield return ballot;
            }
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    [InlineData(4)]
    public void AddBallots_FromALazySequence_MatchesTheTallyAndEnumeratesOnce(int maxDegreeOfParallelism)
    {
        var scenario = Build();
        var source = new LazyBallots(scenario.Ballots);
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        verifier.AddBallots(source, maxDegreeOfParallelism);

        Assert.Equal(1, source.Enumerations);
        Assert.Equal(BallotCount, verifier.BallotsAdded);
        Assert.Null(Record.Exception(() => verifier.Verify(scenario.Tally)));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    [InlineData(4)]
    public void AddBallots_FromALazySequenceMissingABallot_FailsVerification(int maxDegreeOfParallelism)
    {
        var scenario = Build();
        var verifier = new BallotAggregationVerifier(scenario.Manifest);

        verifier.AddBallots(new LazyBallots(scenario.Ballots.Where((_, i) => i != BallotCount / 2)), maxDegreeOfParallelism);

        Assert.Equal(BallotCount - 1, verifier.BallotsAdded);
        AssertFailsVerification9(verifier, scenario.Tally);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    [InlineData(4)]
    public void AddBallots_FromALazySequenceWithAMalformedBallot_FaultsTheVerifier(int maxDegreeOfParallelism)
    {
        var scenario = Build();
        var verifier = new BallotAggregationVerifier(scenario.Manifest);
        var ballots = scenario.Ballots.Select((ballot, i) => i == BallotCount / 2 ? WithUnknownTrailingContest(ballot) : ballot);

        Assert.ThrowsAny<Exception>(() => verifier.AddBallots(new LazyBallots(ballots), maxDegreeOfParallelism));

        AssertFaulted(verifier, scenario.Tally);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void BallotAggregationVerification_FromALazySequence_VerifiesInOneCall(int maxDegreeOfParallelism)
    {
        var scenario = Build();
        var verification = new BallotAggregationVerification();

        Assert.Null(Record.Exception(() => verification.Verify(new LazyBallots(scenario.Ballots), scenario.Manifest, scenario.Tally, maxDegreeOfParallelism)));
        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(new LazyBallots(scenario.Ballots.Skip(1)), scenario.Manifest, scenario.Tally, maxDegreeOfParallelism));
        Assert.Equal("9.A", exception.SubSection);
    }

    /// <summary>
    /// A ballot of weight w contributes (alpha^w, beta^w), the same as w copies of a weight-1
    /// ballot -- which is how the claimed tally here is built, independently of the verifier's
    /// exponentiation path.
    /// </summary>
    [Fact]
    public void AddBallot_WeightedBallot_MatchesThatManyUnweightedCopies()
    {
        const int weight = 3;
        var scenario = Build();
        var ballot = scenario.Ballots[0];
        var weighted = new EncryptedBallot
        {
            Id = ballot.Id,
            SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
            BallotStyleId = ballot.BallotStyleId,
            Contests = ballot.Contests,
            ConfirmationCode = ballot.ConfirmationCode,
            EncryptedBallotNonce = ballot.EncryptedBallotNonce,
            ChainingField = ballot.ChainingField,
            Weight = weight,
            Status = BallotStatus.Cast,
            DeviceId = ballot.DeviceId,
        };

        var verifier = new BallotAggregationVerifier(scenario.Manifest);
        verifier.AddBallot(weighted);

        Assert.Null(Record.Exception(() => verifier.Verify(
            ElectionFixtureBuilder.CreateEncryptedTally(scenario.Manifest, Enumerable.Repeat(ballot, weight).ToArray()))));
        AssertFailsVerification9(verifier, ElectionFixtureBuilder.CreateEncryptedTally(scenario.Manifest, ballot));
    }
}
