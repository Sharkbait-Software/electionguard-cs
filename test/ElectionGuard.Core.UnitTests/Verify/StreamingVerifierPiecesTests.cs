using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.Crypto;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.Tally;
using System.Security.Cryptography;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordCarrierElections;

namespace ElectionGuard.Core.UnitTests.Verify;

/// <summary>
/// S10b-8 (design §6.2-§6.8): the streaming verifier's pieces on their own: the constant-memory chain
/// walker, the spilling 5.A set, and the Verification 9 partials merged through the standard form.
/// </summary>
public class StreamingVerifierPiecesTests
{
    public StreamingVerifierPiecesTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    // ---- DeviceChainWalker --------------------------------------------------------------------------

    private static (EncryptionRecord Record, List<EncryptedBallot> Ballots, DeviceChainRecord Chain) DeviceOne()
    {
        var election = RegularElection.Value;
        var ballots = election.Devices.Single(x => x.DeviceId == "device-1").Ballots;
        var chain = new DeviceChain(election.Record, "device-1");
        foreach (var ballot in ballots)
        {
            chain.Append(ballot);
        }

        return (election.Record, ballots, chain.Close());
    }

    /// <summary>
    /// The walker collects: after a link that fails 8.E it goes on against the code the link states,
    /// so a second broken link is reported too (the domain API, built on it, throws the first), and a
    /// sound chain closes (8.G) without a finding.
    /// </summary>
    [Fact]
    public void Walker_ReportsEveryBrokenLink_AndAcceptsTheSoundChain()
    {
        var (record, ballots, chain) = DeviceOne();
        var walker = new DeviceChainWalker(DeviceChainWalk.Encrypted, record);
        Assert.Null(walker.Begin(chain.DeviceId, chain.DeviceInformationHash, chain.BallotKind, chain.ChainingMode, chain.InitialHash));
        Assert.All(ballots, b => Assert.Null(walker.Next(b.Id, b.ConfirmationCode, b.ChainingField)));
        Assert.Null(walker.End(chain.ClosingChainingField, chain.ClosingHash));
        Assert.Equal(ElectionGuard.Core.RecordFormat.RecordDigests.CodesRoot(chain.ConfirmationCodes), walker.CodesRoot);

        // Ballots 2 and 4 swapped with each other's chaining field: both links break.
        var broken = new DeviceChainWalker(DeviceChainWalk.Encrypted, record);
        broken.Begin(chain.DeviceId, chain.DeviceInformationHash, chain.BallotKind, chain.ChainingMode, chain.InitialHash);
        var failures = ballots.Select((b, i) => broken.Next(b.Id, b.ConfirmationCode, i == 1 ? ballots[3].ChainingField : i == 3 ? ballots[1].ChainingField : b.ChainingField)).ToList();
        Assert.Equal([null, "8.E", null, "8.E"], failures.Select(x => x?.SubSection));
        Assert.Null(broken.End(chain.ClosingChainingField, chain.ClosingHash));
    }

    /// <summary>A link that cannot be read is skipped: the next link and the close are not checked against it, and the walk is incomplete.</summary>
    [Fact]
    public void Walker_SkippedLink_LeavesTheChainIncomplete()
    {
        var (record, ballots, chain) = DeviceOne();
        var walker = new DeviceChainWalker(DeviceChainWalk.Encrypted, record);
        walker.Begin(chain.DeviceId, chain.DeviceInformationHash, chain.BallotKind, chain.ChainingMode, chain.InitialHash);
        Assert.Null(walker.Next(ballots[0].Id, ballots[0].ConfirmationCode, ballots[0].ChainingField));
        walker.Skip();
        Assert.Null(walker.Next(ballots[2].Id, ballots[2].ConfirmationCode, ballots[0].ChainingField)); // unknowable after the gap
        walker.Skip();
        Assert.False(walker.IsComplete);
        Assert.Equal(4, walker.Count);
        Assert.Null(walker.End(chain.ClosingChainingField, chain.ClosingHash));
    }

    /// <summary>Design §6.8: a walker exported mid-chain and imported into a new one finishes exactly as an uninterrupted walk.</summary>
    [Fact]
    public void Walker_ExportedAndImportedMidChain_FinishesAsAnUninterruptedWalk()
    {
        var (record, ballots, chain) = DeviceOne();
        var first = new DeviceChainWalker(DeviceChainWalk.Encrypted, record);
        first.Begin(chain.DeviceId, chain.DeviceInformationHash, chain.BallotKind, chain.ChainingMode, chain.InitialHash);
        first.Next(ballots[0].Id, ballots[0].ConfirmationCode, ballots[0].ChainingField);
        first.Next(ballots[1].Id, ballots[1].ConfirmationCode, ballots[1].ChainingField);

        var second = new DeviceChainWalker(DeviceChainWalk.Encrypted, record);
        second.Import(first.Export());
        Assert.Null(second.Next(ballots[2].Id, ballots[2].ConfirmationCode, ballots[2].ChainingField));
        Assert.Equal("8.E", second.Next(ballots[3].Id, ballots[3].ConfirmationCode, ballots[1].ChainingField)!.SubSection);

        var resumed = new DeviceChainWalker(DeviceChainWalk.Encrypted, record);
        resumed.Import(first.Export());
        resumed.Next(ballots[2].Id, ballots[2].ConfirmationCode, ballots[2].ChainingField);
        resumed.Next(ballots[3].Id, ballots[3].ConfirmationCode, ballots[3].ChainingField);
        Assert.Null(resumed.End(chain.ClosingChainingField, chain.ClosingHash));
        Assert.Equal(ElectionGuard.Core.RecordFormat.RecordDigests.CodesRoot(chain.ConfirmationCodes), resumed.CodesRoot);

        // A dropped last ballot with a recomputed close passes the walk (the close is over what is
        // listed); only a chain-close attestation over ℓ and codes_root catches it (design §4.9).
        var truncated = new DeviceChainWalker(DeviceChainWalk.Encrypted, record);
        truncated.Begin(chain.DeviceId, chain.DeviceInformationHash, chain.BallotKind, chain.ChainingMode, chain.InitialHash);
        foreach (var ballot in ballots.Take(3))
        {
            truncated.Next(ballot.Id, ballot.ConfirmationCode, ballot.ChainingField);
        }

        var closing = ChainingField.Closing(chain.DeviceInformationHash, record.ExtendedBaseHash, ballots[2].ConfirmationCode);
        Assert.Null(truncated.End(closing, ChainingField.ClosingHash(closing, record.ExtendedBaseHash)));
        Assert.Equal("8.G", truncated.End(chain.ClosingChainingField, chain.ClosingHash)!.SubSection);
    }

    // ---- SpillingIdentifierSet ----------------------------------------------------------------------

    /// <summary>
    /// Design §6.5: 3,000 identifiers under a 128-byte budget (16 prefixes per run, so about 190 runs),
    /// with three planted duplicates at random positions: the merge finds exactly the planted prefixes,
    /// and the confirmation pass names exactly the planted identifiers with both their places.
    /// </summary>
    [Fact]
    public void SpillingSet_FindsPlantedDuplicates_AcrossSpilledRuns()
    {
        var ids = Enumerable.Range(0, 3000).Select(_ => RandomNumberGenerator.GetBytes(32)).ToList();
        var planted = new[] { (17, 2950), (1200, 1201), (2999, 0) };
        foreach (var (from, to) in planted)
        {
            ids[to] = ids[from];
        }

        using var set = new SpillingIdentifierSet(128, TempDirectory("spill"));
        foreach (var id in ids)
        {
            set.Add(id);
        }

        Assert.True(set.RunCount >= 180, $"{set.RunCount} runs");
        var colliding = set.CollidingPrefixes();
        Assert.Equal(planted.Select(x => set.PrefixOf(ids[x.Item1])).Order(), colliding);

        var confirmation = new SpillingIdentifierSet.Confirmation<int>(set, colliding);
        for (int i = 0; i < ids.Count; i++)
        {
            confirmation.Offer(ids[i], i);
        }

        var duplicates = confirmation.Duplicates();
        Assert.Equal(3, duplicates.Count);
        foreach (var (from, to) in planted)
        {
            var found = Assert.Single(duplicates, x => x.IdentifierHex == Convert.ToHexStringLower(ids[from]));
            Assert.Equal([Math.Min(from, to), Math.Max(from, to)], found.Places);
        }

    }

    /// <summary>
    /// Adversarially skewed identifiers (every id_B shares its first 24 bytes) spread over the keyed
    /// prefixes like any others: no false collision, the same run count as random ids, and a planted
    /// duplicate still found.
    /// </summary>
    [Fact]
    public void SpillingSet_IsNotSkewedByIdentifiersThatShareTheirLeadingBytes()
    {
        byte[] stem = RandomNumberGenerator.GetBytes(24);
        var ids = Enumerable.Range(0, 2000).Select(i => (byte[])[.. stem, .. BitConverter.GetBytes((long)i)]).ToList();
        ids[1999] = ids[3];
        using var set = new SpillingIdentifierSet(256, TempDirectory("spill-skew"));
        foreach (var id in ids)
        {
            set.Add(id);
        }

        Assert.Equal(2000 / 32 - (2000 % 32 == 0 ? 1 : 0), set.RunCount);
        Assert.Equal([set.PrefixOf(ids[3])], set.CollidingPrefixes());

        // The 1,999 distinct identifiers have 1,999 distinct prefixes (a chance collision is about
        // 2000²/2^65): a prefix over only the shared stem would give them one.
        Assert.Equal(1999, ids.Take(1999).Select(x => set.PrefixOf(x)).Distinct().Count());
    }

    /// <summary>
    /// The prefix is keyed (design §6.5: without k a publisher cannot aim two ballots at one prefix):
    /// one identifier has different prefixes under different keys, and the same under the same key.
    /// A set checkpointed and restored mid-stream finds what an uninterrupted one does.
    /// </summary>
    [Fact]
    public void SpillingSet_IsKeyed_AndRestoresFromACheckpoint()
    {
        byte[] id = RandomNumberGenerator.GetBytes(32);
        byte[] key = RandomNumberGenerator.GetBytes(16);
        using (var a = new SpillingIdentifierSet(1024, TempDirectory("spill-key"), key))
        using (var b = new SpillingIdentifierSet(1024, TempDirectory("spill-key"), key))
        using (var c = new SpillingIdentifierSet(1024, TempDirectory("spill-key")))
        {
            Assert.Equal(a.PrefixOf(id), b.PrefixOf(id));
            Assert.NotEqual(a.PrefixOf(id), c.PrefixOf(id));
        }

        var ids = Enumerable.Range(0, 500).Select(_ => RandomNumberGenerator.GetBytes(32)).ToList();
        ids[400] = ids[100];
        string directory = TempDirectory("spill-restore");
        SpillingIdentifierSet.State state;
        var first = new SpillingIdentifierSet(160, directory);
        foreach (var x in ids.Take(250))
        {
            first.Add(x);
        }

        state = first.Checkpoint();
        using var restored = SpillingIdentifierSet.Restore(state, 160, directory);
        foreach (var x in ids.Skip(250))
        {
            restored.Add(x);
        }

        Assert.Equal(500, restored.Count);
        Assert.Equal([restored.PrefixOf(ids[100])], restored.CollidingPrefixes());
    }

    /// <summary>
    /// The memory budget is a ceiling, not an allocation: the default 256 MiB set starts with a small
    /// buffer, which doubles as identifiers arrive and spills nothing until the budget is reached; a
    /// small budget caps the buffer and spills.
    /// </summary>
    [Fact]
    public void SpillingSet_GrowsItsBufferUpToTheBudget_BeforeItSpills()
    {
        using var large = new SpillingIdentifierSet(SpillingIdentifierSet.DefaultMemoryBudgetBytes, TempDirectory("spill-grow"));
        Assert.Equal(1 << 16, large.BufferCapacity);
        for (int i = 0; i < (1 << 16) + 1; i++)
        {
            large.Add(RandomNumberGenerator.GetBytes(32));
        }

        Assert.Equal(1 << 17, large.BufferCapacity);
        Assert.Equal(0, large.RunCount);

        using var small = new SpillingIdentifierSet(800, TempDirectory("spill-grow"));
        Assert.Equal(100, small.BufferCapacity);
        for (int i = 0; i < 250; i++)
        {
            small.Add(RandomNumberGenerator.GetBytes(32));
        }

        Assert.Equal(100, small.BufferCapacity);
        Assert.Equal(2, small.RunCount);
    }

    // ---- BallotAggregationVerifier.Merge -------------------------------------------------------------

    /// <summary>
    /// Design §6.7: partial recounts over disjoint ballots, merged through the standard form, verify the
    /// tally as one recount does, in either order; an exported and imported partial is the same; a
    /// faulted operand faults the result; a partial over another manifest is refused.
    /// </summary>
    [Fact]
    public void Merge_OfPartialRecounts_VerifiesTheTally_AndAFaultedOperandFaultsTheResult()
    {
        var election = RegularElection.Value;
        var ballots = election.Ballots.ToList();
        var a = new BallotAggregationVerifier(election.Manifest);
        var b = new BallotAggregationVerifier(election.Manifest);
        a.AddBallots(ballots.Take(2).ToList());
        b.AddBallots(ballots.Skip(2).ToList());

        var merged = BallotAggregationVerifier.ImportStandardForm(election.Manifest, a.ExportStandardForm());
        merged.Merge(b);
        merged.Verify(election.Tally);
        merged.VerifySummary(election.Tally);
        Assert.Equal(election.Tally.BallotsCast, merged.BallotsAdded);
        Assert.Equal(election.Tally.TotalCastWeight, merged.WeightAdded);

        var reversed = new BallotAggregationVerifier(election.Manifest);
        reversed.Merge(b.ExportStandardForm());
        reversed.Merge(a);
        reversed.Verify(election.Tally);

        var faulted = new BallotAggregationVerifier(election.Manifest);
        Assert.ThrowsAny<Exception>(() => faulted.AddBallot(RecordFormat.RecordDirectoryCarrierTests.Copy(ballots[0], BallotStatus.Unrecorded)));
        Assert.True(faulted.IsFaulted);
        var combined = new BallotAggregationVerifier(election.Manifest);
        combined.Merge(a);
        combined.Merge(faulted);
        Assert.True(combined.IsFaulted);
        Assert.Throws<InvalidOperationException>(() => combined.Verify(election.Tally));

        var other = PreEncryptedRecord.Value;
        Assert.Throws<ArgumentException>(() => new BallotAggregationVerifier(other.Record.Manifest).Merge(a.ExportStandardForm()));
    }

    /// <summary>
    /// CLAUDE.md: a ModPProduct carries engine-specific Montgomery drift, so partials cross engines only
    /// in standard form. A recount on the scalar engine and one on AVX-512 export the same standard form,
    /// and merged across the two they verify the tally.
    /// </summary>
    [Avx512Fact]
    public void Merge_AcrossTheScalarAndAvx512Engines_ThroughTheStandardForm_VerifiesTheTally()
    {
        var election = RegularElection.Value;
        var ballots = election.Ballots.ToList();
        var scalar = new BallotAggregationVerifier(election.Manifest, allowAvx512: false);
        var vector = new BallotAggregationVerifier(election.Manifest, allowAvx512: true);
        scalar.AddBallots(ballots, maxDegreeOfParallelism: 1);
        vector.AddBallots(ballots, maxDegreeOfParallelism: 1);
        var s = scalar.ExportStandardForm();
        var v = vector.ExportStandardForm();
        Assert.Equal(s.Contests.SelectMany(x => x.Choices).Select(x => Convert.ToHexString(x.A) + Convert.ToHexString(x.B)),
            v.Contests.SelectMany(x => x.Choices).Select(x => Convert.ToHexString(x.A) + Convert.ToHexString(x.B)));

        var half = new BallotAggregationVerifier(election.Manifest, allowAvx512: false);
        half.AddBallots(ballots.Take(3).ToList(), 1);
        var rest = new BallotAggregationVerifier(election.Manifest, allowAvx512: true);
        rest.AddBallots(ballots.Skip(3).ToList(), 1);
        half.Merge(rest);
        half.Verify(election.Tally);
    }
}
