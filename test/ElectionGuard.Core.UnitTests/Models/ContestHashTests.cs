using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.TestFixtures;

namespace ElectionGuard.Core.UnitTests.Models;

public class ContestHashTests
{
    public ContestHashTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static (EncryptedContest Contest, SelectionEncryptionIdentifierHash SelIdHash, int ContestIndex) CreateEncryptedContest(
        bool includeWriteIn = false)
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: includeWriteIn);
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "Device 1");

        var choiceId = manifest.Contests[0].Choices[0].Id;
        var ballot = ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { [choiceId] = 1 },
            numWriteinsSelected: includeWriteIn ? 1 : 0,
            contestData: includeWriteIn ? "write-in-name" : null);

        var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "Device 1", deviceHash, ballot);

        return (encryptedBallot.Contests[0], encryptedBallot.SelectionEncryptionIdentifierHash, manifest.Contests[0].Index);
    }

    private static ContestHash BuildHash(EncryptedContest contest, SelectionEncryptionIdentifierHash selIdHash, int contestIndex, EncryptedData? contestData)
    {
        return new ContestHash(
            selIdHash,
            contestIndex,
            contest.Choices,
            contest.OvervoteCount,
            contest.NullvoteCount,
            contest.UndervoteCount,
            contest.WriteInVoteCount,
            contestData);
    }

    [Fact]
    public void FullCtor_SameInputs_ProducesSameHash()
    {
        var (contest, selIdHash, contestIndex) = CreateEncryptedContest();

        var hash1 = BuildHash(contest, selIdHash, contestIndex, contest.ContestData);
        var hash2 = BuildHash(contest, selIdHash, contestIndex, contest.ContestData);

        Assert.Equal(hash1, hash2);
        Assert.True(hash1 == hash2);
    }

    [Fact]
    public void FullCtor_DifferentSelectionCiphertexts_ProducesDifferentHash()
    {
        // Two independent encryption passes over the (effectively) same ballot content produce
        // different selection ciphertexts due to fresh random nonces, so the resulting ContestHash
        // must differ even though both are hashed with a 32-byte selection-encryption-identifier
        // hash as the HMAC key.
        var (contest1, selIdHash, contestIndex) = CreateEncryptedContest();
        var (contest2, _, _) = CreateEncryptedContest();

        var hash1 = BuildHash(contest1, selIdHash, contestIndex, contest1.ContestData);
        var hash2 = BuildHash(contest2, selIdHash, contestIndex, contest2.ContestData);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void FullCtor_WithContestData_IncludesContestDataInHash()
    {
        var (contest, selIdHash, contestIndex) = CreateEncryptedContest(includeWriteIn: true);
        Assert.NotNull(contest.ContestData);

        var hashWithData = BuildHash(contest, selIdHash, contestIndex, contest.ContestData);
        var hashWithoutData = BuildHash(contest, selIdHash, contestIndex, null);

        Assert.NotEqual(hashWithData, hashWithoutData);
    }

    [Fact]
    public void EqualityOperator_And_GetHashCode_BehaveConsistently()
    {
        var (contest, selIdHash, contestIndex) = CreateEncryptedContest();

        var hash1 = BuildHash(contest, selIdHash, contestIndex, contest.ContestData);
        var hash2 = BuildHash(contest, selIdHash, contestIndex, contest.ContestData);

        Assert.True(hash1 == hash2);
        Assert.False(hash1 != hash2);

        // Discovered quirk (pinned, not fixed -- see CLAUDE.md guidance on treating spec/behavior
        // as source of truth rather than editing production code from a test): ContestHash.GetHashCode()
        // calls HashCode.Combine(_value) where _value is a byte[]. Arrays don't override
        // GetHashCode(), so HashCode.Combine hashes the array's reference identity, not its
        // content. Two content-equal ContestHash values (per == above) built from independent
        // byte[] instances can therefore still produce different hash codes.
        Assert.NotEqual(hash1.GetHashCode(), hash2.GetHashCode());
    }

    // Gap-closing tests (verified via mutation): unlike every sibling Model hash type
    // (ElectionBaseHash, ExtendedBaseHash, SelectionEncryptionIdentifierHash,
    // VotingDeviceInformationHash, EncryptionNonce, ConfirmationCode), ContestHashTests had no
    // "HandComputed_MatchesDirectEGHashCall" test pinning the exact field order/marker byte fed
    // into EGHash.Hash. These two fixture-based tests reproduce the full field ordering (marker
    // 0x28, contest index, per-choice alpha/beta pairs, then overvote/nullvote/undervote/write-in
    // alpha/beta pairs, and -- when present -- contest data C0/C1/Challenge/Response).
    //
    // Note: against ElectionFixtureBuilder's default single-selection ballot, a same-source-order
    // swap between OvervoteCount and NullvoteCount specifically does NOT fail these two tests --
    // both fields encrypt plaintext 0 via EncryptContestValue(0, ..., contestIndex, choiceIndex:
    // null), and since EncryptionNonce depends only on (selIdHash, ballotNonce, contestIndex,
    // choiceIndex) with no per-field-type marker, identical (value, nonce) inputs produce
    // byte-identical Alpha/Beta ciphertexts for both fields in that scenario. See
    // FullCtor_HandComputed_WithDistinctFieldValues_MatchesExactFieldOrder below, which uses
    // directly-constructed (non-colliding) field values specifically to close that gap.
    [Fact]
    public void FullCtor_WithoutContestData_HandComputed_MatchesDirectEGHashCall()
    {
        var (contest, selIdHash, contestIndex) = CreateEncryptedContest();

        var hash = BuildHash(contest, selIdHash, contestIndex, null);

        var bytesToHash = new List<byte[]> { new byte[] { 0x28 }, contestIndex.ToByteArray() };
        foreach (var choice in contest.Choices)
        {
            bytesToHash.Add(choice.Alpha);
            bytesToHash.Add(choice.Beta);
        }
        bytesToHash.Add(contest.OvervoteCount.Alpha);
        bytesToHash.Add(contest.OvervoteCount.Beta);
        bytesToHash.Add(contest.NullvoteCount.Alpha);
        bytesToHash.Add(contest.NullvoteCount.Beta);
        bytesToHash.Add(contest.UndervoteCount.Alpha);
        bytesToHash.Add(contest.UndervoteCount.Beta);
        bytesToHash.Add(contest.WriteInVoteCount.Alpha);
        bytesToHash.Add(contest.WriteInVoteCount.Beta);

        var expected = EGHash.Hash(selIdHash, bytesToHash.ToArray());

        Assert.Equal(expected, (byte[])hash);
    }

    [Fact]
    public void FullCtor_WithContestData_HandComputed_MatchesDirectEGHashCall()
    {
        var (contest, selIdHash, contestIndex) = CreateEncryptedContest(includeWriteIn: true);
        Assert.NotNull(contest.ContestData);

        var hash = BuildHash(contest, selIdHash, contestIndex, contest.ContestData);

        var bytesToHash = new List<byte[]> { new byte[] { 0x28 }, contestIndex.ToByteArray() };
        foreach (var choice in contest.Choices)
        {
            bytesToHash.Add(choice.Alpha);
            bytesToHash.Add(choice.Beta);
        }
        bytesToHash.Add(contest.OvervoteCount.Alpha);
        bytesToHash.Add(contest.OvervoteCount.Beta);
        bytesToHash.Add(contest.NullvoteCount.Alpha);
        bytesToHash.Add(contest.NullvoteCount.Beta);
        bytesToHash.Add(contest.UndervoteCount.Alpha);
        bytesToHash.Add(contest.UndervoteCount.Beta);
        bytesToHash.Add(contest.WriteInVoteCount.Alpha);
        bytesToHash.Add(contest.WriteInVoteCount.Beta);
        bytesToHash.Add(contest.ContestData!.C0);
        bytesToHash.Add(contest.ContestData!.C1);
        bytesToHash.Add(contest.ContestData!.Challenge);
        bytesToHash.Add(contest.ContestData!.Response);

        var expected = EGHash.Hash(selIdHash, bytesToHash.ToArray());

        Assert.Equal(expected, (byte[])hash);
    }

    // Closes the gap noted above: every Alpha/Beta pair here is a distinct hand-built IntegerModP
    // value (no shared plaintext/nonce collisions like the fixture-based tests have), so this test
    // fails under a mutation that reorders, drops, or duplicates any field -- including specifically
    // the OvervoteCount/NullvoteCount adjacent-pair swap that FullCtor_WithoutContestData_/
    // FullCtor_WithContestData_HandComputed_MatchesDirectEGHashCall above cannot detect.
    [Fact]
    public void FullCtor_HandComputed_WithDistinctFieldValues_MatchesExactFieldOrder()
    {
        var selIdHash = new SelectionEncryptionIdentifierHash(new byte[32]);

        static EncryptedSelection Choice(string id, int seed) => new()
        {
            ChoiceId = id,
            Alpha = new IntegerModP(seed),
            Beta = new IntegerModP(seed + 1),
            Proofs = Array.Empty<ChallengeResponsePair>(),
        };

        static EncryptedValueWithProofs Field(int seed) => new()
        {
            Alpha = new IntegerModP(seed),
            Beta = new IntegerModP(seed + 1),
            Proofs = Array.Empty<ChallengeResponsePair>(),
        };

        var choices = new List<EncryptedSelection> { Choice("choice-1", 10), Choice("choice-2", 20) };
        var overVoteCount = Field(30);
        var nullVoteCount = Field(40);
        var underVoteCount = Field(50);
        var writeInVoteCount = Field(60);
        var contestData = new EncryptedData
        {
            C0 = new byte[] { 0x70 },
            C1 = new byte[] { 0x71 },
            Challenge = new IntegerModQ(72),
            Response = new IntegerModQ(73),
        };
        int contestIndex = 5;

        var hash = new ContestHash(
            selIdHash,
            contestIndex,
            choices,
            overVoteCount,
            nullVoteCount,
            underVoteCount,
            writeInVoteCount,
            contestData);

        var bytesToHash = new List<byte[]> { new byte[] { 0x28 }, contestIndex.ToByteArray() };
        foreach (var choice in choices)
        {
            bytesToHash.Add(choice.Alpha);
            bytesToHash.Add(choice.Beta);
        }
        bytesToHash.Add(overVoteCount.Alpha);
        bytesToHash.Add(overVoteCount.Beta);
        bytesToHash.Add(nullVoteCount.Alpha);
        bytesToHash.Add(nullVoteCount.Beta);
        bytesToHash.Add(underVoteCount.Alpha);
        bytesToHash.Add(underVoteCount.Beta);
        bytesToHash.Add(writeInVoteCount.Alpha);
        bytesToHash.Add(writeInVoteCount.Beta);
        bytesToHash.Add(contestData.C0);
        bytesToHash.Add(contestData.C1);
        bytesToHash.Add(contestData.Challenge);
        bytesToHash.Add(contestData.Response);

        var expected = EGHash.Hash(selIdHash, bytesToHash.ToArray());

        Assert.Equal(expected, (byte[])hash);
    }
}
