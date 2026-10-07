using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;

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

    private static ContestHash BuildHash(EncryptedContest contest, SelectionEncryptionIdentifierHash selIdHash, int contestIndex, EncryptedContestData? contestData)
    {
        return new ContestHash(
            selIdHash,
            contestIndex,
            // Eq. (70): the options, then the supplemental fields the manifest declares, in manifest
            // order (G8). The encryptor lists both in that order.
            contest.Choices.Concat<EncryptedValueWithProofs>(contest.SupplementalFields),
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

        // ContestHash.GetHashCode() now hashes the byte[] content (each byte folded via
        // System.HashCode) instead of the array's reference identity, so content-equal ContestHash
        // values (per == above) built from independent byte[] instances correctly produce equal
        // hash codes.
        Assert.Equal(hash1.GetHashCode(), hash2.GetHashCode());
    }

    // Gap-closing tests (verified via mutation): unlike every sibling Model hash type
    // (ElectionBaseHash, ExtendedBaseHash, SelectionEncryptionIdentifierHash,
    // VotingDeviceInformationHash, EncryptionNonce, ConfirmationCode), ContestHashTests had no
    // "HandComputed_MatchesDirectEGHashCall" test pinning the exact field order/marker byte fed
    // into EGHash.Hash. These two fixture-based tests reproduce the full field ordering (marker
    // 0x28, contest index, per-choice alpha/beta pairs, then the declared supplemental fields'
    // alpha/beta pairs in manifest order, and -- when present -- contest data
    // C0/C1/Challenge/Response). Each supplemental field now has its own nonce xi_{i,j} (G3), so
    // no two of them share a ciphertext. The KAT's contest_hash family pins the digest itself.
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
        foreach (var field in contest.SupplementalFields)
        {
            bytesToHash.Add(field.Alpha);
            bytesToHash.Add(field.Beta);
        }

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
        foreach (var field in contest.SupplementalFields)
        {
            bytesToHash.Add(field.Alpha);
            bytesToHash.Add(field.Beta);
        }
        bytesToHash.Add(contest.ContestData!.C0);
        bytesToHash.Add(contest.ContestData!.C1);
        bytesToHash.Add(contest.ContestData!.Challenge);
        bytesToHash.Add(contest.ContestData!.Response);

        var expected = EGHash.Hash(selIdHash, bytesToHash.ToArray());

        Assert.Equal(expected, (byte[])hash);
    }

    // Every Alpha/Beta pair here is a distinct hand-built IntegerModP value, so this test fails
    // under a mutation that reorders, drops, or duplicates any entry of the ordered list (options,
    // then four supplemental fields) or the contest data.
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
        var contestData = new EncryptedContestData
        {
            C0 = new IntegerModP(0x70),
            C1 = new byte[] { 0x71 },
            Challenge = new IntegerModQ(72),
            Response = new IntegerModQ(73),
        };
        int contestIndex = 5;

        var hash = new ContestHash(
            selIdHash,
            contestIndex,
            choices.Concat<EncryptedValueWithProofs>(new[] { overVoteCount, nullVoteCount, underVoteCount, writeInVoteCount }),
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

    // The constructor builds its hash input in one pooled buffer, sized from the choices before
    // writing them. A lazily evaluated sequence has no count, so it must be materialized once rather
    // than enumerated twice; values of every width (zero, small, p - 1, multi-byte contest data,
    // empty contest data) must come out padded exactly as ToByteArray pads them.
    [Fact]
    public void FullCtor_LazyChoicesAndEdgeWidths_MatchesDirectEGHashCall()
    {
        var selIdHash = new SelectionEncryptionIdentifierHash(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray());
        var p = EGParameters.CryptographicParameters.P;

        static EncryptedValueWithProofs Field(IntegerModP alpha, IntegerModP beta) => new()
        {
            Alpha = alpha,
            Beta = beta,
            Proofs = Array.Empty<ChallengeResponsePair>(),
        };

        int enumerations = 0;
        IEnumerable<EncryptedSelection> LazyChoices()
        {
            enumerations++;
            yield return new EncryptedSelection { ChoiceId = "a", Alpha = new IntegerModP(0), Beta = new IntegerModP(p - 1), Proofs = [] };
            yield return new EncryptedSelection { ChoiceId = "b", Alpha = new IntegerModP(1), Beta = new IntegerModP(p - 2), Proofs = [] };
            yield return new EncryptedSelection { ChoiceId = "c", Alpha = new IntegerModP(256), Beta = new IntegerModP(65537), Proofs = [] };
        }

        var overVoteCount = Field(2, 3);
        var nullVoteCount = Field(new IntegerModP(p - 3), 4);
        var underVoteCount = Field(5, 6);
        var writeInVoteCount = Field(7, 8);
        var contestData = new EncryptedContestData
        {
            // C_0 is hashed as b(C_0, 512) (eq. 70), padded like every other element of Z_p.
            C0 = new IntegerModP(p - 5),
            C1 = Array.Empty<byte>(),
            Challenge = new IntegerModQ(0),
            Response = new IntegerModQ(EGParameters.CryptographicParameters.Q - 1),
        };

        var hash = new ContestHash(selIdHash, 12, LazyChoices().Concat<EncryptedValueWithProofs>(new[] { overVoteCount, nullVoteCount, underVoteCount, writeInVoteCount }), contestData);

        var bytesToHash = new List<byte[]> { new byte[] { 0x28 }, 12.ToByteArray() };
        foreach (var choice in LazyChoices())
        {
            bytesToHash.Add(choice.Alpha);
            bytesToHash.Add(choice.Beta);
        }
        foreach (var field in new[] { overVoteCount, nullVoteCount, underVoteCount, writeInVoteCount })
        {
            bytesToHash.Add(field.Alpha);
            bytesToHash.Add(field.Beta);
        }
        bytesToHash.Add(contestData.C0);
        bytesToHash.Add(contestData.C1);
        bytesToHash.Add(contestData.Challenge);
        bytesToHash.Add(contestData.Response);

        Assert.Equal(EGHash.Hash(selIdHash, bytesToHash.ToArray()), (byte[])hash);
        Assert.Equal(2, enumerations);
    }
}
