using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.UnitTests.TestFixtures;

namespace ElectionGuard.Core.UnitTests.Serialization;

public class JsonEncryptedBallotSerializerTests
{
    public JsonEncryptedBallotSerializerTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    /// <summary>
    /// Builds one EncryptedBallot that exercises every field this phase needs to assert: both
    /// choices are selected against SelectionLimit=1/OptionSelectionLimit=1 (CreateMinimalManifest's
    /// defaults), so BallotEncryptor.EncryptContest's overvote branch fires (see
    /// BallotEncryption/BallotEncryptor.cs lines 155-169), and a write-in count + ContestData string
    /// are supplied so WriteInVoteCount and ContestData are populated too. This gives a single
    /// ballot with real, non-degenerate cryptographic values in every EncryptedContest field.
    /// </summary>
    private static EncryptedBallot BuildRichEncryptedBallot()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");

        var ballot = ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 1 },
            numWriteinsSelected: 1,
            contestData: "Write-In Candidate Name");

        return ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot);
    }

    private static EncryptedBallot RoundTrip(EncryptedBallot ballot)
    {
        var serializer = new JsonEncryptedBallotSerializer();
        using var stream = new MemoryStream();
        serializer.Serialize(stream, ballot);
        stream.Position = 0;

        var result = serializer.Deserialize(stream);
        Assert.NotNull(result);
        return result!;
    }

    private static void AssertEncryptedValueWithProofsEqual(EncryptedValueWithProofs expected, EncryptedValueWithProofs actual)
    {
        Assert.Equal(expected.Alpha, actual.Alpha);
        Assert.Equal(expected.Beta, actual.Beta);
        Assert.Equal(expected.Proofs.Length, actual.Proofs.Length);
        for (int i = 0; i < expected.Proofs.Length; i++)
        {
            Assert.Equal(expected.Proofs[i].Challenge, actual.Proofs[i].Challenge);
            Assert.Equal(expected.Proofs[i].Response, actual.Proofs[i].Response);
        }
    }

    [Fact]
    public void RoundTrip_PreservesBallotLevelFields()
    {
        var original = BuildRichEncryptedBallot();

        var result = RoundTrip(original);

        Assert.Equal(original.Id, result.Id);
        Assert.Equal(original.BallotStyleId, result.BallotStyleId);
        Assert.Equal(original.DeviceId, result.DeviceId);
        Assert.Equal(original.Weight, result.Weight);
        // ConfirmationCode is the field that folds the (currently no-op, see
        // BallotEncryptorTests.Encrypt_SecondBallotOnDevice_ChainingHasNoEffect...) ChainingField
        // into the ballot -- asserting it here is how this phase covers "ChainingField" per the
        // plan, since ChainingField itself is a transient input to BallotEncryptor.Encrypt and is
        // not a stored property of EncryptedBallot.
        Assert.Equal(original.ConfirmationCode, result.ConfirmationCode);
        // SelectionEncryptionIdentifierHash is a HashValue subclass with no Equals/GetHashCode
        // override (reference equality only), so it must be compared via its byte[] conversion --
        // matching the existing convention in Models/SelectionEncryptionIdentifierHashTests.cs.
        Assert.Equal((byte[])original.SelectionEncryptionIdentifierHash, (byte[])result.SelectionEncryptionIdentifierHash);
    }

    [Fact]
    public void RoundTrip_PreservesEachContestsSelections_AlphaBetaAndProofs()
    {
        var original = BuildRichEncryptedBallot();

        var result = RoundTrip(original);

        Assert.Equal(original.Contests.Count, result.Contests.Count);
        foreach (var originalContest in original.Contests)
        {
            var resultContest = result.Contests.Single(c => c.Id == originalContest.Id);

            Assert.Equal(originalContest.Choices.Count, resultContest.Choices.Count);
            foreach (var originalSelection in originalContest.Choices)
            {
                var resultSelection = resultContest.Choices.Single(s => s.ChoiceId == originalSelection.ChoiceId);
                AssertEncryptedValueWithProofsEqual(originalSelection, resultSelection);
            }

            // Contest-level aggregate proofs (over the summed selection ciphertext), distinct from
            // each individual selection's own per-choice proofs asserted above.
            Assert.Equal(originalContest.Proofs.Length, resultContest.Proofs.Length);
            for (int p = 0; p < originalContest.Proofs.Length; p++)
            {
                Assert.Equal(originalContest.Proofs[p].Challenge, resultContest.Proofs[p].Challenge);
                Assert.Equal(originalContest.Proofs[p].Response, resultContest.Proofs[p].Response);
            }
        }
    }

    [Fact]
    public void RoundTrip_PreservesOvervoteNullvoteUndervoteWriteInCounters()
    {
        var original = BuildRichEncryptedBallot();

        var result = RoundTrip(original);

        var originalContest = original.Contests.Single();
        var resultContest = result.Contests.Single();

        AssertEncryptedValueWithProofsEqual(originalContest.OvervoteCount, resultContest.OvervoteCount);
        AssertEncryptedValueWithProofsEqual(originalContest.NullvoteCount, resultContest.NullvoteCount);
        AssertEncryptedValueWithProofsEqual(originalContest.UndervoteCount, resultContest.UndervoteCount);
        AssertEncryptedValueWithProofsEqual(originalContest.WriteInVoteCount, resultContest.WriteInVoteCount);
    }

    [Fact]
    public void RoundTrip_PreservesContestData_WhenWriteInPresent()
    {
        var original = BuildRichEncryptedBallot();
        Assert.NotNull(original.Contests.Single().ContestData);

        var result = RoundTrip(original);

        var originalContestData = original.Contests.Single().ContestData!;
        var resultContestData = result.Contests.Single().ContestData;

        Assert.NotNull(resultContestData);
        Assert.Equal(originalContestData.C0, resultContestData!.C0);
        Assert.Equal(originalContestData.C1, resultContestData.C1);
        Assert.Equal(originalContestData.Challenge, resultContestData.Challenge);
        Assert.Equal(originalContestData.Response, resultContestData.Response);
    }

    [Fact]
    public void RoundTrip_PreservesContestHash()
    {
        var original = BuildRichEncryptedBallot();

        var result = RoundTrip(original);

        Assert.Equal(original.Contests.Single().ContestHash, result.Contests.Single().ContestHash);
    }

    [Fact]
    public void RoundTrip_DoesNotAttemptToSerializeEncryptionNonce()
    {
        // EncryptedValueWithProofs.EncryptionNonce (inherited by EncryptedSelection, and present on
        // each of the four per-contest counters) is decorated [JsonIgnore] in
        // BallotEncryption/EncryptedSelection.cs -- by design, since shipping the nonce off-device
        // would let anyone downstream recover the plaintext selection it was used to encrypt. This
        // test pins that the nonce is genuinely absent after round-tripping (not merely unchecked by
        // our other assertions), rather than asserting equality on it.
        var original = BuildRichEncryptedBallot();
        var originalContest = original.Contests.Single();
        Assert.NotNull(originalContest.Choices.First().EncryptionNonce);
        Assert.NotNull(originalContest.OvervoteCount.EncryptionNonce);

        var result = RoundTrip(original);

        var resultContest = result.Contests.Single();
        Assert.All(resultContest.Choices, s => Assert.Null(s.EncryptionNonce));
        Assert.Null(resultContest.OvervoteCount.EncryptionNonce);
        Assert.Null(resultContest.NullvoteCount.EncryptionNonce);
        Assert.Null(resultContest.UndervoteCount.EncryptionNonce);
        Assert.Null(resultContest.WriteInVoteCount.EncryptionNonce);
    }

    [Fact]
    public void RoundTrip_PreservesSelectionEncryptionIdentifier()
    {
        // JsonEncryptedBallotSerializer now registers a SelectionEncryptionIdentifierJsonConverter
        // (matching the converter it already had for every other hash/identifier-shaped type
        // reachable from EncryptedBallot), so the 32 random bytes BallotEncryptor generated for
        // SelectionEncryptionIdentifier survive the round trip instead of being silently dropped.
        var original = BuildRichEncryptedBallot();
        var originalBytes = (byte[])original.SelectionEncryptionIdentifier;
        Assert.NotEmpty(originalBytes);

        var result = RoundTrip(original);
        var resultBytes = (byte[])result.SelectionEncryptionIdentifier;

        Assert.Equal(originalBytes, resultBytes);
    }
}
