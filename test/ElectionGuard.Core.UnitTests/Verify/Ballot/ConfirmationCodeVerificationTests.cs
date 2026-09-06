using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.TestFixtures;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;

namespace ElectionGuard.Core.UnitTests.Verify.Ballot;

public class ConfirmationCodeVerificationTests
{
    public ConfirmationCodeVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static (EncryptedBallot Ballot, EncryptionRecord EncryptionRecord, VotingDeviceInformationHash DeviceHash) BuildValidBallot(
        ChainingMode chainingMode, ConfirmationCode? previousConfirmationCode = null, string deviceId = "device-1", string ballotId = "ballot-1")
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(chainingMode: chainingMode);
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, deviceId);
        var ballot = ElectionFixtureBuilder.CreateBallot(manifest, ballotId: ballotId, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 });
        var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, deviceId, deviceHash, ballot, previousConfirmationCode);

        return (encryptedBallot, encryptionRecordResult.EncryptionRecord, deviceHash);
    }

    private static EncryptedBallot Clone(EncryptedBallot ballot, List<EncryptedContest>? contests = null, ConfirmationCode? confirmationCode = null)
    {
        return new EncryptedBallot
        {
            Id = ballot.Id,
            SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
            BallotStyleId = ballot.BallotStyleId,
            Contests = contests ?? ballot.Contests,
            ConfirmationCode = confirmationCode ?? ballot.ConfirmationCode,
            Weight = ballot.Weight,
            DeviceId = ballot.DeviceId,
        };
    }

    [Fact]
    public void Verify_ValidBallot_ChainingModeNone_DoesNotThrow()
    {
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.None, previousConfirmationCode: null);
        var verification = new ConfirmationCodeVerification();

        var exception = Record.Exception(() => verification.Verify(ballot, deviceHash, encryptionRecord, previousConfirmationCode: null));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify_ValidBallot_ChainingModeSimple_DoesNotThrow()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(chainingMode: ChainingMode.Simple);
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");

        var ballot1 = ElectionFixtureBuilder.CreateBallot(manifest, ballotId: "ballot-1", selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 });
        var encryptedBallot1 = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot1, previousConfirmationCode: null);

        var ballot2 = ElectionFixtureBuilder.CreateBallot(manifest, ballotId: "ballot-2", selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-2"] = 1 });
        var encryptedBallot2 = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot2, previousConfirmationCode: encryptedBallot1.ConfirmationCode);

        var verification = new ConfirmationCodeVerification();

        var exception = Record.Exception(() => verification.Verify(
            encryptedBallot2, deviceHash, encryptionRecordResult.EncryptionRecord, previousConfirmationCode: encryptedBallot1.ConfirmationCode));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify_TamperedContestHash_Throws_SubSection8A()
    {
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.None, previousConfirmationCode: null);

        var tamperedBytes = ((byte[])ballot.Contests[0].ContestHash).ToArray();
        tamperedBytes[0] ^= 0xFF;
        var tamperedContest = ballot.Contests[0] with { ContestHash = new ContestHash(tamperedBytes) };
        var tamperedBallot = Clone(ballot, contests: new List<EncryptedContest> { tamperedContest });

        var verification = new ConfirmationCodeVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(tamperedBallot, deviceHash, encryptionRecord, previousConfirmationCode: null));
        Assert.Equal("8.A", exception.SubSection);
    }

    [Fact]
    public void Verify_TamperedConfirmationCode_Throws_SubSection8B()
    {
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.None, previousConfirmationCode: null);

        var tamperedBytes = ((byte[])ballot.ConfirmationCode).ToArray();
        tamperedBytes[0] ^= 0xFF;
        var tamperedBallot = Clone(ballot, confirmationCode: new ConfirmationCode(tamperedBytes));

        var verification = new ConfirmationCodeVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(tamperedBallot, deviceHash, encryptionRecord, previousConfirmationCode: null));
        Assert.Equal("8.B", exception.SubSection);
    }

    [Fact]
    public void Verify_TamperedDeviceInformationHash_Throws_SubSection8C()
    {
        // Isolating 8.C specifically requires a scenario where a tampered deviceHash does NOT also
        // change the recomputed ChainingField/ConfirmationCode (which would instead be caught
        // earlier by 8.B, now that ConfirmationCode folds the chaining field into its hash -- see
        // Models/ConfirmationCodeTests.cs). For ChainingMode.Simple with a real (non-null) previous
        // confirmation code, ChainingField's formula (76) branch is BC,j = 0x00000001 || Hj-1 --
        // deviceHash plays no role in it at all -- so a wrong deviceHash passed to Verify leaves
        // 8.B's recomputed confirmation code matching, and 8.C is the first (and only) check that
        // can catch it.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(chainingMode: ChainingMode.Simple);
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");

        var ballot1 = ElectionFixtureBuilder.CreateBallot(manifest, ballotId: "ballot-1", selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 });
        var encryptedBallot1 = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot1, previousConfirmationCode: null);

        var ballot2 = ElectionFixtureBuilder.CreateBallot(manifest, ballotId: "ballot-2", selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-2"] = 1 });
        var encryptedBallot2 = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot2, previousConfirmationCode: encryptedBallot1.ConfirmationCode);

        var wrongDeviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "a-different-device");

        var verification = new ConfirmationCodeVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(encryptedBallot2, wrongDeviceHash, encryptionRecordResult.EncryptionRecord, previousConfirmationCode: encryptedBallot1.ConfirmationCode));
        Assert.Equal("8.C", exception.SubSection);
    }

    [Fact]
    public void Verify_ChainingModeNone_IgnoresPreviousConfirmationCodeArgument_DoesNotThrow()
    {
        // Per §3.4.4 formula (73), a ChainingMode.None ballot's chaining field BC = 0x00000000 ||
        // HDI never depends on any previous confirmation code -- that is the whole point of "no
        // chaining" mode (see Models/ChainingField.cs's ChainingMode.None branch). So a
        // previousConfirmationCode argument to Verify is simply irrelevant/unused for a None-mode
        // ballot, not a misuse to detect: passing an unrelated value here does not, and per spec
        // should not, cause a failure.
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.None, previousConfirmationCode: null);

        var unrelatedPreviousCode = ballot.ConfirmationCode;

        var verification = new ConfirmationCodeVerification();

        var exception = Record.Exception(
            () => verification.Verify(ballot, deviceHash, encryptionRecord, previousConfirmationCode: unrelatedPreviousCode));
        Assert.Null(exception);
    }

    [Fact]
    public void Verify_ChainingModeSimple_MismatchedPreviousConfirmationCode_Throws_SubSection8B()
    {
        // Was PINNED, NOW PARTIALLY FIXED: now that ConfirmationCode folds its ChainingField into
        // the hash (§3.4.2 formula (71) -- see Models/ConfirmationCodeTests.cs), a
        // previousConfirmationCode unrelated to the ballot actually being verified changes the
        // recomputed ChainingField/ConfirmationCode, so 8.B (not 8.E) now correctly rejects it.
        //
        // NOTE: for ChainingMode.Simple specifically, ConfirmationCodeVerification.Verify still
        // computes both `chainingField` (line 35) and `expectedChainingField` (the 8.E check) from
        // the exact same inputs -- ChainingMode.Simple, deviceInformationHash,
        // encryptionRecord.ExtendedBaseHash, and the single previousConfirmationCode parameter --
        // so 8.E specifically remains dead/tautological code (a separate, narrower issue from the
        // ConfirmationCode hashing bug fixed here); it just no longer matters for detecting a
        // mismatched previous code, because 8.B now catches it first.
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.Simple, previousConfirmationCode: null);

        // A previousConfirmationCode that has nothing to do with this ballot or device.
        var unrelatedPreviousCode = new ConfirmationCode(new byte[32]);

        var verification = new ConfirmationCodeVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(ballot, deviceHash, encryptionRecord, previousConfirmationCode: unrelatedPreviousCode));

        Assert.Equal("8.B", exception.SubSection);
    }
}
