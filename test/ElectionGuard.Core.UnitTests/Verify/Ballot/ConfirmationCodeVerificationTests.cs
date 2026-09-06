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
        var (ballot, encryptionRecord, _) = BuildValidBallot(ChainingMode.None, previousConfirmationCode: null);

        var wrongDeviceHash = new VotingDeviceInformationHash(encryptionRecord.ExtendedBaseHash, "a-different-device");

        var verification = new ConfirmationCodeVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(ballot, wrongDeviceHash, encryptionRecord, previousConfirmationCode: null));
        Assert.Equal("8.C", exception.SubSection);
    }

    [Fact]
    public void Verify_ChainingModeNone_NonNullPreviousConfirmationCode_Throws_SubSection8D()
    {
        // For a ChainingMode.None ballot, Verify recomputes `chainingField` (line 35) using
        // whatever previousConfirmationCode the caller passes in, but compares it against an
        // `expectedChainingField` built with a hardcoded null (line 52). A correctly-operating
        // caller always passes null here for a None-mode ballot; passing a non-null value -- the
        // exact misuse this check exists to catch -- makes the two disagree.
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.None, previousConfirmationCode: null);

        var bogusPreviousCode = ballot.ConfirmationCode;

        var verification = new ConfirmationCodeVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(ballot, deviceHash, encryptionRecord, previousConfirmationCode: bogusPreviousCode));
        Assert.Equal("8.D", exception.SubSection);
    }

    [Fact]
    public void Verify_ChainingModeSimple_MismatchedPreviousConfirmationCode_NeverThrows_SubSection8E_DueToTautologicalComparison()
    {
        // GENUINE BUG, PINNED NOT FIXED (per CLAUDE.md / task instructions -- production code is
        // not modified as part of test generation): for ChainingMode.Simple,
        // ConfirmationCodeVerification.Verify computes both `chainingField` (line 35) and
        // `expectedChainingField` (line 60) from the exact same inputs -- ChainingMode.Simple,
        // deviceInformationHash, encryptionRecord.ExtendedBaseHash, and the single
        // previousConfirmationCode parameter passed to Verify. There is no way to make these two
        // values differ through the public Verify(...) signature, so the "8.E" throw at line 63 is
        // dead code: no matter what previousConfirmationCode is supplied -- even one wholly
        // unrelated to the ballot being verified -- the comparison always succeeds.
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.Simple, previousConfirmationCode: null);

        // A previousConfirmationCode that has nothing to do with this ballot or device -- if 8.E
        // were reachable, this is exactly the case it should catch.
        var unrelatedPreviousCode = new ConfirmationCode(new byte[32]);

        var verification = new ConfirmationCodeVerification();

        var exception = Record.Exception(
            () => verification.Verify(ballot, deviceHash, encryptionRecord, previousConfirmationCode: unrelatedPreviousCode));

        Assert.Null(exception);
    }
}
