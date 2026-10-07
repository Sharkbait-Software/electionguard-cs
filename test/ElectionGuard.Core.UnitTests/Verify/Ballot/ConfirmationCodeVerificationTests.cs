using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;
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
            EncryptedBallotNonce = ballot.EncryptedBallotNonce,
            ChainingField = ballot.ChainingField,
            Weight = ballot.Weight,
            Status = ballot.Status,
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
    public void Verify_ChainingModeSimple_MismatchedPreviousConfirmationCode_Throws_SubSection8E()
    {
        // RE-PINNED in S8 (G37), 8.B -> 8.E. The ballot now carries the chaining field B_C it was
        // hashed with, and 8.B recomputes H_C from that field, so 8.B passes: the ballot is
        // internally consistent. What is wrong is the chain position the caller claims (an unrelated
        // previous confirmation code), which is exactly 8.E: "the chaining field byte array used to
        // compute H_j is equal to B_C,j = 0x00000001 || H_{j-1}". Before S8, 8.E compared two fields
        // built from the same inputs and could not fail, so the mismatch surfaced as 8.B.
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.Simple, previousConfirmationCode: null);

        // A previousConfirmationCode that has nothing to do with this ballot or device.
        var unrelatedPreviousCode = new ConfirmationCode(new byte[32]);

        var verification = new ConfirmationCodeVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(ballot, deviceHash, encryptionRecord, previousConfirmationCode: unrelatedPreviousCode));

        Assert.Equal("8.E", exception.SubSection);
    }

    /// <summary>
    /// The ballot with chaining field <paramref name="field"/> and a confirmation code recomputed over
    /// it, so that 8.A and 8.B pass and only 8.D/8.E can catch the field.
    /// </summary>
    internal static EncryptedBallot Rechained(EncryptedBallot ballot, ChainingField field, string? deviceId = null)
    {
        return WithChainingField(
            ballot,
            field,
            new ConfirmationCode(ballot.SelectionEncryptionIdentifierHash, ballot.Contests.Select(x => x.ContestHash).ToList(), field),
            deviceId);
    }

    internal static EncryptedBallot WithChainingField(EncryptedBallot ballot, ChainingField field, ConfirmationCode confirmationCode, string? deviceId = null)
    {
        return new EncryptedBallot
        {
            Id = ballot.Id,
            SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
            BallotStyleId = ballot.BallotStyleId,
            Contests = ballot.Contests,
            ConfirmationCode = confirmationCode,
            ChainingField = field,
            EncryptedBallotNonce = ballot.EncryptedBallotNonce,
            Weight = ballot.Weight,
            Status = ballot.Status,
            DeviceId = deviceId ?? ballot.DeviceId,
        };
    }

    [Fact]
    public void Verify_ValidBallot_CarriesTheChainingFieldItWasHashedWith()
    {
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.None);

        Assert.Equal(new ChainingField(ChainingMode.None, deviceHash, encryptionRecord.ExtendedBaseHash, null), ballot.ChainingField);
        Assert.Null(Record.Exception(() => new ConfirmationCodeVerification().Verify(ballot, encryptionRecord)));
    }

    [Fact]
    public void Verify_NoChaining_TamperedChainingFieldWithoutRehashing_Throws_SubSection8B()
    {
        var (ballot, encryptionRecord, _) = BuildValidBallot(ChainingMode.None);
        byte[] bytes = ((byte[])ballot.ChainingField).ToArray();
        bytes[^1] ^= 0x01;
        var tampered = WithChainingField(ballot, ChainingField.FromCanonicalBytes(bytes), ballot.ConfirmationCode);

        var exception = Assert.Throws<VerificationFailedException>(() => new ConfirmationCodeVerification().Verify(tampered, encryptionRecord));

        Assert.Equal("8.B", exception.SubSection);
    }

    [Theory]
    [InlineData("other device hash")]
    [InlineData("simple-chaining identifier")]
    [InlineData("zero hash")]
    public void Verify_NoChainingBallotWithWrongChainingField_Throws_SubSection8D(string variant)
    {
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.None);
        var otherDevice = new VotingDeviceInformationHash(encryptionRecord.ExtendedBaseHash, "device-2");
        var field = variant switch
        {
            "other device hash" => new ChainingField(ChainingMode.None, otherDevice, encryptionRecord.ExtendedBaseHash, null),
            "simple-chaining identifier" => ChainingField.FromCanonicalBytes([0, 0, 0, 1, .. ((byte[])ballot.ChainingField)[4..]]),
            _ => ElectionFixtureBuilder.PlaceholderChainingField,
        };
        var tampered = Rechained(ballot, field);
        var verification = new ConfirmationCodeVerification();

        Assert.Equal("8.D", Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord)).SubSection);
        Assert.Equal("8.D", Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, deviceHash, encryptionRecord, null)).SubSection);
    }

    [Fact]
    public void Verify_SimpleChaining_PerBallot_ChecksOnlyTheModeIdentifier()
    {
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.Simple);
        var verification = new ConfirmationCodeVerification();

        // Any H_{j-1} is accepted per ballot (the device walk decides which is right) ...
        var otherPosition = Rechained(ballot, new ChainingField(ChainingMode.Simple, deviceHash, encryptionRecord.ExtendedBaseHash, new ConfirmationCode(new byte[32])));
        Assert.Null(Record.Exception(() => verification.Verify(otherPosition, encryptionRecord)));

        // ... but not the no-chaining identifier.
        var noChaining = Rechained(ballot, new ChainingField(ChainingMode.None, deviceHash, encryptionRecord.ExtendedBaseHash, null));
        Assert.Equal("8.E", Assert.Throws<VerificationFailedException>(() => verification.Verify(noChaining, encryptionRecord)).SubSection);
    }

    [Fact]
    public void Verify_SimpleChaining_ExplicitPreviousCode_FirstBallotMustChainFromItsDevicesH0()
    {
        var (ballot, encryptionRecord, deviceHash) = BuildValidBallot(ChainingMode.Simple);
        var verification = new ConfirmationCodeVerification();
        var initialHash = ChainingField.InitialHash(deviceHash, encryptionRecord.ExtendedBaseHash);
        Assert.Equal(new ChainingField(ChainingMode.Simple, deviceHash, encryptionRecord.ExtendedBaseHash, initialHash), ballot.ChainingField);

        // Given H_0 explicitly as the previous code: the same field.
        Assert.Null(Record.Exception(() => verification.Verify(ballot, deviceHash, encryptionRecord, initialHash)));

        // A ballot hashed with another device's H_0, claimed to be this device's first ballot.
        var otherDevice = new VotingDeviceInformationHash(encryptionRecord.ExtendedBaseHash, "device-2");
        var foreign = Rechained(ballot, new ChainingField(ChainingMode.Simple, otherDevice, encryptionRecord.ExtendedBaseHash, null));
        Assert.Equal("8.E", Assert.Throws<VerificationFailedException>(() => verification.Verify(foreign, deviceHash, encryptionRecord, null)).SubSection);
    }

    [Fact]
    public void Verify_DefaultChainingField_Throws_SubSection8Structure()
    {
        var (ballot, encryptionRecord, _) = BuildValidBallot(ChainingMode.None);
        var malformed = WithChainingField(ballot, default, ballot.ConfirmationCode);

        Assert.Equal("8.structure", Assert.Throws<VerificationFailedException>(() => new ConfirmationCodeVerification().Verify(malformed, encryptionRecord)).SubSection);
    }
}
