using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.Verify.PreEncryption;

/// <summary>
/// The once-per-device items of Verification 16 (16.D, 16.E/16.F in list order, 16.G, 16.H) over the
/// chain of a device generating pre-encrypted ballots (§4.1.4): H_0 = H(H_E; 0x42, B_C,0) (eq. 117)
/// and the close B-bar_C = 0x00000001 || H(H_E; 0x44, H_ℓ, B_C,0) (eq. 120, body form per user
/// decision Q4), H-bar = H(H_E; 0x42, B-bar_C) (eq. 118). Two devices: device-1 generates three
/// ballots, device-2 two. The walk is shared with Verification 8 (see DeviceChainVerificationTests);
/// these cases pin the pre-encrypted scheme's sub-section labels and separators on each of its
/// paths. A changed ballot has its confirmation code recomputed over its new chaining field
/// (eq. 116), so the per-ballot 16.C still passes.
/// </summary>
public class PreEncryptedDeviceChainTests
{
    private const string BallotStyleId = "ballot-style-1";

    private sealed record Election(
        EncryptionRecord Record,
        DeviceChainRecord Device1,
        List<PreEncryptedBallot> Ballots1,
        DeviceChainRecord Device2,
        List<PreEncryptedBallot> Ballots2)
    {
        public List<PreEncryptedBallot> AllBallots => [.. Ballots1, .. Ballots2];
    }

    private static readonly Dictionary<ChainingMode, Election> Elections = [];

    public PreEncryptedDeviceChainTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static Election Build(ChainingMode mode)
    {
        if (Elections.TryGetValue(mode, out var built))
        {
            return built;
        }

        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(
            chainingMode: mode,
            hashTrimmingFunction: HashTrimmingFunction.LetterDigit);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;

        (DeviceChainRecord, List<PreEncryptedBallot>) Device(string deviceId, int count)
        {
            var chain = DeviceChain.ForPreEncryptedBallots(record, deviceId);
            var preEncryptor = new BallotPreEncryptor(record, deviceId);
            var ballots = Enumerable.Range(1, count).Select(i => preEncryptor.PreEncryptNext($"{deviceId}-ballot-{i}", BallotStyleId, chain)).ToList();
            return (chain.Close(), ballots);
        }

        var (device1, ballots1) = Device("device-1", 3);
        var (device2, ballots2) = Device("device-2", 2);
        built = new Election(record, device1, ballots1, device2, ballots2);
        Elections[mode] = built;
        return built;
    }

    /// <summary>The ballot hashed with <paramref name="field"/> instead (eq. 116), optionally under another device id.</summary>
    private static PreEncryptedBallot Rechained(PreEncryptedBallot ballot, ChainingField field, string? deviceId = null)
    {
        return ballot with
        {
            ChainingField = field,
            ConfirmationCode = ConfirmationCode.ForPreEncryptedBallot(
                ballot.SelectionEncryptionIdentifierHash,
                ballot.Contests.OrderBy(x => x.ContestIndex).Select(x => x.ContestHash),
                field),
            DeviceId = deviceId ?? ballot.DeviceId,
        };
    }

    private static VerificationFailedException Fails(DeviceChainRecord device, IEnumerable<PreEncryptedBallot> ballots, EncryptionRecord record)
    {
        return Assert.Throws<VerificationFailedException>(() => new PreEncryptedConfirmationCodeVerification().VerifyDevice(device, ballots, record));
    }

    // --- An honest record ---------------------------------------------------------------------

    [Fact]
    public void HonestChain_Verifies_AndHoldsThePreEncryptedValues()
    {
        var election = Build(ChainingMode.Simple);
        var (record, ballots, device) = (election.Record, election.Ballots1, election.Device1);
        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, "device-1");
        var verification = new PreEncryptedConfirmationCodeVerification();

        verification.VerifyDevice(device, ballots, record);
        verification.VerifyDevice(device, election.AllBallots, record);
        verification.VerifyDevices([election.Device2, device], election.AllBallots, record);
        ConfirmationCode? previous = null;
        foreach (var ballot in ballots)
        {
            verification.Verify(ballot, deviceHash, record, previous);
            previous = ballot.ConfirmationCode;
        }

        Assert.Equal(DeviceChainBallotKind.PreEncrypted, device.BallotKind);
        Assert.Equal(deviceHash, device.DeviceInformationHash);
        Assert.Equal(ChainingField.InitialHashForPreEncryptedBallots(deviceHash, record.ExtendedBaseHash), device.InitialHash);
        var closing = ChainingField.ClosingForPreEncryptedBallots(deviceHash, record.ExtendedBaseHash, ballots[^1].ConfirmationCode);
        Assert.Equal(closing, device.ClosingChainingField);
        Assert.Equal(ChainingField.ClosingHashForPreEncryptedBallots(closing, record.ExtendedBaseHash), device.ClosingHash);

        // Not the regular-ballot values (0x29 and 0x2B).
        Assert.NotEqual(ChainingField.InitialHash(deviceHash, record.ExtendedBaseHash), device.InitialHash);
        Assert.NotEqual(ChainingField.Closing(deviceHash, record.ExtendedBaseHash, ballots[^1].ConfirmationCode), device.ClosingChainingField);
    }

    [Fact]
    public void HonestNoChainingDevices_Verify_WithoutInitialOrClosingValues()
    {
        var election = Build(ChainingMode.None);
        var verification = new PreEncryptedConfirmationCodeVerification();

        verification.VerifyDevices([election.Device1, election.Device2], election.AllBallots, election.Record);
        Assert.Equal(election.Ballots1.Select(x => x.ConfirmationCode), election.Device1.ConfirmationCodes);
        Assert.Null(election.Device1.InitialHash);
        Assert.Null(election.Device1.ClosingChainingField);
        Assert.Null(election.Device1.ClosingHash);
    }

    // --- 16.E/16.F: each ballot's chaining field in list order ---------------------------------

    [Fact]
    public void NoChaining_BallotWithWrongChainingField_Fails16E()
    {
        // The regular-ballot (0x2A) device hash in place of the pre-encrypted one (0x43, eq. 119).
        var election = Build(ChainingMode.None);
        var record = election.Record;
        var ballots = election.Ballots1.ToList();
        var regularDeviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1");
        ballots[1] = Rechained(ballots[1], new ChainingField(ChainingMode.None, regularDeviceHash, record.ExtendedBaseHash, null));
        var device = election.Device1 with { ConfirmationCodes = [.. ballots.Select(x => x.ConfirmationCode)] };

        var exception = Fails(device, ballots, record);
        Assert.Equal("16.E", exception.SubSection);
        Assert.Contains(ballots[1].Id, exception.Message);
    }

    [Fact]
    public void NoChaining_BallotFromAnotherDeviceWithItsIdRewritten_Fails16E()
    {
        var election = Build(ChainingMode.None);
        var spliced = election.Ballots2[0] with { DeviceId = "device-1" };
        var ballots = election.Ballots1.Append(spliced).ToList();
        var device = election.Device1 with { ConfirmationCodes = [.. ballots.Select(x => x.ConfirmationCode)] };

        Assert.Equal("16.E", Fails(device, ballots, election.Record).SubSection);
    }

    [Fact]
    public void WrongPreviousCode_Fails16F()
    {
        // Ballot 3 was hashed with ballot 1's code instead of ballot 2's.
        var election = Build(ChainingMode.Simple);
        var record = election.Record;
        var ballots = election.Ballots1.ToList();
        var wrong = ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, election.Device1.DeviceInformationHash, record.ExtendedBaseHash, ballots[0].ConfirmationCode);
        ballots[2] = Rechained(ballots[2], wrong);
        var device = election.Device1 with { ConfirmationCodes = [.. ballots.Select(x => x.ConfirmationCode)] };

        var exception = Fails(device, ballots, record);
        Assert.Equal("16.F", exception.SubSection);
        Assert.Contains(ballots[2].Id, exception.Message);
    }

    [Fact]
    public void FirstBallotChainedFromTheRegularInitialHash_Fails16F()
    {
        // B_C,1 = 0x00000001 || H_0 with the regular-ballot H_0 (0x29, eq. 74) instead of eq. (117)'s.
        var election = Build(ChainingMode.Simple);
        var record = election.Record;
        var ballots = election.Ballots1.ToList();
        var regularInitialHash = ChainingField.InitialHash(election.Device1.DeviceInformationHash, record.ExtendedBaseHash);
        ballots[0] = Rechained(ballots[0], ChainingField.FromCanonicalBytes([0, 0, 0, 1, .. (byte[])regularInitialHash]));
        var device = election.Device1 with { ConfirmationCodes = [.. ballots.Select(x => x.ConfirmationCode)] };

        var exception = Fails(device, ballots, record);
        Assert.Equal("16.F", exception.SubSection);
        Assert.Contains(ballots[0].Id, exception.Message);
    }

    [Fact]
    public void ReorderedBallots_Fail16F()
    {
        var election = Build(ChainingMode.Simple);
        var codes = election.Device1.ConfirmationCodes.ToList();
        (codes[0], codes[1]) = (codes[1], codes[0]);

        Assert.Equal("16.F", Fails(election.Device1 with { ConfirmationCodes = codes }, election.Ballots1, election.Record).SubSection);
    }

    [Fact]
    public void DroppedMiddleBallot_Fails16F()
    {
        var election = Build(ChainingMode.Simple);
        var kept = election.Ballots1.Where((_, i) => i != 1).ToList();

        Assert.Equal("16.F", Fails(election.Device1 with { ConfirmationCodes = [.. kept.Select(x => x.ConfirmationCode)] }, kept, election.Record).SubSection);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BallotFromAnotherDeviceSplicedIn_Fails(bool deviceIdRewritten)
    {
        // Device-2's first ballot inserted after device-1's first. As published it names device-2
        // (structure); with its device id rewritten to device-1 it still chains from device-2's
        // H_0, which no ballot of device-1 does (16.F).
        var election = Build(ChainingMode.Simple);
        var spliced = deviceIdRewritten ? election.Ballots2[0] with { DeviceId = "device-1" } : election.Ballots2[0];
        var ballots = election.Ballots1.ToList();
        ballots.Insert(1, spliced);
        var device = election.Device1 with { ConfirmationCodes = [.. ballots.Select(x => x.ConfirmationCode)] };

        var exception = Fails(device, [.. ballots, election.Ballots2[1]], election.Record);
        Assert.Equal(deviceIdRewritten ? "16.F" : "16.structure", exception.SubSection);
    }

    // --- 16.G: the initialization code ----------------------------------------------------------

    [Theory]
    [InlineData("regular")]
    [InlineData("missing")]
    public void WrongInitialHash_Fails16G(string variant)
    {
        var election = Build(ChainingMode.Simple);
        var record = election.Record;
        var initialHash = variant == "missing" ? (ConfirmationCode?)null : ChainingField.InitialHash(election.Device1.DeviceInformationHash, record.ExtendedBaseHash);

        Assert.Equal("16.G", Fails(election.Device1 with { InitialHash = initialHash }, election.Ballots1, record).SubSection);
    }

    // --- 16.H: the chain close ------------------------------------------------------------------

    [Fact]
    public void DroppedLastBallot_FromListAndRecord_Fails16H()
    {
        var election = Build(ChainingMode.Simple);
        var truncated = election.Device1 with { ConfirmationCodes = [.. election.Device1.ConfirmationCodes.Take(2)] };

        Assert.Equal("16.H", Fails(truncated, election.Ballots1.Take(2), election.Record).SubSection);
    }

    [Theory]
    [InlineData("closing hash")]
    [InlineData("closing field")]
    [InlineData("regular close")]
    [InlineData("no closing hash")]
    [InlineData("no closing field")]
    public void WrongClose_Fails16H(string variant)
    {
        var election = Build(ChainingMode.Simple);
        var record = election.Record;
        var device = election.Device1;
        byte[] hash = ((byte[])device.ClosingHash!.Value).ToArray();
        hash[0] ^= 0x80;
        byte[] field = ((byte[])device.ClosingChainingField!.Value).ToArray();
        field[^1] ^= 0x01;
        var regular = ChainingField.Closing(device.DeviceInformationHash, record.ExtendedBaseHash, election.Ballots1[^1].ConfirmationCode);
        var tampered = variant switch
        {
            // The closing field is right; only H-bar is wrong.
            "closing hash" => device with { ClosingHash = new ConfirmationCode(hash) },
            "closing field" => device with { ClosingChainingField = ChainingField.FromCanonicalBytes(field) },

            // The regular-ballot close (0x2B, 0x29), consistent with itself.
            "regular close" => device with { ClosingChainingField = regular, ClosingHash = ChainingField.ClosingHash(regular, record.ExtendedBaseHash) },
            "no closing hash" => device with { ClosingHash = null },
            _ => device with { ClosingChainingField = null },
        };

        var exception = Fails(tampered, election.Ballots1, record);
        Assert.Equal("16.H", exception.SubSection);
        Assert.Contains(variant is "closing hash" or "no closing hash" ? "closing hash recorded" : "final input byte array", exception.Message);
    }

    // --- 16.D and structure ---------------------------------------------------------------------

    [Theory]
    [InlineData(ChainingMode.None)]
    [InlineData(ChainingMode.Simple)]
    public void RegularDeviceInformationHash_Fails16D(ChainingMode mode)
    {
        var election = Build(mode);

        Assert.Equal("16.D", Fails(election.Device1 with { DeviceInformationHash = new VotingDeviceInformationHash(election.Record.ExtendedBaseHash, "device-1") }, election.Ballots1, election.Record).SubSection);
    }

    [Fact]
    public void ARecordThatDoesNotAccountForItsBallots_FailsStructure()
    {
        var election = Build(ChainingMode.Simple);
        var record = election.Record;
        var device = election.Device1;

        // A regular-ballot chain; the last ballot dropped from the list only; a mode other than the
        // manifest's.
        Assert.Equal("16.structure", Fails(device with { BallotKind = DeviceChainBallotKind.Encrypted }, election.Ballots1, record).SubSection);
        var exception = Fails(device with { ConfirmationCodes = [.. device.ConfirmationCodes.Take(2)] }, election.AllBallots, record);
        Assert.Equal("16.structure", exception.SubSection);
        Assert.Contains(election.Ballots1[2].Id, exception.Message);
        Assert.Equal("16.structure", Fails(device with { ChainingMode = ChainingMode.None }, election.Ballots1, record).SubSection);
    }

    [Fact]
    public void VerifyDevices_EveryBallotOnExactlyOneDevicesList()
    {
        var election = Build(ChainingMode.Simple);

        // Device-2 has no list: its ballots are on none.
        Assert.Equal("16.structure", Assert.Throws<VerificationFailedException>(() => new PreEncryptedConfirmationCodeVerification().VerifyDevices([election.Device1], election.AllBallots, election.Record)).SubSection);
    }

    // --- DeviceChain ----------------------------------------------------------------------------

    [Fact]
    public void PreEncryptNext_RefusesARegularBallotChain()
    {
        var record = Build(ChainingMode.Simple).Record;

        Assert.Throws<ArgumentException>(() => new BallotPreEncryptor(record, "device-1").PreEncryptNext("ballot-x", BallotStyleId, new DeviceChain(record, "device-1")));
    }

    [Fact]
    public void DeviceChain_RefusesAPreEncryptedBallotOfAnotherDeviceOrChainPosition()
    {
        var election = Build(ChainingMode.Simple);
        var chain = DeviceChain.ForPreEncryptedBallots(election.Record, "device-1");

        Assert.Throws<ArgumentException>(() => chain.Append(election.Ballots2[0]));
        Assert.Throws<ArgumentException>(() => chain.Append(election.Ballots1[1]));
        chain.Append(election.Ballots1[0]);
        Assert.Throws<ArgumentException>(() => chain.Append(election.Ballots1[2]));
        chain.Append(election.Ballots1[1]);
        chain.Append(election.Ballots1[2]);

        var closed = chain.Close();
        Assert.Equal(election.Device1.ConfirmationCodes, closed.ConfirmationCodes);
        Assert.Equal(election.Device1.ClosingHash, closed.ClosingHash);
        Assert.Throws<InvalidOperationException>(() => chain.Append(election.Ballots1[0]));
    }
}
