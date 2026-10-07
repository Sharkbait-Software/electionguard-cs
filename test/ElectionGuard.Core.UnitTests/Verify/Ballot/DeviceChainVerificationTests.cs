using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.Verify.Ballot;

/// <summary>
/// The once-per-device part of Verification 8 (§3.4.4, §3.7 "Ordered lists of the ballots encrypted
/// by each device"): <see cref="DeviceChain"/> builds and closes a device's chain, and
/// <see cref="ConfirmationCodeVerification.VerifyDevice(DeviceChainRecord, IEnumerable{EncryptedBallot}, EncryptionRecord)"/>
/// walks it. Two devices: device-1 encrypts four ballots, device-2 two. Each negative case changes
/// one thing a malicious insider could (§3.4.4: "selectively delete ballots and confirmation codes")
/// and asserts the lettered check that catches it. A changed ballot always has its confirmation code
/// recomputed over its new chaining field, so the per-ballot 8.A/8.B still pass.
/// </summary>
public class DeviceChainVerificationTests
{
    private sealed record Election(
        EncryptionRecord Record,
        DeviceChainRecord Device1,
        List<EncryptedBallot> Ballots1,
        DeviceChainRecord Device2,
        List<EncryptedBallot> Ballots2)
    {
        public List<EncryptedBallot> AllBallots => [.. Ballots1, .. Ballots2];
    }

    private static readonly Dictionary<ChainingMode, Election> Elections = [];

    public DeviceChainVerificationTests()
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
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(chainingMode: mode);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;

        (DeviceChainRecord, List<EncryptedBallot>) Device(string deviceId, int count)
        {
            var chain = new DeviceChain(record, deviceId);
            var encryptor = new BallotEncryptor(record, deviceId, new VotingDeviceInformationHash(record.ExtendedBaseHash, deviceId));
            var ballots = new List<EncryptedBallot>();
            for (int i = 0; i < count; i++)
            {
                var ballot = ElectionFixtureBuilder.CreateBallot(manifest, ballotId: $"{deviceId}-ballot-{i + 1}", selectionValuesByChoiceId: new Dictionary<string, int> { [i % 2 == 0 ? "choice-1" : "choice-2"] = 1 });
                var encrypted = encryptor.EncryptNext(ballot, chain);
                encrypted.RecordStatus(i == 1 ? BallotStatus.Challenged : BallotStatus.Cast);
                ballots.Add(encrypted);
            }

            return (chain.Close(), ballots);
        }

        var (device1, ballots1) = Device("device-1", 4);
        var (device2, ballots2) = Device("device-2", 2);
        built = new Election(record, device1, ballots1, device2, ballots2);
        Elections[mode] = built;
        return built;
    }

    private static VerificationFailedException Fails(DeviceChainRecord device, IEnumerable<EncryptedBallot> ballots, EncryptionRecord record)
    {
        return Assert.Throws<VerificationFailedException>(() => new ConfirmationCodeVerification().VerifyDevice(device, ballots, record));
    }

    private static void Passes(DeviceChainRecord device, IEnumerable<EncryptedBallot> ballots, EncryptionRecord record)
    {
        var verification = new ConfirmationCodeVerification();
        Assert.Null(Record.Exception(() => verification.VerifyDevice(device, ballots, record)));
        foreach (var ballot in ballots)
        {
            Assert.Null(Record.Exception(() => verification.Verify(ballot, record)));
        }
    }

    // --- An honest record ---------------------------------------------------------------------

    [Theory]
    [InlineData(ChainingMode.None)]
    [InlineData(ChainingMode.Simple)]
    public void HonestDevices_Verify(ChainingMode mode)
    {
        var election = Build(mode);

        Passes(election.Device1, election.AllBallots, election.Record);
        Passes(election.Device2, election.AllBallots, election.Record);
        Assert.Null(Record.Exception(() => new ConfirmationCodeVerification().VerifyDevices([election.Device2, election.Device1], election.AllBallots, election.Record)));
        Assert.Null(Record.Exception(() => new ConfirmationCodeVerification().VerifyDevices([election.Device1, election.Device2], election.AllBallots.Select(DeviceChainLink.From), election.Record)));
    }

    [Fact]
    public void SimpleChain_RecordHoldsTheSpecsValues()
    {
        var election = Build(ChainingMode.Simple);
        var record = election.Record;
        var device = election.Device1;
        var deviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1");

        Assert.Equal("device-1", device.DeviceId);
        Assert.Equal(deviceHash, device.DeviceInformationHash);
        Assert.Equal(DeviceChainBallotKind.Encrypted, device.BallotKind);
        Assert.Equal(ChainingMode.Simple, device.ChainingMode);
        Assert.Equal(election.Ballots1.Select(x => x.ConfirmationCode), device.ConfirmationCodes);

        // Eq. (74), and the first ballot chains from it (eq. 76, j = 1); every later one from its predecessor.
        Assert.Equal(ChainingField.InitialHash(deviceHash, record.ExtendedBaseHash), device.InitialHash);
        Assert.Equal(new ChainingField(ChainingMode.Simple, deviceHash, record.ExtendedBaseHash, device.InitialHash), election.Ballots1[0].ChainingField);
        for (int j = 1; j < election.Ballots1.Count; j++)
        {
            Assert.Equal([0, 0, 0, 1, .. (byte[])election.Ballots1[j - 1].ConfirmationCode], (byte[])election.Ballots1[j].ChainingField);
        }

        // Eqs. (78) and (77) over the last confirmation code.
        var closing = ChainingField.Closing(deviceHash, record.ExtendedBaseHash, election.Ballots1[^1].ConfirmationCode);
        Assert.Equal(closing, device.ClosingChainingField);
        Assert.Equal(ChainingField.ClosingHash(closing, record.ExtendedBaseHash), device.ClosingHash);
    }

    [Fact]
    public void NoChaining_RecordHasNoInitialOrClosingValues()
    {
        var election = Build(ChainingMode.None);

        Assert.Equal(election.Ballots1.Select(x => x.ConfirmationCode), election.Device1.ConfirmationCodes);
        Assert.Null(election.Device1.InitialHash);
        Assert.Null(election.Device1.ClosingChainingField);
        Assert.Null(election.Device1.ClosingHash);
    }

    // --- The required negative cases ----------------------------------------------------------

    [Fact]
    public void WrongPreviousCode_Fails8E()
    {
        // Ballot 3 was hashed with ballot 1's code instead of ballot 2's.
        var election = Build(ChainingMode.Simple);
        var ballots = election.Ballots1.ToList();
        var wrong = new ChainingField(ChainingMode.Simple, election.Device1.DeviceInformationHash, election.Record.ExtendedBaseHash, ballots[0].ConfirmationCode);
        ballots[2] = ConfirmationCodeVerificationTests.Rechained(ballots[2], wrong);
        var device = election.Device1 with { ConfirmationCodes = [.. ballots.Select(x => x.ConfirmationCode)] };

        // Ballot 4 now also follows a code it was not hashed with; ballot 3 is reported first.
        var exception = Fails(device, ballots, election.Record);
        Assert.Equal("8.E", exception.SubSection);
        Assert.Contains(ballots[2].Id, exception.Message);
    }

    [Theory]
    [InlineData(ChainingMode.Simple, "8.E")]
    [InlineData(ChainingMode.None, null)]
    public void ReorderedBallots_FailUnderSimpleChaining(ChainingMode mode, string? subSection)
    {
        var election = Build(mode);
        var codes = election.Device1.ConfirmationCodes.ToList();
        (codes[1], codes[2]) = (codes[2], codes[1]);
        var device = election.Device1 with { ConfirmationCodes = codes };

        if (subSection is null)
        {
            // No chaining: nothing in the ballots attests to their order (eq. 73).
            Passes(device, election.AllBallots, election.Record);
        }
        else
        {
            Assert.Equal(subSection, Fails(device, election.AllBallots, election.Record).SubSection);
        }
    }

    [Fact]
    public void DroppedLastBallot_FromListAndRecord_Fails8G()
    {
        // The insider deletes the last ballot and its confirmation code, but the closing hash was
        // published when the device closed its chain.
        var election = Build(ChainingMode.Simple);
        var device = election.Device1 with { ConfirmationCodes = [.. election.Device1.ConfirmationCodes.Take(3)] };

        Assert.Equal("8.G", Fails(device, election.Ballots1.Take(3), election.Record).SubSection);
    }

    [Fact]
    public void DroppedLastBallot_WithARecomputedClose_PassesTheChecksButNotTheOriginalClosingHash()
    {
        // The close is not keyed with any secret: an insider who can also replace the published
        // closing hash produces a consistent shorter chain. What prevents that is publishing H-bar
        // when the device closes (§3.4.4: "closed at the end of an election by forming and
        // publishing"), so the shorter chain's H-bar differs from the one already published.
        var election = Build(ChainingMode.Simple);
        var record = election.Record;
        var last = election.Ballots1[2].ConfirmationCode;
        var closing = ChainingField.Closing(election.Device1.DeviceInformationHash, record.ExtendedBaseHash, last);
        var device = election.Device1 with
        {
            ConfirmationCodes = [.. election.Device1.ConfirmationCodes.Take(3)],
            ClosingChainingField = closing,
            ClosingHash = ChainingField.ClosingHash(closing, record.ExtendedBaseHash),
        };

        Passes(device, election.Ballots1.Take(3), record);
        Assert.NotEqual(election.Device1.ClosingHash, device.ClosingHash);
    }

    [Fact]
    public void DroppedLastBallot_FromTheListOnly_FailsStructure()
    {
        var election = Build(ChainingMode.Simple);
        var device = election.Device1 with { ConfirmationCodes = [.. election.Device1.ConfirmationCodes.Take(3)] };

        var exception = Fails(device, election.AllBallots, election.Record);
        Assert.Equal("8.structure", exception.SubSection);
        Assert.Contains(election.Ballots1[3].Id, exception.Message);
    }

    [Theory]
    [InlineData(ChainingMode.Simple, "8.E")]
    [InlineData(ChainingMode.None, null)]
    public void DroppedMiddleBallot_FromListAndRecord_FailsUnderSimpleChaining(ChainingMode mode, string? subSection)
    {
        var election = Build(mode);
        var kept = election.Ballots1.Where((_, i) => i != 1).ToList();
        var device = election.Device1 with { ConfirmationCodes = [.. kept.Select(x => x.ConfirmationCode)] };

        if (subSection is null)
        {
            Passes(device, kept, election.Record);
        }
        else
        {
            var exception = Fails(device, kept, election.Record);
            Assert.Equal(subSection, exception.SubSection);
            Assert.Contains(election.Ballots1[2].Id, exception.Message);
        }
    }

    [Theory]
    [InlineData("closing hash")]
    [InlineData("closing field")]
    [InlineData("closing field of the regular separator over the wrong code")]
    [InlineData("no closing hash")]
    [InlineData("no closing field")]
    public void WrongClose_Fails8G(string variant)
    {
        var election = Build(ChainingMode.Simple);
        var record = election.Record;
        byte[] hash = ((byte[])election.Device1.ClosingHash!.Value).ToArray();
        hash[0] ^= 0x80;
        byte[] field = ((byte[])election.Device1.ClosingChainingField!.Value).ToArray();
        field[^1] ^= 0x01;
        var device = variant switch
        {
            "closing hash" => election.Device1 with { ClosingHash = new ConfirmationCode(hash) },
            "closing field" => election.Device1 with { ClosingChainingField = ChainingField.FromCanonicalBytes(field) },
            "closing field of the regular separator over the wrong code" => election.Device1 with
            {
                ClosingChainingField = ChainingField.Closing(election.Device1.DeviceInformationHash, record.ExtendedBaseHash, election.Ballots1[2].ConfirmationCode),
            },
            "no closing hash" => election.Device1 with { ClosingHash = null },
            _ => election.Device1 with { ClosingChainingField = null },
        };

        Assert.Equal("8.G", Fails(device, election.AllBallots, record).SubSection);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BallotFromAnotherDeviceSplicedIn_Fails(bool deviceIdRewritten)
    {
        // Device-2's first ballot inserted after device-1's second. As published it names device-2
        // (structure); with its device id rewritten to device-1 it still chains from device-2's
        // H_0, which no ballot of device-1 does (8.E).
        var election = Build(ChainingMode.Simple);
        var spliced = deviceIdRewritten
            ? ConfirmationCodeVerificationTests.WithChainingField(election.Ballots2[0], election.Ballots2[0].ChainingField, election.Ballots2[0].ConfirmationCode, "device-1")
            : election.Ballots2[0];
        var ballots = election.Ballots1.ToList();
        ballots.Insert(2, spliced);
        var device = election.Device1 with { ConfirmationCodes = [.. ballots.Select(x => x.ConfirmationCode)] };

        var exception = Fails(device, [.. ballots, election.Ballots2[1]], election.Record);
        Assert.Equal(deviceIdRewritten ? "8.E" : "8.structure", exception.SubSection);
    }

    [Fact]
    public void NoChaining_BallotFromAnotherDeviceWithItsIdRewritten_Fails8D()
    {
        var election = Build(ChainingMode.None);
        var spliced = ConfirmationCodeVerificationTests.WithChainingField(election.Ballots2[0], election.Ballots2[0].ChainingField, election.Ballots2[0].ConfirmationCode, "device-1");
        var ballots = election.Ballots1.Append(spliced).ToList();
        var device = election.Device1 with { ConfirmationCodes = [.. ballots.Select(x => x.ConfirmationCode)] };

        Assert.Equal("8.D", Fails(device, ballots, election.Record).SubSection);
        Assert.Equal("8.D", Assert.Throws<VerificationFailedException>(() => new ConfirmationCodeVerification().Verify(spliced, election.Record)).SubSection);
    }

    [Fact]
    public void NoChaining_BallotWithWrongChainingField_Fails8D()
    {
        var election = Build(ChainingMode.None);
        var ballots = election.Ballots1.ToList();
        ballots[1] = ConfirmationCodeVerificationTests.Rechained(ballots[1], ElectionFixtureBuilder.PlaceholderChainingField);
        var device = election.Device1 with { ConfirmationCodes = [.. ballots.Select(x => x.ConfirmationCode)] };

        var exception = Fails(device, ballots, election.Record);
        Assert.Equal("8.D", exception.SubSection);
        Assert.Contains(ballots[1].Id, exception.Message);
    }

    // --- The other once-per-device checks -----------------------------------------------------

    [Theory]
    [InlineData("wrong")]
    [InlineData("missing")]
    public void WrongInitialHash_Fails8F(string variant)
    {
        var election = Build(ChainingMode.Simple);
        var device = election.Device1 with { InitialHash = variant == "missing" ? null : election.Ballots1[0].ConfirmationCode };

        Assert.Equal("8.F", Fails(device, election.AllBallots, election.Record).SubSection);
    }

    [Theory]
    [InlineData(ChainingMode.None)]
    [InlineData(ChainingMode.Simple)]
    public void WrongDeviceInformationHash_Fails8C(ChainingMode mode)
    {
        var election = Build(mode);
        var device = election.Device1 with { DeviceInformationHash = election.Device2.DeviceInformationHash };

        Assert.Equal("8.C", Fails(device, election.AllBallots, election.Record).SubSection);
    }

    [Fact]
    public void ARecordThatDoesNotAccountForItsBallots_FailsStructure()
    {
        var election = Build(ChainingMode.Simple);
        var record = election.Record;
        var codes = election.Device1.ConfirmationCodes;

        // A code listed twice; a code no ballot has; a mode other than the manifest's; the
        // pre-encrypted kind; an empty chain.
        Assert.Equal("8.structure", Fails(election.Device1 with { ConfirmationCodes = [.. codes, codes[3]] }, election.AllBallots, record).SubSection);
        Assert.Equal("8.structure", Fails(election.Device1 with { ConfirmationCodes = [.. codes, new ConfirmationCode(new byte[32])] }, election.AllBallots, record).SubSection);
        Assert.Equal("8.structure", Fails(election.Device1 with { ChainingMode = ChainingMode.None }, election.AllBallots, record).SubSection);
        Assert.Equal("8.structure", Fails(election.Device1 with { BallotKind = DeviceChainBallotKind.PreEncrypted }, election.AllBallots, record).SubSection);
        Assert.Equal("8.structure", Fails(election.Device1 with { ConfirmationCodes = [] }, election.Ballots2, record).SubSection);
    }

    [Fact]
    public void NoChainingRecordWithAClose_FailsStructure()
    {
        var simple = Build(ChainingMode.Simple);
        var election = Build(ChainingMode.None);
        var device = election.Device1 with { ClosingHash = simple.Device1.ClosingHash };

        Assert.Equal("8.structure", Fails(device, election.AllBallots, election.Record).SubSection);
    }

    [Fact]
    public void VerifyDevices_EveryBallotOnExactlyOneDevicesList()
    {
        var election = Build(ChainingMode.Simple);
        var verification = new ConfirmationCodeVerification();

        // Device-2 has no list: its ballots are on none.
        Assert.Equal("8.structure", Assert.Throws<VerificationFailedException>(() => verification.VerifyDevices([election.Device1], election.AllBallots, election.Record)).SubSection);

        // Two lists for device-1.
        Assert.Equal("8.structure", Assert.Throws<VerificationFailedException>(() => verification.VerifyDevices([election.Device1, election.Device2, election.Device1], election.AllBallots, election.Record)).SubSection);

        // Two ballots with one confirmation code.
        Assert.Equal("8.structure", Assert.Throws<VerificationFailedException>(() => verification.VerifyDevices([election.Device1, election.Device2], [.. election.AllBallots, election.Ballots1[0]], election.Record)).SubSection);
    }

    // --- DeviceChain --------------------------------------------------------------------------

    [Fact]
    public void DeviceChain_RefusesABallotOfAnotherDeviceOrChainPosition_AndAnyAfterClose()
    {
        var election = Build(ChainingMode.Simple);
        var record = election.Record;
        var chain = new DeviceChain(record, "device-1");

        Assert.Null(chain.PreviousConfirmationCode);
        Assert.Throws<ArgumentException>(() => chain.Append(election.Ballots2[0]));
        Assert.Throws<ArgumentException>(() => chain.Append(election.Ballots1[1]));
        chain.Append(election.Ballots1[0]);
        Assert.Equal(election.Ballots1[0].ConfirmationCode, chain.PreviousConfirmationCode);
        Assert.Throws<ArgumentException>(() => chain.Append(election.Ballots1[2]));
        chain.Append(election.Ballots1[1]);
        Assert.Equal(2, chain.Count);

        var closed = chain.Close();
        Assert.Equal(closed.ClosingHash, chain.Close().ClosingHash);
        Assert.Throws<InvalidOperationException>(() => chain.Append(election.Ballots1[2]));

        // A different encryptor's device.
        var encryptor = new BallotEncryptor(record, "device-2", new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-2"));
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(chainingMode: ChainingMode.Simple);
        Assert.Throws<ArgumentException>(() => encryptor.EncryptNext(ElectionFixtureBuilder.CreateBallot(manifest), new DeviceChain(record, "device-1")));
    }

    [Theory]
    [InlineData(ChainingMode.None)]
    [InlineData(ChainingMode.Simple)]
    public void DeviceChain_EmptyChain_ClosesOnlyWithoutChaining(ChainingMode mode)
    {
        var election = Build(mode);
        var chain = new DeviceChain(election.Record, "device-3");

        if (mode == ChainingMode.None)
        {
            var closed = chain.Close();
            Assert.Empty(closed.ConfirmationCodes);
            Assert.Null(closed.ClosingHash);
            Assert.Null(Record.Exception(() => new ConfirmationCodeVerification().VerifyDevice(closed, election.AllBallots, election.Record)));
        }
        else
        {
            // Eq. (78) closes over the final confirmation code H_ℓ, which an empty chain lacks.
            Assert.Throws<InvalidOperationException>(() => chain.Close());
        }
    }

    [Fact]
    public void DeviceChain_NoChaining_PreviousCodeIsAlwaysNull()
    {
        var election = Build(ChainingMode.None);
        var chain = new DeviceChain(election.Record, "device-1");
        chain.Append(election.Ballots1[0]);
        chain.Append(election.Ballots1[2]);

        Assert.Null(chain.PreviousConfirmationCode);
        Assert.Equal([election.Ballots1[0].ConfirmationCode, election.Ballots1[2].ConfirmationCode], chain.Close().ConfirmationCodes);
    }
}
