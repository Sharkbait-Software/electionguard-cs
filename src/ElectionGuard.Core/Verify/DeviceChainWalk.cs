using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// The once-per-device part of Verification 8 (8.C, 8.D/8.E in chain order, 8.F, 8.G) and of
/// Verification 16 (16.D, 16.E/16.F, 16.G, 16.H): a walk of a device's ordered ballot list
/// (§3.7) against the ballots of the record. The two differ only in their sub-section numbers and
/// domain separators (§3.4.4 vs §4.1.4).
///
/// Each listed ballot's chaining field is compared with the one its position implies: under no
/// chaining 0x00000000 || H_DI (eq. 73); under simple chaining 0x00000001 || H_{j-1}, with H_{j-1}
/// the confirmation code of the ballot listed before it, or H_0 for the first (eq. 76). A
/// reordered list, a ballot dropped from the middle of the chain, or a ballot spliced in from
/// another device's chain therefore fails 8.E (16.F), and a ballot dropped from the end fails the
/// closing hash, 8.G (16.H). The confirmation codes the walk links are taken as published; that
/// each is the hash of its own ballot's contents and B_C is the per-ballot 8.B (16.C), which must
/// also be run on every ballot.
///
/// The record must also account for the ballots: every listed confirmation code must be the code
/// of exactly one ballot of the record, encrypted on this device (its <c>DeviceId</c>), listed
/// once; every ballot of the record that names the device must be listed; the record's mode and
/// ballot kind must be the manifest's and the verification's; and under no chaining there is no
/// initialization or closing value, while under simple chaining the chain is not empty. A failure
/// there is reported as <c>"N.structure"</c>, before any lettered check.
/// </summary>
internal static class DeviceChainWalk
{
    internal sealed record Scheme(
        int Verification,
        DeviceChainBallotKind BallotKind,
        string DeviceHashSubSection,
        string NoChainingSubSection,
        string SimpleChainingSubSection,
        string InitialHashSubSection,
        string ClosingSubSection,
        Func<ExtendedBaseHash, string, VotingDeviceInformationHash> DeviceHash,
        Func<ChainingMode, VotingDeviceInformationHash, ExtendedBaseHash, ConfirmationCode?, ChainingField> ChainingField,
        Func<VotingDeviceInformationHash, ExtendedBaseHash, ConfirmationCode> InitialHash,
        Func<VotingDeviceInformationHash, ExtendedBaseHash, ConfirmationCode, ChainingField> Closing,
        Func<ChainingField, ExtendedBaseHash, ConfirmationCode> ClosingHash);

    internal static readonly Scheme Encrypted = new(
        8,
        DeviceChainBallotKind.Encrypted,
        "8.C",
        "8.D",
        "8.E",
        "8.F",
        "8.G",
        static (extendedBaseHash, deviceId) => new VotingDeviceInformationHash(extendedBaseHash, deviceId),
        static (mode, deviceHash, extendedBaseHash, previous) => new ChainingField(mode, deviceHash, extendedBaseHash, previous),
        ChainingField.InitialHash,
        ChainingField.Closing,
        ChainingField.ClosingHash);

    internal static readonly Scheme PreEncrypted = new(
        16,
        DeviceChainBallotKind.PreEncrypted,
        "16.D",
        "16.E",
        "16.F",
        "16.G",
        "16.H",
        VotingDeviceInformationHash.ForPreEncryptedBallots,
        ChainingField.ForPreEncryptedBallots,
        ChainingField.InitialHashForPreEncryptedBallots,
        ChainingField.ClosingForPreEncryptedBallots,
        ChainingField.ClosingHashForPreEncryptedBallots);

    /// <summary>The ballots of the record by confirmation code; a code held by two ballots is a structural failure.</summary>
    internal static Dictionary<ConfirmationCode, DeviceChainLink> Index(IEnumerable<DeviceChainLink> ballots, Scheme scheme)
    {
        ArgumentNullException.ThrowIfNull(ballots);

        var byCode = new Dictionary<ConfirmationCode, DeviceChainLink>();
        foreach (var link in ballots)
        {
            if (!byCode.TryAdd(link.ConfirmationCode, link))
            {
                throw Structure(scheme, $"ballots {byCode[link.ConfirmationCode].BallotId} and {link.BallotId} have the same confirmation code {link.ConfirmationCode}.");
            }
        }

        return byCode;
    }

    /// <summary>Verifies every device record, each ballot of the record being on exactly one of them.</summary>
    internal static void VerifyAll(IEnumerable<DeviceChainRecord> devices, IEnumerable<DeviceChainLink> ballots, EncryptionRecord encryptionRecord, Scheme scheme)
    {
        ArgumentNullException.ThrowIfNull(devices);
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        var links = ballots.ToList();
        var byCode = Index(links, scheme);
        var deviceList = devices.ToList();

        // Each device's ballots, so that each walk's completeness check reads only its own group:
        // O(ballots) for the whole record rather than O(devices x ballots). byCode stays whole, so a
        // listed ballot of another device is still found and reported.
        var byDevice = new Dictionary<string, List<DeviceChainLink>>(StringComparer.Ordinal);
        foreach (var link in links)
        {
            if (link.DeviceId is null)
            {
                continue;
            }

            if (!byDevice.TryGetValue(link.DeviceId, out var group))
            {
                byDevice[link.DeviceId] = group = [];
            }

            group.Add(link);
        }

        var deviceIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var device in deviceList)
        {
            if (device is null)
            {
                throw Structure(scheme, "the list of device records has a null entry.");
            }

            if (!deviceIds.Add(device.DeviceId))
            {
                throw Structure(scheme, $"device {device.DeviceId} has more than one ordered ballot list.");
            }
        }

        foreach (var link in links)
        {
            if (!deviceIds.Contains(link.DeviceId))
            {
                throw Structure(scheme, $"ballot {link.BallotId} was encrypted on device {link.DeviceId}, which has no ordered ballot list (§3.7).");
            }
        }

        foreach (var device in deviceList)
        {
            // A device record without an id fails structure in Verify before the group is read.
            var group = device.DeviceId is { } deviceId && byDevice.TryGetValue(deviceId, out var own) ? own : [];
            Verify(device, group, byCode, encryptionRecord, scheme);
        }
    }

    internal static void Verify(
        DeviceChainRecord device,
        IReadOnlyCollection<DeviceChainLink> ballots,
        Dictionary<ConfirmationCode, DeviceChainLink> byCode,
        EncryptionRecord encryptionRecord,
        Scheme scheme)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        string deviceId = device.DeviceId ?? throw Structure(scheme, "a device record has no device id.");
        var mode = encryptionRecord.Manifest.ChainingMode;

        // Structure: the record's shape, then that its list accounts for exactly this device's ballots.
        if (device.BallotKind != scheme.BallotKind)
        {
            throw Structure(scheme, $"the record of device {deviceId} lists {device.BallotKind} ballots; Verification {scheme.Verification} checks {scheme.BallotKind} ones.");
        }

        if (device.ChainingMode != mode)
        {
            throw Structure(scheme, $"device {deviceId} records chaining mode {device.ChainingMode}; the manifest specifies {mode}.");
        }

        var codes = device.ConfirmationCodes ?? throw Structure(scheme, $"device {deviceId} has no list of ballots.");
        if (mode == ChainingMode.None && (device.InitialHash is not null || device.ClosingChainingField is not null || device.ClosingHash is not null))
        {
            throw Structure(scheme, $"device {deviceId} uses no chaining but records an initialization or closing value; the no-chaining mode has none (eq. 73).");
        }

        if (mode != ChainingMode.None && codes.Count == 0)
        {
            throw Structure(scheme, $"device {deviceId} has an empty chain; eq. (78) closes a chain over its final confirmation code, which an empty one does not have.");
        }

        var listed = new List<DeviceChainLink>(codes.Count);
        var seen = new HashSet<ConfirmationCode>();
        for (int j = 0; j < codes.Count; j++)
        {
            var code = codes[j];
            if (!seen.Add(code))
            {
                throw Structure(scheme, $"device {deviceId} lists confirmation code {code} more than once.");
            }

            if (!byCode.TryGetValue(code, out var link))
            {
                throw Structure(scheme, $"ballot {j + 1} on device {deviceId}, confirmation code {code}, is not a ballot of the record.");
            }

            if (!string.Equals(link.DeviceId, deviceId, StringComparison.Ordinal))
            {
                throw Structure(scheme, $"device {deviceId} lists ballot {link.BallotId}, which was encrypted on device {link.DeviceId}.");
            }

            listed.Add(link);
        }

        foreach (var link in ballots)
        {
            if (string.Equals(link.DeviceId, deviceId, StringComparison.Ordinal) && !seen.Contains(link.ConfirmationCode))
            {
                throw Structure(scheme, $"ballot {link.BallotId} was encrypted on device {deviceId} but is not in its ordered list of ballots (§3.7).");
            }
        }

        // The lettered checks, on the streaming walker the record verifier uses (8.C and 8.F at the
        // start, 8.D/8.E per link in chain order, 8.G at the close), stopping at the first failure.
        var walker = new DeviceChainWalker(scheme, encryptionRecord);
        Throw(walker.Begin(deviceId, device.DeviceInformationHash, device.BallotKind, device.ChainingMode, device.InitialHash));
        foreach (var link in listed)
        {
            Throw(walker.Next(link.BallotId, link.ConfirmationCode, link.ChainingField));
        }

        Throw(walker.End(device.ClosingChainingField, device.ClosingHash));

        static void Throw(VerificationFailedException? failure)
        {
            if (failure is not null)
            {
                throw failure;
            }
        }
    }

    private static VerificationFailedException Structure(Scheme scheme, string message)
    {
        return new VerificationFailedException(
            $"{scheme.Verification}.{BallotStructure.SubSectionSuffix}",
            $"Device chain verification failed: {message}");
    }
}
