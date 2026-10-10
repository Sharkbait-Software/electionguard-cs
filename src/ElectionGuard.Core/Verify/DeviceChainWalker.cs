using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// The incremental, constant-memory form of <see cref="DeviceChainWalk"/> (design §6.2, §8.4): the
/// once-per-device lettered checks of Verification 8 (8.C, 8.D/8.E in chain order, 8.F, 8.G) or 16
/// (16.D, 16.E/16.F, 16.G, 16.H), walked over one device's ballots as they stream by, with the same
/// sub-sections and messages. Its state is the scheme, the device, H_DI, the chain position, the
/// previous link and the codes frontier, whatever the device's length, which replaces the O(N)
/// <see cref="DeviceChainWalk.Index"/> on the record path (design §6.4): a record's device section
/// <em>is</em> its ordered list, so the completeness checks the domain API needs (every ballot listed
/// once, on its own device) are structural there.
///
/// <see cref="Begin"/> checks the device (kind and mode against the scheme and the manifest; 8.C; 8.F),
/// <see cref="Next"/> each link (8.D/8.E), and <see cref="End"/> the close (no close values under no
/// chaining, a non-empty simple chain, 8.G). Each returns the first failure it finds, or null, and
/// the walk goes on after a failure (the next link is checked against the code the failing one
/// states), so a verifier that collects findings sees every link's; the domain API throws the first.
/// A link the caller cannot read (an item that is not canonical) is <see cref="Skip"/>ped: the next
/// link's chaining field and the close cannot be checked against it, and <see cref="IsComplete"/>
/// turns false.
/// </summary>
internal sealed class DeviceChainWalker
{
    private readonly DeviceChainWalk.Scheme _scheme;
    private readonly ExtendedBaseHash _extendedBaseHash;
    private readonly ChainingMode _manifestMode;
    private VotingDeviceInformationHash? _deviceHash;
    private MerkleFrontier _codes = new();

    public DeviceChainWalker(DeviceChainWalk.Scheme scheme, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);
        _scheme = scheme ?? throw new ArgumentNullException(nameof(scheme));
        _extendedBaseHash = encryptionRecord.ExtendedBaseHash;
        _manifestMode = encryptionRecord.Manifest.ChainingMode;
    }

    /// <summary>The device's S_device, once begun.</summary>
    public string? DeviceId { get; private set; }

    /// <summary>The links walked (skipped ones included): the chain position of the last.</summary>
    public long Count { get; private set; }

    /// <summary>The confirmation code the last link stated, null before the first or after a skipped one.</summary>
    public ConfirmationCode? Previous { get; private set; }

    /// <summary>The string id of the last link, for messages.</summary>
    public string? PreviousBallotId { get; private set; }

    /// <summary>False once a link was skipped: the chain checks after it, and the codes root, are not evaluable.</summary>
    public bool IsComplete { get; private set; } = true;

    /// <summary>codes_root over the confirmation codes walked so far, in chain order (design §4.9); meaningless once a link was skipped.</summary>
    public Sha256Digest CodesRoot => _codes.Root();

    /// <summary>The number of codes in <see cref="CodesRoot"/>.</summary>
    public long CodesCount => _codes.Count;

    /// <summary>The previous code a ballot at the next position chains from (null: H_0, or no chaining).</summary>
    public ConfirmationCode? PreviousForNext => Count == 0 ? null : Previous;

    /// <summary>
    /// Starts the walk of the device <paramref name="deviceId"/> that records H_DI
    /// <paramref name="deviceInformationHash"/>, <paramref name="ballotKind"/> ballots, chaining mode
    /// <paramref name="chainingMode"/> and H_0 <paramref name="initialHash"/>: structure (the scheme's
    /// kind, the manifest's mode, no H_0 under no chaining), then 8.C (16.D) and 8.F (16.G).
    /// </summary>
    public VerificationFailedException? Begin(string deviceId, VotingDeviceInformationHash deviceInformationHash, DeviceChainBallotKind ballotKind, ChainingMode chainingMode, ConfirmationCode? initialHash)
    {
        if (DeviceId is not null)
        {
            throw new InvalidOperationException("The walk has already begun.");
        }

        if (deviceId is null)
        {
            return Structure("a device record has no device id.");
        }

        DeviceId = deviceId;

        // The device hash is computed whatever the checks find, so that the walk can go on.
        var deviceHash = _scheme.DeviceHash(_extendedBaseHash, deviceId);
        _deviceHash = deviceHash;
        if (ballotKind != _scheme.BallotKind)
        {
            return Structure($"the record of device {deviceId} lists {ballotKind} ballots; Verification {_scheme.Verification} checks {_scheme.BallotKind} ones.");
        }

        if (chainingMode != _manifestMode)
        {
            return Structure($"device {deviceId} records chaining mode {chainingMode}; the manifest specifies {_manifestMode}.");
        }

        if (_manifestMode == ChainingMode.None && initialHash is not null)
        {
            return Structure($"device {deviceId} uses no chaining but records an initialization or closing value; the no-chaining mode has none (eq. 73).");
        }

        // 8.C (16.D): the device information hash, computed from S_device.
        if (deviceHash != deviceInformationHash)
        {
            return new VerificationFailedException(_scheme.DeviceHashSubSection, $"The device information hash recorded for device {deviceId} is not H(H_E; {(_scheme.BallotKind == DeviceChainBallotKind.PreEncrypted ? "0x43" : "0x2A")}, S_device).");
        }

        // 8.F (16.G): the initialization code H_0, once per device.
        if (_manifestMode != ChainingMode.None && initialHash != _scheme.InitialHash(deviceHash, _extendedBaseHash))
        {
            return new VerificationFailedException(_scheme.InitialHashSubSection, $"The initial hash code H_0 recorded for device {deviceId} is not H(H_E; {(_scheme.BallotKind == DeviceChainBallotKind.PreEncrypted ? "0x42" : "0x29")}, B_C,0) with B_C,0 = 0x00000001 || H_DI.");
        }

        return null;
    }

    /// <summary>
    /// The next link: 8.D (no chaining: B_C = 0x00000000 || H_DI) or 8.E (simple chaining: B_C,j =
    /// 0x00000001 || H_{j-1}, with H_0 for the first), or 16.E/16.F. The link's code is taken as stated
    /// (8.B/16.C, run per ballot, recompute it).
    /// </summary>
    public VerificationFailedException? Next(string ballotId, ConfirmationCode confirmationCode, ChainingField chainingField)
    {
        var deviceHash = RequireBegun();
        VerificationFailedException? failure = null;
        bool checkable = _manifestMode == ChainingMode.None || Count == 0 || Previous is not null;
        if (checkable)
        {
            var expected = _scheme.ChainingField(_manifestMode, deviceHash, _extendedBaseHash, Count == 0 ? null : Previous);
            if (chainingField != expected)
            {
                failure = _manifestMode == ChainingMode.None
                    ? new VerificationFailedException(_scheme.NoChainingSubSection, $"Ballot {ballotId} on device {DeviceId} does not carry the no-chaining field B_C = 0x00000000 || H_DI of its device.")
                    : new VerificationFailedException(_scheme.SimpleChainingSubSection, $"Ballot {ballotId}, ballot {Count + 1} on device {DeviceId}, does not carry B_C,{Count + 1} = 0x00000001 || H_{Count} ({(Count == 0 ? "the initial hash code H_0" : $"the confirmation code of ballot {PreviousBallotId}")}).");
            }
        }

        Count++;
        Previous = confirmationCode;
        PreviousBallotId = ballotId;
        _codes.Append(RecordDigests.ConfirmationCodeLeafBytes(confirmationCode));
        return failure;
    }

    /// <summary>A link whose item could not be read: counted, unchecked, and the next link's chaining and the close become unknown.</summary>
    public void Skip()
    {
        RequireBegun();
        Count++;
        Previous = null;
        PreviousBallotId = null;
        IsComplete = false;
    }

    /// <summary>
    /// The close: structure (no close values under no chaining; a simple chain is not empty, Q25),
    /// then 8.G (16.H): B-bar_C over the last code H_ℓ, and H-bar over B-bar_C. Null when nothing
    /// fails, or when a skipped last link leaves 8.G unknowable.
    /// </summary>
    public VerificationFailedException? End(ChainingField? closingChainingField, ConfirmationCode? closingHash)
    {
        var deviceHash = RequireBegun();
        if (_manifestMode == ChainingMode.None)
        {
            return closingChainingField is not null || closingHash is not null
                ? Structure($"device {DeviceId} uses no chaining but records an initialization or closing value; the no-chaining mode has none (eq. 73).")
                : null;
        }

        if (Count == 0)
        {
            return Structure($"device {DeviceId} has an empty chain; eq. (78) closes a chain over its final confirmation code, which an empty one does not have.");
        }

        if (Previous is not { } last)
        {
            return null;
        }

        var closing = _scheme.Closing(deviceHash, _extendedBaseHash, last);
        if (closingChainingField != closing)
        {
            return new VerificationFailedException(_scheme.ClosingSubSection, $"The final input byte array recorded for device {DeviceId} is not 0x00000001 || H(H_E; {(_scheme.BallotKind == DeviceChainBallotKind.PreEncrypted ? "0x44" : "0x2B")}, H_ℓ, B_C,0) over its last listed ballot {PreviousBallotId}.");
        }

        if (closingHash != _scheme.ClosingHash(closing, _extendedBaseHash))
        {
            return new VerificationFailedException(_scheme.ClosingSubSection, $"The closing hash recorded for device {DeviceId} is not H(H_E; {(_scheme.BallotKind == DeviceChainBallotKind.PreEncrypted ? "0x42" : "0x29")}, B_C) over its final input byte array.");
        }

        return null;
    }

    /// <summary>The walk's state, for a verifier checkpoint (design §6.8).</summary>
    public State Export() => new(DeviceId, Count, Previous is { } previous ? (byte[])previous : null, PreviousBallotId, IsComplete, _codes.Serialize());

    /// <summary>Restores a state <see cref="Export"/> gave, on a walker of the same scheme and election that has not begun.</summary>
    public void Import(State state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (DeviceId is not null)
        {
            throw new InvalidOperationException("The walk has already begun.");
        }

        DeviceId = state.DeviceId;
        _deviceHash = state.DeviceId is null ? null : _scheme.DeviceHash(_extendedBaseHash, state.DeviceId);
        Count = state.Count;
        Previous = state.Previous is null ? null : ConfirmationCode.FromCanonicalBytes(state.Previous);
        PreviousBallotId = state.PreviousBallotId;
        IsComplete = state.IsComplete;
        _codes = MerkleFrontier.Deserialize(state.Codes);
    }

    /// <summary>A walker's state (<see cref="Export"/>).</summary>
    public sealed record State(string? DeviceId, long Count, byte[]? Previous, string? PreviousBallotId, bool IsComplete, byte[] Codes);

    private VotingDeviceInformationHash RequireBegun() =>
        _deviceHash ?? throw new InvalidOperationException("The walk has not begun on a device with an id.");

    private VerificationFailedException Structure(string message) =>
        new($"{_scheme.Verification}.{BallotStructure.SubSectionSuffix}", $"Device chain verification failed: {message}");
}
