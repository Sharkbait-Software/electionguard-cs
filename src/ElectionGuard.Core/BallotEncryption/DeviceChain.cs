using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;

namespace ElectionGuard.Core.BallotEncryption;

/// <summary>
/// The confirmation code chain of one device (§3.4.4; §4.1.4 for a device generating pre-encrypted
/// ballots): the order it processed its ballots in, the confirmation code the next ballot chains
/// from, and the chain close "at the end of an election" (eqs. 77/78, 118/120), which produces the
/// device's <see cref="DeviceChainRecord"/> for the election record (§3.7).
///
/// Encrypt each ballot with <see cref="PreviousConfirmationCode"/> (or through
/// <see cref="BallotEncryptor.EncryptNext(Ballot, DeviceChain)"/>), then <see cref="Append(EncryptedBallot)"/>
/// it, cast or challenged: every ballot the device produced is in its chain. Under simple chaining
/// each ballot depends on the one before it, so a device encrypts one ballot at a time. Under no
/// chaining the order recorded is the order of the <see cref="Append(EncryptedBallot)"/> calls.
/// Appending is serialized by a lock; the order of concurrent appends is whatever order they take it in.
/// </summary>
public sealed class DeviceChain
{
    private readonly object _lock = new();
    private readonly EncryptionRecord _encryptionRecord;
    private readonly List<ConfirmationCode> _confirmationCodes = [];
    private ConfirmationCode? _last;
    private bool _closed;

    /// <summary>A chain of regular ballots encrypted on the device <paramref name="deviceId"/> (S_device).</summary>
    public DeviceChain(EncryptionRecord encryptionRecord, string deviceId)
        : this(encryptionRecord, deviceId, DeviceChainBallotKind.Encrypted)
    {
    }

    private DeviceChain(EncryptionRecord encryptionRecord, string deviceId, DeviceChainBallotKind ballotKind)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);
        ArgumentNullException.ThrowIfNull(deviceId);

        _encryptionRecord = encryptionRecord;
        DeviceId = deviceId;
        BallotKind = ballotKind;
        ChainingMode = encryptionRecord.Manifest.ChainingMode;
        DeviceInformationHash = ballotKind == DeviceChainBallotKind.PreEncrypted
            ? VotingDeviceInformationHash.ForPreEncryptedBallots(encryptionRecord.ExtendedBaseHash, deviceId)
            : new VotingDeviceInformationHash(encryptionRecord.ExtendedBaseHash, deviceId);
    }

    /// <summary>A chain of pre-encrypted ballots generated on the device <paramref name="deviceId"/> (§4.1.4).</summary>
    public static DeviceChain ForPreEncryptedBallots(EncryptionRecord encryptionRecord, string deviceId)
    {
        return new DeviceChain(encryptionRecord, deviceId, DeviceChainBallotKind.PreEncrypted);
    }

    public string DeviceId { get; }

    public DeviceChainBallotKind BallotKind { get; }

    /// <summary>The manifest's chaining mode, which every ballot on the device uses.</summary>
    public ChainingMode ChainingMode { get; }

    /// <summary>H_DI of the device: eq. (72), or eq. (119) for pre-encrypted ballots.</summary>
    public VotingDeviceInformationHash DeviceInformationHash { get; }

    /// <summary>
    /// What the next ballot passes to the encryptor as its previous confirmation code: under simple
    /// chaining the last appended ballot's H_C, or null before the first (the encryptor then chains
    /// from H_0); under no chaining always null.
    /// </summary>
    public ConfirmationCode? PreviousConfirmationCode
    {
        get
        {
            lock (_lock)
            {
                return ChainingMode == ChainingMode.None ? null : _last;
            }
        }
    }

    /// <summary>The number of ballots appended so far.</summary>
    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _confirmationCodes.Count;
            }
        }
    }

    /// <summary>
    /// Records <paramref name="ballot"/> as the device's next ballot. Throws
    /// <see cref="ArgumentException"/> if it names another device, or if its chaining field is not
    /// the one its place in this chain implies (eq. 73 or 76): then it was encrypted against another
    /// previous code, and appending it would publish a chain that fails Verification 8.D/8.E.
    /// </summary>
    public void Append(EncryptedBallot ballot)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        RequireKind(DeviceChainBallotKind.Encrypted);
        Append(DeviceChainLink.From(ballot), (mode, previous) =>
            new ChainingField(mode, DeviceInformationHash, _encryptionRecord.ExtendedBaseHash, previous));
    }

    /// <summary>Records a pre-encrypted <paramref name="ballot"/> as the device's next one (eqs. 73, 76 as used by §4.1.4).</summary>
    public void Append(PreEncryptedBallot ballot)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        RequireKind(DeviceChainBallotKind.PreEncrypted);
        Append(DeviceChainLink.From(ballot), (mode, previous) =>
            ChainingField.ForPreEncryptedBallots(mode, DeviceInformationHash, _encryptionRecord.ExtendedBaseHash, previous));
    }

    private void Append(DeviceChainLink link, Func<ChainingMode, ConfirmationCode?, ChainingField> expectedField)
    {
        if (!string.Equals(link.DeviceId, DeviceId, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Ballot {link.BallotId} was encrypted on device {link.DeviceId}, not on {DeviceId}.", "ballot");
        }

        lock (_lock)
        {
            if (_closed)
            {
                throw new InvalidOperationException($"The chain of device {DeviceId} is closed; no ballot can be added to it.");
            }

            var expected = expectedField(ChainingMode, ChainingMode == ChainingMode.None ? null : _last);
            if (link.ChainingField != expected)
            {
                throw new ArgumentException(
                    $"Ballot {link.BallotId} carries chaining field {link.ChainingField}, but as ballot {_confirmationCodes.Count + 1} on device {DeviceId} it must carry {expected} (§3.4.4 eq. {(ChainingMode == ChainingMode.None ? "73" : "76")}).",
                    "ballot");
            }

            _confirmationCodes.Add(link.ConfirmationCode);
            _last = link.ConfirmationCode;
        }
    }

    /// <summary>
    /// Closes the chain "at the end of an election" and returns the device's record. Under simple
    /// chaining it carries H_0 (eq. 74 or 117), the final input byte array B-bar_C (eq. 78 or 120)
    /// and the closing hash H-bar (eq. 77 or 118); a chain with no ballot cannot be closed
    /// (<see cref="InvalidOperationException"/>), since the spec defines no H_ℓ for it. After this,
    /// <see cref="Append(EncryptedBallot)"/> throws. Closing again returns an equal record.
    /// </summary>
    public DeviceChainRecord Close()
    {
        lock (_lock)
        {
            var extendedBaseHash = _encryptionRecord.ExtendedBaseHash;
            ConfirmationCode? initialHash = null;
            ChainingField? closingField = null;
            ConfirmationCode? closingHash = null;
            if (ChainingMode != ChainingMode.None)
            {
                if (_last is not ConfirmationCode last)
                {
                    throw new InvalidOperationException(
                        $"The chain of device {DeviceId} holds no ballot. Eq. (78) closes a chain over its final confirmation code H_ℓ, which an empty chain does not have.");
                }

                bool preEncrypted = BallotKind == DeviceChainBallotKind.PreEncrypted;
                initialHash = preEncrypted
                    ? ChainingField.InitialHashForPreEncryptedBallots(DeviceInformationHash, extendedBaseHash)
                    : ChainingField.InitialHash(DeviceInformationHash, extendedBaseHash);
                var closing = preEncrypted
                    ? ChainingField.ClosingForPreEncryptedBallots(DeviceInformationHash, extendedBaseHash, last)
                    : ChainingField.Closing(DeviceInformationHash, extendedBaseHash, last);
                closingField = closing;
                closingHash = preEncrypted
                    ? ChainingField.ClosingHashForPreEncryptedBallots(closing, extendedBaseHash)
                    : ChainingField.ClosingHash(closing, extendedBaseHash);
            }

            _closed = true;
            return new DeviceChainRecord
            {
                DeviceId = DeviceId,
                DeviceInformationHash = DeviceInformationHash,
                BallotKind = BallotKind,
                ChainingMode = ChainingMode,
                ConfirmationCodes = [.. _confirmationCodes],
                InitialHash = initialHash,
                ClosingChainingField = closingField,
                ClosingHash = closingHash,
            };
        }
    }

    private void RequireKind(DeviceChainBallotKind kind)
    {
        if (BallotKind != kind)
        {
            throw new InvalidOperationException($"The chain of device {DeviceId} holds {BallotKind} ballots, not {kind} ones.");
        }
    }
}
