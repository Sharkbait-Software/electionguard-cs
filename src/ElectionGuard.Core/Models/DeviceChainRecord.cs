namespace ElectionGuard.Core.Models;

/// <summary>
/// The election record's ordered list of the ballots one device encrypted (§3.7, "Ordered lists of
/// the ballots encrypted by each device"), with the values of its confirmation code chain that
/// Verification 8.C/8.F/8.G (16.D/16.G/16.H for pre-encrypted ballots) check once per device. It is
/// produced by <see cref="BallotEncryption.DeviceChain.Close"/> and checked by
/// <see cref="Verify.Ballot.ConfirmationCodeVerification.VerifyDevice(DeviceChainRecord, IEnumerable{BallotEncryption.EncryptedBallot}, EncryptionRecord)"/>
/// (or <see cref="Verify.PreEncryption.PreEncryptedConfirmationCodeVerification.VerifyDevice"/>).
///
/// The ballots are referenced by confirmation code: it is the value the chain links (eq. 76), the
/// one voters hold, and it is bound to the ballot's contents and id_B, where the string ballot id is
/// bound to nothing.
///
/// Under no chaining (eq. 73) the list still records the order the device processed the ballots in,
/// but nothing in the ballots attests to it, and there is no initialization code or chain close:
/// <see cref="InitialHash"/>, <see cref="ClosingChainingField"/> and <see cref="ClosingHash"/> are
/// null. Under simple chaining all three are set; the chain must hold at least one ballot, since
/// eq. (78) closes with "the final confirmation code in the chain" and the spec defines none for an
/// empty one.
/// </summary>
public record DeviceChainRecord
{
    /// <summary>S_device, the string the device information hash is computed from (eqs. 72, 119).</summary>
    public required string DeviceId { get; init; }

    /// <summary>H_DI = H(H_E; 0x2A, S_device) (eq. 72), or 0x43 for a pre-encrypting device (eq. 119).</summary>
    public required VotingDeviceInformationHash DeviceInformationHash { get; init; }

    /// <summary>Whether the chain holds regular ballots (Verification 8) or pre-encrypted ones (16).</summary>
    public required DeviceChainBallotKind BallotKind { get; init; }

    /// <summary>The chaining mode the device used; it must be the manifest's.</summary>
    public required ChainingMode ChainingMode { get; init; }

    /// <summary>The confirmation codes H_1, ..., H_ℓ of the device's ballots, in the order processed.</summary>
    public required List<ConfirmationCode> ConfirmationCodes { get; init; }

    /// <summary>Simple chaining: H_0 = H(H_E; 0x29, B_C,0) (eq. 74; 0x42 by eq. 117). Null otherwise.</summary>
    public ConfirmationCode? InitialHash { get; init; }

    /// <summary>
    /// Simple chaining: the final input byte array B-bar_C = 0x00000001 || H(H_E; 0x2B, H_ℓ, B_C,0)
    /// (eq. 78; 0x44 by eq. 120). Null otherwise.
    /// </summary>
    public ChainingField? ClosingChainingField { get; init; }

    /// <summary>Simple chaining: the closing hash H-bar = H(H_E; 0x29, B-bar_C) (eq. 77; 0x42 by eq. 118). Null otherwise.</summary>
    public ConfirmationCode? ClosingHash { get; init; }
}

/// <summary>The kind of ballot a device chain holds, which selects the domain separators of §3.4.4 or §4.1.4.</summary>
public enum DeviceChainBallotKind
{
    /// <summary>Regular ElectionGuard ballots (§3.4.4; Verification 8).</summary>
    Encrypted = 0,

    /// <summary>Pre-encrypted ballots, chained on the device that generates them (§4.1.4; Verification 16).</summary>
    PreEncrypted = 1,
}

/// <summary>
/// What a device chain check needs to know of one ballot: its id (for messages), the device it names,
/// its confirmation code and the chaining field it was hashed with. Lets a streaming caller check a
/// device's chain without keeping the ballots themselves. The confirmation code is trusted to be the
/// one Verification 8.B (16.C) recomputed from the ballot.
/// </summary>
public readonly record struct DeviceChainLink(string BallotId, string DeviceId, ConfirmationCode ConfirmationCode, ChainingField ChainingField)
{
    public static DeviceChainLink From(BallotEncryption.EncryptedBallot ballot)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        return new DeviceChainLink(ballot.Id, ballot.DeviceId, ballot.ConfirmationCode, ballot.ChainingField);
    }

    public static DeviceChainLink From(PreEncryption.PreEncryptedBallot ballot)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        return new DeviceChainLink(ballot.Id, ballot.DeviceId, ballot.ConfirmationCode, ballot.ChainingField);
    }
}
