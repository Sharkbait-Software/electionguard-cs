using ElectionGuard.Core.KeyGeneration;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// A guardian (or the administrator's wrapper, on its behalf) refused to decrypt a ballot's
/// encrypted nonce because the request is not authorized (user decision Q31, S9b): no share was
/// produced and no exponentiation with a secret key share was performed. Distinct from
/// <see cref="ArgumentException"/> (a malformed ballot) and <see cref="TallyDecryptionException"/>
/// (an encrypted nonce whose C_ξB,0 or proof does not check): those are faults of the ballot; this
/// is a request the guardian will not serve, however well formed.
/// </summary>
public class BallotNonceDecryptionRefusedException : Exception
{
    public BallotNonceDecryptionRefusedException(GuardianIndex guardianIndex, string ballotId, BallotNonceDecryptionRefusal reason, string message) : base(message)
    {
        GuardianIndex = guardianIndex;
        BallotId = ballotId;
        Reason = reason;
    }

    /// <summary>The guardian that refused.</summary>
    public GuardianIndex GuardianIndex { get; }

    /// <summary>The string id of the ballot in the request (a claim of the request, like everything in it).</summary>
    public string BallotId { get; }

    public BallotNonceDecryptionRefusal Reason { get; }
}

/// <summary>Why a ballot-nonce decryption request was refused.</summary>
public enum BallotNonceDecryptionRefusal
{
    /// <summary>
    /// The cast-ballot view or the issued list given is for another election (its H_E differs from
    /// the encryption record's), so it cannot vouch for the request.
    /// </summary>
    ForeignElection,

    /// <summary>The request's id_B, H_I or C_ξB,0 matches a cast ballot of the published record.</summary>
    CastBallot,

    /// <summary>Pre-encrypted path: the request's id_B is not on the printer-committed issued list.</summary>
    NotIssued,

    /// <summary>
    /// Pre-encrypted path: the request's id_B is on the issued list, but its C_ξB,0 is not the one
    /// the printer committed for that id_B.
    /// </summary>
    IssuedNonceDiffers,

    /// <summary>Pre-encrypted path: this guardian has already decrypted the nonce of this id_B once.</summary>
    AlreadyDecrypted,

    /// <summary>
    /// Challenged path: the request's id_B is on the issued pre-encrypted ballot list. Such a nonce is
    /// decrypted only through the pre-encrypted path, at most once (S9b-1).
    /// </summary>
    IssuedPreEncryptedBallot,
}
