using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

/// <summary>
/// §4.2.1 Deterministic Nonce Derivation. The nonce used within contest i, selection vector j, to
/// form the k-th encryption of a pre-encrypted ballot.
/// </summary>
public struct PreEncryptionNonce
{
    /// <param name="contestIndex">i, the contest's index in the manifest.</param>
    /// <param name="selectionIndex">j, the option index of the selection vector (null vectors extend the option indices).</param>
    /// <param name="positionIndex">k, the option index of the encryption's position within the vector.</param>
    public PreEncryptionNonce(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce, int contestIndex, int selectionIndex, int positionIndex)
    {
        // Formula (121): xi_{i,j,k} = Hq(HI; 0x45, i, j, k, xi_B).
        _value = EGHash.HashModQ(selectionEncryptionIdentifierHash,
            [0x45],
            contestIndex.ToByteArray(),
            selectionIndex.ToByteArray(),
            positionIndex.ToByteArray(),
            ballotNonce);
    }

    private readonly IntegerModQ _value;

    public static implicit operator IntegerModQ(PreEncryptionNonce nonce)
    {
        return nonce._value;
    }
}
