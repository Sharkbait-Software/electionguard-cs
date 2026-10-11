using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

public struct EncryptionNonce
{
    /// <summary>
    /// §3.3.3 eq. (33): xi_{i,j} = H_q(H_I; 0x21, i, j, xi_B), the nonce of the field with option
    /// index j in the contest with index i. Every verifiable field has its own j, supplemental fields
    /// included (§3.1.3 p.19: they are "treated like and listed with the option selection fields"),
    /// so no two fields of a contest share a nonce. There is deliberately no form without j: one
    /// nonce shared by several fields reveals the ratios of their plaintexts from public data (G3).
    /// </summary>
    public EncryptionNonce(SelectionEncryptionIdentifierHash selectionIdentifierHash, BallotNonce ballotNonce, int contestIndex, int choiceIndex)
    {
        _value = EGHash.HashModQ(selectionIdentifierHash,
            [0x21],
            contestIndex.ToByteArray(),
            choiceIndex.ToByteArray(),
            ballotNonce);
    }

    private readonly IntegerModQ _value;

    public static implicit operator byte[](EncryptionNonce i)
    {
        return i._value;
    }

    public static implicit operator IntegerModQ(EncryptionNonce i)
    {
        return i._value;
    }
}
