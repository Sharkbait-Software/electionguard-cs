using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

public struct SelectionNonce
{
    public SelectionNonce(SelectionEncryptionIdentifierHash selectionIdentifierHash, BallotNonce ballotNonce, int contestIndex, int choiceIndex)
    {
        _value = EGHash.HashModQ(selectionIdentifierHash,
            [0x21],
            contestIndex.ToByteArray(),
            choiceIndex.ToByteArray(),
            ballotNonce);
    }

    private readonly IntegerModQ _value;

    public static implicit operator byte[](SelectionNonce i)
    {
        return i._value;
    }

    public static implicit operator IntegerModQ(SelectionNonce i)
    {
        return i._value;
    }
}