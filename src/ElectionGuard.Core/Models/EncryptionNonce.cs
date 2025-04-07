using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

public struct EncryptionNonce
{
    public EncryptionNonce(SelectionEncryptionIdentifierHash selectionIdentifierHash, BallotNonce ballotNonce, int contestIndex, int? choiceIndex = null)
    {
        List<byte[]> bytesToHash = [
            [0x21],
            contestIndex.ToByteArray()];

        // Choice index is null for optional data at the contest level (overvotes, undervotes, null votes, writein count) but populated otherwise.
        if(choiceIndex != null)
        {
            bytesToHash.Add(choiceIndex.Value.ToByteArray());
        }
        bytesToHash.Add(ballotNonce);

        _value = EGHash.HashModQ(selectionIdentifierHash, bytesToHash.ToArray());
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
