using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.Models;

public struct ConfirmationCode
{
    public ConfirmationCode(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, IEnumerable<ContestHash> contestHashes, ChainingField? chainingField)
    {
        List<byte[]> bytesToHash = [[0x29]];
        foreach(var contestHash in contestHashes)
        {
            bytesToHash.Add(contestHash);
        }

        _value = EGHash.Hash(selectionEncryptionIdentifierHash, bytesToHash.ToArray());
    }

    private readonly byte[] _value;

    public static implicit operator byte[](ConfirmationCode i)
    {
        return i._value;
    }
}
