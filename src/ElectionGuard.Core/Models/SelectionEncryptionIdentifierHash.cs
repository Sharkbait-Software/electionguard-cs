using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.Models;

public class SelectionEncryptionIdentifierHash : HashValue
{
    public SelectionEncryptionIdentifierHash(ExtendedBaseHash extendedBaseHash, SelectionEncryptionIdentifier identifier)
    {
        Bytes = EGHash.Hash(extendedBaseHash,
            [0x20],
            identifier);
    }

    protected override byte[] Bytes { get; }
}