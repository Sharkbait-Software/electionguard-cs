using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.Models;

public class SelectionEncryptionIdentifierHash : HashValue
{
    public SelectionEncryptionIdentifierHash(byte[] bytes)
    {
        Bytes = bytes;
    }

    public SelectionEncryptionIdentifierHash(ExtendedBaseHash extendedBaseHash, SelectionEncryptionIdentifier identifier)
    {
        Bytes = EGHash.Hash(extendedBaseHash,
            [0x20],
            identifier);
    }

    /// <summary>
    /// Strict decoding of H_I read from a ballot: exactly 32 bytes. Throws
    /// <see cref="Serialization.NonCanonicalEncodingException"/> otherwise; a field missing from a
    /// document arrives here as null.
    /// </summary>
    public static SelectionEncryptionIdentifierHash FromCanonicalBytes(byte[]? bytes)
    {
        if (bytes is not { Length: EGHash.HashBytes })
        {
            throw new Serialization.NonCanonicalEncodingException($"A selection encryption identifier hash H_I is {EGHash.HashBytes} bytes; got {bytes?.Length ?? 0}.");
        }

        return new SelectionEncryptionIdentifierHash(bytes.ToArray());
    }

    protected override byte[] Bytes { get; }
}