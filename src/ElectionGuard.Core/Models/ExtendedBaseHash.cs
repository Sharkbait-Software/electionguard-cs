using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.Models;

public class ExtendedBaseHash : HashValue
{
    public ExtendedBaseHash(ElectionBaseHash electionBaseHash, ElectionPublicKeys electionPublicKeys)
    {
        Bytes = EGHash.Hash(electionBaseHash,
            [0x14],
            electionPublicKeys.VoteEncryptionKey,
            electionPublicKeys.OtherBallotDataEncryptionKey);
    }


    /// <summary>
    /// Strict decoding of an extended base hash H_E read from a record: exactly 32 bytes, kept as read (never
    /// recomputed, so the verification that checks it still has something to check). Throws
    /// <see cref="Serialization.NonCanonicalEncodingException"/> otherwise; a field missing from a
    /// document arrives here as null.
    /// </summary>
    public static ExtendedBaseHash FromCanonicalBytes(byte[]? bytes)
    {
        if (bytes is not { Length: EGHash.HashBytes })
        {
            throw new Serialization.NonCanonicalEncodingException($"An extended base hash H_E is {EGHash.HashBytes} bytes; got {bytes?.Length ?? 0}.");
        }

        return new ExtendedBaseHash(bytes.ToArray(), fromBytes: true);
    }

    private ExtendedBaseHash(byte[] bytes, bool fromBytes)
    {
        Bytes = bytes;
    }

    protected override byte[] Bytes { get; }
}
