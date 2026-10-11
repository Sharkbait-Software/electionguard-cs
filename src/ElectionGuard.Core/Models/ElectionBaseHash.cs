using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

public class ElectionBaseHash : HashValue
{
    public ElectionBaseHash(ParameterBaseHash parameterBaseHash, ManifestFile manifestFile)
    {
        Bytes = Compute(parameterBaseHash, manifestFile.Bytes);
    }

    /// <summary>
    /// §3.1.4 eq. (5): H_B = H(H_P; 0x01, manifest). The manifest is a file input, so per §5.1.5 it
    /// is hashed as b(len(manifest), 4) || manifest, 5 + len(manifest) bytes (§5.5.1). Shared with
    /// Verification 1.F so the two cannot drift apart.
    /// </summary>
    public static byte[] Compute(byte[] parameterBaseHash, byte[] manifestBytes)
    {
        return EGHash.Hash(parameterBaseHash,
            [0x01],
            manifestBytes.Length.ToByteArray(),
            manifestBytes);
    }


    /// <summary>
    /// Strict decoding of an election base hash H_B read from a record: exactly 32 bytes, kept as read (never
    /// recomputed, so the verification that checks it still has something to check). Throws
    /// <see cref="Serialization.NonCanonicalEncodingException"/> otherwise; a field missing from a
    /// document arrives here as null.
    /// </summary>
    public static ElectionBaseHash FromCanonicalBytes(byte[]? bytes)
    {
        if (bytes is not { Length: EGHash.HashBytes })
        {
            throw new Serialization.NonCanonicalEncodingException($"An election base hash H_B is {EGHash.HashBytes} bytes; got {bytes?.Length ?? 0}.");
        }

        return new ElectionBaseHash(bytes.ToArray(), fromBytes: true);
    }

    private ElectionBaseHash(byte[] bytes, bool fromBytes)
    {
        Bytes = bytes;
    }

    protected override byte[] Bytes { get; }
}
