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

    protected override byte[] Bytes { get; }
}
