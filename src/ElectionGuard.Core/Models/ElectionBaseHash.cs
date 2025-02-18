using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.Models;

public class ElectionBaseHash : HashValue
{
    public ElectionBaseHash(ParameterBaseHash parameterBaseHash, ManifestFile manifestFile)
    {
        Bytes = EGHash.Hash(parameterBaseHash,
            [0x01],
            manifestFile.Bytes
            );
    }

    protected override byte[] Bytes { get; }
}
