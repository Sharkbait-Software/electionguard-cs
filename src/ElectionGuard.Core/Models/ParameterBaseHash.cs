using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

public class ParameterBaseHash : HashValue
{
    public ParameterBaseHash(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters)
    {
        Bytes = EGHash.Hash(cryptographicParameters.Version,
            [0x00],
            cryptographicParameters.P.ToByteArray(),
            cryptographicParameters.Q.ToByteArray(),
            cryptographicParameters.G.ToByteArray(),
            guardianParameters.N.ToByteArray(),
            guardianParameters.K.ToByteArray());
    }

    protected override byte[] Bytes { get; }
}
