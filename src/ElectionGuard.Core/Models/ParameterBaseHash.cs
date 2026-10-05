using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

public class ParameterBaseHash : HashValue
{
    public ParameterBaseHash(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters)
    {
        // §3.1.2 eq. (4): H_P = H(ver; 0x00, b(p, 512), b(q, 32), b(g, 512), b(n, 4), b(k, 4)), 1065
        // bytes hashed (§5.5.1). p and q are encoded as themselves, so they go through the plain
        // big-endian encoder, never IntegerModP/IntegerModQ, which would reduce them to zero.
        Bytes = EGHash.Hash(cryptographicParameters.Version,
            [0x00],
            cryptographicParameters.P.ToBigEndianPadded(IntegerModP.ByteLength),
            cryptographicParameters.Q.ToBigEndianPadded(IntegerModQ.ByteLength),
            cryptographicParameters.G.ToBigEndianPadded(IntegerModP.ByteLength),
            guardianParameters.N.ToByteArray(),
            guardianParameters.K.ToByteArray());
    }

    protected override byte[] Bytes { get; }
}
