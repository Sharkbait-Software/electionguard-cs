using System.Numerics;
using System.Security.Cryptography;

namespace ElectionGuard.Core;

public class ElectionGuardCryptoFactory
{
    public ElectionGuardCryptoFactory(CryptographicParameters cryptographicParameters)
    {
        Q = new IntegerModQ(cryptographicParameters.Q, cryptographicParameters.Q);
        P = new IntegerModP(cryptographicParameters.P, cryptographicParameters.P);
        R = new IntegerModP(cryptographicParameters.R, cryptographicParameters.P);
        G = new IntegerModP(cryptographicParameters.G, cryptographicParameters.P);
    }

    public IntegerModQ Q { get; }
    public IntegerModP P { get; }
    public IntegerModP R { get; }
    public IntegerModP G { get; }

    public KeyPair GenerateKeyPair()
    {
        IntegerModQ secretKey = GetRandomIntegerModQ();

        // Public key is g^secretKey mod p
        IntegerModP publicKey = IntegerModP.PowModP(G, secretKey);

        return new KeyPair(secretKey, publicKey);
    }

    public IntegerModQ GetRandomIntegerModQ()
    {
        // Naive implementation for now. Generate a random bigint with the correct number of bytes, 
        // and return it if it is within our requested bounds.
        // A better implementation would probably carry over insignificant 0 bits at least.
        while (true)
        {
            var randomBytes = RandomNumberGenerator.GetBytes(Q.ToBigInteger().GetByteCount(true));
            var b = new BigInteger(randomBytes, true, true);
            if (b < Q)
            {
                return new IntegerModQ(b, Q);
            }
        }
    }
}
