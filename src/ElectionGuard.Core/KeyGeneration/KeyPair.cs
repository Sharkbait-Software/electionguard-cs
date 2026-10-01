using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.KeyGeneration;

public class KeyPair
{
    public KeyPair(IntegerModQ secretKey, IntegerModP publicKey)
    {
        SecretKey = secretKey;
        PublicKey = publicKey;
    }

    public IntegerModQ SecretKey { get; }
    public IntegerModP PublicKey { get; }

    public static KeyPair GenerateRandom()
    {
        IntegerModQ secretKey = ElectionGuardRandom.GetIntegerModQ();

        // Public key is g^secretKey mod p.
        // This is one of the fixed-base exponentiations Note 3.5 describes: the base is always g.
        // It sits squarely in the ballot encryption hot path, since every commitment in a range
        // proof is generated here, so it takes the Montgomery path. With no precomputed table
        // registered that path is still about twice as fast as BigInteger.ModPow, so this is never
        // a regression for callers that have not opted in.
        IntegerModP publicKey = MontgomeryModP.PowModP(EGParameters.G, secretKey);

        return new KeyPair(secretKey, publicKey);
    }
}
