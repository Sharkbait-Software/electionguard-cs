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

        // Public key is g^secretKey mod p
        IntegerModP publicKey = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, secretKey);

        return new KeyPair(secretKey, publicKey);
    }
}
