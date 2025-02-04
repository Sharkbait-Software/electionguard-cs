using ElectionGuard.Core.Crypto;

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
}
