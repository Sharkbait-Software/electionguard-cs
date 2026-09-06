using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.KeyGeneration;

public class KeyPairTests
{
    public KeyPairTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    [Fact]
    public void GenerateRandom_PublicKeyEqualsGeneratorRaisedToSecretKey()
    {
        var keyPair = KeyPair.GenerateRandom();

        var expected = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, keyPair.SecretKey);

        Assert.Equal(expected, keyPair.PublicKey);
    }

    [Fact]
    public void GenerateRandom_ProducesDistinctKeyPairsAcrossCalls()
    {
        var keyPair1 = KeyPair.GenerateRandom();
        var keyPair2 = KeyPair.GenerateRandom();

        Assert.NotEqual(keyPair1.SecretKey, keyPair2.SecretKey);
        Assert.NotEqual(keyPair1.PublicKey, keyPair2.PublicKey);
    }
}
