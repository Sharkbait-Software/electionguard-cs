using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.Models;

public class ElectionBaseHashTests
{
    public ElectionBaseHashTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static ManifestFile CreateManifestFile(byte marker = 0x01)
    {
        return new ManifestFile { Bytes = new byte[] { marker, 0x02, 0x03 } };
    }

    [Fact]
    public void Constructor_SameInputs_ProducesSameHash()
    {
        var manifestFile = CreateManifestFile();

        var hash1 = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var hash2 = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);

        Assert.Equal((byte[])hash1, (byte[])hash2);
    }

    [Fact]
    public void Constructor_DifferentManifestBytes_ProducesDifferentHash()
    {
        var manifestFile1 = CreateManifestFile(0x01);
        var manifestFile2 = CreateManifestFile(0x99);

        var hash1 = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile1);
        var hash2 = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile2);

        Assert.NotEqual((byte[])hash1, (byte[])hash2);
    }

    [Fact]
    public void Constructor_HandComputed_MatchesDirectEGHashCall()
    {
        var manifestFile = CreateManifestFile();

        var hash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var expected = EGHash.Hash(EGParameters.ParameterBaseHash, new byte[] { 0x01 }, manifestFile.Bytes);

        Assert.Equal(expected, (byte[])hash);
    }
}
