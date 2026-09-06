using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Text;

namespace ElectionGuard.Core.UnitTests.Models;

public class VotingDeviceInformationHashTests
{
    public VotingDeviceInformationHashTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static ExtendedBaseHash CreateExtendedBaseHash()
    {
        var manifestFile = new ManifestFile { Bytes = new byte[] { 0x01, 0x02 } };
        var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var electionPublicKeys = new ElectionPublicKeys(
            new[] { new IntegerModP(3) },
            new[] { new IntegerModP(5) });
        return new ExtendedBaseHash(electionBaseHash, electionPublicKeys);
    }

    [Fact]
    public void Constructor_SameDeviceId_ProducesSameHash()
    {
        var extendedBaseHash = CreateExtendedBaseHash();

        var hash1 = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");
        var hash2 = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");

        Assert.Equal((byte[])hash1, (byte[])hash2);
    }

    [Fact]
    public void Constructor_DifferentDeviceId_ProducesDifferentHash()
    {
        var extendedBaseHash = CreateExtendedBaseHash();

        var hash1 = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");
        var hash2 = new VotingDeviceInformationHash(extendedBaseHash, "Device 2");

        Assert.NotEqual((byte[])hash1, (byte[])hash2);
    }

    [Fact]
    public void Constructor_HandComputed_MatchesDirectEGHashCall()
    {
        var extendedBaseHash = CreateExtendedBaseHash();
        var deviceId = "Device 1";
        var deviceIdBytes = Encoding.UTF8.GetBytes(deviceId);

        var hash = new VotingDeviceInformationHash(extendedBaseHash, deviceId);
        var expected = EGHash.Hash(extendedBaseHash, deviceIdBytes.Length.ToByteArray(), deviceIdBytes);

        Assert.Equal(expected, (byte[])hash);
    }

    [Fact]
    public void EqualityOperator_ReturnsTrue_ForEqualHashes()
    {
        var extendedBaseHash = CreateExtendedBaseHash();

        var hash1 = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");
        var hash2 = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");

        Assert.True(hash1 == hash2);
        Assert.False(hash1 != hash2);
    }

    [Fact]
    public void EqualityOperator_ReturnsFalse_ForDifferentHashes()
    {
        var extendedBaseHash = CreateExtendedBaseHash();

        var hash1 = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");
        var hash2 = new VotingDeviceInformationHash(extendedBaseHash, "Device 2");

        Assert.False(hash1 == hash2);
        Assert.True(hash1 != hash2);
    }

    [Fact]
    public void GetHashCode_IsConsistentWithEquals()
    {
        var extendedBaseHash = CreateExtendedBaseHash();

        var hash1 = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");
        var hash2 = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");

        Assert.Equal(hash1, hash2);

        // VotingDeviceInformationHash.GetHashCode() now hashes the byte[] content (each byte folded
        // via System.HashCode) instead of the array's reference identity, so content-equal instances
        // built from independent byte[] instances correctly produce equal hash codes, honoring the
        // usual Equals/GetHashCode contract.
        Assert.Equal(hash1.GetHashCode(), hash2.GetHashCode());
    }
}
