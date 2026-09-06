using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.Models;

public class SelectionEncryptionIdentifierHashTests
{
    public SelectionEncryptionIdentifierHashTests()
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
    public void RawByteCtor_RoundTripsBytes()
    {
        var bytes = new byte[] { 0x01, 0x02, 0x03 };

        var hash = new SelectionEncryptionIdentifierHash(bytes);

        Assert.Equal(bytes, (byte[])hash);
    }

    [Fact]
    public void ExtendedHashCtor_SameInputs_ProducesSameHash()
    {
        var extendedBaseHash = CreateExtendedBaseHash();
        var identifier = new SelectionEncryptionIdentifier(new byte[] { 0xAA, 0xBB });

        var hash1 = new SelectionEncryptionIdentifierHash(extendedBaseHash, identifier);
        var hash2 = new SelectionEncryptionIdentifierHash(extendedBaseHash, identifier);

        Assert.Equal((byte[])hash1, (byte[])hash2);
    }

    [Fact]
    public void ExtendedHashCtor_DifferentIdentifier_ProducesDifferentHash()
    {
        var extendedBaseHash = CreateExtendedBaseHash();
        var identifier1 = new SelectionEncryptionIdentifier(new byte[] { 0xAA, 0xBB });
        var identifier2 = new SelectionEncryptionIdentifier(new byte[] { 0xCC, 0xDD });

        var hash1 = new SelectionEncryptionIdentifierHash(extendedBaseHash, identifier1);
        var hash2 = new SelectionEncryptionIdentifierHash(extendedBaseHash, identifier2);

        Assert.NotEqual((byte[])hash1, (byte[])hash2);
    }

    [Fact]
    public void ExtendedHashCtor_HandComputed_MatchesDirectEGHashCall()
    {
        // Note: this is the exact formula SelectionEncryptionIdentifierVerification sub-check 5.B
        // re-derives (cross-consistency, not duplication -- see research.md).
        var extendedBaseHash = CreateExtendedBaseHash();
        var identifier = new SelectionEncryptionIdentifier(new byte[] { 0xAA, 0xBB });

        var hash = new SelectionEncryptionIdentifierHash(extendedBaseHash, identifier);
        var expected = EGHash.Hash(extendedBaseHash, new byte[] { 0x20 }, identifier);

        Assert.Equal(expected, (byte[])hash);
    }
}
