using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Security.Cryptography;

namespace ElectionGuard.Core.UnitTests.Crypto;

public class EGHashTests
{
    public EGHashTests()
    {
        CryptographicParameters cryptographicParameters = new CryptographicParameters();
        GuardianParameters guardianParameters = new GuardianParameters();
        EGParameters.Init(cryptographicParameters, guardianParameters);
    }

    [Fact]
    public void Hash_ThrowsArgumentNullException_WhenKeyIsNull()
    {
        Assert.Throws<ArgumentNullException>(() => EGHash.Hash(null!, new byte[] { 1 }));
    }

    [Fact]
    public void Hash_ThrowsArgumentNullException_WhenBytesIsNull()
    {
        var key = new byte[32];
        Assert.Throws<ArgumentNullException>(() => EGHash.Hash(key, null!));
    }

    [Fact]
    public void Hash_ThrowsArgumentException_WhenKeyIsEmpty()
    {
        var key = Array.Empty<byte>();
        Assert.Throws<ArgumentException>(() => EGHash.Hash(key, new byte[] { 1 }));
    }

    [Fact]
    public void Hash_ThrowsArgumentException_WhenBytesIsEmpty()
    {
        var key = new byte[32];
        Assert.Throws<ArgumentException>(() => EGHash.Hash(key));
    }

    [Fact]
    public void Hash_ThrowsArgumentException_WhenKeyLengthIsNot32()
    {
        var key = new byte[16];
        Assert.Throws<ArgumentException>(() => EGHash.Hash(key, new byte[] { 1 }));
    }

    [Fact]
    public void Hash_ReturnsExpectedHmacSha256()
    {
        // Arrange
        var key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var data1 = new byte[] { 0x01, 0x02, 0x03 };
        var data2 = new byte[] { 0x04, 0x05 };
        var expected = HMACSHA256.HashData(key, data1.Concat(data2).ToArray());

        // Act
        var result = EGHash.Hash(key, data1, data2);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void HashModQ_ReturnsIntegerModQ_WithExpectedBytes()
    {
        // Arrange
        var key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var data = new byte[] { 0xAA, 0xBB, 0xCC };

        // Act
        var hashBytes = EGHash.Hash(key, data);
        var modQ = EGHash.HashModQ(key, data);

        // Assert
        Assert.Equal(new IntegerModQ(hashBytes), modQ);
    }
}
