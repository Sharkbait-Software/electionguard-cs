using System.Numerics;
using System.Security.Cryptography;

namespace ElectionGuard.Core;

public static class EGHash
{
    // §5.2
    public static byte[] Hash(byte[] key, params byte[][] bytes)
    {
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        if (bytes == null)
        {
            throw new ArgumentNullException(nameof(bytes));
        }

        if (key.Length == 0)
        {
            throw new ArgumentException("No value for key.", nameof(key));
        }

        if (bytes.Length == 0)
        {
            throw new ArgumentException("No values to be hashed.", nameof(bytes));
        }

        // According to the spec, the first input will always have length 32
        if (key.Length != 32)
        {
            throw new ArgumentException("First value should always have a length of 32.", nameof(key));
        }

        return HMACSHA256.HashData(key, ByteArrayExtensions.Concat(bytes));
    }

    public static IntegerModQ HashModQ(byte[] key, params byte[][] bytes)
    {
        byte[] b = Hash(key, bytes);
        return new IntegerModQ(b);
    }
}
