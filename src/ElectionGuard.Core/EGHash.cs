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

        int bytesLength = bytes.Sum(b => b.Length);
        byte[] concatBytes = new byte[bytesLength];

        int destinationOffset = 0;
        foreach (byte[] b in bytes)
        {
            Buffer.BlockCopy(b, 0, concatBytes, destinationOffset, b.Length);
            destinationOffset += b.Length;
        }

        return HMACSHA256.HashData(key, concatBytes);
    }

    public static BigInteger HashMod(byte[] key, BigInteger mod, params byte[][] bytes)
    {
        byte[] b = Hash(key, bytes);
        BigInteger bi = new BigInteger(b, true, true);
        return bi.Mod(mod);
    }
}
