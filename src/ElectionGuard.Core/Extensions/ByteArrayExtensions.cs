using System.Numerics;

namespace ElectionGuard.Core.Extensions;

public static class ByteArrayExtensions
{
    public static byte[] XOR(this byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            throw new IndexOutOfRangeException("Byte arrays are not the same length.");
        }

        var result = new byte[a.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);

        for (int i = 0; i < result.Length; i++)
        {
            result[i] ^= b[i];
        }

        return result;
    }

    public static BigInteger AsBigInteger(this byte[] bytes)
    {
        return new BigInteger(bytes, true, true);
    }

    public static byte[] Concat(params byte[][] bytes)
    {
        byte[] result = new byte[bytes.Sum(b => b.Length)];
        int resultOffset = 0;

        for (int i = 0; i < bytes.Length; ++i)
        {
            Buffer.BlockCopy(bytes[i], 0, result, resultOffset, bytes[i].Length);
            resultOffset += bytes[i].Length;
        }
        return result;
    }

    public static byte[] PadToLength(this byte[] bytes, int length)
    {
        if (bytes.Length > length)
        {
            throw new Exception("Asked to pad an array to a length less than array.");
        }

        byte[] result = new byte[length];
        Buffer.BlockCopy(bytes, 0, result, length - bytes.Length, bytes.Length);
        return result;
    }
}
