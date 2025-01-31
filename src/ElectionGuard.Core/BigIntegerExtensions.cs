using System.Buffers.Binary;
using System.Numerics;

namespace ElectionGuard.Core;

public static class BigIntegerExtensions
{
    // Technically, the % operator is a remainder, not a modulo.
    // Therefore, it doesn't handle negative numbers correctly. This does.
    public static BigInteger Mod(this BigInteger a, BigInteger b)
    {
        BigInteger r = a % b;
        return r < 0 ? r + b : r;
    }
}

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


}

public static class IntExtensions
{
    public static byte[] ToByteArray(this int i)
    {
        byte[] bytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, i);
        return bytes;
    }
}