using ElectionGuard.Core.Extensions;
using System.Numerics;
using System.Security.Cryptography;

namespace ElectionGuard.Core.Crypto;

public static class EGHash
{
    /// <summary>Bytes in every hash this produces (HMAC-SHA-256).</summary>
    internal const int HashBytes = 32;

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

    /// <summary>
    /// §5.2 H(key; message) over a message the caller has already concatenated, for hot paths that
    /// build their input in one (pooled) buffer rather than as an array of freshly allocated arrays.
    /// <see cref="Hash"/> concatenates its inputs and hashes the result, so for the same bytes the
    /// two agree exactly. Writes the 32-byte digest into <paramref name="destination"/>.
    /// </summary>
    internal static void HashConcatenated(byte[] key, ReadOnlySpan<byte> message, Span<byte> destination)
    {
        ValidateKey(key);
        HMACSHA256.HashData(key, message, destination[..HashBytes]);
    }

    /// <summary>
    /// <see cref="HashConcatenated"/> reduced into Z_q, exactly as <see cref="HashModQ"/> reduces
    /// <see cref="Hash"/>'s output, without allocating the digest.
    /// </summary>
    internal static IntegerModQ HashModQConcatenated(byte[] key, ReadOnlySpan<byte> message)
    {
        Span<byte> digest = stackalloc byte[HashBytes];
        HashConcatenated(key, message, digest);
        return new IntegerModQ(new BigInteger(digest, isUnsigned: true, isBigEndian: true));
    }

    /// <summary>The key checks of <see cref="Hash"/>, for the concatenated variants.</summary>
    private static void ValidateKey(byte[] key)
    {
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        if (key.Length == 0)
        {
            throw new ArgumentException("No value for key.", nameof(key));
        }

        // According to the spec, the first input will always have length 32
        if (key.Length != 32)
        {
            throw new ArgumentException("First value should always have a length of 32.", nameof(key));
        }
    }
}
