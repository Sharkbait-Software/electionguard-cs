using System.Buffers.Binary;
using System.Text;

namespace ElectionGuard.Core.BallotEncryption;

/// <summary>
/// Turns a string into a contest data field D_Λ and back. NOT SPEC: §3.3.10 p.40 requires only that
/// D_Λ be exactly 32·b_Λ bytes, filled "unambiguously" by the calling device, so that no padding can
/// be confused with data. This is the library's encoding (user decision Q7):
/// D = b(len, 4) ‖ UTF-8(s) ‖ 0x00 ... 0x00, len being the UTF-8 byte count, zero-padded to exactly
/// 32·b_Λ bytes. The length prefix makes the padding unambiguous, even for a string that ends in NUL
/// characters. A string whose UTF-8 encoding is longer than 32·b_Λ - 4 bytes is rejected, never
/// truncated. The empty string encodes as 32·b_Λ zero bytes, which is what the encryptor uses for a
/// ballot that carries no contest data in a contest that declares some.
///
/// The encryptor and decryptor take the raw bytes, so a device may use any other unambiguous
/// encoding; <see cref="Decode"/> reads only this one.
/// </summary>
public static class ContestDataEncoding
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>The most UTF-8 bytes a field of <paramref name="blocks"/> blocks holds: 32·b_Λ - 4.</summary>
    public static int Capacity(int blocks)
    {
        if (blocks < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(blocks), blocks, "A contest with contest data has b_Λ >= 1 (§3.3.10 p.40).");
        }

        return ContestDataEncryption.BlockBytes * blocks - sizeof(int);
    }

    /// <summary>
    /// D = b(len, 4) ‖ UTF-8(<paramref name="text"/>) ‖ zero padding, exactly 32·<paramref name="blocks"/>
    /// bytes. Throws <see cref="ArgumentException"/> when the UTF-8 encoding does not fit (more than
    /// 32·b_Λ - 4 bytes) or is not valid UTF-16 to begin with (an unpaired surrogate).
    /// </summary>
    public static byte[] Encode(string text, int blocks)
    {
        ArgumentNullException.ThrowIfNull(text);
        int capacity = Capacity(blocks);

        byte[] utf8;
        try
        {
            utf8 = StrictUtf8.GetBytes(text);
        }
        catch (EncoderFallbackException ex)
        {
            throw new ArgumentException("The contest data string is not valid Unicode text.", nameof(text), ex);
        }

        if (utf8.Length > capacity)
        {
            throw new ArgumentException($"The contest data string is {utf8.Length} UTF-8 bytes; a field of b_Λ = {blocks} blocks holds at most {capacity} (32·b_Λ less the 4-byte length).", nameof(text));
        }

        var data = new byte[ContestDataEncryption.BlockBytes * blocks];
        BinaryPrimitives.WriteInt32BigEndian(data, utf8.Length);
        utf8.CopyTo(data, sizeof(int));
        return data;
    }

    /// <summary>
    /// The string <see cref="Encode"/> wrote into <paramref name="data"/>. Throws
    /// <see cref="FormatException"/> unless <paramref name="data"/> is a whole number of 32-byte
    /// blocks whose length prefix fits, whose padding is all zero, and whose text is valid UTF-8.
    /// </summary>
    public static string Decode(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0 || data.Length % ContestDataEncryption.BlockBytes != 0)
        {
            throw new FormatException($"A contest data field is a whole number of {ContestDataEncryption.BlockBytes}-byte blocks; got {data.Length} bytes.");
        }

        uint length = BinaryPrimitives.ReadUInt32BigEndian(data);
        if (length > (uint)(data.Length - sizeof(int)))
        {
            throw new FormatException($"The contest data field's length prefix is {length}, more than its {data.Length - sizeof(int)} bytes of capacity.");
        }

        var text = data.Slice(sizeof(int), (int)length);
        if (data[(sizeof(int) + (int)length)..].ContainsAnyExcept((byte)0))
        {
            throw new FormatException("The contest data field's padding after its text is not all zero.");
        }

        try
        {
            return StrictUtf8.GetString(text);
        }
        catch (DecoderFallbackException ex)
        {
            throw new FormatException("The contest data field's text is not valid UTF-8.", ex);
        }
    }
}
