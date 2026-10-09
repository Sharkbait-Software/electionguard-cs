using System.Buffers;
using System.Buffers.Text;
using System.Text.Json;

namespace ElectionGuard.Core.Serialization;

/// <summary>
/// Reads a JSON string as base64 in its one canonical form (RFC 4648 §4: the standard alphabet,
/// padded with '=' to a multiple of 4 characters, unused trailing bits zero, nothing else), the
/// form <see cref="Convert.ToBase64String(byte[])"/> and <see cref="Utf8JsonWriter.WriteBase64StringValue(ReadOnlySpan{byte})"/>
/// write. JSON escapes are undone first, so <c>+</c> is '+' (System.Text.Json writes '+'
/// escaped). Every JSON decoder of a published value in this library reads base64 through here.
///
/// <para><see cref="Convert.FromBase64String(string)"/> and <see cref="Utf8JsonReader.GetBytesFromBase64"/>
/// both skip whitespace inside the string, and accept nonzero unused bits, so several strings would
/// decode to one value; the first also throws a bare <see cref="FormatException"/> for a string
/// that is not base64 at all. Here anything but the canonical form is a
/// <see cref="NonCanonicalEncodingException"/>, like a value of the wrong width, and a token that
/// is not a string (null included) is a <see cref="JsonException"/>.</para>
/// </summary>
internal static class StrictBase64
{
    // Large enough for an element of Z_p (512 bytes, 684 characters) on the stack; longer values,
    // such as a manifest file in a record, use a pooled buffer.
    private const int StackLimit = 1024;

    public static byte[] Read(ref Utf8JsonReader reader, string what)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"The {what} is a base64 string; got {reader.TokenType}.");
        }

        int escapedLength = reader.HasValueSequence ? checked((int)reader.ValueSequence.Length) : reader.ValueSpan.Length;
        byte[]? rented = null;
        Span<byte> text = escapedLength <= StackLimit
            ? stackalloc byte[StackLimit]
            : (rented = ArrayPool<byte>.Shared.Rent(escapedLength));
        try
        {
            // Unescaping never lengthens the value, so the escaped length bounds the copy.
            int length = reader.CopyString(text);
            return Decode(text[..length], what);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>Decodes UTF-8 base64 text in its canonical form, or throws <see cref="NonCanonicalEncodingException"/>.</summary>
    public static byte[] Decode(ReadOnlySpan<byte> utf8, string what)
    {
        if (utf8.Length % 4 != 0)
        {
            throw NotCanonical(what);
        }

        int padding = utf8.EndsWith("=="u8) ? 2 : utf8.EndsWith("="u8) ? 1 : 0;
        var bytes = new byte[utf8.Length / 4 * 3 - padding];
        var status = Base64.DecodeFromUtf8(utf8, bytes, out int consumed, out int written);
        if (status != OperationStatus.Done || consumed != utf8.Length || written != bytes.Length)
        {
            throw NotCanonical(what);
        }

        // The decoder skips whitespace and ignores unused bits; re-encoding the bytes gives the one
        // canonical text, which must be exactly what was read.
        byte[]? rented = null;
        Span<byte> again = utf8.Length <= StackLimit
            ? stackalloc byte[StackLimit]
            : (rented = ArrayPool<byte>.Shared.Rent(utf8.Length));
        try
        {
            if (Base64.EncodeToUtf8(bytes, again, out _, out int encoded) != OperationStatus.Done
                || !again[..encoded].SequenceEqual(utf8))
            {
                throw NotCanonical(what);
            }
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        return bytes;
    }

    private static NonCanonicalEncodingException NotCanonical(string what)
    {
        return new NonCanonicalEncodingException($"The {what} is not base64 in its canonical form (RFC 4648 §4 alphabet, padded to a multiple of 4 characters, unused bits zero, no whitespace).");
    }
}
