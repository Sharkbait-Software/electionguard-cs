using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.Serialization.Converters;

/// <summary>A selection hash ψ (§4.1.1) as base64. Strict: exactly 32 bytes.</summary>
public class SelectionHashJsonConverter : JsonConverter<SelectionHash>
{
    public override SelectionHash Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return SelectionHash.FromCanonicalBytes(StrictBase64.Read(ref reader, "selection hash"));
    }

    public override void Write(Utf8JsonWriter writer, SelectionHash value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(Convert.ToBase64String(value));
    }
}

/// <summary>A short code ω (§4.1.5) as its string. Null is refused.</summary>
public class ShortCodeJsonConverter : JsonConverter<ShortCode>
{
    public override ShortCode Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return new ShortCode(reader.GetString() ?? throw new JsonException("A short code is a string, not null."));
    }

    public override void Write(Utf8JsonWriter writer, ShortCode value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Value);
    }
}

/// <summary>
/// A released ballot nonce ξ_B (§4.4) as base64 of its 32 bytes, exactly as the device drew them
/// (ξ_B is never reduced mod q; eq. 121 hashes the bytes). Strict: exactly 32 bytes.
/// </summary>
public class BallotNonceJsonConverter : JsonConverter<BallotNonce>
{
    public override BallotNonce Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        byte[] bytes = StrictBase64.Read(ref reader, "ballot nonce");
        if (bytes.Length != BallotNonceEncryption.NonceBytes)
        {
            throw new NonCanonicalEncodingException($"A ballot nonce ξ_B is {BallotNonceEncryption.NonceBytes} bytes; got {bytes.Length}.");
        }

        return new BallotNonce(bytes);
    }

    public override void Write(Utf8JsonWriter writer, BallotNonce value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(Convert.ToBase64String(value.ToByteArray()));
    }
}
