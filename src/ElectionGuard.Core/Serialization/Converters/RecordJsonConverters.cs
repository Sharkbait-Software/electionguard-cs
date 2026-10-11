using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.Serialization.Converters;

/// <summary>
/// A 32-byte hash claim of the election record (H_P, H_B, H_E) as base64, decoded strictly to the
/// bytes as read (never recomputed): Verifications 1.E, 1.F and 4.A then check it against what the
/// record's other values give.
/// </summary>
internal sealed class HashClaimJsonConverter<T> : JsonConverter<T> where T : HashValue
{
    private readonly Func<byte[]?, T> _fromCanonicalBytes;

    public HashClaimJsonConverter(Func<byte[]?, T> fromCanonicalBytes)
    {
        _fromCanonicalBytes = fromCanonicalBytes;
    }

    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return _fromCanonicalBytes(RecordJson.ReadBase64(ref reader, typeof(T).Name));
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        writer.WriteBase64StringValue((byte[])value);
    }
}

/// <summary>The manifest file as base64 of its exact bytes, which H_B hashes (eq. 5).</summary>
internal sealed class ManifestFileJsonConverter : JsonConverter<ManifestFile>
{
    public override ManifestFile Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return new ManifestFile { Bytes = RecordJson.ReadBase64(ref reader, "manifest file") };
    }

    public override void Write(Utf8JsonWriter writer, ManifestFile value, JsonSerializerOptions options)
    {
        writer.WriteBase64StringValue(value.Bytes);
    }
}

/// <summary>A guardian index as a JSON number of at least 1 (§3.2.1).</summary>
internal sealed class GuardianIndexJsonConverter : JsonConverter<GuardianIndex>
{
    public override GuardianIndex Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number || !reader.TryGetInt32(out int index) || index < 1)
        {
            throw new JsonException("A guardian index is a JSON integer of at least 1 (§3.2.1).");
        }

        return new GuardianIndex(index);
    }

    public override void Write(Utf8JsonWriter writer, GuardianIndex value, JsonSerializerOptions options)
    {
        writer.WriteNumberValue(value.Index);
    }
}

/// <summary>
/// The baseline parameters the record claims (§3.7): the version string and p, q, r, g as base64
/// of b(p, 512), b(q, 32), b(r, 512) and b(g, 512), big-endian and left-padded. They are encoded
/// as plain integers, never through <see cref="IntegerModP"/>/<see cref="IntegerModQ"/>, which
/// would reduce p and q to 0; r = (p - 1)/q is 481 bytes for the spec's parameters and is padded to
/// the width of Z_p. Each must be exactly its width. Verification 1 compares them with the
/// parameters in use.
/// </summary>
internal sealed class CryptographicParametersJsonConverter : JsonConverter<CryptographicParameters>
{
    private sealed class Document
    {
        public required string Version { get; init; }
        public required byte[] P { get; init; }
        public required byte[] Q { get; init; }
        public required byte[] R { get; init; }
        public required byte[] G { get; init; }
    }

    public override CryptographicParameters Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var document = JsonSerializer.Deserialize<Document>(ref reader, options)
            ?? throw new JsonException("The cryptographic parameters are an object, not null.");
        return new CryptographicParameters(
            document.Version,
            Convert.ToHexString(RecordJson.RequireLength(document.Q, IntegerModQ.ByteLength, "q")),
            Convert.ToHexString(RecordJson.RequireLength(document.P, IntegerModP.ByteLength, "p")),
            Convert.ToHexString(RecordJson.RequireLength(document.R, IntegerModP.ByteLength, "r")),
            Convert.ToHexString(RecordJson.RequireLength(document.G, IntegerModP.ByteLength, "g")));
    }

    public override void Write(Utf8JsonWriter writer, CryptographicParameters value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, new Document
        {
            Version = value.Version,
            P = Padded(value.P, IntegerModP.ByteLength, "p"),
            Q = Padded(value.Q, IntegerModQ.ByteLength, "q"),
            R = Padded(value.R, IntegerModP.ByteLength, "r"),
            G = Padded(value.G, IntegerModP.ByteLength, "g"),
        }, options);
    }

    private static byte[] Padded(BigInteger value, int length, string name)
    {
        if (value.Sign < 0 || value.GetByteCount(isUnsigned: true) > length)
        {
            throw new JsonException($"The parameter {name} does not fit in {length} bytes.");
        }

        return value.ToBigEndianPadded(length);
    }
}

/// <summary>n and k (§3.1.2) as <c>{"n": ..., "k": ...}</c>; 1 &lt;= k &lt;= n.</summary>
internal sealed class GuardianParametersJsonConverter : JsonConverter<GuardianParameters>
{
    private sealed class Document
    {
        public required int N { get; init; }
        public required int K { get; init; }
    }

    public override GuardianParameters Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var document = JsonSerializer.Deserialize<Document>(ref reader, options)
            ?? throw new JsonException("The guardian parameters are an object, not null.");
        if (document.N < 1 || document.K < 1 || document.K > document.N)
        {
            throw new JsonException($"Guardian parameters n = {document.N}, k = {document.K} are not 1 <= k <= n.");
        }

        return new GuardianParameters(document.N, document.K);
    }

    public override void Write(Utf8JsonWriter writer, GuardianParameters value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, new Document { N = value.N, K = value.K }, options);
    }
}

/// <summary>K and K-hat (§3.2.2 eqs. 23, 24) as the two group elements, kept as read.</summary>
internal sealed class ElectionPublicKeysJsonConverter : JsonConverter<ElectionPublicKeys>
{
    private sealed class Document
    {
        public required IntegerModP VoteEncryptionKey { get; init; }
        public required IntegerModP OtherBallotDataEncryptionKey { get; init; }
    }

    public override ElectionPublicKeys Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var document = JsonSerializer.Deserialize<Document>(ref reader, options)
            ?? throw new JsonException("The election public keys are an object, not null.");
        return ElectionPublicKeys.FromKeys(document.VoteEncryptionKey, document.OtherBallotDataEncryptionKey);
    }

    public override void Write(Utf8JsonWriter writer, ElectionPublicKeys value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, new Document
        {
            VoteEncryptionKey = value.VoteEncryptionKey,
            OtherBallotDataEncryptionKey = value.OtherBallotDataEncryptionKey,
        }, options);
    }
}

/// <summary>Shared reading helpers for the record converters.</summary>
internal static class RecordJson
{
    /// <summary>
    /// A base64 JSON string in its canonical form (<see cref="StrictBase64"/>); null or another
    /// token is a <see cref="JsonException"/>, any other text a <see cref="NonCanonicalEncodingException"/>.
    /// </summary>
    public static byte[] ReadBase64(ref Utf8JsonReader reader, string what)
    {
        return StrictBase64.Read(ref reader, what);
    }

    /// <summary>Throws <see cref="NonCanonicalEncodingException"/> unless <paramref name="bytes"/> is exactly <paramref name="length"/> bytes.</summary>
    public static byte[] RequireLength(byte[] bytes, int length, string what)
    {
        if (bytes.Length != length)
        {
            throw new NonCanonicalEncodingException($"The parameter {what} is encoded in exactly {length} bytes; got {bytes.Length}.");
        }

        return bytes;
    }
}
