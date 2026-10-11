using ElectionGuard.Core.Crypto;
using System.Text.Json.Serialization;
using System.Text.Json;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Serialization.Converters;

public class IntegerModQJsonConverter : JsonConverter<IntegerModQ>
{
    public override IntegerModQ Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        // Strict: exactly 32 bytes below q (see NonCanonicalEncodingException). Canonical base64 only (StrictBase64).
        byte[] bytes = StrictBase64.Read(ref reader, typeToConvert.Name);
        return IntegerModQ.FromCanonicalBytes(bytes);
    }

    public override void Write(Utf8JsonWriter writer, IntegerModQ value, JsonSerializerOptions options)
    {
        byte[] bytes = value.ToByteArray();
        string hexString = Convert.ToBase64String(bytes);
        writer.WriteStringValue(hexString);
    }
}

public class IntegerModPJsonConverter : JsonConverter<IntegerModP>
{
    public override IntegerModP Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        // Strict: exactly 512 bytes below p (see NonCanonicalEncodingException). Canonical base64 only (StrictBase64).
        byte[] bytes = StrictBase64.Read(ref reader, typeToConvert.Name);
        return IntegerModP.FromCanonicalBytes(bytes);
    }

    public override void Write(Utf8JsonWriter writer, IntegerModP value, JsonSerializerOptions options)
    {
        byte[] bytes = value.ToByteArray();
        string hexString = Convert.ToBase64String(bytes);
        writer.WriteStringValue(hexString);
    }
}

public class ConfirmationCodeJsonConverter : JsonConverter<ConfirmationCode>
{
    public override ConfirmationCode Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        // Strict: exactly 32 bytes. Canonical base64 only (StrictBase64).
        byte[] bytes = StrictBase64.Read(ref reader, typeToConvert.Name);
        return ConfirmationCode.FromCanonicalBytes(bytes);
    }

    public override void Write(Utf8JsonWriter writer, ConfirmationCode value, JsonSerializerOptions options)
    {
        byte[] bytes = value;
        string hexString = Convert.ToBase64String(bytes);
        writer.WriteStringValue(hexString);
    }
}

public class ContestHashJsonConverter : JsonConverter<ContestHash>
{
    public override ContestHash Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        // Strict: exactly 32 bytes. Canonical base64 only (StrictBase64).
        byte[] bytes = StrictBase64.Read(ref reader, typeToConvert.Name);
        return ContestHash.FromCanonicalBytes(bytes);
    }

    public override void Write(Utf8JsonWriter writer, ContestHash value, JsonSerializerOptions options)
    {
        byte[] bytes = value;
        string hexString = Convert.ToBase64String(bytes);
        writer.WriteStringValue(hexString);
    }
}

public class SelectionEncryptionIdentifierHashJsonConverter : JsonConverter<SelectionEncryptionIdentifierHash>
{
    public override SelectionEncryptionIdentifierHash Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        // Strict: exactly 32 bytes. Canonical base64 only (StrictBase64).
        byte[] bytes = StrictBase64.Read(ref reader, typeToConvert.Name);
        return SelectionEncryptionIdentifierHash.FromCanonicalBytes(bytes);
    }

    public override void Write(Utf8JsonWriter writer, SelectionEncryptionIdentifierHash value, JsonSerializerOptions options)
    {
        byte[] bytes = value;
        string hexString = Convert.ToBase64String(bytes);
        writer.WriteStringValue(hexString);
    }
}

public class SelectionEncryptionIdentifierJsonConverter : JsonConverter<SelectionEncryptionIdentifier>
{
    public override SelectionEncryptionIdentifier Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        // Strict: exactly 32 bytes, b(id_B, 32) in eq. (32). Canonical base64 only (StrictBase64).
        byte[] bytes = StrictBase64.Read(ref reader, typeToConvert.Name);
        return SelectionEncryptionIdentifier.FromCanonicalBytes(bytes);
    }

    public override void Write(Utf8JsonWriter writer, SelectionEncryptionIdentifier value, JsonSerializerOptions options)
    {
        byte[] bytes = value;
        string hexString = Convert.ToBase64String(bytes);
        writer.WriteStringValue(hexString);
    }
}

public class VotingDeviceInformationHashJsonConverter : JsonConverter<VotingDeviceInformationHash>
{
    public override VotingDeviceInformationHash Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        // Strict: exactly 32 bytes. Canonical base64 only (StrictBase64).
        byte[] bytes = StrictBase64.Read(ref reader, typeToConvert.Name);
        return VotingDeviceInformationHash.FromCanonicalBytes(bytes);
    }

    public override void Write(Utf8JsonWriter writer, VotingDeviceInformationHash value, JsonSerializerOptions options)
    {
        byte[] bytes = value;
        string hexString = Convert.ToBase64String(bytes);
        writer.WriteStringValue(hexString);
    }
}
public class ChainingFieldJsonConverter : JsonConverter<ChainingField>
{
    public override ChainingField Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        // Strict: exactly 36 bytes, the mode identifier and a 32-byte hash (§3.4.4). Canonical base64 only (StrictBase64).
        byte[] bytes = StrictBase64.Read(ref reader, typeToConvert.Name);
        return ChainingField.FromCanonicalBytes(bytes);
    }

    public override void Write(Utf8JsonWriter writer, ChainingField value, JsonSerializerOptions options)
    {
        byte[] bytes = value;
        string hexString = Convert.ToBase64String(bytes);
        writer.WriteStringValue(hexString);
    }
}
