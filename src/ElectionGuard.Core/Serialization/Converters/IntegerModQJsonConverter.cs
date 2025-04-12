using ElectionGuard.Core.Crypto;
using System.Text.Json.Serialization;
using System.Text.Json;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Serialization.Converters;

public class IntegerModQJsonConverter : JsonConverter<IntegerModQ>
{
    public override IntegerModQ Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? hexString = reader.GetString();
        if (hexString == null)
        {
            throw new JsonException("Hex string is null");
        }

        byte[] bytes = Convert.FromBase64String(hexString);
        return new IntegerModQ(bytes);
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
        string? hexString = reader.GetString();
        if (hexString == null)
        {
            throw new JsonException("Hex string is null");
        }

        byte[] bytes = Convert.FromBase64String(hexString);
        return new IntegerModP(bytes);
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
        string? hexString = reader.GetString();
        if (hexString == null)
        {
            throw new JsonException("Hex string is null");
        }

        byte[] bytes = Convert.FromBase64String(hexString);
        return new ConfirmationCode(bytes);
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
        string? hexString = reader.GetString();
        if (hexString == null)
        {
            throw new JsonException("Hex string is null");
        }

        byte[] bytes = Convert.FromBase64String(hexString);
        return new ContestHash(bytes);
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
        string? hexString = reader.GetString();
        if (hexString == null)
        {
            throw new JsonException("Hex string is null");
        }

        byte[] bytes = Convert.FromBase64String(hexString);
        return new SelectionEncryptionIdentifierHash(bytes);
    }

    public override void Write(Utf8JsonWriter writer, SelectionEncryptionIdentifierHash value, JsonSerializerOptions options)
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
        string? hexString = reader.GetString();
        if (hexString == null)
        {
            throw new JsonException("Hex string is null");
        }

        byte[] bytes = Convert.FromBase64String(hexString);
        return new VotingDeviceInformationHash(bytes);
    }

    public override void Write(Utf8JsonWriter writer, VotingDeviceInformationHash value, JsonSerializerOptions options)
    {
        byte[] bytes = value;
        string hexString = Convert.ToBase64String(bytes);
        writer.WriteStringValue(hexString);
    }
}