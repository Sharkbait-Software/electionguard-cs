using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization.Converters;
using System.Text.Json;

namespace ElectionGuard.Core.Serialization;

/// <summary>
/// JSON for the election record's per-device ordered ballot lists (<see cref="DeviceChainRecord"/>,
/// §3.7), in the encoding the ballot serializer uses: camelCase properties, hashes and chaining
/// fields base64, enums as numbers. A chaining field must decode to exactly 36 bytes, and a
/// confirmation code, H_0, H-bar and H_DI to exactly 32; the null initialization and closing values
/// of a no-chaining device are written as null. Decoding refuses an unknown property, a property
/// named twice, a null device id, code list or list entry (<see cref="JsonException"/>; S10a).
/// </summary>
public class JsonDeviceChainRecordSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
        RespectNullableAnnotations = true,
        WriteIndented = true,
        Converters =
        {
            new ConfirmationCodeJsonConverter(),
            new VotingDeviceInformationHashJsonConverter(),
            new ChainingFieldJsonConverter(),
        },
    };

    public void Serialize(Stream destination, IReadOnlyList<DeviceChainRecord> records)
    {
        JsonSerializer.Serialize(destination, records, Options);
    }

    public List<DeviceChainRecord>? Deserialize(Stream source)
    {
        using var buffer = new MemoryStream();
        source.CopyTo(buffer);
        byte[] bytes = buffer.ToArray();
        StrictJson.RejectAmbiguity(bytes);
        var records = JsonSerializer.Deserialize<List<DeviceChainRecord>>(bytes, Options);
        if (records is not null && records.Contains(null!))
        {
            throw new JsonException("The device chain record list has a null entry.");
        }

        return records;
    }
}
