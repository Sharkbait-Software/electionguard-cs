using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization.Converters;
using System.Text.Json;

namespace ElectionGuard.Core.Serialization;

/// <summary>
/// JSON for the election record's per-device ordered ballot lists (<see cref="DeviceChainRecord"/>,
/// §3.7), in the encoding the ballot serializer uses: camelCase properties, hashes and chaining
/// fields base64, enums as numbers. A chaining field must decode to exactly 36 bytes; the null
/// initialization and closing values of a no-chaining device are written as null.
/// </summary>
public class JsonDeviceChainRecordSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
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
        return JsonSerializer.Deserialize<List<DeviceChainRecord>>(source, Options);
    }
}
