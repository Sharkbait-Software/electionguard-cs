using System.Globalization;
using System.Text;
using System.Text.Json;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Verifier;

/// <summary>How egrecord writes and reads the values it shows: locators, device keys, phases, digests.</summary>
internal static class Formats
{
    private const string Regular = "regular";
    private const string PreEncrypting = "pre-encrypting";

    /// <summary>A device key as its directory name in the layout (design §5.3.1): <c>regular-&lt;H_DI hex&gt;</c> or <c>pre-encrypting-&lt;H_DI hex&gt;</c>.</summary>
    public static string Device(DeviceKey key) =>
        $"{(key.Kind == DeviceChainBallotKind.PreEncrypted ? PreEncrypting : Regular)}-{Convert.ToHexStringLower((byte[])key.DeviceInformationHash)}";

    /// <summary>A locator as <c>&lt;device&gt;/&lt;position&gt;</c>, the device as in the layout and the position 1-based (the spec's j).</summary>
    public static string Locator(BallotLocator locator) => $"{Device(locator.Device)}/{locator.Position.ToString(CultureInfo.InvariantCulture)}";

    /// <summary>Parses <see cref="Locator(BallotLocator)"/>'s form; <see cref="FormatException"/> otherwise.</summary>
    public static BallotLocator ParseLocator(string text)
    {
        int slash = text.LastIndexOf('/');
        if (slash < 0 || !long.TryParse(text.AsSpan(slash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out long position) || position < 1)
        {
            throw new FormatException($"'{text}' is not a ballot locator: expected regular-<H_DI hex>/<position> or pre-encrypting-<H_DI hex>/<position>, the position 1 or more.");
        }

        string device = text[..slash];
        (DeviceChainBallotKind kind, string hex) = device.StartsWith(PreEncrypting + "-", StringComparison.Ordinal)
            ? (DeviceChainBallotKind.PreEncrypted, device[(PreEncrypting.Length + 1)..])
            : device.StartsWith(Regular + "-", StringComparison.Ordinal)
                ? (DeviceChainBallotKind.Encrypted, device[(Regular.Length + 1)..])
                : throw new FormatException($"'{text}' is not a ballot locator: the device is regular-<hex> or pre-encrypting-<hex>.");
        if (hex.Length != 64 || !hex.All(char.IsAsciiHexDigitLower))
        {
            throw new FormatException($"'{text}' is not a ballot locator: H_DI is 64 lowercase hex digits.");
        }

        return new BallotLocator(new DeviceKey(kind, VotingDeviceInformationHash.FromCanonicalBytes(Convert.FromHexString(hex))), position);
    }

    /// <summary>A confirmation code given as 64 hex digits or as base64 of its 32 bytes (as the JSON representation writes it).</summary>
    public static ConfirmationCode ParseConfirmationCode(string text)
    {
        byte[]? bytes = null;
        if (text.Length == 64 && text.All(char.IsAsciiHexDigit))
        {
            bytes = Convert.FromHexString(text);
        }
        else
        {
            try
            {
                bytes = Convert.FromBase64String(text);
            }
            catch (FormatException)
            {
            }
        }

        if (bytes is not { Length: 32 })
        {
            throw new FormatException($"'{text}' is not a confirmation code: 64 hex digits, or base64 of 32 bytes.");
        }

        return ConfirmationCode.FromCanonicalBytes(bytes);
    }

    /// <summary>A phase by the name the layout gives it (design §5.3: <c>signatures/&lt;phase&gt;-...</c>).</summary>
    public static string Phase(RecordPhase phase) => phase switch
    {
        RecordPhase.Setup => "setup",
        RecordPhase.Sealed => "sealed",
        RecordPhase.Aggregated => "aggregated",
        RecordPhase.Final => "final",
        _ => phase.ToString(),
    };

    public static string Encoding(RecordEncoding encoding) => encoding == RecordEncoding.Json ? "json" : "protobuf";

    public static string Carrier(RecordCarrier carrier) => carrier == RecordCarrier.Zip ? "zip" : "directory";

    public static string Version(RecordFormatVersion version) => $"{version.Major}.{version.Minor}";

    /// <summary>The trust anchors of <c>--trust</c>: P-256 public keys in PEM ("PUBLIC KEY", the DER SubjectPublicKeyInfo), one or more per file.</summary>
    public static IReadOnlyList<ReadOnlyMemory<byte>> ReadPublicKeys(IEnumerable<string> paths)
    {
        var keys = new List<ReadOnlyMemory<byte>>();
        foreach (string path in paths)
        {
            string text = File.ReadAllText(path);
            int found = 0;
            ReadOnlySpan<char> rest = text;
            while (System.Security.Cryptography.PemEncoding.TryFind(rest, out var fields))
            {
                if (rest[fields.Label].SequenceEqual("PUBLIC KEY"))
                {
                    keys.Add(Convert.FromBase64String(rest[fields.Base64Data].ToString()));
                    found++;
                }

                rest = rest[fields.Location.End..];
            }

            if (found == 0)
            {
                throw new FormatException($"{path} holds no PEM \"PUBLIC KEY\" (a DER SubjectPublicKeyInfo).");
            }
        }

        return keys;
    }

    /// <summary>A JSON writer over <paramref name="output"/>, indented, non-ASCII written raw.</summary>
    public static Utf8JsonWriter Json(Stream output) =>
        new(output, new JsonWriterOptions { Indented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });

    /// <summary>Writes <paramref name="write"/>'s JSON document to standard output.</summary>
    public static void WriteJson(Action<Utf8JsonWriter> write)
    {
        using var buffer = new MemoryStream();
        using (var writer = Json(buffer))
        {
            write(writer);
        }

        Console.Out.WriteLine(System.Text.Encoding.UTF8.GetString(buffer.ToArray()));
    }

    public static string Join(this IEnumerable<string> values, string separator) => string.Join(separator, values);

    public static StringBuilder Line(this StringBuilder builder, string text) => builder.Append(text).Append('\n');
}
