using System.Text.Json;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.Serialization;

/// <summary>
/// Checks shared by the strict JSON readers of the manifest (<see cref="ManifestSerializer"/>) and of
/// the election record (<see cref="JsonElectionRecordSerializer"/>): the parts of "one document,
/// one meaning" that System.Text.Json does not enforce on its own.
/// </summary>
internal static class StrictJson
{
    /// <summary>
    /// Throws <see cref="JsonException"/> if <paramref name="utf8Json"/> starts with a UTF-8 byte
    /// order mark, or if any object in it names the same property twice (after unescaping, so
    /// <c>"id"</c> and <c>"id"</c> are the same name). System.Text.Json on .NET 9 lets the
    /// last duplicate win, and other JSON readers keep the first, so two conformant readers could
    /// see two different documents in the same bytes. Comments and trailing commas are refused as
    /// well (the reader's defaults).
    /// </summary>
    public static void RejectAmbiguity(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
        {
            throw new JsonException("The document starts with a UTF-8 byte order mark; it is UTF-8 without one.");
        }

        var reader = new Utf8JsonReader(utf8Json, new JsonReaderOptions
        {
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
        });

        var scopes = new Stack<HashSet<string>?>();
        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        scopes.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;
                    case JsonTokenType.StartArray:
                        scopes.Push(null);
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.EndArray:
                        scopes.Pop();
                        break;
                    case JsonTokenType.PropertyName:
                        string name = reader.GetString()!;
                        if (!scopes.Peek()!.Add(name))
                        {
                            throw new JsonException($"Property \"{name}\" appears more than once in one object (at byte {reader.TokenStartIndex}); a strict document names each property once.");
                        }

                        break;
                }
            }
        }
        catch (InvalidOperationException ex)
        {
            // GetString throws InvalidOperationException for a property name that is not valid
            // text: invalid UTF-8, or an escaped lone surrogate such as "\uD800". Only
            // JsonSerializer.Deserialize turns the reader's exceptions into JsonException, and this
            // runs before it, so the readers' typed-error promise needs the translation here.
            throw new JsonException($"A property name is not valid text: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// The options every strict reader starts from: camelCase names matched case-sensitively, no
    /// member the type does not have, no null where the type has no nullable annotation, numbers as
    /// JSON numbers only, no comments or trailing commas. Written compact, in declaration order.
    /// </summary>
    public static JsonSerializerOptions CreateOptions()
    {
        return new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
            NumberHandling = JsonNumberHandling.Strict,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
            WriteIndented = false,
        };
    }
}

/// <summary>
/// An enum written and read by its exact member name, case-sensitively, never by number: the
/// strict counterpart of <see cref="JsonStringEnumConverter{TEnum}"/>, which also reads numbers and
/// any casing of a name.
/// </summary>
internal sealed class StrictEnumNameConverter<TEnum> : JsonConverter<TEnum> where TEnum : struct, Enum
{
    public override TEnum Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"A {typeof(TEnum).Name} is written as its name, a JSON string; got {reader.TokenType}.");
        }

        string name = reader.GetString()!;
        foreach (var value in Enum.GetValues<TEnum>())
        {
            if (string.Equals(Enum.GetName(value), name, StringComparison.Ordinal))
            {
                return value;
            }
        }

        throw new JsonException($"\"{name}\" is not a {typeof(TEnum).Name} name (names are case-sensitive).");
    }

    public override void Write(Utf8JsonWriter writer, TEnum value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(Enum.GetName(value) ?? throw new JsonException($"{value} is not a named {typeof(TEnum).Name}."));
    }
}
