using ElectionGuard.Core.Models;
using System.Text.Json;

namespace ElectionGuard.Core.Serialization;

/// <summary>
/// The library's one manifest file format. §3.1.3 p.19: "The data in the election manifest is
/// written to a file manifest in a canonical representation that may be implementation specific",
/// and H_B hashes that file (eq. 5). This is that representation, and the only way the library
/// turns a manifest file into a <see cref="Manifest"/>: an <see cref="EncryptionRecord"/>'s
/// <see cref="EncryptionRecord.Manifest"/> is parsed from its <see cref="EncryptionRecord.ManifestFile"/>
/// here, so the manifest every verification computes with is the one H_B was computed over.
///
/// <para><b>Reading</b> (<see cref="Deserialize"/>) is strict, so that two conformant readers
/// cannot see different manifests in the same bytes:</para>
/// <list type="bullet">
/// <item>UTF-8 JSON without a byte order mark, comments or trailing commas; one top-level object.</item>
/// <item>Property names are the camelCase names of the <see cref="Manifest"/>, <see cref="Contest"/>,
/// <see cref="Choice"/>, <see cref="SupplementalField"/> and <see cref="BallotStyle"/> members, matched
/// case-sensitively. An unknown property, or one named twice in an object, is refused.</item>
/// <item>Required members (<c>electionId</c>, <c>contests</c>, <c>ballotStyles</c>; a contest's
/// <c>id</c>, <c>name</c>, <c>selectionLimit</c>, <c>optionSelectionLimit</c>, <c>index</c>,
/// <c>choices</c>; an option's <c>id</c>, <c>name</c>, <c>index</c>; a supplemental field's as an
/// option's plus <c>kind</c>; a ballot style's <c>id</c>, <c>name</c>, <c>contestIds</c>) must be
/// present. The optional ones default as the model does: <c>chainingMode</c> 0,
/// <c>hashTrimmingFunction</c> absent, <c>supplementalFields</c> [], <c>writeInFieldCount</c> 0,
/// <c>contestDataBlocks</c> 0. No value may be null, and no list entry may be null.</item>
/// <item>Integers are JSON numbers in the 32-bit range (no strings, no fractions).
/// <c>chainingMode</c> and <c>hashTrimmingFunction</c> are numbers (the 4-byte mode identifier of
/// §3.4.4, the Ω subscript of §4.6); a supplemental field's <c>kind</c> is its
/// <see cref="SupplementalFieldKind"/> name, case-sensitive.</item>
/// <item>The result must pass <see cref="Manifest.Validate"/>.</item>
/// </list>
/// Any failure throws <see cref="InvalidManifestException"/>, with the JSON error as its inner
/// exception where there is one.
///
/// <para><b>Writing</b> (<see cref="Serialize"/>) is deterministic: the same manifest always gives
/// the same bytes. Compact (no whitespace), UTF-8 without a byte order mark, members in declaration
/// order (<c>electionId</c>, <c>contests</c>, <c>ballotStyles</c>, <c>chainingMode</c>, then
/// <c>hashTrimmingFunction</c> only when set; a contest's <c>id</c>, <c>name</c>, <c>selectionLimit</c>,
/// <c>optionSelectionLimit</c>, <c>index</c>, <c>choices</c>, <c>supplementalFields</c>,
/// <c>writeInFieldCount</c>, <c>contestDataBlocks</c>; an option's <c>id</c>, <c>name</c>,
/// <c>index</c>; a supplemental field's <c>kind</c> first, then an option's members; a ballot
/// style's <c>id</c>, <c>name</c>, <c>contestIds</c>), every optional member written, strings escaped as System.Text.Json's
/// default encoder escapes them (non-ASCII and HTML-sensitive characters as <c>\uXXXX</c>).</para>
///
/// <para>A file need not be in the written form to be read: H_B is computed over the file as it is
/// (§3.1.4), whitespace and member order included, and the reader accepts any document that meets
/// the rules above. Election tooling should publish the written form.</para>
/// </summary>
public static class ManifestSerializer
{
    private static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = StrictJson.CreateOptions();

        // Overrides the type's JsonStringEnumConverter, which also reads numbers and any casing.
        options.Converters.Add(new StrictEnumNameConverter<SupplementalFieldKind>());
        return options;
    }

    /// <summary>The manifest in the library's written form; see the class remarks. Does not validate it.</summary>
    public static byte[] Serialize(Manifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        return JsonSerializer.SerializeToUtf8Bytes(manifest, Options);
    }

    /// <summary>A manifest file holding <paramref name="manifest"/> in the library's written form.</summary>
    public static ManifestFile ToManifestFile(Manifest manifest)
    {
        return new ManifestFile { Bytes = Serialize(manifest) };
    }

    /// <summary>
    /// Parses and validates a manifest file under the rules in the class remarks. Throws
    /// <see cref="InvalidManifestException"/> on any violation.
    /// </summary>
    public static Manifest Deserialize(ReadOnlySpan<byte> utf8Json)
    {
        Manifest? manifest;
        try
        {
            StrictJson.RejectAmbiguity(utf8Json);
            manifest = JsonSerializer.Deserialize<Manifest>(utf8Json, Options);
        }
        catch (JsonException ex)
        {
            throw new InvalidManifestException($"The manifest file is not a manifest in the library's format: {ex.Message}", ex);
        }

        if (manifest is null)
        {
            throw new InvalidManifestException("The manifest file holds the JSON value null, not a manifest.");
        }

        manifest.Validate();
        return manifest;
    }

    /// <summary>Parses and validates <paramref name="manifestFile"/>; see <see cref="Deserialize(ReadOnlySpan{byte})"/>.</summary>
    public static Manifest Deserialize(ManifestFile manifestFile)
    {
        ArgumentNullException.ThrowIfNull(manifestFile);
        return Deserialize(manifestFile.Bytes);
    }
}
