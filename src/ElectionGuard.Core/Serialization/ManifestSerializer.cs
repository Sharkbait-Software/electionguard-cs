using ElectionGuard.Core.Models;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.Serialization;

/// <summary>
/// The library's one manifest file format. §3.1.3 p.19: "The data in the election manifest is
/// written to a file manifest in a canonical representation that may be implementation specific",
/// and H_B hashes that file (eq. 5). This is that representation, and the only way the library
/// turns a manifest file into a <see cref="Manifest"/>: an <see cref="EncryptionRecord"/>'s
/// <see cref="EncryptionRecord.Manifest"/> is parsed from its <see cref="EncryptionRecord.ManifestFile"/>
/// here, so the manifest every verification computes with is the one H_B was computed over.
///
/// <para><b>Reading</b> (<see cref="Deserialize"/>) is strict about everything the library reads,
/// so that two conformant readers cannot see different manifests in the same bytes, and tolerant of
/// properties it does not know:</para>
/// <list type="bullet">
/// <item>UTF-8 JSON without a byte order mark, comments or trailing commas; one top-level object.
/// Every byte is well-formed UTF-8 and no string or property name escapes to a lone surrogate,
/// including inside the value of a property the reader ignores (RFC 8259 §8.1 requires UTF-8; §8.2
/// leaves lone surrogates' behaviour unpredictable). Whether a file is a manifest therefore does not
/// depend on which properties a reader knows. Nesting is at most 64 levels deep, the top-level
/// object being level 1, vendor data included (RFC 8259 §9 lets a parser limit depth).</item>
/// <item>Property names are the camelCase names of the <see cref="Manifest"/>, <see cref="Contest"/>,
/// <see cref="Choice"/>, <see cref="SupplementalField"/> and <see cref="BallotStyle"/> members, matched
/// case-sensitively. A property named twice in an object is refused, known or not.</item>
/// <item>A property the model does not have is ignored, at any level and whatever its value (user
/// decision NQ-1, 2026-10-09: the manifest is the one place a vendor may add data). It stays in
/// the file's bytes, so H_B (eq. 5), which hashes the file as it is, still binds it. That
/// includes a name that differs from a member's only in case, <c>_</c> or <c>-</c>
/// (<c>ChainingMode</c>, <c>chaining_mode</c>): member names are matched exactly, so it is an
/// unknown property and is ignored like any other (user decision R-3, 2026-10-09: "Ignore them
/// too"). A conformant reader in any language matches names exactly as well; one that matched
/// them loosely would read another manifest from the same bytes.</item>
/// <item>Required members (<c>electionId</c>, <c>contests</c>, <c>ballotStyles</c>; a contest's
/// <c>id</c>, <c>name</c>, <c>selectionLimit</c>, <c>optionSelectionLimit</c>, <c>index</c>,
/// <c>choices</c>; an option's <c>id</c>, <c>name</c>, <c>index</c>; a supplemental field's as an
/// option's plus <c>kind</c>; a ballot style's <c>id</c>, <c>name</c>, <c>contestIds</c>) must be
/// present. The optional ones default as the model does: <c>chainingMode</c> 0,
/// <c>hashTrimmingFunction</c> absent, <c>supplementalFields</c> [], <c>writeInFieldCount</c> 0,
/// <c>contestDataBlocks</c> 0, and the informational election facts (<c>electionName</c>,
/// <c>electionDate</c>, <c>electionType</c>, <c>jurisdiction</c>, <c>location</c>; §3.7, user
/// decision NQ-4) absent. No required member, list or list entry may be null; an optional
/// member written as null reads as absent.</item>
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
/// <c>hashTrimmingFunction</c>, <c>electionName</c>, <c>electionDate</c>, <c>electionType</c>,
/// <c>jurisdiction</c> and <c>location</c>, each only when set; a contest's <c>id</c>, <c>name</c>, <c>selectionLimit</c>,
/// <c>optionSelectionLimit</c>, <c>index</c>, <c>choices</c>, <c>supplementalFields</c>,
/// <c>writeInFieldCount</c>, <c>contestDataBlocks</c>; an option's <c>id</c>, <c>name</c>,
/// <c>index</c>; a supplemental field's <c>kind</c> first, then an option's members; a ballot
/// style's <c>id</c>, <c>name</c>, <c>contestIds</c>), every optional member written, strings escaped as System.Text.Json's
/// default encoder escapes them (non-ASCII and HTML-sensitive characters as <c>\uXXXX</c>).</para>
///
/// <para>A file need not be in the written form to be read: H_B is computed over the file as it is
/// (§3.1.4), whitespace, member order and unknown properties included, and the reader accepts any
/// document that meets the rules above. The election record stores the file byte for byte as it
/// was entered (user decision S10b #19); the written form has no canonical status. Writing drops
/// unknown properties, since the model does not hold them.</para>
/// </summary>
public static class ManifestSerializer
{
    private static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = StrictJson.CreateOptions();

        // NQ-1: unknown properties are vendor data, ignored here and bound by H_B through the
        // bytes. Only this reader is tolerant; the record readers keep StrictJson's Disallow.
        options.UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip;

        // Overrides the type's JsonStringEnumConverter, which also reads numbers and any casing.
        options.Converters.Add(new StrictEnumNameConverter<SupplementalFieldKind>());
        options.MakeReadOnly(populateMissingResolver: true);
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
