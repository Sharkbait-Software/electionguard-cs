using System.Globalization;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>A record's representation (design §5.1): canonical protobuf item bytes, or the proto3 JSON mapping of them.</summary>
public enum RecordEncoding
{
    /// <summary>Length-delimited <c>.binpb</c> segments holding the canonical item bytes (§5.2).</summary>
    Protobuf,

    /// <summary><c>.jsonl</c> segments, one proto3 JSON object per line (§5.5).</summary>
    Json,
}

/// <summary>A record's carrier (design §5.3, §5.4).</summary>
public enum RecordCarrier
{
    Directory,
    Zip,
}

/// <summary>
/// A section's identity: its type and key (empty except a device section's 33-byte device key).
/// Ordered and compared by content, in canonical section order (ascending type, then key bytes).
/// </summary>
public readonly struct SectionKey : IEquatable<SectionKey>, IComparable<SectionKey>
{
    private readonly byte[]? _key;

    public SectionKey(RecordSectionType type, ReadOnlySpan<byte> key)
    {
        Type = type;
        _key = key.ToArray();
    }

    public RecordSectionType Type { get; }

    public ReadOnlyMemory<byte> Key => _key ?? [];

    /// <summary>The section of a device.</summary>
    public static SectionKey Device(DeviceKey device) => new(RecordSectionType.Device, device.ToBytes());

    /// <summary>A section with an empty key.</summary>
    public static SectionKey Of(RecordSectionType type) => new(type, []);

    public RecordPhase Phase => RecordSections.PhaseOf(Type);

    public int CompareTo(SectionKey other)
    {
        int c = ((ushort)Type).CompareTo((ushort)other.Type);
        return c != 0 ? c : Key.Span.SequenceCompareTo(other.Key.Span);
    }

    public bool Equals(SectionKey other) => Type == other.Type && Key.Span.SequenceEqual(other.Key.Span);

    public override bool Equals(object? obj) => obj is SectionKey other && Equals(other);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Type);
        hash.AddBytes(Key.Span);
        return hash.ToHashCode();
    }

    public static bool operator ==(SectionKey left, SectionKey right) => left.Equals(right);

    public static bool operator !=(SectionKey left, SectionKey right) => !left.Equals(right);

    public override string ToString() => Key.IsEmpty ? $"0x{(ushort)Type:x4}" : $"0x{(ushort)Type:x4}/{Convert.ToHexStringLower(Key.Span)}";
}

/// <summary>
/// One stored item as a reader hands it on: its canonical <c>RecordItem</c> bytes (for a JSON
/// record, the canonical encoding of the parsed line; design §5.1), its 0-based ordinal in its
/// section, and the canonicality check of those bytes (§4.4). A protobuf item that fails the check
/// is still handed on with the bytes as read, so its leaf hash, and so the root check, can still be
/// computed (§4.8 layer 1); whoever consumes it decides whether that is fatal.
/// </summary>
public readonly record struct RecordItemBytes(ReadOnlyMemory<byte> Bytes, long Ordinal, CanonicalCheck Check);

/// <summary>What a path in a record names (design §5.3.1).</summary>
internal enum LayoutFileKind
{
    Segment,
    Toc,
    Signature,
    Meta,
    ManifestCopy,
    Derived,
}

/// <summary>A path of a record, parsed by <see cref="RecordLayout.Parse"/>.</summary>
internal sealed record LayoutFile(string Path, LayoutFileKind Kind, SectionKey Section, int SegmentIndex, string? Extension);

/// <summary>
/// The layout of a record's files (design §5.3, §5.3.1), the same in both carriers: every path is a
/// function of the logical record, and anything outside the layout is <c>R.container</c>. Paths are
/// relative, use '/', and are compared byte for byte; hex is lowercase; a section that the layout
/// shows as one file is exactly one segment with that name, and any other section's segments are
/// <c>&lt;8-digit index&gt;.&lt;ext&gt;</c> from 00000000 with no gap.
/// </summary>
internal static class RecordLayout
{
    public const string ProtobufExtension = "binpb";
    public const string JsonExtension = "jsonl";
    public const string MetaPath = "meta.json";
    public const string ManifestCopyPath = "setup/manifest.json";
    public const string DerivedPrefix = "derived/";
    public const string SignaturesPrefix = "signatures/";

    private const string RegularDevice = "regular";
    private const string PreEncryptingDevice = "pre-encrypting";

    private static readonly Dictionary<RecordSectionType, string> SingleFiles = new()
    {
        [RecordSectionType.Header] = "setup/header",
        [RecordSectionType.Parameters] = "setup/parameters",
        [RecordSectionType.Manifest] = "setup/manifest",
        [RecordSectionType.Guardians] = "setup/guardians",
        [RecordSectionType.ElectionKeys] = "setup/election_keys",
        [RecordSectionType.DeviceAttestations] = "device_attestations",
        [RecordSectionType.EncryptedTally] = "aggregated/encrypted_tally",
        [RecordSectionType.ContestDataRequests] = "aggregated/contest_data_requests",
        [RecordSectionType.DecryptedTally] = "final/decrypted_tally",
    };

    private static readonly Dictionary<RecordSectionType, string> SegmentedDirectories = new()
    {
        [RecordSectionType.ChallengedBallotDecryptions] = "final/challenged_ballot_decryptions",
        [RecordSectionType.ContestDataDecryptions] = "final/contest_data_decryptions",
        [RecordSectionType.UncastNonceReleases] = "final/uncast_nonce_releases",
    };

    private static readonly Dictionary<string, RecordSectionType> SingleFileTypes = SingleFiles.ToDictionary(x => x.Value, x => x.Key, StringComparer.Ordinal);
    private static readonly Dictionary<string, RecordSectionType> SegmentedTypes = SegmentedDirectories.ToDictionary(x => x.Value, x => x.Key, StringComparer.Ordinal);

    public static string Extension(RecordEncoding encoding) => encoding == RecordEncoding.Protobuf ? ProtobufExtension : JsonExtension;

    public static RecordEncoding EncodingOf(string extension) => extension == ProtobufExtension ? RecordEncoding.Protobuf : RecordEncoding.Json;

    /// <summary>Whether a section of <paramref name="type"/> is one file (one segment) in the layout.</summary>
    public static bool IsSingleFile(RecordSectionType type) => SingleFiles.ContainsKey(type);

    /// <summary>The path of segment <paramref name="segment"/> of <paramref name="section"/>.</summary>
    public static string SegmentPath(SectionKey section, int segment, RecordEncoding encoding)
    {
        string ext = Extension(encoding);
        if (SingleFiles.TryGetValue(section.Type, out var single))
        {
            if (segment != 0 || !section.Key.IsEmpty)
            {
                throw new ArgumentException($"Section {section} is one segment with an empty key.", nameof(section));
            }

            return $"{single}.{ext}";
        }

        string name = $"{segment.ToString("D8", CultureInfo.InvariantCulture)}.{ext}";
        if (SegmentedDirectories.TryGetValue(section.Type, out var directory))
        {
            return $"{directory}/{name}";
        }

        if (section.Type == RecordSectionType.Device)
        {
            var key = section.Key.Span;
            string kind = key.Length == DeviceKey.ByteLength
                ? DeviceKey.KindOf(key[0]) switch
                {
                    Models.DeviceChainBallotKind.Encrypted => RegularDevice,
                    Models.DeviceChainBallotKind.PreEncrypted => PreEncryptingDevice,
                    _ => throw new ArgumentException($"Device kind {key[0]} is not declared.", nameof(section)),
                }
                : throw new ArgumentException("A device section's key is 33 bytes.", nameof(section));
            return $"devices/{kind}-{Convert.ToHexStringLower(key[1..])}/{name}";
        }

        if (RecordSections.IsVendor(section.Type))
        {
            string key = section.Key.IsEmpty ? "" : "-" + Convert.ToHexStringLower(section.Key.Span);
            return $"vendor/{(ushort)section.Type:x4}{key}/{name}";
        }

        throw new ArgumentException($"Section type 0x{(ushort)section.Type:x4} has no place in the layout.", nameof(section));
    }

    public static string TocPath(RecordEncoding encoding) => $"toc.{Extension(encoding)}";

    /// <summary>A record signature's file: <c>signatures/&lt;phase&gt;-&lt;SHA-256(statement) hex&gt;.&lt;ext&gt;</c>.</summary>
    public static string SignaturePath(RecordPhase phase, Sha256Digest statement, RecordEncoding encoding) =>
        $"{SignaturesPrefix}{PhaseName(phase)}-{statement}.{Extension(encoding)}";

    public static string PhaseName(RecordPhase phase) => phase switch
    {
        RecordPhase.Setup => "setup",
        RecordPhase.Sealed => "sealed",
        RecordPhase.Aggregated => "aggregated",
        RecordPhase.Final => "final",
        _ => throw new ArgumentOutOfRangeException(nameof(phase), phase, null),
    };

    /// <summary>
    /// What <paramref name="path"/> names. Throws <c>R.container</c> for a name that breaks the
    /// naming rules or is not in the layout. A file under <c>derived/</c> is accepted and never read.
    /// </summary>
    public static LayoutFile Parse(string path)
    {
        RequireValidName(path);
        if (path.StartsWith(DerivedPrefix, StringComparison.Ordinal))
        {
            return new LayoutFile(path, LayoutFileKind.Derived, default, 0, null);
        }

        if (path == MetaPath)
        {
            return new LayoutFile(path, LayoutFileKind.Meta, default, 0, null);
        }

        if (path == ManifestCopyPath)
        {
            return new LayoutFile(path, LayoutFileKind.ManifestCopy, default, 0, null);
        }

        int dot = path.LastIndexOf('.');
        int slash = path.LastIndexOf('/');
        if (dot <= slash + 1)
        {
            throw Unlisted(path);
        }

        string ext = path[(dot + 1)..];
        if (ext is not (ProtobufExtension or JsonExtension))
        {
            throw Unlisted(path);
        }

        string stem = path[..dot];
        if (stem == "toc")
        {
            return new LayoutFile(path, LayoutFileKind.Toc, default, 0, ext);
        }

        if (SingleFileTypes.TryGetValue(stem, out var singleType))
        {
            return new LayoutFile(path, LayoutFileKind.Segment, SectionKey.Of(singleType), 0, ext);
        }

        if (stem.StartsWith(SignaturesPrefix, StringComparison.Ordinal))
        {
            string name = stem[SignaturesPrefix.Length..];
            int dash = name.IndexOf('-');
            if (dash < 0 || name[..dash] is not ("setup" or "sealed" or "aggregated" or "final") || !IsLowerHex(name[(dash + 1)..], 64))
            {
                throw Unlisted(path);
            }

            return new LayoutFile(path, LayoutFileKind.Signature, default, 0, ext);
        }

        if (slash < 0 || !TryParseSegmentIndex(stem[(slash + 1)..], out int index))
        {
            throw Unlisted(path);
        }

        string directory = stem[..slash];
        if (SegmentedTypes.TryGetValue(directory, out var segmentedType))
        {
            return new LayoutFile(path, LayoutFileKind.Segment, SectionKey.Of(segmentedType), index, ext);
        }

        if (directory.StartsWith("devices/", StringComparison.Ordinal))
        {
            string name = directory["devices/".Length..];
            byte kind;
            string hex;
            if (name.StartsWith(RegularDevice + "-", StringComparison.Ordinal))
            {
                kind = DeviceKey.KindNumber(Models.DeviceChainBallotKind.Encrypted);
                hex = name[(RegularDevice.Length + 1)..];
            }
            else if (name.StartsWith(PreEncryptingDevice + "-", StringComparison.Ordinal))
            {
                kind = DeviceKey.KindNumber(Models.DeviceChainBallotKind.PreEncrypted);
                hex = name[(PreEncryptingDevice.Length + 1)..];
            }
            else
            {
                throw Unlisted(path);
            }

            if (!IsLowerHex(hex, 64))
            {
                throw Unlisted(path);
            }

            return new LayoutFile(path, LayoutFileKind.Segment, new SectionKey(RecordSectionType.Device, [kind, .. Convert.FromHexString(hex)]), index, ext);
        }

        if (directory.StartsWith("vendor/", StringComparison.Ordinal))
        {
            string name = directory["vendor/".Length..];
            string typeHex = name.Length >= 4 ? name[..4] : "";
            string keyHex = name.Length > 4 && name[4] == '-' ? name[5..] : "";
            if (!IsLowerHex(typeHex, 4) || (name.Length > 4 && (name[4] != '-' || keyHex.Length == 0 || keyHex.Length % 2 != 0 || !IsLowerHex(keyHex, keyHex.Length))))
            {
                throw Unlisted(path);
            }

            var type = (RecordSectionType)ushort.Parse(typeHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            if (!RecordSections.IsVendor(type))
            {
                throw Unlisted(path);
            }

            return new LayoutFile(path, LayoutFileKind.Segment, new SectionKey(type, Convert.FromHexString(keyHex)), index, ext);
        }

        throw Unlisted(path);
    }

    /// <summary>
    /// The naming rules of §5.3.1, for every name of a record (<c>derived/</c> included, and a zip
    /// directory entry without its trailing '/'): printable ASCII (0x20-0x7E) other than '\' and ':',
    /// relative, '/'-separated, no empty, <c>.</c> or <c>..</c> segment; anything else is
    /// <c>R.container</c>. Names being ASCII, case folding is ASCII case alone in every language.
    /// </summary>
    public static void RequireValidName(string path)
    {
        if (string.IsNullOrEmpty(path) || path[0] == '/' || path.Any(c => c is < ' ' or > '~' or '\\' or ':'))
        {
            throw RecordCodes.Failure(RecordCodes.Container, $"\"{path}\" is not a relative '/'-separated name of printable ASCII other than '\\' and ':' (§5.3.1).");
        }

        foreach (var segment in path.Split('/'))
        {
            if (segment is "" or "." or "..")
            {
                throw RecordCodes.Failure(RecordCodes.Container, $"\"{path}\" has an empty, '.' or '..' path segment (§5.3.1).");
            }
        }
    }

    /// <summary>
    /// Throws <c>R.container</c> if two names are equal under case folding (they collide when
    /// extracted on Windows or macOS). Valid names are ASCII (<see cref="RequireValidName"/>), so this
    /// is ASCII case folding; it runs before the naming rules, so it must not fail on other names.
    /// </summary>
    public static void RequireNoCaseFoldCollision(IEnumerable<string> paths)
    {
        var seen = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var path in paths)
        {
            string folded = path.ToUpperInvariant().ToLowerInvariant();
            if (seen.TryGetValue(folded, out var other))
            {
                throw RecordCodes.Failure(RecordCodes.Container, $"\"{path}\" and \"{other}\" are the same name under case folding (§5.3.1).");
            }

            seen[folded] = path;
        }
    }

    private static bool TryParseSegmentIndex(string name, out int index)
    {
        index = 0;
        return name.Length == 8 && name.All(char.IsAsciiDigit) && int.TryParse(name, NumberStyles.None, CultureInfo.InvariantCulture, out index);
    }

    private static bool IsLowerHex(string text, int length) =>
        text.Length == length && text.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static Exception Unlisted(string path) =>
        RecordCodes.Failure(RecordCodes.Container, $"\"{path}\" is not in the record layout (§5.3.1: no unlisted files; hex is lowercase).");
}
