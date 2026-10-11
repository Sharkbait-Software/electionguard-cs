namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// The election record format's version (design §7). The major version is the <c>.proto</c>
/// package (<c>electionguard.egrf.v2</c>); a minor version only appends (fields, item types, and
/// values of the enums other than <c>SectionType</c> and <c>DeviceKind</c>), so a reader of an older
/// minor verifies what it understands of a newer record and reports the rest. A new section kind or
/// device kind needs a new major (user decisions NQ-7, NQ-9).
/// </summary>
public readonly record struct RecordFormatVersion(ushort Major, ushort Minor)
{
    /// <summary>EGRF v2.0, the version this library reads and writes.</summary>
    public static readonly RecordFormatVersion V2_0 = new(2, 0);

    /// <summary>The version of the schema this library was built from (<see cref="V2_0"/>).</summary>
    public static RecordFormatVersion Library => V2_0;
}

/// <summary>
/// The protocol phase a section belongs to (design §4.5): the section type's high byte, capped at
/// final. The values equal the schema's <c>RecordPhase</c> enum numbers.
/// </summary>
public enum RecordPhase : byte
{
    Setup = 1,
    Sealed = 2,
    Aggregated = 3,
    Final = 4,
}

/// <summary>
/// The section types of EGRF v2.0 (design §4.5); the values equal the schema's <c>SectionType</c>
/// numbers. There are no others: a new section kind needs a new format major (user decision NQ-7),
/// and there are no vendor sections (vendors extend only the manifest; user decisions NQ-1 and
/// "Remove them", 2026-10-10).
/// </summary>
public enum RecordSectionType : ushort
{
    Header = 0x0001,
    Parameters = 0x0002,
    Manifest = 0x0003,
    Guardians = 0x0004,
    ElectionKeys = 0x0005,
    Device = 0x0101,
    DeviceAttestations = 0x0102,
    EncryptedTally = 0x0201,
    ContestDataRequests = 0x0202,
    DecryptedTally = 0x0301,
    ChallengedBallotDecryptions = 0x0302,
    ContestDataDecryptions = 0x0303,
    UncastNonceReleases = 0x0304,
}

/// <summary>The fixed properties of section types (design §4.5).</summary>
public static class RecordSections
{
    /// <summary>Phase = min(type >> 8, 3), as <see cref="RecordPhase"/> (that number plus one).</summary>
    public static RecordPhase PhaseOf(RecordSectionType type) => (RecordPhase)(Math.Min((ushort)type >> 8, 3) + 1);

    /// <summary>Whether <paramref name="type"/> is a section type of EGRF v2.0.</summary>
    public static bool IsStandard(RecordSectionType type) => Enum.IsDefined(type);

    /// <summary>
    /// The critical bit a TOC entry of a section type must carry: true for every v2.0 type (design
    /// §4.5). Null for any other value, which no record reaches a v2 reader with: a new section kind
    /// comes with a new format major (user decision NQ-7), and the reader refuses a TOC entry naming
    /// one as <c>R.version</c>.
    /// </summary>
    public static bool? FixedCritical(RecordSectionType type) => IsStandard(type) ? true : null;
}
