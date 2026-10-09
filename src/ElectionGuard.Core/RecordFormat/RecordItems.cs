using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// A device section's 33-byte key (design §4.5): the record's <c>DeviceKind</c> number (1 regular,
/// 2 pre-encrypting; not the <see cref="DeviceChainBallotKind"/> value) followed by H_DI. Ordered by
/// those bytes, which is the canonical order of device sections.
/// </summary>
public readonly record struct DeviceKey(DeviceChainBallotKind Kind, VotingDeviceInformationHash DeviceInformationHash) : IComparable<DeviceKey>
{
    public const int ByteLength = 33;

    /// <summary>The kind byte: the schema's <c>DeviceKind</c> number.</summary>
    public byte KindByte => KindNumber(Kind);

    /// <summary>The key's 33 bytes.</summary>
    public byte[] ToBytes()
    {
        byte[] hash = DeviceInformationHash;
        if (hash is not { Length: 32 })
        {
            throw new InvalidOperationException("A device key's H_DI is 32 bytes.");
        }

        return [KindByte, .. hash];
    }

    public int CompareTo(DeviceKey other) => ToBytes().AsSpan().SequenceCompareTo(other.ToBytes());

    /// <summary>The schema's <c>DeviceKind</c> number of <paramref name="kind"/>.</summary>
    public static byte KindNumber(DeviceChainBallotKind kind) => kind switch
    {
        DeviceChainBallotKind.Encrypted => 1,
        DeviceChainBallotKind.PreEncrypted => 2,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Not a device kind."),
    };

    /// <summary>The <see cref="DeviceChainBallotKind"/> of the schema's <c>DeviceKind</c> number; null for any other number.</summary>
    public static DeviceChainBallotKind? KindOf(long number) => number switch
    {
        1 => DeviceChainBallotKind.Encrypted,
        2 => DeviceChainBallotKind.PreEncrypted,
        _ => null,
    };
}

/// <summary>
/// A ballot's canonical address in the record (design §2): its device and its 1-based position in
/// that device's chain (the spec's j). Locator order is canonical ballot order.
/// </summary>
public readonly record struct BallotLocator(DeviceKey Device, long Position) : IComparable<BallotLocator>
{
    public int CompareTo(BallotLocator other)
    {
        int c = Device.CompareTo(other.Device);
        return c != 0 ? c : Position.CompareTo(other.Position);
    }
}

/// <summary>
/// The first item of a device section (design §4.5): the device's kind, S_device, H_DI, its chaining
/// mode and, under simple chaining, H_0. The domain <see cref="DeviceChainRecord"/> splits into this
/// and a <see cref="DeviceClose"/>; its confirmation codes are the section's ballots, in order.
/// </summary>
public sealed record DeviceHeader(DeviceChainBallotKind Kind, string DeviceId, VotingDeviceInformationHash DeviceInformationHash,
    ChainingMode ChainingMode, ConfirmationCode? InitialHash)
{
    public DeviceKey Key => new(Kind, DeviceInformationHash);
}

/// <summary>
/// The last item of a device section (design §4.5): the number of ballot items ℓ and, under simple
/// chaining, B-bar_C and H-bar; when the device closed, if recorded (UTC, whole milliseconds).
/// </summary>
public sealed record DeviceClose(long BallotCount, ChainingField? ClosingChainingField, ConfirmationCode? ClosingHash, DateTimeOffset? ClosedAt);

/// <summary>
/// A contest-data ciphertext marked for decryption (§3.6.1; follow-up #10, "Record the requested
/// set"), sealed into the aggregated phase before any decryption: the ballot's locator, its H_I (a
/// binding: it must equal the ballot's) and the contest index.
/// </summary>
public sealed record ContestDataRequest(BallotLocator Ballot, SelectionEncryptionIdentifierHash IdentifierHash, int ContestIndex);

/// <summary>The encrypted tally's header (#17): the number of cast ballots of both kinds and their total weight.</summary>
public sealed record EncryptedTallyHeader(long CastBallotCount, long TotalCastWeight);

/// <summary>
/// The setup sections of a record (design §3.1, §4.5: header, parameters, manifest, guardians,
/// election keys) as domain values. Every hash is a claim, kept as read; the parameters are the
/// record's claim too (CLAUDE.md: arithmetic reads <see cref="EGParameters"/>, and Verification 1
/// compares the two). The manifest is the file's bytes exactly as entered (#19), and is parsed only
/// by <see cref="ToEncryptionRecord"/>.
/// </summary>
public sealed record RecordSetup(
    RecordFormatVersion Format,
    CryptographicParameters Parameters,
    GuardianParameters GuardianParameters,
    ParameterBaseHash ParameterBaseHash,
    ManifestFile ManifestFile,
    string ManifestMediaType,
    ElectionBaseHash ElectionBaseHash,
    IReadOnlyList<GuardianPublicView> Guardians,
    ElectionPublicKeys Keys,
    ExtendedBaseHash ExtendedBaseHash)
{
    /// <summary>The media type of a manifest file in <see cref="Serialization.ManifestSerializer"/>'s reading rules.</summary>
    public const string ManifestMediaTypeFormat1 = "application/vnd.electionguard.manifest+json;format=1";

    /// <summary>
    /// The encryption record these sections describe: the manifest parsed from the stored bytes
    /// (S10a binding; throws <see cref="InvalidManifestException"/> if they are not a manifest), the
    /// keys as claimed (<see cref="ElectionPublicKeys.FromKeys"/>, never recomputed).
    /// </summary>
    public EncryptionRecord ToEncryptionRecord() => new()
    {
        CryptographicParameters = Parameters,
        GuardianParameters = GuardianParameters,
        ParameterBaseHash = ParameterBaseHash,
        ManifestFile = ManifestFile,
        ElectionBaseHash = ElectionBaseHash,
        Guardians = [.. Guardians],
        ElectionPublicKeys = Keys,
        ExtendedBaseHash = ExtendedBaseHash,
    };

    /// <summary>The guardian record these sections hold (everything but H_E).</summary>
    public GuardianRecord ToGuardianRecord() => new()
    {
        CryptographicParameters = Parameters,
        GuardianParameters = GuardianParameters,
        ParameterBaseHash = ParameterBaseHash,
        ManifestFile = new ManifestFile { Bytes = ManifestFile.Bytes.ToArray() },
        ElectionBaseHash = ElectionBaseHash,
        Guardians = [.. Guardians],
        ElectionPublicKeys = Keys,
    };

    /// <summary>The setup sections of <paramref name="record"/>, format v2.0, its manifest file as it holds it.</summary>
    public static RecordSetup FromEncryptionRecord(EncryptionRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return new RecordSetup(RecordFormatVersion.V2_0, record.CryptographicParameters, record.GuardianParameters, record.ParameterBaseHash,
            record.ManifestFile, ManifestMediaTypeFormat1, record.ElectionBaseHash, record.Guardians, record.ElectionPublicKeys, record.ExtendedBaseHash);
    }

    /// <summary>
    /// The setup sections of a guardian record. The record's election keys item carries H_E, which a
    /// guardian record does not, so the caller gives it (H(H_B; 0x14, K, K-hat), eq. 25).
    /// </summary>
    public static RecordSetup FromGuardianRecord(GuardianRecord record, ExtendedBaseHash extendedBaseHash)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(extendedBaseHash);
        return new RecordSetup(RecordFormatVersion.V2_0, record.CryptographicParameters, record.GuardianParameters, record.ParameterBaseHash,
            record.ManifestFile, ManifestMediaTypeFormat1, record.ElectionBaseHash, record.Guardians, record.ElectionPublicKeys, extendedBaseHash);
    }
}
