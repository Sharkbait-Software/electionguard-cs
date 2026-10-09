using ElectionGuard.Core.KeyGeneration;

namespace ElectionGuard.Core.Models;

public class EncryptionRecord
{
    public required CryptographicParameters CryptographicParameters { get; init; }
    public required GuardianParameters GuardianParameters { get; init; }

    /// <summary>H_P (eq. 4). §3.7 lists it in the election record; checked by Verification 1.E.</summary>
    public required ParameterBaseHash ParameterBaseHash { get; init; }

    /// <summary>
    /// The election manifest file: the bytes H_B is computed over (§3.1.3, §3.1.4). §3.7 lists the
    /// manifest file in the election record. Verification 1.F checks H_B against these bytes.
    /// <para>
    /// Setting it parses and validates it with <see cref="Serialization.ManifestSerializer"/>, the
    /// library's one manifest format, and <see cref="Manifest"/> is that parse. There is no other way
    /// to give a record a manifest, so the manifest that Verifications 6-14, the encryptor,
    /// pre-encryption and the tally compute with is always the one these bytes, and so H_B, describe
    /// (S2 review R1, closed in S10a). A file that is not a valid manifest throws
    /// <see cref="InvalidManifestException"/>. The record keeps its own copy of the bytes, so a
    /// caller that changes the array it passed in changes neither the parse nor what 1.F hashes.
    /// The copy is reachable through this getter and <see cref="Manifest"/> is a mutable object
    /// graph: in-process code must treat both as read-only (nothing re-checks the parse against the
    /// bytes after this).
    /// </para>
    /// </summary>
    public required ManifestFile ManifestFile
    {
        get => _manifestFile;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            ArgumentNullException.ThrowIfNull(value.Bytes);
            var copy = new ManifestFile { Bytes = value.Bytes.ToArray() };
            _manifest = Serialization.ManifestSerializer.Deserialize(copy);
            _manifestFile = copy;
        }
    }

    private readonly ManifestFile _manifestFile = null!;

    /// <summary>H_B = H(H_P; 0x01, manifest) (eq. 5). §3.7 lists it in the election record; checked by Verification 1.F.</summary>
    public required ElectionBaseHash ElectionBaseHash { get; init; }

    public required List<GuardianPublicView> Guardians { get; init; }
    public required ElectionPublicKeys ElectionPublicKeys { get; init; }
    public required ExtendedBaseHash ExtendedBaseHash { get; init; }

    /// <summary>
    /// The election manifest, parsed from <see cref="ManifestFile"/> and validated
    /// (<see cref="Manifest.Validate"/>) when the file was set; every index-bearing hash computed
    /// against this record trusts its contest and option indices. It is derived, so
    /// <see cref="Serialization.JsonElectionRecordSerializer"/> does not write it (the record carries
    /// the file) and refuses a document that has it.
    /// </summary>
    public Manifest Manifest => _manifest;

    private readonly Manifest _manifest = null!;
}
