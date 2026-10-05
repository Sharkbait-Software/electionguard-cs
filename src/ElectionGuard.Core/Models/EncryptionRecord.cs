using ElectionGuard.Core.KeyGeneration;

namespace ElectionGuard.Core.Models;

public class EncryptionRecord
{
    public required CryptographicParameters CryptographicParameters { get; init; }
    public required GuardianParameters GuardianParameters { get; init; }

    /// <summary>H_P (eq. 4). §3.7 lists it in the election record; checked by Verification 1.E.</summary>
    public required ParameterBaseHash ParameterBaseHash { get; init; }

    /// <summary>
    /// The election manifest file: the canonical bytes H_B is computed over (§3.1.3, §3.1.4). §3.7
    /// lists the manifest file in the election record. Verification 1.F checks H_B against these
    /// bytes.
    /// <para>
    /// Known gap, tracked for S10 in docs/spec-compliance/2026-10-04-fix-progress.md: nothing binds
    /// <see cref="Manifest"/>, the parsed form that Verifications 6-8, pre-encryption and the
    /// encryptor compute with, to these bytes. §3.1.3 leaves the canonical representation
    /// implementation specific and the library does not define one yet, so a record can pass 1.F
    /// over one manifest while its ballots are checked against another. Until it does, build both
    /// from the same source, as Program.cs and the perf harness do.
    /// </para>
    /// </summary>
    public required ManifestFile ManifestFile { get; init; }

    /// <summary>H_B = H(H_P; 0x01, manifest) (eq. 5). §3.7 lists it in the election record; checked by Verification 1.F.</summary>
    public required ElectionBaseHash ElectionBaseHash { get; init; }

    public required List<GuardianPublicView> Guardians { get; init; }
    public required ElectionPublicKeys ElectionPublicKeys { get; init; }
    public required ExtendedBaseHash ExtendedBaseHash { get; init; }

    /// <summary>
    /// The election manifest. Validated on assignment (<see cref="Manifest.Validate"/>), since every
    /// index-bearing hash computed against this record trusts its contest and option indices.
    /// </summary>
    public required Manifest Manifest
    {
        get => _manifest;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            value.Validate();
            _manifest = value;
        }
    }

    private readonly Manifest _manifest = null!;
}
