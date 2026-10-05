using ElectionGuard.Core.KeyGeneration;

namespace ElectionGuard.Core.Models;

public class EncryptionRecord
{
    public required CryptographicParameters CryptographicParameters { get; init; }
    public required GuardianParameters GuardianParameters { get; init; }
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
