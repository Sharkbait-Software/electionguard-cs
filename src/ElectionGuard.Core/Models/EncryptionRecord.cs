using ElectionGuard.Core.KeyGeneration;

namespace ElectionGuard.Core.Models;

public class EncryptionRecord
{
    public required CryptographicParameters CryptographicParameters { get; init; }
    public required GuardianParameters GuardianParameters { get; init; }
    public required List<GuardianPublicView> Guardians { get; init; }
    public required ElectionPublicKeys ElectionPublicKeys { get; init; }
    public required ExtendedBaseHash ExtendedBaseHash { get; init; }
    public required Manifest Manifest { get; init; }
}
