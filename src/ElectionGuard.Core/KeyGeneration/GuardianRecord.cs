using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.KeyGeneration;

public class GuardianRecord
{
    public required CryptographicParameters CryptographicParameters { get; init; }
    public required GuardianParameters GuardianParameters { get; init; }
    public required ParameterBaseHash ParameterBaseHash { get; init; }
    public required List<GuardianPublicView> Guardians { get; init; }
    public required ElectionPublicKeys ElectionPublicKeys { get; init; }
}
