using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.KeyGeneration;

/// <summary>
/// The preliminary guardian record the election administrator shows every guardian at the end of
/// key generation (§3.2.2 "Share verification and the guardian record"). Besides the parameters,
/// keys, commitments and proofs the spec lists, it carries the manifest file and H_B: step 1 has
/// each guardian key its comparison hash H_G with H_B (eq. 27) and check H_B by performing
/// Verification 1, which needs both.
/// </summary>
public class GuardianRecord
{
    public required CryptographicParameters CryptographicParameters { get; init; }
    public required GuardianParameters GuardianParameters { get; init; }
    public required ParameterBaseHash ParameterBaseHash { get; init; }

    /// <summary>The election manifest file, in the canonical bytes H_B is computed over (§3.1.3, §3.1.4).</summary>
    public required ManifestFile ManifestFile { get; init; }

    /// <summary>H_B = H(H_P; 0x01, manifest) (eq. 5). A claim, checked by Verification 1.F.</summary>
    public required ElectionBaseHash ElectionBaseHash { get; init; }

    public required List<GuardianPublicView> Guardians { get; init; }
    public required ElectionPublicKeys ElectionPublicKeys { get; init; }
}
