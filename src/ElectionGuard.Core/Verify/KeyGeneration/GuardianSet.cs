using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.KeyGeneration;

/// <summary>
/// The guardian-set shape the key-generation verifications rely on: exactly n guardians, numbered
/// 1..n with no index twice (§3.2.1 "guardians G_1, ..., G_n"; Verification 2 "for each guardian
/// G_i, 1 &lt;= i &lt;= n"; Verification 3's products over i = 1..n). n is read from
/// <see cref="EGParameters"/>, which Verification 1 has already tied to the record's own claim.
/// </summary>
internal static class GuardianSet
{
    /// <summary>
    /// Throws <see cref="VerificationFailedException"/> with <paramref name="subSection"/> unless
    /// <paramref name="guardians"/> is exactly G_1..G_n, in any order.
    /// </summary>
    public static void RequireComplete(IReadOnlyCollection<GuardianPublicView> guardians, string subSection)
    {
        int n = EGParameters.GuardianParameters.N;

        if (guardians.Count != n)
        {
            throw new VerificationFailedException(subSection, $"Expected exactly n = {n} guardians, found {guardians.Count}.");
        }

        var seen = new bool[n + 1];
        foreach (var guardian in guardians)
        {
            int index = guardian.Index.Index;
            if (index < 1 || index > n)
            {
                throw new VerificationFailedException(subSection, $"Guardian index {index} is outside 1..n (n = {n}).");
            }

            if (seen[index])
            {
                throw new VerificationFailedException(subSection, $"Guardian index {index} appears more than once.");
            }

            seen[index] = true;
        }
    }
}
