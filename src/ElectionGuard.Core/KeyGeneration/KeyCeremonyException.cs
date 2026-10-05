namespace ElectionGuard.Core.KeyGeneration;

/// <summary>
/// A guardian's check of the preliminary guardian record failed (§3.2.2 "Share verification and the
/// guardian record", steps 1 and 4). The spec has the guardian complain to the administrator and
/// the other guardians, so the failure names the step and, where one can be named, the guardian
/// whose data did not check out. Verification 1 (run inside step 1) and steps 2 and 3
/// (Verifications 2 and 3) throw <see cref="Verify.VerificationFailedException"/> instead.
/// </summary>
public class KeyCeremonyException : Exception
{
    public KeyCeremonyException(int step, GuardianIndex? offendingGuardian, string message) : base(message)
    {
        Step = step;
        OffendingGuardian = offendingGuardian;
    }

    /// <summary>The §3.2.2 share-verification step that failed (1 or 4).</summary>
    public int Step { get; }

    /// <summary>The guardian whose data failed the check, or null when no single guardian can be named.</summary>
    public GuardianIndex? OffendingGuardian { get; }
}
