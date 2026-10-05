using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// A decrypted tally as published in the election record (§3.7): for each option of each contest,
/// the count t, the decrypted value T = B·M^-1 = K^t (eq. 82) and the proof (c, v) of correct
/// decryption (§3.6.5), which Verification 10 checks against the encrypted aggregate (A, B).
/// Verification 11 checks its labels against the manifest.
/// </summary>
public class DecryptedTally
{
    public required Dictionary<string, DecryptedContest> Contests { get; init; }

    public class DecryptedContest
    {
        /// <summary>
        /// ind_c(Λ), the contest's index in the manifest (§3.1.3), as hashed by eq. (90).
        /// Verification 10 takes the index from the manifest and requires this to agree.
        /// </summary>
        public required int ContestIndex { get; init; }

        public required Dictionary<string, DecryptedChoice> Choices { get; init; }
    }

    public class DecryptedChoice
    {
        /// <summary>ind_o(λ), the option's index within its contest (§3.1.3), as hashed by eq. (90).</summary>
        public required int ChoiceIndex { get; init; }

        /// <summary>The decrypted count t, with T = K^t mod p (Verification 10.C).</summary>
        public int VoteCount { get; init; }

        /// <summary>T = (B·M^-1) mod p (eq. 82).</summary>
        public required IntegerModP T { get; init; }

        /// <summary>The proof challenge c (eq. 90).</summary>
        public required IntegerModQ Challenge { get; init; }

        /// <summary>The proof response v = (Σ v_i) mod q (eq. 93).</summary>
        public required IntegerModQ Response { get; init; }
    }
}
