using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;

namespace ElectionGuard.Core.Tally;

// The three messages each participating guardian sends in the §3.6.5 decryption protocol, through
// the administrator. There is no network layer: a deployment carries them however it likes, and
// TallyAdmin.Decrypt drives in-process guardians through the same three rounds. Each is keyed like
// the tally itself, contest id then option id.

/// <summary>
/// Round 1 (<see cref="TallyGuardian.Commit"/>): guardian i's partial decryption
/// M_i = A^{z_i} (eq. 84) of every option, and its commitment hash d_i (eq. 88) to the commitment
/// pair (a_i, b_i) that it reveals only in round 2.
/// </summary>
public class PartialTallyDecryption
{
    public required GuardianIndex GuardianIndex { get; init; }
    public required Dictionary<string, PartialTallyContestDecryption> Contests { get; init; }

    public class PartialTallyContestDecryption
    {
        public required Dictionary<string, PartialTallyChoiceDecryption> Choices { get; init; }
    }

    public class PartialTallyChoiceDecryption
    {
        /// <summary>M_i = A^{z_i} mod p (eq. 84).</summary>
        public required IntegerModP Mi { get; init; }

        /// <summary>d_i (eq. 88), 32 bytes.</summary>
        public required byte[] CommitmentHash { get; init; }
    }
}

/// <summary>
/// Round 2 (<see cref="TallyGuardian.Reveal"/>), sent only once guardian i holds every
/// participant's round-1 message: its commitment pair (a_i, b_i) = (g^{u_i}, A^{u_i}) (eq. 87) for
/// every option.
/// </summary>
public class TallyDecryptionCommitmentReveal
{
    public required GuardianIndex GuardianIndex { get; init; }
    public required Dictionary<string, ContestReveal> Contests { get; init; }

    public class ContestReveal
    {
        public required Dictionary<string, ChoiceReveal> Choices { get; init; }
    }

    public class ChoiceReveal
    {
        /// <summary>a_i = g^{u_i} mod p.</summary>
        public required IntegerModP CommitmentA { get; init; }

        /// <summary>b_i = A^{u_i} mod p.</summary>
        public required IntegerModP CommitmentB { get; init; }
    }
}

/// <summary>
/// Round 3 (<see cref="TallyGuardian.Respond"/>): guardian i's response
/// v_i = (u_i - c_i·z_i) mod q (eq. 92) for every option, where c_i = c·w_i (eq. 91) and c is the
/// eq. (90) challenge the guardian computed itself.
/// </summary>
public class TallyDecryptionResponse
{
    public required GuardianIndex GuardianIndex { get; init; }
    public required Dictionary<string, ContestResponse> Contests { get; init; }

    public class ContestResponse
    {
        public required Dictionary<string, ChoiceResponse> Choices { get; init; }
    }

    public class ChoiceResponse
    {
        /// <summary>v_i (eq. 92).</summary>
        public required IntegerModQ Response { get; init; }
    }
}

/// <summary>
/// The tally decryption protocol (§3.6.5) was halted: a participant's message did not check, or
/// the combined proof did not verify. <see cref="OffendingGuardian"/> names the guardian the
/// failure is attributed to, when it can be: one whose d_j does not match what it revealed (the
/// complaint of p.48), or, through the per-guardian checks of Note 3.7 (eqs. 94, 95), one whose
/// share of the proof is invalid.
/// </summary>
public class TallyDecryptionException : Exception
{
    public TallyDecryptionException(GuardianIndex? offendingGuardian, string message) : base(message)
    {
        OffendingGuardian = offendingGuardian;
    }

    public GuardianIndex? OffendingGuardian { get; }
}
