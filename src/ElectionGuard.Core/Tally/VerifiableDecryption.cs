using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// One value the guardians decrypt jointly, with a proof, by the three-round protocol of §3.6.5:
/// the base X whose power X^s they compute (A of a tally option's (A, B); C_0 of a contest data
/// field, §3.6.6), and the statement's own commitment hash and challenge. The two decryptions differ
/// only in these, in the key share used (z_i or ẑ_i) and in the public key the proof is checked
/// against (K or K-hat); <see cref="VerifiableDecryption"/> does the rest for both.
/// </summary>
internal interface IDecryptionStatement
{
    /// <summary>X: guardian i sends X^{s_i}, and commits to (g^{u_i}, X^{u_i}).</summary>
    IntegerModP Base { get; }

    /// <summary>What is being decrypted, for messages: "contest c, option o".</summary>
    string Description { get; }

    /// <summary>The equation of the commitment hash, for messages: "eq. 88".</summary>
    string CommitmentEquation { get; }

    /// <summary>d_i over guardian i's commitment pair and partial decryption, and U.</summary>
    byte[] CommitmentHash(GuardianIndex guardian, IntegerModP commitmentA, IntegerModP commitmentB, IntegerModP partialDecryption, IReadOnlyCollection<GuardianIndex> participants);

    /// <summary>The joint challenge c over a = ∏ a_i, b = ∏ b_i and the combined decryption.</summary>
    IntegerModQ Challenge(IntegerModP commitmentA, IntegerModP commitmentB, IntegerModP combinedDecryption);
}

/// <summary>
/// The parts of the §3.6.5 protocol that do not depend on what is decrypted, shared by tally
/// decryption (§3.6.5, eqs. 84-95) and contest data decryption (§3.6.6, eqs. 96-103, "exactly the
/// same as the one in Section 3.6.5"): a guardian's round-1 values, the check of every d_j and the
/// combination into a, b, the combined decryption and c, a guardian's response, the check of the
/// combined proof, and Note 3.7's attribution of a failing proof to a guardian. Values are kept in
/// arrays in statement order and participant order (ascending index).
/// </summary>
internal static class VerifiableDecryption
{
    /// <summary>A participant's round-1 message, flattened in statement order.</summary>
    internal sealed class ReceivedCommitment
    {
        public required IntegerModP[] PartialDecryptions { get; init; }
        public required byte[][] CommitmentHashes { get; init; }
    }

    /// <summary>A participant's round-2 message, flattened in statement order.</summary>
    internal sealed class ReceivedReveal
    {
        public required IntegerModP[] CommitmentsA { get; init; }
        public required IntegerModP[] CommitmentsB { get; init; }
    }

    internal sealed class CombinedProof
    {
        /// <summary>w_j (eq. 85), in participant order.</summary>
        public required IntegerModQ[] LagrangeCoefficients { get; init; }

        /// <summary>a = ∏ a_j (eqs. 89, 100), per statement.</summary>
        public required IntegerModP[] CommitmentA { get; init; }

        /// <summary>b = ∏ b_j (eqs. 89, 100), per statement.</summary>
        public required IntegerModP[] CommitmentB { get; init; }

        /// <summary>M = ∏ M_j^{w_j} (eq. 86) or β = ∏ m_j^{w_j} (eq. 97), per statement.</summary>
        public required IntegerModP[] CombinedDecryptions { get; init; }

        /// <summary>c (eqs. 90, 101), per statement.</summary>
        public required IntegerModQ[] Challenges { get; init; }
    }

    /// <summary>A guardian's round-1 values and the secrets it keeps until round 3.</summary>
    internal sealed class GuardianCommitment
    {
        public required IntegerModQ[] Nonces { get; init; }
        public required IntegerModP[] PartialDecryptions { get; init; }
        public required IntegerModP[] CommitmentsA { get; init; }
        public required IntegerModP[] CommitmentsB { get; init; }
        public required byte[][] CommitmentHashes { get; init; }
    }

    /// <summary>
    /// Round 1 for guardian <paramref name="self"/>: for each statement a fresh u_i
    /// (<paramref name="nonceSource"/> only in tests), the partial decryption X^{s_i} (eqs. 84, 96),
    /// the commitment pair (g^{u_i}, X^{u_i}) (eqs. 87, 98) and d_i.
    /// </summary>
    public static GuardianCommitment Commit<T>(
        T[] statements,
        IntegerModQ secretShare,
        GuardianIndex self,
        GuardianIndex[] participants,
        Func<int, IntegerModQ?>? nonceSource,
        Func<int, IntegerModP, IntegerModP>? tamper,
        ParallelOptions parallelOptions)
        where T : IDecryptionStatement
    {
        var nonces = new IntegerModQ[statements.Length];
        var partialDecryptions = new IntegerModP[statements.Length];
        var commitmentsA = new IntegerModP[statements.Length];
        var commitmentsB = new IntegerModP[statements.Length];
        var commitmentHashes = new byte[statements.Length][];

        Parallel.For(0, statements.Length, parallelOptions, o =>
        {
            var statement = statements[o];
            var u = nonceSource?.Invoke(o) ?? ElectionGuardRandom.GetIntegerModQ();

            // u_i and the key share are secrets and full-width elements of Z_q: the constant-time path.
            var partialDecryption = MontgomeryModP.PowModP(statement.Base, secretShare);
            if (tamper is not null)
            {
                partialDecryption = tamper(o, partialDecryption);
            }

            var commitmentA = MontgomeryModP.PowModP(EGParameters.G, u);
            var commitmentB = MontgomeryModP.PowModP(statement.Base, u);

            nonces[o] = u;
            partialDecryptions[o] = partialDecryption;
            commitmentsA[o] = commitmentA;
            commitmentsB[o] = commitmentB;
            commitmentHashes[o] = statement.CommitmentHash(self, commitmentA, commitmentB, partialDecryption, participants);
        });

        return new GuardianCommitment
        {
            Nonces = nonces,
            PartialDecryptions = partialDecryptions,
            CommitmentsA = commitmentsA,
            CommitmentsB = commitmentsB,
            CommitmentHashes = commitmentHashes,
        };
    }

    /// <summary>
    /// Checks every participant's d_j, recomputed from the caller's own statements and U and the
    /// partial decryption and (a_j, b_j) guardian j sent; then forms a and b (eqs. 89, 100), the
    /// combined decryption (eqs. 86, 97) and c (eqs. 90, 101) for every statement. A mismatch throws
    /// <see cref="TallyDecryptionException"/> naming the first guardian, in statement order, whose
    /// d_j does not hold: the complaint of p.48 and p.50.
    /// </summary>
    public static CombinedProof CheckAndCombine<T>(
        GuardianIndex[] participants,
        T[] statements,
        ReceivedCommitment[] commitments,
        ReceivedReveal[] reveals,
        ParallelOptions parallelOptions)
        where T : IDecryptionStatement
    {
        var lagrangeCoefficients = participants.Select(j => TallyDecryptionHashes.LagrangeCoefficient(j, participants)).ToArray();

        var mismatch = new int[statements.Length];
        var commitmentA = new IntegerModP[statements.Length];
        var commitmentB = new IntegerModP[statements.Length];
        var combined = new IntegerModP[statements.Length];
        var challenges = new IntegerModQ[statements.Length];

        Parallel.For(0, statements.Length, parallelOptions, o =>
        {
            var statement = statements[o];
            mismatch[o] = -1;
            for (int j = 0; j < participants.Length; j++)
            {
                var expected = statement.CommitmentHash(participants[j], reveals[j].CommitmentsA[o], reveals[j].CommitmentsB[o],
                    commitments[j].PartialDecryptions[o], participants);
                if (!expected.AsSpan().SequenceEqual(commitments[j].CommitmentHashes[o]))
                {
                    mismatch[o] = j;
                    return;
                }
            }

            IntegerModP a = 1;
            IntegerModP b = 1;
            IntegerModP m = 1;
            for (int j = 0; j < participants.Length; j++)
            {
                a *= reveals[j].CommitmentsA[o];
                b *= reveals[j].CommitmentsB[o];

                // w_j is public, but a full-width element of Z_q.
                m *= MontgomeryModP.PowModP(commitments[j].PartialDecryptions[o], lagrangeCoefficients[j]);
            }

            commitmentA[o] = a;
            commitmentB[o] = b;
            combined[o] = m;
            challenges[o] = statement.Challenge(a, b, m);
        });

        for (int o = 0; o < statements.Length; o++)
        {
            if (mismatch[o] >= 0)
            {
                var offender = participants[mismatch[o]];
                throw new TallyDecryptionException(offender,
                    $"Guardian {offender.Index}'s commitment hash d_{offender.Index} ({statements[o].CommitmentEquation}) does not match the (a, b) it revealed and the partial decryption it sent for {statements[o].Description}; the protocol halts.");
            }
        }

        return new CombinedProof
        {
            LagrangeCoefficients = lagrangeCoefficients,
            CommitmentA = commitmentA,
            CommitmentB = commitmentB,
            CombinedDecryptions = combined,
            Challenges = challenges,
        };
    }

    /// <summary>
    /// Round 3 for the participant at position <paramref name="self"/>: v_i = (u_i - c·w_i·s_i) mod q
    /// for every statement (eqs. 91-92, 102). Clears each u_i once used.
    /// </summary>
    public static IntegerModQ[] Respond(CombinedProof proof, int self, IntegerModQ[] nonces, IntegerModQ secretShare)
    {
        var lagrangeCoefficient = proof.LagrangeCoefficients[self];
        var responses = new IntegerModQ[nonces.Length];
        for (int o = 0; o < nonces.Length; o++)
        {
            var challenge = proof.Challenges[o] * lagrangeCoefficient;
            responses[o] = nonces[o] - challenge * secretShare;
            nonces[o] = default;
        }

        return responses;
    }

    /// <summary>v = Σ v_j mod q (eqs. 93, 103), per statement.</summary>
    public static IntegerModQ[] SumResponses(IntegerModQ[][] responded, int statements)
    {
        var sums = new IntegerModQ[statements];
        for (int o = 0; o < statements; o++)
        {
            IntegerModQ v = 0;
            for (int j = 0; j < responded.Length; j++)
            {
                v += responded[j][o];
            }

            sums[o] = v;
        }

        return sums;
    }

    /// <summary>
    /// The position of the first participant who sent a zero partial decryption, with the statement,
    /// or null. A zero has no inverse and makes the combined decryption zero; only a corrupt share can
    /// be zero.
    /// </summary>
    public static (int Participant, int Statement)? FindZeroPartialDecryption(ReceivedCommitment[] received)
    {
        for (int j = 0; j < received.Length; j++)
        {
            int zero = Array.FindIndex(received[j].PartialDecryptions, m => m == 0);
            if (zero >= 0)
            {
                return (j, zero);
            }
        }

        return null;
    }

    /// <summary>
    /// g^v·Y^c = a and X^v·M^c = b, Y being the public key (K or K-hat) and X the statement's base:
    /// Verification 10.2/10.3 (12.1/12.2) against the commitments the guardians revealed.
    /// </summary>
    public static bool ProofHolds(IntegerModP statementBase, IntegerModP combinedDecryption, IntegerModP publicKey, IntegerModP commitmentA, IntegerModP commitmentB, IntegerModQ challenge, IntegerModQ response)
    {
        var expectedA = MontgomeryModP.PowModP(EGParameters.G, response) * MontgomeryModP.PowModP(publicKey, challenge);
        if (expectedA != commitmentA)
        {
            return false;
        }

        var expectedB = MontgomeryModP.PowModP(statementBase, response) * MontgomeryModP.PowModP(combinedDecryption, challenge);
        return expectedB == commitmentB;
    }

    /// <summary>
    /// Guardian j's public key share g^{s_j} = ∏_l ∏_m Y_{l,m}^{j^m}, from every guardian's
    /// commitments to the key in question (K_{l,m} or K-hat_{l,m}).
    /// </summary>
    public static IntegerModP PublicKeyShare(IEnumerable<IReadOnlyList<IntegerModP>> commitments, GuardianIndex guardian)
    {
        // j^m is a small public exponent: BigInteger.ModPow scales with it and wins here.
        IntegerModP share = 1;
        foreach (var guardianCommitments in commitments)
        {
            for (int m = 0; m < guardianCommitments.Count; m++)
            {
                share *= IntegerModP.PowModP(guardianCommitments[m], BigInteger.Pow(guardian.Index, m));
            }
        }

        return share;
    }

    /// <summary>
    /// Note 3.7: for each participant j and each failing statement, recomputes
    /// a'_j = (g^{s_j})^{c_j}·g^{v_j} (eq. 94) and b'_j = X^{v_j}·M_j^{c_j} (eq. 95), with
    /// c_j = c·w_j, and returns the first guardian for which either differs from what it revealed.
    /// <paramref name="publicKeyShare"/> gives g^{s_j}. Runs only once the combined proof has failed.
    /// </summary>
    public static GuardianIndex? IdentifyInvalidShare<T>(
        GuardianIndex[] participants,
        T[] statements,
        bool[] failing,
        CombinedProof proof,
        ReceivedCommitment[] received,
        ReceivedReveal[] revealed,
        IntegerModQ[][] responded,
        Func<GuardianIndex, IntegerModP> publicKeyShare)
        where T : IDecryptionStatement
    {
        for (int j = 0; j < participants.Length; j++)
        {
            var share = publicKeyShare(participants[j]);
            for (int o = 0; o < statements.Length; o++)
            {
                if (!failing[o])
                {
                    continue;
                }

                var challenge = proof.Challenges[o] * proof.LagrangeCoefficients[j];
                var response = responded[j][o];
                var expectedA = MontgomeryModP.PowModP(share, challenge) * MontgomeryModP.PowModP(EGParameters.G, response);
                var expectedB = MontgomeryModP.PowModP(statements[o].Base, response) * MontgomeryModP.PowModP(received[j].PartialDecryptions[o], challenge);
                if (expectedA != revealed[j].CommitmentsA[o] || expectedB != revealed[j].CommitmentsB[o])
                {
                    return participants[j];
                }
            }
        }

        return null;
    }

    /// <summary>
    /// <paramref name="messages"/> in participant order, one per participant. A message from a
    /// guardian outside U, a second message from one guardian, or a participant with no message
    /// throws <see cref="TallyDecryptionException"/> naming the guardian.
    /// </summary>
    public static T[] InParticipantOrder<T>(IEnumerable<T> messages, Func<T, GuardianIndex> sender, GuardianIndex[] participants, string round)
        where T : class
    {
        var ordered = new T[participants.Length];
        foreach (var message in messages)
        {
            var from = sender(message);
            int position = Array.IndexOf(participants, from);
            if (position < 0)
            {
                throw new TallyDecryptionException(from, $"Guardian {from.Index} sent a {round} message but is not a participant in this decryption.");
            }

            if (ordered[position] is not null)
            {
                throw new TallyDecryptionException(from, $"Guardian {from.Index} sent more than one {round} message.");
            }

            ordered[position] = message;
        }

        for (int j = 0; j < participants.Length; j++)
        {
            if (ordered[j] is null)
            {
                throw new TallyDecryptionException(participants[j], $"Guardian {participants[j].Index} sent no {round} message; the protocol halts.");
            }
        }

        return ordered;
    }
}
