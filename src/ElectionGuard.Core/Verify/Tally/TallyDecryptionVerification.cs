using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using System.Numerics;

namespace ElectionGuard.Core.Verify.Tally;

/// <summary>
/// Verification 10 (Correctness of tally decryptions), §3.6.5 p.49 and §6.2.5 p.89.
///
/// For each option λ in each contest Λ of the decrypted tally, with (A, B) the option's encrypted
/// aggregate and (T, c, v, t) its published decryption and proof, the verifier computes
/// (10.1) M = B·T^-1, (10.2) a = g^v·K^c and (10.3) b = A^v·M^c, and confirms
/// (10.A) v ∈ Z_q, (10.B) c = H_q(H_E; 0x31, ind_c(Λ), ind_o(λ), A, B, a, b, M) (eq. 90), and
/// (10.C) T = K^t.
///
/// Why this catches a dishonest guardian: one that sends M_i' = M_i·K^(-δ/w_i) in place of its
/// partial decryption would shift t by δ, and the Lagrange coefficients w_i are public. But then
/// b = A^u·K^(-δc) for the true A^u the guardians committed to, the recomputed hash differs from c,
/// and 10.B fails. A count published without a matching T fails 10.C.
/// </summary>
public class TallyDecryptionVerification
{
    /// <summary>
    /// Verifies every option of <paramref name="decryptedTally"/> against its aggregate in
    /// <paramref name="encryptedTally"/>, on up to <paramref name="maxDegreeOfParallelism"/> threads
    /// (-1, the default, for no limit). H_E, K and the indices ind_c, ind_o come from
    /// <paramref name="encryptionRecord"/> (its manifest), never from the tally. Throws
    /// <see cref="VerificationFailedException"/>:
    /// <list type="bullet">
    /// <item>"10.structure" if a contest or option of the decrypted tally is not in the manifest or
    /// has no encrypted aggregate (the proof cannot be checked without ind_c, ind_o, A and B), or
    /// if its published index differs from the manifest's. Verification 11 checks the labels
    /// themselves.</item>
    /// <item>"10.A" if any response v is not in Z_q (checked for every option first).</item>
    /// <item>"10.B" or "10.C" for the first option, in manifest order, that fails one. An option
    /// whose T is 0 has no M to recompute and fails 10.C: no t has K^t = 0.</item>
    /// </list>
    /// The values checked are all public, so the variable-time batch inversion of the T values is
    /// safe here.
    /// </summary>
    public void Verify(EncryptionRecord encryptionRecord, EncryptedTally encryptedTally, DecryptedTally decryptedTally, int maxDegreeOfParallelism = -1)
    {
        var options = Options(encryptionRecord.Manifest, encryptedTally, decryptedTally);

        // 10.A. An IntegerModQ holds only values in [0, q), and the strict decoders reject anything
        // else (G23), so this is an invariant; it is checked as Verification 10 states it.
        foreach (var option in options)
        {
            if (!IsInZq(option.Decrypted.Response))
            {
                throw new VerificationFailedException("10.A", $"Tally decryption verification failed for contest {option.ContestId}, option {option.ChoiceId}: the response v is not in Z_q.");
            }
        }

        var extendedBaseHash = encryptionRecord.ExtendedBaseHash;
        var voteEncryptionKey = encryptionRecord.ElectionPublicKeys.VoteEncryptionKey;

        // (10.1) needs T^-1. Invert the nonzero values in one batch; a zero T fails 10.C below.
        var nonzero = Enumerable.Range(0, options.Length).Where(o => options[o].Decrypted.T != 0).ToArray();
        var inverted = TallyAdmin.InvertAll(nonzero.Select(o => options[o].Decrypted.T).ToArray());
        var inverses = new IntegerModP?[options.Length];
        for (int i = 0; i < nonzero.Length; i++)
        {
            inverses[nonzero[i]] = inverted[i];
        }

        var failures = new string?[options.Length];
        Parallel.For(0, options.Length, new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism }, o =>
        {
            var option = options[o];
            var decrypted = option.Decrypted;
            if (inverses[o] is not { } inverse)
            {
                failures[o] = "10.C";
                return;
            }

            var m = option.B * inverse;
            var a = MontgomeryModP.PowModP(EGParameters.G, decrypted.Response) * MontgomeryModP.PowModP(voteEncryptionKey, decrypted.Challenge);
            var b = MontgomeryModP.PowModP(option.A, decrypted.Response) * MontgomeryModP.PowModP(m, decrypted.Challenge);
            var challenge = TallyDecryptionHashes.Challenge(extendedBaseHash, option.ContestIndex, option.ChoiceIndex, option.A, option.B, a, b, m);
            if (challenge != decrypted.Challenge)
            {
                failures[o] = "10.B";
                return;
            }

            // t is a small public exponent: BigInteger.ModPow scales with it and wins here.
            if (decrypted.VoteCount < 0 || IntegerModP.PowModP(voteEncryptionKey, new BigInteger(decrypted.VoteCount)) != decrypted.T)
            {
                failures[o] = "10.C";
            }
        });

        for (int o = 0; o < options.Length; o++)
        {
            switch (failures[o])
            {
                case "10.B":
                    throw new VerificationFailedException("10.B", $"Tally decryption verification failed for contest {options[o].ContestId}, option {options[o].ChoiceId}: the challenge c is not H_q(H_E; 0x31, ind_c, ind_o, A, B, a, b, M) (eq. 90).");
                case "10.C":
                    throw new VerificationFailedException("10.C", $"Tally decryption verification failed for contest {options[o].ContestId}, option {options[o].ChoiceId}: T is not K^t for the published count t = {options[o].Decrypted.VoteCount}.");
            }
        }
    }

    private sealed record Option(string ContestId, string ChoiceId, int ContestIndex, int ChoiceIndex, IntegerModP A, IntegerModP B, DecryptedTally.DecryptedChoice Decrypted);

    /// <summary>The decrypted tally's options in manifest order, each with its manifest indices and (A, B).</summary>
    private static Option[] Options(Manifest manifest, EncryptedTally encryptedTally, DecryptedTally decryptedTally)
    {
        var options = new List<Option>();
        foreach (var (contestId, decryptedContest) in decryptedTally.Contests)
        {
            var contest = manifest.Contests.FirstOrDefault(x => x.Id == contestId)
                ?? throw new VerificationFailedException("10.structure", $"Tally decryption verification failed: contest {contestId} is not in the manifest, so ind_c is undefined.");
            if (decryptedContest.ContestIndex != contest.Index)
            {
                throw new VerificationFailedException("10.structure", $"Tally decryption verification failed: contest {contestId} is published with index {decryptedContest.ContestIndex}, but the manifest gives it {contest.Index}.");
            }

            if (!encryptedTally.Contests.TryGetValue(contestId, out var aggregateContest))
            {
                throw new VerificationFailedException("10.structure", $"Tally decryption verification failed: the encrypted tally has no aggregate for contest {contestId}.");
            }

            foreach (var (choiceId, decryptedChoice) in decryptedContest.Choices)
            {
                // An option or a declared supplemental field (§3.3.9), each under its own index.
                var choice = contest.VerifiableFields().FirstOrDefault(x => x.Id == choiceId)
                    ?? throw new VerificationFailedException("10.structure", $"Tally decryption verification failed: option {choiceId} is not in manifest contest {contestId}, so ind_o is undefined.");
                if (decryptedChoice.ChoiceIndex != choice.Index)
                {
                    throw new VerificationFailedException("10.structure", $"Tally decryption verification failed: option {choiceId} of contest {contestId} is published with index {decryptedChoice.ChoiceIndex}, but the manifest gives it {choice.Index}.");
                }

                if (!aggregateContest.Choices.TryGetValue(choiceId, out var aggregate))
                {
                    throw new VerificationFailedException("10.structure", $"Tally decryption verification failed: the encrypted tally has no aggregate for option {choiceId} of contest {contestId}.");
                }

                options.Add(new Option(contestId, choiceId, contest.Index, choice.Index, aggregate.A, aggregate.B, decryptedChoice));
            }
        }

        return options.OrderBy(x => x.ContestIndex).ThenBy(x => x.ChoiceIndex).ToArray();
    }

    private static bool IsInZq(IntegerModQ value)
    {
        BigInteger x = value.ToBigInteger();
        return x >= 0 && x < EGParameters.Q;
    }
}
