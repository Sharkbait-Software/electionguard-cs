using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Verify.Ballot;

/// <summary>
/// Builds a range proof that passes every check of Verification 6 or 7 except 6.A / 7.A, for a
/// ciphertext whose alpha has been replaced by -alpha = p - alpha, which is outside Z_p^r (its
/// order-2 component is -1). Only such a ballot shows whether the subgroup test is applied at all:
/// tampering a component without re-proving also breaks the proof, so a verifier that skipped the
/// subgroup test would still reject it, with 6.D or 7.D.
///
/// This is the attack the subgroup checks exist to stop. The verifier computes
/// a_j = g^v_j * (-alpha)^c_j = g^v_j * alpha^c_j * (-1)^c_j, so an honest-style proof still checks
/// whenever every challenge c_j is even. The simulated challenges are chosen even, and the real one,
/// which the hash fixes, is even half the time, so a few attempts suffice. b_j does not involve
/// alpha and checks as usual. The prover must know the ciphertext's nonce, which fixtures keep.
/// </summary>
internal static class NonMemberRangeProof
{
    /// <summary>
    /// Proves that (-alpha, beta) encrypts <paramref name="value"/> in [0, <paramref name="limit"/>],
    /// given the nonce xi with alpha = g^xi and beta = K^(value + xi). <paramref name="indexPrefix"/>
    /// is the hashed prefix after 0x24: the contest index, and for a selection the choice index.
    /// </summary>
    public static (IntegerModP NegatedAlpha, ChallengeResponsePair[] Proofs) Forge(
        IntegerModP alpha,
        IntegerModP beta,
        IntegerModQ nonce,
        int value,
        int limit,
        IntegerModP voteEncryptionKey,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        params int[] indexPrefix)
    {
        IntegerModP negatedAlpha = new(EGParameters.P - alpha.ToBigInteger());
        IntegerModP g = new(EGParameters.G);

        for (int attempt = 0; attempt < 200; attempt++)
        {
            var u = new IntegerModQ[limit + 1];
            var simulated = new IntegerModQ?[limit + 1];
            var bytes = new List<byte[]> { new byte[] { 0x24 } };
            bytes.AddRange(indexPrefix.Select(index => index.ToByteArray()));
            bytes.Add(negatedAlpha);
            bytes.Add(beta);

            for (int j = 0; j <= limit; j++)
            {
                u[j] = ElectionGuardRandom.GetIntegerModQ();
                IntegerModP a = IntegerModP.PowModP(g, u[j]);
                IntegerModP b;
                if (j == value)
                {
                    b = IntegerModP.PowModP(voteEncryptionKey, u[j]);
                }
                else
                {
                    IntegerModQ cj = EvenNonZero(ElectionGuardRandom.GetIntegerModQ());
                    simulated[j] = cj;
                    b = IntegerModP.PowModP(voteEncryptionKey, u[j] + (value - j) * cj);
                }

                bytes.Add(a);
                bytes.Add(b);
            }

            IntegerModQ c = EGHash.HashModQ(selectionEncryptionIdentifierHash, bytes.ToArray());
            IntegerModQ real = c;
            foreach (IntegerModQ? cj in simulated)
            {
                if (cj is { } challenge)
                {
                    real -= challenge;
                }
            }

            if (real.ToBigInteger().IsZero || !real.ToBigInteger().IsEven)
            {
                continue;
            }

            var proofs = new ChallengeResponsePair[limit + 1];
            for (int j = 0; j <= limit; j++)
            {
                IntegerModQ challenge = simulated[j] ?? real;
                proofs[j] = new ChallengeResponsePair { Challenge = challenge, Response = u[j] - challenge * nonce };
            }

            return (negatedAlpha, proofs);
        }

        throw new InvalidOperationException("No attempt produced an even real challenge.");
    }

    private static IntegerModQ EvenNonZero(IntegerModQ value)
    {
        BigInteger v = value.ToBigInteger();
        if (!v.IsEven)
        {
            v -= 1;
        }

        return new IntegerModQ(v.IsZero ? new BigInteger(2) : v);
    }
}
