using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.Verify.Ballot;

/// <summary>
/// Builds a valid range proof (§3.3.5) in which every simulated branch has challenge c_j = 0 and
/// response v_j = 0. Z_q is {x : 0 &lt;= x &lt; q}, so a conformant verifier must accept it: 6.B/6.C
/// and 7.B/7.C ask only that each c_j and v_j be in Z_q (G33). Another implementation is free to
/// simulate a branch this way, and then a_j = g^0 * alpha^0 = 1 and b_j = K^0 * beta^0 = 1.
/// </summary>
internal static class ZeroChallengeRangeProof
{
    /// <summary>
    /// Proves that (alpha, beta) = (g^xi, K^(value + xi)) encrypts <paramref name="value"/> in
    /// [0, <paramref name="limit"/>]. <paramref name="indexPrefix"/> is the hashed prefix after
    /// 0x24: the contest index, and for a selection the choice index.
    /// </summary>
    public static ChallengeResponsePair[] Prove(
        IntegerModP alpha,
        IntegerModP beta,
        IntegerModQ nonce,
        int value,
        int limit,
        IntegerModP voteEncryptionKey,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        params int[] indexPrefix)
    {
        IntegerModP g = new(EGParameters.G);
        IntegerModQ u = ElectionGuardRandom.GetIntegerModQ();

        var bytes = new List<byte[]> { new byte[] { 0x24 } };
        bytes.AddRange(indexPrefix.Select(index => index.ToByteArray()));
        bytes.Add(alpha);
        bytes.Add(beta);
        for (int j = 0; j <= limit; j++)
        {
            // The real branch commits honestly; a simulated one with c_j = v_j = 0 commits to 1, 1.
            bytes.Add(j == value ? IntegerModP.PowModP(g, u) : new IntegerModP(1));
            bytes.Add(j == value ? IntegerModP.PowModP(voteEncryptionKey, u) : new IntegerModP(1));
        }

        // The simulated challenges sum to zero, so the real one is the whole challenge c.
        IntegerModQ c = EGHash.HashModQ(selectionEncryptionIdentifierHash, bytes.ToArray());

        var proofs = new ChallengeResponsePair[limit + 1];
        for (int j = 0; j <= limit; j++)
        {
            proofs[j] = j == value
                ? new ChallengeResponsePair { Challenge = c, Response = u - c * nonce }
                : new ChallengeResponsePair { Challenge = new IntegerModQ(0), Response = new IntegerModQ(0) };
        }

        return proofs;
    }
}
