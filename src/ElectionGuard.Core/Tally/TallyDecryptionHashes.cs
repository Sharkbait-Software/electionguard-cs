using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Buffers;
using System.Buffers.Binary;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// The hashes of the §3.6.5 proof of correct tally decryption (§5.5.4 table, p.77), and the
/// Lagrange coefficients of eq. (85). The guardians, the administrator and Verification 10 all
/// compute them here, so that no two of them can encode an input differently.
/// </summary>
public static class TallyDecryptionHashes
{
    /// <summary>
    /// Eq. (88): the commitment hash
    /// d_i = H(H_E; 0x30, ind_c(Λ), ind_o(λ), i, A, B, a_i, b_i, M_i, U), with
    /// B1 = 0x30 ‖ b(ind_c, 4) ‖ b(ind_o, 4) ‖ b(i, 4) ‖ b(A, 512) ‖ b(B, 512) ‖ b(a_i, 512) ‖
    /// b(b_i, 512) ‖ b(M_i, 512) ‖ b(#U, 4) ‖ b(j_1, 4) ‖ ... ‖ b(j_#U, 4), len(B1) = 2577 + 4·#U.
    ///
    /// The spec does not say in which order U's indices j_1..j_#U are listed. They are listed in
    /// ascending order here, whatever order <paramref name="participants"/> is in, as the KAT oracle
    /// does (test/kat). The hash only travels between guardians, not into the election record.
    /// </summary>
    public static byte[] CommitmentHash(
        ExtendedBaseHash extendedBaseHash,
        int contestIndex,
        int optionIndex,
        GuardianIndex guardianIndex,
        IntegerModP a,
        IntegerModP b,
        IntegerModP commitmentA,
        IntegerModP commitmentB,
        IntegerModP partialDecryption,
        IReadOnlyCollection<GuardianIndex> participants)
    {
        var sorted = Canonical(participants);

        // Built in one pooled buffer rather than as an array of freshly allocated 512-byte arrays,
        // as ContestHash and RangeProofChallenge do; the bytes hashed are the same, which the
        // eq. (88) known-answer test pins.
        int length = CommitmentHashFixedLength + 4 * sorted.Length;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = 0x30;
            int offset = 1;
            WriteIndex(message, ref offset, contestIndex);
            WriteIndex(message, ref offset, optionIndex);
            WriteIndex(message, ref offset, guardianIndex.Index);
            WriteElement(message, ref offset, a);
            WriteElement(message, ref offset, b);
            WriteElement(message, ref offset, commitmentA);
            WriteElement(message, ref offset, commitmentB);
            WriteElement(message, ref offset, partialDecryption);
            WriteIndex(message, ref offset, sorted.Length);
            foreach (var participant in sorted)
            {
                WriteIndex(message, ref offset, participant.Index);
            }

            var digest = new byte[EGHash.HashBytes];
            EGHash.HashConcatenated(extendedBaseHash, message, digest);
            return digest;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Eq. (90) and Verification 10.B: the challenge
    /// c = H_q(H_E; 0x31, ind_c(Λ), ind_o(λ), A, B, a, b, M), with
    /// B1 = 0x31 ‖ b(ind_c, 4) ‖ b(ind_o, 4) ‖ b(A, 512) ‖ b(B, 512) ‖ b(a, 512) ‖ b(b, 512) ‖ b(M, 512),
    /// len(B1) = 2569. Neither U nor the public key is hashed.
    /// </summary>
    public static IntegerModQ Challenge(
        ExtendedBaseHash extendedBaseHash,
        int contestIndex,
        int optionIndex,
        IntegerModP a,
        IntegerModP b,
        IntegerModP commitmentA,
        IntegerModP commitmentB,
        IntegerModP combinedDecryption)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ChallengeLength);
        try
        {
            Span<byte> message = buffer.AsSpan(0, ChallengeLength);
            message[0] = 0x31;
            int offset = 1;
            WriteIndex(message, ref offset, contestIndex);
            WriteIndex(message, ref offset, optionIndex);
            WriteElement(message, ref offset, a);
            WriteElement(message, ref offset, b);
            WriteElement(message, ref offset, commitmentA);
            WriteElement(message, ref offset, commitmentB);
            WriteElement(message, ref offset, combinedDecryption);
            return EGHash.HashModQConcatenated(extendedBaseHash, message);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>len(B1) of eq. (88) without U's indices: 0x30, three 4-byte indices, five elements of Z_p, #U.</summary>
    private const int CommitmentHashFixedLength = 1 + 3 * sizeof(int) + 5 * IntegerModP.ByteLength + sizeof(int);

    /// <summary>len(B1) of eq. (90): 0x31, two 4-byte indices, five elements of Z_p (2569).</summary>
    private const int ChallengeLength = 1 + 2 * sizeof(int) + 5 * IntegerModP.ByteLength;

    /// <summary>b(value, 4): the same 4 big-endian bytes as <c>int.ToByteArray()</c>.</summary>
    private static void WriteIndex(Span<byte> message, ref int offset, int value)
    {
        BinaryPrimitives.WriteInt32BigEndian(message.Slice(offset, sizeof(int)), value);
        offset += sizeof(int);
    }

    /// <summary>b(value, 512): the same bytes as <see cref="IntegerModP.ToByteArray"/>.</summary>
    private static void WriteElement(Span<byte> message, ref int offset, IntegerModP value)
    {
        value.WriteBigEndian(message.Slice(offset, IntegerModP.ByteLength));
        offset += IntegerModP.ByteLength;
    }

    /// <summary>
    /// Eq. (85): w_i = (∏_{ℓ ∈ U \ {i}} ℓ / (ℓ - i)) mod q, for <paramref name="guardianIndex"/> in
    /// <paramref name="participants"/>. For |U| = 1 the product is empty and w_i = 1 (G28).
    /// </summary>
    public static IntegerModQ LagrangeCoefficient(GuardianIndex guardianIndex, IReadOnlyCollection<GuardianIndex> participants)
    {
        var others = participants.Where(x => x != guardianIndex).ToList();
        if (others.Count != participants.Count - 1)
        {
            throw new ArgumentException($"Guardian {guardianIndex.Index} is not among the participants.", nameof(participants));
        }

        var numerator = others.Select(x => new IntegerModQ(x.Index)).Product();
        var denominator = others.Select(x => new IntegerModQ(x.Index - guardianIndex.Index)).Product();

        return numerator / denominator;
    }

    /// <summary>
    /// <paramref name="participants"/> in ascending index order. Throws <see cref="ArgumentException"/>
    /// on a repeated index: U is a set.
    /// </summary>
    internal static GuardianIndex[] Canonical(IEnumerable<GuardianIndex> participants)
    {
        var sorted = participants.OrderBy(x => x.Index).ToArray();
        for (int j = 1; j < sorted.Length; j++)
        {
            if (sorted[j].Index == sorted[j - 1].Index)
            {
                throw new ArgumentException($"Guardian {sorted[j].Index} is listed more than once among the participants.", nameof(participants));
            }
        }

        return sorted;
    }

    /// <summary>
    /// Requires <paramref name="participants"/> to be a valid U for a decryption (§3.6.4): distinct
    /// indices in 1..n, at least k of them. Returns them in ascending order.
    /// </summary>
    internal static GuardianIndex[] RequireQuorum(IEnumerable<GuardianIndex> participants)
    {
        var sorted = Canonical(participants);
        int n = EGParameters.GuardianParameters.N;
        int k = EGParameters.GuardianParameters.K;
        if (sorted.Length < k)
        {
            throw new ArgumentException($"{sorted.Length} guardians cannot decrypt: a quorum of at least k = {k} is needed (§3.6.4).", nameof(participants));
        }

        if (sorted.Length > 0 && sorted[^1].Index > n)
        {
            throw new ArgumentException($"Guardian {sorted[^1].Index} is not one of the n = {n} guardians.", nameof(participants));
        }

        return sorted;
    }
}
