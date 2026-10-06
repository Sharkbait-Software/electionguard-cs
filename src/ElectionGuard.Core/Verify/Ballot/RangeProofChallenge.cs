using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// The arithmetic of the range-proof checks of Verifications 6 and 7, done in Montgomery form.
///
/// <see cref="Compute"/> recomputes the challenge of a range proof for one ciphertext (alpha, beta):
/// c = H(H_I; prefix, alpha, beta, a_0, b_0, ..., a_L, b_L) with a_j = g^v_j * alpha^c_j and
/// b_j = K^w_j * beta^c_j, w_j = v_j - j * c_j. The verifier needs a_j and b_j only as hash input, so
/// rather than producing each power as an <see cref="IntegerModP"/> and multiplying them with
/// BigInteger <c>*</c> and <c>% p</c> (about 16 us and 1.6 KB per product), both powers are left in
/// the same Montgomery representation - <see cref="Avx512Montgomery"/> digits where the hardware has
/// AVX-512F, <see cref="MontgomeryContext"/> limbs otherwise - multiplied there, and converted out
/// once, straight into the hash buffer. alpha^c_j and beta^c_j come from the shared-squaring
/// multi-exponentiation; g^v_j and K^w_j from their <see cref="PowRadix"/> tables when those were
/// precomputed in the matching representation, and from the table-free exponentiation otherwise.
///
/// <see cref="Aggregate"/> computes the contest aggregate ciphertext of Verification 7, the product
/// of a contest's selection ciphertexts, the same way.
///
/// This changes how the numbers are computed, not which numbers: the hash input is byte-for-byte
/// what the straightforward construction builds, and unit tests pin that on both engines, with and
/// without tables. It performs no validation; the verifications check the proofs' challenges and
/// responses before calling it, so the exceptions they raise are unchanged. The one overload that
/// reports anything else, <see cref="Compute(byte[], ReadOnlySpan{byte}, IntegerModP, IntegerModP, ReadOnlySpan{ChallengeResponsePair}, out bool)"/>,
/// also says whether alpha and beta lie in Z_p^r, read off the squaring chains it walks anyway, and
/// leaves acting on that to the caller.
///
/// An instance is immutable and holds no working state, so one may be shared by parallel callers.
/// It is meant to be built once per ballot, so the table lookups happen once rather than once per
/// exponentiation.
/// </summary>
internal sealed class RangeProofChallenge
{
    private const int ModPBytes = IntegerModP.ByteLength;

    /// <summary>
    /// Single-value buffers are stack-allocated up to this width, which covers both representations
    /// of the spec's p: 64 scalar limbs or 80 AVX-512 digits.
    /// </summary>
    private const int MaxStackAllocWidth = Avx512Montgomery.Lanes;

    private readonly MontgomeryContext _context;
    private readonly Avx512Montgomery? _engine;
    private readonly BigInteger _g;
    private readonly BigInteger _k;
    private readonly PowRadix? _gTable;
    private readonly PowRadix? _kTable;

    public RangeProofChallenge(IntegerModP voteEncryptionKey)
        : this(voteEncryptionKey, allowAvx512: true)
    {
    }

    /// <summary>
    /// With <paramref name="allowAvx512"/> false the scalar representation is used even where
    /// AVX-512F is available, so that tests can check it on every machine.
    /// </summary>
    internal RangeProofChallenge(IntegerModP voteEncryptionKey, bool allowAvx512)
    {
        _context = MontgomeryContext.Current;
        _engine = allowAvx512 && Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine) ? engine : null;
        _g = new IntegerModP(EGParameters.G).ToBigInteger();
        _k = voteEncryptionKey.ToBigInteger();
        _gTable = MatchingTable(_g);
        _kTable = MatchingTable(_k);
    }

    /// <summary>Whether the AVX-512 representation is in use, for tests.</summary>
    internal bool UsesAvx512 => _engine is not null;

    /// <summary>Whether g and K have tables in the representation in use, for tests.</summary>
    internal bool UsesTables => _gTable is not null && _kTable is not null;

    /// <summary>
    /// The registered table for <paramref name="basis"/>, if there is one in the representation this
    /// instance computes in. A table's representation is fixed when it is built, so a table built
    /// for AVX-512 is no use to a scalar computation, or the reverse; that basis then goes table-free.
    /// </summary>
    private PowRadix? MatchingTable(BigInteger basis)
    {
        return PowRadixRegistry.TryGet(basis, out PowRadix table) && table.UsesAvx512 == (_engine is not null)
            ? table
            : null;
    }

    /// <summary>
    /// Computes H(key; prefix, alpha, beta, a_0, b_0, ..., a_L, b_L) mod q, where L + 1 is the
    /// number of proofs. <paramref name="prefix"/> is everything hashed before alpha.
    /// </summary>
    public IntegerModQ Compute(
        byte[] key,
        ReadOnlySpan<byte> prefix,
        IntegerModP alpha,
        IntegerModP beta,
        ReadOnlySpan<ChallengeResponsePair> proofs)
    {
        return Compute(key, prefix, alpha, beta, proofs, firstValue: 0);
    }

    /// <summary>
    /// <see cref="Compute(byte[], ReadOnlySpan{byte}, IntegerModP, IntegerModP, ReadOnlySpan{ChallengeResponsePair})"/>
    /// for a proof over the consecutive values firstValue, firstValue + 1, ...: proof j stands for
    /// the value firstValue + j, so w_j = v_j - (firstValue + j) * c_j. Note 3.4 allows a range proof
    /// over any small set of values; a single proof with <paramref name="firstValue"/> = L proves
    /// that (alpha, beta) encrypts exactly L.
    /// </summary>
    public IntegerModQ Compute(
        byte[] key,
        ReadOnlySpan<byte> prefix,
        IntegerModP alpha,
        IntegerModP beta,
        ReadOnlySpan<ChallengeResponsePair> proofs,
        int firstValue)
    {
        return _engine is not null
            ? Compute(new Avx512MontgomeryArithmetic(_engine), key, prefix, alpha, beta, proofs, firstValue, checkMembership: false, out _)
            : Compute(new ScalarMontgomeryArithmetic(_context), key, prefix, alpha, beta, proofs, firstValue, checkMembership: false, out _);
    }

    /// <summary>
    /// <see cref="Compute(byte[], ReadOnlySpan{byte}, IntegerModP, IntegerModP, ReadOnlySpan{ChallengeResponsePair})"/>,
    /// also deciding exactly whether alpha and beta are both in Z_p^r (Verifications 6.A and 7.A),
    /// from the squaring chains that raise them to the challenges. See
    /// <see cref="MontgomeryModP.PowVariableTimeMontgomeryCheckingMembership"/>. Only for an active q
    /// that <see cref="CanCheckMembership"/> accepts.
    /// </summary>
    public IntegerModQ Compute(
        byte[] key,
        ReadOnlySpan<byte> prefix,
        IntegerModP alpha,
        IntegerModP beta,
        ReadOnlySpan<ChallengeResponsePair> proofs,
        out bool componentsAreMembers)
    {
        return _engine is not null
            ? Compute(new Avx512MontgomeryArithmetic(_engine), key, prefix, alpha, beta, proofs, firstValue: 0, checkMembership: true, out componentsAreMembers)
            : Compute(new ScalarMontgomeryArithmetic(_context), key, prefix, alpha, beta, proofs, firstValue: 0, checkMembership: true, out componentsAreMembers);
    }

    /// <summary>Whether the active q allows the membership-checking overload of Compute.</summary>
    public static bool CanCheckMembership => MontgomeryModP.TryGetChainMembershipShape(out _);

    private IntegerModQ Compute<TArithmetic>(
        TArithmetic arithmetic,
        byte[] key,
        ReadOnlySpan<byte> prefix,
        IntegerModP alpha,
        IntegerModP beta,
        ReadOnlySpan<ChallengeResponsePair> proofs,
        int firstValue,
        bool checkMembership,
        out bool componentsAreMembers)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        int m = proofs.Length;
        int s = arithmetic.Width;
        int length = prefix.Length + ModPBytes * (2 + 2 * m);

        byte[] messageArray = ArrayPool<byte>.Shared.Rent(length);
        ulong[] powersArray = ArrayPool<ulong>.Shared.Rent(Math.Max(1, 2 * m * s));
        IntegerModQ[] challengesArray = ArrayPool<IntegerModQ>.Shared.Rent(Math.Max(1, m));
        try
        {
            Span<IntegerModQ> challenges = challengesArray.AsSpan(0, m);
            for (int j = 0; j < m; j++)
            {
                challenges[j] = proofs[j].Challenge;
            }

            // alpha and beta are each raised to every challenge c_j. The challenges are public proof
            // data, so the verifier-only variable-time path, which shares one squaring chain across
            // all of a base's exponents, is safe here.
            Span<ulong> alphaPowers = powersArray.AsSpan(0, m * s);
            Span<ulong> betaPowers = powersArray.AsSpan(m * s, m * s);
            if (checkMembership)
            {
                bool alphaIsMember = MontgomeryModP.PowVariableTimeMontgomeryCheckingMembership(alpha, challenges, alphaPowers, arithmetic);
                bool betaIsMember = MontgomeryModP.PowVariableTimeMontgomeryCheckingMembership(beta, challenges, betaPowers, arithmetic);
                componentsAreMembers = alphaIsMember && betaIsMember;
            }
            else
            {
                MontgomeryModP.PowVariableTimeMontgomery(alpha.ToBigInteger(), challenges, alphaPowers, arithmetic);
                MontgomeryModP.PowVariableTimeMontgomery(beta.ToBigInteger(), challenges, betaPowers, arithmetic);
                componentsAreMembers = false;
            }

            // g and K in Montgomery form, needed only for a base without a matching table.
            Span<ulong> gMontgomery = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            Span<ulong> kMontgomery = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            Span<ulong> product = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
            gMontgomery = gMontgomery[..s];
            kMontgomery = kMontgomery[..s];
            product = product[..s];
            if (_gTable is null)
            {
                arithmetic.ToMontgomery(_g, gMontgomery);
            }

            if (_kTable is null)
            {
                arithmetic.ToMontgomery(_k, kMontgomery);
            }

            Span<byte> exponentBytes = stackalloc byte[IntegerModQ.ByteLength];

            Span<byte> message = messageArray.AsSpan(0, length);
            prefix.CopyTo(message);
            int offset = prefix.Length;
            alpha.WriteBigEndian(message.Slice(offset, ModPBytes));
            offset += ModPBytes;
            beta.WriteBigEndian(message.Slice(offset, ModPBytes));
            offset += ModPBytes;

            for (int j = 0; j < m; j++)
            {
                ChallengeResponsePair proof = proofs[j];

                // a_j = g^v_j * alpha^c_j
                FixedBasePow(arithmetic, _gTable, gMontgomery, proof.Response, exponentBytes, product);
                arithmetic.Multiply(product, alphaPowers.Slice(j * s, s), product);
                arithmetic.WriteBigEndian(product, message.Slice(offset, ModPBytes));
                offset += ModPBytes;

                // b_j = K^w_j * beta^c_j, w_j = v_j - j * c_j (the value of proof j is firstValue + j)
                IntegerModQ w = proof.Response - (firstValue + j) * proof.Challenge;
                FixedBasePow(arithmetic, _kTable, kMontgomery, w, exponentBytes, product);
                arithmetic.Multiply(product, betaPowers.Slice(j * s, s), product);
                arithmetic.WriteBigEndian(product, message.Slice(offset, ModPBytes));
                offset += ModPBytes;
            }

            return EGHash.HashModQConcatenated(key, message);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(messageArray);
            ArrayPool<ulong>.Shared.Return(powersArray);
            ArrayPool<IntegerModQ>.Shared.Return(challengesArray, clearArray: true);
        }
    }

    /// <summary>
    /// basis^exponent in Montgomery form: from the table when there is one, and otherwise by the
    /// same table-free exponentiation <see cref="MontgomeryModP.PowModP(BigInteger, IntegerModQ)"/>
    /// uses, over the exponent padded to the full width of Z_q.
    /// </summary>
    private static void FixedBasePow<TArithmetic>(
        TArithmetic arithmetic,
        PowRadix? table,
        ReadOnlySpan<ulong> montgomeryBasis,
        IntegerModQ exponent,
        Span<byte> exponentBytes,
        Span<ulong> result)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        if (table is not null)
        {
            table.PowMontgomeryInto(exponent, result);
            return;
        }

        exponent.WriteBigEndian(exponentBytes);
        arithmetic.PowMontgomeryInto(montgomeryBasis, exponentBytes, result);
    }

    /// <summary>
    /// The aggregate ciphertext of a contest, (prod alpha_i, prod beta_i) over its selections, as
    /// <c>Select(x =&gt; x.Alpha).Product()</c> computes it but in Montgomery form, entering it once
    /// per value and leaving it once per product. An empty list throws, as Product does.
    /// </summary>
    public (IntegerModP Alpha, IntegerModP Beta) Aggregate(IReadOnlyList<EncryptedValueWithProofs> ciphertexts)
    {
        if (ciphertexts.Count == 0)
        {
            throw new InvalidOperationException("Sequence contains no elements");
        }

        return _engine is not null
            ? Aggregate(new Avx512MontgomeryArithmetic(_engine), ciphertexts)
            : Aggregate(new ScalarMontgomeryArithmetic(_context), ciphertexts);
    }

    private static (IntegerModP Alpha, IntegerModP Beta) Aggregate<TArithmetic>(TArithmetic arithmetic, IReadOnlyList<EncryptedValueWithProofs> ciphertexts)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        if (ciphertexts.Count == 1)
        {
            // Nothing to multiply, so no reason to enter Montgomery form.
            return (ciphertexts[0].Alpha, ciphertexts[0].Beta);
        }

        int s = arithmetic.Width;
        Span<ulong> alpha = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
        Span<ulong> beta = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
        Span<ulong> factor = s <= MaxStackAllocWidth ? stackalloc ulong[MaxStackAllocWidth] : new ulong[s];
        alpha = alpha[..s];
        beta = beta[..s];
        factor = factor[..s];

        arithmetic.ToMontgomery(ciphertexts[0].Alpha.ToBigInteger(), alpha);
        arithmetic.ToMontgomery(ciphertexts[0].Beta.ToBigInteger(), beta);
        for (int i = 1; i < ciphertexts.Count; i++)
        {
            arithmetic.ToMontgomery(ciphertexts[i].Alpha.ToBigInteger(), factor);
            arithmetic.Multiply(alpha, factor, alpha);
            arithmetic.ToMontgomery(ciphertexts[i].Beta.ToBigInteger(), factor);
            arithmetic.Multiply(beta, factor, beta);
        }

        return (new IntegerModP(arithmetic.FromMontgomery(alpha)), new IntegerModP(arithmetic.FromMontgomery(beta)));
    }

    /// <summary>
    /// The ciphertexts of a contest's selection-limit relations (Verification 7 with the
    /// supplemental fields of §3.3.9; user decision Q15), from the encryption of s + w (the product
    /// of <paramref name="sumTerms"/>, the options and the write-in count) and the declared fields
    /// (null when not declared), with L = <paramref name="limit"/>:
    /// <list type="bullet">
    /// <item>Limit: s + w + L*overvote + undervote indicator (the selection-limit proof).</item>
    /// <item>Difference: s + w + L*overvote + u, when u is declared (null otherwise).</item>
    /// <item>NullVote: s + w + L*null, when the null-vote indicator is declared (null otherwise).</item>
    /// </list>
    /// Computed in one Montgomery representation: every input is converted in once, the power of
    /// the overvote indicator is shared by the first two, and each output is converted out once.
    /// L is public and small, so the powers are short windows over its own bits. With no field
    /// declared, Limit is <see cref="Aggregate"/> of the terms.
    /// </summary>
    public ContestRelationCiphertexts RelationCiphertexts(
        IReadOnlyList<EncryptedValueWithProofs> sumTerms,
        EncryptedValueWithProofs? overvote,
        EncryptedValueWithProofs? undervote,
        EncryptedValueWithProofs? difference,
        EncryptedValueWithProofs? nullVote,
        int limit)
    {
        if (overvote is null && undervote is null && difference is null && nullVote is null)
        {
            return new ContestRelationCiphertexts(Aggregate(sumTerms), null, null);
        }

        if (sumTerms.Count == 0)
        {
            throw new InvalidOperationException("Sequence contains no elements");
        }

        return _engine is not null
            ? RelationCiphertexts(new Avx512MontgomeryArithmetic(_engine), sumTerms, overvote, undervote, difference, nullVote, limit)
            : RelationCiphertexts(new ScalarMontgomeryArithmetic(_context), sumTerms, overvote, undervote, difference, nullVote, limit);
    }

    private static ContestRelationCiphertexts RelationCiphertexts<TArithmetic>(
        TArithmetic arithmetic,
        IReadOnlyList<EncryptedValueWithProofs> sumTerms,
        EncryptedValueWithProofs? overvote,
        EncryptedValueWithProofs? undervote,
        EncryptedValueWithProofs? difference,
        EncryptedValueWithProofs? nullVote,
        int limit)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        int s = arithmetic.Width;
        Span<ulong> buffer = s <= MaxStackAllocWidth ? stackalloc ulong[6 * MaxStackAllocWidth] : new ulong[6 * s];
        Span<ulong> sumAlpha = buffer.Slice(0, s);
        Span<ulong> sumBeta = buffer.Slice(s, s);
        Span<ulong> factor = buffer.Slice(2 * s, s);
        Span<ulong> power = buffer.Slice(3 * s, s);
        Span<ulong> alpha = buffer.Slice(4 * s, s);
        Span<ulong> beta = buffer.Slice(5 * s, s);

        // s + w
        arithmetic.ToMontgomery(sumTerms[0].Alpha.ToBigInteger(), sumAlpha);
        arithmetic.ToMontgomery(sumTerms[0].Beta.ToBigInteger(), sumBeta);
        for (int i = 1; i < sumTerms.Count; i++)
        {
            arithmetic.ToMontgomery(sumTerms[i].Alpha.ToBigInteger(), factor);
            arithmetic.Multiply(sumAlpha, factor, sumAlpha);
            arithmetic.ToMontgomery(sumTerms[i].Beta.ToBigInteger(), factor);
            arithmetic.Multiply(sumBeta, factor, sumBeta);
        }

        Span<byte> limitBytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(limitBytes, limit);
        ReadOnlySpan<byte> exponent = limitBytes[Math.Min(BitOperations.LeadingZeroCount((uint)limit) / 8, sizeof(int) - 1)..];

        // s + w + L*overvote, in place in the sum: both the limit and the difference relation
        // carry the term, and the null-vote relation, which does not, is computed first.
        (IntegerModP Alpha, IntegerModP Beta)? nullVoteCiphertext = null;
        if (nullVote is not null)
        {
            MultiplyPower(arithmetic, sumAlpha, nullVote.Alpha, exponent, factor, power, alpha);
            MultiplyPower(arithmetic, sumBeta, nullVote.Beta, exponent, factor, power, beta);
            nullVoteCiphertext = (new IntegerModP(arithmetic.FromMontgomery(alpha)), new IntegerModP(arithmetic.FromMontgomery(beta)));
        }

        if (overvote is not null)
        {
            MultiplyPower(arithmetic, sumAlpha, overvote.Alpha, exponent, factor, power, sumAlpha);
            MultiplyPower(arithmetic, sumBeta, overvote.Beta, exponent, factor, power, sumBeta);
        }

        (IntegerModP Alpha, IntegerModP Beta)? differenceCiphertext = null;
        if (difference is not null)
        {
            arithmetic.ToMontgomery(difference.Alpha.ToBigInteger(), factor);
            arithmetic.Multiply(sumAlpha, factor, alpha);
            arithmetic.ToMontgomery(difference.Beta.ToBigInteger(), factor);
            arithmetic.Multiply(sumBeta, factor, beta);
            differenceCiphertext = (new IntegerModP(arithmetic.FromMontgomery(alpha)), new IntegerModP(arithmetic.FromMontgomery(beta)));
        }

        if (undervote is not null)
        {
            arithmetic.ToMontgomery(undervote.Alpha.ToBigInteger(), factor);
            arithmetic.Multiply(sumAlpha, factor, sumAlpha);
            arithmetic.ToMontgomery(undervote.Beta.ToBigInteger(), factor);
            arithmetic.Multiply(sumBeta, factor, sumBeta);
        }

        var limitCiphertext = (new IntegerModP(arithmetic.FromMontgomery(sumAlpha)), new IntegerModP(arithmetic.FromMontgomery(sumBeta)));
        return new ContestRelationCiphertexts(limitCiphertext, differenceCiphertext, nullVoteCiphertext);
    }

    /// <summary>result = accumulator * value^exponent, all in Montgomery form; result may alias accumulator.</summary>
    private static void MultiplyPower<TArithmetic>(
        TArithmetic arithmetic,
        ReadOnlySpan<ulong> accumulator,
        IntegerModP value,
        ReadOnlySpan<byte> exponentBigEndian,
        Span<ulong> factor,
        Span<ulong> power,
        Span<ulong> result)
        where TArithmetic : struct, IMontgomeryArithmetic
    {
        arithmetic.ToMontgomery(value.ToBigInteger(), factor);
        arithmetic.PowMontgomeryInto(factor, exponentBigEndian, power);
        arithmetic.Multiply(accumulator, power, result);
    }

    /// <summary>Writes a 4-byte big-endian integer, as <c>int.ToByteArray()</c> produces.</summary>
    public static void WriteIndex(Span<byte> destination, int index)
    {
        BinaryPrimitives.WriteInt32BigEndian(destination, index);
    }
}

/// <summary>
/// The ciphertexts of a contest's selection-limit relations; see
/// <see cref="RangeProofChallenge.RelationCiphertexts"/>. Difference and NullVote are null when the
/// contest does not declare the field.
/// </summary>
internal readonly record struct ContestRelationCiphertexts(
    (IntegerModP Alpha, IntegerModP Beta) Limit,
    (IntegerModP Alpha, IntegerModP Beta)? Difference,
    (IntegerModP Alpha, IntegerModP Beta)? NullVote);
