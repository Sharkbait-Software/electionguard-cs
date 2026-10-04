using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace ElectionGuard.Core.Crypto;

internal sealed partial class Avx512Montgomery
{
    /// <summary>
    /// The body of <see cref="Multiply"/>, with the accumulator unrolled into named locals so that
    /// it can stay in registers. See the class remarks for the algorithm and its bounds.
    ///
    /// The unrolling is written out by hand: there are <see cref="Vectors"/> = 10 copies of each
    /// per-vector statement, identical but for the vector index k and, in the shift, the neighbour
    /// k + 1 (the last vector shifts in zero). Change one copy and you must change them all the same
    /// way; the engine tests check every product against BigInteger, so a copy that drifts fails
    /// them. Keep the accumulator in named locals rather than a span or array, which the JIT
    /// reloads from memory on every step.
    /// </summary>
    // SkipLocalsInit: aDigits is written in full before it is read, so zeroing it first is waste.
    [MethodImpl(MethodImplOptions.NoInlining)]
    [SkipLocalsInit]
    private void MultiplyCore(ref ulong a, ref ulong b, ref ulong result)
    {
        // a's digits as doubles, exactly: each is below 2^52, so OR-ing it into the mantissa of 2^52
        // and subtracting 2^52 recovers it. b's digits are converted one at a time as they are used.
        Span<double> aDigits = stackalloc double[Lanes];
        ref Vector512<ulong> va = ref Unsafe.As<ulong, Vector512<ulong>>(ref a);
        ref Vector512<double> vad = ref Unsafe.As<double, Vector512<double>>(ref aDigits[0]);
        Vector512<ulong> lowBias = Vector512.Create(LowBias);
        Vector512<double> twoPow52 = Vector512.Create(TwoPow52);
        Unsafe.Add(ref vad, 0) = Avx512F.Subtract(Avx512F.Or(Unsafe.Add(ref va, 0), lowBias).AsDouble(), twoPow52);
        Unsafe.Add(ref vad, 1) = Avx512F.Subtract(Avx512F.Or(Unsafe.Add(ref va, 1), lowBias).AsDouble(), twoPow52);
        Unsafe.Add(ref vad, 2) = Avx512F.Subtract(Avx512F.Or(Unsafe.Add(ref va, 2), lowBias).AsDouble(), twoPow52);
        Unsafe.Add(ref vad, 3) = Avx512F.Subtract(Avx512F.Or(Unsafe.Add(ref va, 3), lowBias).AsDouble(), twoPow52);
        Unsafe.Add(ref vad, 4) = Avx512F.Subtract(Avx512F.Or(Unsafe.Add(ref va, 4), lowBias).AsDouble(), twoPow52);
        Unsafe.Add(ref vad, 5) = Avx512F.Subtract(Avx512F.Or(Unsafe.Add(ref va, 5), lowBias).AsDouble(), twoPow52);
        Unsafe.Add(ref vad, 6) = Avx512F.Subtract(Avx512F.Or(Unsafe.Add(ref va, 6), lowBias).AsDouble(), twoPow52);
        Unsafe.Add(ref vad, 7) = Avx512F.Subtract(Avx512F.Or(Unsafe.Add(ref va, 7), lowBias).AsDouble(), twoPow52);
        Unsafe.Add(ref vad, 8) = Avx512F.Subtract(Avx512F.Or(Unsafe.Add(ref va, 8), lowBias).AsDouble(), twoPow52);
        Unsafe.Add(ref vad, 9) = Avx512F.Subtract(Avx512F.Or(Unsafe.Add(ref va, 9), lowBias).AsDouble(), twoPow52);

        ref Vector512<double> vp = ref Unsafe.As<double, Vector512<double>>(ref _modulusDoubles[0]);
        ulong k0 = _k0;
        Vector512<double> highAddend = Vector512.Create(TwoPow104);
        Vector512<double> lowAddend = Vector512.Create(TwoPow104 + TwoPow52);
        Vector512<ulong> zero = Vector512<ulong>.Zero;

        // The accumulator, digit 8k + j in lane j of xk, each lane offset by a known bias.
        Vector512<ulong> x0 = zero;
        Vector512<ulong> x1 = zero;
        Vector512<ulong> x2 = zero;
        Vector512<ulong> x3 = zero;
        Vector512<ulong> x4 = zero;
        Vector512<ulong> x5 = zero;
        Vector512<ulong> x6 = zero;
        Vector512<ulong> x7 = zero;
        Vector512<ulong> x8 = zero;
        Vector512<ulong> x9 = zero;

        // Lane 0's bias in x0 grows by IterationBias every step. t0 adds one low half to it and s0
        // two, so these track the bias of each, to subtract where the true value is needed.
        ulong lane0Bias = LowBias;
        ulong sumBias = 2 * LowBias;
        for (int i = 0; i < Iterations; i++)
        {
            Vector512<double> vb = Vector512.Create((double)(long)Unsafe.Add(ref b, i));

            // a * b[i], each lane split exactly into high and low 52-bit halves; see the class remarks.
            // Only the bottom vector is needed before y; the rest are computed beside the p * y
            // products, so that fewer of them are live at once.
            Vector512<double> ah0 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 0), vb, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> al0 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 0), vb, Avx512F.Subtract(lowAddend, ah0));

            // y makes the bottom digit of acc + a*b[i] + y*p divisible by 2^DigitBits, so the whole
            // sum can be shifted down one digit. t0 is that bottom digit before y*p is added.
            ulong t0 = x0.ToScalar() + al0.AsUInt64().ToScalar() - lane0Bias;
            ulong y = unchecked(t0 * k0) & DigitMask;
            Vector512<double> vy = Vector512.Create((double)(long)y);

            // acc += a * b[i] + p * y: the low halves where they are, the high halves one digit up,
            // which after the shift below is where they already sit.
            Vector512<double> ph0 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 0), vy, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> pl0 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 0), vy, Avx512F.Subtract(lowAddend, ph0));
            Vector512<ulong> s0 = Avx512F.Add(Avx512F.Add(x0, al0.AsUInt64()), pl0.AsUInt64());
            Vector512<ulong> g0 = Avx512F.Add(ah0.AsUInt64(), ph0.AsUInt64());
            Vector512<double> ah1 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 1), vb, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> al1 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 1), vb, Avx512F.Subtract(lowAddend, ah1));
            Vector512<double> ph1 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 1), vy, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> pl1 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 1), vy, Avx512F.Subtract(lowAddend, ph1));
            Vector512<ulong> s1 = Avx512F.Add(Avx512F.Add(x1, al1.AsUInt64()), pl1.AsUInt64());
            Vector512<ulong> g1 = Avx512F.Add(ah1.AsUInt64(), ph1.AsUInt64());
            Vector512<double> ah2 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 2), vb, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> al2 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 2), vb, Avx512F.Subtract(lowAddend, ah2));
            Vector512<double> ph2 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 2), vy, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> pl2 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 2), vy, Avx512F.Subtract(lowAddend, ph2));
            Vector512<ulong> s2 = Avx512F.Add(Avx512F.Add(x2, al2.AsUInt64()), pl2.AsUInt64());
            Vector512<ulong> g2 = Avx512F.Add(ah2.AsUInt64(), ph2.AsUInt64());
            Vector512<double> ah3 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 3), vb, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> al3 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 3), vb, Avx512F.Subtract(lowAddend, ah3));
            Vector512<double> ph3 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 3), vy, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> pl3 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 3), vy, Avx512F.Subtract(lowAddend, ph3));
            Vector512<ulong> s3 = Avx512F.Add(Avx512F.Add(x3, al3.AsUInt64()), pl3.AsUInt64());
            Vector512<ulong> g3 = Avx512F.Add(ah3.AsUInt64(), ph3.AsUInt64());
            Vector512<double> ah4 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 4), vb, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> al4 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 4), vb, Avx512F.Subtract(lowAddend, ah4));
            Vector512<double> ph4 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 4), vy, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> pl4 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 4), vy, Avx512F.Subtract(lowAddend, ph4));
            Vector512<ulong> s4 = Avx512F.Add(Avx512F.Add(x4, al4.AsUInt64()), pl4.AsUInt64());
            Vector512<ulong> g4 = Avx512F.Add(ah4.AsUInt64(), ph4.AsUInt64());
            Vector512<double> ah5 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 5), vb, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> al5 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 5), vb, Avx512F.Subtract(lowAddend, ah5));
            Vector512<double> ph5 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 5), vy, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> pl5 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 5), vy, Avx512F.Subtract(lowAddend, ph5));
            Vector512<ulong> s5 = Avx512F.Add(Avx512F.Add(x5, al5.AsUInt64()), pl5.AsUInt64());
            Vector512<ulong> g5 = Avx512F.Add(ah5.AsUInt64(), ph5.AsUInt64());
            Vector512<double> ah6 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 6), vb, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> al6 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 6), vb, Avx512F.Subtract(lowAddend, ah6));
            Vector512<double> ph6 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 6), vy, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> pl6 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 6), vy, Avx512F.Subtract(lowAddend, ph6));
            Vector512<ulong> s6 = Avx512F.Add(Avx512F.Add(x6, al6.AsUInt64()), pl6.AsUInt64());
            Vector512<ulong> g6 = Avx512F.Add(ah6.AsUInt64(), ph6.AsUInt64());
            Vector512<double> ah7 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 7), vb, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> al7 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 7), vb, Avx512F.Subtract(lowAddend, ah7));
            Vector512<double> ph7 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 7), vy, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> pl7 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 7), vy, Avx512F.Subtract(lowAddend, ph7));
            Vector512<ulong> s7 = Avx512F.Add(Avx512F.Add(x7, al7.AsUInt64()), pl7.AsUInt64());
            Vector512<ulong> g7 = Avx512F.Add(ah7.AsUInt64(), ph7.AsUInt64());
            Vector512<double> ah8 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 8), vb, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> al8 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 8), vb, Avx512F.Subtract(lowAddend, ah8));
            Vector512<double> ph8 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 8), vy, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> pl8 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 8), vy, Avx512F.Subtract(lowAddend, ph8));
            Vector512<ulong> s8 = Avx512F.Add(Avx512F.Add(x8, al8.AsUInt64()), pl8.AsUInt64());
            Vector512<ulong> g8 = Avx512F.Add(ah8.AsUInt64(), ph8.AsUInt64());
            Vector512<double> ah9 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 9), vb, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> al9 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vad, 9), vb, Avx512F.Subtract(lowAddend, ah9));
            Vector512<double> ph9 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 9), vy, highAddend, FloatRoundingMode.ToNegativeInfinity);
            Vector512<double> pl9 = Avx512F.FusedMultiplyAdd(Unsafe.Add(ref vp, 9), vy, Avx512F.Subtract(lowAddend, ph9));
            Vector512<ulong> s9 = Avx512F.Add(Avx512F.Add(x9, al9.AsUInt64()), pl9.AsUInt64());
            Vector512<ulong> g9 = Avx512F.Add(ah9.AsUInt64(), ph9.AsUInt64());

            // The bottom digit is now a multiple of 2^DigitBits; its quotient is the carry, computed
            // in scalar because the shift discards lane 0.
            ulong carry = (s0.ToScalar() - sumBias) >> DigitBits;

            // acc >>= DigitBits: every lane moves down one and the top lane fills with zero; then the
            // high halves are added in.
            x0 = Avx512F.Add(Avx512F.AlignRight64(s1, s0, 1), g0);
            x1 = Avx512F.Add(Avx512F.AlignRight64(s2, s1, 1), g1);
            x2 = Avx512F.Add(Avx512F.AlignRight64(s3, s2, 1), g2);
            x3 = Avx512F.Add(Avx512F.AlignRight64(s4, s3, 1), g3);
            x4 = Avx512F.Add(Avx512F.AlignRight64(s5, s4, 1), g4);
            x5 = Avx512F.Add(Avx512F.AlignRight64(s6, s5, 1), g5);
            x6 = Avx512F.Add(Avx512F.AlignRight64(s7, s6, 1), g6);
            x7 = Avx512F.Add(Avx512F.AlignRight64(s8, s7, 1), g7);
            x8 = Avx512F.Add(Avx512F.AlignRight64(s9, s8, 1), g8);
            x9 = Avx512F.Add(Avx512F.AlignRight64(zero, s9, 1), g9);
            x0 = Avx512F.Add(x0, Vector512.CreateScalar(carry));
            lane0Bias += IterationBias;
            sumBias += IterationBias;
        }

        // a and b are not read again, so writing the result now is safe even when it aliases them.
        ref Vector512<ulong> vr = ref Unsafe.As<ulong, Vector512<ulong>>(ref result);
        ref Vector512<ulong> vbias = ref Unsafe.As<ulong, Vector512<ulong>>(ref FinalBias[0]);
        Unsafe.Add(ref vr, 0) = Avx512F.Subtract(x0, Unsafe.Add(ref vbias, 0));
        Unsafe.Add(ref vr, 1) = Avx512F.Subtract(x1, Unsafe.Add(ref vbias, 1));
        Unsafe.Add(ref vr, 2) = Avx512F.Subtract(x2, Unsafe.Add(ref vbias, 2));
        Unsafe.Add(ref vr, 3) = Avx512F.Subtract(x3, Unsafe.Add(ref vbias, 3));
        Unsafe.Add(ref vr, 4) = Avx512F.Subtract(x4, Unsafe.Add(ref vbias, 4));
        Unsafe.Add(ref vr, 5) = Avx512F.Subtract(x5, Unsafe.Add(ref vbias, 5));
        Unsafe.Add(ref vr, 6) = Avx512F.Subtract(x6, Unsafe.Add(ref vbias, 6));
        Unsafe.Add(ref vr, 7) = Avx512F.Subtract(x7, Unsafe.Add(ref vbias, 7));
        Unsafe.Add(ref vr, 8) = Avx512F.Subtract(x8, Unsafe.Add(ref vbias, 8));
        Unsafe.Add(ref vr, 9) = Avx512F.Subtract(x9, Unsafe.Add(ref vbias, 9));

        PropagateCarries(ref result);
    }
}
