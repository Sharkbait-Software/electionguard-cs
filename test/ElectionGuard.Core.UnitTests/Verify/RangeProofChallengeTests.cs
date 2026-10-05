using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.Crypto;
using ElectionGuard.Core.Verify.Ballot;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Verify;

/// <summary>
/// RangeProofChallenge builds the challenge hash input of Verifications 6 and 7 straight from
/// Montgomery-form values instead of through IntegerModP, and computes Verification 7's aggregate
/// ciphertexts the same way. These pin that every byte it hashes, and every aggregate, is what the
/// straightforward BigInteger computation produces.
///
/// Every case runs on the engine the machine would choose (AVX-512 where available) and with AVX-512
/// ruled out, with and without precomputed g and K tables, so both representations and both
/// fixed-base paths are covered everywhere. With DOTNET_EnableAVX512F=0 every run is scalar.
/// </summary>
public class RangeProofChallengeTests : IDisposable
{
    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;
    private static readonly BigInteger Q = EGParameters.CryptographicParameters.Q;

    public RangeProofChallengeTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        PowRadixRegistry.Clear();
    }

    public void Dispose()
    {
        PowRadixRegistry.Clear();
    }

    public static TheoryData<bool> Engines => new() { true, false };

    public static TheoryData<bool, bool, int> EnginesTablesAndProofCounts()
    {
        TheoryData<bool, bool, int> data = new();
        foreach (bool allowAvx512 in new[] { true, false })
        {
            foreach (bool withTables in new[] { false, true })
            {
                foreach (int proofCount in new[] { 1, 2, 3 })
                {
                    data.Add(allowAvx512, withTables, proofCount);
                }
            }
        }

        return data;
    }

    public static TheoryData<BigInteger> ModPValues() => new()
    {
        BigInteger.Zero,
        BigInteger.One,
        new BigInteger(0x1234_5678),
        P - 1,
        EGParameters.CryptographicParameters.G,
    };

    // --- Byte writers ---

    [Theory]
    [MemberData(nameof(ModPValues))]
    public void IntegerModP_WriteBigEndian_MatchesToByteArray(BigInteger value)
    {
        var element = new IntegerModP(value);
        byte[] written = new byte[IntegerModP.ByteLength + 3];
        written.AsSpan().Fill(0xAA);

        element.WriteBigEndian(written);

        Assert.Equal(element.ToByteArray(), written[..IntegerModP.ByteLength]);
        // Nothing past the value's 512 bytes is touched.
        Assert.All(written[IntegerModP.ByteLength..], b => Assert.Equal(0xAA, b));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(255)]
    [InlineData(int.MaxValue)]
    public void IntegerModQ_WriteBigEndian_MatchesToByteArray(int value)
    {
        var element = new IntegerModQ(value);
        byte[] written = new byte[IntegerModQ.ByteLength];
        written.AsSpan().Fill(0xAA);

        element.WriteBigEndian(written);

        Assert.Equal(element.ToByteArray(), written);
    }

    [Fact]
    public void IntegerModQ_WriteBigEndian_MatchesToByteArray_ForLargestElement()
    {
        var element = new IntegerModQ(Q - 1);
        byte[] written = new byte[IntegerModQ.ByteLength];

        element.WriteBigEndian(written);

        Assert.Equal(element.ToByteArray(), written);
    }

    [Fact]
    public void WriteLimbsBigEndian_ValueWiderThanDestination_Throws()
    {
        ulong[] limbs = [0x01, 0x0100];

        Assert.Throws<ArgumentException>(() => MontgomeryContext.WriteLimbsBigEndian(limbs, new byte[9]));
    }

    [Fact]
    public void WriteLimbsBigEndian_DestinationNarrowerThanLimbs_KeepsValueWhenHighBytesAreZero()
    {
        ulong[] limbs = [0x0102030405060708, 0x09, 0];
        byte[] written = new byte[9];

        MontgomeryContext.WriteLimbsBigEndian(limbs, written);

        Assert.Equal(new byte[] { 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, written);
    }

    [Theory]
    [MemberData(nameof(ModPValues))]
    public void ScalarMontgomery_WriteBigEndian_MatchesToByteArray(BigInteger value)
    {
        MontgomeryContext context = MontgomeryContext.Current;
        ulong[] limbs = new ulong[context.LimbCount];
        byte[] written = new byte[IntegerModP.ByteLength];

        context.ToMontgomery(value, limbs);
        context.WriteBigEndian(limbs, written);

        Assert.Equal(new IntegerModP(value).ToByteArray(), written);
    }

    [Avx512Fact]
    public void Avx512Montgomery_WriteBigEndian_MatchesToByteArray()
    {
        Assert.True(Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine));
        foreach (BigInteger value in new[] { BigInteger.Zero, BigInteger.One, new BigInteger(0x1234_5678), P - 1, EGParameters.CryptographicParameters.G })
        {
            ulong[] digits = new ulong[Avx512Montgomery.Lanes];
            byte[] written = new byte[IntegerModP.ByteLength];

            engine.ToMontgomery(value, digits);
            engine.WriteBigEndian(digits, written);

            Assert.Equal(new IntegerModP(value).ToByteArray(), written);
        }
    }

    [Avx512Fact]
    public void Avx512Montgomery_WriteBigEndian_RedundantRepresentations()
    {
        Assert.True(Avx512Montgomery.TryGetCurrent(out Avx512Montgomery engine));

        // p itself is the engine's redundant form of 0 (Montgomery form of 0 is 0, and 0 + p is
        // allowed). Multiplying it out by 1 leaves exactly p, which must be written as 0, as
        // FromMontgomery returns it.
        ulong[] p = new ulong[Avx512Montgomery.Lanes];
        Avx512Montgomery.WriteDigits(P, p);
        byte[] written = new byte[IntegerModP.ByteLength];
        engine.WriteBigEndian(p, written);
        Assert.Equal(new IntegerModP(BigInteger.Zero).ToByteArray(), written);
        Assert.Equal(BigInteger.Zero, engine.FromMontgomery(p));

        // R mod p + p is the redundant form of 1.
        BigInteger r = BigInteger.One << (Avx512Montgomery.DigitBits * Avx512Montgomery.Iterations);
        ulong[] onePlusP = new ulong[Avx512Montgomery.Lanes];
        Avx512Montgomery.WriteDigits(r % P + P, onePlusP);
        engine.WriteBigEndian(onePlusP, written);
        Assert.Equal(new IntegerModP(BigInteger.One).ToByteArray(), written);
    }

    // --- Hashing ---

    [Fact]
    public void HashConcatenated_MatchesHashOfTheParts()
    {
        byte[] key = ElectionGuardRandom.GetBytes(32);
        byte[][] parts = [[0x24], new byte[] { 0, 0, 0, 7 }, ElectionGuardRandom.GetBytes(512), [], ElectionGuardRandom.GetBytes(33)];
        byte[] concatenated = ByteArrayExtensions.Concat(parts);

        byte[] digest = new byte[32];
        EGHash.HashConcatenated(key, concatenated, digest);

        Assert.Equal(EGHash.Hash(key, parts), digest);
        Assert.Equal(EGHash.HashModQ(key, parts), EGHash.HashModQConcatenated(key, concatenated));
    }

    [Fact]
    public void HashConcatenated_ValidatesKeyAsHashDoes()
    {
        Assert.Throws<ArgumentNullException>(() => EGHash.HashModQConcatenated(null!, [1]));
        Assert.Throws<ArgumentException>(() => EGHash.HashModQConcatenated([], [1]));
        Assert.Throws<ArgumentException>(() => EGHash.HashModQConcatenated(new byte[31], [1]));
    }

    // --- Range-proof challenge ---

    [Theory]
    [MemberData(nameof(EnginesTablesAndProofCounts))]
    public void Compute_MatchesStraightforwardHash(bool allowAvx512, bool withTables, int proofCount)
    {
        IntegerModP key = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        if (withTables)
        {
            PowRadixRegistry.Precompute(4, EGParameters.G, key.ToBigInteger());
        }

        IntegerModP alpha = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        IntegerModP beta = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        ChallengeResponsePair[] proofs = Enumerable.Range(0, proofCount)
            .Select(_ => new ChallengeResponsePair
            {
                Challenge = ElectionGuardRandom.GetIntegerModQ(),
                Response = ElectionGuardRandom.GetIntegerModQ(),
            })
            .ToArray();

        var challenge = new RangeProofChallenge(key, allowAvx512);
        AssertExpectedConfiguration(challenge, allowAvx512, withTables);
        AssertMatchesStraightforwardHash(challenge, key, alpha, beta, proofs);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void Compute_ZeroAndEdgeExponents_MatchesStraightforwardHash(bool allowAvx512)
    {
        // A zero challenge takes the shared-squaring path's "result is one" branch, a zero response
        // gives g^0, and q - 1 has every bit the exponent can have. Zero is in Z_q, so 6.B/6.C and
        // 7.B/7.C accept zero challenges and responses (G33) and they do reach this.
        IntegerModP key = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        IntegerModP alpha = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        IntegerModP beta = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        ChallengeResponsePair[] proofs =
        [
            new() { Challenge = 0, Response = 0 },
            new() { Challenge = new IntegerModQ(Q - 1), Response = 1 },
            new() { Challenge = 1, Response = new IntegerModQ(Q - 1) },
        ];

        AssertMatchesStraightforwardHash(new RangeProofChallenge(key, allowAvx512), key, alpha, beta, proofs);

        ChallengeResponsePair[] allZeroChallenges = [new() { Challenge = 0, Response = 5 }, new() { Challenge = 0, Response = 6 }];
        AssertMatchesStraightforwardHash(new RangeProofChallenge(key, allowAvx512), key, alpha, beta, allZeroChallenges);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void Compute_EdgeCiphertexts_MatchesStraightforwardHash(bool allowAvx512)
    {
        // Values the 6.A/7.A checks would reject, but whose bytes must still come out right: zero
        // and one bases, and p - 1.
        IntegerModP key = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        ChallengeResponsePair[] proofs =
        [
            new() { Challenge = ElectionGuardRandom.GetIntegerModQ(), Response = ElectionGuardRandom.GetIntegerModQ() },
            new() { Challenge = ElectionGuardRandom.GetIntegerModQ(), Response = ElectionGuardRandom.GetIntegerModQ() },
        ];

        var challenge = new RangeProofChallenge(key, allowAvx512);
        AssertMatchesStraightforwardHash(challenge, key, new IntegerModP(0), new IntegerModP(1), proofs);
        AssertMatchesStraightforwardHash(challenge, key, new IntegerModP(P - 1), new IntegerModP(P - 1), proofs);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void Compute_TablesInTheOtherRepresentation_AreNotUsedButResultMatches(bool allowAvx512)
    {
        // PowRadixRegistry always builds tables for the machine's preferred representation. A
        // scalar-forced computation on AVX-512 hardware must not read 52-bit digits as 64-bit limbs.
        IntegerModP key = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        PowRadixRegistry.Precompute(4, EGParameters.G, key.ToBigInteger());

        var challenge = new RangeProofChallenge(key, allowAvx512);
        bool tablesAreAvx512 = Avx512Montgomery.IsSupported;
        Assert.Equal(challenge.UsesAvx512 == tablesAreAvx512, challenge.UsesTables);

        IntegerModP alpha = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        IntegerModP beta = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        ChallengeResponsePair[] proofs =
        [
            new() { Challenge = ElectionGuardRandom.GetIntegerModQ(), Response = ElectionGuardRandom.GetIntegerModQ() },
            new() { Challenge = ElectionGuardRandom.GetIntegerModQ(), Response = ElectionGuardRandom.GetIntegerModQ() },
        ];
        AssertMatchesStraightforwardHash(challenge, key, alpha, beta, proofs);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void PowRadix_PowMontgomeryInto_ConvertsToPow(bool allowAvx512)
    {
        PowRadix radix = PowRadix.Build(EGParameters.G, 4, allowAvx512);
        IntegerModQ exponent = ElectionGuardRandom.GetIntegerModQ();
        ulong[] montgomery = new ulong[Avx512Montgomery.Lanes];

        radix.PowMontgomeryInto(exponent, montgomery);
        BigInteger converted = radix.UsesAvx512
            ? radix.Engine!.FromMontgomery(montgomery)
            : radix.Context.FromMontgomery(montgomery.AsSpan(0, radix.Context.LimbCount));

        Assert.Equal(radix.Pow(exponent), new IntegerModP(converted));
        Assert.Equal(IntegerModP.PowModP(EGParameters.G, exponent), new IntegerModP(converted));
    }

    // --- Aggregate ---

    [Theory]
    [InlineData(1, true)]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(2, false)]
    [InlineData(5, true)]
    [InlineData(5, false)]
    public void Aggregate_MatchesProduct(int count, bool allowAvx512)
    {
        IntegerModP key = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        List<EncryptedValueWithProofs> ciphertexts = Enumerable.Range(0, count)
            .Select(_ => Ciphertext(
                IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ()),
                IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ())))
            .ToList();

        var (alpha, beta) = new RangeProofChallenge(key, allowAvx512).Aggregate(ciphertexts);

        Assert.Equal(ciphertexts.Select(x => x.Alpha).Product(), alpha);
        Assert.Equal(ciphertexts.Select(x => x.Beta).Product(), beta);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void Aggregate_EdgeValues_MatchesProduct(bool allowAvx512)
    {
        IntegerModP key = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());
        List<EncryptedValueWithProofs> withZero = [Ciphertext(new IntegerModP(P - 1), 0), Ciphertext(new IntegerModP(P - 1), 7)];

        var (alpha, beta) = new RangeProofChallenge(key, allowAvx512).Aggregate(withZero);

        Assert.Equal(new IntegerModP(BigInteger.One), alpha);
        Assert.Equal(new IntegerModP(BigInteger.Zero), beta);
    }

    [Theory]
    [MemberData(nameof(Engines))]
    public void Aggregate_Empty_ThrowsAsProductDoes(bool allowAvx512)
    {
        IntegerModP key = IntegerModP.PowModP(EGParameters.G, ElectionGuardRandom.GetIntegerModQ());

        Assert.Throws<InvalidOperationException>(() => new List<IntegerModP>().Product());
        Assert.Throws<InvalidOperationException>(() => new RangeProofChallenge(key, allowAvx512).Aggregate(new List<EncryptedValueWithProofs>()));
    }

    private static EncryptedValueWithProofs Ciphertext(IntegerModP alpha, IntegerModP beta)
    {
        return new EncryptedValueWithProofs { Alpha = alpha, Beta = beta, Proofs = [] };
    }

    private static void AssertExpectedConfiguration(RangeProofChallenge challenge, bool allowAvx512, bool withTables)
    {
        Assert.Equal(allowAvx512 && Avx512Montgomery.IsSupported, challenge.UsesAvx512);

        // Registered tables are always in the machine's preferred representation.
        bool tablesMatch = challenge.UsesAvx512 == Avx512Montgomery.IsSupported;
        Assert.Equal(withTables && tablesMatch, challenge.UsesTables);
    }

    /// <summary>
    /// The construction Verifications 6 and 7 used before RangeProofChallenge: every value through
    /// BigInteger ModPow and IntegerModP multiplication, every hash input its own array.
    /// </summary>
    private static void AssertMatchesStraightforwardHash(
        RangeProofChallenge challenge,
        IntegerModP key,
        IntegerModP alpha,
        IntegerModP beta,
        ChallengeResponsePair[] proofs)
    {
        byte[] hashKey = ElectionGuardRandom.GetBytes(32);
        byte[] prefix = [0x24, 0, 0, 0, 7, 0, 0, 1, 2];

        List<byte[]> expectedInput = [[0x24], new byte[] { 0, 0, 0, 7 }, new byte[] { 0, 0, 1, 2 }, alpha, beta];
        for (int j = 0; j < proofs.Length; j++)
        {
            var proof = proofs[j];
            expectedInput.Add(IntegerModP.PowModP(EGParameters.G, proof.Response) * IntegerModP.PowModP(alpha, proof.Challenge));
            expectedInput.Add(IntegerModP.PowModP(key, proof.Response - j * proof.Challenge) * IntegerModP.PowModP(beta, proof.Challenge));
        }

        IntegerModQ expected = EGHash.HashModQ(hashKey, expectedInput.ToArray());

        Assert.Equal(expected, challenge.Compute(hashKey, prefix, alpha, beta, proofs));
    }
}
