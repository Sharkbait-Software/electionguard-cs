using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// G23: published values decode strictly (§5.1.1, §5.1.2, eq. 32). An element of Z_p is exactly 512
/// big-endian bytes below p, an element of Z_q exactly 32 bytes below q, and id_B exactly 32 bytes.
/// The reducing constructors would accept p as 0, q as 0, or a padded encoding as its value, which
/// leaves the 0 &lt;= x &lt; p and 0 &lt;= x &lt; q halves of 2.A/2.B, 6.A-6.C and 7.A-7.C unenforceable
/// on anything read from a record. A non-canonical encoding is a
/// <see cref="NonCanonicalEncodingException"/> at decode time.
/// </summary>
public class StrictDecodingTests
{
    public StrictDecodingTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static byte[] Encode(BigInteger value, int length) => value.ToBigEndianPadded(length);

    [Fact]
    public void IntegerModP_FromCanonicalBytes_AcceptsExactlyZeroToPMinusOne()
    {
        BigInteger p = EGParameters.P;

        Assert.Equal(new IntegerModP(p - 1), IntegerModP.FromCanonicalBytes(Encode(p - 1, 512)));
        Assert.Equal(new IntegerModP(0), IntegerModP.FromCanonicalBytes(new byte[512]));
        Assert.Equal(new IntegerModP(12345), IntegerModP.FromCanonicalBytes(Encode(12345, 512)));
    }

    [Fact]
    public void IntegerModP_FromCanonicalBytes_RejectsPAndAbove()
    {
        BigInteger p = EGParameters.P;

        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModP.FromCanonicalBytes(Encode(p, 512)));
        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModP.FromCanonicalBytes(Encode(p + 1, 512)));
        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModP.FromCanonicalBytes(Enumerable.Repeat((byte)0xFF, 512).ToArray()));

        // What the reducing constructor does with the same bytes: p decodes as 0.
        Assert.Equal(new IntegerModP(0), new IntegerModP(Encode(p, 512)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32)]
    [InlineData(511)]
    [InlineData(513)]
    public void IntegerModP_FromCanonicalBytes_RejectsAnyOtherLength(int length)
    {
        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModP.FromCanonicalBytes(new byte[length]));
    }

    [Fact]
    public void IntegerModQ_FromCanonicalBytes_AcceptsExactlyZeroToQMinusOne()
    {
        BigInteger q = EGParameters.Q;

        Assert.Equal(new IntegerModQ(q - 1), IntegerModQ.FromCanonicalBytes(Encode(q - 1, 32)));
        Assert.Equal(new IntegerModQ(0), IntegerModQ.FromCanonicalBytes(new byte[32]));
    }

    [Fact]
    public void IntegerModQ_FromCanonicalBytes_RejectsQAndAbove()
    {
        BigInteger q = EGParameters.Q;

        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModQ.FromCanonicalBytes(Encode(q, 32)));
        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModQ.FromCanonicalBytes(Encode(q + 188, 32)));

        // What the reducing constructor does with the same bytes: q decodes as 0.
        Assert.Equal(new IntegerModQ(0), new IntegerModQ(Encode(q, 32)));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(512)]
    public void IntegerModQ_FromCanonicalBytes_RejectsAnyOtherLength(int length)
    {
        Assert.Throws<NonCanonicalEncodingException>(() => IntegerModQ.FromCanonicalBytes(Encode(5, length)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void SelectionEncryptionIdentifier_FromCanonicalBytes_RejectsAnyLengthButThirtyTwo(int length)
    {
        Assert.Throws<NonCanonicalEncodingException>(() => SelectionEncryptionIdentifier.FromCanonicalBytes(new byte[length]));
    }

    /// <summary>
    /// A missing protobuf field decodes as a null array. That is a length-0 encoding like any other,
    /// so it is a <see cref="NonCanonicalEncodingException"/>, as it is for IntegerModP and IntegerModQ.
    /// </summary>
    [Fact]
    public void SelectionEncryptionIdentifier_FromCanonicalBytes_RejectsNull()
    {
        byte[]? missing = null;

        Assert.Throws<NonCanonicalEncodingException>(() => SelectionEncryptionIdentifier.FromCanonicalBytes(missing));
    }

    [Fact]
    public void SelectionEncryptionIdentifier_FromCanonicalBytes_AcceptsThirtyTwoBytes()
    {
        byte[] bytes = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

        Assert.Equal(new SelectionEncryptionIdentifier(bytes), SelectionEncryptionIdentifier.FromCanonicalBytes(bytes));
    }
}
