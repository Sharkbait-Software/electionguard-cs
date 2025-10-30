using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

public class IntegerModQTests
{
    public IntegerModQTests()
    {
        CryptographicParameters cryptographicParameters = new CryptographicParameters();
        GuardianParameters guardianParameters = new GuardianParameters();
        EGParameters.Init(cryptographicParameters, guardianParameters);
    }
    
    private static readonly BigInteger Q = EGParameters.CryptographicParameters.Q;

    [Fact]
    public void Constructor_BigInteger_WrapsModQ()
    {
        var value = Q + 5;
        var modQ = new IntegerModQ(value);
        Assert.Equal(5, (int)modQ.ToBigInteger());
    }

    [Fact]
    public void Constructor_BigInteger_Negative_WrapsModQ()
    {
        var value = -3;
        var modQ = new IntegerModQ(value);
        var expected = ((value % Q) + Q) % Q;
        Assert.Equal(expected, modQ.ToBigInteger());
    }

    [Fact]
    public void Constructor_ByteArray_ParsesCorrectly()
    {
        var value = new BigInteger(12345);
        var bytes = value.ToByteArray(true, true);
        var modQ = new IntegerModQ(bytes);
        Assert.Equal(12345, (int)modQ.ToBigInteger());
    }

    [Fact]
    public void ToByteArray_Returns32Bytes()
    {
        var modQ = new IntegerModQ(42);
        var bytes = modQ.ToByteArray();
        Assert.Equal(32, bytes.Length);
        Assert.Equal(42, new BigInteger(bytes, true, true));
    }


    [Fact]
    public void ToBigInteger_ReturnsUnderlyingValue()
    {
        var modQ = new IntegerModQ(123);
        Assert.Equal(123, (int)modQ.ToBigInteger());
    }

    [Fact]
    public void PowModQ_IntegerModQ_Exponent()
    {
        var modQ = new IntegerModQ(2);
        var result = IntegerModQ.PowModQ(modQ, 10);
        Assert.Equal(1024, (int)result.ToBigInteger());
    }

    [Fact]
    public void PowModQ_Int_Exponent()
    {
        var result = IntegerModQ.PowModQ(3, 4);
        Assert.Equal(81, (int)result.ToBigInteger());
    }

    [Fact]
    public void ImplicitOperator_ByteArray()
    {
        var modQ = new IntegerModQ(55);
        byte[] bytes = modQ;
        Assert.Equal(32, bytes.Length);
        Assert.Equal(55, new BigInteger(bytes, true, true));
    }

    [Fact]
    public void ImplicitOperator_BigInteger()
    {
        var modQ = new IntegerModQ(77);
        BigInteger value = modQ;
        Assert.Equal(77, (int)value);
    }

    [Fact]
    public void ImplicitOperator_Int()
    {
        IntegerModQ modQ = 99;
        Assert.Equal(99, (int)modQ.ToBigInteger());
    }

    [Fact]
    public void Operator_Addition()
    {
        var a = new IntegerModQ(10);
        var b = new IntegerModQ(15);
        var result = a + b;
        Assert.Equal(25, (int)result.ToBigInteger());
    }

    [Fact]
    public void Operator_Subtraction()
    {
        var a = new IntegerModQ(20);
        var b = new IntegerModQ(5);
        var result = a - b;
        Assert.Equal(15, (int)result.ToBigInteger());
    }

    [Fact]
    public void Operator_Multiplication()
    {
        var a = new IntegerModQ(7);
        var b = new IntegerModQ(6);
        var result = a * b;
        Assert.Equal(42, (int)result.ToBigInteger());
    }

    [Fact]
    public void Operator_Division()
    {
        var a = new IntegerModQ(20);
        var b = new IntegerModQ(4);
        var result = a / b;
        Assert.Equal(5, (int)result.ToBigInteger());
    }

    [Fact]
    public void Operator_Comparison()
    {
        var a = new IntegerModQ(3);
        var b = new IntegerModQ(7);
        Assert.True(a < b);
        Assert.True(b > a);
        Assert.True(a <= b);
        Assert.True(b >= a);
    }

    [Fact]
    public void Equals_ObjectAndTyped()
    {
        var a = new IntegerModQ(123);
        var b = new IntegerModQ(123);
        var c = new IntegerModQ(456);
        Assert.True(a.Equals((object)b));
        Assert.True(a.Equals(b));
        Assert.False(a.Equals(c));
        Assert.False(a.Equals(null));
    }

    [Fact]
    public void GetHashCode_ConsistentWithEquals()
    {
        var a = new IntegerModQ(789);
        var b = new IntegerModQ(789);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Operator_Equality()
    {
        var a = new IntegerModQ(42);
        var b = new IntegerModQ(42);
        var c = new IntegerModQ(43);
        Assert.True(a == b);
        Assert.False(a == c);
        Assert.True(a != c);
        Assert.False(a != b);
    }
}
