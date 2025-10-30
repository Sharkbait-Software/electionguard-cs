using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Crypto;

public class IntegerModPTests
{
    public IntegerModPTests()
    {
        CryptographicParameters cryptographicParameters = new CryptographicParameters();
        GuardianParameters guardianParameters = new GuardianParameters();
        EGParameters.Init(cryptographicParameters, guardianParameters);
    }

    private static readonly BigInteger P = EGParameters.CryptographicParameters.P;

    [Fact]
    public void Constructor_BigInteger_WithinRange()
    {
        var value = new BigInteger(12345);
        var modP = new IntegerModP(value);
        Assert.Equal(value, modP.ToBigInteger());
    }

    [Fact]
    public void Constructor_BigInteger_AboveP()
    {
        var value = P + 123;
        var modP = new IntegerModP(value);
        Assert.Equal(123, modP.ToBigInteger());
    }

    [Fact]
    public void Constructor_BigInteger_Negative()
    {
        var value = new BigInteger(-1);
        var modP = new IntegerModP(value);
        Assert.Equal(P - 1, modP.ToBigInteger());
    }

    [Fact]
    public void Constructor_ByteArray()
    {
        var value = new BigInteger(12345);
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        var modP = new IntegerModP(bytes);
        Assert.Equal(value, modP.ToBigInteger());
    }

    [Fact]
    public void ToByteArray_LengthIs512()
    {
        var value = new IntegerModP(1);
        var bytes = value.ToByteArray();
        Assert.Equal(512, bytes.Length);
    }

    [Fact]
    public void ToByteArray_ThrowsIfTooBig()
    {
        var bigValue = BigInteger.Pow(2, 4096); // Will be reduced mod P, so not too big
        var modP = new IntegerModP(bigValue);
        var bytes = modP.ToByteArray();
        Assert.Equal(512, bytes.Length);
    }

    [Fact]
    public void ToBigInteger_ReturnsValue()
    {
        var value = new BigInteger(98765);
        var modP = new IntegerModP(value);
        Assert.Equal(value, modP.ToBigInteger());
    }

    [Fact]
    public void PowModP_IntegerModP_And_IntegerModQ()
    {
        var baseVal = new IntegerModP(2);
        var exp = new IntegerModQ(10);
        var result = IntegerModP.PowModP(baseVal, exp);
        Assert.Equal(BigInteger.ModPow(2, 10, P), result.ToBigInteger());
    }

    [Fact]
    public void PowModP_BigInteger_And_IntegerModQ()
    {
        var baseVal = new BigInteger(3);
        var exp = new IntegerModQ(5);
        var result = IntegerModP.PowModP(baseVal, exp);
        Assert.Equal(BigInteger.ModPow(3, 5, P), result.ToBigInteger());
    }

    [Fact]
    public void PowModP_BigInteger_And_BigInteger()
    {
        var baseVal = new BigInteger(4);
        var exp = new BigInteger(7);
        var result = IntegerModP.PowModP(baseVal, exp);
        Assert.Equal(BigInteger.ModPow(4, 7, P), result.ToBigInteger());
    }

    [Fact]
    public void Implicit_ByteArray()
    {
        var value = new IntegerModP(42);
        byte[] bytes = value;
        Assert.Equal(512, bytes.Length);
    }

    [Fact]
    public void Implicit_BigInteger()
    {
        var value = new IntegerModP(1234);
        BigInteger big = value;
        Assert.Equal(1234, big);
    }

    [Fact]
    public void Implicit_Int()
    {
        IntegerModP modP = 5678;
        Assert.Equal(5678, modP.ToBigInteger());
    }

    [Fact]
    public void Operator_Add()
    {
        var a = new IntegerModP(10);
        var b = new IntegerModP(20);
        var c = a + b;
        Assert.Equal(30, c.ToBigInteger());
    }

    [Fact]
    public void Operator_Subtract()
    {
        var a = new IntegerModP(50);
        var b = new IntegerModP(20);
        var c = a - b;
        Assert.Equal(30, c.ToBigInteger());
    }

    [Fact]
    public void Operator_Multiply()
    {
        var a = new IntegerModP(7);
        var b = new IntegerModP(6);
        var c = a * b;
        Assert.Equal(42, c.ToBigInteger());
    }

    [Fact]
    public void Operator_Divide()
    {
        var a = new IntegerModP(10);
        var b = new IntegerModP(2);
        var c = a / b;
        Assert.Equal(5, c.ToBigInteger());
    }

    [Fact]
    public void Operator_LessThan()
    {
        var a = new IntegerModP(1);
        var b = new IntegerModP(2);
        Assert.True(a < b);
    }

    [Fact]
    public void Operator_GreaterThan()
    {
        var a = new IntegerModP(3);
        var b = new IntegerModP(2);
        Assert.True(a > b);
    }

    [Fact]
    public void Operator_LessThanOrEqual()
    {
        var a = new IntegerModP(2);
        var b = new IntegerModP(2);
        Assert.True(a <= b);
    }

    [Fact]
    public void Operator_GreaterThanOrEqual()
    {
        var a = new IntegerModP(2);
        var b = new IntegerModP(2);
        Assert.True(a >= b);
    }

    [Fact]
    public void Equals_Object()
    {
        var a = new IntegerModP(123);
        object b = new IntegerModP(123);
        Assert.True(a.Equals(b));
    }

    [Fact]
    public void Equals_IntegerModP()
    {
        var a = new IntegerModP(456);
        var b = new IntegerModP(456);
        Assert.True(a.Equals(b));
    }

    [Fact]
    public void GetHashCode_Consistent()
    {
        var a = new IntegerModP(789);
        var b = new IntegerModP(789);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Operator_Equality()
    {
        var a = new IntegerModP(1000);
        var b = new IntegerModP(1000);
        Assert.True(a == b);
    }

    [Fact]
    public void Operator_Inequality()
    {
        var a = new IntegerModP(1000);
        var b = new IntegerModP(1001);
        Assert.True(a != b);
    }
}
