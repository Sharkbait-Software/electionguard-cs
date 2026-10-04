using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;

namespace ElectionGuard.Core.UnitTests.PreEncryption;

public class HashTrimmingTests
{
    private static SelectionHash HashEndingWith(params byte[] finalBytes)
    {
        var bytes = new byte[32];
        // Fill the leading bytes so a trimming function that reads the wrong end would show it.
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = 0xA5;
        }
        finalBytes.CopyTo(bytes, bytes.Length - finalBytes.Length);
        return new SelectionHash(bytes);
    }

    [Theory]
    [InlineData(HashTrimmingFunction.TwoHex, 0, "00")]
    [InlineData(HashTrimmingFunction.TwoHex, 10, "0A")]
    [InlineData(HashTrimmingFunction.TwoHex, 255, "FF")]
    [InlineData(HashTrimmingFunction.LetterDigit, 0, "A0")]
    [InlineData(HashTrimmingFunction.LetterDigit, 9, "A9")]
    [InlineData(HashTrimmingFunction.LetterDigit, 10, "B0")]
    [InlineData(HashTrimmingFunction.LetterDigit, 255, "Z5")]
    [InlineData(HashTrimmingFunction.DigitLetter, 0, "0A")]
    [InlineData(HashTrimmingFunction.DigitLetter, 25, "0Z")]
    [InlineData(HashTrimmingFunction.DigitLetter, 26, "1A")]
    [InlineData(HashTrimmingFunction.DigitLetter, 255, "9V")]
    [InlineData(HashTrimmingFunction.Number0To255, 0, "0")]
    [InlineData(HashTrimmingFunction.Number0To255, 255, "255")]
    [InlineData(HashTrimmingFunction.Number1To256, 0, "1")]
    [InlineData(HashTrimmingFunction.Number1To256, 255, "256")]
    [InlineData(HashTrimmingFunction.Number100To355, 0, "100")]
    [InlineData(HashTrimmingFunction.Number100To355, 255, "355")]
    [InlineData(HashTrimmingFunction.Number101To356, 0, "101")]
    [InlineData(HashTrimmingFunction.Number101To356, 255, "356")]
    public void Trim_SingleByteFunctions_MapFinalByteAsSpecified(HashTrimmingFunction omega, int finalByte, string expected)
    {
        var psi = HashEndingWith((byte)finalByte);

        var shortCode = HashTrimming.Trim(omega, psi);

        Assert.Equal(expected, shortCode.Value);
    }

    [Theory]
    [InlineData(0x00, 0x00, "0000")]
    [InlineData(0x01, 0xAB, "01AB")]
    [InlineData(0xFF, 0xFF, "FFFF")]
    public void Trim_FourHex_UsesFinalTwoBytesInOrder(int secondToLast, int last, string expected)
    {
        var psi = HashEndingWith((byte)secondToLast, (byte)last);

        var shortCode = HashTrimming.Trim(HashTrimmingFunction.FourHex, psi);

        Assert.Equal(expected, shortCode.Value);
    }

    [Theory]
    [InlineData(HashTrimmingFunction.TwoHex)]
    [InlineData(HashTrimmingFunction.LetterDigit)]
    [InlineData(HashTrimmingFunction.DigitLetter)]
    [InlineData(HashTrimmingFunction.Number0To255)]
    [InlineData(HashTrimmingFunction.Number1To256)]
    [InlineData(HashTrimmingFunction.Number100To355)]
    [InlineData(HashTrimmingFunction.Number101To356)]
    public void Trim_SingleByteFunctions_AreInjectiveOverAllByteValues(HashTrimmingFunction omega)
    {
        var codes = Enumerable.Range(0, 256)
            .Select(b => HashTrimming.Trim(omega, HashEndingWith((byte)b)).Value)
            .ToHashSet();

        Assert.Equal(256, codes.Count);
    }

    [Theory]
    [InlineData(HashTrimmingFunction.TwoHex, 256)]
    [InlineData(HashTrimmingFunction.FourHex, 65536)]
    [InlineData(HashTrimmingFunction.LetterDigit, 256)]
    [InlineData(HashTrimmingFunction.DigitLetter, 256)]
    [InlineData(HashTrimmingFunction.Number0To255, 256)]
    [InlineData(HashTrimmingFunction.Number1To256, 256)]
    [InlineData(HashTrimmingFunction.Number100To355, 256)]
    [InlineData(HashTrimmingFunction.Number101To356, 256)]
    public void CodeSpaceSize_MatchesNumberOfTrimmedBytes(HashTrimmingFunction omega, int expected)
    {
        Assert.Equal(expected, HashTrimming.CodeSpaceSize(omega));
    }

    [Fact]
    public void Trim_UndefinedFunction_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HashTrimming.Trim((HashTrimmingFunction)99, HashEndingWith(0)));
    }

    [Fact]
    public void HashTrimmingFunction_ValuesMatchSpecSubscripts()
    {
        Assert.Equal(1, (int)HashTrimmingFunction.TwoHex);
        Assert.Equal(2, (int)HashTrimmingFunction.FourHex);
        Assert.Equal(3, (int)HashTrimmingFunction.LetterDigit);
        Assert.Equal(4, (int)HashTrimmingFunction.DigitLetter);
        Assert.Equal(5, (int)HashTrimmingFunction.Number0To255);
        Assert.Equal(6, (int)HashTrimmingFunction.Number1To256);
        Assert.Equal(7, (int)HashTrimmingFunction.Number100To355);
        Assert.Equal(8, (int)HashTrimmingFunction.Number101To356);
    }
}
