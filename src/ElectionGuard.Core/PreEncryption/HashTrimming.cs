using ElectionGuard.Core.Models;
using System.Globalization;

namespace ElectionGuard.Core.PreEncryption;

/// <summary>
/// §4.6 Hash-Trimming Functions. "Final byte" is the last byte of the 32-byte selection hash, i.e.
/// its least significant byte when read big endian (§5.1). The spec does not fix the case of the
/// hexadecimal forms; they are uppercase here, matching the spec's own hex notation.
/// </summary>
public static class HashTrimming
{
    public static ShortCode Trim(HashTrimmingFunction omega, SelectionHash psi)
    {
        byte[] bytes = psi;
        byte last = bytes[^1];

        string code = omega switch
        {
            HashTrimmingFunction.TwoHex => last.ToString("X2", CultureInfo.InvariantCulture),
            HashTrimmingFunction.FourHex => bytes[^2].ToString("X2", CultureInfo.InvariantCulture)
                + last.ToString("X2", CultureInfo.InvariantCulture),
            HashTrimmingFunction.LetterDigit => $"{(char)('A' + last / 10)}{last % 10}",
            HashTrimmingFunction.DigitLetter => $"{last / 26}{(char)('A' + last % 26)}",
            HashTrimmingFunction.Number0To255 => last.ToString(CultureInfo.InvariantCulture),
            HashTrimmingFunction.Number1To256 => (last + 1).ToString(CultureInfo.InvariantCulture),
            HashTrimmingFunction.Number100To355 => (last + 100).ToString(CultureInfo.InvariantCulture),
            HashTrimmingFunction.Number101To356 => (last + 101).ToString(CultureInfo.InvariantCulture),
            _ => throw new ArgumentOutOfRangeException(nameof(omega), omega, "Unknown hash-trimming function."),
        };

        return new ShortCode(code);
    }

    /// <summary>
    /// The number of distinct short codes the function can produce. A contest with more selection
    /// and null vectors than this cannot be given unique short codes (§4.1.5).
    /// </summary>
    public static int CodeSpaceSize(HashTrimmingFunction omega)
    {
        return omega switch
        {
            HashTrimmingFunction.FourHex => 1 << 16,
            >= HashTrimmingFunction.TwoHex and <= HashTrimmingFunction.Number101To356 => 1 << 8,
            _ => throw new ArgumentOutOfRangeException(nameof(omega), omega, "Unknown hash-trimming function."),
        };
    }
}
