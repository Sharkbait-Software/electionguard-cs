namespace ElectionGuard.Core.PreEncryption;

/// <summary>
/// §4.6 Hash-Trimming Functions. The pre-specified functions Ω that turn a selection hash ψ into a
/// short code. Each value equals the subscript of the function in the spec (Ω1..Ω8), so the number
/// recorded in a manifest names the function unambiguously.
/// </summary>
public enum HashTrimmingFunction
{
    /// <summary>Ω1: final byte as two hexadecimal characters.</summary>
    TwoHex = 1,
    /// <summary>Ω2: final two bytes as four hexadecimal characters.</summary>
    FourHex = 2,
    /// <summary>Ω3: final byte as a letter followed by a digit, {0..255} -> {A0..A9, B0..B9, ..., Z0..Z5}.</summary>
    LetterDigit = 3,
    /// <summary>Ω4: final byte as a digit followed by a letter, {0..255} -> {0A..0Z, 1A..1Z, ..., 9A..9V}.</summary>
    DigitLetter = 4,
    /// <summary>Ω5: final byte as a number 0-255.</summary>
    Number0To255 = 5,
    /// <summary>Ω6: final byte plus 1, as a number 1-256.</summary>
    Number1To256 = 6,
    /// <summary>Ω7: final byte plus 100, as a number 100-355.</summary>
    Number100To355 = 7,
    /// <summary>Ω8: final byte plus 101, as a number 101-356.</summary>
    Number101To356 = 8,
}
