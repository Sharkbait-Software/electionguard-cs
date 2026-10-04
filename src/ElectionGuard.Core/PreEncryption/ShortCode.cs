namespace ElectionGuard.Core.PreEncryption;

/// <summary>
/// §4.1.5 Short Codes. The human-readable code printed beside a selectable option on a
/// pre-encrypted ballot, Ω(ψ) for the option's selection hash ψ.
/// </summary>
public readonly record struct ShortCode(string Value)
{
    public override string ToString() => Value;
}
