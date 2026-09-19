using System.ComponentModel;
using System.Globalization;

namespace ElectionGuard.Perf.Cli.Commands;

/// <summary>The value of <c>--guardians N:K</c>.</summary>
[TypeConverter(typeof(GuardianThresholdConverter))]
public sealed record GuardianThreshold(int N, int K)
{
    public static GuardianThreshold Parse(string value)
    {
        var parts = value.Split(':');
        if (parts.Length != 2 || !int.TryParse(parts[0], out var n) || !int.TryParse(parts[1], out var k))
        {
            throw new FormatException($"--guardians expects N:K, got '{value}'.");
        }

        return new GuardianThreshold(n, k);
    }
}

public sealed class GuardianThresholdConverter : TypeConverter
{
    public override bool CanConvertFrom(ITypeDescriptorContext? context, Type sourceType) =>
        sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);

    public override object? ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value) =>
        value is string text ? GuardianThreshold.Parse(text) : base.ConvertFrom(context, culture, value);
}
