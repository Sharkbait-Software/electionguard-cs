using System.ComponentModel;
using System.Globalization;

namespace ElectionGuard.Perf.Cli.Commands;

/// <summary>
/// Converts an integer option's value. Spectre's default Int32Converter reports a bad value as
/// "many is not a valid value for Int32. (Parameter 'value')"; this says what was expected instead.
/// </summary>
public sealed class WholeNumberConverter : TypeConverter
{
    public override bool CanConvertFrom(ITypeDescriptorContext? context, Type sourceType) =>
        sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);

    public override object? ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value)
    {
        if (value is not string text)
        {
            return base.ConvertFrom(context, culture, value);
        }

        return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : throw new FormatException($"Expected a whole number, got '{text}'.");
    }
}
