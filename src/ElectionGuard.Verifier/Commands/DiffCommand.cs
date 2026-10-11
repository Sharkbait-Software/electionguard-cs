using System.ComponentModel;
using ElectionGuard.Core.RecordFormat;
using Spectre.Console;
using Spectre.Console.Cli;

namespace ElectionGuard.Verifier.Commands;

/// <summary>
/// <c>egrecord diff</c>: <see cref="ElectionRecord.DiffAsync"/>, by descent from the roots (only the
/// sections whose roots differ are read). Exits 0 when the two are equivalent (the same logical
/// record, whatever their encodings and carriers), 1 when they differ.
/// </summary>
public sealed class DiffCommand : AsyncCommand<DiffCommand.Settings>
{
    public sealed class Settings : RecordSettings
    {
        [CommandArgument(1, "<other>")]
        [Description("The second record.")]
        public string Other { get; set; } = "";

        public override ValidationResult Validate()
        {
            var basic = base.Validate();
            return !basic.Successful ? basic : string.IsNullOrWhiteSpace(Other) ? ValidationResult.Error("A second record is required.") : ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        await using var a = await ElectionRecord.OpenAsync(settings.Path, cancellationToken);
        await using var b = await ElectionRecord.OpenAsync(settings.Other, cancellationToken);
        var differences = new List<RecordDifference>();
        await foreach (var difference in ElectionRecord.DiffAsync(a, b, cancellationToken))
        {
            differences.Add(difference);
        }

        if (settings.Json)
        {
            Formats.WriteJson(json =>
            {
                json.WriteStartObject();
                json.WriteBoolean("equivalent", differences.Count == 0);
                json.WriteStartArray("differences");
                foreach (var d in differences)
                {
                    json.WriteStartObject();
                    json.WriteString("kind", d.Kind.ToString());
                    if (d.Section is { } section)
                    {
                        json.WriteString("section", section.ToString());
                    }

                    if (d.Ordinal is { } ordinal)
                    {
                        json.WriteNumber("ordinal", ordinal);
                    }

                    json.WriteString("leafA", d.LeafA?.ToString());
                    json.WriteString("leafB", d.LeafB?.ToString());
                    json.WriteString("message", d.Message);
                    json.WriteEndObject();
                }

                json.WriteEndArray();
                json.WriteEndObject();
            });
        }
        else
        {
            foreach (var d in differences)
            {
                Console.Out.WriteLine($"{d.Kind,-15} {d.Message}");
            }

            Console.Out.WriteLine(differences.Count == 0 ? "equivalent: the same logical record (equal roots)" : $"{differences.Count} difference(s)");
        }

        return differences.Count == 0 ? Program.Passed : Program.Failed;
    }
}
