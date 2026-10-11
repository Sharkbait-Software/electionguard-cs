using System.ComponentModel;
using ElectionGuard.Core.RecordFormat;
using Spectre.Console;
using Spectre.Console.Cli;

namespace ElectionGuard.Verifier.Commands;

/// <summary>
/// <c>egrecord convert</c>: <see cref="ElectionRecord.ConvertAsync"/> into a new directory, or a new
/// <c>.zip</c> when the destination ends <c>.zip</c>. A converter is correct iff it preserves every
/// phase root (design §5.1); the roots are printed. Content a JSON line cannot carry (a newer minor's)
/// is refused (<c>R.version</c>, exit 1), never dropped.
/// </summary>
public sealed class ConvertCommand : AsyncCommand<ConvertCommand.Settings>
{
    public sealed class Settings : RecordSettings
    {
        [CommandArgument(1, "<destination>")]
        [Description("A new or empty directory, or a new file ending .zip.")]
        public string Destination { get; set; } = "";

        [CommandOption("--encoding <ENCODING>")]
        [Description("protobuf or json.")]
        public string Encoding { get; set; } = "";

        public override ValidationResult Validate()
        {
            var basic = base.Validate();
            if (!basic.Successful)
            {
                return basic;
            }

            if (string.IsNullOrWhiteSpace(Destination))
            {
                return ValidationResult.Error("A destination is required.");
            }

            return Encoding is "protobuf" or "json" ? ValidationResult.Success() : ValidationResult.Error("--encoding is protobuf or json.");
        }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var encoding = settings.Encoding == "json" ? RecordEncoding.Json : RecordEncoding.Protobuf;
        var carrier = settings.Destination.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ? RecordCarrier.Zip : RecordCarrier.Directory;
        await using var reader = await ElectionRecord.OpenAsync(settings.Path, cancellationToken);
        var toc = await ElectionRecord.ConvertAsync(reader, settings.Destination, encoding, carrier, -1, ct: cancellationToken);
        var phases = Enum.GetValues<RecordPhase>().Where(x => x <= toc.Phase).ToList();
        if (settings.Json)
        {
            Formats.WriteJson(json =>
            {
                json.WriteStartObject();
                json.WriteString("destination", settings.Destination);
                json.WriteString("encoding", Formats.Encoding(encoding));
                json.WriteString("carrier", Formats.Carrier(carrier));
                json.WriteStartObject("phaseRoots");
                foreach (var phase in phases)
                {
                    json.WriteString(Formats.Phase(phase), toc.PhaseRoot(phase).ToString());
                }

                json.WriteEndObject();
                json.WriteEndObject();
            });
        }
        else
        {
            Console.Out.WriteLine($"wrote {settings.Destination} ({Formats.Encoding(encoding)} {Formats.Carrier(carrier)})");
            foreach (var phase in phases)
            {
                Console.Out.WriteLine($"{Formats.Phase(phase),-10} {toc.PhaseRoot(phase)}");
            }
        }

        return Program.Passed;
    }
}
