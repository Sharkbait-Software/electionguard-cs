using System.ComponentModel;
using Spectre.Console;
using Spectre.Console.Cli;

namespace ElectionGuard.Verifier.Commands;

/// <summary>The settings every command that reads one record shares: the record and <c>--json</c>.</summary>
public class RecordSettings : CommandSettings
{
    [CommandArgument(0, "<path>")]
    [Description("The record: a directory, or a .zip, in either encoding.")]
    public string Path { get; set; } = "";

    [CommandOption("--json")]
    [Description("Write the result as JSON on standard output.")]
    public bool Json { get; set; }

    public override ValidationResult Validate() =>
        string.IsNullOrWhiteSpace(Path) ? ValidationResult.Error("A record path is required.") : ValidationResult.Success();
}
