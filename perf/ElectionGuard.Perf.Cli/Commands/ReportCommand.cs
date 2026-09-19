using System.ComponentModel;
using ElectionGuard.Perf.Cli.Reporting;
using ElectionGuard.Perf.Cli.Results;
using Spectre.Console.Cli;

namespace ElectionGuard.Perf.Cli.Commands;

public sealed class ReportCommand : Command<ReportCommand.Settings>
{
    /// <summary>
    /// Deliberately no `--html`: it used to parse and do nothing, since HTML is the only output this
    /// command has ever produced. Strict parsing (see Program) now rejects it like any unknown option.
    /// </summary>
    public sealed class Settings : PerfSettings
    {
        [CommandOption("--output <PATH>")]
        [Description("Defaults to perf/results/report.html.")]
        public string? Output { get; set; }

        [CommandOption("--machine <ID>")]
        [Description("Restrict to one machine.")]
        public string? Machine { get; set; }

        [CommandOption("--results-dir <DIR>")]
        [Description("Override perf/results.")]
        public string? ResultsDir { get; set; }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var root = settings.ResolveRepoRoot();
        var resultsDirectory = settings.ResultsDir ?? RepoPaths.Results(root);

        var records = Directory.Exists(resultsDirectory)
            ? Directory.EnumerateFiles(resultsDirectory, "*.jsonl", SearchOption.TopDirectoryOnly)
                .SelectMany(RunRecordStore.ReadAll)
                .OrderBy(x => x.TimestampUtc)
                .ToList()
            : [];

        var machineId = settings.Machine;
        if (machineId is not null)
        {
            var slug = RunRecordStore.Slug(machineId);
            records = records.Where(x => x.Environment.MachineId == slug).ToList();
        }

        var output = settings.Output ?? Path.Combine(resultsDirectory, "report.html");

        // A bare filename with no directory component (`--output report.html`) makes
        // Path.GetDirectoryName return "", and Directory.CreateDirectory("") throws
        // ArgumentException -- "report.html" is perfectly valid as a relative path meaning "the
        // current directory", it just has nothing to create.
        var directory = Path.GetDirectoryName(output);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(output, HtmlReport.Render(records));

        Console.WriteLine($"Wrote {records.Count} run(s) to {output}");
        return 0;
    }
}
