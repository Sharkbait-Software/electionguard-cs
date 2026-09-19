using ElectionGuard.Perf.Cli.Commands;
using ElectionGuard.Perf.Cli.Configuration;
using Spectre.Console;
using Spectre.Console.Cli;

namespace ElectionGuard.Perf.Cli;

/// <summary>
/// The egperf command tree. An explicit class rather than top-level statements so tests can call
/// <see cref="Main"/> and <see cref="Configure"/> directly, driving exactly the parsing, validation and
/// exit-code mapping a user gets.
///
/// Exit codes: 0 success, 1 a failed run or a gating regression (set by the commands themselves),
/// 2 a usage or configuration error.
/// </summary>
public static class Program
{
    public const int UsageErrorExitCode = 2;

    public static int Main(string[] args)
    {
        var app = new CommandApp();
        app.Configure(Configure);
        return app.Run(RewriteHelpVerb(args));
    }

    /// <summary>
    /// Spectre has no help verb, only <c>--help</c>. <c>egperf help</c> and <c>egperf help run</c>
    /// predate the move to Spectre and are kept working by rewriting them into that form.
    /// </summary>
    public static string[] RewriteHelpVerb(string[] args) => args switch
    {
        ["help"] => ["--help"],
        ["help", var command] => [command, "--help"],
        _ => args,
    };

    public static void Configure(IConfigurator config)
    {
        config.SetApplicationName("egperf");

        // An unrecognised option is never harmless here: "--balots 1000" on the large scenario used
        // to silently run a million ballots, and every such typo produced a recorded,
        // authoritative-looking measurement of a workload nobody asked for. Non-strict parsing would
        // file the unknown option under remaining arguments and carry on, so strict it is.
        config.UseStrictParsing();

        config.SetExceptionHandler((exception, _) => HandleException(exception));

        config.AddCommand<RunCommand>("run")
            .WithDescription("Run a scenario and record the result.")
            .WithExample("run", "--scenario", "smoke")
            .WithExample("run", "--scenario", "medium", "--ballots", "5000", "--parallelism", "1", "--no-decrypt");

        config.AddCommand<CompareCommand>("compare")
            .WithDescription("Compare recorded runs. Exits 1 when a gating metric regresses beyond tolerance.")
            .WithExample("compare", "--scenario", "medium");

        config.AddCommand<ReportCommand>("report")
            .WithDescription("Generate a self-contained HTML trend report.")
            .WithExample("report", "--output", "perf/results/report.html");

        config.AddCommand<CorpusCommand>("corpus")
            .WithDescription("Materialize a plaintext ballot corpus to disk.")
            .WithExample("corpus", "--scenario", "smoke", "--output", "corpus/smoke");
    }

    private static int HandleException(Exception exception)
    {
        // Written to stderr through a console created per call, so it follows Console.SetError.
        var error = AnsiConsole.Create(new AnsiConsoleSettings { Out = new AnsiConsoleOutput(Console.Error) });

        switch (exception)
        {
            // Parse and validation failures: unknown commands or options, missing required options,
            // values that do not convert.
            case CommandAppException { Pretty: { } pretty }:
                error.Write(pretty);
                return UsageErrorExitCode;
            // A value that failed to convert: Spectre's own message names only the target type
            // ("Failed to convert '3' to GuardianThreshold."), while the converter's says what was expected.
            case CommandRuntimeException { InnerException: FormatException or ArgumentException }:
                error.WriteLine(exception.InnerException.Message);
                return UsageErrorExitCode;
            case CommandAppException:
            case ScenarioConfigurationException:
            case FormatException:
            case ArgumentException:
                error.WriteLine(exception.Message);
                return UsageErrorExitCode;
            default:
                error.WriteException(exception);
                return -1;
        }
    }
}
