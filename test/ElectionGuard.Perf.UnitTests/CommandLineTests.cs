using ElectionGuard.Perf.Cli;
using ElectionGuard.Perf.Cli.Commands;
using Spectre.Console.Cli;

namespace ElectionGuard.Perf.UnitTests;

/// <summary>
/// The command tree Program configures: which options each command binds, what it rejects, and the
/// exit code a usage error produces. The command tests (RunCommandTests etc.) cover execution.
/// </summary>
public class CommandLineTests
{
    /// <summary>Thrown by the interceptor once settings are bound, so no command actually executes.</summary>
    private sealed class BindingCaptured : Exception;

    private sealed class CaptureInterceptor(Action<CommandSettings> capture) : ICommandInterceptor
    {
        public void Intercept(CommandContext context, CommandSettings settings)
        {
            capture(settings);
            throw new BindingCaptured();
        }
    }

    /// <summary>Parses and binds args through Program's real configuration, without executing.</summary>
    private static TSettings Bind<TSettings>(params string[] args)
        where TSettings : CommandSettings
    {
        CommandSettings? bound = null;
        Exception? failure = null;

        var app = new CommandApp();
        app.Configure(config =>
        {
            Program.Configure(config);
            config.SetInterceptor(new CaptureInterceptor(settings => bound = settings));
            config.SetExceptionHandler((exception, _) =>
            {
                failure = exception is BindingCaptured ? null : exception;
                return 0;
            });
        });
        app.Run(args);

        Assert.Null(failure);
        return Assert.IsType<TSettings>(bound);
    }

    /// <summary>Runs Program.Main with stderr captured, restoring Console.Error even if Main throws.</summary>
    private static (int ExitCode, string StdErr) RunCapturingError(params string[] args)
    {
        var originalError = Console.Error;
        var writer = new StringWriter();
        Console.SetError(writer);
        try
        {
            return (Program.Main(args), writer.ToString());
        }
        finally
        {
            Console.SetError(originalError);
        }
    }

    [Fact]
    public void Run_BindsEveryOption()
    {
        var settings = Bind<RunCommand.Settings>(
            "run",
            "--repo-root", "root",
            "--scenario", "medium",
            "--ballots", "5000",
            "--seed", "7",
            "--parallelism", "1",
            "--chunk", "250",
            "--warmup", "10",
            "--guardians", "5:3",
            "--no-decrypt",
            "--no-ballot-verification",
            "--no-tally-verification",
            "--no-serialization",
            "--repeat", "3",
            "--machine", "box",
            "--markdown",
            "--results-dir", "results",
            "--allow-debug");

        Assert.Equal("root", settings.RepoRoot);
        Assert.Equal("medium", settings.Scenario);
        Assert.Equal(5000, settings.Ballots);
        Assert.Equal(7, settings.Seed);
        Assert.Equal(1, settings.Parallelism);
        Assert.Equal(250, settings.Chunk);
        Assert.Equal(10, settings.Warmup);
        Assert.Equal(new GuardianThreshold(5, 3), settings.Guardians);
        Assert.True(settings.NoDecrypt);
        Assert.True(settings.NoBallotVerification);
        Assert.True(settings.NoTallyVerification);
        Assert.True(settings.NoSerialization);
        Assert.Equal(3, settings.Repeat);
        Assert.Equal("box", settings.Machine);
        Assert.True(settings.Markdown);
        Assert.Equal("results", settings.ResultsDir);
        Assert.True(settings.AllowDebug);
    }

    [Fact]
    public void Run_LeavesOmittedOverridesUnset()
    {
        var settings = Bind<RunCommand.Settings>("run", "--scenario", "medium");

        Assert.Null(settings.RepoRoot);
        Assert.Null(settings.Ballots);
        Assert.Null(settings.Guardians);
        Assert.Null(settings.Repeat);
        Assert.False(settings.NoDecrypt);
        Assert.False(settings.Markdown);
        Assert.False(settings.AllowDebug);
    }

    [Fact]
    public void Run_SupportsEqualsSyntax()
    {
        var settings = Bind<RunCommand.Settings>("run", "--scenario=large", "--ballots=10");

        Assert.Equal("large", settings.Scenario);
        Assert.Equal(10, settings.Ballots);
    }

    [Fact]
    public void Compare_BindsEveryOption()
    {
        var settings = Bind<CompareCommand.Settings>(
            "compare",
            "--repo-root", "root",
            "--scenario", "medium",
            "--baseline", "abc",
            "--candidate", "def",
            "--machine", "box",
            "--results-dir", "results");

        Assert.Equal("root", settings.RepoRoot);
        Assert.Equal("medium", settings.Scenario);
        Assert.Equal("abc", settings.Baseline);
        Assert.Equal("def", settings.Candidate);
        Assert.Equal("box", settings.Machine);
        Assert.Equal("results", settings.ResultsDir);
    }

    [Fact]
    public void Report_BindsEveryOption()
    {
        var settings = Bind<ReportCommand.Settings>(
            "report",
            "--repo-root", "root",
            "--output", "out.html",
            "--machine", "box",
            "--results-dir", "results");

        Assert.Equal("root", settings.RepoRoot);
        Assert.Equal("out.html", settings.Output);
        Assert.Equal("box", settings.Machine);
        Assert.Equal("results", settings.ResultsDir);
    }

    [Fact]
    public void Corpus_BindsEveryOption()
    {
        var settings = Bind<CorpusCommand.Settings>(
            "corpus",
            "--repo-root", "root",
            "--scenario", "small",
            "--output", "out",
            "--ballots", "10",
            "--seed", "7");

        Assert.Equal("root", settings.RepoRoot);
        Assert.Equal("small", settings.Scenario);
        Assert.Equal("out", settings.Output);
        Assert.Equal(10, settings.Ballots);
        Assert.Equal(7, settings.Seed);
    }

    /// <summary>
    /// Before strict parsing, "--balots 1000" on the large scenario was accepted, ignored, and
    /// silently ran a million ballots, recording the result as authoritative.
    /// </summary>
    [Theory]
    [InlineData("--balots", "run", "--scenario", "large", "--balots", "1000")]
    [InlineData("--scenerio", "compare", "--scenerio", "medium")]
    [InlineData("--balots", "corpus", "--scenario", "small", "--output", "out", "--balots", "10")]
    // `report --html` used to parse and do nothing. HTML is the only output it produces.
    [InlineData("--html", "report", "--html")]
    public void UnknownOption_ExitsTwoAndNamesTheOption(string offending, params string[] args)
    {
        var (exitCode, stdErr) = RunCapturingError(args);

        Assert.Equal(Program.UsageErrorExitCode, exitCode);
        Assert.Contains($"Unknown option '{offending.TrimStart('-')}'", stdErr, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("scenario", "run")]
    [InlineData("scenario", "corpus", "--output", "out")]
    [InlineData("output", "corpus", "--scenario", "small")]
    public void MissingRequiredOption_ExitsTwoAndNamesTheOption(string missing, params string[] args)
    {
        var (exitCode, stdErr) = RunCapturingError(args);

        Assert.Equal(Program.UsageErrorExitCode, exitCode);
        Assert.Contains($"'{missing}'", stdErr, StringComparison.Ordinal);
    }

    [Fact]
    public void NonNumericValue_ExitsTwoAndSaysAWholeNumberWasExpected()
    {
        var (exitCode, stdErr) = RunCapturingError("run", "--scenario", "smoke", "--ballots", "many");

        Assert.Equal(Program.UsageErrorExitCode, exitCode);
        Assert.Contains("Expected a whole number, got 'many'.", stdErr, StringComparison.Ordinal);
    }

    [Fact]
    public void MalformedGuardians_ExitsTwoAndSaysNColonKWasExpected()
    {
        var (exitCode, stdErr) = RunCapturingError("run", "--scenario", "smoke", "--guardians", "3");

        Assert.Equal(Program.UsageErrorExitCode, exitCode);
        Assert.Contains("--guardians expects N:K, got '3'.", stdErr, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("3:2", 3, 2)]
    [InlineData("5:3", 5, 3)]
    public void GuardianThreshold_ParsesNColonK(string value, int expectedN, int expectedK)
    {
        Assert.Equal(new GuardianThreshold(expectedN, expectedK), GuardianThreshold.Parse(value));
    }

    [Theory]
    [InlineData("3")]
    [InlineData("3:")]
    [InlineData("a:b")]
    [InlineData("3:2:1")]
    public void GuardianThreshold_ThrowsOnAMalformedValue(string value)
    {
        Assert.Throws<FormatException>(() => GuardianThreshold.Parse(value));
    }

    [Fact]
    public void RewriteHelpVerb_MapsTheHelpVerbOntoTheHelpFlag()
    {
        Assert.Equal(["--help"], Program.RewriteHelpVerb(["help"]));
        Assert.Equal(["run", "--help"], Program.RewriteHelpVerb(["help", "run"]));
        Assert.Equal(["run", "--scenario", "help"], Program.RewriteHelpVerb(["run", "--scenario", "help"]));
    }
}
