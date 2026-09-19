using System.Diagnostics;

namespace ElectionGuard.Perf.UnitTests;

/// <summary>
/// In-process tests call Program.Main directly (see CommandLineTests). These launch the actual built CLI
/// as a child process instead, proving Program.cs is wired to it and that help and errors reach the
/// right stream with the right process exit code.
///
/// This works because ElectionGuard.Perf.UnitTests references ElectionGuard.Perf.Cli as a
/// ProjectReference, so the build copies egperf's apphost (egperf.exe) into this test project's own
/// output directory alongside the test assembly -- no separate publish step or hardcoded path back
/// into the perf project's bin folder is needed.
/// </summary>
public class ProgramTests
{
    private static readonly string ExecutablePath = Path.Combine(
        AppContext.BaseDirectory,
        OperatingSystem.IsWindows() ? "egperf.exe" : "egperf");

    private static (int ExitCode, string StdOut, string StdErr) Run(params string[] args)
    {
        var startInfo = new ProcessStartInfo(ExecutablePath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        foreach (var arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Failed to start {ExecutablePath}.");

        string stdOut = process.StandardOutput.ReadToEnd();
        string stdErr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return (process.ExitCode, stdOut, stdErr);
    }

    [Fact]
    public void UnknownVerb_ExitsTwoAndNamesTheProblem()
    {
        var (exitCode, _, stdErr) = Run("frobnicate");

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown command 'frobnicate'", stdErr);
    }

    [Theory]
    [InlineData]
    [InlineData("--help")]
    [InlineData("help")]
    public void TopLevelHelp_PrintsUsageAndExitsZero(params string[] args)
    {
        var (exitCode, stdOut, _) = Run(args);

        Assert.Equal(0, exitCode);
        Assert.Contains("egperf [OPTIONS] <COMMAND>", stdOut);
        Assert.Contains("Run a scenario and record the result", stdOut);
    }

    /// <summary>
    /// `--help` after a command is the most natural thing to type; it must print that command's
    /// options rather than be rejected as an unknown option by strict parsing.
    /// </summary>
    [Theory]
    [InlineData("run", "--help")]
    [InlineData("help", "run")]
    public void CommandHelp_PrintsTheCommandsOptionsAndExitsZero(params string[] args)
    {
        var (exitCode, stdOut, _) = Run(args);

        Assert.Equal(0, exitCode);
        Assert.Contains("egperf run [OPTIONS]", stdOut);
        Assert.Contains("--scenario <ID|PATH>", stdOut);
        Assert.Contains("--repo-root <DIR>", stdOut);
    }

    [Fact]
    public void UnknownOption_ExitsTwoOnStdErr()
    {
        var (exitCode, _, stdErr) = Run("report", "--html");

        Assert.Equal(2, exitCode);
        Assert.Contains("Unknown option 'html'", stdErr);
    }
}
