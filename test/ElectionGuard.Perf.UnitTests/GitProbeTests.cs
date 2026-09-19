using System.Diagnostics;
using System.Runtime.InteropServices;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.UnitTests;

/// <summary>
/// Pins GitProbe's process handling, which runs at the start of every unattended run and is the
/// one place in the harness that can hang the whole thing.
///
/// The probe is exercised against a stand-in child rather than git, because git cannot be made to
/// behave badly on demand: these tests need a process that refuses to exit, and one that floods a
/// pipe. GitProbe.Run's fileName/timeout parameters exist for exactly this.
/// </summary>
public class GitProbeTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("egperf-gitprobe-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A child that outlived its kill would hold the directory. The assertions, not cleanup,
            // are what report that.
        }
    }

    private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    /// <summary>
    /// A child that waits about a second and only then writes its marker, so the marker's absence
    /// afterwards is proof the child never got to finish rather than proof it was slow.
    /// </summary>
    private static (string FileName, string Arguments) SlowMarkerWriter() => IsWindows
        ? ("cmd.exe", "/c ping -n 2 127.0.0.1 > nul & echo alive > alive.txt")
        : ("/bin/sh", "-c \"sleep 1; echo alive > alive.txt\"");

    private static (string FileName, string Arguments) StderrFlood(string fileName) => IsWindows
        ? ("cmd.exe", $"/c type {fileName} 1>&2")
        : ("/bin/sh", $"-c \"cat {fileName} 1>&2\"");

    [Fact]
    public void Run_TimesOutAndKillsAChildThatWillNotExit()
    {
        var (fileName, arguments) = SlowMarkerWriter();
        var marker = Path.Combine(_directory, "alive.txt");

        var stopwatch = Stopwatch.StartNew();
        var result = GitProbe.Run(fileName, _directory, arguments, timeoutMs: 50);
        stopwatch.Stop();

        Assert.Null(result);
        Assert.True(
            stopwatch.ElapsedMilliseconds < 3000,
            $"The probe took {stopwatch.ElapsedMilliseconds} ms against a 50 ms timeout; the timeout " +
            "must bound the whole operation, not just part of it.");

        // Longer than the child's own delay: if the process tree survived the timeout, the marker
        // appears in this window.
        Thread.Sleep(1500);

        Assert.False(
            File.Exists(marker),
            "The timed-out child kept running and completed its work. GitProbe must kill the process " +
            "tree on timeout, not abandon it -- an abandoned git holds a lock and burns a core.");
    }

    /// <summary>
    /// The deadlock regression. Reading stdout to the end before waiting for exit hangs forever
    /// when the child fills the stderr pipe buffer that nobody is draining, which is exactly what
    /// `git status` does in a repository with a large number of warnings. Both pipes must be
    /// drained concurrently with the exit wait.
    /// </summary>
    [Fact]
    public void Run_CompletesWhenTheChildFloodsStderr()
    {
        var payload = Path.Combine(_directory, "payload.txt");
        File.WriteAllText(payload, string.Concat(Enumerable.Repeat(new string('x', 255) + "\n", 1024)));

        var (fileName, arguments) = StderrFlood("payload.txt");

        var stopwatch = Stopwatch.StartNew();
        var result = GitProbe.Run(fileName, _directory, arguments, timeoutMs: 30_000);
        stopwatch.Stop();

        // Exit code 0 with nothing on stdout: the probe's own success path, trimmed to empty.
        Assert.Equal(string.Empty, result);
        Assert.True(
            stopwatch.ElapsedMilliseconds < 10_000,
            $"Draining ~256 KB of stderr took {stopwatch.ElapsedMilliseconds} ms; that is the shape " +
            "of the deadlock this test exists to catch.");
    }

    [Fact]
    public void Run_ReturnsNullWhenTheExecutableIsNotOnPath()
    {
        // Degrading to null rather than throwing is the contract: a run outside a checkout, or on a
        // machine without git, is still a legitimate run.
        Assert.Null(GitProbe.Run(
            "egperf-no-such-executable", _directory, "--version", timeoutMs: 1000));
    }

    [Fact]
    public void Capture_NeverThrowsAndAlwaysFillsEverySourceField()
    {
        var source = GitProbe.Capture(_directory);

        Assert.False(string.IsNullOrWhiteSpace(source.Commit));
        Assert.False(string.IsNullOrWhiteSpace(source.Branch));
    }
}
