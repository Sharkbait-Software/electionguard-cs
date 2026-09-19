using System.Diagnostics;

namespace ElectionGuard.Perf.Cli.Results;

public static class GitProbe
{
    /// <summary>
    /// Bounds an entire git invocation -- process exit plus draining both stdout and stderr.
    /// Not just the wait: stdout.ReadToEnd() alone has no timeout, and if git fills the stderr
    /// pipe buffer while nobody drains it, the child blocks and never closes stdout.
    /// </summary>
    private const int DefaultTimeoutMs = 5000;

    public static SourceInfo Capture(string repositoryRoot) => new()
    {
        Commit = Run(repositoryRoot, "rev-parse --short HEAD") ?? "unknown",
        Branch = Run(repositoryRoot, "rev-parse --abbrev-ref HEAD") ?? "unknown",
        Dirty = !string.IsNullOrWhiteSpace(Run(repositoryRoot, "status --porcelain")),
    };

    private static string? Run(string workingDirectory, string arguments) =>
        Run("git", workingDirectory, arguments, DefaultTimeoutMs);

    /// <summary>
    /// The whole probe, with the executable and the timeout parameterised.
    ///
    /// This is a test seam and nothing else: <see cref="Capture"/> is the wire-facing entry point
    /// and always passes "git" and <see cref="DefaultTimeoutMs"/>. The parameters exist so the
    /// timeout and pipe-draining behaviour -- which runs at the start of every unattended run and
    /// used to be able to deadlock on a full stderr pipe -- can be pinned by a sub-second test
    /// against a child process that behaves the way git would in the failure case.
    /// </summary>
    internal static string? Run(string fileName, string workingDirectory, string arguments, int timeoutMs)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(fileName, arguments)
            {
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });

            if (process is null)
            {
                return null;
            }

            using var cts = new CancellationTokenSource(timeoutMs);
            try
            {
                // Drain stdout and stderr concurrently with the exit wait, all under the same
                // cancellation token, so neither pipe can fill while the other is being read and
                // the timeout genuinely bounds the whole operation -- not just the wait.
                var stdoutTask = process.StandardOutput.ReadToEndAsync(cts.Token);
                var stderrTask = process.StandardError.ReadToEndAsync(cts.Token);
                var exitTask = process.WaitForExitAsync(cts.Token);

                Task.WhenAll(stdoutTask, stderrTask, exitTask).GetAwaiter().GetResult();

                // Only read ExitCode once the process is confirmed exited.
                return process.ExitCode == 0 ? stdoutTask.Result.Trim() : null;
            }
            catch (OperationCanceledException)
            {
                KillProcessTree(process);
                return null;
            }
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // git is not on PATH, or this is not a repository. A run outside a checkout is still a
            // legitimate run; it just cannot be attributed to a commit.
            return null;
        }
    }

    private static void KillProcessTree(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch
        {
            // Best effort -- the process may already have exited between the timeout firing and
            // the kill call. Either way, we already have our answer: null.
        }
    }
}
