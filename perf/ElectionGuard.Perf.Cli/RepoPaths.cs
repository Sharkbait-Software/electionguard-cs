namespace ElectionGuard.Perf.Cli;

public static class RepoPaths
{
    /// <summary>
    /// Walks up from a starting directory looking for the repository root, so the tool works from
    /// anywhere in the tree and from the build output directory.
    /// </summary>
    public static string FindRoot(string start)
    {
        var directory = new DirectoryInfo(start);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, ".git"))
                || File.Exists(Path.Combine(directory.FullName, "electionguard-cs.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            $"Could not locate the repository root above '{start}'. Pass --repo-root explicitly.");
    }

    public static string Scenarios(string root) => Path.Combine(root, "perf", "scenarios");

    public static string Results(string root) => Path.Combine(root, "perf", "results");

    public static string ResultsLatest(string root) => Path.Combine(root, "perf", "results", "latest");

    public static string Thresholds(string root) => Path.Combine(root, "perf", "thresholds.json");
}
