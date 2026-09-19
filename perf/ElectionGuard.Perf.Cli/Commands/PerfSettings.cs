using System.ComponentModel;
using Spectre.Console.Cli;

namespace ElectionGuard.Perf.Cli.Commands;

/// <summary>
/// The options every command accepts. Each command's settings derive from this, so an option added
/// here reaches all four commands without any of them having to declare it.
/// </summary>
public abstract class PerfSettings : CommandSettings
{
    [CommandOption("--repo-root <DIR>")]
    [Description("Repository root. Defaults to the nearest ancestor of the binary containing .git or electionguard-cs.sln.")]
    public string? RepoRoot { get; set; }

    public string ResolveRepoRoot() => RepoRoot ?? RepoPaths.FindRoot(AppContext.BaseDirectory);
}
