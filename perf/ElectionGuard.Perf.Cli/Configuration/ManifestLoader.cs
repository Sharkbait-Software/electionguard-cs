using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;

namespace ElectionGuard.Perf.Cli.Configuration;

/// <summary>
/// Loads and validates a manifest file with consistent error handling across the tool.
/// Mirrors ScenarioLoader.Load's care for its own file: check existence, catch malformed JSON,
/// and reject a null deserialization -- all wrapped in the tool's friendly exception type so a
/// typo'd manifest path (in the scenario file, or via a wrong --repo-root) gets the two-line
/// message Program.cs already knows how to print, not a raw stack trace.
/// </summary>
public static class ManifestLoader
{
    /// <summary>
    /// Where a scenario's manifest resolves to on disk. A scenario names its manifest by a
    /// repo-relative path, so this is the one place that combines it with the repo root -- callers
    /// that need the path (RunCommand records it in the run's notes) call this instead of
    /// re-deriving <c>Path.Combine(repoRoot, scenario.Manifest)</c> themselves.
    /// </summary>
    public static string ResolvePath(string repoRoot, PerfScenario scenario) =>
        Path.Combine(repoRoot, scenario.Manifest);

    public static Manifest Load(string repoRoot, PerfScenario scenario)
    {
        var manifestPath = ResolvePath(repoRoot, scenario);

        if (!File.Exists(manifestPath))
        {
            throw new ScenarioConfigurationException(
                $"Scenario '{scenario.Id}' points at manifest {manifestPath}, which does not exist.");
        }

        // Core's manifest format (ManifestSerializer): strict, case-sensitive, validated. It is the
        // format the encryption record parses its manifest from.
        try
        {
            return ManifestSerializer.Deserialize(File.ReadAllBytes(manifestPath));
        }
        catch (InvalidManifestException ex)
        {
            throw new ScenarioConfigurationException(
                $"Scenario '{scenario.Id}' points at manifest {manifestPath}, which could not be read: {ex.Message}");
        }
    }
}
