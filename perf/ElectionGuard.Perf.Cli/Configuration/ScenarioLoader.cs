using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ElectionGuard.Perf.Cli.Configuration;

/// <summary>Shared JSON settings for every file this tool reads or writes.</summary>
public static class PerfJson
{
    /// <summary>
    /// Settings for hand-authored INPUT files: scenarios, manifests and thresholds.
    ///
    /// UnmappedMemberHandling is Disallow here on purpose. These files are typed by a human, and a
    /// member this tool does not understand is always a mistake with a measurable consequence: a
    /// misspelt "chunkSyze" or a field copied from documentation that the model never had (the
    /// design's illustrative scenario JSON documents a "tallyVerificationMaxBallots" that
    /// PhaseSettings has no member for) would otherwise be silently dropped, leaving the default in
    /// force and recording a wrong measurement as authoritative. Better to refuse the file.
    /// </summary>
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    /// <summary>
    /// Compact, non-indented settings for JSONL, where one record is one line.
    ///
    /// Deliberately does NOT set UnmappedMemberHandling.Disallow, unlike <see cref="Options"/>.
    /// This reads PERSISTED results, which are a forward-compatible wire format: an older binary
    /// must still be able to read a results file written by a newer one that added a field. Failing
    /// on an unknown member here would make a single new field retroactively unreadable to every
    /// build that predates it, destroying the historical record these files exist to hold.
    /// </summary>
    public static readonly JsonSerializerOptions LineOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
    };
}

public static class ScenarioLoader
{
    public static PerfScenario Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new ScenarioConfigurationException($"Scenario file not found: {path}");
        }

        PerfScenario? scenario;
        try
        {
            scenario = JsonSerializer.Deserialize<PerfScenario>(File.ReadAllBytes(path), PerfJson.Options);
        }
        catch (JsonException ex)
        {
            // Covers both malformed JSON and a member this tool does not understand -- PerfJson.Options
            // rejects the latter, and the exception message names the offending property.
            throw new ScenarioConfigurationException($"Scenario file {path} could not be read: {ex.Message}");
        }

        if (scenario is null)
        {
            throw new ScenarioConfigurationException($"Scenario file {path} deserialized to null.");
        }

        Validate(scenario);
        return scenario;
    }

    /// <summary>
    /// Every *.json file in the directory is a scenario. There is deliberately no list of known
    /// scenario ids anywhere -- adding a scenario is adding a file.
    /// </summary>
    public static IReadOnlyList<PerfScenario> LoadAll(string directory)
    {
        if (!Directory.Exists(directory))
        {
            throw new ScenarioConfigurationException($"Scenario directory not found: {directory}");
        }

        return Directory.EnumerateFiles(directory, "*.json", SearchOption.TopDirectoryOnly)
            .OrderBy(x => x, StringComparer.Ordinal)
            .Select(Load)
            .ToList();
    }

    public static void Validate(PerfScenario scenario)
    {
        if (string.IsNullOrWhiteSpace(scenario.Id))
        {
            throw new ScenarioConfigurationException("Scenario id must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(scenario.Manifest))
        {
            throw new ScenarioConfigurationException($"Scenario '{scenario.Id}' must name a manifest.");
        }

        if (scenario.BallotCount < 1)
        {
            throw new ScenarioConfigurationException(
                $"Scenario '{scenario.Id}' has ballotCount {scenario.BallotCount}; it must be at least 1.");
        }

        if (scenario.ChunkSize < 1)
        {
            throw new ScenarioConfigurationException(
                $"Scenario '{scenario.Id}' has chunkSize {scenario.ChunkSize}; it must be at least 1.");
        }

        if (scenario.WarmupBallots < 0)
        {
            throw new ScenarioConfigurationException(
                $"Scenario '{scenario.Id}' has warmupBallots {scenario.WarmupBallots}; it must not be negative.");
        }

        if (scenario.Parallelism < 0)
        {
            throw new ScenarioConfigurationException(
                $"Scenario '{scenario.Id}' has parallelism {scenario.Parallelism}; use 0 for ProcessorCount.");
        }

        if (scenario.Guardians.N < 1 || scenario.Guardians.K < 1 || scenario.Guardians.K > scenario.Guardians.N)
        {
            throw new ScenarioConfigurationException(
                $"Scenario '{scenario.Id}' has an invalid guardian threshold {scenario.Guardians.K}-of-{scenario.Guardians.N}.");
        }

        foreach (var (phase, minutes) in scenario.Budgets)
        {
            if (!PhaseNames.All.Contains(phase))
            {
                throw new ScenarioConfigurationException(
                    $"Scenario '{scenario.Id}' budgets unknown phase '{phase}'. Known phases: {string.Join(", ", PhaseNames.All)}.");
            }

            if (minutes <= 0)
            {
                throw new ScenarioConfigurationException(
                    $"Scenario '{scenario.Id}' budgets phase '{phase}' at {minutes} minutes; a budget must be positive. Omit the key for unlimited.");
            }

            // A budgeted phase (DecryptTally, VerifyTally) is enforced via Task.Wait(TimeSpan), which
            // converts the TimeSpan to a signed 32-bit millisecond count internally and throws
            // ArgumentOutOfRangeException above int.MaxValue ms (~24.855 days) -- a crash with no
            // diagnostic, at the moment the phase actually starts, rather than a message naming the
            // scenario file at load time. Practically unreachable for a real budget, but a typo (an
            // extra zero, or minutes where hours was meant) reaches it easily.
            if (minutes > MaxBudgetMinutes)
            {
                throw new ScenarioConfigurationException(
                    $"Scenario '{scenario.Id}' budgets phase '{phase}' at {minutes:N0} minutes, which exceeds " +
                    $"the ~24.85-day maximum ({MaxBudgetMinutes:N0} minutes) a budget can enforce.");
            }
        }
    }

    /// <summary>int.MaxValue milliseconds, in whole minutes, rounded down so the resulting budget is
    /// never itself the one value that overflows Task.Wait(TimeSpan).</summary>
    private const double MaxBudgetMinutes = int.MaxValue / 60_000.0;

    /// <summary>
    /// A hash of the fully resolved configuration, recorded on every run so that results produced
    /// under a configuration that has since drifted are never silently compared.
    /// </summary>
    public static string ComputeConfigHash(PerfScenario scenario)
    {
        // Budgets are a dictionary, so its enumeration order is not guaranteed stable across
        // processes; normalise before serializing.
        var normalized = scenario with
        {
            Budgets = scenario.Budgets
                .OrderBy(x => x.Key, StringComparer.Ordinal)
                .ToDictionary(x => x.Key, x => x.Value),
        };

        var json = JsonSerializer.Serialize(normalized, PerfJson.LineOptions);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return "sha256:" + Convert.ToHexStringLower(hash);
    }
}
