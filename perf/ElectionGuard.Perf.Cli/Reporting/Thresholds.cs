using System.Text.Json;
using ElectionGuard.Perf.Cli.Configuration;

namespace ElectionGuard.Perf.Cli.Reporting;

/// <summary>
/// Regression tolerances, as a percentage increase over baseline.
///
/// Allocation is strict and timing is loose on purpose. Identical inputs allocate identically to
/// within a fraction of a percent, with no sensitivity to thermal throttling, noisy neighbours or
/// scheduling -- so allocation is a usable signal on hardware where timing is not.
/// </summary>
public sealed record Thresholds
{
    /// <summary>Informational only -- a wall-time breach never gates the exit code.</summary>
    public double WallMsPercent { get; init; } = 15;

    /// <summary>The only gating metric: a breach here fails `compare`.</summary>
    public double AllocatedBytesPercent { get; init; } = 2;

    /// <summary>
    /// Informational only. Peak heap is sampled with GC.GetTotalMemory(false), so it carries
    /// uncollected gen-0 garbage as well as DKG and warmup, and was measured moving 8.63% between
    /// two identical runs -- too noisy to fail a build on. See RunComparer.
    /// </summary>
    public double PeakHeapPercent { get; init; } = 10;

    public static Thresholds Load(string path)
    {
        if (!File.Exists(path))
        {
            return new Thresholds();
        }

        try
        {
            return JsonSerializer.Deserialize<Thresholds>(File.ReadAllBytes(path), PerfJson.Options) ?? new Thresholds();
        }
        catch (JsonException ex)
        {
            throw new ScenarioConfigurationException($"Thresholds file {path} could not be read: {ex.Message}");
        }
    }
}
