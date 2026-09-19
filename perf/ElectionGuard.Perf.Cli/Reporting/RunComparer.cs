using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.Cli.Reporting;

public sealed record MetricDelta(
    string Phase,
    string Metric,
    double Baseline,
    double Candidate,
    double PercentChange,
    bool Breach,
    /// <summary>
    /// True for the one strict, load-bearing metric -- allocation -- that can fail a build.
    /// Wall-time and peak-heap deltas are informational only: they can be flagged as over
    /// tolerance, but they never gate the exit code -- see HasBreach.
    /// </summary>
    bool Gates,
    /// <summary>
    /// True when the baseline for this metric was zero, so PercentChange (always finite, never
    /// zero-baseline-divided) is meaningless and should be rendered as "new" rather than 0%.
    /// </summary>
    bool BaselineWasZero);

public sealed record ComparisonResult
{
    public required IReadOnlyList<MetricDelta> Deltas { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }

    /// <summary>
    /// False when the two runs were produced under conditions that make the numbers incomparable.
    /// Deltas are still reported for information, but no breach is ever declared.
    /// </summary>
    public required bool Comparable { get; init; }

    /// <summary>
    /// Only a breach on a gating metric -- allocation -- fails the run. Wall-time and peak-heap
    /// breaches are still visible on their MetricDelta, but are informational and must never gate
    /// the exit code: both move run to run on identical inputs, and allocation does not.
    /// </summary>
    public bool HasBreach => Comparable && Deltas.Any(x => x.Breach && x.Gates);
}

public static class RunComparer
{
    public static ComparisonResult Compare(RunRecord baseline, RunRecord candidate, Thresholds thresholds)
    {
        var warnings = new List<string>();
        bool comparable = true;

        void Incomparable(string reason)
        {
            comparable = false;
            warnings.Add(reason);
        }

        if (baseline.Environment.BuildConfig != candidate.Environment.BuildConfig)
        {
            Incomparable($"Build configuration differs ({baseline.Environment.BuildConfig} vs {candidate.Environment.BuildConfig}).");
        }

        if (baseline.Environment.GcMode != candidate.Environment.GcMode)
        {
            Incomparable($"GC mode differs ({baseline.Environment.GcMode} vs {candidate.Environment.GcMode}).");
        }

        if (baseline.Environment.MachineId != candidate.Environment.MachineId)
        {
            Incomparable($"Machine differs ({baseline.Environment.MachineId} vs {candidate.Environment.MachineId}).");
        }

        if (baseline.Scenario.ConfigHash != candidate.Scenario.ConfigHash)
        {
            Incomparable("Scenario configuration differs; the runs measured different workloads.");
        }

        // ConfigHash cannot see this. The scenario record it hashes holds the manifest as a PATH
        // STRING, so editing the manifest file changes the election shape -- contests, choices,
        // chaining -- completely while leaving ConfigHash byte-identical. ManifestHash is the hash
        // of the manifest's canonical bytes and is the only thing that catches it.
        if (baseline.Scenario.ManifestHash != candidate.Scenario.ManifestHash)
        {
            Incomparable("Manifest content differs; the runs measured different elections.");
        }

        // A run whose Correctness.Status is Error or Failed did not produce a trustworthy tally --
        // its phase metrics may be partial (an error mid-run) or simply not proof of anything
        // (a failed tally comparison). Aborted-phase judgeable guards below catch the specific
        // zero-baseline case this leaves in the JSONL history, but the general principle stands on
        // its own: a run that did not succeed is not a measurement to compare against, gating or
        // not, regardless of which individual phases happen to look clean.
        if (baseline.Correctness.Status is CorrectnessStatus.Error or CorrectnessStatus.Failed)
        {
            Incomparable(
                $"Baseline run '{baseline.RunId}' did not complete successfully " +
                $"(correctness status '{baseline.Correctness.Status}'); refusing to judge against it.");
        }

        if (candidate.Correctness.Status is CorrectnessStatus.Error or CorrectnessStatus.Failed)
        {
            Incomparable(
                $"Candidate run '{candidate.RunId}' did not complete successfully " +
                $"(correctness status '{candidate.Correctness.Status}'); refusing to judge against it.");
        }

        if (baseline.SchemaVersion != candidate.SchemaVersion)
        {
            warnings.Add($"Record schema versions differ ({baseline.SchemaVersion} vs {candidate.SchemaVersion}).");
        }

        // Phase sets legitimately change over time as previously impractical phases become
        // practical. Compare the intersection and name the difference; never read an absent phase
        // as a zero.
        foreach (var phase in baseline.Phases.Keys.Except(candidate.Phases.Keys))
        {
            warnings.Add($"Phase '{phase}' ran in the baseline but not in the candidate.");
        }

        foreach (var phase in candidate.Phases.Keys.Except(baseline.Phases.Keys))
        {
            warnings.Add($"Phase '{phase}' ran in the candidate but not in the baseline.");
        }

        var deltas = new List<MetricDelta>();

        foreach (var phase in baseline.Phases.Keys.Intersect(candidate.Phases.Keys).OrderBy(x => x, StringComparer.Ordinal))
        {
            var before = baseline.Phases[phase];
            var after = candidate.Phases[phase];

            // An aborted phase's numbers cover only part of the workload, so they are reported but
            // never allowed to declare a regression.
            bool judgeable = !before.Aborted && !after.Aborted;
            if (!judgeable)
            {
                warnings.Add($"Phase '{phase}' was aborted in at least one run; its deltas are informational only.");
            }

            int beforeBallots = Math.Max(1, before.BallotsProcessed);
            int afterBallots = Math.Max(1, after.BallotsProcessed);

            deltas.Add(Delta(phase, "msPerBallot",
                before.WallMs / beforeBallots, after.WallMs / afterBallots,
                thresholds.WallMsPercent, judgeable, gates: false));

            deltas.Add(Delta(phase, "allocBytesPerBallot",
                before.AllocatedBytes / (double)beforeBallots, after.AllocatedBytes / (double)afterBallots,
                thresholds.AllocatedBytesPercent, judgeable, gates: true));
        }

        // Informational, NOT gating. Peak heap was measured moving 8.63% between two identical
        // back-to-back runs against a 10% tolerance -- it is a noisy signal for the same reason
        // wall time is. GC.GetTotalMemory(false) counts uncollected gen-0 garbage, and the sampler
        // starts before DKG and warmup, so their allocations land in the peak too. Allocation moved
        // ~0% in that same comparison, which is why allocBytesPerBallot is the sole gate.
        deltas.Add(Delta("memory", "peakManagedHeapBytes",
            baseline.Memory.PeakManagedHeapBytes, candidate.Memory.PeakManagedHeapBytes,
            thresholds.PeakHeapPercent, judgeable: true, gates: false));

        return new ComparisonResult { Deltas = deltas, Warnings = warnings, Comparable = comparable };
    }

    private static MetricDelta Delta(
        string phase, string metric, double baseline, double candidate, double tolerancePercent,
        bool judgeable, bool gates)
    {
        bool baselineWasZero = baseline == 0;

        // A zero baseline has no meaningful percentage. Report the change without a manufactured
        // number -- never Infinity/NaN, which System.Text.Json refuses to serialize -- and let
        // BaselineWasZero carry the meaning instead.
        double percent = baselineWasZero ? 0 : (candidate - baseline) / baseline * 100.0;

        bool breach = baselineWasZero
            // A gating metric (allocation) that legitimately allocated nothing at baseline and now
            // allocates something is a real regression, not noise; it must not read as a flat 0.00%.
            ? judgeable && gates && candidate > 0
            : judgeable && percent > tolerancePercent;

        return new MetricDelta(phase, metric, baseline, candidate, percent, breach, gates, baselineWasZero);
    }
}
