using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.Cli.Reporting;

/// <summary>
/// Expands a record selected for `compare` into its --repeat group (RunRecord.RepeatGroup) and, when
/// the group has more than one member, synthesizes a "median record" for RunComparer.Compare to judge
/// instead of the one arbitrarily-selected member. RunCommand already tags every iteration of a
/// --repeat invocation with a shared RepeatGroup id; until now nothing read it back, so comparing a
/// repeat group threw away every run but one and reintroduced the run-to-run noise --repeat exists to
/// average out.
/// </summary>
public static class RepeatGroupAggregator
{
    public sealed record AggregationOutcome
    {
        /// <summary>
        /// The record RunComparer.Compare should actually judge -- either the original selection
        /// (no group, a group of one, or a group with no healthy members) or a synthetic median.
        /// </summary>
        public required RunRecord Record { get; init; }

        public required bool Aggregated { get; init; }
        public required string? RepeatGroup { get; init; }

        /// <summary>Total members of the group, healthy or not. 1 when there is no group at all.</summary>
        public required int GroupSize { get; init; }

        public required int HealthyCount { get; init; }
        public required int ExcludedCount { get; init; }

        /// <summary>
        /// Phase-drop notices: a phase present in only some healthy members of the group can't be
        /// medianed honestly -- consistent with RunComparer's own refusal to read an absent phase
        /// as zero -- so it is dropped from the synthetic record and named here instead.
        /// </summary>
        public required IReadOnlyList<string> Notes { get; init; }
    }

    /// <summary>
    /// <paramref name="allRecords"/> must be the full pool <paramref name="selected"/> was drawn
    /// from (e.g. compare's scenario-filtered list) -- the rest of its repeat group is found by
    /// scanning that pool for a matching RepeatGroup, not just consulting the one record passed in.
    /// </summary>
    public static AggregationOutcome Resolve(RunRecord selected, IReadOnlyList<RunRecord> allRecords)
    {
        if (selected.RepeatGroup is null)
        {
            return NotAggregated(selected, groupSize: 1, excluded: 0);
        }

        var group = allRecords.Where(x => x.RepeatGroup == selected.RepeatGroup).ToList();
        if (group.Count <= 1)
        {
            // A group of one is just that record -- printing "median of 1 run" would be technically
            // true but misleading noise for what reads to a user as a plain, ungrouped run.
            return NotAggregated(selected, groupSize: Math.Max(group.Count, 1), excluded: 0);
        }

        var healthy = group
            .Where(x => x.Correctness.Status is not (CorrectnessStatus.Error or CorrectnessStatus.Failed))
            .ToList();
        int excluded = group.Count - healthy.Count;

        if (healthy.Count == 0)
        {
            // Nothing trustworthy to median. Leave the original selection in place -- it is itself
            // unhealthy (every member of the group is), so RunComparer's existing incomparability
            // check will correctly refuse to judge it rather than this code fabricating a result.
            return NotAggregated(selected, groupSize: group.Count, excluded: excluded);
        }

        var notes = new List<string>();

        // Metadata (environment/source/scenario/setup/correctness/notes/...) is identical across a
        // group's members -- they come from one invocation -- give or take per-iteration noise like
        // the timestamp, so it is taken wholesale from one member rather than merged field by field.
        // That member is the LAST HEALTHY one, not simply the last of the group: picking the literal
        // last member could land on an excluded, unhealthy record and hand the synthetic record its
        // Error/Failed Correctness.Status, which would make RunComparer refuse a comparison that the
        // surviving healthy members should still be allowed to make.
        var metadata = healthy[^1];

        var record = metadata with
        {
            Phases = MedianPhases(healthy, notes),
            Memory = new MemoryMetrics
            {
                PeakManagedHeapBytes = Median(healthy.Select(x => x.Memory.PeakManagedHeapBytes)),
                PeakWorkingSetBytes = Median(healthy.Select(x => x.Memory.PeakWorkingSetBytes)),
                TotalAllocatedBytes = Median(healthy.Select(x => x.Memory.TotalAllocatedBytes)),
            },
            Derived = new DerivedMetrics
            {
                MsPerBallotEncrypt = Median(healthy.Select(x => x.Derived.MsPerBallotEncrypt)),
                BallotsPerSec = Median(healthy.Select(x => x.Derived.BallotsPerSec)),
                AllocBytesPerBallot = Median(healthy.Select(x => x.Derived.AllocBytesPerBallot)),
            },
        };

        return new AggregationOutcome
        {
            Record = record,
            Aggregated = true,
            RepeatGroup = selected.RepeatGroup,
            GroupSize = group.Count,
            HealthyCount = healthy.Count,
            ExcludedCount = excluded,
            Notes = notes,
        };
    }

    private static AggregationOutcome NotAggregated(RunRecord selected, int groupSize, int excluded) => new()
    {
        Record = selected,
        Aggregated = false,
        RepeatGroup = selected.RepeatGroup,
        GroupSize = groupSize,
        HealthyCount = groupSize - excluded,
        ExcludedCount = excluded,
        Notes = [],
    };

    private static Dictionary<string, PhaseMetrics> MedianPhases(List<RunRecord> healthy, List<string> notes)
    {
        var allPhaseNames = healthy.SelectMany(x => x.Phases.Keys).Distinct();
        var commonPhaseNames = allPhaseNames
            .Where(phase => healthy.All(x => x.Phases.ContainsKey(phase)))
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToList();

        // Only phases present in EVERY healthy member can be medianed honestly; a phase that ran in
        // some members and not others is dropped rather than treating the runs that lack it as zero.
        foreach (var phase in allPhaseNames.Except(commonPhaseNames).OrderBy(x => x, StringComparer.Ordinal))
        {
            notes.Add(
                $"Phase '{phase}' ran in only some members of the repeat group; it cannot be " +
                "medianed honestly and is dropped from the synthetic record.");
        }

        var phases = new Dictionary<string, PhaseMetrics>();
        foreach (var phase in commonPhaseNames)
        {
            var members = healthy.Select(x => x.Phases[phase]).ToList();
            phases[phase] = new PhaseMetrics
            {
                WallMs = Median(members.Select(x => x.WallMs)),
                AllocatedBytes = Median(members.Select(x => x.AllocatedBytes)),
                BallotsProcessed = Median(members.Select(x => x.BallotsProcessed)),
                Gc = new GcCounts
                {
                    G0 = Median(members.Select(x => x.Gc.G0)),
                    G1 = Median(members.Select(x => x.Gc.G1)),
                    G2 = Median(members.Select(x => x.Gc.G2)),
                },
                // Conservative: if any member's phase was cut short by its budget, the synthetic
                // phase's numbers are partial too. RunComparer already treats an Aborted phase as
                // informational-only, which is exactly the caution a partially-aborted median needs.
                Aborted = members.Any(x => x.Aborted),
            };
        }

        return phases;
    }

    /// <summary>
    /// Sorted middle element for an odd-sized sample. For an EVEN-sized sample this deliberately
    /// takes the LOWER of the two middle elements rather than their average: averaging would
    /// synthesize a value no run ever actually produced, and every figure aggregated here is meant
    /// to be a real measurement, not a manufactured one.
    /// </summary>
    private static T Median<T>(IEnumerable<T> values) where T : IComparable<T>
    {
        var sorted = values.OrderBy(x => x).ToList();
        int index = sorted.Count % 2 == 1 ? sorted.Count / 2 : (sorted.Count / 2) - 1;
        return sorted[index];
    }
}
