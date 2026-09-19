using System.ComponentModel;
using ElectionGuard.Perf.Cli.Reporting;
using ElectionGuard.Perf.Cli.Results;
using Spectre.Console.Cli;

namespace ElectionGuard.Perf.Cli.Commands;

public sealed class CompareCommand : Command<CompareCommand.Settings>
{
    public sealed class Settings : PerfSettings
    {
        [CommandOption("--scenario <ID>")]
        [Description("Restrict to one scenario.")]
        public string? Scenario { get; set; }

        [CommandOption("--baseline <RUNID|SHA>")]
        [Description("Defaults to the most recent run outside the candidate's repeat group.")]
        public string? Baseline { get; set; }

        [CommandOption("--candidate <RUNID|SHA>")]
        [Description("Defaults to the most recent run.")]
        public string? Candidate { get; set; }

        [CommandOption("--machine <ID>")]
        [Description("Which machine's results to read (defaults to the hostname).")]
        public string? Machine { get; set; }

        [CommandOption("--results-dir <DIR>")]
        [Description("Override perf/results.")]
        public string? ResultsDir { get; set; }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var root = settings.ResolveRepoRoot();
        var resultsDirectory = settings.ResultsDir ?? RepoPaths.Results(root);
        var machineId = RunRecordStore.Slug(settings.Machine ?? Environment.MachineName);
        var path = Path.Combine(resultsDirectory, $"{machineId}.jsonl");

        var all = RunRecordStore.ReadAll(path);
        if (all.Count == 0)
        {
            Console.Error.WriteLine($"No results recorded in {path}.");
            return 2;
        }

        var scenarioId = settings.Scenario;
        var records = (scenarioId is null ? all : all.Where(x => x.Scenario.Id == scenarioId)).ToList();

        if (records.Count < 2)
        {
            Console.Error.WriteLine(
                $"Need at least two runs to compare; found {records.Count}" +
                (scenarioId is null ? "." : $" for scenario '{scenarioId}'."));
            return 2;
        }

        var candidate = Find(records, settings.Candidate) ?? records[^1];
        var baseline = Find(records, settings.Baseline) ?? DefaultBaseline(records, candidate);

        // A record that belongs to a --repeat group expands to the whole group and is judged by
        // per-metric medians rather than by the single arbitrarily-selected member -- see
        // RepeatGroupAggregator. This applies whether the record was picked explicitly (--baseline
        // <runId> names a specific run, but the user is identifying which GROUP they mean) or by
        // the defaults below.
        var baselineOutcome = RepeatGroupAggregator.Resolve(baseline, records);
        var candidateOutcome = RepeatGroupAggregator.Resolve(candidate, records);

        var result = RunComparer.Compare(
            baselineOutcome.Record, candidateOutcome.Record, Thresholds.Load(RepoPaths.Thresholds(root)));

        PrintSide("baseline", baselineOutcome);
        PrintSide("candidate", candidateOutcome);
        Console.WriteLine();

        foreach (var delta in result.Deltas)
        {
            var percentText = delta.BaselineWasZero ? "n/a (new)" : $"{delta.PercentChange,8:N2}%";
            // Both labels mean "over tolerance" -- REGRESSION additionally means it gates the exit
            // code, so an informational (wall-time) breach must read differently in the console.
            var label = delta.Breach ? (delta.Gates ? "REGRESSION" : "OVER TOLERANCE") : string.Empty;

            Console.WriteLine(
                $"  {delta.Phase,-14} {delta.Metric,-22} {delta.Baseline,14:N3} -> {delta.Candidate,14:N3}  " +
                $"{percentText,10}  {label}");
        }

        foreach (var warning in result.Warnings)
        {
            Console.WriteLine($"  warning: {warning}");
        }

        if (!result.Comparable)
        {
            Console.WriteLine();
            Console.WriteLine("These runs are not comparable; deltas above are informational only.");
            return 0;
        }

        return result.HasBreach ? 1 : 0;
    }

    /// <summary>Matches a run id exactly, or falls back to the most recent run at a commit.</summary>
    private static RunRecord? Find(List<RunRecord> records, string? identifier)
    {
        if (identifier is null)
        {
            return null;
        }

        return records.LastOrDefault(x => x.RunId == identifier)
            ?? records.LastOrDefault(x => x.Source.Commit == identifier)
            ?? throw new ArgumentException($"No recorded run matches '{identifier}'.");
    }

    /// <summary>
    /// The pre-repeat-group default was simply records[^2]. That still holds for ungrouped runs, but
    /// once the candidate expands into a multi-member repeat group, the second-to-last individual
    /// record is typically just ANOTHER member of that same group -- defaulting to it would compare
    /// the group against itself and always show a zero delta, defeating the point of aggregating it.
    /// So the default baseline is instead the most recent record that is NOT part of the candidate's
    /// own group, i.e. the previous invocation's result.
    /// </summary>
    private static RunRecord DefaultBaseline(List<RunRecord> records, RunRecord candidate)
    {
        for (int i = records.Count - 1; i >= 0; i--)
        {
            var record = records[i];
            if (record.RunId == candidate.RunId)
            {
                continue;
            }

            bool sameGroupAsCandidate =
                candidate.RepeatGroup is not null && record.RepeatGroup == candidate.RepeatGroup;
            if (!sameGroupAsCandidate)
            {
                return record;
            }
        }

        // Every other record belongs to the candidate's own group (there is nothing else to compare
        // against) -- fall back to the old behaviour rather than throwing.
        return records[^2];
    }

    private static void PrintSide(string label, RepeatGroupAggregator.AggregationOutcome outcome)
    {
        string descriptor;
        if (outcome.Aggregated)
        {
            descriptor = outcome.ExcludedCount > 0
                ? $"median of {outcome.HealthyCount} of {outcome.GroupSize} runs " +
                  $"(group {outcome.RepeatGroup}, {outcome.ExcludedCount} excluded as unhealthy)"
                : $"median of {outcome.GroupSize} runs (group {outcome.RepeatGroup})";
        }
        else
        {
            descriptor = outcome.Record.RunId;
        }

        Console.WriteLine(
            $"{label,-11}{descriptor}  {outcome.Record.Source.Commit}  {outcome.Record.TimestampUtc:u}");

        // Every member of the group was unhealthy: nothing was aggregated, and the run being printed
        // above is the original, unaggregated selection -- say so, since it would otherwise look
        // exactly like an ordinary ungrouped single-run comparison.
        if (!outcome.Aggregated && outcome.GroupSize > 1)
        {
            Console.WriteLine(
                $"  note: repeat group {outcome.RepeatGroup} has no healthy members " +
                $"({outcome.ExcludedCount}/{outcome.GroupSize} excluded); comparing the " +
                $"unaggregated run {outcome.Record.RunId}.");
        }

        foreach (var note in outcome.Notes)
        {
            Console.WriteLine($"  note: {note}");
        }
    }
}
