using System.Text;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.Cli.Reporting;

public static class ConsoleReport
{
    public static string Render(RunRecord record, bool markdown)
    {
        var builder = new StringBuilder();

        builder.AppendLine($"scenario   {record.Scenario.Id}  ({record.Scenario.BallotCount:N0} ballots, " +
                           $"{record.Scenario.GuardianK}-of-{record.Scenario.GuardianN} guardians, " +
                           $"parallelism {record.Scenario.Parallelism})");
        builder.AppendLine($"commit     {record.Source.Commit}{(record.Source.Dirty ? " (dirty)" : string.Empty)} on {record.Source.Branch}");
        builder.AppendLine($"machine    {record.Environment.MachineId}  {record.Environment.LogicalCores} cores, " +
                           $"{record.Environment.GcMode} GC, {record.Environment.BuildConfig}");
        builder.AppendLine($"dkg        {record.Setup.DkgMs:N0} ms");
        builder.AppendLine();

        var header = new[] { "phase", "wall ms", "ms/ballot", "alloc MB", "MB/ballot", "gc 0/1/2", "ballots", "" };
        var rows = new List<string[]>();

        foreach (var phaseName in PhaseNames.All)
        {
            if (!record.Phases.TryGetValue(phaseName, out var phase))
            {
                continue;
            }

            int ballots = Math.Max(1, phase.BallotsProcessed);
            rows.Add(
            [
                phaseName,
                $"{phase.WallMs:N0}",
                $"{phase.WallMs / ballots:N3}",
                $"{phase.AllocatedBytes / 1024.0 / 1024.0:N1}",
                $"{phase.AllocatedBytes / 1024.0 / 1024.0 / ballots:N4}",
                $"{phase.Gc.G0}/{phase.Gc.G1}/{phase.Gc.G2}",
                $"{phase.BallotsProcessed:N0}",
                phase.Aborted ? "ABORTED" : string.Empty,
            ]);
        }

        builder.Append(Table(header, rows, markdown));
        builder.AppendLine();
        builder.AppendLine($"peak heap  {record.Memory.PeakManagedHeapBytes / 1024.0 / 1024.0:N1} MB" +
                           $"   peak working set {record.Memory.PeakWorkingSetBytes / 1024.0 / 1024.0:N1} MB");

        if (record.Serialization is not null)
        {
            // ContestCount/SelectionCount are null only for a record read back from before this
            // field existed (see SerializerMetrics) -- both serializers measured the same ballot, so
            // either one's shape describes both.
            var shape = record.Serialization.Json.ContestCount is int contests
                    && record.Serialization.Json.SelectionCount is int selections
                ? $" ({contests:N0} contest{(contests == 1 ? "" : "s")}, {selections:N0} selection{(selections == 1 ? "" : "s")})"
                : string.Empty;

            builder.AppendLine($"serialized ballot{shape}");
            builder.AppendLine($"json       {record.Serialization.Json.SerializeOpsPerSec:N0} ser/s, " +
                               $"{record.Serialization.Json.DeserializeOpsPerSec:N0} deser/s, " +
                               $"{record.Serialization.Json.Bytes:N0} bytes");
            builder.AppendLine($"protobuf   {record.Serialization.Protobuf.SerializeOpsPerSec:N0} ser/s, " +
                               $"{record.Serialization.Protobuf.DeserializeOpsPerSec:N0} deser/s, " +
                               $"{record.Serialization.Protobuf.Bytes:N0} bytes");
        }

        builder.AppendLine();
        builder.AppendLine($"correctness {record.Correctness.Status}");
        foreach (var mismatch in record.Correctness.Mismatches)
        {
            builder.AppendLine($"  {mismatch.ContestId}/{mismatch.ChoiceId}: expected {mismatch.Expected}, got {mismatch.Actual}");
        }

        foreach (var (key, value) in record.Notes)
        {
            builder.AppendLine($"note       {key}: {value}");
        }

        return builder.ToString();
    }

    private static string Table(string[] header, List<string[]> rows, bool markdown)
    {
        var widths = header
            .Select((_, column) => rows
                .Select(row => row[column].Length)
                .Append(header[column].Length)
                .Max())
            .ToArray();

        var builder = new StringBuilder();
        builder.AppendLine(Row(header, widths, markdown));
        builder.AppendLine(markdown
            ? "| " + string.Join(" | ", widths.Select(w => new string('-', Math.Max(3, w)))) + " |"
            : new string('-', widths.Sum() + widths.Length * 3));

        foreach (var row in rows)
        {
            builder.AppendLine(Row(row, widths, markdown));
        }

        return builder.ToString();
    }

    private static string Row(string[] cells, int[] widths, bool markdown)
    {
        var padded = cells.Select((cell, i) => cell.PadRight(widths[i]));
        return markdown
            ? "| " + string.Join(" | ", padded) + " |"
            : "  " + string.Join("   ", padded).TrimEnd();
    }
}
