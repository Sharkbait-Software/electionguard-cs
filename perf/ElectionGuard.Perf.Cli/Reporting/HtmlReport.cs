using System.Net;
using System.Text;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.Cli.Reporting;

/// <summary>
/// Renders the recorded history as one self-contained HTML file: inline CSS, inline SVG, no
/// scripts and no external resources. That is deliberate -- the same file opens from disk today and
/// can be published to GitHub Pages unchanged, making the Pages step a workflow file rather than a
/// project.
/// </summary>
public static class HtmlReport
{
    private const int ChartWidth = 720;
    private const int ChartHeight = 200;
    private const int Padding = 32;

    public static string Render(IReadOnlyList<RunRecord> records)
    {
        var builder = new StringBuilder();
        builder.AppendLine("<!doctype html>");
        builder.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\">");
        builder.AppendLine("<title>ElectionGuard performance</title>");
        builder.AppendLine("<style>");
        builder.AppendLine("""
        :root { color-scheme: light dark; --fg:#111; --muted:#666; --bg:#fff; --line:#d0d0d0; --accent:#2b6cb0; --bad:#c53030; }
        @media (prefers-color-scheme: dark) {
          :root { --fg:#eee; --muted:#aaa; --bg:#161616; --line:#444; --accent:#7fb3e8; --bad:#fc8181; }
        }
        body { margin:0; padding:2rem; background:var(--bg); color:var(--fg);
               font:14px/1.5 ui-sans-serif, system-ui, sans-serif; }
        h1 { font-size:1.4rem; } h2 { font-size:1.1rem; margin-top:2.5rem; }
        h3 { font-size:.9rem; color:var(--muted); font-weight:600; margin:1.25rem 0 .25rem; }
        table { border-collapse:collapse; width:100%; margin-top:1rem; }
        th, td { text-align:left; padding:.35rem .6rem; border-bottom:1px solid var(--line); vertical-align:top; }
        th { color:var(--muted); font-weight:600; white-space:nowrap; }
        td.num { text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }
        .scroll { overflow-x:auto; }
        .charts { display:grid; grid-template-columns:repeat(auto-fit, minmax(22rem, 1fr)); gap:0 1.5rem; }
        dl { display:grid; grid-template-columns:max-content 1fr; gap:.2rem 1rem; margin:.5rem 0; }
        dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
        .bad { color:var(--bad); font-weight:600; }
        svg { max-width:100%; height:auto; }
        .axis { stroke:var(--line); stroke-width:1; }
        .series { fill:none; stroke:var(--accent); stroke-width:2; }
        .point { fill:var(--accent); }
        """);
        builder.AppendLine("</style></head><body>");
        builder.AppendLine("<h1>ElectionGuard performance</h1>");

        if (records.Count == 0)
        {
            builder.AppendLine("<p>No runs recorded yet.</p></body></html>");
            return builder.ToString();
        }

        // Render sorts within each scenario group below, but the "most recent" headline reads
        // records[^1] directly -- that is only the most recent run if the caller already handed
        // records in timestamp order. ReportCommand does sort before calling this, but nothing
        // enforces that at this boundary, so an unsorted caller would get a wrong headline
        // timestamp with no error. Sorting here, once, makes every use of `records` below safe
        // regardless of what order it arrived in.
        records = records.OrderBy(x => x.TimestampUtc).ToList();

        builder.AppendLine($"<p>{records.Count} run(s), most recent {Escape(records[^1].TimestampUtc.ToString("u"))}.</p>");

        foreach (var group in records.GroupBy(x => x.Scenario.Id).OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            var ordered = group.OrderBy(x => x.TimestampUtc).ToList();

            // Phases are optional per run (see RunRecord), so only phases that at least one run in
            // this scenario actually recorded get a chart or a column -- an absent phase is "did not
            // run", never a zero.
            var phases = PhaseNames.All
                .Where(phase => ordered.Any(x => x.Phases.ContainsKey(phase)))
                .ToList();

            builder.AppendLine($"<h2>{Escape(group.Key)}</h2>");

            LatestRun(builder, ordered[^1], phases);

            builder.AppendLine("<div class=\"charts\">");
            foreach (var phase in phases)
            {
                ChartSection(builder, $"{phase}: milliseconds per ballot", Chart(ordered, PerBallot(phase, x => x.WallMs)));
            }

            ChartSection(builder, $"{PhaseNames.EncryptBallots}: allocated bytes per ballot",
                Chart(ordered, PerBallot(PhaseNames.EncryptBallots, x => x.AllocatedBytes)));
            ChartSection(builder, "Key generation (DKG): milliseconds", Chart(ordered, x => x.Setup.DkgMs));
            ChartSection(builder, "Peak managed heap: MB", Chart(ordered, x => x.Memory.PeakManagedHeapBytes / 1024.0 / 1024.0));
            ChartSection(builder, "Peak working set: MB", Chart(ordered, x => x.Memory.PeakWorkingSetBytes / 1024.0 / 1024.0));
            builder.AppendLine("</div>");

            TimingHistory(builder, ordered, phases);
            ResourceHistory(builder, ordered);
        }

        builder.AppendLine("</body></html>");
        return builder.ToString();
    }

    private static void ChartSection(StringBuilder builder, string title, string chart)
    {
        builder.AppendLine("<div>");
        builder.AppendLine($"<h3>{Escape(title)}</h3>");
        builder.AppendLine(chart);
        builder.AppendLine("</div>");
    }

    /// <summary>
    /// Everything recorded about the scenario's most recent run -- the same information
    /// ConsoleReport prints at the end of `run`, plus the environment and scenario configuration
    /// that console output abbreviates.
    /// </summary>
    private static void LatestRun(StringBuilder builder, RunRecord record, IReadOnlyList<string> phases)
    {
        builder.AppendLine($"<h3>Latest run: {Escape(record.RunId)}</h3>");

        builder.AppendLine("<dl>");
        Term(builder, "when", record.TimestampUtc.ToString("u"));
        Term(builder, "commit", $"{record.Source.Commit}{(record.Source.Dirty ? " (dirty)" : string.Empty)} on {record.Source.Branch}");
        Term(builder, "implementation", record.Implementation);
        if (record.RepeatGroup is not null)
        {
            Term(builder, "repeat group", record.RepeatGroup);
        }

        Term(builder, "scenario",
            $"{record.Scenario.BallotCount:N0} ballots, {record.Scenario.GuardianK}-of-{record.Scenario.GuardianN} guardians, " +
            $"parallelism {record.Scenario.Parallelism}, chunk size {record.Scenario.ChunkSize:N0}, seed {record.Scenario.Seed}");
        Term(builder, "config hash", record.Scenario.ConfigHash);
        Term(builder, "manifest hash", record.Scenario.ManifestHash);
        Term(builder, "machine",
            $"{record.Environment.MachineId}: {record.Environment.Cpu}, {record.Environment.LogicalCores} cores, {record.Environment.RamGb} GB RAM");
        Term(builder, "runtime",
            $"{record.Environment.Os}, {record.Environment.DotNet}, {record.Environment.GcMode} GC, {record.Environment.BuildConfig}");
        Term(builder, "key generation (DKG)", $"{record.Setup.DkgMs:N0} ms");
        Term(builder, "throughput", $"{record.Derived.BallotsPerSec:N2} ballots/s encrypted");
        Term(builder, "memory",
            $"peak heap {Megabytes(record.Memory.PeakManagedHeapBytes)} MB, peak working set {Megabytes(record.Memory.PeakWorkingSetBytes)} MB, " +
            $"total allocated {Megabytes(record.Memory.TotalAllocatedBytes)} MB");
        builder.AppendLine("</dl>");

        builder.AppendLine("<div class=\"scroll\"><table>");
        builder.AppendLine("<tr><th>phase</th><th>wall ms</th><th>ms/ballot</th><th>alloc MB</th><th>MB/ballot</th>" +
                           "<th>gc 0/1/2</th><th>ballots</th><th>status</th></tr>");
        foreach (var phaseName in phases)
        {
            if (!record.Phases.TryGetValue(phaseName, out var phase))
            {
                builder.AppendLine($"<tr><td>{Escape(phaseName)}</td><td colspan=\"7\">did not run</td></tr>");
                continue;
            }

            int ballots = Math.Max(1, phase.BallotsProcessed);
            builder.AppendLine(
                $"<tr><td>{Escape(phaseName)}</td>" +
                $"<td class=\"num\">{phase.WallMs:N0}</td>" +
                $"<td class=\"num\">{phase.WallMs / ballots:N3}</td>" +
                $"<td class=\"num\">{Megabytes(phase.AllocatedBytes)}</td>" +
                $"<td class=\"num\">{phase.AllocatedBytes / 1024.0 / 1024.0 / ballots:N4}</td>" +
                $"<td class=\"num\">{phase.Gc.G0}/{phase.Gc.G1}/{phase.Gc.G2}</td>" +
                $"<td class=\"num\">{phase.BallotsProcessed:N0}</td>" +
                $"<td>{(phase.Aborted ? "<span class=\"bad\">aborted</span>" : "complete")}</td></tr>");
        }

        builder.AppendLine("</table></div>");

        if (record.Serialization is { } serialization)
        {
            // ContestCount/SelectionCount are null only for a record read back from before those
            // fields existed (see SerializerMetrics); both serializers measured the same ballot.
            var shape = serialization.Json.ContestCount is int contests && serialization.Json.SelectionCount is int selections
                ? $" ({contests:N0} contest{(contests == 1 ? "" : "s")}, {selections:N0} selection{(selections == 1 ? "" : "s")})"
                : string.Empty;

            builder.AppendLine($"<h3>Serialized ballot{Escape(shape)}</h3>");
            builder.AppendLine("<div class=\"scroll\"><table>");
            builder.AppendLine("<tr><th>format</th><th>serialize ops/s</th><th>deserialize ops/s</th><th>bytes</th></tr>");
            SerializerRow(builder, "json", serialization.Json);
            SerializerRow(builder, "protobuf", serialization.Protobuf);
            builder.AppendLine("</table></div>");
        }

        builder.AppendLine("<dl>");
        builder.AppendLine($"<dt>correctness</dt><dd>{CorrectnessCell(record.Correctness)}</dd>");
        foreach (var (key, value) in record.Notes.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            Term(builder, $"note: {key}", value);
        }

        builder.AppendLine("</dl>");

        if (record.Correctness.Mismatches.Count > 0)
        {
            builder.AppendLine("<div class=\"scroll\"><table>");
            builder.AppendLine("<tr><th>contest</th><th>choice</th><th>expected</th><th>actual</th></tr>");
            foreach (var mismatch in record.Correctness.Mismatches)
            {
                builder.AppendLine(
                    $"<tr><td>{Escape(mismatch.ContestId)}</td><td>{Escape(mismatch.ChoiceId)}</td>" +
                    $"<td class=\"num\">{mismatch.Expected:N0}</td><td class=\"num\">{mismatch.Actual:N0}</td></tr>");
            }

            builder.AppendLine("</table></div>");
        }
    }

    private static void SerializerRow(StringBuilder builder, string format, SerializerMetrics metrics) =>
        builder.AppendLine(
            $"<tr><td>{format}</td><td class=\"num\">{metrics.SerializeOpsPerSec:N0}</td>" +
            $"<td class=\"num\">{metrics.DeserializeOpsPerSec:N0}</td><td class=\"num\">{metrics.Bytes:N0}</td></tr>");

    private static void TimingHistory(StringBuilder builder, IReadOnlyList<RunRecord> ordered, IReadOnlyList<string> phases)
    {
        builder.AppendLine("<h3>History: timing</h3>");
        builder.AppendLine("<div class=\"scroll\"><table>");
        builder.Append("<tr><th>when</th><th>commit</th><th>machine</th><th>ballots</th><th>dkg ms</th>");
        foreach (var phase in phases)
        {
            builder.Append($"<th>{Escape(phase)} ms/ballot</th>");
        }

        builder.AppendLine("<th>ballots/s</th><th>correctness</th><th>notes</th></tr>");

        foreach (var record in ordered)
        {
            builder.Append(
                $"<tr><td>{Escape(record.TimestampUtc.ToString("yyyy-MM-dd HH:mm"))}</td>" +
                $"<td>{Escape(record.Source.Commit)}{(record.Source.Dirty ? "*" : string.Empty)}</td>" +
                $"<td>{Escape(record.Environment.MachineId)}</td>" +
                $"<td class=\"num\">{record.Scenario.BallotCount:N0}</td>" +
                $"<td class=\"num\">{record.Setup.DkgMs:N0}</td>");

            foreach (var phaseName in phases)
            {
                if (!record.Phases.TryGetValue(phaseName, out var phase))
                {
                    builder.Append("<td class=\"num\">&ndash;</td>");
                    continue;
                }

                // A partial phase is still shown -- hiding it would hide that the budget was hit --
                // but marked, because its per-ballot figure covers only the ballots it reached.
                builder.Append(
                    $"<td class=\"num\">{phase.WallMs / Math.Max(1, phase.BallotsProcessed):N3}" +
                    $"{(phase.Aborted ? $" <span class=\"bad\" title=\"aborted after {phase.BallotsProcessed:N0} ballots\">(aborted)</span>" : string.Empty)}</td>");
            }

            builder.AppendLine(
                $"<td class=\"num\">{record.Derived.BallotsPerSec:N2}</td>" +
                $"<td>{CorrectnessCell(record.Correctness)}</td>" +
                $"<td>{string.Join("<br>", record.Notes.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => Escape($"{x.Key}: {x.Value}")))}</td></tr>");
        }

        builder.AppendLine("</table></div>");
    }

    private static void ResourceHistory(StringBuilder builder, IReadOnlyList<RunRecord> ordered)
    {
        builder.AppendLine("<h3>History: memory and serialization</h3>");
        builder.AppendLine("<div class=\"scroll\"><table>");
        builder.AppendLine("<tr><th>when</th><th>commit</th><th>alloc B/ballot</th><th>total alloc MB</th>" +
                           "<th>peak heap MB</th><th>peak working set MB</th>" +
                           "<th>json ser/s</th><th>json deser/s</th><th>json bytes</th>" +
                           "<th>protobuf ser/s</th><th>protobuf deser/s</th><th>protobuf bytes</th></tr>");

        foreach (var record in ordered)
        {
            var json = record.Serialization?.Json;
            var protobuf = record.Serialization?.Protobuf;
            builder.AppendLine(
                $"<tr><td>{Escape(record.TimestampUtc.ToString("yyyy-MM-dd HH:mm"))}</td>" +
                $"<td>{Escape(record.Source.Commit)}{(record.Source.Dirty ? "*" : string.Empty)}</td>" +
                $"<td class=\"num\">{record.Derived.AllocBytesPerBallot:N0}</td>" +
                $"<td class=\"num\">{Megabytes(record.Memory.TotalAllocatedBytes)}</td>" +
                $"<td class=\"num\">{Megabytes(record.Memory.PeakManagedHeapBytes)}</td>" +
                $"<td class=\"num\">{Megabytes(record.Memory.PeakWorkingSetBytes)}</td>" +
                $"<td class=\"num\">{Optional(json?.SerializeOpsPerSec)}</td>" +
                $"<td class=\"num\">{Optional(json?.DeserializeOpsPerSec)}</td>" +
                $"<td class=\"num\">{Optional(json?.Bytes)}</td>" +
                $"<td class=\"num\">{Optional(protobuf?.SerializeOpsPerSec)}</td>" +
                $"<td class=\"num\">{Optional(protobuf?.DeserializeOpsPerSec)}</td>" +
                $"<td class=\"num\">{Optional(protobuf?.Bytes)}</td></tr>");
        }

        builder.AppendLine("</table></div>");
    }

    private static string CorrectnessCell(CorrectnessResult correctness)
    {
        var status = Escape(correctness.Status);
        var text = correctness.Mismatches.Count > 0
            ? $"{status} ({correctness.Mismatches.Count:N0} mismatch{(correctness.Mismatches.Count == 1 ? "" : "es")})"
            : status;

        return correctness.Status is CorrectnessStatus.Failed or CorrectnessStatus.Error
            ? $"<span class=\"bad\">{text}</span>"
            : text;
    }

    private static void Term(StringBuilder builder, string term, string description) =>
        builder.AppendLine($"<dt>{Escape(term)}</dt><dd>{Escape(description)}</dd>");

    private static string Megabytes(long bytes) => (bytes / 1024.0 / 1024.0).ToString("N1");

    private static string Optional(double? value) => value is { } x ? x.ToString("N0") : "&ndash;";

    private static Func<RunRecord, double?> PerBallot(string phase, Func<PhaseMetrics, double> selector) =>
        record =>
        {
            if (!record.Phases.TryGetValue(phase, out var metrics) || metrics.Aborted)
            {
                return null;
            }

            return selector(metrics) / Math.Max(1, metrics.BallotsProcessed);
        };

    private static string Chart(IReadOnlyList<RunRecord> records, Func<RunRecord, double?> selector)
    {
        var points = records
            .Select((record, index) => (Index: index, Value: selector(record)))
            .Where(x => x.Value.HasValue)
            .Select(x => (x.Index, Value: x.Value!.Value))
            .ToList();

        if (points.Count == 0)
        {
            return "<p>No data for this metric.</p>";
        }

        double max = points.Max(x => x.Value);
        double min = points.Min(x => x.Value);
        if (Math.Abs(max - min) < double.Epsilon)
        {
            // A flat series would divide by zero; give it a band so the line renders mid-chart.
            max += 1;
            min -= 1;
        }

        double stepX = records.Count > 1
            ? (ChartWidth - 2.0 * Padding) / (records.Count - 1)
            : 0;

        string X(int index) => (Padding + index * stepX).ToString("F1");
        string Y(double value) =>
            (ChartHeight - Padding - (value - min) / (max - min) * (ChartHeight - 2.0 * Padding)).ToString("F1");

        var svg = new StringBuilder();
        svg.Append($"<svg viewBox=\"0 0 {ChartWidth} {ChartHeight}\" role=\"img\">");
        svg.Append($"<line class=\"axis\" x1=\"{Padding}\" y1=\"{ChartHeight - Padding}\" " +
                   $"x2=\"{ChartWidth - Padding}\" y2=\"{ChartHeight - Padding}\" />");
        svg.Append($"<line class=\"axis\" x1=\"{Padding}\" y1=\"{Padding}\" " +
                   $"x2=\"{Padding}\" y2=\"{ChartHeight - Padding}\" />");
        svg.Append($"<polyline class=\"series\" points=\"" +
                   string.Join(" ", points.Select(p => $"{X(p.Index)},{Y(p.Value)}")) + "\" />");

        foreach (var point in points)
        {
            svg.Append($"<circle class=\"point\" cx=\"{X(point.Index)}\" cy=\"{Y(point.Value)}\" r=\"3\">");
            svg.Append($"<title>{Escape(records[point.Index].Source.Commit)}: {point.Value:N3}</title>");
            svg.Append("</circle>");
        }

        svg.Append($"<text x=\"{Padding}\" y=\"{Padding - 10}\" font-size=\"11\" fill=\"currentColor\">" +
                   $"{Escape($"{min:N3} – {max:N3}")}</text>");
        svg.Append("</svg>");
        return svg.ToString();
    }

    private static string Escape(string value) => WebUtility.HtmlEncode(value);
}
