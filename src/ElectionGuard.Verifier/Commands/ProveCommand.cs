using System.ComponentModel;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Verify;
using Spectre.Console;
using Spectre.Console.Cli;

namespace ElectionGuard.Verifier.Commands;

/// <summary>
/// <c>egrecord prove</c>: §3.7's confirmation-code lookup. Finds the ballot whose H_C is the given
/// code, runs the ballot correctness profile on it (design §6.9: its own verifications, plus RFC 9162
/// inclusion proofs from its leaf to its section root and from its section's TOC entry to the record
/// root), and checks both proofs. Exits 0 when the ballot is found, passes and is proven included, 1
/// otherwise (not found, a failure, or no claimed TOC to prove inclusion under).
/// </summary>
public sealed class ProveCommand : AsyncCommand<ProveCommand.Settings>
{
    public sealed class Settings : RecordSettings
    {
        [CommandArgument(1, "<confirmation-code>")]
        [Description("The ballot's confirmation code H_C: 64 hex digits, or base64 of its 32 bytes.")]
        public string Code { get; set; } = "";

        [CommandOption("--parallelism <N>")]
        [Description("Maximum degree of parallelism; 1 is single-threaded, -1 (default) uses every core.")]
        public int Parallelism { get; set; } = -1;

        public override ValidationResult Validate()
        {
            var basic = base.Validate();
            if (!basic.Successful)
            {
                return basic;
            }

            return Parallelism == 0 || Parallelism < -1 ? ValidationResult.Error("--parallelism is a positive number, or -1 for every core.") : ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var code = Formats.ParseConfirmationCode(settings.Code);
        await using var reader = await ElectionRecord.OpenAsync(settings.Path, cancellationToken);
        var found = new List<BallotLocator>();
        await foreach (var locator in ElectionRecord.FindBallotsAsync(reader, code, cancellationToken))
        {
            found.Add(locator);
        }

        VerificationReport? report = null;
        bool proven = false;
        if (found.Count > 0)
        {
            report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions
            {
                Profile = VerificationProfile.BallotCorrectness,
                Ballots = found,
                MaxDegreeOfParallelism = settings.Parallelism,
            }, null, cancellationToken);
            proven = report.Inclusions.Count == found.Count && report.Inclusions.All(x =>
                MerkleProofs.VerifyInclusion(x.LeafHash, x.Locator.Position, x.SectionSize, x.SectionRoot, x.SectionPath)
                && MerkleProofs.VerifyInclusion(reader.ClaimedToc!.LeafHashes[(int)x.TocIndex], x.TocIndex, x.TocSize, x.Root, x.TocPath));
        }

        bool ok = found.Count > 0 && report!.Passed && proven;
        if (settings.Json)
        {
            Formats.WriteJson(json =>
            {
                json.WriteStartObject();
                json.WriteString("confirmationCode", Convert.ToHexStringLower((byte[])code));
                json.WriteBoolean("found", found.Count > 0);
                json.WriteBoolean("passed", report?.Passed ?? false);
                json.WriteBoolean("proven", proven);
                json.WriteStartArray("inclusions");
                foreach (var inclusion in report?.Inclusions ?? [])
                {
                    ReportOutput.Inclusion(json, inclusion);
                }

                json.WriteEndArray();
                json.WriteStartArray("findings");
                foreach (var finding in report?.Findings ?? [])
                {
                    json.WriteStringValue($"{finding.SubSection}: {finding.Message}");
                }

                json.WriteEndArray();
                json.WriteEndObject();
            });
        }
        else if (found.Count == 0)
        {
            Console.Out.WriteLine($"no ballot of {settings.Path} has confirmation code {Convert.ToHexStringLower((byte[])code)}");
        }
        else
        {
            foreach (var inclusion in report!.Inclusions)
            {
                Console.Out.WriteLine($"ballot     {Formats.Locator(inclusion.Locator)}");
                Console.Out.WriteLine($"leaf       {inclusion.LeafHash} (item {inclusion.Locator.Position} of {inclusion.SectionSize})");
                Console.Out.WriteLine($"section    {inclusion.SectionRoot} via {string.Join(" ", inclusion.SectionPath)}");
                Console.Out.WriteLine($"toc entry  {inclusion.TocIndex} of {inclusion.TocSize} via {string.Join(" ", inclusion.TocPath)}");
                Console.Out.WriteLine($"root       {inclusion.Root}");
            }

            foreach (var finding in report.Findings)
            {
                Console.Out.WriteLine($"  {finding.SubSection,-14} {finding.Message}");
            }

            Console.Out.WriteLine(ok ? "PROVEN: the ballot verifies and is included under the record root"
                : report.Inclusions.Count == 0 ? "NOT PROVEN: the record has no claimed TOC to prove inclusion under" : "FAILED");
        }

        return ok ? Program.Passed : Program.Failed;
    }
}
