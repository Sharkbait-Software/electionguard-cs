using System.ComponentModel;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Verify;
using Spectre.Console;
using Spectre.Console.Cli;

namespace ElectionGuard.Verifier.Commands;

/// <summary>
/// <c>egrecord verify</c>: <see cref="ElectionRecordVerifier.VerifyAllAsync"/> over a record (design
/// §6.9). Exits 0 when the record passed and is complete, 2 when it passed but holds content of a
/// newer format minor that was skipped (user decision R-2), 1 on any failure.
/// </summary>
public sealed class VerifyCommand : AsyncCommand<VerifyCommand.Settings>
{
    public sealed class Settings : RecordSettings
    {
        [CommandOption("--profile <PROFILE>")]
        [Description("full (default; a final record), guardian (§3.6.1: the aggregated prefix, V1-V9 with 15 and 16) or ballot (the --locator ballots, with inclusion proofs).")]
        public string Profile { get; set; } = "full";

        [CommandOption("--locator <LOCATOR>")]
        [Description("A ballot for the ballot profile, as <device>/<position>, e.g. regular-<H_DI hex>/3. Repeatable.")]
        public string[] Locators { get; set; } = [];

        [CommandOption("--parallelism <N>")]
        [Description("Maximum degree of parallelism; 1 is single-threaded, -1 (default) uses every core.")]
        public int Parallelism { get; set; } = -1;

        [CommandOption("--checkpoint <PATH>")]
        [Description("Make the run resumable: its state is written here between batches (local, trusted; never accept one from a third party).")]
        public string? Checkpoint { get; set; }

        [CommandOption("--signature-policy <POLICY>")]
        [Description("report (default: list every signature check) or require (fail a device without a valid chain close, a record without a valid signature over its root, and any invalid signature).")]
        public string SignaturePolicy { get; set; } = "report";

        [CommandOption("--trust <PEM>")]
        [Description("A trusted ecdsa-p256-sha256 public key (PEM \"PUBLIC KEY\"). Repeatable. Without one, signatures are reported as present, not checked.")]
        public string[] Trust { get; set; } = [];

        [CommandOption("--max-findings <N>")]
        [Description("Stop collecting findings after this many (default 10,000; the verdict is already failed).")]
        public int MaxFindings { get; set; } = 10_000;

        public override ValidationResult Validate()
        {
            var basic = base.Validate();
            if (!basic.Successful)
            {
                return basic;
            }

            if (Profile is not ("full" or "guardian" or "ballot"))
            {
                return ValidationResult.Error($"--profile is full, guardian or ballot, not '{Profile}'.");
            }

            if (Profile == "ballot" && Locators.Length == 0)
            {
                return ValidationResult.Error("--profile ballot needs at least one --locator.");
            }

            if (Profile != "ballot" && Locators.Length > 0)
            {
                return ValidationResult.Error("--locator is for --profile ballot.");
            }

            if (SignaturePolicy is not ("report" or "require"))
            {
                return ValidationResult.Error($"--signature-policy is report or require, not '{SignaturePolicy}'.");
            }

            if (Parallelism == 0 || Parallelism < -1)
            {
                return ValidationResult.Error("--parallelism is a positive number, or -1 for every core.");
            }

            return MaxFindings < 1 ? ValidationResult.Error("--max-findings is at least 1.") : ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var locators = settings.Locators.Select(Formats.ParseLocator).ToList();
        var trust = settings.Trust.Length == 0 ? [] : new ISignatureVerifier[] { new EcdsaP256Sha256Verifier(Formats.ReadPublicKeys(settings.Trust)) };
        var options = new VerifyAllOptions
        {
            Profile = settings.Profile switch
            {
                "guardian" => VerificationProfile.GuardianPreliminary,
                "ballot" => VerificationProfile.BallotCorrectness,
                _ => VerificationProfile.Full,
            },
            Ballots = locators.Count == 0 ? null : locators,
            MaxDegreeOfParallelism = settings.Parallelism,
            CheckpointPath = settings.Checkpoint,
            SignaturePolicy = settings.SignaturePolicy == "require" ? Core.Verify.SignaturePolicy.RequireValid : Core.Verify.SignaturePolicy.Report,
            SignatureVerifiers = trust,
            MaxFindings = settings.MaxFindings,
        };

        await using var reader = await ElectionRecord.OpenAsync(settings.Path, cancellationToken);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader, options, null, cancellationToken);
        int exit = ExitCode(report);
        if (settings.Json)
        {
            Formats.WriteJson(writer => ReportOutput.Json(writer, reader, report, exit));
        }
        else
        {
            Console.Out.Write(ReportOutput.Text(settings.Path, reader, report));
        }

        return exit;
    }

    /// <summary>Design §6.9 and R-2: 0 passed and complete, 2 passed but incomplete, 1 failed.</summary>
    public static int ExitCode(VerificationReport report) =>
        !report.Passed ? Program.Failed : report.Complete ? Program.Passed : Program.PassedIncomplete;
}
