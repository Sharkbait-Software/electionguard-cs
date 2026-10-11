using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Verify;
using ElectionGuard.Verifier.Commands;
using Spectre.Console.Cli;

namespace ElectionGuard.Verifier;

/// <summary>
/// The egrecord command tree (design §8.2, S10b-14): verify, digest, convert, diff, prove and show
/// an EGRF v2 election record, over the Core API. An explicit class rather than top-level statements
/// so tests can call <see cref="Main"/> and <see cref="Configure"/> directly.
///
/// Exit codes (design §6.9): 0 passed (or, for the other commands, done) and complete; 2 passed but
/// incomplete (content of a newer format minor was skipped); 1 failed (any finding, a record the
/// reader refuses, records that differ, a ballot not found); 3 a usage or I/O error.
/// </summary>
public static class Program
{
    public const int Passed = 0;
    public const int Failed = 1;
    public const int PassedIncomplete = 2;
    public const int UsageOrIoError = 3;

    public static int Main(string[] args)
    {
        UseUtf8Output();
        return Run(args);
    }

    /// <summary>
    /// The command tree over whatever <see cref="Console.Out"/> and <see cref="Console.Error"/> are:
    /// <see cref="Main"/> after <see cref="UseUtf8Output"/>, and the in-process tests with writers of
    /// their own.
    /// </summary>
    public static int Run(string[] args)
    {
        var app = new CommandApp();
        app.Configure(Configure);
        return app.Run(args);
    }

    /// <summary>
    /// Labels, device ids and messages (which cite design sections with §) are written as UTF-8
    /// without a BOM, to a terminal and, above all, to a pipe or file: <c>--json</c> is read by scripts,
    /// and an OEM code page would turn § into the control byte 0x15, which no JSON parser accepts.
    /// A redirected stream gets a UTF-8 writer straight over the process's standard handle, so its
    /// bytes never depend on Console.OutputEncoding: setting that fails (an IOException) when the
    /// process has no console of its own, for instance under Git Bash, and the encoding then stays the
    /// OEM code page (S10b-E review round 3). A terminal keeps the console's writer, with its output
    /// code page set to UTF-8 where that succeeds, since UTF-8 bytes written to a console of another
    /// code page would show as mojibake.
    /// </summary>
    public static void UseUtf8Output()
    {
        var utf8 = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        if (Console.IsOutputRedirected)
        {
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), utf8) { AutoFlush = true });
        }

        if (Console.IsErrorRedirected)
        {
            Console.SetError(new StreamWriter(Console.OpenStandardError(), utf8) { AutoFlush = true });
        }

        if (!Console.IsOutputRedirected || !Console.IsErrorRedirected)
        {
            try
            {
                Console.OutputEncoding = utf8;
            }
            catch (IOException)
            {
            }
        }
    }

    public static void Configure(IConfigurator config)
    {
        config.SetApplicationName("egrecord");

        // An unknown option is never harmless: "--signature-polcy require" would verify under the
        // default policy and report a pass the user did not ask for.
        config.UseStrictParsing();
        config.SetExceptionHandler((exception, _) => HandleException(exception));

        config.AddCommand<VerifyCommand>("verify")
            .WithDescription("Run Verifications 1-19 and every record-level rule over a record. Exits 0 passed, 2 passed but incomplete, 1 failed.")
            .WithExample("verify", "record.zip")
            .WithExample("verify", "record", "--profile", "guardian", "--json")
            .WithExample("verify", "record", "--signature-policy", "require", "--trust", "admin.pem");

        config.AddCommand<DigestCommand>("digest")
            .WithDescription("Print the phase roots and section roots: two representations are equivalent iff they print the same roots.")
            .WithExample("digest", "record.zip");

        config.AddCommand<ConvertCommand>("convert")
            .WithDescription("Copy a record into another encoding or carrier (a destination ending .zip is a zip), preserving every root.")
            .WithExample("convert", "record", "record-json.zip", "--encoding", "json");

        config.AddCommand<DiffCommand>("diff")
            .WithDescription("List how two records differ, by descent from the roots. Exits 0 equivalent, 1 different.")
            .WithExample("diff", "a.zip", "b");

        config.AddCommand<ProveCommand>("prove")
            .WithDescription("Find a ballot by its confirmation code and give its inclusion proofs to the record root.")
            .WithExample("prove", "record.zip", "3f1c...e2");

        config.AddCommand<ShowCommand>("show")
            .WithDescription("Summarize a record: format, phase, election, sections, devices.")
            .WithExample("show", "record.zip");
    }

    private static int HandleException(Exception exception)
    {
        var error = Console.Error;
        switch (exception)
        {
            // A record the reader refuses (R.container, R.version, ...) is a verdict on the record, not
            // a usage error: whoever published it controls it.
            case VerificationFailedException failure:
                error.WriteLine($"{failure.SubSection}: {failure.Message}");
                return Failed;
            case CommandAppException { Pretty: { } pretty }:
                Spectre.Console.AnsiConsole.Create(new Spectre.Console.AnsiConsoleSettings { Out = new Spectre.Console.AnsiConsoleOutput(error) }).Write(pretty);
                return UsageOrIoError;
            case CommandRuntimeException { InnerException: VerificationFailedException inner }:
                error.WriteLine($"{inner.SubSection}: {inner.Message}");
                return Failed;

            // The same for a value or a manifest in the record that does not decode: the commands take
            // no manifest and no encoded value from the user (a confirmation code or a PEM file that
            // does not parse is a plain FormatException, below), so these name the record's content.
            case InvalidManifestException or NonCanonicalEncodingException:
            case CommandRuntimeException { InnerException: InvalidManifestException or NonCanonicalEncodingException }:
                error.WriteLine($"The record holds content that does not decode: {(exception is CommandRuntimeException { InnerException: { } cause } ? cause : exception).Message}");
                return Failed;
            case CommandRuntimeException { InnerException: { } inner }:
                error.WriteLine(inner.Message);
                return UsageOrIoError;
            case CommandAppException:
            case ArgumentException:
            case FormatException:
            case IOException:
            case UnauthorizedAccessException:
                error.WriteLine(exception.Message);
                return UsageOrIoError;
            default:
                error.WriteLine(exception.ToString());
                return UsageOrIoError;
        }
    }
}
