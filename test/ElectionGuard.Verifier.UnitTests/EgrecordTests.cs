using System.Security.Cryptography;
using System.Text.Json.Nodes;
using ElectionGuard.Verifier;

namespace ElectionGuard.Verifier.UnitTests;

/// <summary>
/// S10b-14: egrecord over the committed golden, positive and negative records of test/egrf/records/
/// (design §5.7), each command and each exit code: 0 passed (done) and complete, 2 passed but
/// incomplete, 1 failed, 3 usage or I/O error.
/// </summary>
public class EgrecordTests
{
    private static readonly string Records = Path.Combine(RepositoryRoot(), "test", "egrf", "records");

    private static string Record(string relative) => Path.Combine(Records, Path.Combine(relative.Split('/')));

    private static string TrustKey => Record("trust/signer.pem");

    public static TheoryData<string> GoldenRecords()
    {
        var data = new TheoryData<string>();
        foreach (var election in new[] { "regular-unchained", "regular-chained", "pre-encrypted" })
        {
            foreach (var representation in new[] { "protobuf", "json", "protobuf.zip", "json.zip" })
            {
                data.Add($"golden/{election}/{representation}");
            }
        }

        return data;
    }

    // ---- verify ----------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(GoldenRecords))]
    public void Verify_AGoldenRecord_PassesComplete_ExitZero(string record)
    {
        var (exit, output, error) = Run("verify", Record(record));
        Assert.True(exit == Program.Passed, $"{record}: {exit}\n{output}\n{error}");
        Assert.EndsWith("PASSED", output.TrimEnd());
    }

    [Fact]
    public void Verify_ARecordOfANewerMinor_PassesIncomplete_ExitTwo()
    {
        var (exit, output, _) = Run("verify", Record("positive/newer-minor"), "--json");
        Assert.Equal(Program.PassedIncomplete, exit);
        var report = JsonNode.Parse(output)!.AsObject();
        Assert.True((bool)report["passed"]!);
        Assert.False((bool)report["complete"]!);
        Assert.Equal("2.1", (string)report["recordFormat"]!);
        Assert.Equal(2, (int)report["exitCode"]!);
    }

    [Theory]
    [InlineData("negative/root-claimed-root-differs", "R.root")]
    [InlineData("negative/summary-tally-header", "R.summary")]
    [InlineData("negative/order-join-section", "R.order")]
    [InlineData("negative/attestation-chain-close-count", "R.attestation")]
    [InlineData("negative/signature-wrong-root", "R.signature")]
    [InlineData("negative/encoding-noncanonical-item", "R.encoding")]
    public void Verify_ARecordWithAFinding_Fails_ExitOne(string record, string code)
    {
        var (exit, output, _) = Run("verify", Record(record), "--json");
        Assert.Equal(Program.Failed, exit);
        var report = JsonNode.Parse(output)!.AsObject();
        Assert.False((bool)report["passed"]!);
        Assert.Contains(report["findings"]!.AsArray(), x => (string)x!["subSection"]! == code);
    }

    /// <summary>A record the reader refuses when it opens it is a verdict on the record (exit 1, the R-code on stderr), not a usage error.</summary>
    [Theory]
    [InlineData("negative/container-unlisted-file", "R.container")]
    [InlineData("negative/container-zip-duplicate-entry.zip", "R.container")]
    [InlineData("negative/version-major", "R.version")]
    [InlineData("negative/structure-missing-section", "R.structure")]
    public void Verify_ARecordTheReaderRefuses_Fails_ExitOne(string record, string code)
    {
        var (exit, _, error) = Run("verify", Record(record));
        Assert.Equal(Program.Failed, exit);
        Assert.StartsWith(code + ":", error.TrimStart());
    }

    [Theory]
    [InlineData("an unknown option", new[] { "verify", "{golden}", "--bogus" })]
    [InlineData("no record", new[] { "verify" })]
    [InlineData("a record that does not exist", new[] { "verify", "{missing}" })]
    [InlineData("an unknown profile", new[] { "verify", "{golden}", "--profile", "everything" })]
    [InlineData("the ballot profile without a locator", new[] { "verify", "{golden}", "--profile", "ballot" })]
    [InlineData("a locator under the full profile", new[] { "verify", "{golden}", "--locator", "regular-00/1" })]
    [InlineData("a malformed locator", new[] { "verify", "{golden}", "--profile", "ballot", "--locator", "regular-xyz/1" })]
    [InlineData("an unknown signature policy", new[] { "verify", "{golden}", "--signature-policy", "ignore" })]
    [InlineData("a parallelism of 0", new[] { "verify", "{golden}", "--parallelism", "0" })]
    [InlineData("a trust file that is no PEM key", new[] { "verify", "{golden}", "--trust", "{golden-toc}" })]
    [InlineData("an unknown command", new[] { "audit", "{golden}" })]
    [InlineData("convert without an encoding", new[] { "convert", "{golden}", "{temp}" })]
    [InlineData("prove with a malformed code", new[] { "prove", "{golden}", "not-a-code" })]
    public void UsageAndIoErrors_ExitThree(string row, string[] args)
    {
        string golden = Record("golden/regular-unchained/protobuf");
        var (exit, output, error) = Run(args.Select(x => x
            .Replace("{golden-toc}", Path.Combine(golden, "toc.binpb"), StringComparison.Ordinal)
            .Replace("{golden}", golden, StringComparison.Ordinal)
            .Replace("{missing}", Path.Combine(Records, "no-such-record"), StringComparison.Ordinal)
            .Replace("{temp}", Path.Combine(Path.GetTempPath(), $"egrecord-{Guid.NewGuid():N}"), StringComparison.Ordinal)).ToArray());
        Assert.True(exit == Program.UsageOrIoError, $"{row}: {exit}\n{output}\n{error}");
    }

    [Fact]
    public void Verify_Json_IsTheReport_WithTheDigestRoots()
    {
        string record = Record("golden/regular-chained/protobuf");
        var (exit, output, _) = Run("verify", record, "--json", "--parallelism", "1");
        Assert.Equal(Program.Passed, exit);
        var report = JsonNode.Parse(output)!.AsObject();
        Assert.True((bool)report["passed"]!);
        Assert.True((bool)report["complete"]!);
        Assert.Equal("final", (string)report["phase"]!);
        Assert.Equal(19, report["verifications"]!.AsObject().Count);
        Assert.Equal("Passed", (string)report["verifications"]!["9"]!);
        Assert.Equal(5, (int)report["statistics"]!["ballotItems"]!);

        var (_, digest, _) = Run("digest", record, "--json");
        Assert.Equal((string)JsonNode.Parse(digest)!["phaseRoots"]!["final"]!, (string)report["phaseRoots"]!["final"]!);
    }

    [Fact]
    public void Verify_TheGuardianProfile_VerifiesTheAggregatedPrefix()
    {
        var (exit, output, _) = Run("verify", Record("golden/regular-chained/json.zip"), "--profile", "guardian", "--json");
        Assert.Equal(Program.Passed, exit);
        var report = JsonNode.Parse(output)!.AsObject();
        Assert.Equal("aggregated", (string)report["phase"]!);
        Assert.Equal("NotRun", (string)report["verifications"]!["10"]!);
        Assert.Single(report["ballotsToOpen"]!.AsArray());
    }

    [Fact]
    public void Verify_RequiringSignatures_PassesOnlyWithTheTrustedKey()
    {
        string record = Record("golden/regular-chained/protobuf.zip");
        var (trusted, output, _) = Run("verify", record, "--signature-policy", "require", "--trust", TrustKey, "--json");
        Assert.Equal(Program.Passed, trusted);
        Assert.All(JsonNode.Parse(output)!["signatures"]!.AsArray(), x => Assert.Equal("Valid", (string)x!["status"]!));

        // No trust anchor: the signatures are present but not checked, which the policy refuses.
        var (untrusted, _, _) = Run("verify", record, "--signature-policy", "require");
        Assert.Equal(Program.Failed, untrusted);

        // Another key: not the signer's.
        string other = Path.Combine(Path.GetTempPath(), $"egrecord-other-{Guid.NewGuid():N}.pem");
        using (var key = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            File.WriteAllText(other, PemEncoding.WriteString("PUBLIC KEY", key.ExportSubjectPublicKeyInfo()));
        }

        try
        {
            var (wrong, _, _) = Run("verify", record, "--signature-policy", "require", "--trust", other);
            Assert.Equal(Program.Failed, wrong);
            // Under the default policy the same record passes: the signature is reported, not required.
            var (reported, _, _) = Run("verify", record, "--trust", other);
            Assert.Equal(Program.Passed, reported);
        }
        finally
        {
            File.Delete(other);
        }
    }

    [Fact]
    public void Verify_TheBallotProfile_ProvesTheChosenBallot()
    {
        string record = Record("golden/pre-encrypted/protobuf");
        var (_, digest, _) = Run("digest", record, "--json");
        string device = (string)JsonNode.Parse(digest)!["sections"]!.AsArray().Single(x => ((string)x!["section"]!).StartsWith("0x0101/", StringComparison.Ordinal))!["section"]!;
        string locator = $"pre-encrypting-{device["0x0101/02".Length..]}/1";

        var (exit, output, error) = Run("verify", record, "--profile", "ballot", "--locator", locator, "--json");
        Assert.True(exit == Program.Passed, $"{exit}\n{output}\n{error}");
        var inclusion = Assert.Single(JsonNode.Parse(output)!["inclusions"]!.AsArray());
        Assert.Equal(locator, (string)inclusion!["locator"]!);
    }

    [Fact]
    public void Verify_WithACheckpoint_PassesAndRemovesIt()
    {
        string checkpoint = Path.Combine(Path.GetTempPath(), $"egrecord-checkpoint-{Guid.NewGuid():N}.json");
        var (exit, _, _) = Run("verify", Record("golden/regular-unchained/protobuf"), "--checkpoint", checkpoint);
        Assert.Equal(Program.Passed, exit);
        Assert.False(File.Exists(checkpoint));
    }

    // ---- digest, convert, diff ----------------------------------------------------------------------

    [Fact]
    public void Digest_GivesEveryRepresentationOfARecordTheSameRoots_TheIndexStates()
    {
        static string Roots(JsonNode roots) => string.Join(",", roots.AsObject().OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => $"{x.Key}={x.Value}"));

        var index = JsonNode.Parse(File.ReadAllText(Path.Combine(Records, "index.json")))!["records"]!.AsArray();
        foreach (var record in index.Where(x => (string)x!["kind"]! == "golden"))
        {
            var (exit, output, _) = Run("digest", Record((string)record!["path"]!), "--json");
            Assert.Equal(Program.Passed, exit);
            var digest = JsonNode.Parse(output)!.AsObject();
            Assert.Equal("matches", (string)digest["claimedToc"]!);
            Assert.Equal(Roots(record["phaseRoots"]!), Roots(digest["phaseRoots"]!));
        }
    }

    [Fact]
    public void Digest_OfARecordWhoseClaimedTocDiffers_ExitsOne()
    {
        var (exit, output, _) = Run("digest", Record("negative/root-critical-bit"));
        Assert.Equal(Program.Failed, exit);
        Assert.Contains("claimed TOC: DIFFERS", output);
    }

    [Theory]
    [InlineData("json", "record.zip")]
    [InlineData("protobuf", "record")]
    public void Convert_PreservesEveryRoot(string encoding, string name)
    {
        string source = Record("golden/regular-chained/json");
        string parent = Path.Combine(Path.GetTempPath(), $"egrecord-convert-{Guid.NewGuid():N}");
        Directory.CreateDirectory(parent);
        try
        {
            string destination = Path.Combine(parent, name);
            var (exit, output, error) = Run("convert", source, destination, "--encoding", encoding, "--json");
            Assert.True(exit == Program.Passed, $"{exit}\n{output}\n{error}");
            var (_, a, _) = Run("digest", source, "--json");
            var (_, b, _) = Run("digest", destination, "--json");
            Assert.Equal(JsonNode.Parse(a)!["phaseRoots"]!.ToJsonString(), JsonNode.Parse(b)!["phaseRoots"]!.ToJsonString());
            Assert.Equal(JsonNode.Parse(output)!["phaseRoots"]!.ToJsonString(), JsonNode.Parse(b)!["phaseRoots"]!.ToJsonString());
            Assert.Equal(Program.Passed, Run("diff", source, destination).ExitCode);
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    [Fact]
    public void Diff_ExitsZeroForEquivalentRecords_AndOneForDifferentOnes()
    {
        Assert.Equal(Program.Passed, Run("diff", Record("golden/pre-encrypted/protobuf"), Record("golden/pre-encrypted/json.zip")).ExitCode);

        var (exit, output, _) = Run("diff", Record("golden/regular-chained/protobuf"), Record("negative/order-join-section"), "--json");
        Assert.Equal(Program.Failed, exit);
        var differences = JsonNode.Parse(output)!["differences"]!.AsArray();
        Assert.Equal(2, differences.Count);
        Assert.All(differences, x => Assert.Equal("0x0303", (string)x!["section"]!));
    }

    // ---- prove, show --------------------------------------------------------------------------------

    [Fact]
    public void Prove_FindsABallotByItsConfirmationCode_AndProvesItIncluded()
    {
        // A voter's code, as the JSON representation carries it (base64); hex works too.
        string device = Directory.GetDirectories(Record("golden/regular-chained/json/devices")).Order(StringComparer.Ordinal).First();
        string line = File.ReadAllText(Path.Combine(device, "00000000.jsonl")).Split('\n')[2];
        string code = (string)JsonNode.Parse(line)!["encryptedBallot"]!["confirmationCode"]!;

        foreach (string given in new[] { code, Convert.ToHexStringLower(Convert.FromBase64String(code)) })
        {
            var (exit, output, error) = Run("prove", Record("golden/regular-chained/protobuf.zip"), given, "--json");
            Assert.True(exit == Program.Passed, $"{exit}\n{output}\n{error}");
            var proof = JsonNode.Parse(output)!.AsObject();
            Assert.True((bool)proof["found"]!);
            Assert.True((bool)proof["proven"]!);
            var inclusion = Assert.Single(proof["inclusions"]!.AsArray());
            Assert.Equal($"{Path.GetFileName(device)}/1", (string)inclusion!["locator"]!);
        }

        var (missing, text, _) = Run("prove", Record("golden/regular-chained/protobuf.zip"), new string('0', 64));
        Assert.Equal(Program.Failed, missing);
        Assert.Contains("no ballot", text);
    }

    [Fact]
    public void Show_SummarizesTheRecord()
    {
        var (exit, output, _) = Run("show", Record("golden/pre-encrypted/json"), "--json");
        Assert.Equal(Program.Passed, exit);
        var show = JsonNode.Parse(output)!.AsObject();
        Assert.Equal("json", (string)show["encoding"]!);
        Assert.Equal("final", (string)show["phase"]!);
        Assert.Equal(2, (int)show["k"]!);
        var device = Assert.Single(show["devices"]!.AsArray());
        Assert.Equal(5, (int)device!["ballots"]!);

        var (textExit, text, _) = Run("show", Record("golden/regular-chained/protobuf.zip"));
        Assert.Equal(Program.Passed, textExit);
        Assert.Contains("phase final", text);
        Assert.Contains("device-1", text);
    }

    [Fact]
    public void Prove_FindsEveryPreEncryptedBallotKind()
    {
        // The device section's ballots: two cast, a full uncast and two compact uncast ballots, each
        // under its own member name; each is found by its code and proven included.
        string device = Directory.GetDirectories(Record("golden/pre-encrypted/json/devices")).Single();
        var kinds = new HashSet<string>(StringComparer.Ordinal);
        var lines = File.ReadAllText(Path.Combine(device, "00000000.jsonl")).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var (line, ordinal) in lines.Select((x, i) => (x, i - 1)).Where(x => x.Item2 >= 1))
        {
            var item = JsonNode.Parse(line)!.AsObject();
            var (kind, ballot) = item.Single();
            if (ballot!["confirmationCode"] is not { } code)
            {
                continue;
            }

            kinds.Add(kind);
            var (exit, output, error) = Run("prove", Record("golden/pre-encrypted/protobuf.zip"), (string)code!, "--json", "--parallelism", "1");
            Assert.True(exit == Program.Passed, $"{kind}: {exit}\n{output}\n{error}");
            var proof = JsonNode.Parse(output)!.AsObject();
            Assert.True((bool)proof["proven"]!, kind);
            var inclusion = Assert.Single(proof["inclusions"]!.AsArray());
            Assert.Equal($"{Path.GetFileName(device)}/{ordinal}", (string)inclusion!["locator"]!);
        }

        Assert.Equal(["preEncryptedCastBallot", "preEncryptedCompactUncastBallot", "preEncryptedUncastBallot"], kinds.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Show_AManifestThatDoesNotParse_IsAVerdictOnTheRecord_NotAUsageError()
    {
        string directory = Path.Combine(Path.GetTempPath(), "egrecord-show-" + Guid.NewGuid().ToString("N"));
        string from = Record("golden/regular-unchained/protobuf");
        foreach (string file in Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(directory, Path.GetRelativePath(from, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }

        try
        {
            // The manifest's required "contests" member renamed in place (same length, so the framing
            // and canonicality hold), in the stored manifest and its plain copy alike: the bytes are
            // well-formed protobuf holding JSON that is not a manifest.
            foreach (string name in new[] { "manifest.binpb", "manifest.json" })
            {
                string path = Path.Combine(directory, "setup", name);
                byte[] bytes = File.ReadAllBytes(path);
                byte[] from8 = "\"contests\""u8.ToArray();
                byte[] to8 = "\"contestz\""u8.ToArray();
                int at = bytes.AsSpan().IndexOf(from8);
                Assert.True(at >= 0, $"{name} names no \"contests\"");
                to8.CopyTo(bytes, at);
                File.WriteAllBytes(path, bytes);
            }

            var (exit, output, error) = Run("show", directory);
            Assert.True(exit == Program.Failed, $"{exit}\n{output}\n{error}");
            Assert.Contains("the manifest does not parse", output);
            Assert.Contains("guardians", output);

            var (jsonExit, json, _) = Run("show", directory, "--json");
            Assert.Equal(Program.Failed, jsonExit);
            var show = JsonNode.Parse(json)!.AsObject();
            Assert.NotNull(show["manifestError"]);
            Assert.Null(show["electionId"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// The real process, its standard output redirected to a pipe as a script reads <c>--json</c>:
    /// the bytes are strict UTF-8 (the § of a finding's message is C2 A7, never an OEM code page's
    /// 0x15) and parse as JSON. The in-process tests replace Console.Out with a string, so they cannot
    /// see the bytes. Two ways of starting it on Windows: in a console of its own (no window) whose
    /// code page is set to 437 first, so the defect shows whatever console the test host has (S10b-E
    /// review round 2), and detached, with no console at all, as under Git Bash, where setting the
    /// console's encoding fails and the OEM code page stayed in force (S10b-E review round 3).
    /// Elsewhere both start the process directly.
    /// </summary>
    [Theory]
    [InlineData("console-437")]
    [InlineData("no-console")]
    public async Task Verify_Json_IsUtf8_WhenStandardOutputIsRedirected(string mode)
    {
        string egrecord = Path.Combine(AppContext.BaseDirectory, "egrecord.dll");
        string dotnet = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host ? host : "dotnet";
        string[] arguments = [egrecord, "verify", Record("negative/container-torn-tail"), "--json", "--parallelism", "1"];
        var (exitCode, output, error) = OperatingSystem.IsWindows() && mode == "no-console"
            ? DetachedProcess.Run(dotnet, arguments, TimeSpan.FromMinutes(2))
            : await RunChildAsync(dotnet, arguments, console437: OperatingSystem.IsWindows());

        Assert.True(exitCode == Program.Failed, $"{exitCode}: {error}");
        Assert.DoesNotContain((byte)0x15, output);
        Assert.True(output.AsSpan().IndexOf("§"u8) >= 0, "no UTF-8 section sign in the output");
        Assert.False(output.AsSpan().StartsWith(System.Text.Encoding.UTF8.Preamble), "a BOM before the JSON");
        string text = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(output);
        using var document = System.Text.Json.JsonDocument.Parse(text);
        Assert.False(document.RootElement.GetProperty("passed").GetBoolean());
    }

    private static async Task<(int ExitCode, byte[] Output, string Error)> RunChildAsync(string dotnet, string[] arguments, bool console437)
    {
        System.Diagnostics.ProcessStartInfo start;
        if (console437)
        {
            // cmd /s /c "<command>": the outer quotes are stripped and the rest is run as written.
            string command = string.Join(" ", new[] { dotnet }.Concat(arguments).Select(x => $"\"{x}\""));
            start = new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"), $"/d /s /c \"chcp 437>nul && {command}\"")
            {
                CreateNoWindow = true,
            };
        }
        else
        {
            start = new System.Diagnostics.ProcessStartInfo(dotnet);
            foreach (string argument in arguments)
            {
                start.ArgumentList.Add(argument);
            }
        }

        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        start.UseShellExecute = false;

        using var process = System.Diagnostics.Process.Start(start)!;
        var error = process.StandardError.ReadToEndAsync();
        using var bytes = new MemoryStream();
        await process.StandardOutput.BaseStream.CopyToAsync(bytes);
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, bytes.ToArray(), await error);
    }

    /// <summary>
    /// In process, on every host: after <see cref="Program.UseUtf8Output"/> a redirected standard output
    /// or error is written as UTF-8 with no preamble (a BOM before <c>--json</c> output is not JSON
    /// either) by the writer itself, whatever Console.OutputEncoding is; a console's output encoding is
    /// UTF-8.
    /// </summary>
    [Fact]
    public void UseUtf8Output_WritesUtf8WithoutABom()
    {
        var (originalOut, originalError, originalEncoding) = (Console.Out, Console.Error, Console.OutputEncoding);
        try
        {
            Program.UseUtf8Output();
            foreach (var (redirected, writer) in new[] { (Console.IsOutputRedirected, Console.Out), (Console.IsErrorRedirected, Console.Error) })
            {
                var encoding = redirected ? writer.Encoding : Console.OutputEncoding;
                Assert.Equal(65001, encoding.CodePage);
                Assert.Empty(encoding.GetPreamble());
            }
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
            try
            {
                Console.OutputEncoding = originalEncoding;
            }
            catch (IOException)
            {
            }
        }
    }

    // ---- plumbing -----------------------------------------------------------------------------------

    /// <summary>Runs the command tree (<see cref="Program.Run"/>, Main without its output set-up) with stdout and stderr captured, restoring both even if it throws.</summary>
    private static (int ExitCode, string Output, string Error) Run(params string[] args)
    {
        var (originalOut, originalError) = (Console.Out, Console.Error);
        var output = new StringWriter();
        var error = new StringWriter();
        Console.SetOut(output);
        Console.SetError(error);
        try
        {
            return (Program.Run(args), output.ToString(), error.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "electionguard-cs.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("The repository root (electionguard-cs.sln) is not above the test binaries.");
    }
}
