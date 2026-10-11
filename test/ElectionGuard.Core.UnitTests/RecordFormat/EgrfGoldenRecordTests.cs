using System.Diagnostics;
using ElectionGuard.Core.RecordFormat;
using System.Text.Json.Nodes;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-12: the golden and negative records under test/egrf/records/ (design §5.7). This library's
/// reader and verifier must give each record the R-codes, phase roots and completeness its
/// index.json entry states, and the Python reference reader (test/egrf/egrf_ref.py, written from
/// the design and the .proto alone) must give the same as this library, record by record. The
/// Python tests are skipped, with the reason, when no Python 3 interpreter is found.
/// </summary>
public class EgrfGoldenRecordTests
{
    /// <summary>
    /// The R-codes the Python reader never decides the way this library does, and why. Empty: checking
    /// a signature (the standard library has no ECDSA) yields no code under the default policy
    /// (Report), which these records are judged under. One code is compared conditionally, not here:
    /// R.summary, which this library leaves not evaluable when a cast ballot has a finding of a
    /// verification the Python reader does not run (see <see cref="CompareWithPythonAsync"/>).
    /// </summary>
    private static readonly IReadOnlySet<string> NotComparedCodes = new HashSet<string>(StringComparer.Ordinal);

    [Fact]
    public async Task CommittedRecords_ReadAsTheirIndexStates()
    {
        await EgrfGoldenRecords.EnsureAsync();
        var index = EgrfGoldenRecords.ReadIndex();
        Assert.Contains(index, x => x.Entry.Kind == "golden");
        foreach (var code in new[] { "R.container", "R.encoding", "R.version", "R.root", "R.structure", "R.order", "R.summary", "R.attestation", "R.signature" })
        {
            Assert.Contains(index, x => x.Entry.Kind == "negative" && x.Entry.Expect.Contains(code));
        }

        foreach (var (entry, codes, roots, complete) in index)
        {
            var actual = await EgrfGoldenRecords.VerdictAsync(EgrfGoldenRecords.FullPath(entry.Path));
            Assert.True(codes.SequenceEqual(actual.Codes), $"{entry.Path}: index {string.Join(",", codes)}, reader {string.Join(",", actual.Codes)}");
            Assert.True(entry.Expect.All(actual.Codes.Contains), $"{entry.Path}: expected {string.Join(",", entry.Expect)}");
            Assert.Equal(complete, actual.Complete);
            if (roots is not null)
            {
                Assert.Equal(roots.OrderBy(x => x.Key), actual.PhaseRoots!.OrderBy(x => x.Key));
            }
        }

        // The four representations of each golden record have the same roots (design §5.1).
        foreach (var group in index.Where(x => x.Entry.Kind == "golden").GroupBy(x => x.Entry.Path[..x.Entry.Path.LastIndexOf('/')]))
        {
            Assert.Equal(4, group.Count());
            Assert.Single(group.Select(x => string.Join(",", x.PhaseRoots!.OrderBy(r => r.Key).Select(r => r.Value))).Distinct());
        }
    }

    [PythonFact]
    public async Task PythonReferenceReader_AgreesWithThisLibrary_OnEveryRecord()
    {
        await EgrfGoldenRecords.EnsureAsync();
        var failures = new List<string>();
        foreach (var (entry, _, _, _) in EgrfGoldenRecords.ReadIndex())
        {
            failures.AddRange(await CompareWithPythonAsync(entry.Path, EgrfGoldenRecords.FullPath(entry.Path)));
        }

        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>
    /// Seeded single-byte mutations of the golden records (S10b-E review round 3), judged by both
    /// readers as the committed records are: the committed negatives pin the rules each was written
    /// for, and these find the combinations no one wrote a record for (a non-canonical item before a
    /// torn tail, a header section that does not read). Each mutation flips, inserts or deletes one byte,
    /// or cuts the file, at a random offset of a random file of a directory record, protobuf and JSON
    /// alike. Deterministic: a fixed seed, so a failure names a reproducible mutation.
    /// EGRF_MUTATIONS sets how many per record (default 8) and EGRF_MUTATION_SEED the seed (default
    /// 20261010) for a longer or another local run; the label names the seed with the mutation.
    /// </summary>
    [PythonFact]
    public async Task PythonReferenceReader_AgreesWithThisLibrary_OnSeededMutationsOfTheGoldenRecords()
    {
        await EgrfGoldenRecords.EnsureAsync();
        int perRecord = int.TryParse(Environment.GetEnvironmentVariable("EGRF_MUTATIONS"), out int n) && n > 0 ? n : 8;
        var failures = new List<string>();
        int seed = int.TryParse(Environment.GetEnvironmentVariable("EGRF_MUTATION_SEED"), out int s) ? s : 20261010;
        var random = new Random(seed);
        foreach (var election in new[] { "regular-unchained", "regular-chained", "pre-encrypted" })
        {
            foreach (var encoding in new[] { "protobuf", "json" })
            {
                string golden = EgrfGoldenRecords.FullPath($"golden/{election}/{encoding}");
                var files = Directory.EnumerateFiles(golden, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToList();
                for (int i = 0; i < perRecord; i++)
                {
                    string file = files[random.Next(files.Count)];
                    byte[] bytes = File.ReadAllBytes(file);
                    int kind = random.Next(4);
                    int offset = random.Next(bytes.Length);
                    int value = random.Next(1, 256);
                    byte[] mutated = kind switch
                    {
                        0 => [.. bytes[..offset], (byte)(bytes[offset] ^ value), .. bytes[(offset + 1)..]],
                        1 => [.. bytes[..offset], (byte)value, .. bytes[offset..]],
                        2 => [.. bytes[..offset], .. bytes[(offset + 1)..]],
                        _ => bytes[..offset],
                    };
                    string label = $"seed {seed}: {election}/{encoding} {Path.GetRelativePath(golden, file).Replace('\\', '/')} {(new[] { "flip", "insert", "delete", "cut" })[kind]}@{offset} 0x{value:x2}";
                    string directory = Path.Combine(Path.GetTempPath(), "egrf-mutation-" + Guid.NewGuid().ToString("N"));
                    try
                    {
                        foreach (string source in files)
                        {
                            string target = Path.Combine(directory, Path.GetRelativePath(golden, source));
                            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                            File.WriteAllBytes(target, source == file ? mutated : File.ReadAllBytes(source));
                        }

                        failures.AddRange(await CompareWithPythonAsync(label, directory));
                    }
                    finally
                    {
                        Directory.Delete(directory, recursive: true);
                    }
                }
            }
        }

        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>
    /// The Python reader's verdict on the record at <paramref name="path"/> against this library's: the
    /// R-codes, completeness, and the phase roots whenever either computed them. R.summary is compared
    /// only when this library's report has no finding of a verification at a ballot: a cast ballot with
    /// such a finding (a bad proof, a weight below 1) has no factor in the recount, so the tally header
    /// is not evaluable here, and the Python reader, which checks no cryptography, cannot see why
    /// (S10b-E review round 3). R.summary and R.attestation are not compared when a setup verification
    /// (1-4) failed here, for the same reason.
    /// </summary>
    private static async Task<List<string>> CompareWithPythonAsync(string label, string path)
    {
        var failures = new List<string>();
        var mine = await EgrfGoldenRecords.VerdictAsync(path);
        var (exit, output, error) = PythonInterpreter.Run(EgrfReferenceScript, "read", path, "--json");
        if (exit is not (0 or 1 or 2))
        {
            failures.Add($"{label}: egrf_ref.py exited {exit}: {error}");
            return failures;
        }

        var python = JsonNode.Parse(output)!.AsObject();
        var notCompared = new HashSet<string>(NotComparedCodes, StringComparer.Ordinal);
        if (mine.HasBallotFinding)
        {
            notCompared.Add(RecordCodes.Summary);
        }

        if (mine.SetupFailed)
        {
            // A V1-V4 failure (or a manifest that does not parse) stops the cryptography, and with it the
            // device pass that compares attestation contents and the tally header; the Python reader
            // runs no setup verification, so it cannot know.
            notCompared.Add(RecordCodes.Summary);
            notCompared.Add(RecordCodes.Attestation);
        }

        var pythonCodes = python["codes"]!.AsArray().Select(x => (string)x!).Where(x => !notCompared.Contains(x)).ToList();
        var myCodes = mine.Codes.Where(x => !notCompared.Contains(x)).ToList();
        if (!pythonCodes.SequenceEqual(myCodes))
        {
            failures.Add($"{label}: Python {string.Join(",", pythonCodes)}, C# {string.Join(",", myCodes)}; Python findings {python["findings"]!.ToJsonString()}; C# findings {string.Join(" | ", mine.Messages)}");
        }

        // Completeness on every record: false for content of a newer minor and for a read that
        // stopped (refused at open, or a record at no phase), so both readers stop at the same rules.
        if ((bool)python["complete"]! != mine.Complete)
        {
            failures.Add($"{label}: complete: Python {(bool)python["complete"]!}, C# {mine.Complete}; Python findings {python["findings"]!.ToJsonString()}; C# findings {string.Join(" | ", mine.Messages)}");
        }

        // The phase roots whenever a reader computed them, failed records included: R.root and
        // R.signature turn on them, and a negative whose TOC was rewritten over a changed item is
        // exactly where two digest implementations could disagree. Both compute them or neither.
        var pythonRoots = python["phaseRoots"]?.AsObject().ToDictionary(x => x.Key, x => (string)x.Value!);
        if ((mine.PhaseRoots is null) != (pythonRoots is null))
        {
            failures.Add($"{label}: phase roots: Python {(pythonRoots is null ? "none" : "computed")}, C# {(mine.PhaseRoots is null ? "none" : "computed")}; Python findings {python["findings"]!.ToJsonString()}; C# findings {string.Join(" | ", mine.Messages)}");
        }
        else if (mine.PhaseRoots is { } roots && !roots.OrderBy(x => x.Key).SequenceEqual(pythonRoots!.OrderBy(x => x.Key)))
        {
            failures.Add($"{label}: phase roots differ: Python {string.Join(",", pythonRoots!)}, C# {string.Join(",", roots)}");
        }

        return failures;
    }

    /// <summary>The reference reader's own self-check: its schema table against test/egrf/schema.json, the item, negative and Merkle vectors, and index.json.</summary>
    [PythonFact]
    public async Task PythonReferenceReader_Check_Passes()
    {
        await EgrfGoldenRecords.EnsureAsync();
        var (exit, output, error) = PythonInterpreter.Run(EgrfReferenceScript, "--check");
        Assert.True(exit == 0, $"egrf_ref.py --check exited {exit}:\n{output}\n{error}");
        Assert.Contains("0 failure(s)", output);
    }

    private static string EgrfReferenceScript => Path.Combine(EgrfTestFiles.RepositoryRoot(), "test", "egrf", "egrf_ref.py");
}

/// <summary>A test that needs a Python 3 interpreter; skipped, with the reason, when none is found.</summary>
public sealed class PythonFactAttribute : FactAttribute
{
    public PythonFactAttribute()
    {
        if (PythonInterpreter.Path is null)
        {
            Skip = "No Python 3 interpreter found (set EGRF_PYTHON to one): the Python reference reader (test/egrf/egrf_ref.py) cross-check is skipped.";
        }
    }
}

/// <summary>
/// Finds a Python 3 interpreter: EGRF_PYTHON, then python3, python and py on the PATH, then the
/// per-user installs under %LOCALAPPDATA%. A candidate counts only when "--version" exits 0 and
/// prints "Python 3" (Windows' Store alias named python exists but fails).
/// </summary>
internal static class PythonInterpreter
{
    private static readonly Lazy<string?> Found = new(Find);

    public static string? Path => Found.Value;

    public static (int ExitCode, string Output, string Error) Run(params string[] arguments)
    {
        var start = new ProcessStartInfo(Path ?? throw new InvalidOperationException("No Python interpreter."))
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        // -I: isolated mode, so nothing from the working directory or the environment is imported.
        start.ArgumentList.Add("-I");
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromMinutes(5)))
        {
            process.Kill(entireProcessTree: true);
            return (-1, output.Result, "timed out");
        }

        return (process.ExitCode, output.Result, error.Result);
    }

    private static string? Find()
    {
        var candidates = new List<string>();
        if (Environment.GetEnvironmentVariable("EGRF_PYTHON") is { Length: > 0 } configured)
        {
            candidates.Add(configured);
        }

        candidates.AddRange(["python3", "python", "py"]);
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (string root in new[] { System.IO.Path.Combine(local, "Python"), System.IO.Path.Combine(local, "Programs", "Python") })
        {
            if (Directory.Exists(root))
            {
                candidates.AddRange(Directory.EnumerateDirectories(root).OrderDescending(StringComparer.Ordinal).Select(x => System.IO.Path.Combine(x, "python.exe")).Where(File.Exists));
            }
        }

        return candidates.FirstOrDefault(Works);
    }

    private static bool Works(string candidate)
    {
        try
        {
            var start = new ProcessStartInfo(candidate, "--version") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            using var process = Process.Start(start);
            if (process is null)
            {
                return false;
            }

            string text = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            return process.WaitForExit(TimeSpan.FromSeconds(30)) && process.ExitCode == 0 && text.StartsWith("Python 3", StringComparison.Ordinal);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
}
