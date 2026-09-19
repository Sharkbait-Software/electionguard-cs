using System.Text.Json;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.UnitTests;

public class RunRecordStoreTests : IDisposable
{
    private readonly string _directory =
        Directory.CreateTempSubdirectory("egperf-results-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private static RunRecord SampleRecord(string runId, string scenarioId = "medium") => new()
    {
        RunId = runId,
        TimestampUtc = new DateTimeOffset(2026, 9, 7, 14, 22, 31, TimeSpan.Zero),
        Scenario = new ScenarioInfo
        {
            Id = scenarioId,
            ConfigHash = "sha256:abc",
            ManifestHash = "sha256:def",
            BallotCount = 1000,
            Seed = 42,
            GuardianN = 3,
            GuardianK = 2,
            Parallelism = 8,
            ChunkSize = 500,
        },
        Source = new SourceInfo { Commit = "5bc78f9", Branch = "main", Dirty = false },
        Environment = new EnvironmentInfo
        {
            MachineId = "seth-desktop",
            Cpu = "Test CPU",
            LogicalCores = 8,
            RamGb = 32,
            Os = "Test OS",
            DotNet = ".NET 9.0.0",
            GcMode = "server",
            BuildConfig = "Release",
        },
        Setup = new SetupInfo { DkgMs = 412 },
        Phases = new Dictionary<string, PhaseMetrics>
        {
            [PhaseNames.EncryptBallots] = new()
            {
                WallMs = 1234.5,
                AllocatedBytes = 999,
                Gc = new GcCounts { G0 = 10, G1 = 2, G2 = 1 },
                BallotsProcessed = 1000,
            },
        },
        Derived = new DerivedMetrics
        {
            MsPerBallotEncrypt = 1.2345,
            BallotsPerSec = 810.0,
            AllocBytesPerBallot = 0.999,
        },
        Memory = new MemoryMetrics
        {
            PeakManagedHeapBytes = 12345,
            PeakWorkingSetBytes = 67890,
            TotalAllocatedBytes = 111213,
        },
        Correctness = new CorrectnessResult { Status = CorrectnessStatus.Passed },
    };

    [Fact]
    public void Append_ThenReadAll_RoundTripsARecord()
    {
        var path = Path.Combine(_directory, "machine.jsonl");

        RunRecordStore.Append(path, SampleRecord("run-1"));
        var records = RunRecordStore.ReadAll(path);

        var record = Assert.Single(records);
        Assert.Equal("run-1", record.RunId);
        Assert.Equal(1, record.SchemaVersion);
        Assert.Equal("csharp", record.Implementation);
        Assert.Equal("medium", record.Scenario.Id);
        Assert.Equal(1000, record.Phases[PhaseNames.EncryptBallots].BallotsProcessed);
        Assert.Equal(CorrectnessStatus.Passed, record.Correctness.Status);
    }

    [Fact]
    public void Append_WritesOneLinePerRecord()
    {
        var path = Path.Combine(_directory, "machine.jsonl");

        RunRecordStore.Append(path, SampleRecord("run-1"));
        RunRecordStore.Append(path, SampleRecord("run-2"));
        RunRecordStore.Append(path, SampleRecord("run-3"));

        var lines = File.ReadAllLines(path).Where(x => x.Length > 0).ToList();

        Assert.Equal(3, lines.Count);
        Assert.Equal(new[] { "run-1", "run-2", "run-3" },
            RunRecordStore.ReadAll(path).Select(x => x.RunId));
    }

    [Fact]
    public void Append_EscapesEmbeddedNewlinesSoARecordStaysOneLine()
    {
        var path = Path.Combine(_directory, "machine.jsonl");
        var record = SampleRecord("run-1") with
        {
            Notes = new Dictionary<string, string> { [PhaseNames.EncryptBallots] = "line one\nline two" },
        };

        RunRecordStore.Append(path, record);

        var lines = File.ReadAllLines(path).Where(x => x.Length > 0).ToList();
        Assert.Single(lines);

        var roundTripped = RunRecordStore.ReadAll(path).Single();
        Assert.Equal("line one\nline two", roundTripped.Notes[PhaseNames.EncryptBallots]);
    }

    /// <summary>
    /// Reproduces the data loss reported against the old implementation, which called
    /// <c>File.AppendAllText</c>: that method opens and closes a brand-new handle per call with
    /// <c>FileShare.Read</c>, a share mode that does not admit a second concurrent writer. Against
    /// that implementation, running this same test (16 writers x 100 appends each) threw
    /// <c>IOException: ... being used by another process</c> on roughly 45% of calls -- each one
    /// uncaught by anything in this tool, discarding that call's record outright. An intermediate
    /// fix that merely widened the share mode to <see cref="FileShare.ReadWrite"/> was tried and
    /// measured too: it threw no exceptions but silently lost data anyway (a lost-update race
    /// between two writers' buffered bytes), including a few lines corrupted by interleaving. Only
    /// <see cref="FileShare.None"/> plus a bounded retry -- which serializes every append so no two
    /// writers' bytes are ever in flight against the file at once -- passes.
    ///
    /// Uses Tasks (via Parallel.ForEach) rather than separate processes: RunRecordStore.Append
    /// opens and closes its own file handle on every call, so the hazard comes from overlapping
    /// opens against one path, not from being literally different processes -- Tasks racing in one
    /// process reproduce the identical contention, deterministically and fast enough to run on
    /// every build, where spawning and synchronizing external processes would be slow and flaky
    /// without adding coverage of a different failure mode.
    /// </summary>
    [Fact]
    public void Append_ConcurrentWriters_LosesNoRecords()
    {
        var path = Path.Combine(_directory, "concurrent.jsonl");
        const int writers = 16;
        const int perWriter = 100;

        var ids = Enumerable.Range(0, writers)
            .SelectMany(w => Enumerable.Range(0, perWriter).Select(i => $"writer-{w}-{i}"))
            .ToList();

        Parallel.ForEach(ids, id => RunRecordStore.Append(path, SampleRecord(id)));

        // ReadAll throws on any line that fails to parse, so getting past it already rules out a
        // corrupted/interleaved line; the count and distinctness checks below rule out a silently
        // dropped or duplicated one.
        var records = RunRecordStore.ReadAll(path);

        Assert.Equal(ids.Count, records.Count);
        Assert.Equal(ids.Count, records.Select(x => x.RunId).Distinct().Count());
        Assert.Equal(
            ids.OrderBy(x => x, StringComparer.Ordinal),
            records.Select(x => x.RunId).OrderBy(x => x, StringComparer.Ordinal));
    }

    [Fact]
    public void Append_CreatesTheDirectory()
    {
        var path = Path.Combine(_directory, "nested", "deeper", "machine.jsonl");

        RunRecordStore.Append(path, SampleRecord("run-1"));

        Assert.True(File.Exists(path));
    }

    [Fact]
    public void Append_WritesNoUtf8Bom()
    {
        var path = Path.Combine(_directory, "machine.jsonl");

        RunRecordStore.Append(path, SampleRecord("run-1"));

        var bytes = File.ReadAllBytes(path);
        Assert.NotEmpty(bytes);
        Assert.Equal((byte)'{', bytes[0]);
        Assert.False(
            bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF,
            "Append must not emit a UTF-8 BOM preamble; it breaks jq, Python's json module, and " +
            "any strict JSON parser reading the first line.");
    }

    [Fact]
    public void ReadAll_ReturnsEmptyForAMissingFile()
    {
        Assert.Empty(RunRecordStore.ReadAll(Path.Combine(_directory, "absent.jsonl")));
    }

    [Fact]
    public void ReadAll_IgnoresBlankLines()
    {
        var path = Path.Combine(_directory, "machine.jsonl");
        RunRecordStore.Append(path, SampleRecord("run-1"));
        File.AppendAllText(path, "\n\n");
        RunRecordStore.Append(path, SampleRecord("run-2"));

        Assert.Equal(2, RunRecordStore.ReadAll(path).Count);
    }

    /// <summary>
    /// These files are committed and routinely hand-inspected, so a truncated or edited line is a
    /// realistic accident. It used to reach the user as a raw JsonException stack trace out of the
    /// top of `compare`, which catches only the tool's own configuration error.
    /// </summary>
    [Fact]
    public void ReadAll_RaisesAConfigurationErrorNamingTheOffendingLine()
    {
        var path = Path.Combine(_directory, "machine.jsonl");
        RunRecordStore.Append(path, SampleRecord("run-1"));
        File.AppendAllText(path, "{ \"runId\": \"truncated\"" + Environment.NewLine);
        RunRecordStore.Append(path, SampleRecord("run-3"));

        var exception = Assert.Throws<ScenarioConfigurationException>(() => RunRecordStore.ReadAll(path));

        Assert.Contains(path, exception.Message, StringComparison.Ordinal);
        Assert.Contains("line 2", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReadAll_RejectsARecordFromANewerSchemaVersion()
    {
        var path = Path.Combine(_directory, "machine.jsonl");
        RunRecordStore.Append(
            path,
            SampleRecord("run-1") with { SchemaVersion = RunRecord.CurrentSchemaVersion + 1 });

        var exception = Assert.Throws<ScenarioConfigurationException>(() => RunRecordStore.ReadAll(path));

        Assert.Contains("schema version", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The other half of the schema contract, and the reason PerfJson.LineOptions deliberately does
    /// NOT reject unmapped members the way PerfJson.Options does: results are a forward-compatible
    /// wire format, so a field added by a newer build must not make the history unreadable here.
    /// </summary>
    [Fact]
    public void ReadAll_ToleratesAFieldAddedByANewerBuild()
    {
        var path = Path.Combine(_directory, "machine.jsonl");
        var line = JsonSerializer.Serialize(SampleRecord("run-1"), PerfJson.LineOptions);
        File.WriteAllText(path, "{\"fieldFromTheFuture\":123," + line[1..] + Environment.NewLine);

        Assert.Equal("run-1", RunRecordStore.ReadAll(path).Single().RunId);
    }

    /// <summary>
    /// SerializerMetrics.ContestCount/SelectionCount were added after SchemaVersion 1 shipped. No
    /// version bump accompanied them (see the doc comment on those properties): they are neither
    /// `required` nor default to 0, precisely so that a line recorded before they existed -- which
    /// this test simulates by hand-writing JSON with no "contestCount"/"selectionCount" keys at all
    /// -- still reads, with those two fields coming back null rather than throwing or silently
    /// reporting a fabricated 0.
    /// </summary>
    [Fact]
    public void ReadAll_ReadsAPreExistingLineMissingTheSerializerShapeFields()
    {
        var path = Path.Combine(_directory, "machine.jsonl");
        var record = SampleRecord("run-1") with
        {
            Serialization = new SerializationMetrics
            {
                Json = new SerializerMetrics { SerializeOpsPerSec = 100, DeserializeOpsPerSec = 200, Bytes = 300 },
                Protobuf = new SerializerMetrics { SerializeOpsPerSec = 400, DeserializeOpsPerSec = 500, Bytes = 600 },
            },
        };

        var json = JsonSerializer.Serialize(record, PerfJson.LineOptions);
        using (var document = JsonDocument.Parse(json))
        {
            Assert.True(document.RootElement.GetProperty("serialization").GetProperty("json")
                .TryGetProperty("contestCount", out _));
        }

        // Strip exactly the two new keys (and their own leading comma -- neither is ever the first
        // property in its object, so this never leaves a dangling trailing comma behind) out of both
        // serializer sub-objects, reproducing the shape a line recorded by the pre-change build would
        // actually have on disk.
        var withoutShapeFields = System.Text.RegularExpressions.Regex.Replace(
            json, ",\"(contestCount|selectionCount)\":null", string.Empty);
        File.WriteAllText(path, withoutShapeFields + Environment.NewLine);

        var roundTripped = Assert.Single(RunRecordStore.ReadAll(path));

        Assert.Equal("run-1", roundTripped.RunId);
        Assert.NotNull(roundTripped.Serialization);
        Assert.Null(roundTripped.Serialization!.Json.ContestCount);
        Assert.Null(roundTripped.Serialization.Json.SelectionCount);
        Assert.Null(roundTripped.Serialization.Protobuf.ContestCount);
        Assert.Null(roundTripped.Serialization.Protobuf.SelectionCount);
        Assert.Equal(300, roundTripped.Serialization.Json.Bytes);
    }

    [Fact]
    public void RecordsPreserveOnlyThePhasesThatRan()
    {
        var path = Path.Combine(_directory, "machine.jsonl");
        var record = SampleRecord("run-1");

        RunRecordStore.Append(path, record);

        var roundTripped = RunRecordStore.ReadAll(path).Single();
        Assert.Equal(new[] { PhaseNames.EncryptBallots }, roundTripped.Phases.Keys);
        Assert.False(roundTripped.Phases.ContainsKey(PhaseNames.DecryptTally));
    }

    [Fact]
    public void AbortedPhasesRoundTripWithTheirPartialBallotCount()
    {
        var path = Path.Combine(_directory, "machine.jsonl");
        var record = SampleRecord("run-1") with
        {
            Phases = new Dictionary<string, PhaseMetrics>
            {
                [PhaseNames.DecryptTally] = new()
                {
                    WallMs = 1_800_000,
                    AllocatedBytes = 5,
                    Gc = new GcCounts(),
                    BallotsProcessed = 250,
                    Aborted = true,
                },
            },
            Correctness = new CorrectnessResult { Status = CorrectnessStatus.Incomplete },
            Notes = new Dictionary<string, string> { [PhaseNames.DecryptTally] = "aborted:budgetExceeded" },
        };

        RunRecordStore.Append(path, record);
        var roundTripped = RunRecordStore.ReadAll(path).Single();

        Assert.True(roundTripped.Phases[PhaseNames.DecryptTally].Aborted);
        Assert.Equal(250, roundTripped.Phases[PhaseNames.DecryptTally].BallotsProcessed);
        Assert.Equal(CorrectnessStatus.Incomplete, roundTripped.Correctness.Status);
        Assert.Equal("aborted:budgetExceeded", roundTripped.Notes[PhaseNames.DecryptTally]);
    }

    [Fact]
    public void MismatchesRoundTrip()
    {
        var path = Path.Combine(_directory, "machine.jsonl");
        var record = SampleRecord("run-1") with
        {
            Correctness = new CorrectnessResult
            {
                Status = CorrectnessStatus.Failed,
                Mismatches =
                [
                    new TallyMismatch { ContestId = "c1", ChoiceId = "ch1", Expected = 5, Actual = 4 },
                ],
            },
        };

        RunRecordStore.Append(path, record);
        var mismatch = Assert.Single(RunRecordStore.ReadAll(path).Single().Correctness.Mismatches);

        Assert.Equal("c1", mismatch.ContestId);
        Assert.Equal(5, mismatch.Expected);
        Assert.Equal(4, mismatch.Actual);
    }

    [Fact]
    public void WriteLatest_WritesIndentedJsonNamedForTheScenario()
    {
        RunRecordStore.WriteLatest(_directory, SampleRecord("run-1", scenarioId: "large"));

        var path = Path.Combine(_directory, "large.json");
        Assert.True(File.Exists(path));
        Assert.Contains("\n", File.ReadAllText(path));
    }

    [Fact]
    public void WriteLatest_OverwritesThePreviousRun()
    {
        RunRecordStore.WriteLatest(_directory, SampleRecord("run-1"));
        RunRecordStore.WriteLatest(_directory, SampleRecord("run-2"));

        Assert.Contains("run-2", File.ReadAllText(Path.Combine(_directory, "medium.json")));
    }

    [Fact]
    public void WriteLatest_WritesNoUtf8Bom()
    {
        RunRecordStore.WriteLatest(_directory, SampleRecord("run-1", scenarioId: "large"));

        var bytes = File.ReadAllBytes(Path.Combine(_directory, "large.json"));
        Assert.NotEmpty(bytes);
        Assert.Equal((byte)'{', bytes[0]);
        Assert.False(
            bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF,
            "WriteLatest must not emit a UTF-8 BOM preamble; it recreates its file on every run, so " +
            "a BOM here would affect every single scenario's latest snapshot.");
    }

    [Theory]
    [InlineData("SETH-DESKTOP", "seth-desktop")]
    [InlineData("Build Server 01", "build-server-01")]
    [InlineData("host_name.local", "host-name-local")]
    [InlineData("  spaced  ", "spaced")]
    public void Slug_NormalizesMachineNames(string input, string expected)
    {
        Assert.Equal(expected, RunRecordStore.Slug(input));
    }
}
