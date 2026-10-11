using ElectionGuard.Perf.Cli.Configuration;

namespace ElectionGuard.Perf.UnitTests;

public class ScenarioLoaderTests : IDisposable
{
    private readonly string _directory =
        Directory.CreateTempSubdirectory("egperf-scenarios-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string WriteScenario(string fileName, string json)
    {
        var path = Path.Combine(_directory, fileName);
        File.WriteAllText(path, json);
        return path;
    }

    [Fact]
    public void Load_ReadsEveryField()
    {
        var path = WriteScenario("full.json", """
        {
          "id": "medium",
          "manifest": "test/data/single-contest/manifest.json",
          "ballotCount": 100000,
          "seed": 20260907,
          "guardians": { "n": 5, "k": 3 },
          "parallelism": 16,
          "chunkSize": 2500,
          "warmupBallots": 500,
          "phases": {
            "ballotVerification": false,
            "tallyVerification": true,
            "decrypt": false,
            "serialization": true
          },
          "budgets": { "EncryptBallots": 60, "DecryptTally": 30 }
        }
        """);

        var scenario = ScenarioLoader.Load(path);

        Assert.Equal("medium", scenario.Id);
        Assert.Equal("test/data/single-contest/manifest.json", scenario.Manifest);
        Assert.Equal(100000, scenario.BallotCount);
        Assert.Equal(20260907, scenario.Seed);
        Assert.Equal(5, scenario.Guardians.N);
        Assert.Equal(3, scenario.Guardians.K);
        Assert.Equal(16, scenario.Parallelism);
        Assert.Equal(2500, scenario.ChunkSize);
        Assert.Equal(500, scenario.WarmupBallots);
        Assert.False(scenario.Phases.BallotVerification);
        Assert.True(scenario.Phases.TallyVerification);
        Assert.False(scenario.Phases.Decrypt);
        Assert.True(scenario.Phases.Serialization);
        Assert.Equal(60, scenario.Budgets[PhaseNames.EncryptBallots]);
        Assert.Equal(30, scenario.Budgets[PhaseNames.DecryptTally]);
    }

    [Fact]
    public void Load_AppliesDefaultsForOmittedFields()
    {
        var path = WriteScenario("minimal.json", """
        { "id": "smoke", "manifest": "m.json", "ballotCount": 1000 }
        """);

        var scenario = ScenarioLoader.Load(path);

        Assert.Equal(3, scenario.Guardians.N);
        Assert.Equal(2, scenario.Guardians.K);
        Assert.Equal(0, scenario.Parallelism);
        Assert.Equal(5000, scenario.ChunkSize);
        Assert.Equal(200, scenario.WarmupBallots);
        Assert.True(scenario.Phases.BallotVerification);
        Assert.True(scenario.Phases.Decrypt);
        Assert.Empty(scenario.Budgets);
    }

    [Fact]
    public void Load_AbsentBudgetMeansUnlimited()
    {
        var path = WriteScenario("nobudget.json", """
        { "id": "smoke", "manifest": "m.json", "ballotCount": 1000 }
        """);

        Assert.False(ScenarioLoader.Load(path).Budgets.ContainsKey(PhaseNames.DecryptTally));
    }

    [Theory]
    [InlineData("""{ "id": "x", "manifest": "m.json", "ballotCount": 0 }""")]
    [InlineData("""{ "id": "x", "manifest": "m.json", "ballotCount": -1 }""")]
    [InlineData("""{ "id": "x", "manifest": "m.json", "ballotCount": 10, "chunkSize": 0 }""")]
    [InlineData("""{ "id": "x", "manifest": "m.json", "ballotCount": 10, "warmupBallots": -1 }""")]
    [InlineData("""{ "id": "x", "manifest": "m.json", "ballotCount": 10, "parallelism": -1 }""")]
    [InlineData("""{ "id": "x", "manifest": "m.json", "ballotCount": 10, "guardians": { "n": 2, "k": 3 } }""")]
    [InlineData("""{ "id": "", "manifest": "m.json", "ballotCount": 10 }""")]
    [InlineData("""{ "id": "x", "manifest": "", "ballotCount": 10 }""")]
    [InlineData("""{ "id": "x", "manifest": "m.json", "ballotCount": 10, "phases": { "verifyRecord": true } }""")]
    [InlineData("""{ "id": "x", "manifest": "m.json", "ballotCount": 10, "phases": { "writeRecord": true }, "record": { "deviceCount": 0 } }""")]
    [InlineData("""{ "id": "x", "manifest": "m.json", "ballotCount": 10, "phases": { "writeRecord": true }, "record": { "encoding": "xml" } }""")]
    [InlineData("""{ "id": "x", "manifest": "m.json", "ballotCount": 10, "record": { "carrier": "zip" } }""")]
    public void Load_RejectsInvalidConfiguration(string json)
    {
        var path = WriteScenario("bad.json", json);

        Assert.Throws<ScenarioConfigurationException>(() => ScenarioLoader.Load(path));
    }

    [Fact]
    public void Load_RejectsANegativeBudget()
    {
        var path = WriteScenario("badbudget.json", """
        { "id": "x", "manifest": "m.json", "ballotCount": 10, "budgets": { "EncryptBallots": -5 } }
        """);

        Assert.Throws<ScenarioConfigurationException>(() => ScenarioLoader.Load(path));
    }

    /// <summary>
    /// A budgeted phase is enforced with Task.Wait(TimeSpan), which converts the TimeSpan to a
    /// signed 32-bit millisecond count internally: above int.MaxValue ms (~24.855 days,
    /// ~35,791.39 minutes) it throws ArgumentOutOfRangeException the moment the phase starts, with
    /// no message naming the scenario file. Practically unreachable for a real budget, but an extra
    /// zero (or minutes where hours was meant) reaches it easily, and should fail at load time with
    /// a diagnostic instead of at run time with a crash.
    /// </summary>
    [Fact]
    public void Load_RejectsABudgetThatOverflowsTaskWaitsIntMillisecondRange()
    {
        var path = WriteScenario("hugebudget.json", """
        { "id": "x", "manifest": "m.json", "ballotCount": 10, "budgets": { "DecryptTally": 35792 } }
        """);

        var exception = Assert.Throws<ScenarioConfigurationException>(() => ScenarioLoader.Load(path));
        Assert.Contains("24.85", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>The largest budget that still converts to a valid Task.Wait(TimeSpan) millisecond count.</summary>
    [Fact]
    public void Load_AcceptsABudgetAtTheMaximumSupportedMinutes()
    {
        var path = WriteScenario("maxbudget.json", """
        { "id": "x", "manifest": "m.json", "ballotCount": 10, "budgets": { "DecryptTally": 35791 } }
        """);

        Assert.Equal(35791, ScenarioLoader.Load(path).Budgets[PhaseNames.DecryptTally]);
    }

    /// <summary>
    /// The design's illustrative scenario JSON documents a "tallyVerificationMaxBallots" inside
    /// phases that PhaseSettings has never had a member for. Copying the documented shape used to
    /// drop it silently, leaving tallyVerification true -- so a large run retained every encrypted
    /// ballot, which is the multi-gigabyte failure the streaming design exists to prevent.
    /// </summary>
    [Fact]
    public void Load_RejectsAFieldThisToolDoesNotUnderstand()
    {
        var path = WriteScenario("unknown.json", """
        {
          "id": "x",
          "manifest": "m.json",
          "ballotCount": 10,
          "phases": { "tallyVerification": true, "tallyVerificationMaxBallots": 50000 }
        }
        """);

        var exception = Assert.Throws<ScenarioConfigurationException>(() => ScenarioLoader.Load(path));

        Assert.Contains("tallyVerificationMaxBallots", exception.Message, StringComparison.Ordinal);
        Assert.Contains(path, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_RejectsAMisspeltFieldRatherThanSilentlyMeasuringTheDefault()
    {
        var path = WriteScenario("typo.json", """
        { "id": "x", "manifest": "m.json", "ballotCount": 10, "chunkSyze": 250 }
        """);

        var exception = Assert.Throws<ScenarioConfigurationException>(() => ScenarioLoader.Load(path));

        Assert.Contains("chunkSyze", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A missing `required` member is a JsonException from System.Text.Json. It must reach the user
    /// as the tool's own configuration error -- Program.cs catches that and nothing else.
    /// </summary>
    [Fact]
    public void Load_SurfacesAMissingRequiredMemberAsAConfigurationError()
    {
        var path = WriteScenario("incomplete.json", """
        { "id": "x", "ballotCount": 10 }
        """);

        var exception = Assert.Throws<ScenarioConfigurationException>(() => ScenarioLoader.Load(path));

        Assert.Contains(path, exception.Message, StringComparison.Ordinal);
        Assert.Contains("manifest", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LoadAll_DiscoversEveryScenarioInTheDirectory()
    {
        WriteScenario("a.json", """{ "id": "a", "manifest": "m.json", "ballotCount": 1 }""");
        WriteScenario("b.json", """{ "id": "b", "manifest": "m.json", "ballotCount": 2 }""");
        WriteScenario("notes.txt", "ignored");

        var scenarios = ScenarioLoader.LoadAll(_directory);

        Assert.Equal(new[] { "a", "b" }, scenarios.Select(x => x.Id).OrderBy(x => x));
    }

    [Fact]
    public void ComputeConfigHash_IsStableAcrossEqualConfigurations()
    {
        var one = ScenarioLoader.Load(WriteScenario("one.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10 }"""));
        var two = ScenarioLoader.Load(WriteScenario("two.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10 }"""));

        Assert.Equal(ScenarioLoader.ComputeConfigHash(one), ScenarioLoader.ComputeConfigHash(two));
        Assert.StartsWith("sha256:", ScenarioLoader.ComputeConfigHash(one));
    }

    [Fact]
    public void ComputeConfigHash_ChangesWhenAnyFieldChanges()
    {
        var baseline = ScenarioLoader.Load(WriteScenario("base.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10 }"""));

        var changed = ScenarioLoader.Load(WriteScenario("changed.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 11 }"""));

        var phaseChanged = ScenarioLoader.Load(WriteScenario("phase.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10, "phases": { "decrypt": false } }"""));

        Assert.NotEqual(ScenarioLoader.ComputeConfigHash(baseline), ScenarioLoader.ComputeConfigHash(changed));
        Assert.NotEqual(ScenarioLoader.ComputeConfigHash(baseline), ScenarioLoader.ComputeConfigHash(phaseChanged));
    }

    /// <summary>
    /// S10b-15: the record phases and settings are left out of the hash while off, so a scenario
    /// written before they existed (smoke, every committed one but smoke-record) keeps its hash and
    /// stays comparable with its earlier records; turning them on changes it.
    /// </summary>
    [Fact]
    public void ComputeConfigHash_IgnoresTheRecordPhasesWhileTheyAreOff()
    {
        var plain = ScenarioLoader.Load(WriteScenario("plain.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10, "phases": { "decrypt": true } }"""));
        var off = ScenarioLoader.Load(WriteScenario("off.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10, "phases": { "decrypt": true, "writeRecord": false, "verifyRecord": false } }"""));
        var on = ScenarioLoader.Load(WriteScenario("on.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10, "phases": { "decrypt": true, "writeRecord": true } }"""));
        var settings = ScenarioLoader.Load(WriteScenario("settings.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10, "phases": { "decrypt": true, "writeRecord": true }, "record": { "deviceCount": 4 } }"""));

        Assert.Equal(ScenarioLoader.ComputeConfigHash(plain), ScenarioLoader.ComputeConfigHash(off));
        Assert.DoesNotContain("record", System.Text.Json.JsonSerializer.Serialize(plain, PerfJson.LineOptions), StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(ScenarioLoader.ComputeConfigHash(plain), ScenarioLoader.ComputeConfigHash(on));
        Assert.NotEqual(ScenarioLoader.ComputeConfigHash(on), ScenarioLoader.ComputeConfigHash(settings));
    }

    [Fact]
    public void ComputeConfigHash_ChangesWhenOnlyBudgetsChange()
    {
        var baseline = ScenarioLoader.Load(WriteScenario("budgets-base.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10, "budgets": { "EncryptBallots": 60 } }"""));

        var changed = ScenarioLoader.Load(WriteScenario("budgets-changed.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10, "budgets": { "EncryptBallots": 30 } }"""));

        Assert.NotEqual(ScenarioLoader.ComputeConfigHash(baseline), ScenarioLoader.ComputeConfigHash(changed));
    }

    [Fact]
    public void ComputeConfigHash_ChangesWhenOnlyGuardiansChange()
    {
        var baseline = ScenarioLoader.Load(WriteScenario("guardians-base.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10, "guardians": { "n": 3, "k": 2 } }"""));

        var changed = ScenarioLoader.Load(WriteScenario("guardians-changed.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10, "guardians": { "n": 5, "k": 3 } }"""));

        Assert.NotEqual(ScenarioLoader.ComputeConfigHash(baseline), ScenarioLoader.ComputeConfigHash(changed));
    }

    [Fact]
    public void Overrides_ReplaceOnlyTheFieldsProvided()
    {
        var scenario = ScenarioLoader.Load(WriteScenario("o.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10, "chunkSize": 500 }"""));

        var result = new ScenarioOverrides { BallotCount = 99, Decrypt = false }.Apply(scenario);

        Assert.Equal(99, result.BallotCount);
        Assert.False(result.Phases.Decrypt);
        Assert.Equal(500, result.ChunkSize);
        Assert.Equal("x", result.Id);
    }

    [Fact]
    public void Overrides_AreValidated()
    {
        var scenario = ScenarioLoader.Load(WriteScenario("v.json",
            """{ "id": "x", "manifest": "m.json", "ballotCount": 10 }"""));

        Assert.Throws<ScenarioConfigurationException>(
            () => new ScenarioOverrides { BallotCount = 0 }.Apply(scenario));
    }
}
