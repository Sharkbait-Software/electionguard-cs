using ElectionGuard.Perf.Cli;
using ElectionGuard.Perf.Cli.Commands;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.UnitTests;

/// <summary>
/// The one end-to-end test of the CLI seam. Driving `run` at a tiny ballot count exercises
/// RunCommand, ScenarioLoader, ManifestLoader, ManifestHasher, GitProbe, EnvironmentProbe,
/// ConsoleReport and RunRecordStore together -- the wiring that unit tests of each part cannot
/// prove is actually connected.
/// </summary>
public class RunCommandTests : IDisposable
{
    private const string MachineId = "egperf-run-command-test";

    private readonly string _directory = Directory.CreateTempSubdirectory("egperf-run-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public void Execute_RecordsAPassingRunAndWritesBothResultFiles()
    {
        // --allow-debug so the test behaves identically whichever configuration it is built in;
        // the recorded BuildConfig still says which one it was.
        var exitCode = Program.Main(
        [
            "run",
            "--scenario", "smoke",
            "--ballots", "12",
            "--chunk", "6",
            "--warmup", "0",
            "--machine", MachineId,
            "--results-dir", _directory,
            "--allow-debug",
        ]);

        Assert.Equal(0, exitCode);

        var record = Assert.Single(RunRecordStore.ReadAll(Path.Combine(_directory, $"{MachineId}.jsonl")));

        Assert.Equal(CorrectnessStatus.Passed, record.Correctness.Status);
        Assert.Empty(record.Correctness.Mismatches);
        Assert.Equal("smoke", record.Scenario.Id);
        Assert.Equal(12, record.Scenario.BallotCount);
        Assert.Equal(12, record.Phases[PhaseNames.EncryptBallots].BallotsProcessed);
        Assert.Equal(12, record.Phases[PhaseNames.DecryptTally].BallotsProcessed);

        // ManifestHasher and ScenarioLoader both contributed; neither is a placeholder.
        Assert.StartsWith("sha256:", record.Scenario.ConfigHash);
        Assert.StartsWith("sha256:", record.Scenario.ManifestHash);

        // GitProbe and EnvironmentProbe ran. Both degrade rather than throw, so the assertion is
        // that they produced something, not what.
        Assert.False(string.IsNullOrWhiteSpace(record.Source.Commit));
        Assert.False(string.IsNullOrWhiteSpace(record.Source.Branch));
        Assert.False(string.IsNullOrWhiteSpace(record.Environment.Cpu));
        Assert.Equal(MachineId, record.Environment.MachineId);

        // The serialization sub-benchmark had a representative ballot to work with.
        Assert.NotNull(record.Serialization);
        Assert.True(record.Serialization!.Json.Bytes > 0);
        Assert.True(record.Serialization.Protobuf.Bytes > 0);

        // And the pretty-printed latest-run snapshot was written alongside the append-only log.
        Assert.True(File.Exists(Path.Combine(_directory, "latest", "smoke.json")));
    }

    /// <summary>
    /// Drives RunCommand.Execute into a genuine Error outcome (not merely Failed) -- ScenarioRunner
    /// throws when a ballot style names a contest id its manifest does not define, and that throw is
    /// caught and recorded as CorrectnessStatus.Error rather than escaping. warmupBallots is 0 so the
    /// throw happens in the main streaming loop rather than during warmup/setup: Encrypt is always
    /// added to the Phases dictionary once Stage 1 is reached, whether or not it ever got to run, so
    /// this exercises the "populated but partial Phases" shape. The sibling test below exercises the
    /// other shape -- an EMPTY Phases dictionary from a setup-time failure -- which RunCommand.RunOnce
    /// used to mishandle. A malformed manifest is the simplest way to reach either path through the
    /// real command surface, without reaching into internals to force it.
    /// </summary>
    [Fact]
    public void Execute_ReturnsExitCodeOneAndAppendsAnErrorRecordWhenTheRunThrows()
    {
        const string brokenManifest = """
        {
          "electionId": "broken-manifest-election",
          "optionalContestDataMaxLength": 0,
          "chainingMode": 0,
          "contests": [
            {
              "id": "1",
              "name": "Single Contest",
              "index": 1,
              "selectionLimit": 1,
              "optionSelectionLimit": 1,
              "choices": [
                { "id": "1", "name": "Choice One", "index": 1 }
              ]
            }
          ],
          "ballotStyles": [
            { "id": "1", "name": "Standard", "contestIds": ["does-not-exist"] }
          ]
        }
        """;

        var manifestPath = Path.Combine(_directory, "manifest.json");
        File.WriteAllText(manifestPath, brokenManifest);

        var scenarioPath = Path.Combine(_directory, "scenario.json");
        File.WriteAllText(scenarioPath, $$"""
        {
          "id": "broken-manifest",
          "manifest": "manifest.json",
          "ballotCount": 1,
          "warmupBallots": 0
        }
        """);

        var exitCode = Program.Main(
        [
            "run",
            "--scenario", scenarioPath,
            "--repo-root", _directory,
            "--machine", MachineId,
            "--results-dir", _directory,
            "--allow-debug",
        ]);

        Assert.Equal(1, exitCode);

        var record = Assert.Single(RunRecordStore.ReadAll(Path.Combine(_directory, $"{MachineId}.jsonl")));
        Assert.Equal(CorrectnessStatus.Error, record.Correctness.Status);
    }

    /// <summary>
    /// Drives RunCommand.Execute into a SETUP-time failure -- the same broken manifest as above, but
    /// with warmupBallots left at its default (200, greater than zero) so BallotGenerator.Generate
    /// throws KeyNotFoundException from inside ScenarioRunner.Run's Stage 0 (Warmup), not from the
    /// main streaming loop. That path returns a RunOutcome with an EMPTY Phases dictionary -- Stage 1
    /// never started -- which is exactly the outcome RunCommand.RunOnce used to mishandle: it indexed
    /// Phases[PhaseNames.EncryptBallots] unconditionally, so a KeyNotFoundException replaced the more
    /// informative failure and RunCommand.Execute never got a chance to record anything. This is the
    /// test whose absence hid that bug -- the sibling test above deliberately steers around this exact
    /// path with warmupBallots: 0.
    /// </summary>
    [Fact]
    public void Execute_ReturnsExitCodeOneAndAppendsAnErrorRecordWhenSetupFails()
    {
        const string brokenManifest = """
        {
          "electionId": "broken-manifest-election",
          "optionalContestDataMaxLength": 0,
          "chainingMode": 0,
          "contests": [
            {
              "id": "1",
              "name": "Single Contest",
              "index": 1,
              "selectionLimit": 1,
              "optionSelectionLimit": 1,
              "choices": [
                { "id": "1", "name": "Choice One", "index": 1 }
              ]
            }
          ],
          "ballotStyles": [
            { "id": "1", "name": "Standard", "contestIds": ["does-not-exist"] }
          ]
        }
        """;

        var manifestPath = Path.Combine(_directory, "manifest.json");
        File.WriteAllText(manifestPath, brokenManifest);

        var scenarioPath = Path.Combine(_directory, "scenario.json");
        File.WriteAllText(scenarioPath, $$"""
        {
          "id": "broken-manifest-setup",
          "manifest": "manifest.json",
          "ballotCount": 1
        }
        """);

        var exitCode = Program.Main(
        [
            "run",
            "--scenario", scenarioPath,
            "--repo-root", _directory,
            "--machine", MachineId,
            "--results-dir", _directory,
            "--allow-debug",
        ]);

        Assert.Equal(1, exitCode);

        var record = Assert.Single(RunRecordStore.ReadAll(Path.Combine(_directory, $"{MachineId}.jsonl")));
        Assert.Equal(CorrectnessStatus.Error, record.Correctness.Status);
        Assert.Empty(record.Phases);
        Assert.True(record.Setup.DkgMs >= 0);
    }
}
