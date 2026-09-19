using System.Text.Json;
using ElectionGuard.Core.Models;
using ElectionGuard.Perf.Cli;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Results;
using ElectionGuard.Perf.Cli.Running;

namespace ElectionGuard.Perf.UnitTests;

/// <summary>
/// Runs the committed smoke scenario at a reduced ballot count against the committed manifest. This
/// is the guard that the harness still produces a correct tally -- it is not a performance test and
/// its timings are meaningless.
/// </summary>
public class EndToEndPipelineTests
{
    [Fact]
    public void SmokeScenario_ProducesACorrectTally()
    {
        var root = RepoPaths.FindRoot(AppContext.BaseDirectory);
        var scenario = ScenarioLoader.Load(Path.Combine(RepoPaths.Scenarios(root), "smoke.json"));

        var reduced = new ScenarioOverrides
        {
            BallotCount = 300,
            ChunkSize = 100,
            WarmupBallots = 10,
        }.Apply(scenario);

        var manifest = JsonSerializer.Deserialize<Manifest>(
            File.ReadAllBytes(Path.Combine(root, reduced.Manifest)), PerfJson.Options)!;

        var outcome = new ScenarioRunner(reduced, manifest).Run();

        Assert.Equal(CorrectnessStatus.Passed, outcome.Correctness.Status);
        Assert.Equal(300, outcome.Phases[PhaseNames.EncryptBallots].BallotsProcessed);
        Assert.Equal(300, outcome.Phases[PhaseNames.Tally].BallotsProcessed);
    }

    [Fact]
    public void EveryCommittedScenarioIsValid()
    {
        var root = RepoPaths.FindRoot(AppContext.BaseDirectory);

        var scenarios = ScenarioLoader.LoadAll(RepoPaths.Scenarios(root));

        Assert.NotEmpty(scenarios);
        foreach (var scenario in scenarios)
        {
            Assert.True(
                File.Exists(Path.Combine(root, scenario.Manifest)),
                $"Scenario '{scenario.Id}' names manifest '{scenario.Manifest}', which does not exist.");
        }
    }
}
