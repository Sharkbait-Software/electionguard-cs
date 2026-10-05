using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Results;
using ElectionGuard.Perf.Cli.Running;
using ElectionGuard.Testing.Common;
using Xunit.Abstractions;

namespace ElectionGuard.Perf.UnitTests;

public class ScenarioRunnerTests
{
    private readonly ITestOutputHelper _output;

    public ScenarioRunnerTests(ITestOutputHelper output) => _output = output;

    private static PerfScenario Scenario(
        int ballotCount = 8,
        int chunkSize = 4,
        int warmupBallots = 2,
        bool decrypt = true,
        bool ballotVerification = false,
        bool tallyVerification = false,
        Dictionary<string, double>? budgets = null) => new()
        {
            Id = "unit",
            Manifest = "unused-in-these-tests.json",
            BallotCount = ballotCount,
            Seed = 4242,
            ChunkSize = chunkSize,
            WarmupBallots = warmupBallots,
            Parallelism = 1,
            Phases = new PhaseSettings
            {
                Decrypt = decrypt,
                BallotVerification = ballotVerification,
                TallyVerification = tallyVerification,
                Serialization = false,
            },
            Budgets = budgets ?? new Dictionary<string, double>(),
        };

    [Fact]
    public void Run_ProducesADecryptedTallyMatchingTheExpectedTally()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(), manifest).Run();

        Assert.Equal(CorrectnessStatus.Passed, outcome.Correctness.Status);
        Assert.Empty(outcome.Correctness.Mismatches);
    }

    /// <summary>
    /// S5 (G10, G29): option selection limits above 1, every supplemental field declared and
    /// write-ins that count toward the limit, verified, tallied and decrypted. The expected tally,
    /// supplemental totals included, is accumulated by ExpectedTallyAccumulator's own reading of the
    /// spec, and the generator emits values up to R and options above R, so a disagreement on the
    /// overvote rule fails the run.
    /// </summary>
    [Theory]
    [InlineData(1, 2, true)]
    [InlineData(3, 3, true)]
    [InlineData(3, 3, false)]
    [InlineData(2, 1, true)]
    public void Run_WithEverySupplementalFieldAndOptionLimitsAboveOne_ProducesTheExpectedTally(int selectionLimit, int optionSelectionLimit, bool writeInsCount)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(
            selectionLimit: selectionLimit,
            optionSelectionLimit: optionSelectionLimit,
            supplementalFields: ElectionFixtureBuilder.AllSupplementalFields,
            writeInFieldCount: 2,
            writeInsCountTowardLimit: writeInsCount);

        var outcome = new ScenarioRunner(Scenario(ballotCount: 600, chunkSize: 300, ballotVerification: true, tallyVerification: true), manifest).Run();

        Assert.Equal(CorrectnessStatus.Passed, outcome.Correctness.Status);
        Assert.Empty(outcome.Correctness.Mismatches);
    }

    [Fact]
    public void Run_RecordsEncryptAndAggregatePhases()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(), manifest).Run();

        Assert.True(outcome.Phases[PhaseNames.EncryptBallots].WallMs > 0);
        Assert.True(outcome.Phases[PhaseNames.EncryptBallots].AllocatedBytes > 0);
        Assert.Equal(8, outcome.Phases[PhaseNames.EncryptBallots].BallotsProcessed);
        Assert.True(outcome.Phases.ContainsKey(PhaseNames.Tally));
    }

    [Fact]
    public void Run_OmitsPhasesThatWereNotRequested()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(decrypt: false, ballotVerification: false), manifest).Run();

        Assert.False(outcome.Phases.ContainsKey(PhaseNames.DecryptTally));
        Assert.False(outcome.Phases.ContainsKey(PhaseNames.VerifyBallots));
        Assert.Equal(CorrectnessStatus.Skipped, outcome.Correctness.Status);
    }

    [Fact]
    public void Run_RecordsTheBallotVerificationPhaseWhenRequested()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(ballotVerification: true), manifest).Run();

        Assert.True(outcome.Phases[PhaseNames.VerifyBallots].WallMs > 0);
        Assert.Equal(8, outcome.Phases[PhaseNames.VerifyBallots].BallotsProcessed);
    }

    [Fact]
    public void Run_AbortsAPhaseThatExceedsItsBudgetAndStillReturns()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var scenario = Scenario(
            ballotCount: 40,
            chunkSize: 4,
            budgets: new Dictionary<string, double> { [PhaseNames.EncryptBallots] = 0.0001 });

        var outcome = new ScenarioRunner(scenario, manifest).Run();

        Assert.True(outcome.Phases[PhaseNames.EncryptBallots].Aborted);
        Assert.True(outcome.Phases[PhaseNames.EncryptBallots].BallotsProcessed < 40);
        Assert.Equal(CorrectnessStatus.Incomplete, outcome.Correctness.Status);
        Assert.Equal("aborted:budgetExceeded", outcome.Notes[PhaseNames.EncryptBallots]);
    }

    /// <summary>
    /// The design's central claim: the runner streams, so the memory it holds at any instant is a
    /// function of chunkSize, not ballotCount. Holding ballotCount fixed at 64 and varying only
    /// chunkSize isolates exactly that -- a streaming runner holds at most chunkSize encrypted
    /// ballots at once, so 64 ballots done in one chunk of 64 must hold measurably more than the
    /// same 64 done in chunks of 4. A runner that retained every encrypted ballot (the bug this
    /// whole design guards against) would hold all 64 either way and show no difference.
    ///
    /// TWO instrument choices here are load-bearing, and both exist because the earlier version of
    /// this test could pass while that bug shipped:
    ///
    /// 1. It measures LIVE bytes -- GC.GetTotalMemory(forceFullCollection: true), sampled on a
    ///    background thread for the duration of the run -- and not the run record's
    ///    peakManagedHeapBytes. That field comes from GC.GetTotalMemory(false), which counts
    ///    uncollected garbage: at this ballot count the loop's ~6 MB of garbage is never collected
    ///    at all, so both configurations read the same total and the field cannot see the
    ///    difference. (That garbage sensitivity is also why peak heap no longer gates `compare`.)
    ///
    /// 2. Each run is preceded by a full collection, and the pair runs BOTH ways round. The sampler
    ///    in MemorySampler is due immediately and is constructed before Warmup's own GC.Collect, so
    ///    a second run in the same process could otherwise capture the first run's uncollected
    ///    garbage -- and under the very counterfactual this test exists to catch, a small-chunk run
    ///    going first leaves behind enough dead ballots to lift the second run's reading on its own.
    ///
    /// Margin derivation: measured empirically for this manifest (see task-8-report.md) at
    /// ~10,229 bytes per retained EncryptedBallot (before/after GC.GetTotalMemory(true) around
    /// building a List&lt;EncryptedBallot&gt; of 150, divided by 150). The large-chunk run holds
    /// (64 - 4) = 60 more ballots at its peak than the small-chunk run, predicting a difference of
    /// about 60 * 10,229 ~= 613,700 bytes. The margin below (200,000 bytes, ~33% of that) sits well
    /// under the predicted signal; because every sample forces a full collection, the reading is a
    /// live-set figure and its run-to-run noise is in the tens of kilobytes.
    ///
    /// The tallyVerification axis covers Verification 9, which used to retain every encrypted
    /// ballot until the end of the run (so both chunk sizes held all 64 and this assertion failed).
    /// It now streams with the other phases, and must hold no more than a chunk either.
    /// </summary>
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Run_KeepsPeakMemoryAFunctionOfChunkSizeNotBallotCount(bool largeChunkFirst, bool tallyVerification)
    {
        const int ballotCount = 64;
        const int smallChunk = 4;
        const int largeChunk = 64;
        const long marginBytes = 200_000;

        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        long PeakLiveBytesFor(int chunkSize)
        {
            // Nothing a previous run left behind may count towards this run's reading.
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            long peak = 0;
            using var stop = new ManualResetEventSlim(false);

            var sampler = new Thread(() =>
            {
                while (!stop.IsSet)
                {
                    peak = Math.Max(peak, GC.GetTotalMemory(forceFullCollection: true));
                    stop.Wait(50);
                }
            })
            {
                IsBackground = true,
                Name = "live-heap-sampler",
            };

            sampler.Start();
            try
            {
                var outcome = new ScenarioRunner(
                    Scenario(ballotCount: ballotCount, chunkSize: chunkSize, decrypt: false, tallyVerification: tallyVerification), manifest).Run();

                Assert.Equal(ballotCount, outcome.Phases[PhaseNames.EncryptBallots].BallotsProcessed);
            }
            finally
            {
                stop.Set();
                sampler.Join();
            }

            return peak;
        }

        long smallChunkPeak;
        long largeChunkPeak;

        if (largeChunkFirst)
        {
            largeChunkPeak = PeakLiveBytesFor(largeChunk);
            smallChunkPeak = PeakLiveBytesFor(smallChunk);
        }
        else
        {
            smallChunkPeak = PeakLiveBytesFor(smallChunk);
            largeChunkPeak = PeakLiveBytesFor(largeChunk);
        }

        // Reported so the spread is inspectable without having to make the test fail first:
        // dotnet test --logger "console;verbosity=detailed".
        _output.WriteLine(
            $"peak live bytes: chunkSize={largeChunk} -> {largeChunkPeak:N0}, " +
            $"chunkSize={smallChunk} -> {smallChunkPeak:N0}, " +
            $"delta {largeChunkPeak - smallChunkPeak:N0} (margin {marginBytes:N0}, tallyVerification={tallyVerification})");

        Assert.True(
            largeChunkPeak > smallChunkPeak + marginBytes,
            $"Peak live bytes for chunkSize={largeChunk} ({largeChunkPeak}) did not exceed " +
            $"chunkSize={smallChunk} ({smallChunkPeak}) by the expected margin of {marginBytes} " +
            $"(the large chunk ran {(largeChunkFirst ? "first" : "second")}, tallyVerification={tallyVerification}); memory held at an " +
            "instant should scale with chunkSize when ballotCount is held fixed, or the runner may " +
            "be retaining encrypted ballots instead of streaming them.");
    }

    [Fact]
    public void Run_ReportsDkgSeparatelyFromTheTimedPhases()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(), manifest).Run();

        Assert.True(outcome.DkgMs > 0);
    }

    [Fact]
    public void Run_ExposesARepresentativeBallotForTheSerializationBenchmark()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(), manifest).Run();

        Assert.NotNull(outcome.RepresentativeBallot);
    }

    [Fact]
    public void Run_HonoursAChunkSizeLargerThanTheBallotCount()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(ballotCount: 3, chunkSize: 500), manifest).Run();

        Assert.Equal(CorrectnessStatus.Passed, outcome.Correctness.Status);
        Assert.Equal(3, outcome.Phases[PhaseNames.EncryptBallots].BallotsProcessed);
    }

    [Fact]
    public void Run_RunsVerification9WhenTallyVerificationIsRequested()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(tallyVerification: true), manifest).Run();

        Assert.Equal(CorrectnessStatus.Passed, outcome.Correctness.Status);
        Assert.Equal("ran", outcome.Notes["tallyVerification"]);

        // Verification 9's own cost used to be attributed to no phase at all, while its allocations
        // still inflated memory.totalAllocatedBytes -- a reader of the record could not see what
        // tally verification cost. It must get its own recorded phase, with real wall time,
        // allocations and a ballot count covering every ballot -- here streamed across two chunks of
        // four, so the count is the sum of the per-chunk accumulations, not one final batch.
        var tallyVerify = outcome.Phases[PhaseNames.VerifyTally];
        Assert.True(tallyVerify.WallMs > 0);
        Assert.True(tallyVerify.AllocatedBytes > 0);
        Assert.Equal(8, tallyVerify.BallotsProcessed);
        Assert.False(tallyVerify.Aborted);
    }

    /// <summary>
    /// The VerifyTally phase must appear only when Verification 9 was requested, consistent with how
    /// every other optional phase behaves -- and then nothing about it, not even a note.
    /// </summary>
    [Fact]
    public void Run_OmitsTheTallyVerifyPhaseWhenTallyVerificationIsNotRequested()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(tallyVerification: false), manifest).Run();

        Assert.False(outcome.Phases.ContainsKey(PhaseNames.VerifyTally));
        Assert.False(outcome.Notes.ContainsKey("tallyVerification"));
    }

    /// <summary>
    /// Verifications 10 (the proof of correct decryption) and 11 (the tally's labels) run after a
    /// successful decryption when tally verification is on, billed to their own phase: TallyComparer
    /// checks the counts but cannot see the proof.
    /// </summary>
    [Fact]
    public void Run_RunsVerifications10And11AfterDecryptionWhenTallyVerificationIsRequested()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(tallyVerification: true), manifest).Run();

        Assert.Equal(CorrectnessStatus.Passed, outcome.Correctness.Status);
        Assert.Equal("ran", outcome.Notes["decryptionVerification"]);
        var phase = outcome.Phases[PhaseNames.VerifyDecryption];
        Assert.True(phase.WallMs > 0);
        Assert.Equal(8, phase.BallotsProcessed);
        Assert.False(phase.Aborted);
        Assert.True(outcome.Phases.ContainsKey(PhaseNames.DecryptTally));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Run_OmitsVerifyDecryptionWithoutBothDecryptionAndTallyVerification(bool decrypt, bool tallyVerification)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var outcome = new ScenarioRunner(Scenario(decrypt: decrypt, tallyVerification: tallyVerification), manifest).Run();

        Assert.False(outcome.Phases.ContainsKey(PhaseNames.VerifyDecryption));
        Assert.False(outcome.Notes.ContainsKey("decryptionVerification"));
    }

    /// <summary>
    /// Verification 9 streams, so its budget is enforced at chunk boundaries like encryption's: the
    /// first chunk's accumulation exhausts it, the run stops there, and the final comparison never
    /// runs. 0.000000001 minutes is 60 nanoseconds (or rounds to zero), which no accumulation beats.
    /// </summary>
    [Fact]
    public void Run_AbortsAVerification9ThatExceedsItsBudgetAtAChunkBoundary()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var scenario = Scenario(
            ballotCount: 8,
            chunkSize: 4,
            tallyVerification: true,
            budgets: new Dictionary<string, double> { [PhaseNames.VerifyTally] = 0.000000001 });

        var outcome = new ScenarioRunner(scenario, manifest).Run();

        var tallyVerify = outcome.Phases[PhaseNames.VerifyTally];
        Assert.True(tallyVerify.Aborted);
        Assert.Equal(4, tallyVerify.BallotsProcessed);
        Assert.Equal("aborted:budgetExceeded", outcome.Notes[PhaseNames.VerifyTally]);
        Assert.Equal("aborted:budgetExceeded", outcome.Notes["tallyVerification"]);

        // Its abort stops the whole run at that boundary, exactly as any other phase's would.
        Assert.Equal(4, outcome.Phases[PhaseNames.EncryptBallots].BallotsProcessed);
        Assert.Equal("skipped:runAborted", outcome.Notes[PhaseNames.DecryptTally]);
        Assert.Equal(CorrectnessStatus.Incomplete, outcome.Correctness.Status);
    }

    /// <summary>
    /// When another phase's budget stops the run, Verification 9 has accumulated the chunks that
    /// did complete but never compared anything. Its phase is reported (it started, and its time
    /// was spent) but aborted, since no verification happened; its note says it was skipped, not
    /// that its own budget tripped, and it carries no budget note of its own.
    /// </summary>
    [Fact]
    public void Run_MarksVerification9SkippedWhenAnotherPhaseAbortsTheRun()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var scenario = Scenario(
            ballotCount: 40,
            chunkSize: 4,
            tallyVerification: true,
            budgets: new Dictionary<string, double> { [PhaseNames.EncryptBallots] = 0.0001 });

        var outcome = new ScenarioRunner(scenario, manifest).Run();

        Assert.Equal("aborted:budgetExceeded", outcome.Notes[PhaseNames.EncryptBallots]);
        Assert.Equal("skipped:runAborted", outcome.Notes["tallyVerification"]);
        Assert.False(outcome.Notes.ContainsKey(PhaseNames.VerifyTally));

        var tallyVerify = outcome.Phases[PhaseNames.VerifyTally];
        Assert.True(tallyVerify.Aborted);
        Assert.Equal(outcome.Phases[PhaseNames.EncryptBallots].BallotsProcessed, tallyVerify.BallotsProcessed);
        Assert.True(tallyVerify.BallotsProcessed < 40);

        // Tally is not marked: it measured the aggregation of exactly the chunks it was given.
        Assert.False(outcome.Phases[PhaseNames.Tally].Aborted);
        Assert.Equal(CorrectnessStatus.Incomplete, outcome.Correctness.Status);
    }

    [Fact]
    public void Run_VerifiesAChainedManifestSerially()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(chainingMode: ChainingMode.Simple);

        var outcome = new ScenarioRunner(Scenario(ballotVerification: true), manifest).Run();

        Assert.Equal("forced:1:chainingMode", outcome.Notes["parallelism"]);
        Assert.Equal(CorrectnessStatus.Passed, outcome.Correctness.Status);
    }

    /// <summary>
    /// A failed run is data. An exception out of the measured work used to discard every
    /// measurement taken before it -- no record, no timings, not even the DKG figure, which the
    /// throw cannot possibly have invalidated.
    ///
    /// The failure is forced by a ballot style naming a contest the manifest does not define, which
    /// throws out of BallotGenerator inside the chunk loop. Warmup is disabled so the throw lands
    /// there and not in the untimed setup that precedes it.
    /// </summary>
    [Fact]
    public void Run_RecordsAPartialResultWhenTheRunThrows()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var broken = manifest with
        {
            BallotStyles =
            [
                new BallotStyle
                {
                    Id = "ballot-style-1",
                    Name = "Ballot Style 1",
                    ContestIds = ["contest-that-does-not-exist"],
                },
            ],
        };

        var outcome = new ScenarioRunner(Scenario(warmupBallots: 0), broken).Run();

        Assert.Equal(CorrectnessStatus.Error, outcome.Correctness.Status);
        Assert.Contains("KeyNotFoundException", outcome.Notes["error"], StringComparison.Ordinal);
        Assert.Equal("skipped:runFailed", outcome.Notes[PhaseNames.DecryptTally]);

        // The record still exists, and everything measured before the throw is still in it.
        Assert.True(outcome.DkgMs > 0);
        Assert.True(outcome.Phases.ContainsKey(PhaseNames.EncryptBallots));
        Assert.True(outcome.Phases.ContainsKey(PhaseNames.Tally));

        // Neither phase reached RecordBallots() for the chunk the throw landed in (generation itself
        // throws, before encrypt.Enter() is ever called), so BallotsProcessed is 0 for both -- an
        // unmarked phase like that is indistinguishable from one that legitimately measured a
        // zero-cost, zero-ballot workload. Both must carry Aborted so RunComparer's judgeable guard
        // excludes them instead of treating a future comparison's zero baseline as real.
        Assert.True(outcome.Phases[PhaseNames.EncryptBallots].Aborted);
        Assert.True(outcome.Phases[PhaseNames.Tally].Aborted);
    }

    /// <summary>
    /// G13: Verification 5.A holds across the whole run, not per chunk. The first ballot of the
    /// second chunk is replaced by the first chunk's first ballot, so the only fault is an id_B that
    /// repeats one from an earlier chunk. A set of identifiers kept per chunk would pass this run.
    /// </summary>
    [Fact]
    public void Run_FailsVerification5A_WhenALaterChunkRepeatsAnEarlierChunksIdentifier()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        EncryptedBallot? first = null;
        var runner = new ScenarioRunner(Scenario(ballotCount: 8, chunkSize: 4, ballotVerification: true), manifest)
        {
            EncryptedBallotHookForTesting = (index, ballot) =>
            {
                first ??= ballot;
                return index == 4 ? first : ballot;
            },
        };

        var outcome = runner.Run();

        Assert.Equal(CorrectnessStatus.Error, outcome.Correctness.Status);
        Assert.Contains("VerificationFailedException", outcome.Notes["error"], StringComparison.Ordinal);
        Assert.Contains("Duplicate selection encryption identifier", outcome.Notes["error"], StringComparison.Ordinal);
    }

    /// <summary>The control for the test above: the same run with the hook leaving every ballot alone passes.</summary>
    [Fact]
    public void Run_PassesVerification5A_WhenTheHookChangesNothing()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var indices = new List<int>();
        var runner = new ScenarioRunner(Scenario(ballotCount: 8, chunkSize: 4, ballotVerification: true), manifest)
        {
            EncryptedBallotHookForTesting = (index, ballot) =>
            {
                indices.Add(index);
                return ballot;
            },
        };

        var outcome = runner.Run();

        Assert.Equal(CorrectnessStatus.Passed, outcome.Correctness.Status);
        Assert.Equal(Enumerable.Range(0, 8), indices);
    }

    /// <summary>
    /// A throw before Verification 9 accumulated its first chunk (here, generation of the first
    /// chunk) leaves no VerifyTally phase and no tallyVerification note: it never started, and
    /// notes.error already says why the run stopped.
    /// </summary>
    [Fact]
    public void Run_OmitsVerification9WhenTheRunThrowsBeforeItStarts()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var broken = manifest with
        {
            BallotStyles =
            [
                new BallotStyle
                {
                    Id = "ballot-style-1",
                    Name = "Ballot Style 1",
                    ContestIds = ["contest-that-does-not-exist"],
                },
            ],
        };

        var outcome = new ScenarioRunner(Scenario(warmupBallots: 0, tallyVerification: true), broken).Run();

        Assert.Equal(CorrectnessStatus.Error, outcome.Correctness.Status);
        Assert.False(outcome.Phases.ContainsKey(PhaseNames.VerifyTally));
        Assert.False(outcome.Notes.ContainsKey("tallyVerification"));
    }

    /// <summary>
    /// The decrypt budget's abort branch, which the shipped large.json depends on to record a
    /// partial result rather than run for hours. Every other budget test budgets `EncryptBallots`, which
    /// sets `aborted` and diverts before this code is ever reached.
    ///
    /// 0.000001 minutes is 60 microseconds, which real threshold decryption cannot beat.
    /// </summary>
    [Fact]
    public void Run_AbortsADecryptionThatExceedsItsBudgetAndStillReturns()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var scenario = Scenario(
            ballotCount: 4,
            chunkSize: 4,
            budgets: new Dictionary<string, double> { [PhaseNames.DecryptTally] = 0.000001 });

        var outcome = new ScenarioRunner(scenario, manifest).Run();

        Assert.True(outcome.Phases[PhaseNames.DecryptTally].Aborted);
        Assert.Equal("aborted:budgetExceeded", outcome.Notes[PhaseNames.DecryptTally]);
        Assert.Equal(CorrectnessStatus.Incomplete, outcome.Correctness.Status);

        // An abandoned decryption produced nothing, so it must not claim the run's ballots: the
        // comparer divides its wall time by exactly this number.
        Assert.Equal(0, outcome.Phases[PhaseNames.DecryptTally].BallotsProcessed);

        // Everything before decrypt completed and is still reported.
        Assert.Equal(4, outcome.Phases[PhaseNames.EncryptBallots].BallotsProcessed);
    }

    /// <summary>
    /// "A failed run is data" extended to setup itself. Before this fix, DKG, encryption-record
    /// construction and warmup had no error handling at all: a throw there escaped Run() entirely,
    /// crashing the whole `run` invocation and losing even the DKG timing already measured.
    ///
    /// Reuses Run_RecordsAPartialResultWhenTheRunThrows' broken-manifest fixture (a ballot style
    /// naming a contest the manifest does not define, which BallotGenerator.Generate throws a
    /// KeyNotFoundException on regardless of ballot index), but leaves warmup ENABLED -- the
    /// default -- so the throw lands inside Warmup(), in Stage 0, before the chunk loop (and its
    /// phase accumulators) ever exists.
    /// </summary>
    [Fact]
    public void Run_RecordsAnErrorResultWhenSetupThrows()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var broken = manifest with
        {
            BallotStyles =
            [
                new BallotStyle
                {
                    Id = "ballot-style-1",
                    Name = "Ballot Style 1",
                    ContestIds = ["contest-that-does-not-exist"],
                },
            ],
        };

        var outcome = new ScenarioRunner(Scenario(), broken).Run();

        Assert.Equal(CorrectnessStatus.Error, outcome.Correctness.Status);
        Assert.Contains("KeyNotFoundException", outcome.Notes["error"], StringComparison.Ordinal);

        // Nothing in Stage 1 ever started -- there is no encrypt/aggregate/etc. accumulator to
        // report, so the phases map is empty rather than a misleading zero-cost phase.
        Assert.Empty(outcome.Phases);
        Assert.Equal(0, outcome.BallotsEncrypted);
        Assert.Null(outcome.RepresentativeBallot);
    }

    /// <summary>
    /// EGParameters.Init used to set the guardian threshold process-wide with no restoration,
    /// leaking a scenario's N/K into whatever ran afterwards in the same process.
    /// OverrideScope, used with `using`, must restore whatever was active before Run() on the way
    /// out -- even though the scenario itself requests a different threshold while it runs.
    /// </summary>
    [Fact]
    public void Run_RestoresTheProcessWideGuardianParametersItOverrode()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        using (EGParameters.OverrideScope(new CryptographicParameters(), new GuardianParameters(5, 3)))
        {
            // The scenario's own threshold (the Scenario() helper's default) differs from the
            // sentinel (5, 3) set just above, so if OverrideScope's restoration did not fire, this
            // assertion would see the scenario's threshold instead.
            new ScenarioRunner(Scenario(), manifest).Run();

            Assert.Equal(5, EGParameters.GuardianParameters.N);
            Assert.Equal(3, EGParameters.GuardianParameters.K);
        }
    }
}
