using System.Diagnostics;
using System.Globalization;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Perf.Cli.Configuration;
using ElectionGuard.Perf.Cli.Measurement;
using ElectionGuard.Perf.Cli.Results;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Perf.Cli.Running;

/// <summary>
/// Runs one scenario end to end.
///
/// Encrypted ballots are roughly 50 KB each for a four-contest manifest, so a million of them would
/// be about 50 GB. The runner therefore streams: it generates a chunk, encrypts it, folds it into
/// the tally, and drops it. Peak memory is a function of chunkSize, not ballotCount.
///
/// Every phase honours an optional budget and stops at the next chunk boundary when it is exhausted,
/// so a scenario that is impractical today can still be configured and run: it yields a recorded
/// partial result rather than an unbounded wait.
/// </summary>
public sealed class ScenarioRunner
{
    private const string DeviceId = "perf-device-1";

    private readonly PerfScenario _scenario;
    private readonly Manifest _manifest;
    private readonly Action<string> _log;
    private readonly int _powRadixWindowBits;

    /// <param name="powRadixWindowBits">
    /// Bits per window for the Note 3.5 precomputed power tables. Zero skips precomputation
    /// entirely, which measures the table-free Montgomery path. Null takes
    /// <see cref="PowRadix.DefaultWindowBits"/>.
    /// </param>
    public ScenarioRunner(PerfScenario scenario, Manifest manifest, Action<string>? log = null, int? powRadixWindowBits = null)
    {
        // Constructed directly rather than through ScenarioLoader (as every test here does), a
        // scenario carries no guarantee of validity -- e.g. a ChunkSize of 0 would produce an empty
        // chunk and blow up at encryptedChunk[0]. Validate here so the runner is safe standalone.
        ScenarioLoader.Validate(scenario);

        _scenario = scenario;
        _manifest = manifest;
        _log = log ?? (_ => { });

        _powRadixWindowBits = powRadixWindowBits ?? PowRadix.DefaultWindowBits;
        if (_powRadixWindowBits < 0 || (_powRadixWindowBits > 0 && _powRadixWindowBits > PowRadix.MaxWindowBits))
        {
            throw new ArgumentOutOfRangeException(
                nameof(powRadixWindowBits),
                _powRadixWindowBits,
                $"Window width must be 0 (no tables) or between {PowRadix.MinWindowBits} and {PowRadix.MaxWindowBits}.");
        }
    }

    public RunOutcome Run()
    {
        var notes = new Dictionary<string, string>();
        using var sampler = new MemorySampler(TimeSpan.FromMilliseconds(250));

        // The guardian threshold is process-wide state that the DKG and GuardianRecord both read.
        // OverrideScope (not Init) restores whatever was in force before this call on the way out --
        // Init would leave this scenario's N/K in force for everything that runs afterwards in the
        // same process, including a later scenario or, inside the test suite, a later test.
        using var parameterScope = EGParameters.OverrideScope(
            new CryptographicParameters(),
            new GuardianParameters(_scenario.Guardians.N, _scenario.Guardians.K));

        // --- Stage 0: setup (untimed) -------------------------------------------------
        var dkgStopwatch = Stopwatch.StartNew();

        ElectionFixtureBuilder.GuardianSetResult guardianSet;
        ElectionFixtureBuilder.EncryptionRecordResult records;
        VotingDeviceInformationHash deviceHash;
        BallotGenerator generator;
        bool isChained;
        int parallelism;

        try
        {
            guardianSet = ElectionFixtureBuilder.CreateGuardianSet(_scenario.Guardians.N, _scenario.Guardians.K);
            var manifestFile = new ManifestFile { Bytes = ManifestHasher.Serialize(_manifest) };
            records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, _manifest, manifestFile);
            dkgStopwatch.Stop();

            deviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, DeviceId);
            generator = new BallotGenerator(_manifest, _scenario.Seed);

            // Chaining makes each ballot depend on the previous one's confirmation code, so it cannot
            // be parallelized at all. Honour the manifest rather than silently producing invalid chains.
            isChained = _manifest.ChainingMode != ChainingMode.None;
            parallelism = isChained
                ? 1
                : _scenario.Parallelism == 0 ? Environment.ProcessorCount : _scenario.Parallelism;

            if (isChained)
            {
                notes["parallelism"] = "forced:1:chainingMode";
            }

            Warmup(records.EncryptionRecord, deviceHash, generator);
        }
        catch (Exception ex)
        {
            // DKG, encryption-record construction and warmup all live above -- none of Stage 1's
            // phase accumulators exist yet, so there is nothing to mark aborted, only a bare record
            // to return. "A failed run is data" applied to everything AFTER this point already; a
            // throw here used to escape uncaught (none of Program.cs's catches list every exception
            // type these can throw), crashing the whole invocation with a raw stack trace and losing
            // even the DKG timing already measured. dkgStopwatch.Stop() is safe to call again if it
            // already stopped above (Stopwatch tolerates a redundant Stop); either way .Elapsed reads
            // whatever accumulated up to the throw, the only measurement this stage could produce.
            dkgStopwatch.Stop();
            var setupFailure = Describe(ex);
            notes["error"] = setupFailure;
            _log($"  setup failed: {setupFailure}");
            sampler.SampleNow();

            return new RunOutcome
            {
                Phases = new Dictionary<string, PhaseMetrics>(),
                Memory = sampler.Snapshot(),
                Correctness = new CorrectnessResult { Status = CorrectnessStatus.Error },
                DkgMs = dkgStopwatch.Elapsed.TotalMilliseconds,
                Notes = notes,
                BallotsEncrypted = 0,
                RepresentativeBallot = null,
            };
        }

        // Note 3.5: every exponentiation performed while encrypting and proving ballot components
        // has a base of g, K or K-hat, so tables of powers of those three are built once here and
        // reused for every ballot. The library leaves this opt-in, but the harness always opts in:
        // measuring encryption without it would be measuring a configuration no real encryptor
        // should run. Built before the encrypt phase opens so the one-time cost is reported on its
        // own rather than charged to the first chunk.
        // Tables are keyed by their base, and every run generates fresh guardian keys, so without
        // this each run in a long-lived process would leave ~8 MB of tables for keys nothing will
        // ever use again. The registry is caller-owned by design; this caller's unit of ownership
        // is one scenario run.
        PowRadixRegistry.Clear();

        notes["powRadixWindowBits"] = _powRadixWindowBits.ToString(CultureInfo.InvariantCulture);

        if (_powRadixWindowBits > 0)
        {
            var powRadixStopwatch = Stopwatch.StartNew();
            BallotEncryptor.PrecomputePowerTables(records.EncryptionRecord, _powRadixWindowBits);
            powRadixStopwatch.Stop();

            long powRadixBytes = PowRadixRegistry.TotalTableSizeInBytes;
            notes["powRadixBuildMs"] = powRadixStopwatch.Elapsed.TotalMilliseconds.ToString("F1", CultureInfo.InvariantCulture);
            notes["powRadixBytes"] = powRadixBytes.ToString(CultureInfo.InvariantCulture);
            _log($"  precomputed power tables ({_powRadixWindowBits}-bit window) in {powRadixStopwatch.Elapsed.TotalMilliseconds:F0} ms ({powRadixBytes / (1024.0 * 1024.0):F0} MB)");
        }
        else
        {
            // Not a no-op path: encryption, verification and the tally still run on Montgomery
            // limbs, just without a table. This is what isolates the table's contribution from the
            // Montgomery representation's.
            notes["powRadixBuildMs"] = "0.0";
            notes["powRadixBytes"] = "0";
            _log("  precomputed power tables disabled (table-free Montgomery)");
        }

        // --- Stage 1: streaming main loop ---------------------------------------------
        var encrypt = new PhaseAccumulator(PhaseNames.EncryptBallots, BudgetFor(PhaseNames.EncryptBallots));
        var ballotVerify = new PhaseAccumulator(PhaseNames.VerifyBallots, BudgetFor(PhaseNames.VerifyBallots));
        var aggregate = new PhaseAccumulator(PhaseNames.Tally, BudgetFor(PhaseNames.Tally));

        var expectedTally = new ExpectedTallyAccumulator(_manifest);
        var encryptedTally = new EncryptedTally(_manifest);
        var retainedBallots = _scenario.Phases.TallyVerification ? new List<EncryptedBallot>() : null;

        // Declared here (rather than only inside the Verification 9 block below) so both the catch
        // block and the phases dictionary can see whether it was ever entered. Stays null exactly
        // when Verification 9 never started -- the setting was off, or the run was already aborted
        // -- which is also when it must NOT appear in the persisted record: PhaseNames.VerifyTally
        // is meant to appear only when tally verification actually ran, unlike VerifyBallots/Tally
        // which are unconditionally created up front because they always at least attempt to run.
        PhaseAccumulator? tallyVerify = null;

        EncryptedBallot? representative = null;
        ConfirmationCode? previousConfirmationCode = null;
        int generated = 0;
        bool aborted = false;

        // Set on the first exception out of the measured work. A failed run is data: whatever
        // phases completed before the throw are still recorded, and the record says why it stopped.
        string? failure = null;

        try
        {
            while (generated < _scenario.BallotCount && !aborted)
            {
                int chunkSize = Math.Min(_scenario.ChunkSize, _scenario.BallotCount - generated);

                // Generation is untimed. Expected-tally contributions are accumulated here, BEFORE
                // encryption, because BallotEncryptor mutates an overvoted ballot's selections to zero.
                var chunk = new Ballot[chunkSize];
                Parallel.For(0, chunkSize, new ParallelOptions { MaxDegreeOfParallelism = parallelism },
                    i => chunk[i] = generator.Generate(generated + i));

                foreach (var ballot in chunk)
                {
                    expectedTally.Add(ballot);
                }

                // Captured before encryption advances it, so verification can replay the same chain
                // this chunk was encrypted against, including the ballot carried over the chunk
                // boundary from the previous chunk.
                var chunkStartConfirmationCode = previousConfirmationCode;

                var encryptedChunk = new EncryptedBallot[chunkSize];
                using (encrypt.Enter())
                {
                    if (isChained)
                    {
                        var encryptor = new BallotEncryptor(records.EncryptionRecord, DeviceId, deviceHash);
                        for (int i = 0; i < chunkSize; i++)
                        {
                            encryptedChunk[i] = encryptor.Encrypt(chunk[i], previousConfirmationCode);
                            previousConfirmationCode = encryptedChunk[i].ConfirmationCode;
                        }
                    }
                    else
                    {
                        Parallel.For(0, chunkSize, new ParallelOptions { MaxDegreeOfParallelism = parallelism }, i =>
                        {
                            var encryptor = new BallotEncryptor(records.EncryptionRecord, DeviceId, deviceHash);
                            encryptedChunk[i] = encryptor.Encrypt(chunk[i], null);
                        });
                    }
                }

                encrypt.RecordBallots(chunkSize);
                representative ??= encryptedChunk[0];

                if (_scenario.Phases.BallotVerification)
                {
                    using (ballotVerify.Enter())
                    {
                        VerifyChunk(encryptedChunk, records.EncryptionRecord, deviceHash, parallelism, isChained, chunkStartConfirmationCode);
                    }

                    ballotVerify.RecordBallots(chunkSize);
                }

                using (aggregate.Enter())
                {
                    foreach (var encryptedBallot in encryptedChunk)
                    {
                        encryptedTally.AddBallot(encryptedBallot);
                    }
                }

                aggregate.RecordBallots(chunkSize);
                retainedBallots?.AddRange(encryptedChunk);

                generated += chunkSize;
                sampler.SampleNow();

                foreach (var phase in new[] { encrypt, ballotVerify, aggregate })
                {
                    if (phase.BudgetExceeded)
                    {
                        phase.MarkAborted();
                        notes[phase.Name] = "aborted:budgetExceeded";
                        aborted = true;
                    }
                }

                _log($"  {generated:N0}/{_scenario.BallotCount:N0} ballots");
            }

            // --- Verification 9 -----------------------------------------------------------
            if (_scenario.Phases.TallyVerification && retainedBallots is not null && !aborted)
            {
                var tallyVerifyBudget = BudgetFor(PhaseNames.VerifyTally);
                tallyVerify = new PhaseAccumulator(PhaseNames.VerifyTally, tallyVerifyBudget);

                using (tallyVerify.Enter())
                {
                    if (tallyVerifyBudget.HasValue)
                    {
                        // Same reasoning as the decrypt budget below: BallotAggregationVerification.Verify
                        // has no CancellationToken and cannot be interrupted mid-flight, so the only way
                        // to bound its wall time is to run it on another thread and stop waiting. A
                        // timed-out verification is ABANDONED, not cancelled -- it keeps running until it
                        // finishes on its own.
                        var verifyTask = Task.Run(() =>
                            new BallotAggregationVerification().Verify(retainedBallots, _manifest, encryptedTally));

                        if (verifyTask.Wait(tallyVerifyBudget.Value))
                        {
                            tallyVerify.RecordBallots(retainedBallots.Count);
                        }
                        else
                        {
                            tallyVerify.MarkAborted();
                        }
                    }
                    else
                    {
                        new BallotAggregationVerification().Verify(retainedBallots, _manifest, encryptedTally);
                        tallyVerify.RecordBallots(retainedBallots.Count);
                    }
                }

                // Keyed "tallyVerification", NOT PhaseNames.VerifyTally: PhaseNames.VerifyTally is the
                // phases-dictionary key, a distinct namespace from notes -- and using it here would
                // read as though the phase entry itself carried this string, when it is a `bool`-shaped
                // Aborted flag instead.
                notes["tallyVerification"] = tallyVerify.Aborted ? "aborted:budgetExceeded" : "ran";
            }
            else if (_scenario.Phases.TallyVerification)
            {
                notes["tallyVerification"] = "skipped:runAborted";
            }
        }
        catch (Exception ex)
        {
            // Encryption, chunk verification, aggregation and Verification 9 all live above. A
            // VerificationFailedException at ballot 800,000 of a long run used to discard every
            // measurement taken up to that point -- including the DKG figure, which the throw
            // cannot possibly have invalidated. Record the cause and return what completed.
            failure = Describe(ex);
            notes["error"] = failure;
            _log($"  run failed: {failure}");

            // The throw can land mid-chunk inside any one of these phases' `using (Enter())` scope:
            // Dispose still runs on unwind and bills the partial ticks/bytes, but the RecordBallots()
            // call that follows the `using` block never executes, so BallotsProcessed undercounts what
            // was just billed. It can equally land before any of them even start (chunk generation,
            // expectedTally.Add) or after all of them finish for this chunk (Verification 9), in which
            // case whichever phase(s) never touched this chunk are internally consistent but still
            // short of the full workload the scenario asked for. Either way none of them represents a
            // complete, trustworthy measurement of the intended run -- exactly the reasoning the
            // budget-exceeded branch above already applies to encrypt/ballotVerify/aggregate regardless
            // of which one tripped the budget -- so mark all of them aborted here rather than guessing
            // which single one was mid-flight. tallyVerify is conditional: it is only non-null once
            // Verification 9 actually started, so a throw earlier in the chunk loop correctly leaves it
            // out of the record entirely rather than reporting a misleading zero-cost aborted phase.
            encrypt.MarkAborted();
            ballotVerify.MarkAborted();
            aggregate.MarkAborted();
            tallyVerify?.MarkAborted();
        }

        retainedBallots?.Clear();

        // --- Stage 2: decrypt ----------------------------------------------------------
        var phases = new Dictionary<string, PhaseMetrics>
        {
            [PhaseNames.EncryptBallots] = encrypt.ToMetrics(),
            [PhaseNames.Tally] = aggregate.ToMetrics(),
        };

        if (_scenario.Phases.BallotVerification)
        {
            phases[PhaseNames.VerifyBallots] = ballotVerify.ToMetrics();
        }

        if (tallyVerify is not null)
        {
            phases[PhaseNames.VerifyTally] = tallyVerify.ToMetrics();
        }

        CorrectnessResult correctness;
        if (failure is not null)
        {
            correctness = new CorrectnessResult { Status = CorrectnessStatus.Error };
            notes[PhaseNames.DecryptTally] = "skipped:runFailed";
        }
        else if (!_scenario.Phases.Decrypt)
        {
            correctness = new CorrectnessResult { Status = CorrectnessStatus.Skipped };
            notes[PhaseNames.DecryptTally] = "skipped:disabled";
        }
        else if (aborted)
        {
            correctness = new CorrectnessResult { Status = CorrectnessStatus.Incomplete };
            notes[PhaseNames.DecryptTally] = "skipped:runAborted";
        }
        else
        {
            var decryptBudget = BudgetFor(PhaseNames.DecryptTally);
            var decrypt = new PhaseAccumulator(PhaseNames.DecryptTally, decryptBudget);

            // K guardians is the threshold; using exactly K is the realistic case and the
            // cheapest correct one.
            DecryptedTally RunDecryption() =>
                new TallyAdmin().Decrypt(
                    guardianSet.Guardians
                        .Take(_scenario.Guardians.K)
                        .Select(guardian => new TallyGuardian(guardian.Index, guardianSet.SecretShares[guardian.Index])
                            .Decrypt(encryptedTally))
                        .ToList(),
                    encryptedTally,
                    guardianSet.ElectionPublicKeys);

            DecryptedTally? decryptedTally = null;
            bool decryptTimedOut = false;

            try
            {
                using (decrypt.Enter())
                {
                    if (decryptBudget.HasValue)
                    {
                        // TallyAdmin.Decrypt brute-forces a discrete log per choice with no early exit
                        // and no CancellationToken, so the only way to bound its wall time is to run it
                        // on another thread and stop waiting. When the budget expires the task is
                        // ABANDONED, not cancelled: it keeps running on a thread-pool thread until it
                        // finishes on its own, however long that takes. In this CLI the process exits
                        // shortly after Run() returns, which reclaims the thread; a long-lived host that
                        // embedded this runner would keep burning a core for the abandoned decryption's
                        // entire remaining run time.
                        var decryptTask = Task.Run(RunDecryption);
                        if (decryptTask.Wait(decryptBudget.Value))
                        {
                            decryptedTally = decryptTask.Result;
                        }
                        else
                        {
                            decryptTimedOut = true;
                        }
                    }
                    else
                    {
                        decryptedTally = RunDecryption();
                    }
                }

                if (decryptTimedOut)
                {
                    decrypt.MarkAborted();
                    notes[PhaseNames.DecryptTally] = "aborted:budgetExceeded";
                    phases[PhaseNames.DecryptTally] = decrypt.ToMetrics();
                    correctness = new CorrectnessResult { Status = CorrectnessStatus.Incomplete };
                }
                else
                {
                    // Recorded only on the success path. An abandoned decryption produced nothing, so
                    // crediting it with the full ballot count would report a per-ballot cost for work
                    // that never finished -- and RunComparer divides by exactly this number.
                    decrypt.RecordBallots(generated);
                    phases[PhaseNames.DecryptTally] = decrypt.ToMetrics();
                    correctness = TallyComparer.Compare(expectedTally.Build(), decryptedTally!);
                }
            }
            catch (Exception ex)
            {
                // Threshold decryption throws for its own reasons (a bad share, a discrete log that
                // falls outside the searched range). Same contract as the loop above: keep the
                // phases that completed, and say what went wrong.
                failure = Describe(ex);
                notes["error"] = failure;

                // decrypt.Enter()'s Dispose already ran on unwind and billed whatever partial ticks
                // and bytes happened before the throw, but decrypt.RecordBallots(generated) --
                // reached only on the success path above -- never fired, so BallotsProcessed stays
                // at 0 against a nonzero cost. Mark it aborted (before snapshotting metrics below) so
                // that mismatch reads as a partial measurement rather than a legitimate, gate-able
                // zero-ballot phase. encrypt/ballotVerify/aggregate need no such marking here: this
                // stage is only reached once the main loop above has already finished cleanly.
                decrypt.MarkAborted();
                phases[PhaseNames.DecryptTally] = decrypt.ToMetrics();
                correctness = new CorrectnessResult { Status = CorrectnessStatus.Error };
                _log($"  decryption failed: {failure}");
            }
        }

        // Error outranks Incomplete: a run that threw is not merely partial.
        if (failure is not null)
        {
            correctness = correctness with { Status = CorrectnessStatus.Error };
        }
        else if (aborted && correctness.Status != CorrectnessStatus.Failed)
        {
            correctness = correctness with { Status = CorrectnessStatus.Incomplete };
        }

        sampler.SampleNow();

        return new RunOutcome
        {
            Phases = phases,
            Memory = sampler.Snapshot(),
            Correctness = correctness,
            DkgMs = dkgStopwatch.Elapsed.TotalMilliseconds,
            Notes = notes,
            BallotsEncrypted = generated,
            RepresentativeBallot = representative,
        };
    }

    /// <summary>
    /// Pushes a small number of ballots through encrypt and aggregate into a throwaway tally.
    ///
    /// .NET tiered compilation runs the first ~30 calls of every method at tier-0, and
    /// BallotEncryptor.Encrypt is a deep call tree. Without this, a 1,000-ballot scenario measures
    /// substantially more JIT than a 1,000,000-ballot one, and the cheap scenario -- the one that
    /// actually gets iterated on -- is the misleading one.
    /// </summary>
    private void Warmup(EncryptionRecord encryptionRecord, VotingDeviceInformationHash deviceHash, BallotGenerator generator)
    {
        if (_scenario.WarmupBallots <= 0)
        {
            return;
        }

        var throwaway = new EncryptedTally(_manifest);
        var encryptor = new BallotEncryptor(encryptionRecord, DeviceId, deviceHash);

        for (int i = 0; i < _scenario.WarmupBallots; i++)
        {
            // Negative indexes so warmup ballots can never collide with measured ones.
            throwaway.AddBallot(encryptor.Encrypt(generator.Generate(-(i + 1)), null));
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    private static void VerifyChunk(
        EncryptedBallot[] chunk,
        EncryptionRecord encryptionRecord,
        VotingDeviceInformationHash deviceHash,
        int parallelism,
        bool isChained,
        ConfirmationCode? chunkStartConfirmationCode)
    {
        // Verification 5 checks that selection encryption identifiers are distinct. Under streaming
        // the whole set is never in memory at once, so this checks distinctness within the chunk --
        // recorded here rather than silently passing a one-element list, which checks nothing.
        new SelectionEncryptionIdentifierVerification()
            .Verify(chunk.Select(x => x.SelectionEncryptionIdentifier).ToList());

        if (isChained)
        {
            // ConfirmationCodeVerification reconstructs each ballot's chaining field from the
            // previous ballot's confirmation code and compares it to the ballot's own code. Under
            // chaining that previous code is real, not null, and each ballot depends on the one
            // before it -- exactly like encryption above, verification must walk the chunk serially,
            // carrying the previous ballot's code (or the prior chunk's last code, at the boundary)
            // forward one ballot at a time. Parallel.ForEach is incompatible with that dependency.
            var previous = chunkStartConfirmationCode;
            foreach (var ballot in chunk)
            {
                new SelectionEncryptionsWellFormedVerification().Verify(ballot, encryptionRecord);
                new AdherenceToVoteLimitsVerification().Verify(ballot, encryptionRecord);
                new ConfirmationCodeVerification().Verify(ballot, deviceHash, encryptionRecord, previous);
                previous = ballot.ConfirmationCode;
            }
        }
        else
        {
            Parallel.ForEach(chunk, new ParallelOptions { MaxDegreeOfParallelism = parallelism }, ballot =>
            {
                new SelectionEncryptionsWellFormedVerification().Verify(ballot, encryptionRecord);
                new AdherenceToVoteLimitsVerification().Verify(ballot, encryptionRecord);
                new ConfirmationCodeVerification().Verify(ballot, deviceHash, encryptionRecord, null);
            });
        }
    }

    /// <summary>Exception type plus message, as recorded in notes["error"].</summary>
    private static string Describe(Exception exception)
    {
        // Parallel.For and Task.Wait both wrap whatever the work threw, and the wrapper's own
        // message ("One or more errors occurred") says nothing about the cause. Report the first
        // real exception; if several iterations failed at once they failed for the same reason.
        var relevant = exception is AggregateException aggregate
            ? aggregate.Flatten().InnerExceptions.FirstOrDefault() ?? exception
            : exception;

        return $"{relevant.GetType().Name}: {relevant.Message}";
    }

    private TimeSpan? BudgetFor(string phase) =>
        _scenario.Budgets.TryGetValue(phase, out var minutes)
            ? TimeSpan.FromMinutes(minutes)
            : null;
}
