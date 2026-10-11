using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.KeyGeneration;
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

    /// <summary>
    /// Test seam: called with each ballot's run-wide index and its encryption, after the encrypt
    /// phase's timing and before the ballot is verified or tallied; the ballot it returns is used in
    /// its place. Lets a test plant a fault that only shows across chunks, such as a later chunk
    /// repeating an earlier chunk's id_B (Verification 5.A). Null, and never set, outside tests.
    ///
    /// Under simple chaining the device chain has already appended the original ballot when the hook
    /// runs, so the closed device record lists what the device encrypted while the replaced ballot
    /// is what gets verified: the hook models a published ballot tampered with after the device
    /// recorded it, which is what the record exists to expose.
    /// </summary>
    internal Func<int, EncryptedBallot, EncryptedBallot>? EncryptedBallotHookForTesting { get; init; }

    /// <summary>
    /// Test seam: under simple chaining, called with the closed device record before the
    /// once-per-device Verification 8 walk checks it; the record it returns is checked in its place.
    /// Lets a test tamper with what only that walk checks (8.F, 8.G). Null, and never set, outside
    /// tests.
    /// </summary>
    internal Func<DeviceChainRecord, DeviceChainRecord>? DeviceChainRecordHookForTesting { get; init; }

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
            // The guardians check H_B and key their comparison hash with it (§3.2.2 step 1), so the
            // manifest file goes into the ceremony as well as into the encryption record.
            var manifestFile = new ManifestFile { Bytes = ManifestHasher.Serialize(_manifest) };
            guardianSet = ElectionFixtureBuilder.CreateGuardianSet(_scenario.Guardians.N, _scenario.Guardians.K, manifestFile);
            records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, _manifest, manifestFile);
            dkgStopwatch.Stop();

            // Verifications 1-4 on the record the ballots are encrypted against. Each runs once per
            // election, not per ballot, so they sit in this untimed setup block, after the DKG
            // stopwatch so that DkgMs stays comparable with earlier runs.
            new ParameterVerification().Verify(records.EncryptionRecord);
            new GuardianPublicKeyVerification().Verify(records.EncryptionRecord.Guardians);
            new ElectionPublicKeyVerification().Verify(records.EncryptionRecord.Guardians, records.EncryptionRecord.ElectionPublicKeys);
            new ExtendedBaseHashVerification().Verify(records.EncryptionRecord.ExtendedBaseHash, records.EncryptionRecord.ElectionBaseHash, records.EncryptionRecord.ElectionPublicKeys);

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

        // Verification 9 streams with everything else: each chunk is folded into the verifier's own
        // independent recomputation right after it is aggregated, and the recomputation is compared
        // with encryptedTally once, after the loop. No encrypted ballot outlives its chunk.
        //
        // Both are null exactly when tallyVerification is off. tallyVerifyStarted is what decides
        // whether PhaseNames.VerifyTally appears in the record: it is set before the first chunk's
        // Enter(), so the phase appears once Verification 9 has started accumulating -- even if a
        // throw then lands mid-chunk, before RecordBallots(), since that scope still billed ticks --
        // and is absent if the run never got that far. Like every other phase, it is marked aborted
        // whenever its measurement is not of the whole intended workload; see the Verification 9
        // block after the loop for why that includes a run some other phase aborted.
        var tallyVerifier = _scenario.Phases.TallyVerification ? new BallotAggregationVerifier(_manifest) : null;
        var tallyVerify = _scenario.Phases.TallyVerification
            ? new PhaseAccumulator(PhaseNames.VerifyTally, BudgetFor(PhaseNames.VerifyTally))
            : null;
        bool tallyVerifyStarted = false;

        // The phases whose budgets are checked at every chunk boundary.
        var budgetedPhases = tallyVerify is null
            ? new[] { encrypt, ballotVerify, aggregate }
            : new[] { encrypt, ballotVerify, aggregate, tallyVerify };

        // Verification 5.A across the whole run, not per chunk: every identifier seen so far. An
        // identifier is 32 bytes and no ballot is retained, so this grows by one small entry per
        // ballot whatever the chunk size.
        var selectionEncryptionIdentifiers = new SelectionEncryptionIdentifierSet();

        // Verification 11.D: every contest label that occurs on a submitted ballot. At most one
        // entry per manifest contest, however many ballots.
        var submittedContestIds = new HashSet<string>(StringComparer.Ordinal);

        EncryptedBallot? representative = null;
        ConfirmationCode? previousConfirmationCode = null;

        // Under simple chaining, the device's confirmation code chain (§3.4.4): every encrypted ballot
        // is appended, the chain is closed after the last chunk (eqs. 77/78), and the published
        // ballots are walked against its record (Verification 8.C-8.G). That keeps a confirmation
        // code per ballot, and a link (id, device, H_C, B_C) per ballot while ballot verification
        // runs. Under no chaining it is skipped: each ballot's B_C is fully checked per ballot (8.D),
        // and the list the harness would publish is just the order it encrypted in.
        var deviceChain = isChained ? new DeviceChain(records.EncryptionRecord, DeviceId) : null;
        var chainLinks = isChained && _scenario.Phases.BallotVerification ? new List<DeviceChainLink>() : null;
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

                // Every generated ballot is cast. The decision comes after encryption (the voter
                // sees the confirmation code first), so it is recorded outside the encrypt timing.
                // Verification 11.D needs the contests that appear on submitted ballots; they are
                // collected here rather than by retaining the ballots.
                foreach (var encryptedBallot in encryptedChunk)
                {
                    deviceChain?.Append(encryptedBallot);
                    encryptedBallot.RecordStatus(BallotStatus.Cast);
                    foreach (var contest in encryptedBallot.Contests)
                    {
                        submittedContestIds.Add(contest.Id);
                    }
                }

                if (EncryptedBallotHookForTesting is { } hook)
                {
                    for (int i = 0; i < chunkSize; i++)
                    {
                        encryptedChunk[i] = hook(generated + i, encryptedChunk[i]);
                    }
                }

                representative ??= encryptedChunk[0];

                if (chainLinks is not null)
                {
                    foreach (var encryptedBallot in encryptedChunk)
                    {
                        chainLinks.Add(DeviceChainLink.From(encryptedBallot));
                    }
                }

                if (_scenario.Phases.BallotVerification)
                {
                    using (ballotVerify.Enter())
                    {
                        VerifyChunk(encryptedChunk, records.EncryptionRecord, deviceHash, parallelism, isChained, chunkStartConfirmationCode, selectionEncryptionIdentifiers);
                    }

                    ballotVerify.RecordBallots(chunkSize);
                }

                using (aggregate.Enter())
                {
                    encryptedTally.AddBallots(encryptedChunk, parallelism);
                }

                aggregate.RecordBallots(chunkSize);

                if (tallyVerifier is not null && tallyVerify is not null)
                {
                    // Deliberately the same chunk that was just aggregated: this phase measures what
                    // Verification 9 costs, not whether the harness's own tally is right --
                    // ExpectedTallyAccumulator and the decrypted-tally comparison are the oracle.
                    tallyVerifyStarted = true;
                    using (tallyVerify.Enter())
                    {
                        tallyVerifier.AddBallots(encryptedChunk, parallelism);
                    }

                    tallyVerify.RecordBallots(chunkSize);
                }

                generated += chunkSize;
                sampler.SampleNow();

                foreach (var phase in budgetedPhases)
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

            // --- Verification 8, once per device (simple chaining) --------------------------
            // The chain is closed when the device stops (eqs. 77/78) and its record checked against
            // the published ballots: 8.C, 8.F, 8.E in list order and 8.G. Billed to ballot
            // verification without adding to its ballot count.
            if (deviceChain is not null && chainLinks is not null && !aborted)
            {
                var deviceChainRecord = deviceChain.Close();
                if (DeviceChainRecordHookForTesting is { } recordHook)
                {
                    deviceChainRecord = recordHook(deviceChainRecord);
                }

                using (ballotVerify.Enter())
                {
                    new ConfirmationCodeVerification().VerifyDevices([deviceChainRecord], chainLinks, records.EncryptionRecord);
                }
            }

            // --- Verification 9 -----------------------------------------------------------
            // The ballots were folded in chunk by chunk above; all that is left is the comparison,
            // one read per option. It is billed to the same phase, and has no budget check of its own:
            // the budget is enforced at chunk boundaries like every other streamed phase, and once
            // the last chunk is in, the comparison is what makes the time already spent worth anything.
            //
            // notes["tallyVerification"] is keyed separately from PhaseNames.VerifyTally (the
            // phases-dictionary key, a distinct namespace) and records whether a verdict was reached:
            //   "ran"                    -- every chunk was accumulated and the comparison executed.
            //   "aborted:budgetExceeded" -- Verification 9's own budget tripped (whether or not
            //                               another phase's did in the same chunk).
            //   "skipped:runAborted"     -- another phase's budget stopped the run first.
            // A throw leaves it unset; notes["error"] says why the run stopped.
            if (tallyVerifier is not null && tallyVerify is not null)
            {
                if (!aborted)
                {
                    tallyVerifyStarted = true;
                    using (tallyVerify.Enter())
                    {
                        tallyVerifier.Verify(encryptedTally);
                    }

                    notes["tallyVerification"] = "ran";
                }
                else if (tallyVerify.Aborted)
                {
                    notes["tallyVerification"] = "aborted:budgetExceeded";
                }
                else
                {
                    // Unlike Tally, which is NOT marked aborted when another phase stops the run --
                    // its metric is the cost of aggregating the chunks it was given, and that
                    // measurement is complete -- VerifyTally is. Its metric is the cost of a
                    // verification, and with the comparison never run and the remaining ballots
                    // never added, no verification happened: its time is a partial accumulation that
                    // must not be read, or compared, as the cost of Verification 9.
                    tallyVerify.MarkAborted();
                    notes["tallyVerification"] = "skipped:runAborted";
                }
            }
        }
        catch (Exception ex)
        {
            // Encryption, chunk verification, aggregation and Verification 9 (its per-chunk
            // accumulation and its final comparison) all live above. A
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
            // expectedTally.Add) or after all of them finish (Verification 9's final comparison), in which
            // case whichever phase(s) never touched this chunk are internally consistent but still
            // short of the full workload the scenario asked for. Either way none of them represents a
            // complete, trustworthy measurement of the intended run, so mark all of them aborted here
            // rather than guessing which single one was mid-flight. This is deliberately broader than
            // the budget-exceeded branch above, which marks only the phase whose budget tripped: that
            // phase is known, and the others each measured exactly the chunks they were given, whereas
            // a throw can land inside any phase's scope. tallyVerify is marked too, but it reaches the record only
            // if tallyVerifyStarted -- a throw before the first chunk's Verification 9 scope (e.g. in
            // the first chunk's encryption) leaves it out entirely rather than reporting a misleading
            // zero-cost aborted phase.
            encrypt.MarkAborted();
            ballotVerify.MarkAborted();
            aggregate.MarkAborted();
            tallyVerify?.MarkAborted();
        }

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

        if (tallyVerify is not null && tallyVerifyStarted)
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
            // cheapest correct one. The phase covers the whole verifiable decryption (§3.6.5): the
            // guardians' three rounds (M_i and d_i; (a_i, b_i); v_i), the administrator's combination
            // and its check of the proof, and the discrete-log search.
            DecryptedTally RunDecryption() =>
                ElectionFixtureBuilder.DecryptTally(guardianSet, encryptedTally, records.EncryptionRecord, _scenario.Guardians.K, parallelism);

            DecryptedTally? decryptedTally = null;
            bool decryptTimedOut = false;

            try
            {
                using (decrypt.Enter())
                {
                    if (decryptBudget.HasValue)
                    {
                        // TallyAdmin.Decrypt has no CancellationToken, so the only way to bound its wall
                        // time is to run it on another thread and stop waiting. When the budget expires
                        // the task is ABANDONED, not cancelled: it keeps running on a thread-pool thread
                        // until it finishes on its own, however long that takes. In this CLI the process exits
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

            // --- Verifications 10 and 11 -----------------------------------------------------
            // TallyComparer checks the counts against the oracle, but it cannot see the proof: a
            // decrypted tally whose (c, v) does not verify is a failed run even when its counts are
            // right. Gated with Verification 9 on tallyVerification, and billed to a phase of its
            // own so DecryptTally stays comparable with runs from before the proof existed.
            if (failure is null && decryptedTally is not null && _scenario.Phases.TallyVerification)
            {
                var decryptionVerify = new PhaseAccumulator(PhaseNames.VerifyDecryption, BudgetFor(PhaseNames.VerifyDecryption));
                try
                {
                    using (decryptionVerify.Enter())
                    {
                        new TallyDecryptionVerification().Verify(records.EncryptionRecord, encryptedTally, decryptedTally, parallelism);
                        new TallyContentsVerification().Verify(_manifest, decryptedTally, submittedContestIds);
                    }

                    decryptionVerify.RecordBallots(generated);
                    notes["decryptionVerification"] = "ran";
                }
                catch (Exception ex)
                {
                    failure = Describe(ex);
                    notes["error"] = failure;
                    decryptionVerify.MarkAborted();
                    _log($"  decryption verification failed: {failure}");
                }

                phases[PhaseNames.VerifyDecryption] = decryptionVerify.ToMetrics();
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
            var warmupBallot = encryptor.Encrypt(generator.Generate(-(i + 1)), null);
            warmupBallot.RecordStatus(BallotStatus.Cast);
            throwaway.AddBallot(warmupBallot);
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
        ConfirmationCode? chunkStartConfirmationCode,
        SelectionEncryptionIdentifierSet selectionEncryptionIdentifiers)
    {
        // Verification 5.A checks that selection encryption identifiers are distinct across every
        // submitted ballot. Under streaming the ballots are never all in memory at once, but their
        // identifiers are: the set carries every earlier chunk's.
        foreach (var ballot in chunk)
        {
            selectionEncryptionIdentifiers.Add(ballot.SelectionEncryptionIdentifier);
        }

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
            // Scheduling, measured on a 16-core/32-thread machine (spike/scheduling):
            //
            // 1. Parallel.ForEach over an array partitions by index range and kept only ~72-75% of
            //    the workers busy on this workload -- each item is roughly a second of CPU, so a
            //    worker holding a range of several ballots strands the rest. Handing out one work
            //    item at a time (NoBuffering) brings that to ~97% and was 1.27-1.30x faster at both
            //    16 and 32 threads, with chunks of 200 and 500.
            // 2. Each ballot is split into two independent items, Verification 6 (~75% of the cost)
            //    and Verifications 7+8, queued largest-first, so the small items fill the tail of the
            //    chunk instead of cores idling while the last whole ballots finish: a further ~3%
            //    at a 500-ballot chunk, more at smaller ones.
            //
            // The verifications are independent of each other and of other ballots here (no
            // chaining), so this changes scheduling only, not the work done.
            var items = new (EncryptedBallot Ballot, bool Proofs)[chunk.Length * 2];
            for (int i = 0; i < chunk.Length; i++)
            {
                items[i] = (chunk[i], true);
                items[chunk.Length + i] = (chunk[i], false);
            }

            Parallel.ForEach(
                Partitioner.Create(items, EnumerablePartitionerOptions.NoBuffering),
                new ParallelOptions { MaxDegreeOfParallelism = parallelism },
                item =>
                {
                    if (item.Proofs)
                    {
                        new SelectionEncryptionsWellFormedVerification().Verify(item.Ballot, encryptionRecord);
                    }
                    else
                    {
                        new AdherenceToVoteLimitsVerification().Verify(item.Ballot, encryptionRecord);
                        new ConfirmationCodeVerification().Verify(item.Ballot, encryptionRecord);
                    }
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
