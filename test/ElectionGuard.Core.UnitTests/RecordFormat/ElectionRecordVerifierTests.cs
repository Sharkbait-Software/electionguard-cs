using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Testing.Common;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordCarrierElections;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;
using Google.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-9: <see cref="ElectionRecordVerifier.VerifyAllAsync"/> over whole records (design §6).
/// </summary>
public class ElectionRecordVerifierTests
{
    public ElectionRecordVerifierTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    /// <summary>Everything a report says but its elapsed time, as text: two equal runs give the same string.</summary>
    internal static string Canonical(VerificationReport report)
    {
        var text = new System.Text.StringBuilder();
        text.AppendLine($"{report.Passed} {report.Complete} {report.Profile} {report.Phase} {report.RecordFormat} {report.ReaderFormat} {report.RootsMatchClaimedToc} {report.Truncated}");
        foreach (var (phase, root) in report.PhaseRoots.OrderBy(x => x.Key))
        {
            text.AppendLine($"root {phase} {root}");
        }

        foreach (var (v, outcome) in report.Verifications.OrderBy(x => x.Key))
        {
            text.AppendLine($"V{v} {outcome}");
        }

        foreach (var f in report.Findings)
        {
            text.AppendLine($"finding {f.SubSection} {f.Verification} {f.Section} {f.Ordinal} {f.Locator} {f.SelectionEncryptionIdentifierHex} {f.Message}");
        }

        foreach (var a in report.Attestations)
        {
            text.AppendLine($"attestation {Convert.ToHexStringLower(a.Device.ToBytes())} {a.Kind} {a.Present} {a.ContentsMatch} {a.Signature} {a.Message}");
        }

        foreach (var s in report.Signatures)
        {
            text.AppendLine($"signature {s}");
        }

        text.AppendLine(string.Join("|", report.SkippedUnknownContent));
        text.AppendLine(report.Statistics.ToString());
        text.AppendLine(string.Join(",", report.BallotsToOpen) + ";" + string.Join(",", report.UncastBallotsToRelease));
        foreach (var i in report.Inclusions)
        {
            text.AppendLine($"inclusion {i.Locator} {i.LeafHash} {i.SectionSize} {string.Join(",", i.SectionPath)} {i.SectionRoot} {i.TocIndex} {i.TocSize} {string.Join(",", i.TocPath)} {i.Root}");
        }

        return text.ToString();
    }

    internal static string Describe(VerificationReport report) =>
        string.Join("\n", report.Findings.Select(x => $"{x.SubSection} [{x.Section}#{x.Ordinal}] {x.Message}"))
        + "\n" + string.Join(", ", report.Verifications.Select(x => $"{x.Key}:{x.Value}"));

    [Theory]
    [InlineData(RecordEncoding.Protobuf)]
    [InlineData(RecordEncoding.Json)]
    public async Task TheRegularTestElection_Passes_EveryVerification(RecordEncoding encoding)
    {
        string directory = TempDirectory("verify-regular");
        await WriteAsync(RegularElection.Value, directory, encoding);
        await using var reader = await ElectionRecord.OpenAsync(directory);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader);
        Assert.True(report.Passed, Describe(report));
        Assert.True(report.Complete);
        Assert.Empty(report.Findings);
        foreach (var v in new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 })
        {
            Assert.True(VerificationOutcome.Passed == report.Verifications[v], $"V{v}: {report.Verifications[v]}\n{Describe(report)}");
        }

        foreach (var v in new[] { 15, 16, 17, 18, 19 })
        {
            Assert.Equal(VerificationOutcome.NotApplicable, report.Verifications[v]);
        }

        Assert.True(report.RootsMatchClaimedToc);
        Assert.Equal(4, report.PhaseRoots.Count);
    }

    [Theory]
    [InlineData(RecordEncoding.Protobuf)]
    [InlineData(RecordEncoding.Json)]
    public async Task ThePreEncryptedTestElection_Passes_EveryVerification(RecordEncoding encoding)
    {
        string directory = TempDirectory("verify-pre");
        await WriteAsync(PreEncryptedRecord.Value, directory, encoding);
        await using var reader = await ElectionRecord.OpenAsync(directory);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader);
        Assert.True(report.Passed, Describe(report));
        foreach (var v in new[] { 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 15, 16, 17, 18, 19 })
        {
            Assert.True(VerificationOutcome.Passed == report.Verifications[v], $"V{v}: {report.Verifications[v]}\n{Describe(report)}");
        }

        Assert.Equal(2, report.Statistics.UncastCompact);
        Assert.Equal(1, report.Statistics.UncastFull);
    }

    /// <summary>
    /// Design §9.2 S10b-10: the four representations of one record (protobuf and JSON, directory and
    /// zip), and a zip given as a stream that cannot seek (spooled, NQ-6), give identical reports.
    /// </summary>
    [Fact]
    public async Task EveryRepresentation_AndANonSeekableZip_GiveTheSameReport()
    {
        string directory = TempDirectory("verify-reps");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var reports = new List<(string Name, VerificationReport Report)>();
        await using (var source = await ElectionRecord.OpenAsync(directory))
        {
            reports.Add(("protobuf directory", await ElectionRecordVerifier.VerifyAllAsync(source)));
        }

        foreach (var (encoding, carrier) in new[] { (RecordEncoding.Json, RecordCarrier.Directory), (RecordEncoding.Protobuf, RecordCarrier.Zip), (RecordEncoding.Json, RecordCarrier.Zip) })
        {
            string destination = carrier == RecordCarrier.Zip ? Path.Combine(TempDirectory("verify-reps-zip"), "record.zip") : TempDirectory("verify-reps-json");
            await using (var source = await ElectionRecord.OpenAsync(directory))
            {
                await ElectionRecord.ConvertAsync(source, destination, encoding, carrier);
            }

            await using (var converted = await ElectionRecord.OpenAsync(destination))
            {
                reports.Add(($"{encoding} {carrier}", await ElectionRecordVerifier.VerifyAllAsync(converted, new VerifyAllOptions { MaxDegreeOfParallelism = 2 })));
            }

            if (carrier == RecordCarrier.Zip)
            {
                await using var stream = await ElectionRecord.OpenAsync(new RecordZipCarrierTests.ForwardOnlyStream(File.OpenRead(destination)), TempDirectory("verify-spool"));
                reports.Add(($"{encoding} zip stream", await ElectionRecordVerifier.VerifyAllAsync(stream)));
            }
        }

        Assert.True(reports[0].Report.Passed, Describe(reports[0].Report));
        foreach (var (name, report) in reports.Skip(1))
        {
            Assert.True(Canonical(reports[0].Report) == Canonical(report), $"{name}:\n{Canonical(report)}\nversus\n{Canonical(reports[0].Report)}");
        }
    }

    /// <summary>
    /// §3.6.1 (design §6.9): the guardians' preliminary verification of an aggregated record runs V1-V9
    /// and the request rules, lists the ballots they will open, and yields the verified aggregate that
    /// tally decryption from a record requires; it decrypts to the published tally. A final record's
    /// aggregated prefix verifies the same way. A root obtained out of band that differs is R.root, and
    /// no aggregate.
    /// </summary>
    [Fact]
    public async Task GuardianPreliminary_OnTheAggregatedRecord_YieldsTheVerifiedAggregate_ThatDecrypts()
    {
        var election = RegularElection.Value;
        string aggregated = TempDirectory("verify-aggregated");
        Sha256Digest aggregatedRoot;
        await using (var writer = ElectionRecord.Create(aggregated, RecordEncoding.Protobuf))
        {
            await writer.WriteSetupAsync(election.Record);
            foreach (var (deviceId, ballots) in election.Devices)
            {
                await using var device = await writer.OpenDeviceAsync(deviceId, DeviceChainBallotKind.Encrypted);
                foreach (var ballot in ballots)
                {
                    await device.AppendAsync(ballot);
                }

                await device.CloseAsync(ClosedAt);
            }

            await writer.SealVotingAsync();
            var requests = election.ContestData.Select(x => new ContestDataRequest(writer.Locate(x.Ballot.SelectionEncryptionIdentifierHash), x.Ballot.SelectionEncryptionIdentifierHash, x.Data.ContestIndex));
            aggregatedRoot = (await writer.SealAggregatedAsync(election.Tally, requests)).Root;
        }

        string final = TempDirectory("verify-final");
        await WriteAsync(election, final, RecordEncoding.Protobuf);
        foreach (var directory in new[] { aggregated, final })
        {
            await using var reader = await ElectionRecord.OpenAsync(directory);
            var (report, aggregate) = await ElectionRecordVerifier.VerifyAggregatedAsync(reader, new VerifyAllOptions { ExpectedAggregatedRoot = aggregatedRoot });
            Assert.True(report.Passed, Describe(report));
            Assert.Equal(VerificationProfile.GuardianPreliminary, report.Profile);
            Assert.Equal(RecordPhase.Aggregated, report.Phase);
            foreach (var v in Enumerable.Range(1, 9))
            {
                Assert.Equal(VerificationOutcome.Passed, report.Verifications[v]);
            }

            // 15 and 16 are in the profile (spec p.64: they stand for 7 and 8 on pre-encrypted
            // ballots); this election has none.
            foreach (var v in new[] { 15, 16 })
            {
                Assert.Equal(VerificationOutcome.NotApplicable, report.Verifications[v]);
            }

            foreach (var v in new[] { 10, 11, 12, 13, 14, 17, 18, 19 })
            {
                Assert.Equal(VerificationOutcome.NotRun, report.Verifications[v]);
            }

            var challenged = Assert.Single(report.BallotsToOpen);
            Assert.Equal(4, challenged.Position);
            Assert.NotNull(aggregate);
            Assert.Equal(aggregatedRoot, aggregate.AggregatedRoot);
            Assert.Equal(aggregatedRoot, report.PhaseRoots[RecordPhase.Aggregated]);

            // The guardians' view of the sealed record holds the cast and the spoiled ballots (Q31,
            // "Refuse spoiled too"), not the challenged one.
            var cast = election.Ballots.First(x => x.Status == BallotStatus.Cast);
            var spoiled = election.Ballots.Single(x => x.Status == BallotStatus.Spoiled);
            Assert.False(aggregate.PublishedBallots.Match(cast.SelectionEncryptionIdentifier, null, null).IsNone);
            Assert.False(aggregate.PublishedBallots.Match(spoiled.SelectionEncryptionIdentifier, null, null).IsNone);
            Assert.True(aggregate.PublishedBallots.Match(election.Challenged.Ballot.SelectionEncryptionIdentifier, null, null).IsNone);

            var decrypted = new TallyAdmin().Decrypt(election.Guardians, aggregate);
            Assert.Equal(
                TallyMapper.ToItems(election.Decrypted).Select(x => Convert.ToHexString(x.DecryptedTallyContest.Fields.Select(f => (long)f.Tally).SelectMany(BitConverter.GetBytes).ToArray())),
                TallyMapper.ToItems(decrypted).Select(x => Convert.ToHexString(x.DecryptedTallyContest.Fields.Select(f => (long)f.Tally).SelectMany(BitConverter.GetBytes).ToArray())));

            var other = Sha256Digest.Of([1]);
            await using var again = await ElectionRecord.OpenAsync(directory);
            var (refused, none) = await ElectionRecordVerifier.VerifyAggregatedAsync(again, new VerifyAllOptions { ExpectedAggregatedRoot = other });
            Assert.False(refused.Passed);
            Assert.Contains(refused.Findings, x => x.SubSection == RecordCodes.Root && x.Message.Contains("obtained out of band"));
            Assert.Null(none);
        }
    }

    public static TheoryData<string, int> ResumeRows()
    {
        // One batch per item: the regular record's device sections hold 6 and 3 items (header,
        // ballots, close), the pre-encrypted record's one section 7. Stopping after the last batch
        // (9 and 7) stops the run in its tally step, after the device pass's last checkpoint.
        var rows = new TheoryData<string, int>();
        foreach (int stop in new[] { 1, 3, 6, 7, 9 })
        {
            rows.Add("regular", stop);
        }

        foreach (int stop in new[] { 1, 3, 6, 7 })
        {
            rows.Add("pre-encrypted", stop);
        }

        // Findings before the stop must survive it: whichever device comes first in canonical order,
        // one of these stops falls after device-1's 6.D and between the two ballots sharing an id_B.
        foreach (int stop in new[] { 3, 6, 9 })
        {
            rows.Add("tampered", stop);
            rows.Add("signed", stop);
        }

        // A device section cut inside its fourth item: the stops fall before the failure is read, on
        // the batch that finds it (the last item read whole) and after it, so a resumed run reports
        // the failure once and counts the broken section once (S10b-E review round 2).
        foreach (int stop in new[] { 2, 3, 4, 5 })
        {
            rows.Add("torn", stop);
        }

        return rows;
    }

    /// <summary>
    /// Design §6.8: a run stopped at any batch (here cancelled from its progress callback, as a kill
    /// would stop it; one item per batch, a checkpoint after each) and run again with the same options
    /// continues from its checkpoint (it verifies only the batches after the stop) and gives exactly
    /// the uninterrupted run's report, whether it stopped mid-section or at a section's end, and with
    /// findings, a 5.A pair split by the stop, or attestation results before it; the checkpoint and
    /// its 5.A runs are then gone. A checkpoint taken under other trust anchors is not resumed.
    /// </summary>
    [Theory]
    [MemberData(nameof(ResumeRows))]
    public async Task ARunStoppedAtABatch_Resumes_AndGivesTheSameReport(string record, int stopAfter)
    {
        string directory = TempDirectory("verify-resume");
        using var signer = EcdsaP256Sha256Signer.Generate();
        IReadOnlyList<ISignatureVerifier> verifiers = [];
        switch (record)
        {
            case "pre-encrypted":
                await WriteAsync(PreEncryptedRecord.Value, directory, RecordEncoding.Protobuf);
                break;
            case "signed":
                await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf, signer: signer);
                verifiers = [new EcdsaP256Sha256Verifier([signer.SubjectPublicKeyInfo])];
                break;
            default:
                await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
                break;
        }

        if (record == "torn")
        {
            // The device with the most items (header, ballots, close), cut inside its item 3.
            DeviceKey largest = default;
            int most = 0;
            await using (var reader = await ElectionRecord.OpenAsync(directory))
            {
                foreach (var key in reader.Devices)
                {
                    int count = (await reader.ReadSectionAsync(SectionKey.Device(key)).ToListAsync()).Count;
                    (largest, most) = count > most ? (key, count) : (largest, most);
                }
            }

            Assert.True(most >= 5, $"{most} items");
            string segment = RecordTamper.PathOf(directory, SectionKey.Device(largest));
            var frames = RecordDirectoryCarrierTests.Frames(File.ReadAllBytes(segment));
            File.WriteAllBytes(segment, [.. RecordDirectoryCarrierTests.Join(frames[..4]), .. frames[4][..^1]]);
        }

        if (record == "tampered")
        {
            var devices = await RecordTamper.DevicesAsync(directory);
            var one = SectionKey.Device(devices["device-1"]);
            byte[] shared = [];
            RecordTamper.Edit(directory, one, items =>
            {
                var field = items[2].EncryptedBallot.Contests[0].Fields[0];
                field.RangeProof = RecordTamper.Flip(field.RangeProof);
                shared = items[1].EncryptedBallot.IdB.ToByteArray();
            });
            RecordTamper.Edit(directory, SectionKey.Device(devices["device-2"]), items => items[1].EncryptedBallot.IdB = ByteString.CopyFrom(shared));
            await RecordTamper.ReTocAsync(directory);
        }

        string checkpoint = Path.Combine(TempDirectory("verify-checkpoint"), "run.checkpoint");
        var options = new VerifyAllOptions { BatchBytes = 1, CheckpointPath = checkpoint, CheckpointInterval = TimeSpan.Zero, UniquenessMemoryBudgetBytes = 8, SignatureVerifiers = verifiers };
        var batchesOf = new List<long>();
        VerificationReport uninterrupted;
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            uninterrupted = await ElectionRecordVerifier.VerifyAllAsync(reader, options with { CheckpointPath = null }, new SynchronousProgress(p =>
            {
                if (p.Step == "ballots")
                {
                    batchesOf.Add(p.ItemsVerified);
                }
            }));
        }

        switch (record)
        {
            case "tampered":
                Assert.False(uninterrupted.Passed);
                Assert.Contains(uninterrupted.Findings, x => x.SubSection == "6.D" && x.Ordinal == 2);
                Assert.Contains(uninterrupted.Findings, x => x.SubSection == "5.A");
                break;
            case "signed":
                Assert.True(uninterrupted.Passed, Describe(uninterrupted));
                Assert.Equal(4, uninterrupted.Attestations.Count(x => x.Signature?.Status == SignatureStatus.Valid));
                break;
            case "torn":
                Assert.False(uninterrupted.Passed);
                Assert.Single(uninterrupted.Findings, x => x.SubSection == RecordCodes.Container);
                Assert.Equal(VerificationOutcome.NotEvaluable, uninterrupted.Verifications[9]);
                break;
            default:
                Assert.True(uninterrupted.Passed, Describe(uninterrupted));
                break;
        }

        await StopAsync(directory, options, stopAfter);
        Assert.True(File.Exists(checkpoint), $"stopped after {stopAfter}: no checkpoint");
        Assert.False(File.Exists(checkpoint + ".tmp"));
        var resumedBatches = new List<long>();
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            var resumed = await ElectionRecordVerifier.VerifyAllAsync(reader, options, new SynchronousProgress(p =>
            {
                if (p.Step == "ballots")
                {
                    resumedBatches.Add(p.ItemsVerified);
                }
            }));
            Assert.Equal(Canonical(uninterrupted), Canonical(resumed));
        }

        // A resume, not a restart: only the batches after the stop, counting on from the stop.
        Assert.Equal(batchesOf.Count - stopAfter, resumedBatches.Count);
        if (resumedBatches.Count > 0)
        {
            Assert.True(resumedBatches[0] >= batchesOf[stopAfter - 1], $"resumed at {resumedBatches[0]} items, stopped at {batchesOf[stopAfter - 1]}");
        }

        Assert.False(File.Exists(checkpoint));
        Assert.False(Directory.Exists(checkpoint + ".5a"));

        if (record == "signed")
        {
            // The same stop, resumed under another trust anchor: the checkpoint's attestation verdicts
            // were reached under the old key, so the run starts over (every batch again).
            await StopAsync(directory, options, stopAfter);
            using var stranger = EcdsaP256Sha256Signer.Generate();
            int again = 0;
            await using var reader = await ElectionRecord.OpenAsync(directory);
            var restarted = await ElectionRecordVerifier.VerifyAllAsync(reader, options with { SignatureVerifiers = [new EcdsaP256Sha256Verifier([stranger.SubjectPublicKeyInfo])] }, new SynchronousProgress(p =>
            {
                if (p.Step == "ballots")
                {
                    again++;
                }
            }));
            Assert.Equal(batchesOf.Count, again);
            Assert.All(restarted.Attestations, x => Assert.Equal(SignatureStatus.NotChecked, x.Signature!.Status));
        }

        static async Task StopAsync(string directory, VerifyAllOptions options, int stopAfter)
        {
            using var stop = new CancellationTokenSource();
            int batches = 0;
            var progress = new SynchronousProgress(p =>
            {
                if (p.Step == "ballots" && ++batches == stopAfter)
                {
                    stop.Cancel();
                }
            });

            await using var reader = await ElectionRecord.OpenAsync(directory);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ElectionRecordVerifier.VerifyAllAsync(reader, options, progress, stop.Token));
        }
    }

    /// <summary>
    /// Design §6.8: a checkpoint that does not apply is not resumed; the run starts over (it verifies
    /// every batch again) and reports what the record now holds. A checkpoint for another record (an
    /// item changed and the TOC rewritten, so the claimed root differs), one whose 5.A
    /// run is gone, and one cut short are each discarded. A record without a claimed TOC is never
    /// checkpointed: nothing would bind the verified prefix to the bytes on disk, so a ballot changed
    /// in that prefix between the stop and the next run is still found.
    /// </summary>
    [Theory]
    [InlineData("an item changed, with its TOC")]
    [InlineData("a 5.A run deleted")]
    [InlineData("the checkpoint cut short")]
    [InlineData("no TOC, a ballot before the stop changed")]
    public async Task ACheckpointThatDoesNotApply_IsNotResumed(string change)
    {
        const int stopAfter = 4;
        string directory = TempDirectory("verify-discard");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        if (change.StartsWith("no TOC"))
        {
            File.Delete(Path.Combine(directory, RecordLayout.TocPath(RecordEncoding.Protobuf)));
        }

        string checkpoint = Path.Combine(TempDirectory("verify-discard-checkpoint"), "run.checkpoint");
        var options = new VerifyAllOptions { BatchBytes = 1, CheckpointPath = checkpoint, CheckpointInterval = TimeSpan.Zero, UniquenessMemoryBudgetBytes = 8 };
        int batches = 0;
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            var clean = await ElectionRecordVerifier.VerifyAllAsync(reader, options with { CheckpointPath = null }, new SynchronousProgress(p => batches += p.Step == "ballots" ? 1 : 0));
            Assert.True(clean.Passed, Describe(clean));
        }

        Assert.True(batches > stopAfter);
        using (var stop = new CancellationTokenSource())
        {
            int seen = 0;
            await using var reader = await ElectionRecord.OpenAsync(directory);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ElectionRecordVerifier.VerifyAllAsync(reader, options, new SynchronousProgress(p =>
            {
                if (p.Step == "ballots" && ++seen == stopAfter)
                {
                    stop.Cancel();
                }
            }), stop.Token));
        }

        // The first device in canonical order: its first ballot (batch 2) is inside the verified prefix.
        SectionKey first;
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            first = SectionKey.Device(reader.Devices[0]);
        }

        bool tampered = false;
        switch (change)
        {
            case "an item changed, with its TOC":
                Assert.True(File.Exists(checkpoint));
                RecordTamper.Edit(directory, first, items => { var f = items[1].EncryptedBallot.Contests[0].Fields[0]; f.RangeProof = RecordTamper.Flip(f.RangeProof); });
                await RecordTamper.ReTocAsync(directory);
                tampered = true;
                break;
            case "a 5.A run deleted":
                Assert.True(File.Exists(checkpoint));
                File.Delete(Directory.EnumerateFiles(checkpoint + ".5a", "*.run").First());
                break;
            case "the checkpoint cut short":
                Assert.True(File.Exists(checkpoint));
                byte[] bytes = File.ReadAllBytes(checkpoint);
                File.WriteAllBytes(checkpoint, bytes[..(bytes.Length / 2)]);
                break;
            default:
                Assert.False(File.Exists(checkpoint), "a record without a TOC was checkpointed");
                Assert.False(Directory.Exists(checkpoint + ".5a"));
                RecordTamper.Edit(directory, first, items => { var f = items[1].EncryptedBallot.Contests[0].Fields[0]; f.RangeProof = RecordTamper.Flip(f.RangeProof); });
                tampered = true;
                break;
        }

        int again = 0;
        VerificationReport rerun;
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            rerun = await ElectionRecordVerifier.VerifyAllAsync(reader, options, new SynchronousProgress(p => again += p.Step == "ballots" ? 1 : 0));
        }

        Assert.Equal(batches, again);
        Assert.Equal(tampered, !rerun.Passed);
        if (tampered)
        {
            Assert.Contains(rerun.Findings, x => x.SubSection == "6.D");
        }
        else
        {
            Assert.True(rerun.Passed, Describe(rerun));
        }

        Assert.False(File.Exists(checkpoint));
        Assert.False(Directory.Exists(checkpoint + ".5a"));
    }

    /// <summary>
    /// Design §6.4, §9.4: the verifier streams. Over 5,000 structure-only ballots (copies of one ballot
    /// under fresh random identifiers; the custom profile runs 5 and the record-level checks, skipping
    /// the cryptography of 6-8), the retained heap does not grow with the ballots, 5.A spills sorted
    /// runs under a small budget (counted on disk) and still finds the one id_B planted twice, naming
    /// both locators, and every section root is checked.
    /// </summary>
    [Fact]
    public async Task FiveThousandStructureOnlyBallots_AreVerifiedWithBoundedMemory_And5AFindsThePlantedDuplicate()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        var deviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "scanner");
        var template = ElectionFixtureBuilder.CreateEncryptedBallot(record, "scanner", deviceHash,
            ElectionFixtureBuilder.CreateBallot(manifest, "template", new Dictionary<string, int> { ["choice-1"] = 1 }, contestData: WriteIn));

        string directory = TempDirectory("verify-five-thousand");
        const int total = 5000;
        SelectionEncryptionIdentifier? planted = null;
        await using (var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf))
        {
            await writer.WriteSetupAsync(record);
            await using var device = await writer.OpenDeviceAsync("scanner", DeviceChainBallotKind.Encrypted);
            for (int i = 1; i <= total; i++)
            {
                // A fresh id_B with its own H_I (so 5.B holds); the contents are the template's. The
                // planted copy repeats ballot 1234's id_B under another H_I (the writer refuses a
                // repeated H_I), so it fails 5.B as well.
                var identifier = i == 4321 ? planted!.Value : new SelectionEncryptionIdentifier(ElectionGuard.Core.Crypto.ElectionGuardRandom.GetBytes(32));
                if (i == 1234)
                {
                    planted = identifier;
                }

                await device.AppendAsync(new EncryptedBallot
                {
                    Id = $"b-{i}", SelectionEncryptionIdentifier = identifier, SelectionEncryptionIdentifierHash = i == 4321 ? SelectionEncryptionIdentifierHash.FromCanonicalBytes(ElectionGuard.Core.Crypto.ElectionGuardRandom.GetBytes(32)) : new SelectionEncryptionIdentifierHash(record.ExtendedBaseHash, identifier),
                    BallotStyleId = template.BallotStyleId, Contests = template.Contests, ConfirmationCode = template.ConfirmationCode, ChainingField = template.ChainingField,
                    EncryptedBallotNonce = template.EncryptedBallotNonce, DeviceId = template.DeviceId, Weight = 1, Status = BallotStatus.Spoiled,
                });
            }

            await device.CloseAsync();
            await writer.SealVotingAsync();
        }

        // The heap is measured at two batch ends (each with one batch of items in flight, the same
        // size), 3,000 ballots apart, so any per-ballot state shows; and 5.A's run files are counted
        // at completion, before the run deletes them.
        long atThousand = 0, atFourThousand = 0;
        int spilled = -1;
        string runs = TempDirectory("verify-five-thousand-runs");
        var progress = new SynchronousProgress(p =>
        {
            if (p.Step == "ballots" && p.ItemsVerified >= 1000 && atThousand == 0)
            {
                atThousand = RetainedBytes();
            }
            else if (p.Step == "ballots" && p.ItemsVerified >= 4000 && atFourThousand == 0)
            {
                atFourThousand = RetainedBytes();
            }
            else if (p.Step == "completion")
            {
                spilled = Directory.EnumerateFiles(runs, "*.run").Count();
            }
        });

        await using var reader = await ElectionRecord.OpenAsync(directory);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions
        {
            Profile = VerificationProfile.Custom,
            Verifications = new HashSet<int> { 5 },
            UniquenessMemoryBudgetBytes = 1024,
            TempDirectory = runs,
        }, progress);

        Assert.True(report.RootsMatchClaimedToc);
        Assert.Equal(total, report.Statistics.BallotItems);
        var duplicate = Assert.Single(report.Findings, x => x.SubSection == "5.A");
        Assert.Equal(4321, duplicate.Ordinal);
        Assert.Contains("position 1234 of device", duplicate.Message);

        // 1,024 bytes hold 128 prefixes: 5,000 ballots spill about 39 sorted runs, all deleted at the end.
        Assert.True(spilled >= total / 128, $"{spilled} runs spilled");
        Assert.Empty(Directory.EnumerateFiles(runs));

        // Far less than any per-ballot structure would take: a link index of the chain (150-250 B per
        // ballot) or 5.A's identifiers held in memory (about 100 B each) would retain 300-750 KB here; measured: about 11 KB.
        Assert.True(atThousand > 0 && atFourThousand > 0);
        Assert.True(atFourThousand - atThousand < 128L << 10, $"The verifier's retained heap grew by {atFourThousand - atThousand:N0} bytes over 3,000 ballots.");
    }

    /// <summary>User decision R-2 ("Pass, flagged incomplete"): a record of a newer format minor that this reader understands in full passes, flagged incomplete with the reason.</summary>
    [Fact]
    public async Task ANewerMinorRecord_Passes_FlaggedIncomplete()
    {
        string directory = TempDirectory("verify-newer");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        RecordTamper.Edit(directory, RecordSectionType.Header, items => items[0].RecordHeader.FormatMinor = 1);
        await RecordTamper.ReTocAsync(directory);
        await using var reader = await ElectionRecord.OpenAsync(directory);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader);
        Assert.True(report.Passed, Describe(report));
        Assert.False(report.Complete);
        Assert.Equal(new RecordFormatVersion(2, 1), report.RecordFormat);
        Assert.Contains(report.SkippedUnknownContent, x => x.Contains("EGRF 2.1"));
    }

    /// <summary>
    /// Design §4.8, §6.2: a cast ballot whose α is out of Z_p is reported once, as 6.A, at its item;
    /// it has no domain object, so its other verifications are not evaluable on it, and Verification 9,
    /// whose recount would miss its factor, is not evaluable (never passed).
    /// </summary>
    [Fact]
    public async Task ACastBallotOutOfRange_Is6A_AndLeavesVerification9NotEvaluable()
    {
        string directory = TempDirectory("verify-range");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var one = SectionKey.Device((await RecordTamper.DevicesAsync(directory))["device-1"]);
        RecordTamper.Edit(directory, one, items => items[1].EncryptedBallot.Contests[0].Fields[0].Alpha = Google.Protobuf.ByteString.CopyFrom(Enumerable.Repeat((byte)0xFF, 512).ToArray()));
        await RecordTamper.ReTocAsync(directory);
        await using var reader = await ElectionRecord.OpenAsync(directory);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader);
        var range = Assert.Single(report.Findings, x => x.SubSection == "6.A");
        Assert.Equal((one, 1L), (range.Section!.Value, range.Ordinal!.Value));
        Assert.Equal(VerificationOutcome.Failed, report.Verifications[6]);
        Assert.Equal(VerificationOutcome.NotEvaluable, report.Verifications[7]);
        Assert.Equal(VerificationOutcome.NotEvaluable, report.Verifications[9]);
    }

    /// <summary>
    /// Design §6.9 BallotCorrectness: chosen ballots get their per-ballot verifications (13/14 for the
    /// challenged one) and RFC 9162 inclusion proofs from their leaf to the claimed root, which verify.
    /// A locator the record does not hold is R.structure.
    /// </summary>
    [Fact]
    public async Task BallotCorrectness_VerifiesTheChosenBallots_WithInclusionProofsToTheRoot()
    {
        string directory = TempDirectory("verify-ballots");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var devices = await RecordTamper.DevicesAsync(directory);
        var chosen = new[] { new BallotLocator(devices["device-1"], 4), new BallotLocator(devices["device-2"], 1) };
        await using var reader = await ElectionRecord.OpenAsync(directory);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { Profile = VerificationProfile.BallotCorrectness, Ballots = chosen });
        Assert.True(report.Passed, Describe(report));
        foreach (var v in new[] { 5, 6, 7, 8, 13, 14 })
        {
            Assert.Equal(VerificationOutcome.Passed, report.Verifications[v]);
        }

        Assert.Equal(VerificationOutcome.NotRun, report.Verifications[9]);
        Assert.Equal(2, report.Statistics.BallotItems);
        Assert.Equal(2, report.Inclusions.Count);
        foreach (var inclusion in report.Inclusions)
        {
            Assert.True(MerkleProofs.VerifyInclusion(inclusion.LeafHash, inclusion.Locator.Position, inclusion.SectionSize, inclusion.SectionRoot, inclusion.SectionPath));
            var entry = reader.ClaimedToc!.Entries[(int)inclusion.TocIndex];
            Assert.Equal(inclusion.SectionRoot, entry.Root);
            Assert.True(MerkleProofs.VerifyInclusion(entry.LeafHash(), inclusion.TocIndex, inclusion.TocSize, inclusion.Root, inclusion.TocPath));
            Assert.Equal(reader.ClaimedToc.Root, inclusion.Root);
        }

        await using var again = await ElectionRecord.OpenAsync(directory);
        var missing = await ElectionRecordVerifier.VerifyAllAsync(again, new VerifyAllOptions { Profile = VerificationProfile.BallotCorrectness, Ballots = [new BallotLocator(devices["device-2"], 7)] });
        Assert.Contains(missing.Findings, x => x.SubSection == RecordCodes.Structure && x.Message.Contains("does not hold"));
    }

    /// <summary>
    /// The record-level codes the verifier reports as findings, with the run going on (design §6.9):
    /// a changed item without its TOC rewritten (R.root), a non-canonical ballot item (R.encoding, still
    /// digested, so the roots still match a TOC written from the bytes), a device segment cut mid-frame
    /// (R.container, the section then has no root), and the full profile on a sealed record (R.structure).
    /// </summary>
    [Theory]
    [InlineData("a ballot changed, the TOC not rewritten", RecordCodes.Root)]
    [InlineData("a ballot item made non-canonical", RecordCodes.Encoding)]
    [InlineData("a device segment cut mid-frame", RecordCodes.Container)]
    [InlineData("the full profile on a sealed record", RecordCodes.Structure)]
    public async Task ARecordLevelFailure_IsAFinding_AndTheRunGoesOn(string tamper, string code)
    {
        string directory = TempDirectory("verify-r");
        var election = RegularElection.Value;
        if (tamper == "the full profile on a sealed record")
        {
            await using var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf);
            await writer.WriteSetupAsync(election.Record);
            foreach (var (deviceId, ballots) in election.Devices)
            {
                await using var device = await writer.OpenDeviceAsync(deviceId, DeviceChainBallotKind.Encrypted);
                foreach (var ballot in ballots)
                {
                    await device.AppendAsync(ballot);
                }

                await device.CloseAsync(ClosedAt);
            }

            await writer.SealVotingAsync();
        }
        else
        {
            await WriteAsync(election, directory, RecordEncoding.Protobuf);
        }

        var two = SectionKey.Device((await RecordTamper.DevicesAsync(directory))["device-2"]);
        string segment = RecordTamper.PathOf(directory, two);
        switch (tamper)
        {
            case "a ballot changed, the TOC not rewritten":
                RecordTamper.Edit(directory, two, items => items[1].EncryptedBallot.Weight = 3);
                break;
            case "a ballot item made non-canonical":
                // The ballot's weight (field 5) written a second time at its end (W3).
                var frames = RecordDirectoryCarrierTests.Frames(File.ReadAllBytes(segment));
                var inner = Pb.RecordItem.Parser.ParseFrom(RecordDirectoryCarrierTests.Payload(frames[2])).EncryptedBallot.ToByteArray();
                byte[] grown = [.. inner, 0x28, 0x01];
                frames[2] = RecordDirectoryCarrierTests.Frame([0x5A, .. EgrfVectors.Varint((ulong)grown.Length), .. grown]);
                File.WriteAllBytes(segment, RecordDirectoryCarrierTests.Join(frames));
                await RecordTamper.ReTocAsync(directory);
                break;
            case "a device segment cut mid-frame":
                File.WriteAllBytes(segment, File.ReadAllBytes(segment)[..^7]);
                break;
        }

        await using var reader = await ElectionRecord.OpenAsync(directory);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader);
        Assert.False(report.Passed);
        Assert.Contains(report.Findings, x => x.SubSection == code);
        Assert.Equal(VerificationOutcome.Passed, report.Verifications[1]);
        if (code == RecordCodes.Encoding)
        {
            var finding = Assert.Single(report.Findings);
            Assert.Equal((two, 1L), (finding.Section!.Value, finding.Ordinal!.Value));
            Assert.True(report.RootsMatchClaimedToc);
            Assert.Equal(VerificationOutcome.NotEvaluable, report.Verifications[9]);
        }

        if (code == RecordCodes.Root)
        {
            Assert.False(report.RootsMatchClaimedToc);
        }
    }

    private static long RetainedBytes()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        return GC.GetTotalMemory(forceFullCollection: true);
    }

    /// <summary>An <see cref="IProgress{T}"/> that reports on the caller's thread, so a test can act at an exact point of a run.</summary>
    internal sealed class SynchronousProgress(Action<VerificationProgress> report) : IProgress<VerificationProgress>
    {
        public void Report(VerificationProgress value) => report(value);
    }
}
