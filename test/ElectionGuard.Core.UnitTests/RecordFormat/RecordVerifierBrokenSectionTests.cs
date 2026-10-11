using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Verify;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordDirectoryCarrierTests;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// A device section that cannot be read whole (S10b-E review): a verification is never Passed over an
/// item it did not see (design §6.9), its failure is reported once (each finding once, §6.9), the last
/// item read whole is still verified, and the join items of the ballots it hides are not strays.
/// And <see cref="ElectionRecord.FindBallotsAsync"/> over every ballot kind.
/// </summary>
public class RecordVerifierBrokenSectionTests
{
    [Fact]
    public async Task ATornDeviceClose_LeavesEveryVerificationItFeedsNotEvaluable_AndIsReportedOnce()
    {
        await EgrfGoldenRecords.EnsureAsync();

        // golden/regular-unchained with its device close cut 2 bytes short: three ballots (cast,
        // spoiled, cast), the last read whole before the torn close.
        await using var reader = await ElectionRecord.OpenAsync(EgrfGoldenRecords.FullPath("negative/container-torn-tail"));
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { MaxDegreeOfParallelism = 1 });

        Assert.False(report.Passed);
        var container = Assert.Single(report.Findings, x => x.SubSection == RecordCodes.Container);
        Assert.Equal(RecordSectionType.Device, container.Section!.Value.Type);

        // The last ballot before the torn close is verified (it was read whole), not dropped.
        Assert.Equal(3, report.Statistics.BallotItems);
        Assert.Equal(2, report.Statistics.Cast);

        // 13 and 14 too: the record is final and holds no challenged ballot the run saw, so an unread
        // challenged ballot's missing decryption could not be seen (no join item names one here, so
        // only BrokenDevice's own rule can make them not evaluable).
        foreach (int v in new[] { 5, 6, 7, 8, 9, 11, 13, 14 })
        {
            Assert.True(report.Verifications[v] == VerificationOutcome.NotEvaluable, $"Verification {v} is {report.Verifications[v]}");
        }

        // Verification 10 reads only the tally sections.
        Assert.Equal(VerificationOutcome.Passed, report.Verifications[10]);
        Assert.DoesNotContain(report.Findings, x => x.SubSection == RecordCodes.Summary);
    }

    [Fact]
    public async Task ADeviceSectionBrokenBeforeAChallengedBallot_LeavesItsJoinsNotEvaluable_NotStrays()
    {
        await EgrfGoldenRecords.EnsureAsync();
        string directory = Path.Combine(Path.GetTempPath(), "egrf-broken-" + Guid.NewGuid().ToString("N"));
        CopyDirectory(EgrfGoldenRecords.FullPath("golden/regular-chained/protobuf"), directory);
        try
        {
            // The challenged ballot's locator, from its decryption.
            BallotLocator challenged;
            await using (var golden = await ElectionRecord.OpenAsync(directory))
            {
                var item = (await golden.ReadSectionAsync(SectionKey.Of(RecordSectionType.ChallengedBallotDecryptions)).ToListAsync())[0];
                challenged = DeviceMapper.FromItem(Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span).ChallengedBallotDecryption.Ballot);
            }

            // Cut the device's segment inside the frame of the item before the challenged ballot (frame 0
            // is the segment header, so item j is frame j + 1).
            string segment = Path.Combine(directory, Path.Combine(RecordLayout.SegmentPath(SectionKey.Device(challenged.Device), 0, RecordEncoding.Protobuf).Split('/')));
            var frames = Frames(File.ReadAllBytes(segment));
            int cut = (int)challenged.Position;
            File.WriteAllBytes(segment, [.. Join(frames[..cut]), .. frames[cut][..^1]]);

            await using var reader = await ElectionRecord.OpenAsync(directory);
            var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { MaxDegreeOfParallelism = 1 });

            Assert.Single(report.Findings, x => x.SubSection == RecordCodes.Container);
            Assert.DoesNotContain(report.Findings, x => x.SubSection is "12.structure" or "13.structure" or "14.structure");
            foreach (int v in new[] { 5, 6, 7, 8, 9, 11, 13, 14 })
            {
                Assert.True(report.Verifications[v] == VerificationOutcome.NotEvaluable, $"Verification {v} is {report.Verifications[v]}");
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// A pre-encrypting device section cut inside its first uncast ballot's frame: every verification
    /// the unread items feed is not evaluable, the chain's (16) and the pre-encrypted ones (15, 17, 18,
    /// 19) included, and the releases naming the unread uncast ballots are not strays (S10b-E review
    /// round 2: the pre-encrypting branch of the broken-section rule had no test).
    /// </summary>
    [Fact]
    public async Task APreEncryptingDeviceSectionBrokenAtAnUncastBallot_LeavesV15ToV19NotEvaluable_AndItsReleasesAreNotStrays()
    {
        await EgrfGoldenRecords.EnsureAsync();
        string directory = Path.Combine(Path.GetTempPath(), "egrf-broken-pre-" + Guid.NewGuid().ToString("N"));
        CopyDirectory(EgrfGoldenRecords.FullPath("golden/pre-encrypted/protobuf"), directory);
        try
        {
            DeviceKey device;
            long uncast;
            int releases;
            await using (var golden = await ElectionRecord.OpenAsync(directory))
            {
                device = Assert.Single(golden.Devices);
                var items = await golden.ReadSectionAsync(SectionKey.Device(device)).ToListAsync();
                uncast = items.First(x => Pb.RecordItem.Parser.ParseFrom(x.Bytes.Span).ItemCase is Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot or Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot).Ordinal;
                releases = (await golden.ReadSectionAsync(SectionKey.Of(RecordSectionType.UncastNonceReleases)).ToListAsync()).Count;
            }

            Assert.True(releases > 0);
            string segment = Path.Combine(directory, Path.Combine(RecordLayout.SegmentPath(SectionKey.Device(device), 0, RecordEncoding.Protobuf).Split('/')));
            var frames = Frames(File.ReadAllBytes(segment));
            int cut = (int)uncast + 1;  // frame 0 is the segment header
            File.WriteAllBytes(segment, [.. Join(frames[..cut]), .. frames[cut][..^1]]);

            await using var reader = await ElectionRecord.OpenAsync(directory);
            var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { MaxDegreeOfParallelism = 1 });

            Assert.False(report.Passed);
            var container = Assert.Single(report.Findings, x => x.SubSection == RecordCodes.Container);
            Assert.Equal(SectionKey.Device(device), container.Section);
            Assert.DoesNotContain(report.Findings, x => x.SubSection is "16.structure" or "18.structure");
            foreach (int v in new[] { 5, 6, 7, 9, 11, 15, 16, 17, 18, 19 })
            {
                Assert.True(report.Verifications[v] == VerificationOutcome.NotEvaluable, $"Verification {v} is {report.Verifications[v]}");
            }

            Assert.Equal(VerificationOutcome.Passed, report.Verifications[10]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// A join item naming a position of a device that was read is a stray whether or not that device's
    /// section breaks later, and whenever the cursor reports it: the position was read, so it does not
    /// wait on the failure. Position 0, the header's ordinal and never a ballot, is the cursor's stray
    /// (<c>Position &gt; 0</c> in the rule); a cast ballot read whole before the break takes its joins
    /// itself, and is judged on its status. Before S10b-E review round 2 the stray at position 0 was
    /// suppressed when the failure had been read before the batch holding position 1 was processed,
    /// which depended on the batch size and the parallelism; now one item per batch and the default
    /// batching give the same report. The rule's other half (<c>Position &gt; lastWhole</c>) is pinned
    /// by <see cref="AJoinItemNamingTheCloseOfADeviceBrokenAfterIt_IsAStray_AtAnyBatching"/>.
    /// </summary>
    [Fact]
    public async Task AJoinItemNamingAPositionReadOfABrokenDevice_IsAStray_AtAnyBatching()
    {
        await EgrfGoldenRecords.EnsureAsync();
        string directory = Path.Combine(Path.GetTempPath(), "egrf-broken-stray-" + Guid.NewGuid().ToString("N"));
        CopyDirectory(EgrfGoldenRecords.FullPath("golden/regular-chained/protobuf"), directory);
        try
        {
            // The device with the most items, so that at least two ballots are read whole before the
            // break and, with one item per batch, position 1 is processed before the break is read.
            DeviceKey device;
            long castPosition;
            await using (var golden = await ElectionRecord.OpenAsync(directory))
            {
                var counts = new Dictionary<DeviceKey, int>();
                foreach (var key in golden.Devices)
                {
                    counts[key] = (await golden.ReadSectionAsync(SectionKey.Device(key)).ToListAsync()).Count;
                }

                device = counts.MaxBy(x => x.Value).Key;
                Assert.True(counts[device] >= 5, $"{counts[device]} items");

                // A cast ballot among the two read whole before the break below (positions 1 and 2).
                var items = (await golden.ReadSectionAsync(SectionKey.Device(device)).ToListAsync()).Take(3).ToList();
                castPosition = items.Skip(1).First(x => Pb.RecordItem.Parser.ParseFrom(x.Bytes.Span).EncryptedBallot.Status == Pb.BallotStatus.Cast).Ordinal;
            }

            // Challenged-ballot decryptions naming (device, 0) and the cast ballot, in locator order.
            RecordTamper.Edit(directory, RecordSectionType.ChallengedBallotDecryptions, items =>
            {
                foreach (long position in new[] { 0L, castPosition })
                {
                    var stray = items[0].Clone();
                    stray.ChallengedBallotDecryption.Ballot = DeviceMapper.ToItem(new BallotLocator(device, 1));
                    stray.ChallengedBallotDecryption.Ballot.Position = (ulong)position;
                    items.Add(stray);
                }

                items.Sort((a, b) => DeviceMapper.FromItem(a.ChallengedBallotDecryption.Ballot).CompareTo(DeviceMapper.FromItem(b.ChallengedBallotDecryption.Ballot)));
            });
            await RecordTamper.ReTocAsync(directory);

            // Then cut the device's segment inside the frame of its third ballot (frame 0 is the
            // segment header, frame 1 the device header).
            string segment = Path.Combine(directory, Path.Combine(RecordLayout.SegmentPath(SectionKey.Device(device), 0, RecordEncoding.Protobuf).Split('/')));
            var frames = Frames(File.ReadAllBytes(segment));
            File.WriteAllBytes(segment, [.. Join(frames[..4]), .. frames[4][..^1]]);

            async Task<VerificationReport> RunAsync(long batchBytes)
            {
                await using var reader = await ElectionRecord.OpenAsync(directory);
                return await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { MaxDegreeOfParallelism = 1, BatchBytes = batchBytes });
            }

            var oneItemPerBatch = await RunAsync(1);
            var defaultBatches = await RunAsync(new VerifyAllOptions().BatchBytes);
            Assert.Equal(ElectionRecordVerifierTests.Canonical(oneItemPerBatch), ElectionRecordVerifierTests.Canonical(defaultBatches));
            var strays = oneItemPerBatch.Findings.Where(x => x.SubSection == "13.structure").Select(x => x.Locator).OrderBy(x => x!.Value.Position).ToList();
            Assert.Equal([new BallotLocator(device, 0), new BallotLocator(device, castPosition)], strays);
            Assert.Single(oneItemPerBatch.Findings, x => x.SubSection == RecordCodes.Container);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// The other half of the stray rule (S10b-E review round 3): a device section read whole up to its
    /// close and then broken (a torn frame after the close) has its close as the last item read whole,
    /// so a join item naming the close's position names a position that was read and is no ballot: a
    /// stray (13.structure), never suppressed as an unread ballot, at any batching. Positions 1 to the
    /// last item read whole are ballots, which take their own joins, so the close is the one position
    /// after 0 where <c>Position &gt; lastWhole</c> decides; without it the stray is lost.
    /// </summary>
    [Fact]
    public async Task AJoinItemNamingTheCloseOfADeviceBrokenAfterIt_IsAStray_AtAnyBatching()
    {
        await EgrfGoldenRecords.EnsureAsync();
        string directory = Path.Combine(Path.GetTempPath(), "egrf-broken-close-" + Guid.NewGuid().ToString("N"));
        CopyDirectory(EgrfGoldenRecords.FullPath("golden/regular-chained/protobuf"), directory);
        try
        {
            DeviceKey device;
            long closeOrdinal;
            await using (var golden = await ElectionRecord.OpenAsync(directory))
            {
                device = golden.Devices[0];
                closeOrdinal = (await golden.ReadSectionAsync(SectionKey.Device(device)).ToListAsync()).Count - 1;
            }

            RecordTamper.Edit(directory, RecordSectionType.ChallengedBallotDecryptions, items =>
            {
                var stray = items[0].Clone();
                stray.ChallengedBallotDecryption.Ballot = DeviceMapper.ToItem(new BallotLocator(device, closeOrdinal));
                items.Add(stray);
                items.Sort((a, b) => DeviceMapper.FromItem(a.ChallengedBallotDecryption.Ballot).CompareTo(DeviceMapper.FromItem(b.ChallengedBallotDecryption.Ballot)));
            });
            await RecordTamper.ReTocAsync(directory);

            // A frame of 5 bytes with only 1 present after the close: a torn tail.
            string segment = Path.Combine(directory, Path.Combine(RecordLayout.SegmentPath(SectionKey.Device(device), 0, RecordEncoding.Protobuf).Split('/')));
            File.WriteAllBytes(segment, [.. File.ReadAllBytes(segment), 0x05, 0x0A]);

            async Task<VerificationReport> RunAsync(long batchBytes)
            {
                await using var reader = await ElectionRecord.OpenAsync(directory);
                return await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { MaxDegreeOfParallelism = 1, BatchBytes = batchBytes });
            }

            var oneItemPerBatch = await RunAsync(1);
            var defaultBatches = await RunAsync(new VerifyAllOptions().BatchBytes);
            Assert.Equal(ElectionRecordVerifierTests.Canonical(oneItemPerBatch), ElectionRecordVerifierTests.Canonical(defaultBatches));
            var container = Assert.Single(oneItemPerBatch.Findings, x => x.SubSection == RecordCodes.Container);
            Assert.Equal(SectionKey.Device(device), container.Section);
            var stray = Assert.Single(oneItemPerBatch.Findings, x => x.SubSection == "13.structure");
            Assert.Equal(new BallotLocator(device, closeOrdinal), stray.Locator);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task FindBallotsAsync_FindsEveryBallotKind_ByItsConfirmationCode()
    {
        await EgrfGoldenRecords.EnsureAsync();
        await using var reader = await ElectionRecord.OpenAsync(EgrfGoldenRecords.FullPath("golden/pre-encrypted/protobuf"));
        var device = Assert.Single(reader.Devices);
        var byKind = new Dictionary<Pb.RecordItem.ItemOneofCase, List<(long Ordinal, byte[] Code)>>();
        await foreach (var item in reader.ReadSectionAsync(SectionKey.Device(device)))
        {
            var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
            var code = parsed.ItemCase switch
            {
                Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot => parsed.PreEncryptedCastBallot.ConfirmationCode,
                Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot => parsed.PreEncryptedUncastBallot.ConfirmationCode,
                Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot => parsed.PreEncryptedCompactUncastBallot.ConfirmationCode,
                _ => null,
            };

            if (code is not null)
            {
                (byKind.TryGetValue(parsed.ItemCase, out var list) ? list : byKind[parsed.ItemCase] = []).Add((item.Ordinal, code.ToByteArray()));
            }
        }

        Assert.Equal(3, byKind.Count);
        foreach (var (kind, ballots) in byKind)
        {
            foreach (var (ordinal, code) in ballots)
            {
                var found = await ElectionRecord.FindBallotsAsync(reader, ConfirmationCode.FromCanonicalBytes(code)).ToListAsync();
                Assert.True(found.SequenceEqual([new BallotLocator(device, ordinal)]), $"{kind} at {ordinal}: found {string.Join(", ", found)}");
            }
        }

        Assert.Empty(await ElectionRecord.FindBallotsAsync(reader, ConfirmationCode.FromCanonicalBytes(new byte[32])).ToListAsync());

        // A regular ballot too.
        await using var regular = await ElectionRecord.OpenAsync(EgrfGoldenRecords.FullPath("golden/regular-unchained/protobuf"));
        var regularDevice = Assert.Single(regular.Devices);
        var first = (await regular.ReadSectionAsync(SectionKey.Device(regularDevice)).ToListAsync())[1];
        var regularCode = Pb.RecordItem.Parser.ParseFrom(first.Bytes.Span).EncryptedBallot.ConfirmationCode.ToByteArray();
        Assert.Equal([new BallotLocator(regularDevice, 1)], await ElectionRecord.FindBallotsAsync(regular, ConfirmationCode.FromCanonicalBytes(regularCode)).ToListAsync());
    }

    [Fact]
    public async Task FindBallotsAsync_SkipsANonCanonicalItem()
    {
        await EgrfGoldenRecords.EnsureAsync();
        string directory = Path.Combine(Path.GetTempPath(), "egrf-find-" + Guid.NewGuid().ToString("N"));
        CopyDirectory(EgrfGoldenRecords.FullPath("golden/regular-unchained/protobuf"), directory);
        try
        {
            string segment = Directory.GetFiles(Path.Combine(directory, "devices"), "00000000.binpb", SearchOption.AllDirectories).Single();
            var frames = Frames(File.ReadAllBytes(segment));
            var payload = Payload(frames[2]);  // frame 0 is the segment header, 1 the device header
            var code = Pb.RecordItem.Parser.ParseFrom(payload).EncryptedBallot.ConfirmationCode.ToByteArray();

            // The same item with its member's length written in a two-byte varint (W4): it parses to the
            // same ballot, but is not canonical.
            int lengthAt = payload[0] < 0x80 ? 1 : 2;
            int at = lengthAt;
            ulong length = 0;
            int shift = 0;
            byte b;
            do
            {
                b = payload[at++];
                length |= (ulong)(b & 0x7F) << shift;
                shift += 7;
            }
            while ((b & 0x80) != 0);

            byte[] padded = [.. payload[..lengthAt], .. PaddedVarint(length, at - lengthAt + 1), .. payload[at..]];
            Assert.Equal(code, Pb.RecordItem.Parser.ParseFrom(padded).EncryptedBallot.ConfirmationCode.ToByteArray());
            frames[2] = Frame(padded);
            File.WriteAllBytes(segment, Join(frames));

            await using var reader = await ElectionRecord.OpenAsync(directory);
            Assert.Empty(await ElectionRecord.FindBallotsAsync(reader, ConfirmationCode.FromCanonicalBytes(code)).ToListAsync());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }

        static byte[] PaddedVarint(ulong value, int width)
        {
            var bytes = new byte[width];
            for (int i = 0; i < width; i++)
            {
                bytes[i] = (byte)((value >> (7 * i)) & 0x7F);
                if (i < width - 1)
                {
                    bytes[i] |= 0x80;
                }
            }

            return bytes;
        }
    }

    /// <summary>
    /// A setup, tally or decrypted-tally section whose segment is cut inside its last item (S10b-E
    /// review round 3): its failure is reported once, at the section; no count or presence finding is
    /// inferred from the part read (it is not R.structure: the section holds an item the reader could
    /// not read); and the verifications that read it are not evaluable, never judged over that part
    /// (design §6.9). Before, a torn guardians section failed 2.A and 3.A ("found 2"), a torn decrypted
    /// tally passed 10 and failed 11.D, and a torn singleton section added a false R.structure (the
    /// manifest's failure twice).
    /// </summary>
    [Theory]
    [InlineData(RecordSectionType.Parameters, new[] { 1, 2, 3, 4, 5, 9, 10, 11 })]
    [InlineData(RecordSectionType.Manifest, new[] { 1, 2, 3, 4, 5, 9, 10, 11 })]
    [InlineData(RecordSectionType.Guardians, new[] { 1, 2, 3, 4, 5, 9, 10, 11 })]
    [InlineData(RecordSectionType.ElectionKeys, new[] { 1, 2, 3, 4, 5, 9, 10, 11 })]
    [InlineData(RecordSectionType.EncryptedTally, new[] { 9, 10 })]
    [InlineData(RecordSectionType.DecryptedTally, new[] { 10, 11 })]
    public async Task ASetupOrTallySectionCutShort_IsReportedOnce_AndLeavesItsReadersNotEvaluable(RecordSectionType type, int[] notEvaluable)
    {
        await EgrfGoldenRecords.EnsureAsync();
        string directory = Path.Combine(Path.GetTempPath(), "egrf-broken-" + type + "-" + Guid.NewGuid().ToString("N"));
        CopyDirectory(EgrfGoldenRecords.FullPath("golden/regular-unchained/protobuf"), directory);
        try
        {
            var section = SectionKey.Of(type);
            string segment = Path.Combine(directory, Path.Combine(RecordLayout.SegmentPath(section, 0, RecordEncoding.Protobuf).Split('/')));
            var frames = Frames(File.ReadAllBytes(segment));
            File.WriteAllBytes(segment, [.. Join(frames[..^1]), .. frames[^1][..^1]]);

            await using var reader = await ElectionRecord.OpenAsync(directory);
            var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { MaxDegreeOfParallelism = 1 });

            Assert.False(report.Passed);
            var container = Assert.Single(report.Findings, x => x.SubSection == RecordCodes.Container);
            Assert.Equal(section, container.Section);
            Assert.Null(container.Ordinal);
            Assert.DoesNotContain(report.Findings, x => x.SubSection == RecordCodes.Structure);
            Assert.DoesNotContain(report.Findings, x => !x.SubSection.StartsWith("R.", StringComparison.Ordinal));
            foreach (int v in notEvaluable)
            {
                Assert.True(report.Verifications[v] == VerificationOutcome.NotEvaluable, $"Verification {v} is {report.Verifications[v]}");
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// A device header that is not canonical (an undeclared DeviceKind, D2) leaves the device's
    /// chain-close attestation not evaluable: what it binds (S_device, the chaining mode, the codes in
    /// chain order) was not read, so its contents are not reported as differing, and its result says it
    /// could not be compared in full (S10b-E review round 3). The section seal binds only the section
    /// root, read whole, so it is still compared (and differs here, since the header's bytes changed).
    /// </summary>
    [Fact]
    public async Task ADeviceHeaderNotCanonical_LeavesTheChainCloseAttestationNotEvaluable_NotMismatched()
    {
        await EgrfGoldenRecords.EnsureAsync();
        string directory = Path.Combine(Path.GetTempPath(), "egrf-broken-header-" + Guid.NewGuid().ToString("N"));
        CopyDirectory(EgrfGoldenRecords.FullPath("golden/regular-chained/protobuf"), directory);
        try
        {
            DeviceKey device;
            await using (var golden = await ElectionRecord.OpenAsync(directory))
            {
                var report = await ElectionRecordVerifier.VerifyAllAsync(golden, new VerifyAllOptions { MaxDegreeOfParallelism = 1 });
                device = report.Attestations.First(x => x.Kind == AttestationKind.ChainClose && x.Present && x.ContentsMatch).Device;
            }

            RecordTamper.Edit(directory, SectionKey.Device(device), items => items[0].DeviceHeader.Kind = (Pb.DeviceKind)7);
            await RecordTamper.ReTocAsync(directory);

            await using var reader = await ElectionRecord.OpenAsync(directory);
            var tampered = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { MaxDegreeOfParallelism = 1 });
            Assert.Contains(tampered.Findings, x => x.SubSection == RecordCodes.Encoding && x.Section == SectionKey.Device(device) && x.Ordinal == 0);
            var chainClose = Assert.Single(tampered.Attestations, x => x.Device == device && x.Kind == AttestationKind.ChainClose);
            Assert.False(chainClose.ContentsMatch);
            Assert.Contains("could not be compared in full", chainClose.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(tampered.Findings, x => x.SubSection == RecordCodes.Attestation && x.Message.Contains("ChainClose", StringComparison.Ordinal));
            Assert.Contains(tampered.Findings, x => x.SubSection == RecordCodes.Attestation && x.Message.Contains("SectionSeal", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// A header section's segment header line whose magic holds a byte that is not well-formed UTF-8:
    /// the open refuses the record as R.container (D6), never with an InvalidOperationException out of
    /// the format-major peek, which read the line with System.Text.Json and transcoded the string
    /// (found by the seeded mutation test, S10b-E review round 3).
    /// </summary>
    [Fact]
    public async Task AHeaderLineWithAnInvalidUtf8Magic_IsRContainerAtOpen_NeverAnException()
    {
        await EgrfGoldenRecords.EnsureAsync();
        string directory = Path.Combine(Path.GetTempPath(), "egrf-bad-magic-" + Guid.NewGuid().ToString("N"));
        CopyDirectory(EgrfGoldenRecords.FullPath("golden/regular-unchained/json"), directory);
        try
        {
            string header = Path.Combine(directory, "setup", "header.jsonl");
            byte[] bytes = File.ReadAllBytes(header);
            int at = bytes.AsSpan().IndexOf("\"EGRF\""u8);
            Assert.True(at >= 0);
            bytes[at + 2] = 0x9D;
            File.WriteAllBytes(header, bytes);

            var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () => await ElectionRecord.OpenAsync(directory));
            Assert.Equal(RecordCodes.Container, failure.SubSection);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static void CopyDirectory(string from, string to)
    {
        foreach (string file in Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(to, Path.GetRelativePath(from, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }
    }
}
