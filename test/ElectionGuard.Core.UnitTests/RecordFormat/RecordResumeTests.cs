using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using Google.Protobuf;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordCarrierElections;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordDirectoryCarrierTests;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-6: <see cref="ElectionRecordWriter.ResumeAsync"/> (design §5.2). A writer stopped mid-voting
/// with a torn tail (cut short, or zero-filled) resumes from its last complete ballot and finishes
/// the record with the roots of an uninterrupted run; one stopped after the aggregate is sealed
/// discards the unsealed final files and finishes the same way; a corrupt middle item, or a
/// zero-length frame followed by data, is refused rather than repaired.
/// </summary>
public class RecordResumeTests
{
    public RecordResumeTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static async Task<TableOfContents> Uninterrupted(RecordEncoding encoding)
    {
        var tocs = await WriteAsync(RegularElection.Value, TempDirectory("uninterrupted"), encoding);
        return tocs[RecordPhase.Final];
    }

    /// <summary>Writes the setup and the first two ballots of device-1, then stops without closing anything (a crash).</summary>
    private static async Task<(string Directory, string Segment)> StoppedMidVoting(RecordEncoding encoding, ElectionRecordWriterOptions? options = null)
    {
        var election = RegularElection.Value;
        string directory = TempDirectory("stopped");
        var writer = ElectionRecord.Create(directory, encoding, options);
        await writer.WriteSetupAsync(election.Record);
        var device = await writer.OpenDeviceAsync("device-1", DeviceChainBallotKind.Encrypted);
        await device.AppendAsync(election.Devices[0].Ballots[0]);
        await device.AppendAsync(election.Devices[0].Ballots[1]);
        await device.FlushAsync(durable: true);
        await writer.DisposeAsync();
        string segment = System.IO.Directory.GetFiles(Path.Combine(directory, "devices"), "*.*", SearchOption.AllDirectories).Order(StringComparer.Ordinal).Last();
        return (directory, segment);
    }

    private static readonly ElectionRecordWriterOptions EveryItemItsOwnSegment = new() { SegmentSizeBytes = 1 };

    public static TheoryData<RecordEncoding, string> RolloverCrashes() => new()
    {
        { RecordEncoding.Protobuf, "the new segment empty" },
        { RecordEncoding.Protobuf, "the new segment's header frame cut short" },
        { RecordEncoding.Protobuf, "the new segment zero-filled" },
        { RecordEncoding.Protobuf, "the new segment's header frame part written, then zero-filled" },
        { RecordEncoding.Protobuf, "the new segment holding its header only" },
        { RecordEncoding.Json, "the new segment empty" },
        { RecordEncoding.Json, "the new segment's header line cut short" },
        { RecordEncoding.Json, "the new segment zero-filled" },
        { RecordEncoding.Json, "the new segment holding its header only" },
    };

    /// <summary>
    /// A crash just after a segment rollover: the writer had created device-1's next segment but its
    /// header was not complete (or, last row, nothing followed it). Resuming continues the previous
    /// segment (the empty or torn one is removed, and the next append rolls over again and writes the
    /// header) or the header-only one, and the record finishes with the uninterrupted run's TOC.
    /// </summary>
    [Theory]
    [MemberData(nameof(RolloverCrashes))]
    public async Task WriterStoppedAtASegmentRollover_Resumes_AndGivesTheUninterruptedRoots(RecordEncoding encoding, string crash)
    {
        // Each item in its own segment: 00000000 holds the device header, 00000001 and 00000002 the two ballots.
        var (directory, segment) = await StoppedMidVoting(encoding, EveryItemItsOwnSegment);
        Assert.EndsWith("00000002" + Path.GetExtension(segment), segment);
        byte[] previous = File.ReadAllBytes(segment);
        byte[] header = SegmentHeaderBytes(previous, encoding, firstOrdinal: 3);
        string next = Path.Combine(Path.GetDirectoryName(segment)!, "00000003" + Path.GetExtension(segment));
        File.WriteAllBytes(next, crash switch
        {
            "the new segment empty" => [],
            "the new segment's header frame cut short" or "the new segment's header line cut short" => header[..(header.Length / 2)],
            "the new segment zero-filled" => new byte[4096],

            // The header's length and its first bytes, the rest of it and beyond zero-filled.
            "the new segment's header frame part written, then zero-filled" => [.. header[..(header.Length / 2)], .. new byte[4096]],
            _ => header,
        });

        var writer = await ElectionRecord.ResumeAsync(directory, EveryItemItsOwnSegment);
        Assert.Equal(previous.Length, new FileInfo(segment).Length);
        var final = await Finish(writer, deviceOneFrom: 2);

        Assert.Equal((await Uninterrupted(encoding)).Entries, final.Entries);
        await using var reader = await ElectionRecord.OpenAsync(directory);
        Assert.Equal(final.Entries, (await ElectionRecord.CheckClaimedTocAsync(reader)).Entries);
        Assert.Contains("00000005" + Path.GetExtension(segment), System.IO.Directory.GetFiles(Path.GetDirectoryName(segment)!).Select(Path.GetFileName)); // header, 4 ballots, close
    }

    /// <summary>Only the newest segment can lack its header; an empty segment before it is corruption, not a torn tail.</summary>
    [Fact]
    public async Task AnEmptySegmentBeforeTheLast_IsRefused()
    {
        var (directory, segment) = await StoppedMidVoting(RecordEncoding.Protobuf, EveryItemItsOwnSegment);
        string device = Path.GetDirectoryName(segment)!;
        File.Move(segment, Path.Combine(device, "00000003.binpb"));
        File.WriteAllBytes(segment, []);
        var failure = await Assert.ThrowsAsync<InvalidDataException>(() => ElectionRecord.ResumeAsync(directory, EveryItemItsOwnSegment).AsTask());
        Assert.Contains("has no segment header", failure.Message);
    }

    /// <summary>The bytes (with the frame length, or the line feed) of the segment header of <paramref name="segment"/>, with another first ordinal.</summary>
    private static byte[] SegmentHeaderBytes(byte[] segment, RecordEncoding encoding, ulong firstOrdinal)
    {
        if (encoding == RecordEncoding.Protobuf)
        {
            var header = Pb.SegmentHeader.Parser.ParseFrom(Payload(Frames(segment)[0]));
            header.FirstOrdinal = firstOrdinal;
            return Frame(header.ToByteArray());
        }

        int newline = Array.IndexOf(segment, (byte)'\n');
        var parsed = Pb.SegmentHeader.Parser.ParseFrom(RecordJson.ParseSegmentHeader(segment[..newline], 0));
        parsed.FirstOrdinal = firstOrdinal;
        return [.. RecordJson.FormatSegmentHeader(parsed), (byte)'\n'];
    }

    private static async Task<TableOfContents> Finish(ElectionRecordWriter writer, int deviceOneFrom)
    {
        var election = RegularElection.Value;
        await using (writer)
        {
            await using (var device = await writer.OpenDeviceAsync("device-1", DeviceChainBallotKind.Encrypted))
            {
                Assert.Equal(deviceOneFrom, device.Count);
                Assert.Equal(election.Devices[0].Ballots[deviceOneFrom - 1].ConfirmationCode, device.LastConfirmationCode);
                foreach (var ballot in election.Devices[0].Ballots.Skip(deviceOneFrom))
                {
                    await device.AppendAsync(ballot);
                }

                await device.CloseAsync(ClosedAt);
            }

            await using (var device = await writer.OpenDeviceAsync("device-2", DeviceChainBallotKind.Encrypted))
            {
                await device.AppendAsync(election.Devices[1].Ballots[0]);
                await device.CloseAsync(ClosedAt);
            }

            await writer.SealVotingAsync();
            await writer.SealAggregatedAsync(election.Tally, election.ContestData.Select(x => new ContestDataRequest(writer.Locate(x.Ballot.SelectionEncryptionIdentifierHash), x.Ballot.SelectionEncryptionIdentifierHash, x.Data.ContestIndex)));
            foreach (var (ballot, data) in election.ContestData)
            {
                await writer.AddContestDataDecryptionAsync(ballot, data);
            }

            await writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted);
            return await writer.CompleteAsync(election.Decrypted);
        }
    }

    public static TheoryData<RecordEncoding, string> TornTails() => new()
    {
        { RecordEncoding.Protobuf, "the third ballot's frame cut short" },
        { RecordEncoding.Protobuf, "a length varint cut short" },
        { RecordEncoding.Protobuf, "zero bytes" },
        { RecordEncoding.Protobuf, "a length varint cut short, then zero bytes" },
        { RecordEncoding.Protobuf, "a whole length, then zero bytes" },
        { RecordEncoding.Protobuf, "a whole length and part of the frame, then zero bytes past its end" },
        { RecordEncoding.Protobuf, "a whole length and part of the frame, then zero bytes to its end" },
        { RecordEncoding.Protobuf, "none" },
        { RecordEncoding.Json, "the third ballot's line cut short" },
        { RecordEncoding.Json, "zero bytes" },
    };

    [Theory]
    [MemberData(nameof(TornTails))]
    public async Task WriterStoppedMidVoting_WithATornTail_ResumesAndGivesTheUninterruptedRoots(RecordEncoding encoding, string tail)
    {
        var (directory, segment) = await StoppedMidVoting(encoding);
        long complete = new FileInfo(segment).Length;
        var manifest = RegularElection.Value.Manifest;
        byte[] third = ElectionGuard.Core.RecordFormat.Mappers.BallotMapper.ToItem(RegularElection.Value.Devices[0].Ballots[2], manifest).ToByteArray();
        byte[] torn = tail switch
        {
            "the third ballot's frame cut short" => Frame(third)[..500],
            "a length varint cut short" => Frame(third)[..1],
            "zero bytes" => new byte[4096],

            // The first byte of the two-byte length, then zeros: it reads as a length that is not minimal.
            "a length varint cut short, then zero bytes" => [.. Frame(third)[..1], .. new byte[4096]],

            // The whole length, then zeros for the item and beyond: a frame of zero bytes, then zeros.
            "a whole length, then zero bytes" => [.. Frame(third)[..^third.Length], .. new byte[third.Length + 4096]],

            // The length and the frame's first 300 bytes reached the disk, its later pages did not:
            // a frame that ends in zeros (not canonical), then zeros past it, or exactly to its end.
            "a whole length and part of the frame, then zero bytes past its end" => [.. Frame(third)[..300], .. new byte[Frame(third).Length - 300 + 4096]],
            "a whole length and part of the frame, then zero bytes to its end" => [.. Frame(third)[..300], .. new byte[Frame(third).Length - 300]],
            "the third ballot's line cut short" => RecordJson.FormatItem(third, default)[..700],
            _ => [],
        };
        await using (var file = new FileStream(segment, FileMode.Append))
        {
            file.Write(torn);
        }

        var writer = await ElectionRecord.ResumeAsync(directory);
        Assert.Equal(RecordPhase.Setup, writer.Phase);
        Assert.Equal(complete, new FileInfo(segment).Length);
        var final = await Finish(writer, deviceOneFrom: 2);

        Assert.Equal((await Uninterrupted(encoding)).Entries, final.Entries);
        await using var reader = await ElectionRecord.OpenAsync(directory);
        Assert.Equal(final.Root, (await ElectionRecord.CheckClaimedTocAsync(reader)).Root);
    }

    [Theory]
    [InlineData("a ballot item in the middle made non-canonical", "not canonical")]
    [InlineData("a zero-length frame followed by data", "a zero-length frame followed by data")]
    [InlineData("a frame length in the middle that is not minimal", "not minimal (W4)")]
    [InlineData("a frame length that is not minimal, then data", "not minimal (W4)")]
    [InlineData("a frame of zero bytes followed by data", "a frame of zero bytes followed by data")]
    [InlineData("a frame part written, then zeros, then data", "an item that is not canonical")]
    public async Task CorruptionThatIsNotATornTail_IsRefused(string corruption, string expected)
    {
        var (directory, segment) = await StoppedMidVoting(RecordEncoding.Protobuf);
        var frames = Frames(File.ReadAllBytes(segment));
        switch (corruption)
        {
            case "a ballot item in the middle made non-canonical":
                var ballot = Pb.RecordItem.Parser.ParseFrom(Payload(frames[2])).EncryptedBallot;
                byte[] inner = [.. ballot.ToByteArray(), 0x28, 0x01];
                frames[2] = Frame([0x5A, .. EgrfVectors.Varint((ulong)inner.Length), .. inner]);
                File.WriteAllBytes(segment, Join(frames));
                break;
            case "a zero-length frame followed by data":
                File.WriteAllBytes(segment, [.. Join(frames), 0x00, 0x00, 0x05]);
                break;
            case "a frame length in the middle that is not minimal":
                // The second ballot's length padded to three bytes, which every reader refuses (W4).
                byte[] payload = Payload(frames[2]);
                frames[2] = [(byte)((payload.Length & 0x7F) | 0x80), (byte)(((payload.Length >> 7) & 0x7F) | 0x80), 0x00, .. payload];
                File.WriteAllBytes(segment, Join(frames));
                break;
            case "a frame length that is not minimal, then data":
                File.WriteAllBytes(segment, [.. Join(frames), 0x81, 0x00, 0x05]);
                break;
            case "a frame of zero bytes followed by data":
                File.WriteAllBytes(segment, [.. Join(frames), 0x03, 0x00, 0x00, 0x00, 0x05]);
                break;
            case "a frame part written, then zeros, then data":
                // The torn-frame shape of the zero-fill rule, but with data after it: not a tail.
                byte[] third = ElectionGuard.Core.RecordFormat.Mappers.BallotMapper.ToItem(RegularElection.Value.Devices[0].Ballots[2], RegularElection.Value.Manifest).ToByteArray();
                File.WriteAllBytes(segment, [.. Join(frames), .. Frame(third)[..300], .. new byte[Frame(third).Length - 300], 0x05]);
                break;
        }

        byte[] before = File.ReadAllBytes(segment);
        var failure = await Assert.ThrowsAsync<InvalidDataException>(() => ElectionRecord.ResumeAsync(directory).AsTask());
        Assert.Contains("not a torn tail", failure.Message);
        Assert.Contains(expected, failure.Message);
        Assert.Equal(before, File.ReadAllBytes(segment));
    }

    /// <summary>
    /// A section that no unfinished step of the writer leaves behind is foreign data: resuming
    /// refuses it and deletes nothing. Rows: a device section after voting was sealed (sealing needs
    /// every device closed, and a device opens only before it), and a final-phase section at the
    /// sealed phase (only the aggregate seal, the next step, can have been cut short).
    /// </summary>
    [Theory]
    [InlineData("a device section after voting was sealed")]
    [InlineData("a final section at the sealed phase")]
    public async Task ASectionNoUnfinishedStepLeaves_IsRefused_AndKept(string foreign)
    {
        var election = RegularElection.Value;
        string directory = TempDirectory("foreign");
        await using (var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf))
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
        }

        string copied = Path.Combine(DeviceOne(directory), "00000000.binpb");
        string file = foreign == "a device section after voting was sealed"
            ? Path.Combine(directory, "devices", "regular-" + new string('a', 64), "00000000.binpb")
            : Path.Combine(directory, "final", "decrypted_tally.binpb");
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.Copy(copied, file);

        var failure = await Assert.ThrowsAsync<InvalidDataException>(() => ElectionRecord.ResumeAsync(directory).AsTask());
        Assert.Contains("an operator decides", failure.Message);
        Assert.True(File.Exists(file));
    }

    /// <summary>
    /// An aggregate seal that is refused leaves nothing behind (no section written, no request
    /// remembered), so the call made again with the input corrected succeeds: here after a tally the
    /// writer refuses (its total cast weight below its count, as in one restored from the JSON
    /// record format) and after a request list refused at its last request.
    /// </summary>
    [Fact]
    public async Task ARefusedAggregateSeal_LeavesNothingBehind_AndTheCorrectedCallSucceeds()
    {
        var election = RegularElection.Value;
        string directory = TempDirectory("refused-seal");
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
        var requests = election.ContestData.Select(x => new ContestDataRequest(writer.Locate(x.Ballot.SelectionEncryptionIdentifierHash), x.Ballot.SelectionEncryptionIdentifierHash, x.Data.ContestIndex)).ToList();
        Assert.NotEmpty(requests);

        var unknownWeight = new ElectionGuard.Core.Tally.EncryptedTally(election.Manifest) { BallotsCast = election.Tally.BallotsCast };
        Assert.Contains("total cast weight", (await Assert.ThrowsAsync<ArgumentException>(() => writer.SealAggregatedAsync(unknownWeight, requests).AsTask())).Message);
        Assert.Contains("requested twice", (await Assert.ThrowsAsync<ArgumentException>(() => writer.SealAggregatedAsync(election.Tally, [.. requests, requests[0]]).AsTask())).Message);
        Assert.Equal(RecordPhase.Sealed, writer.Phase);
        Assert.False(System.IO.Directory.Exists(Path.Combine(directory, "aggregated")));

        await writer.SealAggregatedAsync(election.Tally, requests);
        foreach (var (ballot, data) in election.ContestData)
        {
            await writer.AddContestDataDecryptionAsync(ballot, data);
        }

        await writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted);
        var final = await writer.CompleteAsync(election.Decrypted);
        Assert.Equal((await Uninterrupted(RecordEncoding.Protobuf)).Entries, final.Entries);
    }

    /// <summary>
    /// A ballot whose item fails to be written (here the write is cancelled) is not indexed: no
    /// locator points at it, and the section refuses further appends, since its tail is unknown. The
    /// resumed writer repairs the tail and gives the next ballot the failed one's position, so the
    /// record finishes with the uninterrupted run's TOC.
    /// </summary>
    [Fact]
    public async Task ABallotWhoseItemIsNotWritten_IsNotIndexed_AndTheResumedWriterGivesTheNextOneItsPosition()
    {
        var election = RegularElection.Value;
        string directory = TempDirectory("failed-append");
        var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf);
        await writer.WriteSetupAsync(election.Record);
        var device = await writer.OpenDeviceAsync("device-1", DeviceChainBallotKind.Encrypted);
        await device.AppendAsync(election.Devices[0].Ballots[0]);
        await device.AppendAsync(election.Devices[0].Ballots[1]);

        var third = election.Devices[0].Ballots[2];
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => device.AppendAsync(third, new CancellationToken(canceled: true)).AsTask());
        Assert.Equal(2, device.Count);
        Assert.Throws<ArgumentException>(() => writer.Locate(third.SelectionEncryptionIdentifierHash));
        Assert.Contains("resume the writer", (await Assert.ThrowsAsync<InvalidOperationException>(() => device.AppendAsync(third).AsTask())).Message);
        Assert.Throws<ArgumentException>(() => writer.Locate(third.SelectionEncryptionIdentifierHash));
        await device.FlushAsync(durable: true);
        await writer.DisposeAsync();

        var final = await Finish(await ElectionRecord.ResumeAsync(directory), deviceOneFrom: 2);
        Assert.Equal((await Uninterrupted(RecordEncoding.Protobuf)).Entries, final.Entries);
    }

    /// <summary>
    /// A contest-data decryption that is refused (it is another ballot's) leaves its request open:
    /// completion still refuses (#10), and the right decryption is then accepted.
    /// </summary>
    [Fact]
    public async Task ARefusedContestDataDecryption_LeavesItsRequestOpen()
    {
        var election = RegularElection.Value;
        string directory = TempDirectory("refused-contest-data");
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
        await writer.SealAggregatedAsync(election.Tally, election.ContestData.Select(x => new ContestDataRequest(writer.Locate(x.Ballot.SelectionEncryptionIdentifierHash), x.Ballot.SelectionEncryptionIdentifierHash, x.Data.ContestIndex)));
        var (first, firstData) = election.ContestData[0];
        var (second, secondData) = election.ContestData[1];
        Assert.Equal(firstData.ContestIndex, secondData.ContestIndex);

        // The first ballot's request answered with the second ballot's decryption.
        Assert.Contains("not of ballot", (await Assert.ThrowsAsync<ArgumentException>(() => writer.AddContestDataDecryptionAsync(first, secondData).AsTask())).Message);
        await writer.AddContestDataDecryptionAsync(second, secondData);
        await writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted);
        Assert.Contains("1 contest-data request(s) without a decryption", (await Assert.ThrowsAsync<InvalidOperationException>(() => writer.CompleteAsync(election.Decrypted).AsTask())).Message);

        await writer.AddContestDataDecryptionAsync(first, firstData);
        var final = await writer.CompleteAsync(election.Decrypted);
        Assert.Equal((await Uninterrupted(RecordEncoding.Protobuf)).Entries, final.Entries);
    }

    /// <summary>
    /// The final-phase adds may run concurrently on one writer: every item lands in its join
    /// section (each add, 32 times over, racing the others; exactly one of each set of
    /// duplicates is accepted), and the record completes with the uninterrupted run's roots. An add
    /// after completion is refused.
    /// </summary>
    [Fact]
    public async Task ConcurrentFinalPhaseAdds_AllLand_AndADuplicateIsAcceptedOnce()
    {
        var election = RegularElection.Value;
        string directory = TempDirectory("concurrent-adds");
        await using var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf, new ElectionRecordWriterOptions { SortBudgetBytes = 1 });
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
        await writer.SealAggregatedAsync(election.Tally, election.ContestData.Select(x => new ContestDataRequest(writer.Locate(x.Ballot.SelectionEncryptionIdentifierHash), x.Ballot.SelectionEncryptionIdentifierHash, x.Data.ContestIndex)));

        // Each add 32 times over, all started at once on the thread pool (a 1-byte sort budget
        // makes every add after the first spill a run, so the adds overlap on I/O too).
        const int copies = 32;
        var adds = new List<Func<Task>>();
        for (int i = 0; i < copies; i++)
        {
            adds.Add(() => writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted).AsTask());
            foreach (var (ballot, data) in election.ContestData)
            {
                adds.Add(() => writer.AddContestDataDecryptionAsync(ballot, data).AsTask());
            }
        }

        using var start = new ManualResetEventSlim();
        var tasks = adds.Select(add => Task.Run(async () =>
        {
            start.Wait();
            try
            {
                await add();
                return true;
            }
            catch (ArgumentException ex) when (ex.Message.Contains("already"))
            {
                return false;
            }
        })).ToList();
        start.Set();
        bool[] accepted = await Task.WhenAll(tasks);
        Assert.Equal(1 + election.ContestData.Count, accepted.Count(x => x));

        var final = await writer.CompleteAsync(election.Decrypted);
        Assert.Equal((await Uninterrupted(RecordEncoding.Protobuf)).Entries, final.Entries);
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted).AsTask());
    }

    /// <summary>
    /// <see cref="SortedSpool"/> takes concurrent adds without losing one (each spilling to a run
    /// under a tiny budget, or not), merges them all in key order, and refuses an add once the merge
    /// has started.
    /// </summary>
    [Theory]
    [InlineData(1L)]
    [InlineData(64L << 20)]
    public async Task SortedSpool_TakesConcurrentAdds_WithoutLosingOne(long budget)
    {
        await using var spool = new SortedSpool(TempDirectory("spool-concurrent"), budget);
        const int threads = 8;
        int perThread = budget == 1 ? 100 : 5000;
        await Task.WhenAll(Enumerable.Range(0, threads).Select(t => Task.Run(async () =>
        {
            for (int i = 0; i < perThread; i++)
            {
                byte[] key = new byte[8];
                System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(key, (long)t * perThread + i);
                await spool.AddAsync(key, [(byte)t], CancellationToken.None);
            }
        })));

        Assert.Equal(threads * perThread, spool.Count);
        long expected = 0;
        await foreach (var (key, _) in spool.MergeAsync("the test pairs"))
        {
            Assert.Equal(expected++, System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(key));
        }

        Assert.Equal(threads * perThread, expected);
        await Assert.ThrowsAsync<InvalidOperationException>(() => spool.AddAsync([0xFF], [0], CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task WriterStoppedAfterTheAggregate_DiscardsUnsealedFinalFiles_AndFinishes()
    {
        var election = RegularElection.Value;
        string directory = TempDirectory("stopped-aggregated");
        var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf);
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
        await writer.SealAggregatedAsync(election.Tally, election.ContestData.Select(x => new ContestDataRequest(writer.Locate(x.Ballot.SelectionEncryptionIdentifierHash), x.Ballot.SelectionEncryptionIdentifierHash, x.Data.ContestIndex)));
        await writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted);
        await writer.DisposeAsync();

        // A completion that crashed half way: the decrypted tally written, nothing else, no new TOC.
        System.IO.Directory.CreateDirectory(Path.Combine(directory, "final"));
        File.WriteAllBytes(Path.Combine(directory, "final", "decrypted_tally.binpb"), [0x01, 0x02]);

        await using (var resumed = await ElectionRecord.ResumeAsync(directory))
        {
            Assert.Equal(RecordPhase.Aggregated, resumed.Phase);
            Assert.False(System.IO.Directory.Exists(Path.Combine(directory, "final")));
            await Assert.ThrowsAsync<InvalidOperationException>(() => resumed.OpenDeviceAsync("device-3", DeviceChainBallotKind.Encrypted).AsTask());

            // The decryptions added before the stop were never sealed, so they are added again.
            await Assert.ThrowsAsync<InvalidOperationException>(() => resumed.CompleteAsync(election.Decrypted).AsTask());
            foreach (var (ballot, data) in election.ContestData)
            {
                await resumed.AddContestDataDecryptionAsync(ballot, data);
            }

            await resumed.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted);
            var final = await resumed.CompleteAsync(election.Decrypted);
            Assert.Equal((await Uninterrupted(RecordEncoding.Protobuf)).Entries, final.Entries);
        }
    }

    [Fact]
    public async Task ADirectoryWithNoFixedPhase_IsNotResumed_AndASealedSectionThatChanged_IsRefused()
    {
        // The setup written, but its TOC (the phase's fixing) never: there is no phase to resume.
        string unfixed = TempDirectory("no-phase");
        await using (var writer = ElectionRecord.Create(unfixed, RecordEncoding.Protobuf))
        {
            await writer.WriteSetupAsync(RegularElection.Value.Record);
        }

        File.Move(Path.Combine(unfixed, "toc.binpb"), Path.Combine(unfixed, "toc.binpb.tmp"));
        Assert.Contains("no table of contents", (await Assert.ThrowsAsync<InvalidDataException>(() => ElectionRecord.ResumeAsync(unfixed).AsTask())).Message);

        string directory = TempDirectory("changed");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        string segment = Path.Combine(DeviceOne(directory), "00000000.binpb");
        var frames = Frames(File.ReadAllBytes(segment));
        (frames[2], frames[3]) = (frames[3], frames[2]);
        File.WriteAllBytes(segment, Join(frames));
        Assert.Contains("is not the one its table of contents fixed", (await Assert.ThrowsAsync<InvalidDataException>(() => ElectionRecord.ResumeAsync(directory).AsTask())).Message);
    }
}
