using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.PreEncryption;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;
using Google.Protobuf;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordCarrierElections;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-6: the directory carrier (design §5.2, §5.3, §8.3). A full election written phase by phase
/// reads back to the same domain objects, which pass the verifications that read them, and writing
/// those again gives the same roots; the reader's layout, framing, header and TOC checks each refuse
/// their tampering under its R-code; the phase gates hold; and writing and reading stream.
/// </summary>
public class RecordDirectoryCarrierTests
{
    public RecordDirectoryCarrierTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static async Task<string> WrittenRegular(RecordEncoding encoding = RecordEncoding.Protobuf, ElectionRecordWriterOptions? options = null)
    {
        string directory = TempDirectory("regular");
        await WriteAsync(RegularElection.Value, directory, encoding, options);
        return directory;
    }

    // ---- round trips --------------------------------------------------------------------------------

    [Theory]
    [InlineData(RecordEncoding.Protobuf)]
    [InlineData(RecordEncoding.Json)]
    public async Task RegularElection_WriteThenRead_GivesTheSameObjects_AndTheSameRoots(RecordEncoding encoding)
    {
        var election = RegularElection.Value;
        string directory = TempDirectory("regular-round-trip");
        var tocs = await WriteAsync(election, directory, encoding);
        var final = tocs[RecordPhase.Final];

        await using var reader = await ElectionRecord.OpenAsync(directory);
        Assert.Equal((encoding, RecordCarrier.Directory, RecordPhase.Final, RecordFormatVersion.V2_0), (reader.Encoding, reader.Carrier, reader.Phase, reader.Format));
        var computed = await ElectionRecord.CheckClaimedTocAsync(reader);
        Assert.Equal(final.Entries, computed.Entries);
        Assert.Equal(final.Root, reader.ClaimedToc!.Root);

        // Phase roots are prefixes: each phase's TOC is extended by the next (design §4.9).
        Assert.True(tocs[RecordPhase.Sealed].Extends(tocs[RecordPhase.Setup]));
        Assert.True(tocs[RecordPhase.Aggregated].Extends(tocs[RecordPhase.Sealed]));
        Assert.True(final.Extends(tocs[RecordPhase.Aggregated]));
        foreach (var phase in Enum.GetValues<RecordPhase>())
        {
            Assert.Equal(tocs[phase].Root, final.PhaseRoot(phase));
        }

        var contents = await ReadAsync(reader);
        var manifest = election.Manifest;

        // Setup: every claim kept, the manifest byte for byte.
        Assert.Equal(election.Record.ManifestFile.Bytes, contents.Setup.ManifestFile.Bytes);
        Assert.Equal(SetupMapper.ToItems(RecordSetup.FromEncryptionRecord(election.Record)).Select(x => x.ToByteArray()), SetupMapper.ToItems(contents.Setup).Select(x => x.ToByteArray()));

        // Devices in key order; ballots in chain order, each re-encoding to its item's bytes.
        Assert.Equal(election.Devices.Count, contents.Devices.Count);
        foreach (var (header, ballots, _, close) in contents.Devices)
        {
            var original = election.Devices.Single(x => x.DeviceId == header.DeviceId).Ballots;
            Assert.Equal(original.Select(x => BallotMapper.ToItem(x, manifest).ToByteArray()), ballots.Select(x => BallotMapper.ToItem(x, manifest).ToByteArray()));
            Assert.Equal(original.Select(x => x.Status), ballots.Select(x => x.Status));
            Assert.Equal(ClosedAt, close!.ClosedAt);
            var chain = DeviceMapper.FromItems(header, close, ballots.Select(x => x.ConfirmationCode));
            new ConfirmationCodeVerification().VerifyDevice(chain, ballots, election.Record);
        }

        Assert.True(contents.Devices.Select(x => x.Header.Key).SequenceEqual(contents.Devices.Select(x => x.Header.Key).Order()));

        // Aggregated and final.
        new BallotAggregationVerification().Verify(contents.Devices.SelectMany(x => x.Ballots), manifest, contents.Tally);
        Assert.Equal(election.Tally.TotalCastWeight, contents.Tally.TotalCastWeight);
        Assert.Equal(TallyMapper.ToItems(election.Decrypted).Select(x => x.ToByteArray()), TallyMapper.ToItems(contents.Decrypted).Select(x => x.ToByteArray()));
        Assert.Equal(2, contents.Requests.Count);
        Assert.True(contents.Requests.Select(x => x.Ballot).SequenceEqual(contents.Requests.Select(x => x.Ballot).Order()));
        Assert.Equal(election.ContestData.Count, contents.ContestData.Count);
        foreach (var data in contents.ContestData)
        {
            var ballot = election.Ballots.Single(x => x.Id == data.BallotId);
            new ContestDataDecryptionVerification().Verify(election.Record, ballot, data);
        }

        var challenged = Assert.Single(contents.Challenged);
        new ChallengedBallotDecryptionVerification().Verify(election.Record, election.Challenged.Ballot, challenged);
        new ChallengedBallotWellFormednessVerification().Verify(manifest, election.Challenged.Ballot, challenged);

        // Written again from what was read: the same roots, phase by phase.
        string again = TempDirectory("regular-again");
        await using (var writer = ElectionRecord.Create(again, encoding))
        {
            await writer.WriteSetupAsync(contents.Setup);
            foreach (var (header, ballots, _, _) in contents.Devices)
            {
                await using var device = await writer.OpenDeviceAsync(header);
                foreach (var ballot in ballots)
                {
                    await device.AppendAsync(ballot);
                }

                await device.CloseAsync(ClosedAt);
            }

            await writer.SealVotingAsync();
            await writer.SealAggregatedAsync(contents.Tally, contents.Requests);
            foreach (var data in contents.ContestData)
            {
                await writer.AddContestDataDecryptionAsync(contents.Devices.SelectMany(x => x.Ballots).Single(x => x.Id == data.BallotId), data);
            }

            await writer.AddChallengedDecryptionAsync(contents.Devices.SelectMany(x => x.Ballots).Single(x => x.Id == challenged.BallotId), challenged);
            var rewritten = await writer.CompleteAsync(contents.Decrypted);
            Assert.Equal(final.Entries, rewritten.Entries);
        }
    }

    [Theory]
    [InlineData(RecordEncoding.Protobuf)]
    [InlineData(RecordEncoding.Json)]
    public async Task PreEncryptedElection_WriteThenRead_CastFullAndCompactUncast_PassVerifications(RecordEncoding encoding)
    {
        var election = PreEncryptedRecord.Value;
        string directory = TempDirectory("pre-encrypted");
        var toc = await WriteAsync(election, directory, encoding);

        await using var reader = await ElectionRecord.OpenAsync(directory);
        Assert.Equal(toc.Entries, (await ElectionRecord.CheckClaimedTocAsync(reader)).Entries);
        var contents = await ReadAsync(reader);
        var (header, casts, uncast, close) = Assert.Single(contents.Devices);
        Assert.Equal(DeviceChainBallotKind.PreEncrypted, header.Kind);
        Assert.Equal(2, casts.Count);
        Assert.Equal(
            [Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot, Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot, Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot],
            uncast.Select(x => x.ItemCase));
        Assert.NotNull(close!.ClosingHash);

        foreach (var cast in casts)
        {
            Assert.Equal(BallotMapper.ToItem(election.Device.Single(x => x.Cast?.Id == cast.Id).Cast!, election.Record.Manifest).ToByteArray(), BallotMapper.ToItem(cast, election.Record.Manifest).ToByteArray());
            new SelectionVectorAccumulationVerification().Verify(cast, election.Record);
        }

        Assert.Equal(3, contents.Releases.Count);
        foreach (var release in contents.Releases)
        {
            var original = election.Releases.Single(x => x.Ballot.Id == release.Ballot.Id);
            Assert.Equal(original.BallotNonce is null, release.BallotNonce is null);
            new UncastBallotEncryptionVerification().Verify(release, election.Record);
        }

        // Verification 16's device walk over the section as read: casts and uncast ballots interleaved in print order.
        var links = new List<DeviceChainLink>();
        await foreach (var entry in reader.OpenDevice(header.Key).ReadEntriesAsync())
        {
            var item = Pb.RecordItem.Parser.ParseFrom(entry.Bytes.Span);
            links.Add(item.ItemCase switch
            {
                Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot => DeviceChainLink.From(casts.Single(x => ((byte[])x.SelectionEncryptionIdentifierHash).AsSpan().SequenceEqual(item.PreEncryptedCastBallot.HI.Span))),
                _ => DeviceChainLink.From(contents.Releases.Single(x => ((byte[])x.Ballot.SelectionEncryptionIdentifierHash).AsSpan().SequenceEqual(
                    (item.PreEncryptedUncastBallot?.HI ?? item.PreEncryptedCompactUncastBallot.HI).Span)).Ballot),
            });
        }

        new PreEncryptedConfirmationCodeVerification().VerifyDevice(DeviceMapper.FromItems(header, close, links.Select(x => x.ConfirmationCode)), links, election.Record);
        Assert.Equal(TallyMapper.ToItems(election.Decrypted).Select(x => x.ToByteArray()), TallyMapper.ToItems(contents.Decrypted).Select(x => x.ToByteArray()));

        // Written again from what was read (casts and uncast ballots in print order, each uncast one
        // in the form it was read in, then the releases): the same TOC. The roots cover every item's
        // bytes, so a mapper that dropped anything (an option label, a short code, a nonce) shows here.
        string again = TempDirectory("pre-encrypted-again");
        await using (var writer = ElectionRecord.Create(again, encoding))
        {
            await writer.WriteSetupAsync(contents.Setup);
            await using (var device = await writer.OpenDeviceAsync(header))
            {
                await foreach (var entry in reader.OpenDevice(header.Key).ReadEntriesAsync())
                {
                    var item = Pb.RecordItem.Parser.ParseFrom(entry.Bytes.Span);
                    switch (item.ItemCase)
                    {
                        case Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot:
                            await device.AppendAsync(casts.Single(x => ((byte[])x.SelectionEncryptionIdentifierHash).AsSpan().SequenceEqual(item.PreEncryptedCastBallot.HI.Span)));
                            break;
                        default:
                            bool full = item.ItemCase == Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot;
                            var hi = full ? item.PreEncryptedUncastBallot.HI : item.PreEncryptedCompactUncastBallot.HI;
                            var printed = contents.Releases.Single(x => ((byte[])x.Ballot.SelectionEncryptionIdentifierHash).AsSpan().SequenceEqual(hi.Span)).Ballot;
                            await device.AppendUncastAsync(printed, full ? UncastDisposition.ReturnedNoncesReleased : UncastDisposition.ReturnedBallotNonceReleased);
                            break;
                    }
                }

                await device.CloseAsync(ClosedAt);
            }

            await writer.SealVotingAsync();
            await writer.SealAggregatedAsync(contents.Tally, contents.Requests);
            foreach (var release in contents.Releases)
            {
                await writer.AddUncastReleaseAsync(release);
            }

            Assert.Equal(toc.Entries, (await writer.CompleteAsync(contents.Decrypted)).Entries);
        }
    }

    [Fact]
    public async Task SegmentRollover_SplitsSections_AndChangesNoRoot()
    {
        var election = RegularElection.Value;
        string whole = await WrittenRegular();
        string split = TempDirectory("regular-split");
        var tocs = await WriteAsync(election, split, RecordEncoding.Protobuf, new ElectionRecordWriterOptions { SegmentSizeBytes = 1 });

        var files = Directory.EnumerateFiles(Path.Combine(split, "devices"), "*.binpb", SearchOption.AllDirectories).Select(Path.GetFileName).ToList();
        Assert.Contains("00000005.binpb", files); // device-1: header, 4 ballots, close
        await using var a = await ElectionRecord.OpenAsync(whole);
        await using var b = await ElectionRecord.OpenAsync(split);
        Assert.Equal((await ElectionRecord.CheckClaimedTocAsync(a)).Root, (await ElectionRecord.CheckClaimedTocAsync(b)).Root);
        Assert.Equal(tocs[RecordPhase.Final].Root, a.ClaimedToc!.Root);
        Assert.Empty(await ElectionRecord.DiffAsync(a, b).ToListAsync());
    }

    // ---- phases --------------------------------------------------------------------------------------

    [Fact]
    public async Task PhaseGates_RefuseOutOfPhaseWrites_AndEachPhaseIsAReadableRecord()
    {
        var election = RegularElection.Value;
        string directory = TempDirectory("phases");
        await using var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf);
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.SealVotingAsync().AsTask());
        var setup = await writer.WriteSetupAsync(election.Record);
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.WriteSetupAsync(election.Record).AsTask());
        await AssertPhase(directory, RecordPhase.Setup, setup);

        var device = await writer.OpenDeviceAsync("device-1", DeviceChainBallotKind.Encrypted);
        foreach (var ballot in election.Devices[0].Ballots)
        {
            await device.AppendAsync(ballot);
        }

        // Q36: no decryption before the aggregate is sealed; no seal with a device open.
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.SealVotingAsync().AsTask());
        var seal = await device.CloseAsync();
        Assert.Equal(6, seal!.ItemCount);
        Assert.Equal(RecordDigests.CodesRoot(election.Devices[0].Ballots.Select(x => x.ConfirmationCode)), seal.CodesRoot);
        await Assert.ThrowsAsync<InvalidOperationException>(() => device.AppendAsync(election.Devices[0].Ballots[0]).AsTask());
        var sealedToc = await writer.SealVotingAsync();
        await AssertPhase(directory, RecordPhase.Sealed, sealedToc);
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.OpenDeviceAsync("device-9", DeviceChainBallotKind.Encrypted).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted).AsTask());

        // The tally of device-1's ballots only. The decrypted tally passed to CompleteAsync below is the
        // two-device election's: this test is about the phase gates, and the writer, which is not a
        // verifier, does not compare the two (Verification 10 would).
        var tally = ElectionFixtureBuilder.CreateEncryptedTally(election.Manifest, election.Devices[0].Ballots.ToArray());
        var aggregated = await writer.SealAggregatedAsync(tally, []);
        await AssertPhase(directory, RecordPhase.Aggregated, aggregated);

        // #8: every challenged ballot has its decryption before the record completes.
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.CompleteAsync(election.Decrypted).AsTask());
        await writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted);
        await Assert.ThrowsAsync<ArgumentException>(() => writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted).AsTask());
        var spoiled = election.Devices[0].Ballots.Single(x => x.Status == BallotStatus.Spoiled);
        var asChallenged = new DecryptedChallengedBallot { BallotId = spoiled.Id, Contests = election.Challenged.Decrypted.Contests };
        Assert.Contains("Spoiled", (await Assert.ThrowsAsync<ArgumentException>(() => writer.AddChallengedDecryptionAsync(spoiled, asChallenged).AsTask())).Message);
        var final = await writer.CompleteAsync(election.Decrypted);
        await AssertPhase(directory, RecordPhase.Final, final);
        Assert.True(final.Extends(setup) && final.Extends(sealedToc) && final.Extends(aggregated));
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.CompleteAsync(election.Decrypted).AsTask());

        static async Task AssertPhase(string directory, RecordPhase phase, TableOfContents toc)
        {
            await using var reader = await ElectionRecord.OpenAsync(directory);
            Assert.Equal(phase, reader.Phase);
            Assert.Equal(toc.Root, (await ElectionRecord.CheckClaimedTocAsync(reader)).Root);
        }
    }

    [Fact]
    public async Task DeviceWriter_RefusesWhatAnHonestSectionCannotHold()
    {
        var election = RegularElection.Value;
        await using var writer = ElectionRecord.Create(TempDirectory("device-refusals"), RecordEncoding.Protobuf);
        await writer.WriteSetupAsync(election.Record);
        var ballots = election.Devices[0].Ballots;
        var device = await writer.OpenDeviceAsync("device-1", DeviceChainBallotKind.Encrypted);

        // Out of chain order: the second ballot first (8.E's chaining field).
        Assert.Contains("chaining field", (await Assert.ThrowsAsync<ArgumentException>(() => device.AppendAsync(ballots[1]).AsTask())).Message);
        // Another device's ballot.
        await Assert.ThrowsAsync<ArgumentException>(() => device.AppendAsync(election.Devices[1].Ballots[0]).AsTask());
        // Unrecorded status.
        var unrecorded = Copy(ballots[0], status: null);
        Assert.Contains("Unrecorded", (await Assert.ThrowsAsync<ArgumentException>(() => device.AppendAsync(unrecorded).AsTask())).Message);
        // A structure violation: a contest listed twice.
        var twice = Copy(ballots[0], BallotStatus.Cast, contests: [.. ballots[0].Contests, ballots[0].Contests[0]]);
        await Assert.ThrowsAsync<ArgumentException>(() => device.AppendAsync(twice).AsTask());

        await device.AppendAsync(ballots[0]);
        await device.AppendAsync(ballots[1]);
        // A device opened twice.
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.OpenDeviceAsync("device-1", DeviceChainBallotKind.Encrypted).AsTask());
        // A header that is not the device's.
        var wrong = new DeviceHeader(DeviceChainBallotKind.Encrypted, "device-7", new VotingDeviceInformationHash(election.Record.ExtendedBaseHash, "device-8"), ChainingMode.Simple, null);
        await Assert.ThrowsAsync<ArgumentException>(() => writer.OpenDeviceAsync(wrong).AsTask());
        // A pre-encrypted section refuses regular ballots.
        var printer = await writer.OpenDeviceAsync("printer", DeviceChainBallotKind.PreEncrypted);
        await Assert.ThrowsAsync<ArgumentException>(() => printer.AppendAsync(ballots[2]).AsTask());
        // An empty device leaves no section (Q25).
        Assert.Null(await printer.CloseAsync());
        Assert.Empty(Directory.GetDirectories(Path.Combine(writer.Directory, "devices"), "pre-encrypting-*"));

        // The chain record DeviceChain.Close made must be this section's.
        var other = new DeviceChain(election.Record, "device-1");
        other.Append(ballots[0]);
        await Assert.ThrowsAsync<ArgumentException>(() => device.CloseAsync(other.Close()).AsTask());
        var chain = new DeviceChain(election.Record, "device-1");
        chain.Append(ballots[0]);
        chain.Append(ballots[1]);
        Assert.NotNull(await device.CloseAsync(chain.Close()));
    }

    [Fact]
    public async Task NeverReturnedBallot_IsWrittenCompact_AndAReleaseOfTheOtherFormIsRefused()
    {
        var election = PreEncryptedRecord.Value.Election;
        await using var writer = ElectionRecord.Create(TempDirectory("never-returned"), RecordEncoding.Protobuf);
        await writer.WriteSetupAsync(election.Record);
        var device = await writer.OpenDeviceAsync(PreEncryptedElection.DeviceId, DeviceChainBallotKind.PreEncrypted);
        var neverReturned = election.Uncast("nr-1", releaseBallotNonce: false, device.PreviousConfirmationCode);
        await device.AppendUncastAsync(neverReturned.Ballot, UncastDisposition.NeverReturned);
        var full = election.Uncast("full-1", releaseBallotNonce: false, device.PreviousConfirmationCode);
        await device.AppendUncastAsync(full.Ballot, UncastDisposition.ReturnedNoncesReleased);
        await device.CloseAsync();
        await writer.SealVotingAsync();
        await writer.SealAggregatedAsync(new EncryptedTally(election.Manifest), []);

        // Never returned: compact whatever the caller holds, so its release must carry ξ_B.
        Assert.Contains("compact", (await Assert.ThrowsAsync<ArgumentException>(() => writer.AddUncastReleaseAsync(neverReturned).AsTask())).Message);
        var withNonce = new PreEncryptedUncastBallot { Ballot = full.Ballot, BallotNonce = election.BallotNonceOf(full.Ballot), Contests = full.Contests };
        Assert.Contains("full", (await Assert.ThrowsAsync<ArgumentException>(() => writer.AddUncastReleaseAsync(withNonce).AsTask())).Message);
        await writer.AddUncastReleaseAsync(new PreEncryptedUncastBallot { Ballot = neverReturned.Ballot, BallotNonce = election.BallotNonceOf(neverReturned.Ballot), Contests = neverReturned.Contests });
        await writer.AddUncastReleaseAsync(full);
        await writer.CompleteAsync(new TallyAdmin().Decrypt(election.Guardians.Take(2).ToList(), new EncryptedTally(election.Manifest), election.Record));

        await using var reader = await ElectionRecord.OpenAsync(writer.Directory);
        var items = new List<Pb.RecordItem.ItemOneofCase>();
        await foreach (var entry in reader.OpenDevice(device.Key).ReadEntriesAsync())
        {
            items.Add(Pb.RecordItem.Parser.ParseFrom(entry.Bytes.Span).ItemCase);
        }

        Assert.Equal([Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot, Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot], items);
    }

    // ---- the manifest ------------------------------------------------------------------------------

    [Fact]
    public async Task Manifest_IsStoredByteForByte_WithItsPlainCopy_AndARefusedDocumentIsNotWritten()
    {
        var election = RegularElection.Value;
        // Whitespace, member order, number spelling and a vendor property survive (#19, NQ-1).
        string text = System.Text.Encoding.UTF8.GetString(election.Record.ManifestFile.Bytes);
        byte[] entered = System.Text.Encoding.UTF8.GetBytes("{\n  \"vendorData\": {\"x\": [1, 2.50]},\n" + text[1..].Replace(",", ",\n  "));
        var manifest = ManifestSerializer.Deserialize(entered);
        var file = new ManifestFile { Bytes = entered };
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: file);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, file).EncryptionRecord;

        string directory = TempDirectory("manifest");
        await using (var writer = ElectionRecord.Create(directory, RecordEncoding.Json))
        {
            await writer.WriteSetupAsync(record);
        }

        Assert.Equal(entered, File.ReadAllBytes(Path.Combine(directory, "setup", "manifest.json")));
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            Assert.Equal(entered, (await reader.ReadSetupAsync()).ManifestFile.Bytes);
        }

        // A copy that differs is R.container.
        File.WriteAllBytes(Path.Combine(directory, "setup", "manifest.json"), [.. entered, (byte)' ']);
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            Assert.Equal(RecordCodes.Container, (await Assert.ThrowsAsync<VerificationFailedException>(() => reader.ReadSetupAsync().AsTask())).SubSection);
        }

        // A document the manifest parser refuses is refused before anything is written.
        foreach (byte[] refused in new[] { [0xEF, 0xBB, 0xBF, .. entered], System.Text.Encoding.UTF8.GetBytes("{\"electionId\":\"a\"," + text[1..]) })
        {
            var setup = RecordSetup.FromEncryptionRecord(record) with { ManifestFile = new ManifestFile { Bytes = refused } };
            string empty = TempDirectory("manifest-refused");
            await using var writer = ElectionRecord.Create(empty, RecordEncoding.Protobuf);
            await Assert.ThrowsAsync<InvalidManifestException>(() => writer.WriteSetupAsync(setup).AsTask());
            Assert.Empty(Directory.EnumerateFileSystemEntries(empty));
        }
    }

    // ---- tampering ---------------------------------------------------------------------------------

    /// <summary>
    /// Each tampering, the code it is refused under, and a fragment of the message of the rule that
    /// must refuse it. Several rows share a code, and a later check would often refuse the record
    /// under the same code if the row's own rule were removed, so the message pins which rule fired.
    /// </summary>
    public static TheoryData<string, string, string> Tampers() => new()
    {
        { "two ballots of a device swapped", RecordCodes.Root, "the claimed TOC states" },
        { "a TOC root changed", RecordCodes.Root, "the claimed TOC states" },
        { "a TOC entry's critical bit flipped", RecordCodes.Root, "critical False;" },
        { "a TOC entry removed", RecordCodes.Root, "has files but no entry in the claimed TOC" },
        { "a TOC entry for a section that has no files", RecordCodes.Root, "which has no files" },
        { "a TOC item that is not a toc_entry", RecordCodes.Root, "is not a toc_entry" },
        { "a TOC entry naming the TOC's own type", RecordCodes.Root, "which no TOC holds" },
        { "a device section's last segment truncated mid-frame", RecordCodes.Container, "bytes inside a" },
        { "a device section's tail filled with zero bytes", RecordCodes.Container, "a zero-length frame" },
        { "a frame length over 64 MiB", RecordCodes.Container, "over the 64 MiB ceiling" },
        { "a frame length varint not minimal", RecordCodes.Container, "is not minimal (W4" },
        { "a segment header naming another section", RecordCodes.Container, "neither one wins" },
        { "a segment header with another magic", RecordCodes.Container, "magic" },
        { "a device directory renamed with uppercase hex", RecordCodes.Container, "is not in the record layout" },
        { "an unlisted file", RecordCodes.Container, "is not in the record layout" },
        { "a .jsonl file beside the .binpb files", RecordCodes.Container, "mixes .binpb and .jsonl" },
        { "a segment gap", RecordCodes.Container, "not numbered 00000000 upward" },
        { "a required section removed", RecordCodes.Structure, "which that phase requires" },
        { "a final section without the aggregate", RecordCodes.Structure, "which that phase requires" },
        { "every section file removed", RecordCodes.Structure, "holds no record sections" },
        { "the header section holding two items", RecordCodes.Structure, "holds more than one item" },
        { "the header section holding a parameters item", RecordCodes.Structure, "does not hold one record_header item" },
        { "the parameters section holding a record_header item", RecordCodes.Structure, "holds item member" },
        { "the parameters section holding two items", RecordCodes.Structure, "holds 2 items; it holds exactly one" },
        { "a ballot item made non-canonical", RecordCodes.Encoding, "EncryptedBallot.weight (5) follows field" },
        { "the header made major 3", RecordCodes.Version, "this reader reads major 2" },
        { "a TOC entry naming a section kind v2 does not define", RecordCodes.Version, "a new section kind comes with a new format major" },
        { "a TOC entry naming a former vendor section type", RecordCodes.Version, "a new section kind comes with a new format major" },
        { "a section at the former vendor path", RecordCodes.Container, "vendor/8001/00000000.binpb" },
        { "two TOC entries out of canonical order", RecordCodes.Root, "The claimed table of contents is not one" },
    };

    [Theory]
    [MemberData(nameof(Tampers))]
    public async Task TamperedRecord_IsRefusedUnderItsCode(string tamper, string code, string message)
    {
        string directory = await WrittenRegular();
        string device1 = DeviceOne(directory);
        string segment = Path.Combine(device1, "00000000.binpb");
        var frames = Frames(File.ReadAllBytes(segment));
        string parametersPath = Path.Combine(directory, "setup", "parameters.binpb");
        var parameters = Frames(File.ReadAllBytes(parametersPath));
        string headerPath = Path.Combine(directory, "setup", "header.binpb");
        var headerFrames = Frames(File.ReadAllBytes(headerPath));
        switch (tamper)
        {
            case "a TOC entry for a section that has no files":
                // A device the record has no section for, in canonical order (after every device key
                // that starts 0x01 0x00...).
                RewriteToc(directory, entries => entries.Insert(entries.FindLastIndex(x => x.SectionType == Pb.SectionType.Device) + 1, new Pb.TocEntry { SectionType = Pb.SectionType.Device, Key = ByteString.CopyFrom([2, .. new byte[32]]), Critical = true, ItemCount = 3, Root = ByteString.CopyFrom(new byte[32]) }));
                break;
            case "a TOC item that is not a toc_entry":
                string tocPath = Path.Combine(directory, "toc.binpb");
                var tocFrames = Frames(File.ReadAllBytes(tocPath));
                tocFrames[2] = parameters[1];
                File.WriteAllBytes(tocPath, Join(tocFrames));
                break;
            case "two TOC entries out of canonical order":
                RewriteToc(directory, entries => (entries[0], entries[1]) = (entries[1], entries[0]));
                break;
            case "a TOC entry naming a section kind v2 does not define":
                // A later tally kind (design §4.5's old example, 0x0203), in canonical order. User
                // decision NQ-7: a new section kind comes only with a new format major.
                RewriteToc(directory, entries => entries.Insert(entries.FindIndex(x => (int)x.SectionType > 0x0203), new Pb.TocEntry { SectionType = (Pb.SectionType)0x0203, ItemCount = 1, Root = ByteString.CopyFrom(new byte[32]) }));
                break;
            case "a TOC entry naming a former vendor section type":
                // Vendor sections are removed (user decision "Remove them", 2026-10-10): 0x8001 is a
                // section kind v2 does not define, like any other.
                RewriteToc(directory, entries => entries.Add(new Pb.TocEntry { SectionType = (Pb.SectionType)0x8001, Critical = false, ItemCount = 1, Root = ByteString.CopyFrom(new byte[32]) }));
                break;
            case "a section at the former vendor path":
                // ... and the layout has no path for one: vendor/<type>/ is an unlisted file (§5.3.1).
                Directory.CreateDirectory(Path.Combine(directory, "vendor", "8001"));
                File.WriteAllBytes(Path.Combine(directory, "vendor", "8001", "00000000.binpb"), [.. Frame(new Pb.SegmentHeader { Magic = "EGRF", FormatMajor = 2, SectionType = (Pb.SectionType)0x8001 }.ToByteArray()), .. Frame([0xA2, 0x06, 0x00])]);
                break;
            case "a TOC entry naming the TOC's own type":
                RewriteToc(directory, entries => entries[^1].SectionType = Pb.SectionType.Toc);
                break;
            case "every section file removed":
                foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).ToList())
                {
                    File.Delete(file);
                }

                File.WriteAllText(Path.Combine(directory, "meta.json"), "{}");
                break;
            case "the header section holding two items":
                File.WriteAllBytes(headerPath, Join([.. headerFrames, headerFrames[1]]));
                break;
            case "the header section holding a parameters item":
                File.WriteAllBytes(headerPath, Join([headerFrames[0], parameters[1]]));
                break;
            case "the parameters section holding a record_header item":
                File.WriteAllBytes(parametersPath, Join([parameters[0], headerFrames[1]]));
                break;
            case "the parameters section holding two items":
                File.WriteAllBytes(parametersPath, Join([.. parameters, parameters[1]]));
                break;
            case "two ballots of a device swapped": (frames[2], frames[3]) = (frames[3], frames[2]); File.WriteAllBytes(segment, Join(frames)); break;
            case "a TOC root changed": RewriteToc(directory, entries => entries[3].Root = ByteString.CopyFrom(new byte[32])); break;
            case "a TOC entry's critical bit flipped": RewriteToc(directory, entries => entries[5].Critical = false); break;
            case "a TOC entry removed": RewriteToc(directory, entries => entries.RemoveAt(entries.Count - 1)); break;
            case "a device section's last segment truncated mid-frame": File.WriteAllBytes(segment, File.ReadAllBytes(segment)[..^7]); break;
            case "a device section's tail filled with zero bytes": File.WriteAllBytes(segment, [.. File.ReadAllBytes(segment), 0, 0, 0, 0]); break;
            case "a frame length over 64 MiB": File.WriteAllBytes(segment, [.. File.ReadAllBytes(segment), 0x81, 0x80, 0x80, 0x20]); break;
            case "a frame length varint not minimal":
                // The device header's own length, padded to four bytes: framed exactly as before but
                // for the padding, so only the minimality rule (W4) can refuse it.
                frames[1] = [.. VarintPadded(Payload(frames[1]).Length), .. Payload(frames[1])];
                File.WriteAllBytes(segment, Join(frames, raw: true));
                break;
            case "a segment header naming another section":
                Directory.Move(device1, device1[..^4] + (device1[^4] == '0' ? "1" : "0") + device1[^3..]);
                break;
            case "a segment header with another magic":
                var header = Pb.SegmentHeader.Parser.ParseFrom(Payload(frames[0]));
                header.Magic = "EGRX";
                frames[0] = Frame(header.ToByteArray());
                File.WriteAllBytes(segment, Join(frames, raw: true));
                break;
            case "a device directory renamed with uppercase hex": Directory.Move(device1, Path.Combine(Path.GetDirectoryName(device1)!, "regular-" + Path.GetFileName(device1)["regular-".Length..].ToUpperInvariant())); break;
            case "an unlisted file": File.WriteAllText(Path.Combine(directory, "notes.txt"), "x"); break;
            case "a .jsonl file beside the .binpb files": File.WriteAllText(Path.Combine(directory, "final", "decrypted_tally.jsonl"), "{}\n"); File.Delete(Path.Combine(directory, "final", "decrypted_tally.binpb")); break;
            case "a segment gap": File.Move(segment, Path.Combine(device1, "00000001.binpb")); break;
            case "a required section removed": File.Delete(Path.Combine(directory, "setup", "election_keys.binpb")); break;
            case "a final section without the aggregate": File.Delete(Path.Combine(directory, "aggregated", "contest_data_requests.binpb")); break;
            case "a ballot item made non-canonical":
                // The first ballot with its weight (field 5) written explicitly a second time at the end
                // (a singular field twice, W3), the envelope's length grown to match: framed and
                // parseable, but not the one encoding.
                var ballot = Pb.RecordItem.Parser.ParseFrom(Payload(frames[2])).EncryptedBallot;
                byte[] inner = [.. ballot.ToByteArray(), 0x28, 0x01];
                frames[2] = Frame([0x5A, .. EgrfVectors.Varint((ulong)inner.Length), .. inner]);
                File.WriteAllBytes(segment, Join(frames, raw: true));
                break;
            case "the header made major 3":
                headerFrames[1] = Frame(new Pb.RecordItem { RecordHeader = new Pb.RecordHeader { FormatMajor = 3 } }.ToByteArray());
                File.WriteAllBytes(headerPath, Join(headerFrames, raw: true));
                break;
        }

        // In a verifier's order: open (layout, version, presence), the setup, every item framed and
        // canonical, then the roots against the claimed TOC.
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () =>
        {
            await using var reader = await ElectionRecord.OpenAsync(directory);
            await reader.ReadSetupAsync();
            foreach (var section in reader.Sections)
            {
                await foreach (var item in reader.ReadSectionAsync(section))
                {
                    if (!item.Check.IsCanonical)
                    {
                        throw new VerificationFailedException(RecordCodes.Encoding, item.Check.Message);
                    }
                }
            }

            await ElectionRecord.CheckClaimedTocAsync(reader);
        });

        Assert.True(code == failure.SubSection, $"{tamper}: {failure.SubSection} {failure.Message}");
        Assert.Contains(message, failure.Message);
    }

    /// <summary>
    /// User decision NQ-7 ("Bump the major version"; design §7): a genuine record of a later major,
    /// with every segment header at major 3, its record_header at major 3 and a file of a new section
    /// kind at a path v2 does not list, is refused as R.version, not as the unlisted path's or D6's
    /// R.container: the header section's segment header at v2's path is read first.
    /// </summary>
    [Theory]
    [InlineData(RecordEncoding.Protobuf)]
    [InlineData(RecordEncoding.Json)]
    public async Task ARecordOfALaterMajor_IsRVersion_BeforeItsNewPathsAndHeaders(RecordEncoding encoding)
    {
        string directory = await WrittenRegular(encoding);
        string extension = encoding == RecordEncoding.Json ? ".jsonl" : ".binpb";
        foreach (string file in Directory.EnumerateFiles(directory, "*" + extension, SearchOption.AllDirectories))
        {
            if (encoding == RecordEncoding.Json)
            {
                var lines = File.ReadAllText(file).Split('\n').ToList();
                var header = System.Text.Json.Nodes.JsonNode.Parse(lines[0])!;
                header["formatMajor"] = 3;
                lines[0] = header.ToJsonString();
                if (Path.GetFileName(file) == "header" + extension)
                {
                    var item = System.Text.Json.Nodes.JsonNode.Parse(lines[1])!;
                    item["recordHeader"]!["formatMajor"] = 3;
                    lines[1] = item.ToJsonString();
                }

                File.WriteAllText(file, string.Join('\n', lines));
            }
            else
            {
                var frames = Frames(File.ReadAllBytes(file));
                var header = Pb.SegmentHeader.Parser.ParseFrom(Payload(frames[0]));
                header.FormatMajor = 3;
                frames[0] = Frame(header.ToByteArray());
                if (Path.GetFileName(file) == "header" + extension)
                {
                    var item = Pb.RecordItem.Parser.ParseFrom(Payload(frames[1]));
                    item.RecordHeader.FormatMajor = 3;
                    frames[1] = Frame(item.ToByteArray());
                }

                File.WriteAllBytes(file, Join(frames, raw: true));
            }
        }

        // A file of a section kind v2 does not define, at a path v2 does not list.
        string newKind = Path.Combine(directory, "final", "precinct_tallies" + extension);
        File.Copy(Path.Combine(directory, "setup", "parameters" + extension), newKind);

        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () => await ElectionRecord.OpenAsync(directory));
        Assert.True(failure.SubSection == RecordCodes.Version, $"{failure.SubSection} {failure.Message}");
        Assert.Contains("EGRF major 3", failure.Message);

        // The same record in a zip: its central directory lists the new path too, and the header is
        // still read first.
        var zipped = await Assert.ThrowsAsync<VerificationFailedException>(async () => await (await ElectionRecord.OpenAsync(ZipOf(directory))).DisposeAsync());
        Assert.True(zipped.SubSection == RecordCodes.Version, $"zip: {zipped.SubSection} {zipped.Message}");
        Assert.Contains("EGRF major 3", zipped.Message);

        // The same file alone, in a v2 record, is still the unlisted path it is, in either carrier.
        string v2 = await WrittenRegular(encoding);
        File.Copy(Path.Combine(v2, "setup", "parameters" + extension), Path.Combine(v2, "final", "precinct_tallies" + extension));
        var unlisted = await Assert.ThrowsAsync<VerificationFailedException>(async () => await ElectionRecord.OpenAsync(v2));
        Assert.Equal(RecordCodes.Container, unlisted.SubSection);
        var unlistedZip = await Assert.ThrowsAsync<VerificationFailedException>(async () => await (await ElectionRecord.OpenAsync(ZipOf(v2))).DisposeAsync());
        Assert.True(unlistedZip.SubSection == RecordCodes.Container, $"zip: {unlistedZip.SubSection} {unlistedZip.Message}");
        Assert.Contains("precinct_tallies", unlistedZip.Message);
    }

    /// <summary>A zip of every file of <paramref name="directory"/>, each stored under its relative path.</summary>
    private static string ZipOf(string directory)
    {
        string zip = Path.Combine(TempDirectory("zipped"), "record.zip");
        using (var archive = System.IO.Compression.ZipFile.Open(zip, System.IO.Compression.ZipArchiveMode.Create))
        {
            foreach (string file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            {
                System.IO.Compression.ZipFileExtensions.CreateEntryFromFile(archive, file,Path.GetRelativePath(directory, file).Replace('\\', '/'), System.IO.Compression.CompressionLevel.NoCompression);
            }
        }

        return zip;
    }

    /// <summary>
    /// The reader's frame ceiling holds before any allocation or read of the frame's bytes: a length
    /// of 64 MiB + 1, or a fifth varint byte, is refused while reading the length; a length of exactly
    /// 64 MiB goes on to read its bytes (here, a stream that fails any read past the length).
    /// </summary>
    [Theory]
    [InlineData("64 MiB + 1", new byte[] { 0x81, 0x80, 0x80, 0x20 }, "over the 64 MiB ceiling")]
    [InlineData("a 5-byte varint", new byte[] { 0x81, 0x80, 0x80, 0x80, 0x00 }, "more than 4 bytes")]
    [InlineData("a 10-byte varint wrapping to 1", new byte[] { 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 }, "more than 4 bytes")]
    public async Task FrameReader_RefusesAnOversizedLength_BeforeReadingTheFrame(string row, byte[] varint, string message)
    {
        var probe = new LengthOnlyStream(varint);
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(() => SegmentFraming.ReadFrameAsync(probe, row, CancellationToken.None).AsTask());
        Assert.Equal(RecordCodes.Container, failure.SubSection);
        Assert.Contains(message, failure.Message);

        // Exactly 64 MiB (2^26, varint 80 80 80 20) is within the ceiling: the reader asks for the bytes.
        await Assert.ThrowsAsync<LengthOnlyStream.ReadPastLength>(() => SegmentFraming.ReadFrameAsync(new LengthOnlyStream([0x80, 0x80, 0x80, 0x20]), "64 MiB", CancellationToken.None).AsTask());
    }

    /// <summary>A JSON line longer than <see cref="RecordJson.MaxLineLength"/> is refused while it is read, before it is parsed.</summary>
    [Fact]
    public async Task LineReader_RefusesALineOverTheCeiling()
    {
        var endless = new EndlessStream((byte)'a');
        var reader = new ElectionRecordReader.LineReader(endless, "endless.jsonl");
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(() => reader.NextAsync(CancellationToken.None).AsTask());
        Assert.Equal(RecordCodes.Container, failure.SubSection);
        Assert.Contains("a line longer than", failure.Message);
        Assert.InRange(endless.Served, RecordJson.MaxLineLength + 1, RecordJson.MaxLineLength + (2 << 16));

        // The cap is exact (§5.5): one byte over it is refused even when the line feed arrives in the
        // same read as that byte (the cap is a multiple of the reader's buffer, so it does here).
        var justOver = new LineThenFeedStream(RecordJson.MaxLineLength + 1);
        var exact = await Assert.ThrowsAsync<VerificationFailedException>(() => new ElectionRecordReader.LineReader(justOver, "over.jsonl").NextAsync(CancellationToken.None).AsTask());
        Assert.Contains("a line longer than", exact.Message);
    }

    /// <summary><paramref name="length"/> bytes of 'a', then one line feed.</summary>
    private sealed class LineThenFeedStream(long length) : Stream
    {
        private long _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => length + 1;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            long left = length + 1 - _position;
            int count = (int)Math.Min(buffer.Length, left);
            for (int i = 0; i < count; i++)
            {
                buffer[i] = _position + i == length ? (byte)'\n' : (byte)'a';
            }

            _position += count;
            return count;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => ValueTask.FromResult(Read(buffer.Span));

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>
    /// The line rules of design §5.5: a line ends with a line feed, except that the last one may lack
    /// it (user decision 2026-10-10, "Optional", following jsonlines.org; until then "a\nb" was refused
    /// as a torn tail); one carriage return before the end of a line is removed; an empty line is no
    /// item. All but the accepted rows are <c>R.container</c>. A last line cut short is refused by its
    /// parse (<c>R.encoding</c>; <see cref="AJsonRecord_WhoseLastLineLacksItsLineFeed_ReadsTheSame_AndOneCutShortIsREncoding"/>).
    /// </summary>
    [Theory]
    [InlineData("a\nb\n", "a|b", null)]
    [InlineData("a\r\nb\r\n", "a|b", null)]
    [InlineData("a\nb", "a|b", null)]
    [InlineData("a\r\nb\r", "a|b", null)]
    [InlineData("a", "a", null)]
    [InlineData("a\n\n", "a", "an empty line")]
    [InlineData("a\n\nb\n", "a", "an empty line")]
    [InlineData("a\n\r\n", "a", "an empty line")]
    public async Task LineReader_AppliesTheLineRules(string text, string accepted, string? refusal)
    {
        var reader = new ElectionRecordReader.LineReader(new MemoryStream(System.Text.Encoding.ASCII.GetBytes(text)), "lines.jsonl");
        var lines = new List<string>();
        var failure = await Record.ExceptionAsync(async () =>
        {
            while (await reader.NextAsync(CancellationToken.None) is { } line)
            {
                lines.Add(System.Text.Encoding.ASCII.GetString(line));
            }
        });

        Assert.Equal(accepted, string.Join("|", lines));
        if (refusal is null)
        {
            Assert.Null(failure);
        }
        else
        {
            var refused = Assert.IsType<VerificationFailedException>(failure);
            Assert.Equal(RecordCodes.Container, refused.SubSection);
            Assert.Contains(refusal, refused.Message);
        }
    }

    /// <summary>
    /// Design §5.5 (user decision 2026-10-10, "Optional"): a JSON record whose files' last lines lack
    /// their line feed reads to the same TOC; a last line cut short by a crash does not parse and is
    /// refused as <c>R.encoding</c>.
    /// </summary>
    [Fact]
    public async Task AJsonRecord_WhoseLastLineLacksItsLineFeed_ReadsTheSame_AndOneCutShortIsREncoding()
    {
        string directory = await WrittenRegular(RecordEncoding.Json);
        TableOfContents expected;
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            expected = await ElectionRecord.CheckClaimedTocAsync(reader);
        }

        // Every section file and the TOC without its final line feed (CRLF files would lose "\r\n").
        foreach (var file in Directory.EnumerateFiles(directory, "*.jsonl", SearchOption.AllDirectories))
        {
            byte[] bytes = File.ReadAllBytes(file);
            Assert.Equal((byte)'\n', bytes[^1]);
            File.WriteAllBytes(file, bytes[..^1]);
        }

        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            await reader.ReadSetupAsync();
            Assert.Equal(expected.Entries, (await ElectionRecord.CheckClaimedTocAsync(reader)).Entries);
        }

        // The device segment's last line (its close) cut in half: no longer one JSON value.
        string segment = Directory.GetDirectories(Path.Combine(directory, "devices")).Select(x => Path.Combine(x, "00000000.jsonl")).MaxBy(x => new FileInfo(x).Length)!;
        byte[] all = File.ReadAllBytes(segment);
        int lastLine = Array.LastIndexOf(all, (byte)'\n') + 1;
        File.WriteAllBytes(segment, all[..(lastLine + (all.Length - lastLine) / 2)]);
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () =>
        {
            await using var reader = await ElectionRecord.OpenAsync(directory);
            await ElectionRecord.CheckClaimedTocAsync(reader);
        });
        Assert.Equal(RecordCodes.Encoding, failure.SubSection);
        Assert.Contains("00000000.jsonl", failure.Message);
    }

    /// <summary>
    /// A segment is flushed to the disk before it is closed when it rolls over and when its section
    /// is completed (design §5.2: a phase root the writer returns survives a power failure); a
    /// writer disposed without completing does not flush.
    /// </summary>
    [Fact]
    public async Task SectionWriter_FlushesEachSegmentToTheDisk_AtRolloverAndCompletion()
    {
        var sink = new FlushObservingSink(TempDirectory("durable"));
        var section = SectionKey.Of(RecordSectionType.ChallengedBallotDecryptions);
        await using (var writer = new SectionWriter(sink, section, RecordEncoding.Protobuf, segmentSize: 1))
        {
            await writer.AppendAsync(new byte[] { 0x0A, 0x02, 0x08, 0x02 }, default, CancellationToken.None);
            await writer.AppendAsync(new byte[] { 0x0A, 0x02, 0x08, 0x03 }, default, CancellationToken.None);
            await writer.CompleteAsync(critical: true, CancellationToken.None);
        }

        Assert.Equal(["00000000.binpb", "00000001.binpb"], sink.Files.Select(x => Path.GetFileName(x.Path)));
        Assert.All(sink.Files, x => Assert.True(x.FlushedToDiskBeforeClose, x.Path));

        var abandoned = new FlushObservingSink(TempDirectory("durable"));
        await using (var writer = new SectionWriter(abandoned, section, RecordEncoding.Protobuf, segmentSize: 1 << 20))
        {
            await writer.AppendAsync(new byte[] { 0x0A, 0x02, 0x08, 0x02 }, default, CancellationToken.None);
        }

        Assert.False(Assert.Single(abandoned.Files).FlushedToDiskBeforeClose);
    }

    private sealed class FlushObservingSink(string root) : IRecordSink
    {
        public List<FlushObservingFile> Files { get; } = [];

        public RecordCarrier Carrier => RecordCarrier.Directory;

        public Stream Create(string path, bool compressible)
        {
            string full = Path.Combine(root, path);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            var file = new FlushObservingFile(full);
            Files.Add(file);
            return file;
        }

        public void Dispose()
        {
        }
    }

    private sealed class FlushObservingFile(string path) : FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 1 << 16)
    {
        private bool _closed;

        public string Path { get; } = path;

        public bool FlushedToDiskBeforeClose { get; private set; }

        public override void Flush(bool flushToDisk)
        {
            if (flushToDisk && !_closed)
            {
                FlushedToDiskBeforeClose = true;
            }

            base.Flush(flushToDisk);
        }

        public override ValueTask DisposeAsync()
        {
            _closed = true;
            return base.DisposeAsync();
        }

        protected override void Dispose(bool disposing)
        {
            _closed = true;
            base.Dispose(disposing);
        }
    }

    /// <summary>Serves a frame length, then fails any further read.</summary>
    private sealed class LengthOnlyStream(byte[] length) : Stream
    {
        private int _position;

        public sealed class ReadPastLength() : Exception("The reader asked for the frame's bytes.");

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(Span<byte> buffer)
        {
            if (_position >= length.Length)
            {
                throw new ReadPastLength();
            }

            int count = Math.Min(buffer.Length, length.Length - _position);
            length.AsSpan(_position, count).CopyTo(buffer);
            _position += count;
            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => ValueTask.FromResult(Read(buffer.Span));

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>An endless run of one byte, counting what it served.</summary>
    private sealed class EndlessStream(byte value) : Stream
    {
        public long Served { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => Served;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            buffer.Fill(value);
            Served += buffer.Length;
            return buffer.Length;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => ValueTask.FromResult(Read(buffer.Span));

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task Writer_RefusesAnItemOverTheFrameCeiling()
    {
        await using var sink = new SectionWriterHarness();
        await Assert.ThrowsAsync<ArgumentException>(() => sink.Writer.AppendAsync(new byte[SegmentFraming.MaxFrameLength + 1], default, CancellationToken.None).AsTask());
        await sink.Writer.AppendAsync(new byte[] { 0x0A, 0x02, 0x08, 0x02 }, default, CancellationToken.None);
    }

    private sealed class SectionWriterHarness : IAsyncDisposable
    {
        private readonly string _directory = TempDirectory("ceiling");

        public SectionWriterHarness()
        {
            Writer = new SectionWriter(new DirectoryRecordSink(_directory), SectionKey.Of(RecordSectionType.Header), RecordEncoding.Protobuf, 1 << 20);
        }

        public SectionWriter Writer { get; }

        public ValueTask DisposeAsync() => Writer.DisposeAsync();
    }

    // ---- diff --------------------------------------------------------------------------------------

    [Fact]
    public async Task Diff_FindsTheOneChangedBallot_ByDescentFromTheRoots()
    {
        string a = await WrittenRegular();
        string b = await WrittenRegular();
        await using (var ra = await ElectionRecord.OpenAsync(a))
        await using (var rb = await ElectionRecord.OpenAsync(b))
        {
            // Two writes of one election differ in no item: every value, including the ciphertexts, is the election's.
            Assert.Empty(await ElectionRecord.DiffAsync(ra, rb).ToListAsync());
        }

        // Relabel the spoiled ballot (device-1, position 3; frame 4 after the segment header and the device header) as cast: only the root protects its status (§6.6).
        string device1 = DeviceOne(b);
        string segment = Path.Combine(device1, "00000000.binpb");
        var frames = Frames(File.ReadAllBytes(segment));
        var item = Pb.RecordItem.Parser.ParseFrom(Payload(frames[4]));
        Assert.Equal(Pb.BallotStatus.Spoiled, item.EncryptedBallot.Status);
        item.EncryptedBallot.Status = Pb.BallotStatus.Cast;
        frames[4] = Frame(item.ToByteArray());
        File.WriteAllBytes(segment, Join(frames, raw: true));

        await using var readerA = await ElectionRecord.OpenAsync(a);
        await using var readerB = await ElectionRecord.OpenAsync(b);
        var difference = Assert.Single(await ElectionRecord.DiffAsync(readerA, readerB).ToListAsync());
        Assert.Equal(RecordDifferenceKind.ItemChanged, difference.Kind);
        Assert.Equal(RecordSectionType.Device, difference.Section!.Value.Type);
        Assert.Equal(3, difference.Ordinal);
    }

    /// <summary>
    /// A record at the sealed phase against the final record of the same election: the phase, then
    /// each section only the final one holds (and the other way round). A device section with one
    /// item more: that item, past the end of the other record's section, and nothing else.
    /// </summary>
    [Fact]
    public async Task Diff_ReportsThePhase_SectionsOnlyOneRecordHolds_AndItemsPastTheOtherSectionsEnd()
    {
        var election = RegularElection.Value;
        string sealedRecord = TempDirectory("diff-sealed");
        await using (var writer = ElectionRecord.Create(sealedRecord, RecordEncoding.Protobuf))
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

        string final = await WrittenRegular();
        RecordSectionType[] later =
        [
            RecordSectionType.EncryptedTally, RecordSectionType.ContestDataRequests, RecordSectionType.DecryptedTally,
            RecordSectionType.ChallengedBallotDecryptions, RecordSectionType.ContestDataDecryptions, RecordSectionType.UncastNonceReleases,
        ];
        await using (var a = await ElectionRecord.OpenAsync(sealedRecord))
        await using (var b = await ElectionRecord.OpenAsync(final))
        {
            var forward = await ElectionRecord.DiffAsync(a, b).ToListAsync();
            Assert.Equal(RecordDifferenceKind.Phase, forward[0].Kind);
            Assert.Equal(later.Select(x => (RecordDifferenceKind.SectionOnlyInB, x)), forward.Skip(1).Select(x => (x.Kind, x.Section!.Value.Type)));

            var backward = await ElectionRecord.DiffAsync(b, a).ToListAsync();
            Assert.Equal(RecordDifferenceKind.Phase, backward[0].Kind);
            Assert.Equal(later.Select(x => (RecordDifferenceKind.SectionOnlyInA, x)), backward.Skip(1).Select(x => (x.Kind, x.Section!.Value.Type)));
        }

        // device-1 with a copy of its first ballot appended after its close: one item more.
        string longer = await WrittenRegular();
        string segment = Path.Combine(DeviceOne(longer), "00000000.binpb");
        var frames = Frames(File.ReadAllBytes(segment));
        File.WriteAllBytes(segment, Join([.. frames, frames[2]]));
        long extra = frames.Count - 1; // the segment header is not an item
        await using (var a = await ElectionRecord.OpenAsync(final))
        await using (var b = await ElectionRecord.OpenAsync(longer))
        {
            var onlyInB = Assert.Single(await ElectionRecord.DiffAsync(a, b).ToListAsync());
            Assert.Equal((RecordDifferenceKind.ItemOnlyInB, RecordSectionType.Device, extra), (onlyInB.Kind, onlyInB.Section!.Value.Type, onlyInB.Ordinal!.Value));
            Assert.Null(onlyInB.LeafA);
            Assert.Equal(MerkleTree.LeafHash(Payload(frames[2])), onlyInB.LeafB);

            var onlyInA = Assert.Single(await ElectionRecord.DiffAsync(b, a).ToListAsync());
            Assert.Equal((RecordDifferenceKind.ItemOnlyInA, extra), (onlyInA.Kind, onlyInA.Ordinal!.Value));
            Assert.Null(onlyInA.LeafB);
        }
    }

    // ---- conversion --------------------------------------------------------------------------------

    /// <summary>
    /// The files outside every root (<c>meta.json</c>, the manifest copy) survive a conversion; a
    /// reader the library did not open cannot hand them over, so it is refused before anything is
    /// created rather than converted without them.
    /// </summary>
    [Theory]
    [InlineData(RecordCarrier.Directory)]
    [InlineData(RecordCarrier.Zip)]
    public async Task Convert_CarriesTheFilesOutsideTheRoots_AndRefusesAReaderTheLibraryDidNotOpen(RecordCarrier carrier)
    {
        string directory = await WrittenRegular();
        byte[] meta = "{\"producer\":\"test\"}"u8.ToArray();
        File.WriteAllBytes(Path.Combine(directory, "meta.json"), meta);
        byte[] manifest = File.ReadAllBytes(Path.Combine(directory, "setup", "manifest.json"));
        string parent = TempDirectory("convert-extras");
        string destination = Path.Combine(parent, carrier == RecordCarrier.Zip ? "record.zip" : "record");
        string refused = Path.Combine(parent, carrier == RecordCarrier.Zip ? "refused.zip" : "refused");
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            var failure = await Assert.ThrowsAsync<ArgumentException>(() => ElectionRecord.ConvertAsync(new WrappedReader(reader), refused, RecordEncoding.Json, carrier).AsTask());
            Assert.Contains("cannot hand over the files outside the roots", failure.Message);
            Assert.False(File.Exists(refused) || Directory.Exists(refused));
            await ElectionRecord.ConvertAsync(reader, destination, RecordEncoding.Json, carrier);
        }

        if (carrier == RecordCarrier.Directory)
        {
            Assert.Equal(meta, File.ReadAllBytes(Path.Combine(destination, "meta.json")));
            Assert.Equal(manifest, File.ReadAllBytes(Path.Combine(destination, "setup", "manifest.json")));
        }
        else
        {
            using var archive = System.IO.Compression.ZipFile.OpenRead(destination);
            Assert.Equal(meta, Read(archive, "meta.json"));
            Assert.Equal(manifest, Read(archive, "setup/manifest.json"));
        }

        // The converted record reads, manifest copy checked.
        await using var converted = await ElectionRecord.OpenAsync(destination);
        await converted.ReadSetupAsync();

        static byte[] Read(System.IO.Compression.ZipArchive archive, string name)
        {
            using var stream = archive.GetEntry(name)!.Open();
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            return copy.ToArray();
        }
    }

    /// <summary>
    /// A source whose claimed TOC is not the TOC of its sections, or that holds an item that is not
    /// canonical, is refused under its code, and the partial output is removed.
    /// </summary>
    [Theory]
    [InlineData("a TOC root changed", RecordCarrier.Directory, RecordCodes.Root, "the conversion is discarded")]
    [InlineData("a TOC root changed", RecordCarrier.Zip, RecordCodes.Root, "the conversion is discarded")]
    [InlineData("a ballot item made non-canonical", RecordCarrier.Directory, RecordCodes.Encoding, "a record is converted only when every item is")]
    [InlineData("a ballot item made non-canonical", RecordCarrier.Zip, RecordCodes.Encoding, "a record is converted only when every item is")]
    public async Task Convert_OfATamperedSource_IsRefused_AndLeavesNothing(string tamper, RecordCarrier carrier, string code, string message)
    {
        string directory = await WrittenRegular();
        if (tamper == "a TOC root changed")
        {
            RewriteToc(directory, entries => entries[3].Root = ByteString.CopyFrom(new byte[32]));
        }
        else
        {
            string segment = Path.Combine(DeviceOne(directory), "00000000.binpb");
            var frames = Frames(File.ReadAllBytes(segment));
            var ballot = Pb.RecordItem.Parser.ParseFrom(Payload(frames[2])).EncryptedBallot;
            byte[] inner = [.. ballot.ToByteArray(), 0x28, 0x01];
            frames[2] = Frame([0x5A, .. EgrfVectors.Varint((ulong)inner.Length), .. inner]);
            File.WriteAllBytes(segment, Join(frames));
        }

        string destination = Path.Combine(TempDirectory("convert-tampered"), carrier == RecordCarrier.Zip ? "record.zip" : "record");
        await using var reader = await ElectionRecord.OpenAsync(directory);
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(() => ElectionRecord.ConvertAsync(reader, destination, RecordEncoding.Protobuf, carrier).AsTask());
        Assert.Equal(code, failure.SubSection);
        Assert.Contains(message, failure.Message);
        Assert.False(File.Exists(destination) || Directory.Exists(destination));
    }

    // ---- naming rules (§5.3.1) ---------------------------------------------------------------------

    [Theory]
    [InlineData("derived/../toc.binpb", "path segment")]
    [InlineData("derived/./x.txt", "path segment")]
    [InlineData("derived//x.txt", "path segment")]
    [InlineData("derived/x/", "path segment")]
    [InlineData("..", "path segment")]
    [InlineData("derived/x\\y.txt", "relative '/'-separated")]
    [InlineData("/toc.binpb", "relative '/'-separated")]
    [InlineData("c:/toc.binpb", "relative '/'-separated")]
    [InlineData("derived/x\ty.txt", "relative '/'-separated")]
    [InlineData("derived/x\u007fy.txt", "printable ASCII")]
    [InlineData("derived/café.txt", "printable ASCII")]
    [InlineData("derived/a:b.txt", "printable ASCII")]
    [InlineData("", "relative '/'-separated")]
    public void RequireValidName_RefusesANameOutsideTheRules(string name, string rule)
    {
        var failure = Assert.Throws<VerificationFailedException>(() => RecordLayout.RequireValidName(name));
        Assert.Equal(RecordCodes.Container, failure.SubSection);
        Assert.Contains(rule, failure.Message);
    }

    [Theory]
    [InlineData("toc.binpb")]
    [InlineData("setup/manifest.json")]
    [InlineData("derived/notes/a.b.txt")]
    [InlineData("derived/a b~!.txt")]
    [InlineData("devices/regular-0a/00000000.jsonl")]
    public void RequireValidName_AcceptsANameWithinTheRules(string name) => RecordLayout.RequireValidName(name);

    [Fact]
    public void RequireNoCaseFoldCollision_RefusesNamesEqualUnderCaseFolding()
    {
        RecordLayout.RequireNoCaseFoldCollision(["derived/a.txt", "derived/b.txt", "toc.binpb"]);
        var failure = Assert.Throws<VerificationFailedException>(() => RecordLayout.RequireNoCaseFoldCollision(["toc.binpb", "derived/A.txt", "derived/a.txt"]));
        Assert.Equal(RecordCodes.Container, failure.SubSection);
        Assert.Contains("same name under case folding", failure.Message);
    }

    /// <summary>
    /// The reader applies both naming rules to every file of the source, including names under
    /// <c>derived/</c>, which the layout accepts without looking at any table, so only the rule under
    /// test refuses these (a directory on Windows cannot hold two names equal under case folding, so
    /// the source lists them itself).
    /// </summary>
    [Theory]
    [InlineData("same name under case folding", "derived/A.txt", "derived/a.txt")]
    [InlineData("path segment", "derived/../x.txt")]
    [InlineData("relative '/'-separated", "derived/x\\y.txt")]
    public async Task ASourceWithANameOnlyTheNamingRulesRefuse_IsRContainer(string rule, params string[] names)
    {
        string directory = TempDirectory("naming");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var source = new ExtraNamesSource(new DirectoryRecordSource(directory), names);
        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () => await (await ElectionRecordReader.OpenAsync(source, default)).DisposeAsync());
        Assert.Equal(RecordCodes.Container, failure.SubSection);
        Assert.Contains(rule, failure.Message);
    }

    /// <summary>A reader that passes everything to <paramref name="inner"/>: an <see cref="IElectionRecordReader"/> the library did not open.</summary>
    private sealed class WrappedReader(IElectionRecordReader inner) : IElectionRecordReader
    {
        public RecordEncoding Encoding => inner.Encoding;

        public RecordCarrier Carrier => inner.Carrier;

        public RecordFormatVersion Format => inner.Format;

        public RecordPhase Phase => inner.Phase;

        public TableOfContents? ClaimedToc => inner.ClaimedToc;

        public IReadOnlyList<SectionKey> Sections => inner.Sections;

        public IReadOnlyList<DeviceKey> Devices => inner.Devices;

        public ValueTask<RecordSetup> ReadSetupAsync(CancellationToken ct = default) => inner.ReadSetupAsync(ct);

        public IDeviceSectionReader OpenDevice(DeviceKey device) => inner.OpenDevice(device);

        public IAsyncEnumerable<RecordItemBytes> ReadSectionAsync(SectionKey section, long fromOrdinal = 0, CancellationToken ct = default) => inner.ReadSectionAsync(section, fromOrdinal, ct);

        public IAsyncEnumerable<RecordItemBytes> ReadSignaturesAsync(CancellationToken ct = default) => inner.ReadSignaturesAsync(ct);

        public IReadOnlyList<string> SignatureFiles => inner.SignatureFiles;

        public IAsyncEnumerable<RecordItemBytes> ReadSignatureFileAsync(string file, CancellationToken ct = default) => inner.ReadSignatureFileAsync(file, ct);

        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }

    /// <summary>A record source that reports, as <paramref name="observed"/> is read, how many of its bytes have been served.</summary>
    private sealed class ObservedSource(IRecordSource inner, string observed, Action<long> onServed) : IRecordSource
    {
        public RecordCarrier Carrier => inner.Carrier;

        public IReadOnlyList<string> Files => inner.Files;

        public Stream OpenRead(string path) => path == observed ? new CountingStream(inner.OpenRead(path), onServed) : inner.OpenRead(path);

        public void Dispose() => inner.Dispose();
    }

    private sealed class CountingStream(Stream inner, Action<long> onServed) : Stream
    {
        private long _served;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => inner.Length;

        public override long Position
        {
            get => _served;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int read = inner.Read(buffer);
            _served += read;
            onServed(_served);
            return read;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            int read = await inner.ReadAsync(buffer, ct);
            _served += read;
            onServed(_served);
            return read;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    /// <summary>A record source that lists some extra names beside its inner source's files.</summary>
    private sealed class ExtraNamesSource(IRecordSource inner, string[] extra) : IRecordSource
    {
        public RecordCarrier Carrier => inner.Carrier;

        public IReadOnlyList<string> Files { get; } = [.. inner.Files, .. extra];

        public Stream OpenRead(string path) => inner.OpenRead(path);

        public void Dispose() => inner.Dispose();
    }

    // ---- streaming ---------------------------------------------------------------------------------

    /// <summary>
    /// The writer, the reader, the converter and the zip carrier stream (design §6.4): 5,000 ballots
    /// (about 13 KB each in the record, 65 MB in all) are written, read back, converted to a protobuf
    /// and a JSON zip and read back from each, with the retained heap growing by far less than the
    /// 4,000 ballots between two measurements would take if anything kept them.
    /// </summary>
    [Fact]
    public async Task FiveThousandBallots_AreWrittenConvertedAndRead_WithBoundedMemory()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        var deviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "scanner");
        var template = ElectionFixtureBuilder.CreateEncryptedBallot(record, "scanner", deviceHash,
            ElectionFixtureBuilder.CreateBallot(manifest, "template", new Dictionary<string, int> { ["choice-1"] = 1 }, contestData: WriteIn));

        string directory = TempDirectory("five-thousand");
        const int total = 5000;
        long afterThousand = 0, afterAll = 0;
        await using (var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf))
        {
            await writer.WriteSetupAsync(record);
            await using var device = await writer.OpenDeviceAsync("scanner", DeviceChainBallotKind.Encrypted);
            for (int i = 1; i <= total; i++)
            {
                // Structurally valid copies under fresh identifiers (the writer checks structure and the chain, not proofs).
                await device.AppendAsync(Copy(template, BallotStatus.Cast, id: $"b-{i}", fresh: true));
                if (i == 1000)
                {
                    afterThousand = RetainedBytes();
                }
            }

            afterAll = RetainedBytes();

            // The writer refuses a second ballot with the same H_I (they share id_B, 5.A).
            await device.AppendAsync(template);
            Assert.Contains("5.A", (await Assert.ThrowsAsync<ArgumentException>(() => device.AppendAsync(template).AsTask())).Message);
            await device.CloseAsync();
            await writer.SealVotingAsync();
        }

        long written = Directory.EnumerateFiles(Path.Combine(directory, "devices"), "*", SearchOption.AllDirectories).Sum(x => new FileInfo(x).Length);
        Assert.True(written > 40L << 20, $"{written} bytes written");
        long writeGrowth = afterAll - afterThousand;
        Assert.True(writeGrowth < 8L << 20, $"The writer's retained heap grew by {writeGrowth:N0} bytes over 4,000 ballots ({written / total:N0} bytes each in the record).");

        long readStart = 0, readGrowth = 0;
        int count = 0;
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            await foreach (var item in reader.OpenDevice(reader.Devices[0]).ReadEntriesAsync())
            {
                Assert.True(item.Check.IsCanonical);
                count++;
                if (count == 1000)
                {
                    readStart = RetainedBytes();
                }
            }

            readGrowth = RetainedBytes() - readStart;
            var toc = await ElectionRecord.CheckClaimedTocAsync(reader);
            Assert.Equal(total + 3, toc.Entries.Single(x => x.Type == RecordSectionType.Device).ItemCount);
        }

        Assert.Equal(total + 1, count);
        Assert.True(readGrowth < 4L << 20, $"The reader's retained heap grew by {readGrowth:N0} bytes over 4,000 ballots.");

        // The converter, the zip writer and the zip reader (STORED protobuf, and DEFLATEd JSON through
        // the line reader) stream too. The conversion is measured from inside it: when the converter
        // has read the device segment past its 1,000th ballot, and when it has read all of it (the
        // source counts the bytes served). The archive is read back measured from before the section
        // is opened, so a reader that buffered a whole entry up front would show it too.
        string deviceSegment = Directory.EnumerateFiles(Path.Combine(directory, "devices"), "*.binpb", SearchOption.AllDirectories).Single();
        var deviceFrames = Frames(File.ReadAllBytes(deviceSegment));
        long thousandth = deviceFrames.Take(1 + 1 + 1000).Sum(x => (long)x.Length); // the segment header, the device header, 1,000 ballots
        long segmentLength = deviceFrames.Sum(x => (long)x.Length);
        string deviceSegmentName = Path.GetRelativePath(directory, deviceSegment).Replace(Path.DirectorySeparatorChar, '/');
        foreach (var encoding in new[] { RecordEncoding.Protobuf, RecordEncoding.Json })
        {
            string zip = Path.Combine(TempDirectory("five-thousand-zip"), "record.zip");
            long atThousand = 0, atLast = 0;
            var observed = new ObservedSource(new DirectoryRecordSource(directory), deviceSegmentName, served =>
            {
                if (atThousand == 0 && served >= thousandth)
                {
                    atThousand = RetainedBytes();
                }
                else if (atLast == 0 && served >= segmentLength)
                {
                    atLast = RetainedBytes();
                }
            });
            await using (var reader = await ElectionRecordReader.OpenAsync(observed, default))
            {
                var toc = await ElectionRecord.ConvertAsync(reader, zip, encoding, RecordCarrier.Zip);
                Assert.Equal(reader.ClaimedToc!.Entries, toc.Entries);
            }

            long convertGrowth = atLast - atThousand;
            Assert.True(atThousand > 0 && atLast > 0, "The conversion was not observed.");
            Assert.True(convertGrowth < 8L << 20, $"Converting to a {encoding} zip, the retained heap grew by {convertGrowth:N0} bytes over 4,000 ballots.");

            long before = 0, thousand = 0, after = 0;
            int read = 0;
            await using (var archive = await ElectionRecord.OpenAsync(zip))
            {
                before = RetainedBytes();
                await foreach (var item in archive.OpenDevice(archive.Devices[0]).ReadEntriesAsync())
                {
                    Assert.True(item.Check.IsCanonical);
                    if (++read == 1000)
                    {
                        thousand = RetainedBytes();
                    }
                }

                after = RetainedBytes();
            }

            Assert.Equal(total + 1, read);
            Assert.True(thousand - before < 8L << 20, $"Reading a {encoding} zip, the retained heap was {thousand - before:N0} bytes above its start after 1,000 ballots.");
            Assert.True(after - thousand < 4L << 20, $"Reading a {encoding} zip, the retained heap grew by {after - thousand:N0} bytes over 4,000 ballots.");
        }

        static long RetainedBytes()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            return GC.GetTotalMemory(forceFullCollection: true);
        }
    }

    // ---- helpers -----------------------------------------------------------------------------------

    internal static EncryptedBallot Copy(EncryptedBallot ballot, BallotStatus? status, string? id = null, List<EncryptedContest>? contests = null, bool fresh = false)
    {
        var copy = new EncryptedBallot
        {
            Id = id ?? ballot.Id,
            SelectionEncryptionIdentifier = fresh ? new SelectionEncryptionIdentifier(ElectionGuard.Core.Crypto.ElectionGuardRandom.GetBytes(32)) : ballot.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = fresh ? SelectionEncryptionIdentifierHash.FromCanonicalBytes(ElectionGuard.Core.Crypto.ElectionGuardRandom.GetBytes(32)) : ballot.SelectionEncryptionIdentifierHash,
            BallotStyleId = ballot.BallotStyleId,
            Contests = contests ?? ballot.Contests,
            ConfirmationCode = ballot.ConfirmationCode,
            ChainingField = ballot.ChainingField,
            EncryptedBallotNonce = ballot.EncryptedBallotNonce,
            DeviceId = ballot.DeviceId,
            Weight = ballot.Weight,
            EncryptionTimestamp = ballot.EncryptionTimestamp,
            Status = status ?? BallotStatus.Unrecorded,
        };

        return copy;
    }

    /// <summary>The section directory of device-1 (four ballots), whichever key sorts first.</summary>
    internal static string DeviceOne(string directory) =>
        Directory.GetDirectories(Path.Combine(directory, "devices")).Single(x => Frames(File.ReadAllBytes(Path.Combine(x, "00000000.binpb"))).Count == 7);

    /// <summary>A segment's frames, each with its length varint.</summary>
    internal static List<byte[]> Frames(byte[] segment)
    {
        var frames = new List<byte[]>();
        int at = 0;
        while (at < segment.Length)
        {
            int start = at;
            ulong length = 0;
            int shift = 0;
            byte b;
            do
            {
                b = segment[at++];
                length |= (ulong)(b & 0x7F) << shift;
                shift += 7;
            }
            while ((b & 0x80) != 0);

            at += (int)length;
            frames.Add(segment[start..at]);
        }

        return frames;
    }

    internal static byte[] Payload(byte[] frame)
    {
        int at = 0;
        while ((frame[at++] & 0x80) != 0)
        {
        }

        return frame[at..];
    }

    internal static byte[] Frame(byte[] payload)
    {
        var varint = new byte[10];
        int n = SegmentFraming.WriteVarint(varint, (ulong)payload.Length);
        return [.. varint[..n], .. payload];
    }

    private static byte[] VarintPadded(int length) => [(byte)(length & 0x7F | 0x80), (byte)((length >> 7) & 0x7F | 0x80), (byte)((length >> 14) & 0x7F | 0x80), (byte)(length >> 21)];

    internal static byte[] Join(List<byte[]> frames, bool raw = true) => frames.SelectMany(x => x).ToArray();

    internal static void RewriteToc(string directory, Action<List<Pb.TocEntry>> change)
    {
        string path = Path.Combine(directory, "toc.binpb");
        var frames = Frames(File.ReadAllBytes(path));
        var entries = frames.Skip(1).Select(x => Pb.RecordItem.Parser.ParseFrom(Payload(x)).TocEntry).ToList();
        change(entries);
        File.WriteAllBytes(path, Join([frames[0], .. entries.Select(x => Frame(new Pb.RecordItem { TocEntry = x }.ToByteArray()))]));
    }
}
