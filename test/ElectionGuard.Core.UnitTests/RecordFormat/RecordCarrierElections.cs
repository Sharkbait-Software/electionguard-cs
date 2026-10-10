using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.PreEncryption;
using ElectionGuard.Testing.Common;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// Two complete elections that the carrier tests write as records (design §5.7's golden-record
/// shapes, built once): a regular election under simple chaining with cast (one timestamped, one of
/// weight 2), spoiled and challenged ballots on two devices, write-ins and contest data, its tally,
/// contest-data requests and decryptions and the challenged ballot's decryption; and a pre-encrypted
/// election (pre-encryption cannot carry contest data, Q26) under simple chaining with a cast
/// pre-encrypted ballot, a returned uncast ballot in full, a returned uncast ballot with ξ_B released
/// and a never-returned one (both compact), their releases and the tally.
/// </summary>
internal static class RecordCarrierElections
{
    public const string WriteIn = "Write-in: Ada Lovelace";
    public static readonly DateTimeOffset Timestamp = new(2026, 11, 3, 14, 3, 7, 412, TimeSpan.Zero);
    public static readonly DateTimeOffset ClosedAt = new(2026, 11, 3, 20, 0, 0, 5, TimeSpan.Zero);

    public sealed class Regular
    {
        public required EncryptionRecord Record { get; init; }
        public required List<(string DeviceId, List<EncryptedBallot> Ballots)> Devices { get; init; }
        public required EncryptedTally Tally { get; init; }
        public required DecryptedTally Decrypted { get; init; }
        public required List<(EncryptedBallot Ballot, DecryptedContestData Data)> ContestData { get; init; }
        public required (EncryptedBallot Ballot, DecryptedChallengedBallot Decrypted) Challenged { get; init; }

        public Manifest Manifest => Record.Manifest;

        public IEnumerable<EncryptedBallot> Ballots => Devices.SelectMany(x => x.Ballots);
    }

    public sealed class PreEncrypted
    {
        public required PreEncryptedElection Election { get; init; }
        public required List<(EncryptedBallot? Cast, PreEncryptedBallot? Printed, UncastDisposition Disposition)> Device { get; init; }
        public required List<PreEncryptedUncastBallot> Releases { get; init; }
        public required EncryptedTally Tally { get; init; }
        public required DecryptedTally Decrypted { get; init; }

        public EncryptionRecord Record => Election.Record;
    }

    public static readonly Lazy<Regular> RegularElection = new(BuildRegular);

    public static readonly Lazy<PreEncrypted> PreEncryptedRecord = new(BuildPreEncrypted);

    private static Regular BuildRegular()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true, chainingMode: ChainingMode.Simple);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;

        List<EncryptedBallot> Device(string deviceId, params (string Id, int Choice1, BallotStatus Status, int Weight, DateTimeOffset? At)[] specs)
        {
            var chain = new DeviceChain(record, deviceId);
            var ballots = new List<EncryptedBallot>();
            foreach (var (id, choice1, status, weight, at) in specs)
            {
                var ballot = ElectionFixtureBuilder.CreateEncryptedBallot(record, deviceId, chain.DeviceInformationHash,
                    ElectionFixtureBuilder.CreateBallot(manifest, id, new Dictionary<string, int> { ["choice-1"] = choice1 }, numWriteinsSelected: 0, contestData: WriteIn),
                    chain.PreviousConfirmationCode, BallotStatus.Unrecorded);
                var copy = new EncryptedBallot
                {
                    Id = ballot.Id,
                    SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
                    SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
                    BallotStyleId = ballot.BallotStyleId,
                    Contests = ballot.Contests,
                    ConfirmationCode = ballot.ConfirmationCode,
                    ChainingField = ballot.ChainingField,
                    EncryptedBallotNonce = ballot.EncryptedBallotNonce,
                    DeviceId = ballot.DeviceId,
                    Weight = weight,
                    EncryptionTimestamp = at,
                    Status = status,
                };
                chain.Append(copy);
                ballots.Add(copy);
            }

            return ballots;
        }

        var devices = new List<(string, List<EncryptedBallot>)>
        {
            ("device-1", Device("device-1",
                ("ballot-1", 1, BallotStatus.Cast, 1, Timestamp),
                ("ballot-2", 1, BallotStatus.Cast, 2, null),
                ("ballot-3", 0, BallotStatus.Spoiled, 1, null),
                ("ballot-4", 0, BallotStatus.Challenged, 1, null))),
            ("device-2", Device("device-2", ("ballot-5", 0, BallotStatus.Cast, 1, Timestamp))),
        };

        var all = devices.SelectMany(x => x.Item2).ToList();
        var tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, all.ToArray());
        var guardians = ElectionFixtureBuilder.TallyGuardians(guardianSet);
        var admin = new TallyAdmin();
        var challenged = all.Single(x => x.Status == BallotStatus.Challenged);
        return new Regular
        {
            Record = record,
            Devices = devices,
            Tally = tally,
            Decrypted = admin.Decrypt(guardians, tally, record),
            ContestData = all.Where(x => x.Id is "ballot-1" or "ballot-5").Select(ballot => (ballot, admin.DecryptContestData(guardians, ballot, "contest-1", record))).ToList(),
            Challenged = (challenged, admin.DecryptChallengedBallot(guardians, challenged, record, PublishedCastAndSpoiledBallots.FromRecord(record.ExtendedBaseHash, all))),
        };
    }

    private static PreEncrypted BuildPreEncrypted()
    {
        var election = PreEncryptedElection.Get(ChainingMode.Simple);
        var device = new List<(EncryptedBallot?, PreEncryptedBallot?, UncastDisposition)>();
        var releases = new List<PreEncryptedUncastBallot>();
        var casts = new List<EncryptedBallot>();
        ConfirmationCode? previous = null;

        // Print order: cast, returned in full, never returned, returned with ξ_B released, cast.
        void Cast(string id, int[] contest1, int[] contest2)
        {
            var (printed, cast) = election.Cast(id, contest1, contest2, previous);
            previous = printed.ConfirmationCode;
            device.Add((cast, null, default));
            casts.Add(cast);
        }

        void Uncast(string id, UncastDisposition disposition)
        {
            var uncast = election.Uncast(id, releaseBallotNonce: disposition != UncastDisposition.ReturnedNoncesReleased, previous);
            previous = uncast.Ballot.ConfirmationCode;
            device.Add((null, uncast.Ballot, disposition));
            releases.Add(uncast);
        }

        Cast("pe-cast-1", [2], [1, 3]);
        Uncast("pe-uncast-full", UncastDisposition.ReturnedNoncesReleased);
        Uncast("pe-never-returned", UncastDisposition.NeverReturned);
        Uncast("pe-returned-xi", UncastDisposition.ReturnedBallotNonceReleased);
        Cast("pe-cast-2", [1], [4]);

        var tally = ElectionFixtureBuilder.CreateEncryptedTally(election.Manifest, casts.ToArray());
        return new PreEncrypted
        {
            Election = election,
            Device = device,
            Releases = releases,
            Tally = tally,
            Decrypted = new TallyAdmin().Decrypt(election.Guardians.Take(2).ToList(), tally, election.Record),
        };
    }

    /// <summary>Writes the regular election through every phase; returns the writer's TOC per phase.</summary>
    public static async Task<Dictionary<RecordPhase, TableOfContents>> WriteAsync(Regular election, string directory, RecordEncoding encoding, ElectionRecordWriterOptions? options = null)
    {
        var tocs = new Dictionary<RecordPhase, TableOfContents>();
        await using var writer = ElectionRecord.Create(directory, encoding, options);
        tocs[RecordPhase.Setup] = await writer.WriteSetupAsync(election.Record);
        foreach (var (deviceId, ballots) in election.Devices)
        {
            await using var device = await writer.OpenDeviceAsync(deviceId, DeviceChainBallotKind.Encrypted);
            foreach (var ballot in ballots)
            {
                await device.AppendAsync(ballot);
            }

            await device.CloseAsync(ClosedAt);
        }

        tocs[RecordPhase.Sealed] = await writer.SealVotingAsync();
        var requests = election.ContestData.Select(x => new ContestDataRequest(writer.Locate(x.Ballot.SelectionEncryptionIdentifierHash), x.Ballot.SelectionEncryptionIdentifierHash, x.Data.ContestIndex));
        tocs[RecordPhase.Aggregated] = await writer.SealAggregatedAsync(election.Tally, requests);

        // Added in reverse, so the writer's sort decides the order.
        foreach (var (ballot, data) in Enumerable.Reverse(election.ContestData))
        {
            await writer.AddContestDataDecryptionAsync(ballot, data);
        }

        await writer.AddChallengedDecryptionAsync(election.Challenged.Ballot, election.Challenged.Decrypted);
        tocs[RecordPhase.Final] = await writer.CompleteAsync(election.Decrypted);
        return tocs;
    }

    /// <summary>Writes the pre-encrypted election through every phase; returns the final TOC.</summary>
    public static async Task<TableOfContents> WriteAsync(PreEncrypted election, string directory, RecordEncoding encoding, ElectionRecordWriterOptions? options = null)
    {
        await using var writer = ElectionRecord.Create(directory, encoding, options);
        await writer.WriteSetupAsync(election.Record);
        await using (var device = await writer.OpenDeviceAsync(PreEncryptedElection.DeviceId, DeviceChainBallotKind.PreEncrypted))
        {
            foreach (var (cast, printed, disposition) in election.Device)
            {
                if (cast is not null)
                {
                    await device.AppendAsync(cast);
                }
                else
                {
                    await device.AppendUncastAsync(printed!, disposition);
                }
            }

            await device.CloseAsync(ClosedAt);
        }

        await writer.SealVotingAsync();
        await writer.SealAggregatedAsync(election.Tally, []);
        foreach (var release in Enumerable.Reverse(election.Releases))
        {
            await writer.AddUncastReleaseAsync(release);
        }

        return await writer.CompleteAsync(election.Decrypted);
    }

    /// <summary>A record's domain contents, read back through the mappers (small records only: everything is in memory).</summary>
    public sealed class Contents
    {
        public required RecordSetup Setup { get; init; }
        public required List<(DeviceHeader Header, List<EncryptedBallot> Ballots, List<Pb.RecordItem> Uncast, DeviceClose? Close)> Devices { get; init; }
        public required EncryptedTally Tally { get; init; }
        public required List<ContestDataRequest> Requests { get; init; }
        public required DecryptedTally Decrypted { get; init; }
        public required List<DecryptedChallengedBallot> Challenged { get; init; }
        public required List<DecryptedContestData> ContestData { get; init; }
        public required List<PreEncryptedUncastBallot> Releases { get; init; }
    }

    /// <summary>Reads a final record's contents through the mappers, every item canonical and without a finding.</summary>
    public static async Task<Contents> ReadAsync(IElectionRecordReader reader)
    {
        var setup = await reader.ReadSetupAsync();
        var record = setup.ToEncryptionRecord();
        var manifest = record.Manifest;
        var index = new RecordBallotIndex();
        var devices = new List<(DeviceHeader, List<EncryptedBallot>, List<Pb.RecordItem>, DeviceClose?)>();
        var printed = new Dictionary<BallotLocator, (Pb.RecordItem Item, string DeviceId)>();
        foreach (var key in reader.Devices)
        {
            var section = reader.OpenDevice(key);
            var header = await section.ReadHeaderAsync();
            var ballots = new List<EncryptedBallot>();
            var uncast = new List<Pb.RecordItem>();
            var ids = new List<(string, SelectionEncryptionIdentifierHash)>();
            await foreach (var entry in section.ReadEntriesAsync())
            {
                Assert.True(entry.Check.IsCanonical, entry.Check.Message);
                var item = Pb.RecordItem.Parser.ParseFrom(entry.Bytes.Span);
                if (item.ItemCase is Pb.RecordItem.ItemOneofCase.EncryptedBallot or Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot)
                {
                    var ballot = Value(BallotMapper.FromItem(item, manifest, header.DeviceId));
                    ballots.Add(ballot);
                    ids.Add((ballot.Id, ballot.SelectionEncryptionIdentifierHash));
                }
                else
                {
                    uncast.Add(item);
                    printed[new BallotLocator(key, entry.Ordinal)] = (item, header.DeviceId);
                    var hi = item.ItemCase == Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot ? item.PreEncryptedUncastBallot.HI : item.PreEncryptedCompactUncastBallot.HI;
                    var idB = item.ItemCase == Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot ? item.PreEncryptedUncastBallot.IdB : item.PreEncryptedCompactUncastBallot.IdB;
                    var reference = item.ItemCase == Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot ? item.PreEncryptedUncastBallot.BallotRef : item.PreEncryptedCompactUncastBallot.BallotRef;
                    ids.Add((BallotMapper.Id(reference, idB), SelectionEncryptionIdentifierHash.FromCanonicalBytes(hi.ToByteArray())));
                }
            }

            index.AddDevice(key, ids);
            devices.Add((header, ballots, uncast, await section.ReadCloseAsync()));
        }

        var tallyItems = await Items(reader, RecordSectionType.EncryptedTally);
        var tally = Value(TallyMapper.FromItems(tallyItems[0].EncryptedTallyHeader, tallyItems.Skip(1).Select(x => x.EncryptedTallyContest), manifest));
        var requests = (await Items(reader, RecordSectionType.ContestDataRequests)).Select(x => Value(DecryptionMapper.FromItem(x.ContestDataRequest))).ToList();
        var decrypted = Value(TallyMapper.FromItems((await Items(reader, RecordSectionType.DecryptedTally)).Select(x => x.DecryptedTallyContest)));
        var challenged = (await Items(reader, RecordSectionType.ChallengedBallotDecryptions)).Select(x => Value(DecryptionMapper.FromItem(x.ChallengedBallotDecryption, index, manifest))).ToList();
        var contestData = (await Items(reader, RecordSectionType.ContestDataDecryptions)).Select(x => Value(DecryptionMapper.FromItem(x.ContestDataDecryption, index, manifest))).ToList();
        var releases = (await Items(reader, RecordSectionType.UncastNonceReleases)).Select(release =>
        {
            var locator = DeviceMapper.FromItem(release.UncastNonceRelease.Ballot);
            var (item, deviceId) = printed[locator];
            return Value(UncastMapper.Join(item, release, record, deviceId));
        }).ToList();

        return new Contents
        {
            Setup = setup,
            Devices = devices,
            Tally = tally,
            Requests = requests,
            Decrypted = decrypted,
            Challenged = challenged,
            ContestData = contestData,
            Releases = releases,
        };
    }

    public static async Task<List<Pb.RecordItem>> Items(IElectionRecordReader reader, RecordSectionType type)
    {
        var items = new List<Pb.RecordItem>();
        await foreach (var item in reader.ReadSectionAsync(SectionKey.Of(type)))
        {
            Assert.True(item.Check.IsCanonical, item.Check.Message);
            items.Add(Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span));
        }

        return items;
    }

    private static T Value<T>(RecordDecoded<T> decoded) where T : class
    {
        Assert.Empty(decoded.Findings);
        return decoded.Value!;
    }

    private static readonly string TestRoot = Path.Combine(Path.GetTempPath(), "egrf-tests", $"run-{Environment.ProcessId}-{Guid.NewGuid():N}");

    static RecordCarrierElections()
    {
        // The records the tests write (one has 5,000 ballots) are removed when the test run ends.
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try
            {
                Directory.Delete(TestRoot, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        };
    }

    /// <summary>A fresh, empty directory under this test run's temporary directory (deleted when the run ends).</summary>
    public static string TempDirectory(string name)
    {
        string path = Path.Combine(TestRoot, $"{name}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }
}

internal static class AsyncEnumerableTestExtensions
{
    public static async Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> source)
    {
        var list = new List<T>();
        await foreach (var item in source)
        {
            list.Add(item);
        }

        return list;
    }
}
