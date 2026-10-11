using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using Google.Protobuf;
using System.Buffers.Binary;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>Settings of an <see cref="ElectionRecordWriter"/>; none of them changes a root.</summary>
public sealed record ElectionRecordWriterOptions
{
    /// <summary>The size at which a multi-segment section rolls over to its next segment file (design §5.2; default 256 MiB).</summary>
    public long SegmentSizeBytes { get; init; } = 256L << 20;

    /// <summary>Whether to write the optional plain copy <c>setup/manifest.json</c> (outside the root, design §4.6). Default true.</summary>
    public bool WriteManifestCopy { get; init; } = true;

    /// <summary>Where the join-section sorts spill their runs (default: the system temporary directory).</summary>
    public string? TempDirectory { get; init; }

    /// <summary>The memory a join-section sort holds before it spills a run (default 64 MiB).</summary>
    public long SortBudgetBytes { get; init; } = 64L << 20;
}

/// <summary>What happened to a printed pre-encrypted ballot that was not cast (design §3.2, §8.3; #5, NQ-2).</summary>
public enum UncastDisposition
{
    /// <summary>Printed and never returned: always written in the compact form, and its release is ξ_B (NQ-2).</summary>
    NeverReturned,

    /// <summary>Returned uncast, with ξ_B released (Q28's opt-in): the compact form (user decision R-1).</summary>
    ReturnedBallotNonceReleased,

    /// <summary>Returned uncast, with only the per-selection nonces released: the full form.</summary>
    ReturnedNoncesReleased,
}

/// <summary>
/// A closed device section's digests and close (design §8.3, §4.9): what a chain-close or
/// section-seal statement commits to. <see cref="ChainCloseStatement"/> and
/// <see cref="SectionSealStatement"/> give the canonical bytes to sign (S8b: signing the chain close
/// at close time stops anyone who can rewrite the record from dropping trailing ballots and
/// recomputing the close, under either chaining mode).
/// </summary>
public sealed record DeviceSeal(DeviceKey Key, long ItemCount, Sha256Digest SectionRoot, Sha256Digest CodesRoot)
{
    /// <summary>S_device.</summary>
    public string DeviceId { get; init; } = "";

    public ChainingMode ChainingMode { get; init; }

    /// <summary>ℓ, the ballot items in the section (<see cref="ItemCount"/> is ℓ + 2).</summary>
    public long BallotCount => ItemCount - 2;

    /// <summary>H̄ under simple chaining; null under no chaining.</summary>
    public ConfirmationCode? ClosingHash { get; init; }

    /// <summary>The close's time, if recorded.</summary>
    public DateTimeOffset? ClosedAt { get; init; }

    /// <summary>The canonical bytes of this device's <c>ChainCloseStatement</c> under H_E <paramref name="extendedBaseHash"/> (design §4.9).</summary>
    public byte[] ChainCloseStatement(ExtendedBaseHash extendedBaseHash) =>
        RecordStatements.ChainClose(extendedBaseHash, Key, DeviceId, ChainingMode, BallotCount, CodesRoot, ClosingHash, ClosedAt);

    /// <summary>The canonical bytes of this device's <c>SectionSealStatement</c> under H_E <paramref name="extendedBaseHash"/> (design §4.9).</summary>
    public byte[] SectionSealStatement(ExtendedBaseHash extendedBaseHash) =>
        RecordStatements.SectionSeal(extendedBaseHash, Key, ItemCount, SectionRoot);
}

/// <summary>
/// Writes an election record into a directory (design §5.3, §8.3), phase by phase, so that an
/// administrator can publish and seal it progressively:
/// <list type="number">
/// <item><see cref="WriteSetupAsync(EncryptionRecord, CancellationToken)"/>: the setup sections; fixes R_setup.</item>
/// <item><see cref="OpenDeviceAsync(string, DeviceChainBallotKind, CancellationToken)"/> per device, ballots appended
/// in chain order, each device closed; then <see cref="SealVotingAsync"/>: fixes R_sealed.</item>
/// <item><see cref="SealAggregatedAsync"/>: the encrypted tally and the contest-data requests; fixes R_aggregated.</item>
/// <item>The decryptions and uncast releases (refused before R_aggregated: Q36, guardians decrypt only a sealed
/// record), then <see cref="CompleteAsync"/>: the decrypted tally and the sorted join sections; fixes R_final.</item>
/// </list>
/// Each phase writes the claimed TOC (<c>toc.&lt;ext&gt;</c>), and each new TOC extends the previous one.
/// Everything streams: an item is written and folded into its section's Merkle frontier, and nothing
/// of it is kept. The writer keeps one small entry per ballot (H_I, locator, status, form; about
/// 100 bytes) to place and check the final-phase items, and the join sections are sorted through a
/// spilling sort. The writer is not a verifier: it refuses what an honest record cannot hold (a
/// broken chain, a ballot structure violation, an unrecorded status, a decryption of a ballot that is
/// not challenged, a release of the wrong form, a missing decryption or release at completion), but
/// it does not check proofs.
/// </summary>
public sealed partial class ElectionRecordWriter : IAsyncDisposable
{
    private readonly object _lock = new();
    private readonly SemaphoreSlim _finalGate = new(1, 1);
    private readonly SemaphoreSlim _signatureGate = new(1, 1);
    private readonly DirectoryRecordSink _sink;
    private readonly ElectionRecordWriterOptions _options;
    private readonly List<TocEntry> _entries = [];
    private readonly Dictionary<SectionKey, DeviceSectionWriter> _openDevices = [];
    private readonly HashSet<SectionKey> _closedDevices = [];
    private readonly Dictionary<Sha256Digest, BallotEntry> _ballots = [];
    private readonly Dictionary<(Sha256Digest IdentifierHash, int Contest), bool> _requests = [];
    private readonly HashSet<(string Device, int Member, Sha256Digest Statement, string Item)> _attestations = [];
    private SortedSpool? _challenged;
    private SortedSpool? _contestData;
    private SortedSpool? _releases;
    private EncryptionRecord? _record;

    internal enum BallotForm : byte
    {
        Regular,
        PreEncryptedCast,
        UncastFull,
        UncastCompact,
    }

    internal sealed class BallotEntry(BallotLocator locator, BallotStatus status, BallotForm form)
    {
        public BallotLocator Locator { get; } = locator;
        public BallotStatus Status { get; } = status;
        public BallotForm Form { get; } = form;
        public bool Opened { get; set; }
    }

    private ElectionRecordWriter(string directory, RecordEncoding encoding, ElectionRecordWriterOptions options)
    {
        _sink = new DirectoryRecordSink(directory);
        Encoding = encoding;
        _options = options;
    }

    /// <summary>
    /// A writer of a new record in <paramref name="directory"/>, which must not exist or be empty.
    /// </summary>
    public static ElectionRecordWriter Create(string directory, RecordEncoding encoding, ElectionRecordWriterOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        if (System.IO.Directory.Exists(directory) && System.IO.Directory.EnumerateFileSystemEntries(directory).Any())
        {
            throw new IOException($"{directory} is not empty; a record is written into an empty directory.");
        }

        System.IO.Directory.CreateDirectory(directory);
        return new ElectionRecordWriter(directory, encoding, options ?? new ElectionRecordWriterOptions());
    }

    public RecordEncoding Encoding { get; }

    /// <summary>The record's directory.</summary>
    public string Directory => _sink.Root;

    /// <summary>The phase the record is at (the last root fixed); null before the setup is written.</summary>
    public RecordPhase? Phase { get; private set; }

    /// <summary>The table of contents as of <see cref="Phase"/>.</summary>
    public TableOfContents? Toc { get; private set; }

    internal EncryptionRecord Record => _record ?? throw new InvalidOperationException("The setup is not written yet.");

    internal ElectionRecordWriterOptions Options => _options;

    internal DirectoryRecordSink Sink => _sink;

    /// <summary>Writes the setup sections of <paramref name="record"/> (format v2.0) and fixes R_setup.</summary>
    public ValueTask<TableOfContents> WriteSetupAsync(EncryptionRecord record, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return WriteSetupAsync(RecordSetup.FromEncryptionRecord(record), ct);
    }

    /// <summary>
    /// Writes the setup sections and fixes R_setup. The manifest bytes are stored exactly as given
    /// (#19); they are parsed first, and a document the manifest parser refuses (a BOM, a duplicate
    /// key, a manifest <see cref="Manifest.Validate"/> refuses) throws <see cref="InvalidManifestException"/>
    /// and nothing is written, since it would make the record unverifiable (design §4.6).
    /// </summary>
    public async ValueTask<TableOfContents> WriteSetupAsync(RecordSetup setup, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(setup);
        RequirePhase(null, "write the setup");
        if (setup.ManifestMediaType != RecordSetup.ManifestMediaTypeFormat1)
        {
            throw new ArgumentException($"The manifest's media type is \"{setup.ManifestMediaType}\"; this writer stores \"{RecordSetup.ManifestMediaTypeFormat1}\".", nameof(setup));
        }

        _ = ManifestSerializer.Deserialize(setup.ManifestFile.Bytes);
        var record = setup.ToEncryptionRecord();
        var items = SetupMapper.ToItems(setup);

        await WriteSectionAsync(SectionKey.Of(RecordSectionType.Header), [items[0]], ct).ConfigureAwait(false);
        await WriteSectionAsync(SectionKey.Of(RecordSectionType.Parameters), [items[1]], ct).ConfigureAwait(false);
        await WriteSectionAsync(SectionKey.Of(RecordSectionType.Manifest), [items[2]], ct).ConfigureAwait(false);
        await WriteSectionAsync(SectionKey.Of(RecordSectionType.Guardians), items.Skip(3).SkipLast(1), ct).ConfigureAwait(false);
        await WriteSectionAsync(SectionKey.Of(RecordSectionType.ElectionKeys), [items[^1]], ct).ConfigureAwait(false);
        if (_options.WriteManifestCopy)
        {
            // Outside the root, but a reader checks it byte for byte, so it is as durable as R_setup.
            await using var copy = _sink.Create(RecordLayout.ManifestCopyPath, compressible: true);
            await copy.WriteAsync(setup.ManifestFile.Bytes, ct).ConfigureAwait(false);
            ((FileStream)copy).Flush(flushToDisk: true);
        }

        _record = record;
        return await FixPhaseAsync(RecordPhase.Setup, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Opens the device section of <paramref name="deviceId"/> for ballots of <paramref name="kind"/>:
    /// its header (H_DI by eq. 72 or 119, the manifest's chaining mode, H_0 under simple chaining) is
    /// written at once. Only before the voting seal; a device is opened once.
    /// </summary>
    public ValueTask<DeviceSectionWriter> OpenDeviceAsync(string deviceId, DeviceChainBallotKind kind, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(deviceId);
        var record = Record;
        var hash = kind == DeviceChainBallotKind.PreEncrypted
            ? VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, deviceId)
            : new VotingDeviceInformationHash(record.ExtendedBaseHash, deviceId);
        var mode = record.Manifest.ChainingMode;
        ConfirmationCode? initial = mode == ChainingMode.None ? null
            : kind == DeviceChainBallotKind.PreEncrypted ? ChainingField.InitialHashForPreEncryptedBallots(hash, record.ExtendedBaseHash)
            : ChainingField.InitialHash(hash, record.ExtendedBaseHash);
        return OpenDeviceAsync(new DeviceHeader(kind, deviceId, hash, mode, initial), ct);
    }

    /// <summary>
    /// Opens the device section that <paramref name="header"/> describes; throws
    /// <see cref="ArgumentException"/> unless its H_DI, chaining mode and H_0 are the ones its device id,
    /// kind and the manifest give.
    /// </summary>
    public async ValueTask<DeviceSectionWriter> OpenDeviceAsync(DeviceHeader header, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(header);
        RequirePhase(RecordPhase.Setup, "open a device");
        var record = Record;
        bool pre = header.Kind == DeviceChainBallotKind.PreEncrypted;
        var hash = pre
            ? VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, header.DeviceId)
            : new VotingDeviceInformationHash(record.ExtendedBaseHash, header.DeviceId);
        if (header.DeviceInformationHash != hash)
        {
            throw new ArgumentException($"Device {header.DeviceId}'s H_DI is not eq. ({(pre ? 119 : 72)})'s for it.", nameof(header));
        }

        if (header.ChainingMode != record.Manifest.ChainingMode)
        {
            throw new ArgumentException($"Device {header.DeviceId} states chaining mode {header.ChainingMode}; the manifest's is {record.Manifest.ChainingMode} (design §4.6).", nameof(header));
        }

        ConfirmationCode? initial = header.ChainingMode == ChainingMode.None ? null
            : pre ? ChainingField.InitialHashForPreEncryptedBallots(hash, record.ExtendedBaseHash) : ChainingField.InitialHash(hash, record.ExtendedBaseHash);
        if (header.InitialHash != initial)
        {
            throw new ArgumentException($"Device {header.DeviceId}'s H_0 is not eq. ({(pre ? 117 : 74)})'s{(initial is null ? ": no chaining has none" : "")}.", nameof(header));
        }

        var section = SectionKey.Device(header.Key);
        DeviceSectionWriter device;
        lock (_lock)
        {
            // A device section a resumed writer found open is handed to the first caller that opens it again.
            if (_openDevices.TryGetValue(section, out var open) && open.Resumed && open.Header.DeviceId == header.DeviceId)
            {
                open.Resumed = false;
                return open;
            }

            if (_openDevices.ContainsKey(section) || _closedDevices.Contains(section))
            {
                throw new InvalidOperationException($"Device {header.DeviceId} ({section}) is already in the record.");
            }

            device = new DeviceSectionWriter(this, header, new SectionWriter(_sink, section, Encoding, _options.SegmentSizeBytes));
            _openDevices[section] = device;
        }

        await device.WriteHeaderAsync(ct).ConfigureAwait(false);
        return device;
    }

    /// <summary>
    /// Adds a device attestation (design §4.9): a chain-close, section-seal or prefix-checkpoint
    /// statement, signed by the device or the collector receiving from it, written into the
    /// <c>device_attestations</c> section when voting is sealed (inside R_sealed; nothing may be added
    /// to it afterwards, so late countersignatures go in the detached signatures layer). Refused
    /// (<see cref="ArgumentException"/>) unless the item is canonical with a statement of member 40-42
    /// (<see cref="CanonicalProtobuf.CheckSignedStatement"/>), under this election's H_E, for a device
    /// the writer opened, and not added before. The writer checks no signature and no statement content
    /// beyond that; the verifier checks both. Attestations are kept in memory until the seal, so after
    /// <see cref="ResumeAsync"/> they must be added again. A device that then closes with no ballots has
    /// no section (Q25), so its attestations are dropped when it closes.
    /// </summary>
    public ValueTask AddAttestationAsync(SignedStatement attestation, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        RequirePhase(RecordPhase.Setup, "add a device attestation");
        byte[] item = attestation.ToDeviceAttestationItem();
        var check = CanonicalProtobuf.CheckSignedStatement(item, RecordFormatVersion.Library.Minor);
        if (!check.IsCanonical)
        {
            throw new ArgumentException($"The attestation is not a canonical signed statement ({check.Rule}): {check.Message}", nameof(attestation));
        }

        var statement = Pb.RecordItem.Parser.ParseFrom(attestation.Statement.Span);
        var (he, deviceKey) = statement.ItemCase switch
        {
            Pb.RecordItem.ItemOneofCase.ChainCloseStatement => (statement.ChainCloseStatement.HE, statement.ChainCloseStatement.DeviceKey),
            Pb.RecordItem.ItemOneofCase.SectionSealStatement => (statement.SectionSealStatement.HE, statement.SectionSealStatement.DeviceKey),
            _ => (statement.PrefixCheckpointStatement.HE, statement.PrefixCheckpointStatement.DeviceKey),
        };

        if (!he.Span.SequenceEqual((byte[])Record.ExtendedBaseHash))
        {
            throw new ArgumentException("The attestation's statement is under another election's H_E.", nameof(attestation));
        }

        var section = new SectionKey(RecordSectionType.Device, deviceKey.Span);
        lock (_lock)
        {
            if (!_openDevices.ContainsKey(section) && !_closedDevices.Contains(section))
            {
                throw new ArgumentException($"The attestation names device {section}, which the writer has not opened.", nameof(attestation));
            }

            var key = (Convert.ToHexStringLower(deviceKey.Span), (int)statement.ItemCase, attestation.StatementDigest, Convert.ToHexStringLower(item));
            if (!_attestations.Add(key))
            {
                throw new ArgumentException("The record already holds this attestation.", nameof(attestation));
            }
        }

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Adds a detached record signature (design §4.9; §3.7 "together with the date"): a signed
    /// <c>RecordStatement</c> over a phase root this writer has fixed, under this election's H_E and
    /// this library's format version, written to <c>signatures/&lt;phase&gt;-&lt;SHA-256(statement)&gt;</c>
    /// outside every root, so it may be added at any later time (another signer of the same statement
    /// joins its file). Refused (<see cref="ArgumentException"/>) unless canonical, of member 43, and
    /// naming the root the writer returned for that phase. The signature itself is not checked here.
    /// Adds through one writer are serialized (the file is read, merged and replaced); writers in
    /// different processes adding to the same record must coordinate among themselves.
    /// </summary>
    public async ValueTask AddRecordSignatureAsync(SignedStatement signature, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        await _signatureGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await AddRecordSignatureLockedAsync(signature, ct).ConfigureAwait(false);
        }
        finally
        {
            _signatureGate.Release();
        }
    }

    private async ValueTask AddRecordSignatureLockedAsync(SignedStatement signature, CancellationToken ct)
    {
        byte[] item = signature.ToRecordSignatureItem();
        var check = CanonicalProtobuf.CheckSignedStatement(item, RecordFormatVersion.Library.Minor);
        if (!check.IsCanonical)
        {
            throw new ArgumentException($"The record signature is not a canonical signed statement ({check.Rule}): {check.Message}", nameof(signature));
        }

        var statement = Pb.RecordItem.Parser.ParseFrom(signature.Statement.Span).RecordStatement;
        var phase = (RecordPhase)(int)statement.Phase;
        var toc = Toc;
        if (toc is null || Phase is null || phase > Phase || !statement.Root.Span.SequenceEqual(toc.PhaseRoot(phase).ToArray()))
        {
            throw new ArgumentException($"The record statement names phase {phase} with a root that is not the one this writer fixed for it.", nameof(signature));
        }

        if (!statement.HE.Span.SequenceEqual((byte[])Record.ExtendedBaseHash) || statement.FormatMajor != RecordFormatVersion.Library.Major || statement.FormatMinor != RecordFormatVersion.Library.Minor)
        {
            throw new ArgumentException("The record statement names another election's H_E or another format version.", nameof(signature));
        }

        string path = RecordLayout.SignaturePath(phase, signature.StatementDigest, Encoding);
        string full = Path.Combine(_sink.Root, path);
        var items = new List<byte[]>();
        if (File.Exists(full))
        {
            await using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
            var lines = Encoding == RecordEncoding.Json ? new ElectionRecordReader.LineReader(stream, path) : null;
            bool header = true;
            while (true)
            {
                byte[]? existing = lines is null
                    ? await SegmentFraming.ReadFrameAsync(stream, path, ct).ConfigureAwait(false)
                    : await lines.NextAsync(ct).ConfigureAwait(false) is { } line ? (header ? line : RecordJson.ParseItem(line, RecordFormatVersion.Library.Minor)) : null;
                if (existing is null)
                {
                    break;
                }

                if (header)
                {
                    header = false;
                    continue;
                }

                if (existing.AsSpan().SequenceEqual(item))
                {
                    throw new ArgumentException("The record already holds this signature.", nameof(signature));
                }

                items.Add(existing);
            }
        }

        items.Add(item);
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        // One fixed name (the adds are serialized), so a temporary file a crash left is replaced by the
        // next add rather than left in the record; a failed write removes its own.
        string temporary = full + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await WritePseudoSectionAsync(stream, Pb.SectionType.Signatures, items, Encoding, ct).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, full, overwrite: true);
        }
        catch
        {
            File.Delete(temporary);
            throw;
        }
    }

    /// <summary>
    /// Seals voting: every opened device must be closed. Writes the device attestations section (the
    /// attestations added, ascending by device key, statement member and SHA-256 of the statement,
    /// design §4.5) and fixes R_sealed.
    /// </summary>
    public async ValueTask<TableOfContents> SealVotingAsync(CancellationToken ct = default)
    {
        RequirePhase(RecordPhase.Setup, "seal voting");
        List<Pb.RecordItem> attestations;
        lock (_lock)
        {
            if (_openDevices.Count > 0)
            {
                throw new InvalidOperationException($"{_openDevices.Count} device(s) are still open; close every device before sealing voting ({string.Join(", ", _openDevices.Values.Select(x => x.Header.DeviceId))}).");
            }

            // Every attestation names a closed device with a section: AddAttestationAsync takes one
            // only for an opened device, and a device that closes empty drops its own (DeviceClosed).
            attestations = _attestations
                .OrderBy(x => x.Device, StringComparer.Ordinal)
                .ThenBy(x => x.Member)
                .ThenBy(x => x.Statement)
                .ThenBy(x => x.Item, StringComparer.Ordinal)
                .Select(x => Pb.RecordItem.Parser.ParseFrom(Convert.FromHexString(x.Item)))
                .ToList();
        }

        await WriteSectionAsync(SectionKey.Of(RecordSectionType.DeviceAttestations), attestations, ct).ConfigureAwait(false);
        return await FixPhaseAsync(RecordPhase.Sealed, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Writes the encrypted tally (its header and one contest per manifest contest) and the
    /// contest-data requests (§3.6.1, follow-up #10: sealed before any decryption), and fixes
    /// R_aggregated. Each request must name a cast regular ballot of the record by its locator and
    /// H_I, and a contest with contest data; the requests are written sorted by (locator, contest
    /// index), each once. A tally or request that is refused (<see cref="ArgumentException"/>) is
    /// refused before anything is written or remembered, so the call can be made again with the
    /// input corrected; a failure while the sections are being written is repaired by
    /// <see cref="ResumeAsync"/> (design §5.2).
    /// </summary>
    public async ValueTask<TableOfContents> SealAggregatedAsync(EncryptedTally tally, IEnumerable<ContestDataRequest> requests, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(tally);
        ArgumentNullException.ThrowIfNull(requests);
        RequirePhase(RecordPhase.Sealed, "seal the aggregate");
        var manifest = Record.Manifest;

        // Everything is checked before the writer remembers any of it: the tally's items are built
        // first, and the requests are collected here and recorded only once both sections are written.
        var tallyItems = TallyMapper.ToItems(tally);
        var requested = new HashSet<(Sha256Digest IdentifierHash, int Contest)>();
        await using var sorted = new SortedSpool(_options.TempDirectory, _options.SortBudgetBytes);
        foreach (var request in requests)
        {
            ArgumentNullException.ThrowIfNull(request);
            var entry = Find(request.IdentifierHash, "The contest-data request");
            if (entry.Locator != request.Ballot || entry.Form != BallotForm.Regular || entry.Status != BallotStatus.Cast)
            {
                throw new ArgumentException($"A contest-data request names the ballot at position {request.Ballot.Position} with H_I {request.IdentifierHash}; a request names a cast regular ballot by its own locator (design §6.2).", nameof(requests));
            }

            if (manifest.Contests.SingleOrDefault(x => x.Index == request.ContestIndex) is not { ContestDataBlocks: > 0 })
            {
                throw new ArgumentException($"A contest-data request names contest index {request.ContestIndex}, which carries no contest data.", nameof(requests));
            }

            if (!requested.Add((Key(request.IdentifierHash), request.ContestIndex)))
            {
                throw new ArgumentException($"Contest {request.ContestIndex} of the ballot with H_I {request.IdentifierHash} is requested twice.", nameof(requests));
            }

            await sorted.AddAsync(SortKey(request.Ballot, request.ContestIndex), DecryptionMapper.ToItem(request).ToByteArray(), ct).ConfigureAwait(false);
        }

        await WriteSectionAsync(SectionKey.Of(RecordSectionType.EncryptedTally), tallyItems, ct).ConfigureAwait(false);
        await WriteSortedAsync(SectionKey.Of(RecordSectionType.ContestDataRequests), sorted, "The contest-data requests", ct).ConfigureAwait(false);
        lock (_lock)
        {
            foreach (var request in requested)
            {
                _requests.Add(request, false);
            }
        }

        _challenged = new SortedSpool(_options.TempDirectory, _options.SortBudgetBytes);
        _contestData = new SortedSpool(_options.TempDirectory, _options.SortBudgetBytes);
        _releases = new SortedSpool(_options.TempDirectory, _options.SortBudgetBytes);
        return await FixPhaseAsync(RecordPhase.Aggregated, ct).ConfigureAwait(false);
    }

    /// <summary>The locator of the ballot whose H_I is <paramref name="identifierHash"/>.</summary>
    public BallotLocator Locate(SelectionEncryptionIdentifierHash identifierHash) => Find(identifierHash, "The lookup").Locator;

    /// <summary>
    /// Adds the decryption of the challenged regular <paramref name="ballot"/> (§3.6.7). Only after
    /// R_aggregated (Q36). Throws unless the record holds the ballot as challenged and it is not yet
    /// decrypted, or (<see cref="ArgumentException"/>) when the decryption's indices and labels are
    /// not the manifest's.
    /// </summary>
    public async ValueTask AddChallengedDecryptionAsync(EncryptedBallot ballot, DecryptedChallengedBallot decrypted, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(decrypted);
        RequirePhase(RecordPhase.Aggregated, "add a challenged ballot's decryption");
        var entry = Find(ballot.SelectionEncryptionIdentifierHash, $"Challenged ballot {ballot.Id}");
        if (entry.Form != BallotForm.Regular || entry.Status != BallotStatus.Challenged)
        {
            throw new ArgumentException($"Ballot {ballot.Id} is recorded as {entry.Status} ({entry.Form}); only a challenged regular ballot is decrypted (§3.6.7, Q31).", nameof(ballot));
        }

        var item = DecryptionMapper.ToItem(decrypted, ballot, entry.Locator, Record.Manifest).ToByteArray();
        await AddFinalItemAsync(() => MarkOpened(entry, $"Challenged ballot {ballot.Id}"), _challenged!, SortKey(entry.Locator, null), item, () => entry.Opened = false, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Adds a contest-data decryption (§3.6.6). Only after R_aggregated; it must answer a sealed
    /// request, once.
    /// </summary>
    public async ValueTask AddContestDataDecryptionAsync(EncryptedBallot ballot, DecryptedContestData decrypted, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(decrypted);
        RequirePhase(RecordPhase.Aggregated, "add a contest-data decryption");
        var entry = Find(ballot.SelectionEncryptionIdentifierHash, $"Ballot {ballot.Id}");
        var request = (Key(ballot.SelectionEncryptionIdentifierHash), decrypted.ContestIndex);

        // Built (and so checked: the decryption must be of this ballot) before the request is marked.
        var item = DecryptionMapper.ToItem(decrypted, ballot, entry.Locator).ToByteArray();
        await AddFinalItemAsync(MarkRequest, _contestData!, SortKey(entry.Locator, decrypted.ContestIndex), item, () => _requests[request] = false, ct).ConfigureAwait(false);

        void MarkRequest()
        {
            lock (_lock)
            {
                if (!_requests.TryGetValue(request, out bool done))
                {
                    throw new ArgumentException($"No sealed request asks for contest {decrypted.ContestIndex} of ballot {ballot.Id} (follow-up #10: only requested contest data is decrypted).", nameof(decrypted));
                }

                if (done)
                {
                    throw new ArgumentException($"Contest {decrypted.ContestIndex} of ballot {ballot.Id} is already decrypted.", nameof(decrypted));
                }

                _requests[request] = true;
            }
        }
    }

    /// <summary>
    /// Adds the opening of an uncast pre-encrypted ballot (§4.3; design §3.2): ξ_B for one written in
    /// the compact form, the per-selection nonces for one written in full. Only after R_aggregated;
    /// a release of the other form than the sealed item's is refused (<see cref="ArgumentException"/>; NQ-2, R-1).
    /// </summary>
    public async ValueTask AddUncastReleaseAsync(PreEncryptedUncastBallot uncast, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(uncast);
        ArgumentNullException.ThrowIfNull(uncast.Ballot);
        RequirePhase(RecordPhase.Aggregated, "add an uncast ballot's release");
        var entry = Find(uncast.Ballot.SelectionEncryptionIdentifierHash, $"Uncast ballot {uncast.Ballot.Id}");
        bool compact = uncast.BallotNonce is not null;
        if (entry.Form is not (BallotForm.UncastCompact or BallotForm.UncastFull))
        {
            throw new ArgumentException($"Ballot {uncast.Ballot.Id} is not an uncast pre-encrypted ballot of the record.", nameof(uncast));
        }

        if (compact != (entry.Form == BallotForm.UncastCompact))
        {
            throw new ArgumentException($"Uncast ballot {uncast.Ballot.Id} was sealed in the {(entry.Form == BallotForm.UncastCompact ? "compact form, so its release is ξ_B" : "full form, so its release is the per-selection nonces")}, and this release is the other form (user decisions NQ-2, R-1).", nameof(uncast));
        }

        var (_, release) = UncastMapper.Split(uncast, entry.Locator);
        byte[] item = release.ToByteArray();
        await AddFinalItemAsync(() => MarkOpened(entry, $"Uncast ballot {uncast.Ballot.Id}"), _releases!, SortKey(entry.Locator, null), item, () => entry.Opened = false, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Adds a built final-phase item to its join section's spool. The final-phase adds and
    /// <see cref="CompleteAsync"/> take turns through one gate, so concurrent adds on one writer are
    /// safe and none can land while the record is being completed: under it, the phase is checked
    /// again, <paramref name="mark"/> marks the ballot or request done (refusing a second item for
    /// it), and the item goes into the spool. If the item does not get into the spool,
    /// <paramref name="unmark"/> takes the mark back, so <see cref="CompleteAsync"/> still counts it
    /// as missing and a retry is accepted.
    /// </summary>
    private async ValueTask AddFinalItemAsync(Action mark, SortedSpool spool, byte[] key, byte[] item, Action unmark, CancellationToken ct)
    {
        await _finalGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            RequirePhase(RecordPhase.Aggregated, "add a final-phase item");
            mark();
            try
            {
                await spool.AddAsync(key, item, ct).ConfigureAwait(false);
            }
            catch
            {
                lock (_lock)
                {
                    unmark();
                }

                throw;
            }
        }
        finally
        {
            _finalGate.Release();
        }
    }

    /// <summary>
    /// Completes the record: every challenged ballot has its decryption (#8), every uncast
    /// pre-encrypted ballot its release (#5) and every request its decryption (#10), or
    /// <see cref="InvalidOperationException"/>. Writes the decrypted tally and the join sections
    /// (sorted by locator) and fixes R_final.
    /// </summary>
    public async ValueTask<TableOfContents> CompleteAsync(DecryptedTally tally, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(tally);
        RequirePhase(RecordPhase.Aggregated, "complete the record");

        // No final-phase add runs while the record is completed (they take turns through this gate).
        await _finalGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            RequirePhase(RecordPhase.Aggregated, "complete the record");
            int challenged, uncast, requests, challengedDone, uncastDone, requestsDone;
            lock (_lock)
            {
                challenged = _ballots.Values.Count(x => x.Form == BallotForm.Regular && x.Status == BallotStatus.Challenged && !x.Opened);
                uncast = _ballots.Values.Count(x => x.Form is BallotForm.UncastCompact or BallotForm.UncastFull && !x.Opened);
                requests = _requests.Values.Count(x => !x);
                challengedDone = _ballots.Values.Count(x => x.Form == BallotForm.Regular && x.Status == BallotStatus.Challenged && x.Opened);
                uncastDone = _ballots.Values.Count(x => x.Form is BallotForm.UncastCompact or BallotForm.UncastFull && x.Opened);
                requestsDone = _requests.Values.Count(x => x);
            }

            if (challenged + uncast + requests > 0)
            {
                throw new InvalidOperationException($"The record cannot be completed: {challenged} challenged ballot(s) without a decryption (#8), {uncast} uncast pre-encrypted ballot(s) without a release (#5) and {requests} contest-data request(s) without a decryption (#10).");
            }

            // A backstop: every mark has its item in the spool, so no join section is fixed short.
            if (_challenged!.Count != challengedDone || _contestData!.Count != requestsDone || _releases!.Count != uncastDone)
            {
                throw new InvalidOperationException($"The record cannot be completed: the join sections hold {_challenged.Count}, {_contestData!.Count} and {_releases!.Count} items for {challengedDone} decrypted challenged ballot(s), {requestsDone} answered request(s) and {uncastDone} released uncast ballot(s).");
            }

            await WriteSectionAsync(SectionKey.Of(RecordSectionType.DecryptedTally), TallyMapper.ToItems(tally), ct).ConfigureAwait(false);
            await WriteSortedAsync(SectionKey.Of(RecordSectionType.ChallengedBallotDecryptions), _challenged, "The challenged ballot decryptions", ct).ConfigureAwait(false);
            await WriteSortedAsync(SectionKey.Of(RecordSectionType.ContestDataDecryptions), _contestData, "The contest-data decryptions", ct).ConfigureAwait(false);
            await WriteSortedAsync(SectionKey.Of(RecordSectionType.UncastNonceReleases), _releases, "The uncast nonce releases", ct).ConfigureAwait(false);
            return await FixPhaseAsync(RecordPhase.Final, ct).ConfigureAwait(false);
        }
        finally
        {
            _finalGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var device in _openDevices.Values.ToList())
        {
            await device.DisposeAsync().ConfigureAwait(false);
        }

        foreach (var spool in new[] { _challenged, _contestData, _releases })
        {
            if (spool is not null)
            {
                await spool.DisposeAsync().ConfigureAwait(false);
            }
        }

        _sink.Dispose();
    }

    // ---- internal: the device writers' calls --------------------------------------------------------

    internal void RequireVoting(string action) => RequirePhase(RecordPhase.Setup, action);

    internal void AddBallot(SelectionEncryptionIdentifierHash identifierHash, BallotEntry entry)
    {
        lock (_lock)
        {
            if (!_ballots.TryAdd(Key(identifierHash), entry))
            {
                throw new ArgumentException($"The record already holds a ballot with H_I {identifierHash}, so the two share id_B (5.A).");
            }
        }
    }

    /// <summary>Takes back an index entry whose item was not written (the device writer's append failed).</summary>
    internal void RemoveBallot(SelectionEncryptionIdentifierHash identifierHash, BallotEntry entry)
    {
        lock (_lock)
        {
            var key = Key(identifierHash);
            if (_ballots.TryGetValue(key, out var held) && ReferenceEquals(held, entry))
            {
                _ballots.Remove(key);
            }
        }
    }

    internal void DeviceClosed(DeviceSectionWriter device, TocEntry? entry)
    {
        lock (_lock)
        {
            var section = SectionKey.Device(device.Key);
            _openDevices.Remove(section);
            if (entry is not null)
            {
                _closedDevices.Add(section);
                _entries.Add(entry);
            }
            else
            {
                // Q25: a device that appended nothing has no section, so nothing attests to it; the
                // attestations added while it was open (a prefix checkpoint at count 0) are dropped
                // rather than left to block the seal.
                string key = Convert.ToHexStringLower(section.Key.Span);
                _attestations.RemoveWhere(x => x.Device == key);
            }
        }
    }

    // ---- helpers -------------------------------------------------------------------------------------

    private void RequirePhase(RecordPhase? phase, string action)
    {
        if (Phase != phase)
        {
            throw new InvalidOperationException($"Cannot {action}: the record is at phase {Phase?.ToString() ?? "(none)"}, and this needs phase {phase?.ToString() ?? "(none: a new record)"} (design §4.9{(phase == RecordPhase.Aggregated ? "; Q36: guardians decrypt only a sealed, aggregated record" : "")}).");
        }
    }

    private BallotEntry Find(SelectionEncryptionIdentifierHash identifierHash, string what)
    {
        ArgumentNullException.ThrowIfNull(identifierHash);
        lock (_lock)
        {
            return _ballots.TryGetValue(Key(identifierHash), out var entry)
                ? entry
                : throw new ArgumentException($"{what} names a ballot (H_I {identifierHash}) that the record does not hold.");
        }
    }

    private void MarkOpened(BallotEntry entry, string what)
    {
        lock (_lock)
        {
            if (entry.Opened)
            {
                throw new ArgumentException($"{what} is already opened in the record (each appears once, design §4.5).");
            }

            entry.Opened = true;
        }
    }

    internal static Sha256Digest Key(SelectionEncryptionIdentifierHash identifierHash) => Sha256Digest.FromBytes((byte[])identifierHash);

    /// <summary>The join sections' sort key: kind, H_DI, position (8 bytes big-endian), then the contest index when there is one.</summary>
    private static byte[] SortKey(BallotLocator locator, int? contestIndex)
    {
        byte[] key = new byte[DeviceKey.ByteLength + 8 + (contestIndex is null ? 0 : 4)];
        locator.Device.ToBytes().CopyTo(key, 0);
        BinaryPrimitives.WriteInt64BigEndian(key.AsSpan(DeviceKey.ByteLength), locator.Position);
        if (contestIndex is { } index)
        {
            BinaryPrimitives.WriteInt32BigEndian(key.AsSpan(DeviceKey.ByteLength + 8), index);
        }

        return key;
    }

    private async ValueTask WriteSectionAsync(SectionKey section, IEnumerable<Pb.RecordItem> items, CancellationToken ct)
    {
        await using var writer = new SectionWriter(_sink, section, Encoding, _options.SegmentSizeBytes);
        foreach (var item in items)
        {
            await writer.AppendAsync(item, ct).ConfigureAwait(false);
        }

        var entry = await writer.CompleteAsync(critical: true, ct).ConfigureAwait(false);
        lock (_lock)
        {
            _entries.Add(entry);
        }
    }

    private async ValueTask WriteSortedAsync(SectionKey section, SortedSpool spool, string what, CancellationToken ct)
    {
        await using var writer = new SectionWriter(_sink, section, Encoding, _options.SegmentSizeBytes);
        await foreach (var (_, item) in spool.MergeAsync(what, ct).ConfigureAwait(false))
        {
            await writer.AppendAsync(item, default, ct).ConfigureAwait(false);
        }

        var entry = await writer.CompleteAsync(critical: true, ct).ConfigureAwait(false);
        lock (_lock)
        {
            _entries.Add(entry);
        }
    }

    private async ValueTask<TableOfContents> FixPhaseAsync(RecordPhase phase, CancellationToken ct)
    {
        TableOfContents toc;
        lock (_lock)
        {
            toc = new TableOfContents(_entries.Order(Comparer<TocEntry>.Create(TocEntry.CompareSections)));
        }

        if (toc.Phase != phase || (Toc is not null && !toc.Extends(Toc)))
        {
            throw new InvalidOperationException($"The table of contents at phase {phase} does not extend the one at phase {Phase} (design §4.9).");
        }

        await WriteTocAsync(_sink.Root, toc, Encoding, ct).ConfigureAwait(false);
        Toc = toc;
        Phase = phase;
        return toc;
    }

    /// <summary>
    /// Writes <c>toc.&lt;ext&gt;</c> (the claimed TOC), replacing any earlier one atomically: a
    /// temporary file, flushed to the disk before it is renamed over the old one, so the rename never
    /// lands before the bytes it names (design §5.2). Every section the TOC lists was flushed to the
    /// disk when it was completed.
    /// </summary>
    internal static async ValueTask WriteTocAsync(string root, TableOfContents toc, RecordEncoding encoding, CancellationToken ct)
    {
        string path = Path.Combine(root, RecordLayout.TocPath(encoding));
        string temporary = path + ".tmp";
        await using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await WriteTocAsync(stream, toc, encoding, ct).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporary, path, overwrite: true);
    }

    /// <summary>Writes the TOC pseudo-section (type 0xFFFE) to <paramref name="stream"/>.</summary>
    internal static ValueTask WriteTocAsync(Stream stream, TableOfContents toc, RecordEncoding encoding, CancellationToken ct) =>
        WritePseudoSectionAsync(stream, Pb.SectionType.Toc, toc.Entries.Select(x => x.ToRecordItemBytes()), encoding, ct);

    /// <summary>Writes a pseudo-section file (the TOC, 0xFFFE, or a signatures file, 0xFFFF): its segment header, then its items.</summary>
    internal static async ValueTask WritePseudoSectionAsync(Stream stream, Pb.SectionType type, IEnumerable<byte[]> items, RecordEncoding encoding, CancellationToken ct)
    {
        var header = new Pb.SegmentHeader { Magic = "EGRF", FormatMajor = RecordFormatVersion.Library.Major, SectionType = type };
        if (encoding == RecordEncoding.Protobuf)
        {
            await SegmentFraming.WriteFrameAsync(stream, header.ToByteArray(), ct).ConfigureAwait(false);
            foreach (var item in items)
            {
                await SegmentFraming.WriteFrameAsync(stream, item, ct).ConfigureAwait(false);
            }
        }
        else
        {
            await WriteLineAsync(RecordJson.FormatSegmentHeader(header)).ConfigureAwait(false);
            foreach (var item in items)
            {
                await WriteLineAsync(RecordJson.FormatItem(item, default)).ConfigureAwait(false);
            }
        }

        async ValueTask WriteLineAsync(byte[] line)
        {
            await stream.WriteAsync(line, ct).ConfigureAwait(false);
            stream.WriteByte((byte)'\n');
        }
    }
}

/// <summary>
/// Writes one device's section (design §4.5, §8.3): its <c>device_header</c>, then its ballot items
/// in chain order, then its <c>device_close</c>. Each ballot is written as it is appended and only
/// its digests are kept (the section frontier, the codes frontier over its confirmation codes, and
/// the last confirmation code for the chain). Appending requires a final status (cast, challenged
/// or spoiled; a device records an abandoned ballot as spoiled before appending the next one), the
/// device's own id, a valid ballot structure and the chaining field its place in the chain implies
/// (eq. 73 or 76; §4.1.4 for pre-encrypted ballots). It does not check proofs.
/// </summary>
public sealed class DeviceSectionWriter : IAsyncDisposable
{
    private readonly ElectionRecordWriter _record;
    private readonly SectionWriter _section;
    private readonly MerkleFrontier _codes = new();
    private bool _closed;

    internal DeviceSectionWriter(ElectionRecordWriter record, DeviceHeader header, SectionWriter section)
    {
        _record = record;
        Header = header;
        _section = section;
    }

    public DeviceHeader Header { get; }

    public DeviceKey Key => Header.Key;

    /// <summary>The number of ballot items appended (the next one's position is this plus one).</summary>
    public long Count { get; private set; }

    /// <summary>The last appended ballot's confirmation code: what the next ballot chains from under simple chaining.</summary>
    public ConfirmationCode? LastConfirmationCode { get; private set; }

    /// <summary>The previous confirmation code to encrypt the next ballot with: null under no chaining or before the first ballot.</summary>
    public ConfirmationCode? PreviousConfirmationCode => Header.ChainingMode == ChainingMode.None ? null : LastConfirmationCode;

    internal ValueTask WriteHeaderAsync(CancellationToken ct) => _section.AppendAsync(DeviceMapper.ToItem(Header), ct);

    /// <summary>Set on a section a resumed writer found open, until it is handed out again.</summary>
    internal bool Resumed { get; set; }

    /// <summary>A resumed section's state: its ballot items' confirmation codes, in order.</summary>
    internal void Restore(IEnumerable<ConfirmationCode> confirmationCodes)
    {
        foreach (var code in confirmationCodes)
        {
            _codes.Append(RecordDigests.ConfirmationCodeLeafBytes(code));
            LastConfirmationCode = code;
            Count++;
        }

        Resumed = true;
    }

    /// <summary>
    /// Appends a regular ballot (on a regular device) or a cast pre-encrypted ballot's record (on a
    /// pre-encrypting device; design §8.3: a cast pre-encrypted ballot is an
    /// <see cref="EncryptedBallot"/> with pre-encrypted contests). Returns its locator.
    /// </summary>
    public async ValueTask<BallotLocator> AppendAsync(EncryptedBallot ballot, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        RequireOpen();
        var record = _record.Record;
        bool pre = Header.Kind == DeviceChainBallotKind.PreEncrypted;
        if (ballot.IsPreEncrypted != pre)
        {
            throw new ArgumentException($"Ballot {ballot.Id} is {(ballot.IsPreEncrypted ? "a cast pre-encrypted ballot" : "a regular ballot")}; device {Header.DeviceId}'s section holds {(pre ? "pre-encrypted" : "regular")} ballots (design §4.5).", nameof(ballot));
        }

        if (ballot.Status is not (BallotStatus.Cast or BallotStatus.Challenged or BallotStatus.Spoiled))
        {
            throw new ArgumentException($"Ballot {ballot.Id} is {ballot.Status}; a recorded ballot is cast, challenged or spoiled (design §8.3).", nameof(ballot));
        }

        RequireDevice(ballot.Id, ballot.DeviceId);
        string? violation = BallotStructure.FindViolation(ballot, record.Manifest)
            ?? (pre ? BallotStructure.FindPreEncryptedCastViolation(ballot, record.Manifest) : null);
        if (violation is not null)
        {
            throw new ArgumentException($"Ballot {ballot.Id}: {violation}", nameof(ballot));
        }

        RequireChain(ballot.Id, ballot.ChainingField);
        byte[] item = BallotMapper.ToItem(ballot, record.Manifest).ToByteArray();
        var locator = new BallotLocator(Key, Count + 1);
        var entry = new ElectionRecordWriter.BallotEntry(locator, ballot.Status, pre ? ElectionRecordWriter.BallotForm.PreEncryptedCast : ElectionRecordWriter.BallotForm.Regular);
        await AppendItemAsync(ballot.SelectionEncryptionIdentifierHash, entry, item, ballot.ConfirmationCode, ct).ConfigureAwait(false);
        return locator;
    }

    /// <summary>
    /// Appends a printed pre-encrypted ballot that was not cast (#5), in print order: in the compact
    /// form for <see cref="UncastDisposition.NeverReturned"/> and
    /// <see cref="UncastDisposition.ReturnedBallotNonceReleased"/> (NQ-2, R-1), in full for
    /// <see cref="UncastDisposition.ReturnedNoncesReleased"/>. Its release is added in the final phase.
    /// </summary>
    public async ValueTask<BallotLocator> AppendUncastAsync(PreEncryptedBallot printed, UncastDisposition disposition, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(printed);
        RequireOpen();
        if (Header.Kind != DeviceChainBallotKind.PreEncrypted)
        {
            throw new ArgumentException($"Device {Header.DeviceId} is a regular device; an uncast pre-encrypted ballot belongs to its printer's section.", nameof(printed));
        }

        if (!Enum.IsDefined(disposition))
        {
            throw new ArgumentOutOfRangeException(nameof(disposition), disposition, null);
        }

        RequireDevice(printed.Id, printed.DeviceId);
        if (BallotStructure.FindViolation(printed, _record.Record.Manifest) is string violation)
        {
            throw new ArgumentException($"Uncast ballot {printed.Id}: {violation}", nameof(printed));
        }

        RequireChain(printed.Id, printed.ChainingField);
        bool compact = disposition != UncastDisposition.ReturnedNoncesReleased;
        byte[] item = UncastMapper.ToPrintedItem(printed, compact).ToByteArray();
        var locator = new BallotLocator(Key, Count + 1);
        var entry = new ElectionRecordWriter.BallotEntry(locator, BallotStatus.Challenged, compact ? ElectionRecordWriter.BallotForm.UncastCompact : ElectionRecordWriter.BallotForm.UncastFull);
        await AppendItemAsync(printed.SelectionEncryptionIdentifierHash, entry, item, printed.ConfirmationCode, ct).ConfigureAwait(false);
        return locator;
    }

    /// <summary>Flushes the section; <paramref name="durable"/> also flushes the operating system's buffers.</summary>
    public ValueTask FlushAsync(bool durable, CancellationToken ct = default) => _section.FlushAsync(durable, ct);

    /// <summary>
    /// Closes the device: under simple chaining the close carries B-bar_C and H-bar (eqs. 77/78, or
    /// 118/120), computed from the last confirmation code. Returns the seal, or null for a device that
    /// appended nothing, whose section is removed (Q25: a device that encrypted nothing has no
    /// section) with any attestation added for it. <paramref name="closedAt"/> is UTC to the millisecond, if recorded.
    /// </summary>
    public async ValueTask<DeviceSeal?> CloseAsync(DateTimeOffset? closedAt = null, CancellationToken ct = default)
    {
        RequireOpen();
        _closed = true;
        if (Count == 0)
        {
            await _section.DisposeAsync().ConfigureAwait(false);
            string directory = Path.GetDirectoryName(Path.Combine(_record.Directory, RecordLayout.SegmentPath(SectionKey.Device(Key), 0, _record.Encoding)))!;
            System.IO.Directory.Delete(directory, recursive: true);
            _record.DeviceClosed(this, null);
            return null;
        }

        var (closingField, closingHash) = Closing();
        await _section.AppendAsync(DeviceMapper.ToItem(new DeviceClose(Count, closingField, closingHash, closedAt)), ct).ConfigureAwait(false);
        var entry = await _section.CompleteAsync(critical: true, ct).ConfigureAwait(false);
        _record.DeviceClosed(this, entry);
        return new DeviceSeal(Key, entry.ItemCount, entry.Root, _codes.Root())
        {
            DeviceId = Header.DeviceId,
            ChainingMode = Header.ChainingMode,
            ClosingHash = closingHash,
            ClosedAt = closedAt,
        };
    }

    /// <summary>
    /// The canonical bytes of a <c>PrefixCheckpointStatement</c> over this device's ballots so far
    /// (design §4.9, optional): a mid-election commitment to the first <see cref="Count"/> codes, to
    /// be signed or posted to a bulletin board at <paramref name="at"/>. Flush the section
    /// (<see cref="FlushAsync"/>, durable) before publishing it.
    /// </summary>
    public byte[] PrefixCheckpointStatement(ExtendedBaseHash extendedBaseHash, DateTimeOffset at) =>
        RecordStatements.PrefixCheckpoint(extendedBaseHash, Key, Count, _codes.Root(), at);

    /// <summary>B-bar_C and H-bar under simple chaining (eqs. 77/78, or 118/120 for pre-encrypted ballots); null under no chaining.</summary>
    private (ChainingField? Field, ConfirmationCode? Hash) Closing()
    {
        if (Header.ChainingMode == ChainingMode.None || LastConfirmationCode is not { } last)
        {
            return (null, null);
        }

        var record = _record.Record;
        bool pre = Header.Kind == DeviceChainBallotKind.PreEncrypted;
        var field = pre
            ? ChainingField.ClosingForPreEncryptedBallots(Header.DeviceInformationHash, record.ExtendedBaseHash, last)
            : ChainingField.Closing(Header.DeviceInformationHash, record.ExtendedBaseHash, last);
        var hash = pre
            ? ChainingField.ClosingHashForPreEncryptedBallots(field, record.ExtendedBaseHash)
            : ChainingField.ClosingHash(field, record.ExtendedBaseHash);
        return (field, hash);
    }

    /// <summary>
    /// Closes the device with the record <see cref="DeviceChain.Close"/> produced, which must be this
    /// section's: the same device, kind and mode, the same confirmation codes in order (compared
    /// through the codes root) and the same H_0, B-bar_C and H-bar (<see cref="ArgumentException"/>).
    /// </summary>
    public async ValueTask<DeviceSeal?> CloseAsync(DeviceChainRecord closing, DateTimeOffset? closedAt = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(closing);
        ArgumentNullException.ThrowIfNull(closing.ConfirmationCodes);
        RequireOpen();
        var (field, hash) = Closing();
        if (closing.DeviceId != Header.DeviceId || closing.DeviceInformationHash != Header.DeviceInformationHash || closing.BallotKind != Header.Kind
            || closing.ChainingMode != Header.ChainingMode || closing.InitialHash != Header.InitialHash
            || closing.ConfirmationCodes.Count != Count || RecordDigests.CodesRoot(closing.ConfirmationCodes) != _codes.Root()
            || closing.ClosingChainingField != field || closing.ClosingHash != hash)
        {
            throw new ArgumentException($"The chain record of device {closing.DeviceId} is not this section's (device, kind, mode, H_0, confirmation codes or close differ).", nameof(closing));
        }

        return await CloseAsync(closedAt, ct).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync() => await _section.DisposeAsync().ConfigureAwait(false);

    private void RequireOpen()
    {
        if (_closed)
        {
            throw new InvalidOperationException($"Device {Header.DeviceId}'s section is closed.");
        }

        _record.RequireVoting($"append to device {Header.DeviceId}");
    }

    private void RequireDevice(string ballotId, string deviceId)
    {
        if (!string.Equals(deviceId, Header.DeviceId, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Ballot {ballotId} names device {deviceId ?? "(none)"}, not {Header.DeviceId}.");
        }
    }

    private void RequireChain(string ballotId, ChainingField chainingField)
    {
        var record = _record.Record;
        var previous = PreviousConfirmationCode;
        var expected = Header.Kind == DeviceChainBallotKind.PreEncrypted
            ? ChainingField.ForPreEncryptedBallots(Header.ChainingMode, Header.DeviceInformationHash, record.ExtendedBaseHash, previous)
            : new ChainingField(Header.ChainingMode, Header.DeviceInformationHash, record.ExtendedBaseHash, previous);
        if (chainingField != expected)
        {
            throw new ArgumentException($"Ballot {ballotId} carries chaining field {chainingField}; as ballot {Count + 1} of device {Header.DeviceId} it must carry {expected} (§3.4.4 eq. {(Header.ChainingMode == ChainingMode.None ? "73" : "76")}).");
        }
    }

    /// <summary>
    /// Writes a ballot item and indexes it. The index entry is taken first, under the record's lock,
    /// so two devices cannot both write a ballot with one H_I (5.A); if the item is then not written
    /// (over the frame ceiling, or an I/O error), the entry is taken back, so no locator points at a
    /// ballot the record does not hold and the next ballot gets this one's position.
    /// </summary>
    private async ValueTask AppendItemAsync(SelectionEncryptionIdentifierHash identifierHash, ElectionRecordWriter.BallotEntry entry, byte[] item, ConfirmationCode confirmationCode, CancellationToken ct)
    {
        _record.AddBallot(identifierHash, entry);
        try
        {
            await _section.AppendAsync(item, default, ct).ConfigureAwait(false);
        }
        catch
        {
            _record.RemoveBallot(identifierHash, entry);
            throw;
        }

        _codes.Append(RecordDigests.ConfirmationCodeLeafBytes(confirmationCode));
        LastConfirmationCode = confirmationCode;
        Count++;
    }
}
