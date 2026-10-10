using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Core.Verify.Tally;
using System.Diagnostics;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// Steps C and D (design §6.1, §6.2): the join cursors and the attestations, then the device pass.
/// The device sections are read in canonical order as one stream of items, cut into batches bounded
/// by bytes (<see cref="VerifyAllOptions.BatchBytes"/>, at least one item) and by count, so that
/// parallelism does not depend on how the ballots are spread over devices. Each batch runs in three
/// stages:
/// <list type="number">
/// <item>a sequencer, in record order: frames, canonicality, the item's kind, the chain walk
/// (<see cref="DeviceChainWalker"/>), 5.A's keyed prefix, the prefix checkpoints, and the join
/// cursors' items at the ballot's locator (one sequential cursor per join section: they are sorted
/// in the same order, design §6.3);</item>
/// <item>workers, in parallel: the leaf hash, the decode with range attribution, and the per-item
/// verifications, with the joined decryption or release while the ballot is in memory, and the
/// Verification 9 fold into pooled recounts (merged later in standard form);</item>
/// <item>the sequencer again: the leaves into each section's frontier, and at a device's close its
/// root and its attestations.</item>
/// </list>
/// A checkpoint can be taken between batches: nothing is in flight then.
/// </summary>
internal sealed partial class RecordVerificationRun
{
    private JoinCursor? _requestCursor;
    private JoinCursor? _contestDataCursor;
    private JoinCursor? _challengedCursor;
    private JoinCursor? _releaseCursor;
    private readonly Dictionary<DeviceKey, List<Sha256Digest>> _leaves = [];
    private DateTime _lastCheckpoint = DateTime.UtcNow;

    private sealed class DeviceContext(int index, DeviceKey key, DeviceChainWalker walker)
    {
        public int Index { get; } = index;

        public DeviceKey Key { get; } = key;

        public SectionKey Section { get; } = SectionKey.Device(key);

        public DeviceChainWalker Walker { get; set; } = walker;

        public MerkleFrontier Frontier { get; set; } = new();

        public DeviceHeader? Header { get; set; }

        public DeviceClose? Close { get; set; }

        public bool HeaderOk { get; set; }

        public bool Broken { get; set; }

        public string DeviceId => Header?.DeviceId ?? WireValues.UnknownLabel("device", Index);

        public bool PreEncrypting => Key.Kind == DeviceChainBallotKind.PreEncrypted;

        public string StructureCode => PreEncrypting ? "16.structure" : "8.structure";

        public int ChainVerification => PreEncrypting ? 16 : 8;

        /// <summary>The codes roots at the counts a prefix-checkpoint statement names (design §4.9).</summary>
        public Dictionary<long, Sha256Digest> PrefixRoots { get; } = [];

        public HashSet<long> PrefixCounts { get; } = [];
    }

    private enum ItemKind
    {
        Opaque,
        Regular,
        PreEncryptedCast,
        UncastFull,
        UncastCompact,
    }

    private sealed class Event(DeviceContext device, RecordItemBytes raw, bool last)
    {
        public DeviceContext Device { get; } = device;

        public RecordItemBytes Raw { get; } = raw;

        public bool Last { get; } = last;

        public bool IsHeader => Raw.Ordinal == 0;

        public bool IsClose { get; set; }

        public Sha256Digest Leaf { get; set; }

        public Work? Work { get; set; }
    }

    private sealed class Work(DeviceContext device, RecordItemBytes raw, Pb.RecordItem item, ItemKind kind)
    {
        public DeviceContext Device { get; } = device;

        public RecordItemBytes Raw { get; } = raw;

        public Pb.RecordItem Item { get; } = item;

        public ItemKind Kind { get; } = kind;

        public BallotLocator Locator => new(Device.Key, Raw.Ordinal);

        public string BallotId { get; init; } = "";

        public string IdentifierHex { get; init; } = "";

        public List<JoinItem> Challenged { get; init; } = [];

        public List<JoinItem> Requests { get; init; } = [];

        public List<JoinItem> ContestData { get; init; } = [];

        public List<JoinItem> Releases { get; init; } = [];

        // Whether each list is the ballot's whole set of join items: false once that section's cursor
        // broke (a carrier or line failure, reported), when a missing item is unknown, not absent.
        public bool ChallengedKnown { get; init; } = true;

        public bool RequestsKnown { get; init; } = true;

        public bool ContestDataKnown { get; init; } = true;

        public bool ReleasesKnown { get; init; } = true;

        public bool Selected { get; init; } = true;
    }

    // ---- step C ---------------------------------------------------------------------------------

    private async ValueTask StepJoinPrepAsync(CheckpointState? resumed)
    {
        Progress("join preparation", 0);
        await ReadAttestationsAsync().ConfigureAwait(false);
        if (Phase >= RecordPhase.Aggregated)
        {
            _requestCursor = OpenCursor(RecordSectionType.ContestDataRequests, Pb.RecordItem.ItemOneofCase.ContestDataRequest, "12.structure", resumed);
        }

        if (Phase >= RecordPhase.Final)
        {
            _contestDataCursor = OpenCursor(RecordSectionType.ContestDataDecryptions, Pb.RecordItem.ItemOneofCase.ContestDataDecryption, "12.structure", resumed);
            _challengedCursor = OpenCursor(RecordSectionType.ChallengedBallotDecryptions, Pb.RecordItem.ItemOneofCase.ChallengedBallotDecryption, "13.structure", resumed);
            _releaseCursor = OpenCursor(RecordSectionType.UncastNonceReleases, Pb.RecordItem.ItemOneofCase.UncastNonceRelease, "18.structure", resumed);
        }
    }

    private JoinCursor? OpenCursor(RecordSectionType type, Pb.RecordItem.ItemOneofCase member, string code, CheckpointState? resumed)
    {
        JoinCursor.State? state = null;
        resumed?.Cursors.TryGetValue(((ushort)type).ToString(System.Globalization.CultureInfo.InvariantCulture), out state);
        return JoinCursor.Open(_reader, type, member, code, finding =>
        {
            // The ballot correctness profile does not verify the join sections, only the items it joins;
            // a failure that stops a section is reported under every profile, since the chosen ballots'
            // joins after it are then unknown.
            if (!IsBallotCorrectness || finding.BreaksSection)
            {
                Report(StepCompletion, finding.SubSection, finding.Message, finding.Section, finding.Ordinal, finding.Locator);
            }
        }, state, _ct);
    }

    /// <summary>Reads the device attestations section (O(attestations)), checking each as a signed statement and their order (design §4.5, §4.9).</summary>
    private async ValueTask ReadAttestationsAsync()
    {
        var section = SectionKey.Of(RecordSectionType.DeviceAttestations);
        var attestations = new Dictionary<DeviceKey, List<Attestation>>();
        (string Device, int Member, Sha256Digest Statement, string Item)? last = null;
        await DigestAsync(section, item =>
        {
            var check = CanonicalProtobuf.CheckSignedStatement(item.Bytes.Span, _reader.Format.Minor);
            if (!check.IsCanonical)
            {
                Report(StepJoinPrep, check.Rule is RecordCodes.Attestation or RecordCodes.Signature ? RecordCodes.Attestation : RecordCodes.Encoding, $"Item {item.Ordinal} of section {section} is not a canonical device attestation ({check.Rule}): {check.Message}", section, item.Ordinal);
                return;
            }

            NoteUnknownContent(check, section);
            var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
            if (parsed.ItemCase != Pb.RecordItem.ItemOneofCase.DeviceAttestation)
            {
                Report(StepJoinPrep, RecordCodes.Attestation, $"Item {item.Ordinal} of section {section} is member {(int)parsed.ItemCase}, not a device_attestation (§4.5).", section, item.Ordinal);
                return;
            }

            var signed = SignedStatement.FromMessage(parsed.DeviceAttestation);
            var statement = Pb.RecordItem.Parser.ParseFrom(signed.Statement.Span);
            var deviceKey = statement.ItemCase switch
            {
                Pb.RecordItem.ItemOneofCase.ChainCloseStatement => statement.ChainCloseStatement.DeviceKey,
                Pb.RecordItem.ItemOneofCase.SectionSealStatement => statement.SectionSealStatement.DeviceKey,
                _ => statement.PrefixCheckpointStatement.DeviceKey,
            };

            var key = (Convert.ToHexStringLower(deviceKey.Span), (int)statement.ItemCase, signed.StatementDigest, Convert.ToHexStringLower(item.Bytes.Span));
            if (last is { } previous && Compare(previous, key) >= 0)
            {
                Report(StepJoinPrep, RecordCodes.Order, $"Item {item.Ordinal} of section {section} is out of order: attestations ascend by device key, statement type and SHA-256 of the statement, each once (§4.5).", section, item.Ordinal);
            }

            last = key;
            DeviceKey device;
            try
            {
                device = ElectionRecordReader.DeviceKeyOf(deviceKey.Span);
            }
            catch (ArgumentException)
            {
                Report(StepJoinPrep, RecordCodes.Attestation, $"Attestation {item.Ordinal} names a device key that is no device's.", section, item.Ordinal);
                return;
            }

            if (!_reader.Devices.Contains(device))
            {
                Report(StepJoinPrep, RecordCodes.Attestation, $"Attestation {item.Ordinal} names device {Convert.ToHexStringLower(deviceKey.Span)}, which has no section in the record.", section, item.Ordinal);
                return;
            }

            if (!attestations.TryGetValue(device, out var list))
            {
                attestations[device] = list = [];
            }

            list.Add(new Attestation(item.Ordinal, signed, statement));
        }).ConfigureAwait(false);

        _attestations = attestations;

        static int Compare((string Device, int Member, Sha256Digest Statement, string Item) a, (string Device, int Member, Sha256Digest Statement, string Item) b)
        {
            int c = string.CompareOrdinal(a.Device, b.Device);
            c = c != 0 ? c : a.Member.CompareTo(b.Member);
            c = c != 0 ? c : a.Statement.CompareTo(b.Statement);
            return c != 0 ? c : string.CompareOrdinal(a.Item, b.Item);
        }
    }

    // ---- step D ---------------------------------------------------------------------------------

    private async ValueTask StepDevicesAsync(CheckpointState? resumed)
    {
        await StepJoinPrepAsync(resumed).ConfigureAwait(false);
        if (_record is null || !_cryptography)
        {
            // No election to read ballots against: the sections are still digested for the roots.
            foreach (var device in _reader.Devices)
            {
                await DigestAsync(SectionKey.Device(device), _ => { }).ConfigureAwait(false);
            }

            await DrainCursorsAsync(digestOnly: true).ConfigureAwait(false);
            return;
        }

        var identifiersDirectory = Checkpointing ? _options.CheckpointPath + ".5a" : _options.TempDirectory;
        _identifiers = resumed?.Identifiers is { } saved
            ? SpillingIdentifierSet.Restore(saved, _options.UniquenessMemoryBudgetBytes, identifiersDirectory)
            : new SpillingIdentifierSet(_options.UniquenessMemoryBudgetBytes, identifiersDirectory);
        DeviceContext? resumedDevice = resumed is null ? null : ApplyCheckpoint(resumed);

        int startDevice = resumed?.DeviceIndex ?? 0;
        long startOrdinal = resumed?.NextOrdinal ?? 0;
        int maxItems = Math.Max(64, 4 * Parallelism);
        var batch = new List<Event>();
        long bytes = 0;
        await foreach (var e in ReadDevicesAsync(startDevice, startOrdinal, resumedDevice).ConfigureAwait(false))
        {
            batch.Add(e);
            bytes += e.Raw.Bytes.Length;
            if (batch.Count >= maxItems || bytes >= _options.BatchBytes)
            {
                await ProcessBatchAsync(batch).ConfigureAwait(false);
                batch.Clear();
                bytes = 0;
                if (Stop())
                {
                    return;
                }
            }
        }

        if (batch.Count > 0)
        {
            await ProcessBatchAsync(batch).ConfigureAwait(false);
        }

        if (!IsBallotCorrectness && !Stop())
        {
            await DrainCursorsAsync(digestOnly: false).ConfigureAwait(false);
        }
    }

    private async ValueTask DrainCursorsAsync(bool digestOnly)
    {
        foreach (var cursor in new[] { _requestCursor, _challengedCursor, _contestDataCursor, _releaseCursor })
        {
            if (cursor is null)
            {
                continue;
            }

            if (digestOnly)
            {
                await cursor.DisposeAsync().ConfigureAwait(false);
                await DigestAsync(cursor.Section, _ => { }).ConfigureAwait(false);
                continue;
            }

            await cursor.DrainAsync().ConfigureAwait(false);
            if (!cursor.Broken)
            {
                // A broken section has no root (its failure is reported): the claimed TOC's entry is then R.root.
                AddEntry(cursor.Section, cursor.Frontier);
            }

            await cursor.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The device sections' items in canonical order, from <paramref name="startOrdinal"/> of device
    /// <paramref name="startDevice"/> on, each marked when it is its section's last. A frame, line or
    /// carrier failure inside a section is reported (it has no root then) and the pass moves on.
    /// </summary>
    private async IAsyncEnumerable<Event> ReadDevicesAsync(int startDevice, long startOrdinal, DeviceContext? resumedDevice)
    {
        var selectedDevices = _selected?.Select(x => x.Device).ToHashSet();
        for (int i = startDevice; i < _reader.Devices.Count; i++)
        {
            var key = _reader.Devices[i];
            if (selectedDevices is not null && !selectedDevices.Contains(key))
            {
                continue;
            }

            var context = i == startDevice && resumedDevice is not null ? resumedDevice : NewDevice(i, key);
            long from = i == startDevice ? startOrdinal : 0;
            var section = SectionKey.Device(key);
            var items = _reader.ReadSectionAsync(section, from > 0 ? 0 : from, _ct).GetAsyncEnumerator(_ct);
            RecordItemBytes? pending = null;
            try
            {
                while (true)
                {
                    bool more;
                    try
                    {
                        more = await items.MoveNextAsync().ConfigureAwait(false);
                    }
                    catch (VerificationFailedException ex)
                    {
                        Report(StepBallots, ex.SubSection, ex.Message, section);
                        context.Broken = true;
                        break;
                    }

                    if (!more)
                    {
                        break;
                    }

                    var raw = items.Current;
                    if (raw.Ordinal < from)
                    {
                        // A resumed section: its header is read again for S_device, without its checks.
                        if (raw.Ordinal == 0 && raw.Check.IsCanonical && Pb.RecordItem.Parser.ParseFrom(raw.Bytes.Span) is { ItemCase: Pb.RecordItem.ItemOneofCase.DeviceHeader } header
                            && DeviceMapper.IsDeclared(header.DeviceHeader.Kind))
                        {
                            context.Header = DeviceMapper.FromItem(header.DeviceHeader);
                        }

                        continue;
                    }

                    if (pending is { } previous)
                    {
                        yield return new Event(context, previous, last: false);
                    }

                    pending = raw;
                }
            }
            finally
            {
                await items.DisposeAsync().ConfigureAwait(false);
            }

            if (pending is { } final && !context.Broken)
            {
                yield return new Event(context, final, last: true);
            }
            else if (!context.Broken && from == 0)
            {
                Report(StepBallots, context.StructureCode, $"Device section {section} holds no item (§4.5: a device_header first).", section);
            }
        }
    }

    private DeviceContext NewDevice(int index, DeviceKey key)
    {
        var scheme = key.Kind == DeviceChainBallotKind.PreEncrypted ? DeviceChainWalk.PreEncrypted : DeviceChainWalk.Encrypted;
        var context = new DeviceContext(index, key, new DeviceChainWalker(scheme, _record!));
        foreach (var attestation in _attestations.GetValueOrDefault(key) ?? [])
        {
            if (attestation.Statement.ItemCase == Pb.RecordItem.ItemOneofCase.PrefixCheckpointStatement)
            {
                context.PrefixCounts.Add((long)Math.Min(attestation.Statement.PrefixCheckpointStatement.BallotCount, long.MaxValue));
            }
        }

        if (IsBallotCorrectness)
        {
            _leaves[key] = [];
        }

        return context;
    }

    private async ValueTask ProcessBatchAsync(List<Event> batch)
    {
        // 1. The sequencer, in record order.
        foreach (var e in batch)
        {
            if (e.IsHeader)
            {
                Header(e);
                if (e.Last)
                {
                    Report(StepBallots, e.Device.StructureCode, $"Device section {e.Device.Section} holds only its header; it ends with a device_close (§4.5).", e.Device.Section, 0);
                }

                continue;
            }

            if (e.Last && IsCloseItem(e.Raw))
            {
                Close(e);
                continue;
            }

            await Entry(e).ConfigureAwait(false);
            if (e.Last)
            {
                Report(StepBallots, e.Device.StructureCode, $"Device section {e.Device.Section} does not end with a device_close (§4.5).", e.Device.Section, e.Raw.Ordinal);
            }
        }

        // 2. The workers: leaf hashes and per-item verifications.
        var options = new ParallelOptions { MaxDegreeOfParallelism = _options.MaxDegreeOfParallelism, CancellationToken = _ct };
        if (_options.MaxDegreeOfParallelism == 1)
        {
            foreach (var e in batch)
            {
                Worker(e);
            }
        }
        else
        {
            Parallel.ForEach(batch, options, Worker);
        }

        // 3. The sequencer again: leaves into the section frontiers, and each closed device's root.
        foreach (var e in batch)
        {
            e.Device.Frontier.AppendLeafHash(e.Leaf);
            _counters.Digest(e.Raw.Bytes.Length);
            if (_leaves.TryGetValue(e.Device.Key, out var leaves))
            {
                leaves.Add(e.Leaf);
            }

            if (e.Last)
            {
                FinishDevice(e.Device);
            }
        }

        _ct.ThrowIfCancellationRequested();
        if (Checkpointing && DateTime.UtcNow - _lastCheckpoint >= _options.CheckpointInterval)
        {
            var last = batch[^1];
            await WriteCheckpointAsync(last.Last ? null : last.Device, last.Last ? last.Device.Index + 1 : last.Device.Index, last.Last ? 0 : last.Raw.Ordinal + 1).ConfigureAwait(false);
            _lastCheckpoint = DateTime.UtcNow;
        }

        Progress("ballots", _counters.BallotItems);
    }

    private void Worker(Event e)
    {
        e.Leaf = MerkleTree.LeafHash(e.Raw.Bytes.Span);
        if (e.Work is { } work && work.Selected)
        {
            switch (work.Kind)
            {
                case ItemKind.Regular:
                    VerifyRegular(work);
                    break;
                case ItemKind.PreEncryptedCast:
                    VerifyPreEncryptedCast(work);
                    break;
                case ItemKind.UncastFull:
                case ItemKind.UncastCompact:
                    VerifyUncast(work);
                    break;
                default:
                    OpaqueJoins(work);
                    break;
            }
        }
    }

    private static bool IsCloseItem(RecordItemBytes raw)
    {
        try
        {
            return raw.Check.IsCanonical && Pb.RecordItem.Parser.ParseFrom(raw.Bytes.Span).ItemCase == Pb.RecordItem.ItemOneofCase.DeviceClose;
        }
        catch (Google.Protobuf.InvalidProtocolBufferException)
        {
            return false;
        }
    }

    private bool ReportsChain(DeviceContext device) => Runs(device.ChainVerification) && !IsBallotCorrectness;

    private void Header(Event e)
    {
        var device = e.Device;
        _counters.Device();
        if (!e.Raw.Check.IsCanonical)
        {
            Report(StepBallots, RecordCodes.Encoding, $"The header of device section {device.Section} is not canonical ({e.Raw.Check.Rule}): {e.Raw.Check.Message}", device.Section, 0);
            return;
        }

        NoteUnknownContent(e.Raw.Check, device.Section);
        var parsed = Pb.RecordItem.Parser.ParseFrom(e.Raw.Bytes.Span);
        if (parsed.ItemCase != Pb.RecordItem.ItemOneofCase.DeviceHeader)
        {
            Report(StepBallots, device.StructureCode, $"Device section {device.Section}'s first item is member {(int)parsed.ItemCase}, not device_header (§4.5).", device.Section, 0);
            return;
        }

        // Compared on the wire values: v2's layout has a section only for a declared device kind
        // (§5.3.1), so a header naming another kind (a later minor's, design §7 "Enum value") does not
        // match its section and is the device's structure finding, never an exception. The header is
        // not taken, so the device's chain is not evaluable (at its close).
        if (!DeviceMapper.NamesKey(parsed.DeviceHeader, device.Key))
        {
            Report(StepBallots, device.StructureCode, DeviceMapper.KeyMismatch(device.Section, parsed.DeviceHeader), device.Section, 0);
            return;
        }

        var header = DeviceMapper.FromItem(parsed.DeviceHeader);

        device.Header = header;
        device.HeaderOk = true;
        var failure = device.Walker.Begin(header.DeviceId, header.DeviceInformationHash, header.Kind, header.ChainingMode, header.InitialHash);
        if (failure is not null && ReportsChain(device))
        {
            Report(StepBallots, failure.SubSection, failure.Message, device.Section, 0);
        }

        if (ReportsChain(device))
        {
            _outcomes.Ran(device.ChainVerification);
        }
    }

    private void Close(Event e)
    {
        var device = e.Device;
        e.IsClose = true;
        var close = DeviceMapper.FromItem(Pb.RecordItem.Parser.ParseFrom(e.Raw.Bytes.Span).DeviceClose);
        device.Close = close;
        NoteUnknownContent(e.Raw.Check, device.Section);
        if (close.BallotCount != e.Raw.Ordinal - 1)
        {
            Report(StepBallots, device.StructureCode, $"The close of device section {device.Section} counts {close.BallotCount} ballot items; the section holds {e.Raw.Ordinal - 1} (§4.5).", device.Section, e.Raw.Ordinal);
        }

        if (!device.HeaderOk)
        {
            if (ReportsChain(device))
            {
                _outcomes.NotEvaluable(device.ChainVerification);
            }

            return;
        }

        var failure = device.Walker.End(close.ClosingChainingField, close.ClosingHash);
        if (failure is not null && ReportsChain(device))
        {
            Report(StepBallots, failure.SubSection, failure.Message, device.Section, e.Raw.Ordinal);
        }

        if (!device.Walker.IsComplete && ReportsChain(device))
        {
            _outcomes.NotEvaluable(device.ChainVerification);
        }
    }

    /// <summary>The sequencer's part for one ballot item: kind, chain walk, 5.A, prefix checkpoints and joins.</summary>
    private async ValueTask Entry(Event e)
    {
        var device = e.Device;
        var raw = e.Raw;
        var locator = new BallotLocator(device.Key, raw.Ordinal);
        Pb.RecordItem? parsed = null;
        if (!raw.Check.IsCanonical)
        {
            Report(StepBallots, RecordCodes.Encoding, $"Item {raw.Ordinal} of device section {device.Section} is not canonical ({raw.Check.Rule}): {raw.Check.Message}", device.Section, raw.Ordinal, locator);
        }
        else
        {
            NoteUnknownContent(raw.Check, device.Section);
            parsed = Pb.RecordItem.Parser.ParseFrom(raw.Bytes.Span);
        }

        var kind = parsed?.ItemCase switch
        {
            Pb.RecordItem.ItemOneofCase.EncryptedBallot when !device.PreEncrypting => ItemKind.Regular,
            Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot when device.PreEncrypting => ItemKind.PreEncryptedCast,
            Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot when device.PreEncrypting => ItemKind.UncastFull,
            Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot when device.PreEncrypting => ItemKind.UncastCompact,
            _ => ItemKind.Opaque,
        };

        if (parsed is not null && kind == ItemKind.Opaque)
        {
            if (parsed.ItemCase == Pb.RecordItem.ItemOneofCase.None)
            {
                Report(StepBallots, RecordCodes.Version, $"Item {raw.Ordinal} of device section {device.Section} is an item type of a newer format minor, in a section that must verify (design §7).", device.Section, raw.Ordinal, locator);
            }
            else
            {
                Report(StepBallots, device.StructureCode, $"Item {raw.Ordinal} of device section {device.Section} is member {(int)parsed.ItemCase}; a {(device.PreEncrypting ? "pre-encrypting" : "regular")} device section holds {(device.PreEncrypting ? "pre-encrypted cast, uncast and compact uncast ballots" : "encrypted_ballot items")} only, between its header and its close (§4.5).", device.Section, raw.Ordinal, locator);
            }
        }

        var fields = parsed is null ? default : BallotFields(parsed);
        bool selected = _selected?.Contains(locator) ?? true;
        if (kind == ItemKind.Opaque)
        {
            // The item's contents are unknown: its chain link, its 5.A entry (when id_B can still be
            // read) and any cast weight cannot be checked; Verification 9 cannot be evaluated, since the
            // item may be a cast ballot (in a pre-encrypting section an opaque item may as well be uncast,
            // which is never tallied, but nothing tells the two apart).
            if (device.HeaderOk)
            {
                device.Walker.Skip();
            }

            Interlocked.Increment(ref _undecodableCast);
            if (ReportsChain(device))
            {
                _outcomes.NotEvaluable(device.ChainVerification);
            }

            if (IdentifierOf(raw) is { Length: 32 } opaqueIdentifier && Runs(5) && !IsBallotCorrectness)
            {
                _identifiers!.Add(opaqueIdentifier);
            }
        }
        else
        {
            string id = BallotMapper.Id(fields.BallotRef, fields.IdB);
            if (device.HeaderOk)
            {
                var failure = device.Walker.Next(id, ConfirmationCode.FromCanonicalBytes(fields.Code.ToByteArray()), ChainingField.FromCanonicalBytes(fields.Chaining.Span));
                if (failure is not null && ReportsChain(device))
                {
                    Report(StepBallots, failure.SubSection, failure.Message, device.Section, raw.Ordinal, locator, Convert.ToHexStringLower(fields.IdB.Span));
                }

                if (device.PrefixCounts.Contains(device.Walker.CodesCount))
                {
                    device.PrefixRoots[device.Walker.CodesCount] = device.Walker.CodesRoot;
                }
            }

            if (Runs(5) && !IsBallotCorrectness)
            {
                _identifiers!.Add(fields.IdB.Span);
            }

            if (_options.Profile == VerificationProfile.GuardianPreliminary)
            {
                if (kind == ItemKind.Regular && parsed!.EncryptedBallot.Status == Pb.BallotStatus.Challenged)
                {
                    lock (_ballotsToOpen)
                    {
                        _ballotsToOpen.Add(locator);
                    }
                }
                else if (kind is ItemKind.UncastFull or ItemKind.UncastCompact)
                {
                    lock (_uncastToRelease)
                    {
                        _uncastToRelease.Add(locator);
                    }
                }
            }
        }

        e.Work = new Work(device, raw, parsed ?? new Pb.RecordItem(), kind)
        {
            BallotId = kind == ItemKind.Opaque ? WireValues.UnknownLabel("ballot", raw.Ordinal) : BallotMapper.Id(fields.BallotRef, fields.IdB),
            IdentifierHex = kind == ItemKind.Opaque ? "" : Convert.ToHexStringLower(fields.IdB.Span),
            Challenged = _challengedCursor is null ? [] : await _challengedCursor.TakeAsync(locator).ConfigureAwait(false),
            Requests = _requestCursor is null ? [] : await _requestCursor.TakeAsync(locator).ConfigureAwait(false),
            ContestData = _contestDataCursor is null ? [] : await _contestDataCursor.TakeAsync(locator).ConfigureAwait(false),
            Releases = _releaseCursor is null ? [] : await _releaseCursor.TakeAsync(locator).ConfigureAwait(false),
            ChallengedKnown = _challengedCursor is not { Broken: true },
            RequestsKnown = _requestCursor is not { Broken: true },
            ContestDataKnown = _contestDataCursor is not { Broken: true },
            ReleasesKnown = _releaseCursor is not { Broken: true },
            Selected = selected,
        };
    }

    private readonly record struct Fields(Google.Protobuf.ByteString IdB, Google.Protobuf.ByteString HI, Google.Protobuf.ByteString Code, Google.Protobuf.ByteString Chaining, string BallotRef);

    private static Fields BallotFields(Pb.RecordItem item) => item.ItemCase switch
    {
        Pb.RecordItem.ItemOneofCase.EncryptedBallot => new(item.EncryptedBallot.IdB, item.EncryptedBallot.HI, item.EncryptedBallot.ConfirmationCode, item.EncryptedBallot.ChainingField, item.EncryptedBallot.BallotRef),
        Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot => new(item.PreEncryptedCastBallot.IdB, item.PreEncryptedCastBallot.HI, item.PreEncryptedCastBallot.ConfirmationCode, item.PreEncryptedCastBallot.ChainingField, item.PreEncryptedCastBallot.BallotRef),
        Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot => new(item.PreEncryptedUncastBallot.IdB, item.PreEncryptedUncastBallot.HI, item.PreEncryptedUncastBallot.ConfirmationCode, item.PreEncryptedUncastBallot.ChainingField, item.PreEncryptedUncastBallot.BallotRef),
        Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot => new(item.PreEncryptedCompactUncastBallot.IdB, item.PreEncryptedCompactUncastBallot.HI, item.PreEncryptedCompactUncastBallot.ConfirmationCode, item.PreEncryptedCompactUncastBallot.ChainingField, item.PreEncryptedCompactUncastBallot.BallotRef),
        _ => default,
    };

    // ---- the workers ----------------------------------------------------------------------------

    private Where WhereOf(Work work) => new(work.Device.Section, work.Raw.Ordinal, work.Locator, work.IdentifierHex);

    private static Where WhereOf(Work work, JoinItem join, SectionKey section) => new(section, join.Ordinal, work.Locator, work.IdentifierHex);

    private void VerifyRegular(Work work)
    {
        var record = _record!;
        var where = WhereOf(work);
        var status = work.Item.EncryptedBallot.Status;
        _counters.Ballot();
        _counters.Status(status);
        var decoded = BallotMapper.FromItem(work.Item, record.Manifest, work.Device.DeviceId);
        NoteContests(decoded.Placeholder.Contests.Select(x => x.Id));
        bool cast = status == Pb.BallotStatus.Cast;
        bool challenged = status == Pb.BallotStatus.Challenged;
        bool knownStatus = cast || challenged || status == Pb.BallotStatus.Spoiled;
        if (!knownStatus)
        {
            // Design §7, "Enum value": a status a newer minor added passes the canonical check as
            // content not understood, but whether the ballot is tallied (V9), opened (V13/V14, #8) or
            // may carry a contest-data request (V12) depends on it: those are not evaluable, with
            // R.version at the item. Verifications 5-8 do not read the status and still run.
            Report(StepBallots, RecordCodes.Version, $"Ballot {work.BallotId} is recorded with status {(int)status}, a value of a newer format minor: whether it is tallied, opened or neither cannot be decided, so the checks that depend on its status are not evaluable (design §7).", where.Section, where.Ordinal, where.Locator, where.Identifier);
            Interlocked.Increment(ref _undecodableCast);
            foreach (var verification in new[] { 9, 12, 13, 14 }.Where(Runs))
            {
                if (verification == 9 || Phase == RecordPhase.Final || work.Challenged.Count > 0 || work.Requests.Count > 0)
                {
                    _outcomes.NotEvaluable(verification);
                }
            }
        }

        var readers = new List<int> { 6, 7, 8 };
        if (cast)
        {
            readers.Add(9);
        }

        if (challenged && work.Challenged.Count > 0)
        {
            readers.AddRange([13, 14]);
        }

        if (work.ContestData.Count > 0)
        {
            readers.Add(12);
        }

        bool evaluable = Decoded(decoded, StepBallots, where, [.. readers]);
        var placeholder = decoded.Placeholder;
        Check(5, StepBallots, () => new SelectionEncryptionIdentifierVerification().Verify(placeholder.SelectionEncryptionIdentifier, placeholder.SelectionEncryptionIdentifierHash, record.ExtendedBaseHash), where);
        if (evaluable)
        {
            Check(6, StepBallots, () => new SelectionEncryptionsWellFormedVerification().Verify(decoded, record), where, decoded);
            Check(7, StepBallots, () => new AdherenceToVoteLimitsVerification().Verify(decoded, record), where, decoded);
            Check(8, StepBallots, () => new ConfirmationCodeVerification().Verify(decoded, record), where, decoded);
        }

        if (cast)
        {
            Fold(decoded, where);
        }

        // A challenged ballot's decryption (§3.6.7; #8: every challenged ballot has one), and the Q31
        // property from the published record: no decryption opens a cast or spoiled ballot.
        var challengedSection = SectionKey.Of(RecordSectionType.ChallengedBallotDecryptions);
        // Under a status not understood (not evaluable above) neither a stray nor a missing decryption can be decided.
        if (knownStatus && !challenged)
        {
            foreach (var join in work.Challenged)
            {
                Report(StepBallots, "13.structure", $"A challenged ballot decryption opens ballot {work.BallotId}, which is recorded {StatusName(status)}: only a challenged regular ballot is opened (Q31, design §6.2).", challengedSection, join.Ordinal, work.Locator, work.IdentifierHex);
            }
        }
        else if (challenged && Phase == RecordPhase.Final && (Runs(13) || Runs(14)))
        {
            if (work.Challenged.Count == 0 && work.ChallengedKnown)
            {
                Report(StepBallots, "13.structure", $"Challenged ballot {work.BallotId} has no decryption; the record requires one for every challenged ballot (user decision #8, design §6.2).", work.Device.Section, work.Raw.Ordinal, work.Locator, work.IdentifierHex);
            }
            else if (work.Challenged.Count == 0)
            {
                // The decryptions section broke before this ballot (reported): its decryption is unknown.
                foreach (var verification in new[] { 13, 14 }.Where(Runs))
                {
                    _outcomes.NotEvaluable(verification);
                }
            }

            foreach (var join in work.Challenged)
            {
                var joinWhere = WhereOf(work, join, challengedSection);
                var index = RecordBallotIndex.Single(work.Locator, work.BallotId, SelectionEncryptionIdentifierHash.FromCanonicalBytes(work.Item.EncryptedBallot.HI.ToByteArray()));
                var opened = DecryptionMapper.FromItem(join.Item.ChallengedBallotDecryption, index, record.Manifest);
                bool openedEvaluable = Decoded(opened, StepBallots, joinWhere, 13, 14);
                Check(13, StepBallots, () => new ChallengedBallotDecryptionVerification().Verify(record, decoded, opened), joinWhere, decoded, opened);
                if (evaluable && openedEvaluable)
                {
                    Check(14, StepBallots, () => new ChallengedBallotWellFormednessVerification().Verify(record.Manifest, decoded.Value!, opened.Value!), joinWhere);
                }
                else if (Runs(14))
                {
                    _outcomes.NotEvaluable(14);
                }
            }
        }

        // Contest-data requests and decryptions (§3.6.6; follow-up #10: the requested set is sealed).
        var requestSection = SectionKey.Of(RecordSectionType.ContestDataRequests);
        var dataSection = SectionKey.Of(RecordSectionType.ContestDataDecryptions);
        var requested = new HashSet<uint>();
        foreach (var join in work.Requests)
        {
            var joinWhere = WhereOf(work, join, requestSection);
            var request = DecryptionMapper.FromItem(join.Item.ContestDataRequest);
            Decoded(request, StepBallots, joinWhere);
            requested.Add(join.ContestIndex);
            if (!cast && knownStatus)
            {
                Report(StepBallots, "12.structure", $"A contest-data request names ballot {work.BallotId}, which is recorded {StatusName(status)}; requests name cast ballots (§3.6.1, design §6.2).", requestSection, join.Ordinal, work.Locator, work.IdentifierHex);
            }

            if (!join.Item.ContestDataRequest.HI.Equals(work.Item.EncryptedBallot.HI))
            {
                Report(StepBallots, "12.structure", $"A contest-data request names ballot {work.BallotId} with an H_I that is not the ballot's.", requestSection, join.Ordinal, work.Locator, work.IdentifierHex);
            }

            var contest = record.Manifest.Contests.FirstOrDefault(x => x.Index == join.ContestIndex);
            if (contest is null || contest.ContestDataBlocks <= 0)
            {
                Report(StepBallots, "12.structure", $"A contest-data request names contest {join.ContestIndex} of ballot {work.BallotId}, which {(contest is null ? "the manifest does not hold" : "has no contest data (b_Λ = 0)")}.", requestSection, join.Ordinal, work.Locator, work.IdentifierHex);
            }
        }

        if (Phase == RecordPhase.Final && (Runs(12) || work.Requests.Count > 0 || work.ContestData.Count > 0))
        {
            foreach (var missing in requested.Where(x => !work.ContestData.Any(d => d.ContestIndex == x)))
            {
                if (work.ContestDataKnown)
                {
                    Report(StepBallots, "12.structure", $"The contest-data request for ballot {work.BallotId}, contest {missing} has no decryption (follow-up #10).", requestSection, work.Requests.First(x => x.ContestIndex == missing).Ordinal, work.Locator, work.IdentifierHex);
                }
                else if (Runs(12))
                {
                    // The decryptions section broke before this ballot (reported): its decryption is unknown.
                    _outcomes.NotEvaluable(12);
                }
            }

            foreach (var join in work.ContestData)
            {
                var joinWhere = WhereOf(work, join, dataSection);
                if (!requested.Contains(join.ContestIndex))
                {
                    if (work.RequestsKnown)
                    {
                        Report(StepBallots, "12.structure", $"A contest-data decryption of ballot {work.BallotId}, contest {join.ContestIndex}, has no request (follow-up #10: nothing is decrypted that was not requested).", dataSection, join.Ordinal, work.Locator, work.IdentifierHex);
                        continue;
                    }

                    // The requests section broke before this ballot (reported): whether one was
                    // requested is unknown; the decryption itself is still verified.
                    if (Runs(12))
                    {
                        _outcomes.NotEvaluable(12);
                    }
                }

                var index = RecordBallotIndex.Single(work.Locator, work.BallotId, SelectionEncryptionIdentifierHash.FromCanonicalBytes(work.Item.EncryptedBallot.HI.ToByteArray()));
                var data = DecryptionMapper.FromItem(join.Item.ContestDataDecryption, index, record.Manifest);
                Decoded(data, StepBallots, joinWhere, 12);
                Check(12, StepBallots, () => new ContestDataDecryptionVerification().Verify(record, decoded, data), joinWhere, decoded, data);
            }
        }

        StrayReleases(work, "a regular ballot");
    }

    private void VerifyPreEncryptedCast(Work work)
    {
        var record = _record!;
        var where = WhereOf(work);
        _counters.Ballot();
        _counters.PreEncryptedCast();
        var decoded = BallotMapper.FromItem(work.Item, record.Manifest, work.Device.DeviceId);
        NoteContests(decoded.Placeholder.Contests.Select(x => x.Id));
        bool evaluable = Decoded(decoded, StepBallots, where, 6, 7, 9, 15, 16, 17);
        var placeholder = decoded.Placeholder;
        Check(5, StepBallots, () => new SelectionEncryptionIdentifierVerification().Verify(placeholder.SelectionEncryptionIdentifier, placeholder.SelectionEncryptionIdentifierHash, record.ExtendedBaseHash), where);
        if (evaluable)
        {
            var ballot = decoded.Value!;
            Check(6, StepBallots, () => new SelectionEncryptionsWellFormedVerification().Verify(decoded, record), where, decoded);
            Check(7, StepBallots, () => new AdherenceToVoteLimitsVerification().Verify(decoded, record), where, decoded);
            Check(15, StepBallots, () => new SelectionVectorAccumulationVerification().Verify(ballot, record), where);
            var (deviceHash, previous) = PerBallotChain(work.Device, ballot.ChainingField);
            Check(16, StepBallots, () => new PreEncryptedConfirmationCodeVerification().Verify(ballot, deviceHash, record, previous), where);
            Check(17, StepBallots, () => new ShortCodeVerification().Verify(ballot, record), where);
        }

        Fold(decoded, where);
        StrayChallenged(work, "a cast pre-encrypted ballot (a pre-encrypting locator)");
        StrayRequests(work, "a pre-encrypted ballot");
        StrayReleases(work, "a cast pre-encrypted ballot");
    }

    private void VerifyUncast(Work work)
    {
        var record = _record!;
        var where = WhereOf(work);
        bool compact = work.Kind == ItemKind.UncastCompact;
        _counters.Ballot();
        _counters.Uncast(compact);
        var (idB, hI) = (work.Item.ItemCase == Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot
            ? (work.Item.PreEncryptedUncastBallot.IdB, work.Item.PreEncryptedUncastBallot.HI)
            : (work.Item.PreEncryptedCompactUncastBallot.IdB, work.Item.PreEncryptedCompactUncastBallot.HI));
        IEnumerable<uint> indices = compact ? work.Item.PreEncryptedCompactUncastBallot.Contests.Select(x => x.Index) : work.Item.PreEncryptedUncastBallot.Contests.Select(x => x.Index);
        NoteContests(indices.Select(i => record.Manifest.Contests.FirstOrDefault(x => x.Index == i)?.Id).OfType<string>());
        Check(5, StepBallots, () => new SelectionEncryptionIdentifierVerification().Verify(SelectionEncryptionIdentifier.FromCanonicalBytes(idB.Span), SelectionEncryptionIdentifierHash.FromCanonicalBytes(hI.ToByteArray()), record.ExtendedBaseHash), where);
        StrayChallenged(work, "an uncast pre-encrypted ballot");
        StrayRequests(work, "an uncast pre-encrypted ballot");
        var releaseSection = SectionKey.Of(RecordSectionType.UncastNonceReleases);
        if (Phase < RecordPhase.Final || work.Releases.Count == 0)
        {
            // Before the releases exist (a guardian run of the aggregated prefix) the ballot is listed
            // for release; in a final record a missing release is 18.structure. Either way what the
            // printed item alone allows is checked now (design §6.9, NQ-10).
            if (Phase >= RecordPhase.Final && work.ReleasesKnown)
            {
                Report(StepBallots, "18.structure", $"Uncast pre-encrypted ballot {work.BallotId} has no nonce release; every uncast ballot has one (#5, NQ-2, design §6.2).", work.Device.Section, work.Raw.Ordinal, work.Locator, work.IdentifierHex);
            }

            VerifyUnreleased(work, where, compact);
            return;
        }

        var join = work.Releases[0];
        var joinWhere = WhereOf(work, join, releaseSection);
        var joined = UncastMapper.Join(work.Item, join.Item, record, work.Device.DeviceId);
        int[] joinedReaders = compact ? [6, 16, 18] : [6, 16, 17, 18, 19];
        // The printed item's findings and checks (6, 16, 17, 19) name the ballot's own item; the
        // release's (18) name the release.
        bool evaluable = Decoded(joined, StepBallots, finding => finding.Verification == 18 ? joinWhere : where, joinedReaders);
        Check(6, StepBallots, () => new SelectionEncryptionsWellFormedVerification().Verify(joined), where, joined);
        var (deviceHash, previous) = PerBallotChain(work.Device, ChainingField.FromCanonicalBytes((work.Item.PreEncryptedUncastBallot?.ChainingField ?? work.Item.PreEncryptedCompactUncastBallot.ChainingField).Span));
        Check(16, StepBallots, () => new PreEncryptedConfirmationCodeVerification().Verify(joined, deviceHash, record, previous), where, joined);
        Check(18, StepBallots, () => new UncastBallotEncryptionVerification().Verify(joined, record), joinWhere, joined);
        if (compact)
        {
            // §3.2: the compact item records no printed codes or labels, so 17.A and 19.A-D hold by
            // construction on it (counted in the statistics as UncastCompact).
            foreach (var verification in new[] { 17, 19 })
            {
                if (Runs(verification) && _cryptography)
                {
                    _outcomes.Ran(verification);
                }
            }
        }
        else if (evaluable)
        {
            var uncast = joined.Value!;
            Check(17, StepBallots, () => new ShortCodeVerification().Verify(uncast.Ballot, record), where);
            Check(19, StepBallots, () => new UncastBallotContentVerification().Verify(record.Manifest, uncast), where);
        }
    }

    /// <summary>
    /// An uncast ballot without its release (none yet, or none in a final record). A full item carries
    /// every vector, ψ, χ, short code and label, so its 6.A, 16.A-16.C, 17 and 19 are checked on the
    /// printed item alone (spec p.64: V6 "for all selection encryptions on all ballots, including ...
    /// pre-encrypted ballots"; p.65: V16 "for each pre-encrypted ballot"); only 18 waits for the
    /// release, so it is not evaluable. A compact item has no vectors until ξ_B is released, but it
    /// prints H_I, each χ, B_C and H_C, so its 16.C (spec p.64's first check of an uncast ballot,
    /// H_C = H(H_I; 0x42, χ_1, ..., χ_mB, B_C)) runs now; 16.A and 16.B, and 6, 17, 18 and 19, read the
    /// regenerated vectors, so they are not evaluable: never Passed for an item they did not run on
    /// (a 16.C failure still makes 16 Failed).
    /// </summary>
    private void VerifyUnreleased(Work work, Where where, bool compact)
    {
        if (compact)
        {
            var compactItem = work.Item.PreEncryptedCompactUncastBallot;
            Check(16, StepBallots, () =>
            {
                var chainingField = ChainingField.FromCanonicalBytes(compactItem.ChainingField.Span);
                var (deviceHash, previous) = PerBallotChain(work.Device, chainingField);
                new PreEncryptedConfirmationCodeVerification().VerifyCompactBeforeRelease(
                    work.BallotId,
                    work.Device.DeviceId,
                    compactItem.BallotStyle,
                    SelectionEncryptionIdentifierHash.FromCanonicalBytes(compactItem.HI.ToByteArray()),
                    compactItem.Contests.Select(x => ((int)x.Index, ContestHash.FromCanonicalBytes(x.ContestHash.ToByteArray()))).ToList(),
                    chainingField,
                    ConfirmationCode.FromCanonicalBytes(compactItem.ConfirmationCode.ToByteArray()),
                    deviceHash,
                    _record!,
                    previous);
            }, where);

            foreach (var verification in new[] { 6, 16, 17, 18, 19 })
            {
                if (Runs(verification))
                {
                    _outcomes.NotEvaluable(verification);
                }
            }

            return;
        }

        var record = _record!;
        var item = work.Item.PreEncryptedUncastBallot;
        var printed = UncastMapper.FromPrinted(item, work.Device.DeviceId);
        bool evaluable = Decoded(printed, StepBallots, where, 6, 16, 17, 19);
        Check(6, StepBallots, () => new SelectionEncryptionsWellFormedVerification().Verify(printed), where, printed);
        var (deviceHash, previous) = PerBallotChain(work.Device, ChainingField.FromCanonicalBytes(item.ChainingField.Span));
        Check(16, StepBallots, () => new PreEncryptedConfirmationCodeVerification().Verify(printed, deviceHash, record, previous), where, printed);
        if (evaluable)
        {
            var uncast = printed.Value!;
            Check(17, StepBallots, () => new ShortCodeVerification().Verify(uncast.Ballot, record), where);
            Check(19, StepBallots, () => new UncastBallotContentVerification().Verify(record.Manifest, uncast), where);
        }

        if (Runs(18))
        {
            _outcomes.NotEvaluable(18);
        }
    }

    /// <summary>
    /// The H_DI and previous code the per-ballot Verification 16 is given on the record path: H_DI as
    /// computed from S_device and the previous code the ballot's own B_C states. So the per-ballot
    /// check is 16.A-16.C, and 16.D-16.F are reported once, by the device walk, against the chain.
    /// </summary>
    private (VotingDeviceInformationHash DeviceHash, ConfirmationCode? Previous) PerBallotChain(DeviceContext device, ChainingField chainingField)
    {
        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(_record!.ExtendedBaseHash, device.DeviceId);
        if (_record.Manifest.ChainingMode == ChainingMode.None)
        {
            return (deviceHash, null);
        }

        byte[] field = chainingField;
        return (deviceHash, ConfirmationCode.FromCanonicalBytes(field[4..]));
    }

    private void Fold(RecordDecoded<EncryptedBallot> decoded, Where where)
    {
        if (!Runs(9) || !_cryptography)
        {
            return;
        }

        if (decoded.Value is not { } ballot)
        {
            Interlocked.Increment(ref _undecodableCast);
            return;
        }

        var aggregator = _aggregators.TryTake(out var pooled) ? pooled : new BallotAggregationVerifier(_record!.Manifest);
        try
        {
            aggregator.AddBallot(ballot);
        }
        catch (VerificationFailedException ex)
        {
            Report(StepBallots, ex.SubSection, ex.Message, where.Section, where.Ordinal, where.Locator, where.Identifier);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or KeyNotFoundException or IndexOutOfRangeException or FormatException or OverflowException)
        {
            // The recount is faulted either way (BallotAggregationVerifier's remarks), so V9 is never passed.
            Report(StepBallots, "9.structure", $"Verification 9 could not fold a malformed ballot into its recount: {ex.Message}", where.Section, where.Ordinal, where.Locator, where.Identifier);
        }
        finally
        {
            _aggregators.Add(aggregator);
        }
    }

    private void OpaqueJoins(Work work)
    {
        var affected = new List<int>();
        if (work.Challenged.Count > 0)
        {
            affected.AddRange([13, 14]);
        }

        if (work.Releases.Count > 0)
        {
            affected.Add(18);
        }

        if (work.ContestData.Count > 0)
        {
            affected.Add(12);
        }

        foreach (var verification in affected.Where(Runs))
        {
            _outcomes.NotEvaluable(verification);
        }
    }

    private void StrayChallenged(Work work, string what)
    {
        foreach (var join in work.Challenged)
        {
            Report(StepBallots, "13.structure", $"A challenged ballot decryption opens ballot {work.BallotId}, {what}: only a challenged regular ballot is opened (§3.3, design §6.2).", SectionKey.Of(RecordSectionType.ChallengedBallotDecryptions), join.Ordinal, work.Locator, work.IdentifierHex);
        }
    }

    private void StrayRequests(Work work, string what)
    {
        foreach (var join in work.Requests)
        {
            Report(StepBallots, "12.structure", $"A contest-data request names ballot {work.BallotId}, {what}; requests name cast regular ballots (design §6.2).", SectionKey.Of(RecordSectionType.ContestDataRequests), join.Ordinal, work.Locator, work.IdentifierHex);
        }

        foreach (var join in work.ContestData)
        {
            Report(StepBallots, "12.structure", $"A contest-data decryption names ballot {work.BallotId}, {what}, which no request can name (design §6.2).", SectionKey.Of(RecordSectionType.ContestDataDecryptions), join.Ordinal, work.Locator, work.IdentifierHex);
        }
    }

    private void StrayReleases(Work work, string what)
    {
        foreach (var join in work.Releases)
        {
            Report(StepBallots, "18.structure", $"An uncast nonce release names ballot {work.BallotId}, {what}; releases open uncast pre-encrypted ballots only (design §6.2).", SectionKey.Of(RecordSectionType.UncastNonceReleases), join.Ordinal, work.Locator, work.IdentifierHex);
        }
    }

    private void NoteContests(IEnumerable<string> contestIds)
    {
        foreach (var id in contestIds)
        {
            if (id.Length > 0 && id[0] != '\0')
            {
                _contestsOnSubmittedBallots.TryAdd(id, true);
            }
        }
    }

    private static string StatusName(Pb.BallotStatus status) => status switch
    {
        Pb.BallotStatus.Cast => "cast",
        Pb.BallotStatus.Challenged => "challenged",
        Pb.BallotStatus.Spoiled => "spoiled",
        _ => $"with status {(int)status}",
    };

    // ---- a device's close -----------------------------------------------------------------------

    private void FinishDevice(DeviceContext device)
    {
        AddEntry(device.Section, device.Frontier);
        if (!IsBallotCorrectness)
        {
            CheckAttestations(device);
        }
    }

    /// <summary>
    /// A device's attestations (design §4.9): each statement's contents against the section, always
    /// (<c>R.attestation</c>), and its signature under the policy; and the recommended chain-close
    /// attestation's absence, reported, and a failure under <see cref="SignaturePolicy.RequireValid"/>.
    /// </summary>
    private void CheckAttestations(DeviceContext device)
    {
        var section = SectionKey.Of(RecordSectionType.DeviceAttestations);
        bool chainClose = false;
        bool validChainClose = false;
        foreach (var attestation in _attestations.GetValueOrDefault(device.Key) ?? [])
        {
            var (kind, mismatch) = AttestationContents(device, attestation.Statement);
            if (mismatch is not null)
            {
                Report(StepBallots, RecordCodes.Attestation, $"The {kind} attestation of device {device.DeviceId} does not match its section: {mismatch} (design §4.9).", section, attestation.Ordinal);
            }

            var signature = CheckSignature(attestation.Signed);
            if (_options.SignaturePolicy == SignaturePolicy.RequireValid && signature.Status != SignatureStatus.Valid)
            {
                Report(StepBallots, RecordCodes.Attestation, $"The {kind} attestation of device {device.DeviceId} has no valid signature under the configured trust anchors ({signature.Status}: {signature.Message}); the policy requires one.", section, attestation.Ordinal);
            }

            lock (_attestationResults)
            {
                _attestationResults.Add(new AttestationResult(device.Key, kind, true, mismatch is null, signature, mismatch ?? $"The {kind} attestation matches the section."));
            }

            if (kind == AttestationKind.ChainClose)
            {
                chainClose = true;
                validChainClose |= mismatch is null && signature.Status == SignatureStatus.Valid;
            }
        }

        if (!chainClose)
        {
            lock (_attestationResults)
            {
                _attestationResults.Add(new AttestationResult(device.Key, AttestationKind.ChainClose, false, false, null, $"Device {device.DeviceId} has no chain-close attestation (recommended for every device, design §4.9): nothing binds its ballots' order and count but the record root."));
            }
        }

        if (_options.SignaturePolicy == SignaturePolicy.RequireValid && !validChainClose)
        {
            Report(StepBallots, RecordCodes.Attestation, $"Device {device.DeviceId} has no validly signed chain-close attestation that matches its section; the policy requires one (design §4.9).", device.Section);
        }
    }

    private (AttestationKind Kind, string? Mismatch) AttestationContents(DeviceContext device, Pb.RecordItem statement)
    {
        var mismatches = new List<string>();
        byte[] he = _record!.ExtendedBaseHash;
        byte[] key = device.Key.ToBytes();
        switch (statement.ItemCase)
        {
            case Pb.RecordItem.ItemOneofCase.ChainCloseStatement:
            {
                var s = statement.ChainCloseStatement;
                Compare(s.HE.Span.SequenceEqual(he), "H_E");
                Compare(s.DeviceKey.Span.SequenceEqual(key), "the device key");
                Compare(s.DeviceId == device.Header?.DeviceId, "S_device");
                Compare(device.Header is { } header && s.ChainingMode == (uint)header.ChainingMode, "the chaining mode");
                Compare(device.Close is { } close && (long)s.BallotCount == close.BallotCount && (long)s.BallotCount == device.Walker.Count, "the ballot count ℓ");
                if (device.Walker.IsComplete)
                {
                    Compare(s.CodesRoot.Span.SequenceEqual(device.Walker.CodesRoot.ToArray()), "codes_root over the confirmation codes in chain order");
                }

                byte[] closing = device.Close?.ClosingHash is { } hash ? hash : [];
                Compare(s.ClosingHash.Span.SequenceEqual(closing), "the closing hash H̄");
                return (AttestationKind.ChainClose, Joined());
            }

            case Pb.RecordItem.ItemOneofCase.SectionSealStatement:
            {
                var s = statement.SectionSealStatement;
                Compare(s.HE.Span.SequenceEqual(he), "H_E");
                Compare(s.DeviceKey.Span.SequenceEqual(key), "the device key");
                Compare((long)s.ItemCount == device.Frontier.Count, "the item count ℓ + 2");
                Compare(s.SectionRoot.Span.SequenceEqual(device.Frontier.Root().ToArray()), "the section root");
                return (AttestationKind.SectionSeal, Joined());
            }

            default:
            {
                var s = statement.PrefixCheckpointStatement;
                Compare(s.HE.Span.SequenceEqual(he), "H_E");
                Compare(s.DeviceKey.Span.SequenceEqual(key), "the device key");
                long count = (long)Math.Min(s.BallotCount, long.MaxValue);
                if (count == 0)
                {
                    Compare(s.CodesRoot.Span.SequenceEqual(MerkleTree.EmptyRoot.ToArray()), "codes_root of no ballots");
                }
                else if (device.Walker.IsComplete)
                {
                    Compare(device.PrefixRoots.TryGetValue(count, out var root) && s.CodesRoot.Span.SequenceEqual(root.ToArray()), $"codes_root over the first {count} confirmation codes");
                }

                return (AttestationKind.PrefixCheckpoint, Joined());
            }
        }

        void Compare(bool equal, string what)
        {
            if (!equal)
            {
                mismatches.Add(what);
            }
        }

        string? Joined() => mismatches.Count == 0 ? null : $"{string.Join(", ", mismatches)} differ";
    }

    private SignatureCheck CheckSignature(SignedStatement signed)
    {
        string keyId = Convert.ToHexStringLower(signed.KeyId.Span);
        if (_options.SignaturePolicy == SignaturePolicy.Ignore)
        {
            return new SignatureCheck(SignatureStatus.Ignored, signed.Algorithm, keyId, "Signatures are not checked under the Ignore policy.");
        }

        var verifier = _options.SignatureVerifiers.FirstOrDefault(x => x.Algorithm == signed.Algorithm);
        return verifier is null
            ? new SignatureCheck(SignatureStatus.NotChecked, signed.Algorithm, keyId, $"No verifier is configured for {signed.Algorithm}: present, not checked (design §4.9).")
            : verifier.Verify(signed);
    }

    // ---- record signatures and inclusion proofs ---------------------------------------------------

    /// <summary>
    /// The detached record signatures (design §4.9): each a canonical signed statement whose
    /// <c>RecordStatement</c> names a phase root of this record, this election's H_E and format major 2
    /// (<c>R.signature</c> otherwise, whatever the policy); each signature checked under the policy,
    /// and under <see cref="SignaturePolicy.RequireValid"/> at least one valid signature over the root
    /// of the phase verified.
    /// </summary>
    private async ValueTask CheckRecordSignaturesAsync()
    {
        bool valid = false;

        // File by file: the signature files are outside every root, so anyone can add one, and an
        // unreadable one must not hide a valid signature in a later file.
        foreach (var file in _reader.SignatureFiles)
        {
            try
            {
                await foreach (var item in _reader.ReadSignatureFileAsync(file, _ct).ConfigureAwait(false))
                {
                    valid |= CheckRecordSignature(item);
                }
            }
            catch (VerificationFailedException ex)
            {
                Report(StepCompletion, ex.SubSection is RecordCodes.Container or RecordCodes.Encoding ? RecordCodes.Signature : ex.SubSection, $"The signatures file {file} could not be read: {ex.Message}");
            }
        }

        if (_options.SignaturePolicy == SignaturePolicy.RequireValid && !valid)
        {
            Report(StepCompletion, RecordCodes.Signature, $"The record has no valid signature over its {Phase} root (§3.7; the policy requires one).");
        }
    }

    /// <summary>One record signature: its statement against the record, its signature under the policy. Returns whether it is a valid signature over the root of the phase verified.</summary>
    private bool CheckRecordSignature(RecordItemBytes item)
    {
        var check = CanonicalProtobuf.CheckSignedStatement(item.Bytes.Span, _reader.Format.Minor);
        if (!check.IsCanonical)
        {
            Report(StepCompletion, RecordCodes.Signature, $"A record signature is not a canonical signed statement ({check.Rule}): {check.Message}");
            return false;
        }

        if (check.HasUnknownContent)
        {
            _complete = false;
            Skipped("A record signature holds content of a newer format minor (unknown fields or enum values), checked as far as it is understood (§7).");
        }

        var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
        if (parsed.ItemCase != Pb.RecordItem.ItemOneofCase.RecordSignature)
        {
            Report(StepCompletion, RecordCodes.Signature, $"An item of a signatures file is member {(int)parsed.ItemCase}, not a record_signature.");
            return false;
        }

        var signed = SignedStatement.FromMessage(parsed.RecordSignature);
        var statement = Pb.RecordItem.Parser.ParseFrom(signed.Statement.Span).RecordStatement;
        var phase = (RecordPhase)(int)statement.Phase;
        if (phase > Phase)
        {
            return false;
        }

        var mismatches = new List<string>();
        if (!_phaseRoots.TryGetValue(phase, out var root) || !statement.Root.Span.SequenceEqual(root.ToArray()))
        {
            mismatches.Add($"the {phase} root");
        }

        if (_record is null || !statement.HE.Span.SequenceEqual((byte[])_record.ExtendedBaseHash))
        {
            mismatches.Add("H_E");
        }

        if (statement.FormatMajor != RecordFormatVersion.Library.Major)
        {
            mismatches.Add("the format major");
        }

        string? mismatch = mismatches.Count == 0 ? null : $"{string.Join(", ", mismatches)} differ";
        if (mismatch is not null)
        {
            Report(StepCompletion, RecordCodes.Signature, $"A record signature's statement ({phase}, signer role \"{statement.SignerRole}\") does not match the record: {mismatch} (design §4.9).");
        }

        var signature = CheckSignature(signed);
        if (_options.SignaturePolicy == SignaturePolicy.RequireValid && signature.Status != SignatureStatus.Valid)
        {
            Report(StepCompletion, RecordCodes.Signature, $"A record signature over the {phase} root ({statement.SignerRole}) is not valid under the configured trust anchors ({signature.Status}: {signature.Message}); the policy requires valid signatures.");
        }

        _signatureResults.Add(new RecordSignatureResult(phase, statement.SignerRole, statement.SignedAt is { } at ? WireValues.Time(at) : null, mismatch is null, signature, mismatch ?? $"The statement names this record's {phase} root."));
        return mismatch is null && signature.Status == SignatureStatus.Valid && phase == Phase;
    }

    /// <summary>The ballot correctness profile's inclusion proofs: each chosen ballot's leaf to its section root, and the section's TOC entry to the claimed root.</summary>
    private void BuildInclusions(TableOfContents computed)
    {
        foreach (var locator in _selected!.Order())
        {
            if (!_leaves.TryGetValue(locator.Device, out var leaves) || locator.Position < 1 || locator.Position >= leaves.Count - 1)
            {
                Report(StepCompletion, RecordCodes.Structure, $"The ballot correctness profile names the ballot at position {locator.Position} of device {Convert.ToHexStringLower(locator.Device.ToBytes())}, which the record does not hold.", SectionKey.Device(locator.Device), locator.Position, locator);
                continue;
            }

            var section = SectionKey.Device(locator.Device);
            var sectionRoot = MerkleTree.Root(leaves);
            var sectionPath = MerkleProofs.InclusionProof(leaves, locator.Position);
            if (_reader.ClaimedToc is not { } claimed)
            {
                continue;
            }

            int index = claimed.Entries.ToList().FindIndex(x => x.Type == section.Type && x.Key.Span.SequenceEqual(section.Key.Span));
            if (index < 0)
            {
                continue;
            }

            var tocPath = MerkleProofs.InclusionProof(claimed.LeafHashes, index);
            _inclusions.Add(new BallotInclusion(locator, leaves[(int)locator.Position], leaves.Count, sectionPath, sectionRoot, index, claimed.Entries.Count, tocPath, claimed.Root));
        }
    }
}
