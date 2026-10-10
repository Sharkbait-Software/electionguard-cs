using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.RecordFormat.Mappers;
using Google.Protobuf;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// A merge cursor over one of the record's join sections (design §6.3): the contest-data requests
/// and decryptions, the challenged ballot decryptions and the uncast nonce releases, all sorted by
/// ballot locator (and contest index), so that the device pass, walking the ballots in the same
/// canonical order, takes each ballot's items in O(1) memory with one sequential read of the section.
/// <list type="bullet">
/// <item>Every item read is digested into the section's frontier, in order, so the section root
/// needs no second read.</item>
/// <item>An item out of ascending (locator, contest index) order is <c>R.order</c>; a repeated key
/// the section's structure code ("12.structure", "13.structure", "18.structure"); an item with no
/// locator, or of another member, that structure code; a non-canonical item <c>R.encoding</c>; an
/// unknown item type of a newer minor <c>R.version</c>. None of these is joined.</item>
/// <item>An item whose locator the pass never reaches (a ballot the record does not hold, or one the
/// pass passed without taking it) is a stray, reported under the structure code when the cursor
/// moves past it or is drained.</item>
/// <item>A carrier or line failure (<c>R.container</c>, <c>R.encoding</c> from the reader) is reported
/// once and ends the cursor (<see cref="Broken"/>): never thrown out of the run.</item>
/// </list>
/// Not thread-safe; the device pass's sequencer drives it.
/// </summary>
internal sealed class JoinCursor : IAsyncDisposable
{
    private readonly IAsyncEnumerator<RecordItemBytes> _items;
    private readonly Pb.RecordItem.ItemOneofCase _member;
    private readonly Action<JoinCursorFinding> _report;
    private readonly bool _keyedByContest;
    private MerkleFrontier _frontier;
    private JoinItem? _peek;
    private bool _ended;
    private (BallotLocator Locator, uint Contest)? _last;
    private (BallotLocator Locator, uint Contest)? _lastBeforePeek;

    private JoinCursor(IElectionRecordReader reader, SectionKey section, Pb.RecordItem.ItemOneofCase member, string structureCode, Action<JoinCursorFinding> report, State? state, CancellationToken ct)
    {
        Section = section;
        StructureCode = structureCode;
        _member = member;
        _report = report;
        _keyedByContest = member is Pb.RecordItem.ItemOneofCase.ContestDataRequest or Pb.RecordItem.ItemOneofCase.ContestDataDecryption;
        _frontier = state is null ? new MerkleFrontier() : MerkleFrontier.Deserialize(state.Frontier);
        NextOrdinal = state?.NextOrdinal ?? 0;
        _last = state?.LastLocator is { } locator ? (DeviceMapper.FromItem(Pb.BallotLocator.Parser.ParseFrom(locator)), state.LastContest) : null;
        _items = reader.ReadSectionAsync(section, NextOrdinal, ct).GetAsyncEnumerator(ct);
    }

    /// <summary>
    /// A cursor over <paramref name="section"/> holding <paramref name="member"/> items, reporting
    /// under <paramref name="structureCode"/>; null when the record has no such section.
    /// <paramref name="state"/> continues a checkpointed cursor.
    /// </summary>
    public static JoinCursor? Open(IElectionRecordReader reader, RecordSectionType type, Pb.RecordItem.ItemOneofCase member, string structureCode, Action<JoinCursorFinding> report, State? state, CancellationToken ct)
    {
        var section = SectionKey.Of(type);
        return reader.Sections.Contains(section) ? new JoinCursor(reader, section, member, structureCode, report, state, ct) : null;
    }

    public SectionKey Section { get; }

    public string StructureCode { get; }

    /// <summary>
    /// Whether a carrier or line failure stopped the cursor: the items after it are unknown, so the
    /// section has no root and a ballot taken since has an unknown set of join items.
    /// </summary>
    public bool Broken { get; private set; }

    /// <summary>The ordinal of the next item not yet consumed.</summary>
    public long NextOrdinal { get; private set; }

    /// <summary>The items consumed so far, and their root (the section's root once drained).</summary>
    public MerkleFrontier Frontier => _frontier;

    /// <summary>
    /// The items at <paramref name="locator"/>, in section order; every earlier item not taken is
    /// reported as a stray first.
    /// </summary>
    public async ValueTask<List<JoinItem>> TakeAsync(BallotLocator locator)
    {
        var taken = new List<JoinItem>();
        while (await PeekAsync().ConfigureAwait(false) is { } next)
        {
            int c = next.Locator.CompareTo(locator);
            if (c > 0)
            {
                break;
            }

            Consume(next);
            if (c < 0)
            {
                Stray(next);
            }
            else
            {
                taken.Add(next);
            }
        }

        return taken;
    }

    /// <summary>Consumes the rest of the section, every item a stray.</summary>
    public async ValueTask DrainAsync()
    {
        while (await PeekAsync().ConfigureAwait(false) is { } next)
        {
            Consume(next);
            Stray(next);
        }
    }

    /// <summary>The cursor's state at a batch boundary, for a checkpoint.</summary>
    public State Export()
    {
        var last = _peek is null ? _last : _lastBeforePeek;
        return new(_peek?.Ordinal ?? NextOrdinal, _frontier.Serialize(), last is { } key ? DeviceMapper.ToItem(key.Locator).ToByteArray() : null, last?.Contest ?? 0);
    }

    /// <summary>A cursor's checkpoint state: the next ordinal, the frontier of the items before it, and the last key read.</summary>
    public sealed record State(long NextOrdinal, byte[] Frontier, byte[]? LastLocator, uint LastContest);

    public ValueTask DisposeAsync() => _items.DisposeAsync();

    private void Consume(JoinItem item)
    {
        _frontier.Append(item.Bytes.Span);
        NextOrdinal = item.Ordinal + 1;
        _peek = null;
    }

    private void Stray(JoinItem item) =>
        _report(new JoinCursorFinding(StructureCode, Section, item.Ordinal, item.Locator, $"Item {item.Ordinal} of section {Section} names the ballot at position {item.Locator.Position} of device {Convert.ToHexStringLower(item.Locator.Device.ToBytes())}, which is not a ballot it can join: the record holds no such ballot, or the ballot is not of the kind or status the item opens (design §6.2 join rules)."));

    /// <summary>The next joinable item, reporting and consuming every unjoinable one before it.</summary>
    private async ValueTask<JoinItem?> PeekAsync()
    {
        while (_peek is null && !_ended)
        {
            bool more;
            try
            {
                more = await _items.MoveNextAsync().ConfigureAwait(false);
            }
            catch (VerificationFailedException ex)
            {
                // A carrier or line failure (a bad segment header, a torn frame, a JSON line that does
                // not parse): reported once, under its code; the section has no root, and nothing after
                // the failure is joined, so the ballots after it have their joins not evaluable.
                _ended = true;
                Broken = true;
                _report(new JoinCursorFinding(ex.SubSection, Section, null, null, $"Section {Section} could not be read from item {NextOrdinal} on: {ex.Message}", BreaksSection: true));
                break;
            }

            if (!more)
            {
                _ended = true;
                break;
            }

            var raw = _items.Current;
            var before = _last;
            var bad = Classify(raw, out var item);
            if (bad is not null)
            {
                _frontier.Append(raw.Bytes.Span);
                NextOrdinal = raw.Ordinal + 1;
                _report(bad);
                continue;
            }

            _peek = item;
            _lastBeforePeek = before;
        }

        return _peek;
    }

    private JoinCursorFinding? Classify(RecordItemBytes raw, out JoinItem? item)
    {
        item = null;
        if (!raw.Check.IsCanonical)
        {
            return new JoinCursorFinding(RecordCodes.Encoding, Section, raw.Ordinal, null, $"Item {raw.Ordinal} of section {Section} is not canonical ({raw.Check.Rule}): {raw.Check.Message}");
        }

        var parsed = Pb.RecordItem.Parser.ParseFrom(raw.Bytes.Span);
        if (parsed.ItemCase != _member)
        {
            return parsed.ItemCase == Pb.RecordItem.ItemOneofCase.None
                ? new JoinCursorFinding(RecordCodes.Version, Section, raw.Ordinal, null, $"Item {raw.Ordinal} of section {Section} is an item type of a newer format minor, which this reader cannot verify (design §7).")
                : new JoinCursorFinding(StructureCode, Section, raw.Ordinal, null, $"Item {raw.Ordinal} of section {Section} is member {(int)parsed.ItemCase}; the section holds {_member} items only (§4.5).");
        }

        var (locator, contest) = parsed.ItemCase switch
        {
            Pb.RecordItem.ItemOneofCase.ContestDataRequest => (parsed.ContestDataRequest.Ballot, parsed.ContestDataRequest.ContestIndex),
            Pb.RecordItem.ItemOneofCase.ContestDataDecryption => (parsed.ContestDataDecryption.Ballot, parsed.ContestDataDecryption.ContestIndex),
            Pb.RecordItem.ItemOneofCase.ChallengedBallotDecryption => (parsed.ChallengedBallotDecryption.Ballot, 0u),
            _ => (parsed.UncastNonceRelease.Ballot, 0u),
        };

        if (locator is null)
        {
            return new JoinCursorFinding(StructureCode, Section, raw.Ordinal, null, $"Item {raw.Ordinal} of section {Section} names no ballot (its locator is absent).");
        }

        if (!DeviceMapper.IsDeclared(locator.Kind))
        {
            // A device kind of a newer minor in a canonical item (design §7 "Enum value"): this reader
            // cannot say which ballot it names, so it is not joined.
            return new JoinCursorFinding(RecordCodes.Version, Section, raw.Ordinal, null, $"Item {raw.Ordinal} of section {Section} names a ballot of device kind {(int)locator.Kind}, a value of a newer format minor this reader cannot verify (design §7).");
        }

        var key = (DeviceMapper.FromItem(locator), _keyedByContest ? contest : 0u);
        if (_last is { } last)
        {
            int c = key.Item1.CompareTo(last.Locator);
            c = c != 0 ? c : key.Item2.CompareTo(last.Contest);
            if (c < 0)
            {
                return new JoinCursorFinding(RecordCodes.Order, Section, raw.Ordinal, key.Item1, $"Item {raw.Ordinal} of section {Section} is out of canonical ballot order (§4.5: ascending locator{(_keyedByContest ? ", then contest index" : "")}).");
            }

            if (c == 0)
            {
                return new JoinCursorFinding(StructureCode, Section, raw.Ordinal, key.Item1, $"Item {raw.Ordinal} of section {Section} repeats the {(_keyedByContest ? "ballot and contest" : "ballot")} of the item before it (each appears once, §4.5).");
            }
        }

        _last = key;
        item = new JoinItem(raw.Ordinal, raw.Bytes, parsed, key.Item1, contest);
        return null;
    }
}

/// <summary>One joinable item of a join section: its ordinal, bytes, parse, locator and (for contest data) contest index.</summary>
internal sealed record JoinItem(long Ordinal, ReadOnlyMemory<byte> Bytes, Pb.RecordItem Item, BallotLocator Locator, uint ContestIndex);

/// <summary>A join-section finding: its code, where, and the message; <paramref name="BreaksSection"/> when the section could not be read on.</summary>
internal sealed record JoinCursorFinding(string SubSection, SectionKey Section, long? Ordinal, BallotLocator? Locator, string Message, bool BreaksSection = false);
