using ElectionGuard.Core.Models;
using Google.Protobuf;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// One entry of the table of contents (design §4.9): a section's type, key, critical bit, item count
/// and Merkle root. Its leaf in the TOC tree is the leaf hash of its canonical
/// <c>RecordItem{toc_entry}</c> bytes (<see cref="ToRecordItemBytes"/>), whose first bytes are
/// 0x92 0x03 (field 50, LEN). Equality compares the key by content.
/// </summary>
public sealed record TocEntry
{
    private readonly byte[] _key;

    /// <summary>
    /// An entry. Throws <see cref="ArgumentOutOfRangeException"/> for a negative item count or a
    /// type that is not a section type of EGRF v2 (0, the pseudo-sections 0xFFFE and 0xFFFF, and any
    /// undeclared value: a new section kind comes with a new format major, user decision NQ-7, and
    /// there are no vendor sections).
    /// </summary>
    public TocEntry(RecordSectionType type, ReadOnlySpan<byte> key, bool critical, long itemCount, Sha256Digest root)
    {
        if (!RecordSections.IsStandard(type))
        {
            throw new ArgumentOutOfRangeException(nameof(type), type, "Only the section types of EGRF v2 appear in a TOC; 0, 0xFFFE (TOC) and 0xFFFF (signatures) never do.");
        }

        ArgumentOutOfRangeException.ThrowIfNegative(itemCount);
        Type = type;
        _key = key.ToArray();
        Critical = critical;
        ItemCount = itemCount;
        Root = root;
    }

    public RecordSectionType Type { get; }

    /// <summary>The section key: empty, except a device section's 33-byte device key.</summary>
    public ReadOnlyMemory<byte> Key => _key;

    public bool Critical { get; }
    public long ItemCount { get; }

    /// <summary>The section root: MTH of the section's items, in canonical order.</summary>
    public Sha256Digest Root { get; }

    /// <summary>The section's phase (<see cref="RecordSections.PhaseOf"/>).</summary>
    public RecordPhase Phase => RecordSections.PhaseOf(Type);

    /// <summary>The canonical <c>RecordItem{toc_entry}</c> bytes, the input of this entry's leaf hash.</summary>
    public byte[] ToRecordItemBytes() => new Pb.RecordItem
    {
        TocEntry = new Pb.TocEntry
        {
            SectionType = (Pb.SectionType)(ushort)Type,
            Key = ByteString.CopyFrom(_key),
            Critical = Critical,
            ItemCount = (ulong)ItemCount,
            Root = ByteString.CopyFrom(Root.ToArray()),
        },
    }.ToByteArray();

    /// <summary>The leaf hash of <see cref="ToRecordItemBytes"/>.</summary>
    public Sha256Digest LeafHash() => MerkleTree.LeafHash(ToRecordItemBytes());

    /// <summary>Canonical section order: ascending type, then key bytes (unsigned, a prefix first).</summary>
    public static int CompareSections(TocEntry a, TocEntry b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        int c = ((ushort)a.Type).CompareTo((ushort)b.Type);
        return c != 0 ? c : a._key.AsSpan().SequenceCompareTo(b._key);
    }

    public bool Equals(TocEntry? other) =>
        other is not null && Type == other.Type && _key.AsSpan().SequenceEqual(other._key)
        && Critical == other.Critical && ItemCount == other.ItemCount && Root == other.Root;

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Type);
        hash.AddBytes(_key);
        hash.Add(Critical);
        hash.Add(ItemCount);
        hash.Add(Root);
        return hash.ToHashCode();
    }
}

/// <summary>
/// The table of contents of a record and its phase roots (design §4.9):
/// <code>
/// R_phase(p) = MTH(TocEntry_1 .. TocEntry_j), j = the last entry whose section phase &lt;= p
/// </code>
/// Entries are in canonical order (ascending type, then key), which is also phase order, so
/// R_setup, R_sealed, R_aggregated and R_final are prefixes of one another and a later one extends
/// an earlier one by an RFC 9162 consistency proof. A verifier never trusts a stored TOC: it builds
/// this from the sections it read and compares.
/// </summary>
public sealed class TableOfContents
{
    private readonly TocEntry[] _entries;
    private readonly Sha256Digest[] _leaves;

    /// <summary>
    /// A TOC of <paramref name="entries"/>. Throws <see cref="ArgumentException"/> unless they are
    /// non-empty and strictly ascending in canonical section order (a section appears once).
    /// </summary>
    public TableOfContents(IEnumerable<TocEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        _entries = entries.ToArray();
        if (_entries.Length == 0)
        {
            throw new ArgumentException("A table of contents has at least the header section.", nameof(entries));
        }

        for (int i = 0; i < _entries.Length; i++)
        {
            ArgumentNullException.ThrowIfNull(_entries[i], nameof(entries));
            if (i > 0 && TocEntry.CompareSections(_entries[i - 1], _entries[i]) >= 0)
            {
                throw new ArgumentException($"TOC entry {i} (section 0x{(ushort)_entries[i].Type:x4}) is not after entry {i - 1} in canonical order (ascending type, then key), or repeats it.", nameof(entries));
            }
        }

        _leaves = _entries.Select(x => x.LeafHash()).ToArray();
    }

    public IReadOnlyList<TocEntry> Entries => _entries;

    /// <summary>The leaf hashes of the entries, in order (the TOC tree's leaves).</summary>
    public IReadOnlyList<Sha256Digest> LeafHashes => _leaves;

    /// <summary>The record's phase: that of its last section.</summary>
    public RecordPhase Phase => _entries[^1].Phase;

    /// <summary>The record root: <see cref="PhaseRoot"/> of <see cref="Phase"/>, the MTH of every entry.</summary>
    public Sha256Digest Root => MerkleTree.Root(_leaves);

    /// <summary>The number of entries whose phase is at or before <paramref name="phase"/> (a prefix).</summary>
    public int PrefixLength(RecordPhase phase)
    {
        int count = 0;
        while (count < _entries.Length && _entries[count].Phase <= phase)
        {
            count++;
        }

        return count;
    }

    /// <summary>
    /// R_phase: the MTH of the entries whose phase is at or before <paramref name="phase"/>. Throws
    /// <see cref="ArgumentOutOfRangeException"/> for a phase after the record's own: that root does
    /// not exist yet.
    /// </summary>
    public Sha256Digest PhaseRoot(RecordPhase phase)
    {
        if (phase is < RecordPhase.Setup or > RecordPhase.Final || phase > Phase)
        {
            throw new ArgumentOutOfRangeException(nameof(phase), phase, $"The record is at phase {Phase}.");
        }

        return MerkleTree.Root(_leaves.Take(PrefixLength(phase)));
    }

    /// <summary>
    /// Whether this TOC extends <paramref name="earlier"/>: its phase is not earlier, and its entries
    /// of every phase up to <paramref name="earlier"/>'s are exactly <paramref name="earlier"/>'s
    /// entries, so R_p(earlier) = R_p(this) for p = earlier's phase. A section added, removed or
    /// changed at or before that phase (a ballot appended after the seal, say) breaks it.
    /// </summary>
    public bool Extends(TableOfContents earlier)
    {
        ArgumentNullException.ThrowIfNull(earlier);
        if (earlier.Phase > Phase)
        {
            return false;
        }

        int prefix = PrefixLength(earlier.Phase);
        return prefix == earlier._entries.Length && _entries.Take(prefix).SequenceEqual(earlier._entries);
    }

    /// <summary>
    /// The RFC 9162 consistency proof from <paramref name="earlier"/>'s root to this TOC's root,
    /// which <see cref="MerkleProofs.VerifyConsistency"/> checks without either TOC. Throws
    /// <see cref="ArgumentException"/> unless this TOC <see cref="Extends"/> it.
    /// </summary>
    public IReadOnlyList<Sha256Digest> ConsistencyProof(TableOfContents earlier)
    {
        if (!Extends(earlier))
        {
            throw new ArgumentException("This table of contents does not extend the earlier one.", nameof(earlier));
        }

        return MerkleProofs.ConsistencyProof(_leaves, earlier._entries.Length);
    }
}

/// <summary>Digests of the record that are not section or TOC roots (design §4.9).</summary>
public static class RecordDigests
{
    /// <summary>
    /// The canonical <c>RecordItem{confirmation_code_leaf: H}</c> bytes, the leaf input of a codes
    /// root: 0x9A 0x03 0x22 0x0A 0x20 || H (field 51, LEN 34; field 1, LEN 32).
    /// </summary>
    public static byte[] ConfirmationCodeLeafBytes(ConfirmationCode code)
    {
        byte[] bytes = code;
        if (bytes is not { Length: 32 })
        {
            throw new ArgumentException("A confirmation code is 32 bytes.", nameof(code));
        }

        return new Pb.RecordItem { ConfirmationCodeLeaf = new Pb.ConfirmationCodeLeaf { Code = ByteString.CopyFrom(bytes) } }.ToByteArray();
    }

    /// <summary>
    /// codes_root(ℓ) = MTH(leaf(confirmation_code_leaf: H_1) .. leaf(confirmation_code_leaf: H_ℓ)):
    /// a device's confirmation codes in chain order, which a chain-close statement commits to.
    /// </summary>
    public static Sha256Digest CodesRoot(IEnumerable<ConfirmationCode> codes)
    {
        ArgumentNullException.ThrowIfNull(codes);
        var frontier = new MerkleFrontier();
        foreach (var code in codes)
        {
            frontier.Append(ConfirmationCodeLeafBytes(code));
        }

        return frontier.Root();
    }

    /// <summary>A section root: MTH of its items' canonical bytes, in order.</summary>
    public static Sha256Digest SectionRoot(IEnumerable<ReadOnlyMemory<byte>> canonicalItems)
    {
        ArgumentNullException.ThrowIfNull(canonicalItems);
        var frontier = new MerkleFrontier();
        foreach (var item in canonicalItems)
        {
            frontier.Append(item.Span);
        }

        return frontier.Root();
    }
}
