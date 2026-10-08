using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ElectionGuard.Core.PreEncryption;

/// <summary>One issued pre-encrypted ballot: its id_B and the C_ξB,0 printed with it.</summary>
public sealed record IssuedPreEncryptedBallot(SelectionEncryptionIdentifier SelectionEncryptionIdentifier, IntegerModP EncryptedBallotNonceC0);

/// <summary>
/// The printer-committed list of every pre-encrypted ballot the encrypting tool issued (user decision
/// Q31, S9b; the spec defines no such list). Guardians decrypt a pre-encrypted ballot's nonce for
/// the recording tool (§4.3.1) only when the request's id_B is on this list with the C_ξB,0 committed
/// for it, and each guardian each id_B at most once
/// (<see cref="Tally.TallyGuardian.DecryptBallotNonce(PreEncryptedBallot, EncryptionRecord, Tally.IPublishedCastBallots, IssuedPreEncryptedBallots)"/>).
/// That keeps regular ballots out of the pre-encrypted path (their id_B is never on it) and keeps a
/// recorded pre-encrypted ballot from being decrypted a second time by any quorum that includes a
/// guardian that answered (every quorum when n &lt; 2k; see the <see cref="Tally.TallyGuardian"/>
/// constructor). The list holds its own copies of the id_Bs and hands out copies.
///
/// The list is fixed when it is built and committed before voting begins. Each guardian holds its
/// own copy, received from the printer, never with a request from the administrator, and all
/// guardians confirm they hold the same list by comparing <see cref="Commitment"/>.
///
/// <b>Encoding (library format, not part of the ElectionGuard spec):</b> <see cref="ToCanonicalBytes"/>
/// writes, in order,
/// <list type="number">
/// <item>the 48 ASCII bytes of <see cref="FormatTag"/>, <c>electionguard-cs:issued-pre-encrypted-ballots:v1</c>;</item>
/// <item>H_E, 32 bytes;</item>
/// <item>the number of ballots n, 4 bytes, big-endian;</item>
/// <item>n entries in strictly increasing order of id_B (unsigned, byte by byte), each
/// b(id_B, 32) ‖ b(C_ξB,0, 512).</item>
/// </list>
/// <see cref="Commitment"/> is SHA-256 of those bytes. Plain SHA-256, not the spec's H: this value
/// is not an ElectionGuard hash and takes no domain-separation byte from §5.5.
/// <see cref="FromCanonicalBytes"/> reads the same bytes strictly.
/// </summary>
public sealed class IssuedPreEncryptedBallots
{
    /// <summary>The format tag that starts <see cref="ToCanonicalBytes"/>.</summary>
    public const string FormatTag = "electionguard-cs:issued-pre-encrypted-ballots:v1";

    private static readonly byte[] TagBytes = Encoding.ASCII.GetBytes(FormatTag);
    private const int HashLength = 32;
    private const int EntryLength = SelectionEncryptionIdentifier.ByteLength + IntegerModP.ByteLength;

    private readonly byte[] _extendedBaseHash;
    private readonly Dictionary<SelectionEncryptionIdentifier, IssuedPreEncryptedBallot> _byIdentifier;
    private readonly List<IssuedPreEncryptedBallot> _sorted;
    private readonly byte[] _commitment;

    /// <summary>
    /// The list of <paramref name="ballots"/> for the election with extended base hash
    /// <paramref name="extendedBaseHash"/>. Throws <see cref="ArgumentException"/> if an id_B is not
    /// 32 bytes or appears twice.
    /// </summary>
    public IssuedPreEncryptedBallots(ExtendedBaseHash extendedBaseHash, IEnumerable<IssuedPreEncryptedBallot> ballots)
        : this((byte[])(extendedBaseHash ?? throw new ArgumentNullException(nameof(extendedBaseHash))), ballots)
    {
    }

    private IssuedPreEncryptedBallots(byte[] extendedBaseHash, IEnumerable<IssuedPreEncryptedBallot> ballots)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        _extendedBaseHash = extendedBaseHash.ToArray();
        _byIdentifier = [];
        foreach (var ballot in ballots)
        {
            ArgumentNullException.ThrowIfNull(ballot, nameof(ballots));
            byte[]? identifier = ballot.SelectionEncryptionIdentifier;
            if (identifier is not { Length: SelectionEncryptionIdentifier.ByteLength })
            {
                throw new ArgumentException($"An issued ballot's id_B must be {SelectionEncryptionIdentifier.ByteLength} bytes.", nameof(ballots));
            }

            // The list's own copy of id_B: SelectionEncryptionIdentifier wraps its array without
            // copying and hashes by content, so a key sharing the caller's array would move to
            // another hash bucket, and drift from the commitment, if the caller changed it.
            var owned = Copy(ballot);
            if (!_byIdentifier.TryAdd(owned.SelectionEncryptionIdentifier, owned))
            {
                throw new ArgumentException($"id_B {ballot.SelectionEncryptionIdentifier} is issued twice.", nameof(ballots));
            }
        }

        _sorted = _byIdentifier.Values
            .OrderBy(x => (byte[])x.SelectionEncryptionIdentifier, ByteOrder.Instance)
            .ToList();
        _commitment = SHA256.HashData(ToCanonicalBytes());
    }

    /// <summary>The list of the printed <paramref name="ballots"/>, as the encrypting tool issues them.</summary>
    public static IssuedPreEncryptedBallots FromPrintedBallots(ExtendedBaseHash extendedBaseHash, IEnumerable<PreEncryptedBallot> ballots)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        return new IssuedPreEncryptedBallots(extendedBaseHash, ballots.Select(x =>
        {
            ArgumentNullException.ThrowIfNull(x, nameof(ballots));
            return new IssuedPreEncryptedBallot(x.SelectionEncryptionIdentifier,
                (x.EncryptedBallotNonce ?? throw new ArgumentException($"Printed ballot {x.Id} carries no encrypted ballot nonce C_ξB.", nameof(ballots))).C0);
        }));
    }

    /// <summary>
    /// Reads <see cref="ToCanonicalBytes"/>'s format strictly: the tag, H_E equal to
    /// <paramref name="extendedBaseHash"/>, the exact length for n entries, id_Bs strictly
    /// increasing, and each C_ξB,0 below p. Throws <see cref="NonCanonicalEncodingException"/>
    /// otherwise.
    /// </summary>
    public static IssuedPreEncryptedBallots FromCanonicalBytes(ReadOnlySpan<byte> bytes, ExtendedBaseHash extendedBaseHash)
    {
        ArgumentNullException.ThrowIfNull(extendedBaseHash);
        int header = TagBytes.Length + HashLength + sizeof(uint);
        if (bytes.Length < header || !bytes[..TagBytes.Length].SequenceEqual(TagBytes))
        {
            throw new NonCanonicalEncodingException($"An issued pre-encrypted ballot list must start with the tag \"{FormatTag}\", H_E and a count.");
        }

        if (!bytes.Slice(TagBytes.Length, HashLength).SequenceEqual((byte[])extendedBaseHash))
        {
            throw new NonCanonicalEncodingException("The issued pre-encrypted ballot list is for another election: its H_E differs.");
        }

        uint count = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(TagBytes.Length + HashLength, sizeof(uint)));
        if ((ulong)(bytes.Length - header) != (ulong)count * EntryLength)
        {
            throw new NonCanonicalEncodingException($"An issued pre-encrypted ballot list of {count} ballots must be {header + (long)count * EntryLength} bytes; got {bytes.Length}.");
        }

        var entries = new List<IssuedPreEncryptedBallot>((int)count);
        ReadOnlySpan<byte> previous = default;
        for (int i = 0; i < count; i++)
        {
            var entry = bytes.Slice(header + i * EntryLength, EntryLength);
            var identifier = entry[..SelectionEncryptionIdentifier.ByteLength];
            if (i > 0 && identifier.SequenceCompareTo(previous) <= 0)
            {
                throw new NonCanonicalEncodingException("The ballots of an issued pre-encrypted ballot list must be in strictly increasing order of id_B.");
            }

            previous = identifier;
            entries.Add(new IssuedPreEncryptedBallot(
                SelectionEncryptionIdentifier.FromCanonicalBytes(identifier),
                IntegerModP.FromCanonicalBytes(entry[SelectionEncryptionIdentifier.ByteLength..])));
        }

        return new IssuedPreEncryptedBallots((byte[])extendedBaseHash, entries);
    }

    /// <summary>
    /// The issued ballots in increasing order of id_B (the canonical order). Each read returns
    /// copies, so changing an id_B's array changes nothing held here.
    /// </summary>
    public IReadOnlyList<IssuedPreEncryptedBallot> Ballots => _sorted.Select(Copy).ToList();

    public int Count => _sorted.Count;

    /// <summary>
    /// SHA-256 of <see cref="ToCanonicalBytes"/> (library format, not an ElectionGuard hash). Each
    /// read returns a copy.
    /// </summary>
    public byte[] Commitment => _commitment.ToArray();

    /// <summary>Whether this list is for the election with extended base hash <paramref name="extendedBaseHash"/>.</summary>
    public bool IsFor(ExtendedBaseHash extendedBaseHash) =>
        extendedBaseHash is not null && _extendedBaseHash.AsSpan().SequenceEqual((byte[])extendedBaseHash);

    /// <summary>The issued ballot with id_B <paramref name="selectionEncryptionIdentifier"/>, if there is one (a copy).</summary>
    public bool TryGet(SelectionEncryptionIdentifier selectionEncryptionIdentifier, out IssuedPreEncryptedBallot ballot)
    {
        if (_byIdentifier.TryGetValue(selectionEncryptionIdentifier, out var held))
        {
            ballot = Copy(held);
            return true;
        }

        ballot = null!;
        return false;
    }

    /// <summary>The entry with a copy of its id_B's bytes (32 bytes, checked by the caller).</summary>
    private static IssuedPreEncryptedBallot Copy(IssuedPreEncryptedBallot ballot) =>
        ballot with { SelectionEncryptionIdentifier = SelectionEncryptionIdentifier.FromCanonicalBytes((byte[])ballot.SelectionEncryptionIdentifier) };

    /// <summary>The canonical encoding described in the class remarks.</summary>
    public byte[] ToCanonicalBytes()
    {
        int header = TagBytes.Length + HashLength + sizeof(uint);
        var bytes = new byte[header + _sorted.Count * EntryLength];
        TagBytes.CopyTo(bytes, 0);
        _extendedBaseHash.CopyTo(bytes, TagBytes.Length);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(TagBytes.Length + HashLength), (uint)_sorted.Count);
        for (int i = 0; i < _sorted.Count; i++)
        {
            var entry = bytes.AsSpan(header + i * EntryLength, EntryLength);
            ((byte[])_sorted[i].SelectionEncryptionIdentifier).CopyTo(entry);
            _sorted[i].EncryptedBallotNonceC0.ToByteArray().CopyTo(entry[SelectionEncryptionIdentifier.ByteLength..]);
        }

        return bytes;
    }

    private sealed class ByteOrder : IComparer<byte[]>
    {
        public static readonly ByteOrder Instance = new();

        public int Compare(byte[]? x, byte[]? y) => x.AsSpan().SequenceCompareTo(y);
    }
}
