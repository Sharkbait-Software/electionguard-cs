using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// A guardian's own, authoritative view of the cast ballots in the published election record, which
/// the guardian consults before computing a share of a challenged ballot's nonce
/// (<see cref="TallyGuardian.DecryptBallotNonce(EncryptedBallot, EncryptionRecord, IPublishedCastBallots)"/>).
/// A request whose id_B, H_I or C_ξB,0 matches any cast ballot is refused: k shares of a cast
/// ballot's encrypted nonce give its ξ_B, and with it every vote (eq. 33 for a regular ballot,
/// eq. 121 for a pre-encrypted one). User decision Q31 (S9b); the
/// spec defines no such check (§3.6.7 trusts that only challenged ballots reach the guardians).
///
/// Trust model: the request is the administrator's, so everything it carries, its status included,
/// is a claim. This view is not: a guardian in a distributed deployment builds it from its own copy
/// of the published record (cast ballots are public), never from anything the administrator hands it
/// with the request. In-process (this library's <see cref="TallyAdmin"/> drives the guardians) the
/// caller holds the record anyway. The view protects only what it holds, so for challenged ballots it
/// must be complete: decrypt challenged ballots once the record's cast ballots are final.
///
/// The check refuses every cast ballot, including those §3.3.4 p.30 names as a use of ballot nonce
/// decryption: "ballots that are selected in the context of a risk limiting audit". That is by
/// design under Q31. A risk-limiting audit (deferred, user decision Q22) needs an authorization path
/// of its own, such as an audit-selection list committed after the record is final, which this
/// library does not model.
/// </summary>
public interface IPublishedCastBallots
{
    /// <summary>H_E of the election whose cast ballots this view holds.</summary>
    ExtendedBaseHash ExtendedBaseHash { get; }

    /// <summary>
    /// Which of a request's values match a cast ballot: its id_B, its H_I and its C_ξB,0, each
    /// compared by content against every cast ballot (not necessarily the same one).
    /// <see cref="CastBallotMatch.None"/> if none does.
    /// </summary>
    CastBallotMatch Match(SelectionEncryptionIdentifier selectionEncryptionIdentifier, SelectionEncryptionIdentifierHash? selectionEncryptionIdentifierHash, IntegerModP? encryptedBallotNonceC0);
}

/// <summary>Which values of a ballot-nonce decryption request match a cast ballot.</summary>
[Flags]
public enum CastBallotMatch
{
    None = 0,

    /// <summary>The request's id_B is a cast ballot's.</summary>
    SelectionEncryptionIdentifier = 1,

    /// <summary>The request's H_I is a cast ballot's.</summary>
    SelectionEncryptionIdentifierHash = 2,

    /// <summary>The request's C_ξB,0 is a cast ballot's.</summary>
    EncryptedBallotNonce = 4,
}

/// <summary>
/// An in-memory <see cref="IPublishedCastBallots"/>: three hash sets of 32-byte keys, one each for
/// id_B, H_I and C_ξB,0 (the last keyed by SHA-256 of its 512-byte encoding, so a cast ballot costs
/// about 3 x 32 bytes plus set overhead, not 576), filled incrementally as ballots are published.
/// Safe to read and add from several threads. A deployment with more cast ballots than memory
/// implements <see cref="IPublishedCastBallots"/> over its own store, with the same semantics.
/// </summary>
public sealed class PublishedCastBallots : IPublishedCastBallots
{
    private readonly HashSet<Key256> _identifiers = [];
    private readonly HashSet<Key256> _identifierHashes = [];
    private readonly HashSet<Key256> _nonces = [];
    private readonly object _lock = new();

    /// <summary>An empty view for the election with extended base hash <paramref name="extendedBaseHash"/>.</summary>
    public PublishedCastBallots(ExtendedBaseHash extendedBaseHash)
    {
        ExtendedBaseHash = extendedBaseHash ?? throw new ArgumentNullException(nameof(extendedBaseHash));
    }

    public ExtendedBaseHash ExtendedBaseHash { get; }

    /// <summary>The number of distinct id_Bs held.</summary>
    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _identifiers.Count;
            }
        }
    }

    /// <summary>
    /// A view holding every ballot of <paramref name="ballots"/> (a published record's submitted
    /// ballots) that is recorded as <see cref="BallotStatus.Cast"/>, regular or pre-encrypted; the
    /// rest are skipped.
    /// </summary>
    public static PublishedCastBallots FromRecord(ExtendedBaseHash extendedBaseHash, IEnumerable<EncryptedBallot> ballots)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        var view = new PublishedCastBallots(extendedBaseHash);
        foreach (var ballot in ballots)
        {
            if (ballot.Status == BallotStatus.Cast)
            {
                view.Add(ballot);
            }
        }

        return view;
    }

    /// <summary>
    /// Adds a cast ballot as it is published. Throws <see cref="ArgumentException"/> if it is not
    /// recorded as cast (a challenged ballot here would refuse its own decryption), carries no C_ξB,
    /// has an id_B or H_I that is not 32 bytes, or its H_I is not H(H_E; 0x20, id_B) for this view's
    /// H_E (a ballot of another election, or one failing Verification 5.B): build the view from a
    /// verified record.
    /// </summary>
    public void Add(EncryptedBallot ballot)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        if (ballot.Status != BallotStatus.Cast)
        {
            throw new ArgumentException($"Ballot {ballot.Id} is recorded as {ballot.Status}, not as cast; only cast ballots are held.", nameof(ballot));
        }

        if (ballot.EncryptedBallotNonce is null)
        {
            throw new ArgumentException($"Ballot {ballot.Id} carries no encrypted ballot nonce C_ξB.", nameof(ballot));
        }

        byte[]? identifier = ballot.SelectionEncryptionIdentifier;
        byte[]? identifierHash = ballot.SelectionEncryptionIdentifierHash is null ? null : (byte[])ballot.SelectionEncryptionIdentifierHash;
        if (identifier is not { Length: SelectionEncryptionIdentifier.ByteLength } || identifierHash is not { Length: 32 })
        {
            throw new ArgumentException($"Ballot {ballot.Id}'s id_B and H_I must each be 32 bytes.", nameof(ballot));
        }

        var expected = new SelectionEncryptionIdentifierHash(ExtendedBaseHash, ballot.SelectionEncryptionIdentifier);
        if (!((byte[])expected).AsSpan().SequenceEqual(identifierHash))
        {
            throw new ArgumentException($"Ballot {ballot.Id}'s H_I is not H(H_E; 0x20, id_B) for this election (Verification 5.B).", nameof(ballot));
        }

        var nonceKey = NonceKey(ballot.EncryptedBallotNonce.C0);
        lock (_lock)
        {
            _identifiers.Add(Key256.From(identifier));
            _identifierHashes.Add(Key256.From(identifierHash));
            _nonces.Add(nonceKey);
        }
    }

    /// <summary><see cref="Add(EncryptedBallot)"/> for each of <paramref name="ballots"/>.</summary>
    public void AddRange(IEnumerable<EncryptedBallot> ballots)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        foreach (var ballot in ballots)
        {
            Add(ballot);
        }
    }

    public CastBallotMatch Match(SelectionEncryptionIdentifier selectionEncryptionIdentifier, SelectionEncryptionIdentifierHash? selectionEncryptionIdentifierHash, IntegerModP? encryptedBallotNonceC0)
    {
        // A value of the wrong length matches nothing held here; the request's structure check
        // refuses it afterwards.
        byte[]? identifier = selectionEncryptionIdentifier;
        byte[]? identifierHash = selectionEncryptionIdentifierHash is null ? null : (byte[])selectionEncryptionIdentifierHash;
        Key256? nonceKey = encryptedBallotNonceC0 is { } c0 ? NonceKey(c0) : null;

        var match = CastBallotMatch.None;
        lock (_lock)
        {
            if (identifier is { Length: 32 } && _identifiers.Contains(Key256.From(identifier)))
            {
                match |= CastBallotMatch.SelectionEncryptionIdentifier;
            }

            if (identifierHash is { Length: 32 } && _identifierHashes.Contains(Key256.From(identifierHash)))
            {
                match |= CastBallotMatch.SelectionEncryptionIdentifierHash;
            }

            if (nonceKey is { } key && _nonces.Contains(key))
            {
                match |= CastBallotMatch.EncryptedBallotNonce;
            }
        }

        return match;
    }

    private static Key256 NonceKey(IntegerModP c0)
    {
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(c0.ToByteArray(), digest);
        return Key256.From(digest);
    }

    /// <summary>
    /// A 32-byte value as a set key. The hash code goes through <see cref="HashCode"/>'s per-process
    /// random seed: id_B and C_ξB,0 are chosen by whoever produced the ballot, so a fixed hash would
    /// let a crafted record degrade every set to a list.
    /// </summary>
    private readonly struct Key256 : IEquatable<Key256>
    {
        private readonly ulong _a, _b, _c, _d;

        private Key256(ulong a, ulong b, ulong c, ulong d)
        {
            _a = a;
            _b = b;
            _c = c;
            _d = d;
        }

        public static Key256 From(ReadOnlySpan<byte> bytes) => new(
            BinaryPrimitives.ReadUInt64BigEndian(bytes),
            BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(bytes[16..]),
            BinaryPrimitives.ReadUInt64BigEndian(bytes[24..]));

        public bool Equals(Key256 other) => _a == other._a && _b == other._b && _c == other._c && _d == other._d;

        public override bool Equals(object? obj) => obj is Key256 other && Equals(other);

        public override int GetHashCode() => HashCode.Combine(_a, _b, _c, _d);
    }
}
