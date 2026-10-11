using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// A guardian's own, authoritative view of the published election record's cast and spoiled
/// ballots, which the guardian consults before computing a share of a challenged ballot's nonce
/// (<see cref="TallyGuardian.DecryptBallotNonce(EncryptedBallot, EncryptionRecord, IPublishedCastAndSpoiledBallots)"/>).
/// A request whose id_B, H_I or C_ξB,0 matches any cast or spoiled ballot is refused: k shares of a
/// ballot's encrypted nonce give its ξ_B, and with it every selection on it (eq. 33 for a regular
/// ballot, eq. 121 for a pre-encrypted one).
/// <list type="bullet">
/// <item>Cast ballots: user decision Q31 (S9b). Opening one reveals a counted vote.</item>
/// <item>Spoiled ballots (<see cref="BallotStatus.Spoiled"/>): user decision "Refuse spoiled too"
/// (2026-10-09, on S10b-A's readings). A spoiled ballot was submitted but neither cast nor
/// challenged, for example abandoned by its voter, and §3.6.7 opens only ballots the voter
/// challenged; its selections may be the voter's real intent, so its nonce is never released. The
/// status test in <see cref="TallyGuardian.DecryptBallotNonce(EncryptedBallot, EncryptionRecord, IPublishedCastAndSpoiledBallots)"/>
/// reads the requester's claim, so without this view a spoiled ballot relabelled challenged would be
/// opened.</item>
/// </list>
/// The spec defines no such check (§3.6.7 trusts that only challenged ballots reach the guardians).
///
/// Trust model: the request is the administrator's, so everything it carries, its status included,
/// is a claim. This view is not: a guardian in a distributed deployment builds it from its own copy
/// of the published (sealed) record, never from anything the administrator hands it with the
/// request. In-process (this library's <see cref="TallyAdmin"/> drives the guardians) the caller
/// holds the record anyway. The view protects only what it holds, so for challenged ballots it must
/// be complete: decrypt challenged ballots once the record's ballots are final (user decision Q36:
/// guardians decrypt only after voting has closed and the record is sealed).
///
/// The check refuses every cast ballot, including those §3.3.4 p.30 names as a use of ballot nonce
/// decryption: "ballots that are selected in the context of a risk limiting audit". That is by
/// design under Q31. A risk-limiting audit (deferred, user decision Q22) needs an authorization path
/// of its own, such as an audit-selection list committed after the record is final, which this
/// library does not model.
/// </summary>
public interface IPublishedCastAndSpoiledBallots
{
    /// <summary>H_E of the election whose ballots this view holds.</summary>
    ExtendedBaseHash ExtendedBaseHash { get; }

    /// <summary>
    /// Which of a request's values match a cast ballot, and which match a spoiled ballot: its id_B,
    /// its H_I and its C_ξB,0, each compared by content against every ballot held (not necessarily
    /// the same one). <see cref="PublishedBallotMatch.None"/> if none does.
    /// </summary>
    PublishedBallotMatch Match(SelectionEncryptionIdentifier selectionEncryptionIdentifier, SelectionEncryptionIdentifierHash? selectionEncryptionIdentifierHash, IntegerModP? encryptedBallotNonceC0);
}

/// <summary>Which values of a ballot-nonce decryption request match a ballot held by the view.</summary>
[Flags]
public enum BallotValueMatch
{
    None = 0,

    /// <summary>The request's id_B is a held ballot's.</summary>
    SelectionEncryptionIdentifier = 1,

    /// <summary>The request's H_I is a held ballot's.</summary>
    SelectionEncryptionIdentifierHash = 2,

    /// <summary>The request's C_ξB,0 is a held ballot's.</summary>
    EncryptedBallotNonce = 4,
}

/// <summary>
/// The values of a request that match a cast ballot (<see cref="Cast"/>) and those that match a
/// spoiled ballot (<see cref="Spoiled"/>) of the published record.
/// </summary>
public readonly record struct PublishedBallotMatch(BallotValueMatch Cast, BallotValueMatch Spoiled)
{
    /// <summary>Nothing matches.</summary>
    public static PublishedBallotMatch None => default;

    /// <summary>Whether no value matches any ballot held.</summary>
    public bool IsNone => Cast == BallotValueMatch.None && Spoiled == BallotValueMatch.None;
}

/// <summary>
/// An in-memory <see cref="IPublishedCastAndSpoiledBallots"/>: per status, three hash sets of 32-byte
/// keys, one each for id_B, H_I and C_ξB,0 (the last keyed by SHA-256 of its 512-byte encoding, so a
/// ballot costs about 3 x 32 bytes plus set overhead, not 576), filled incrementally as ballots are
/// published. Safe to read and add from several threads. A deployment with more ballots than memory
/// implements <see cref="IPublishedCastAndSpoiledBallots"/> over its own store, with the same
/// semantics.
/// </summary>
public sealed class PublishedCastAndSpoiledBallots : IPublishedCastAndSpoiledBallots
{
    private readonly KeySets _cast = new();
    private readonly KeySets _spoiled = new();
    private readonly object _lock = new();

    /// <summary>An empty view for the election with extended base hash <paramref name="extendedBaseHash"/>.</summary>
    public PublishedCastAndSpoiledBallots(ExtendedBaseHash extendedBaseHash)
    {
        ExtendedBaseHash = extendedBaseHash ?? throw new ArgumentNullException(nameof(extendedBaseHash));
    }

    public ExtendedBaseHash ExtendedBaseHash { get; }

    /// <summary>The number of distinct id_Bs held as cast.</summary>
    public int CastCount
    {
        get
        {
            lock (_lock)
            {
                return _cast.Identifiers.Count;
            }
        }
    }

    /// <summary>The number of distinct id_Bs held as spoiled.</summary>
    public int SpoiledCount
    {
        get
        {
            lock (_lock)
            {
                return _spoiled.Identifiers.Count;
            }
        }
    }

    /// <summary>
    /// A view holding every ballot of <paramref name="ballots"/> (a published record's submitted
    /// ballots, regular or pre-encrypted) that is recorded as <see cref="BallotStatus.Cast"/> or
    /// <see cref="BallotStatus.Spoiled"/>; challenged ballots, the ones a guardian may open, are
    /// skipped. A ballot with any other status (<see cref="BallotStatus.Unrecorded"/>, or a value that
    /// is not a status) throws <see cref="ArgumentException"/>: every ballot of a published record
    /// has a recorded status, and skipping one silently would leave it unprotected.
    /// </summary>
    public static PublishedCastAndSpoiledBallots FromRecord(ExtendedBaseHash extendedBaseHash, IEnumerable<EncryptedBallot> ballots)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        var view = new PublishedCastAndSpoiledBallots(extendedBaseHash);
        foreach (var ballot in ballots)
        {
            ArgumentNullException.ThrowIfNull(ballot, nameof(ballots));
            switch (ballot.Status)
            {
                case BallotStatus.Cast or BallotStatus.Spoiled:
                    view.Add(ballot);
                    break;
                case BallotStatus.Challenged:
                    break;
                default:
                    throw new ArgumentException($"Ballot {ballot.Id} has no recorded status ({ballot.Status}); every ballot of a published record is cast, challenged or spoiled.", nameof(ballots));
            }
        }

        return view;
    }

    /// <summary>
    /// Adds a cast or spoiled ballot as it is published. Throws <see cref="ArgumentException"/> if it
    /// is recorded as anything else (a challenged ballot here would refuse its own decryption),
    /// carries no C_ξB, has an id_B or H_I that is not 32 bytes, or its H_I is not H(H_E; 0x20, id_B)
    /// for this view's H_E (a ballot of another election, or one failing Verification 5.B): build the
    /// view from a verified record. A ballot added under both statuses (two ballots of the record
    /// sharing values) is held under both.
    /// </summary>
    public void Add(EncryptedBallot ballot)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        if (ballot.Status is not (BallotStatus.Cast or BallotStatus.Spoiled))
        {
            throw new ArgumentException($"Ballot {ballot.Id} is recorded as {ballot.Status}, not as cast or spoiled; only cast and spoiled ballots are held.", nameof(ballot));
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

        Hold(ballot.Status, identifier, identifierHash, NonceKey(ballot.EncryptedBallotNonce.C0));
    }

    /// <summary>
    /// Adds a cast or spoiled ballot by the raw values a sealed record's item stores: its 32-byte
    /// id_B and H_I and the 512 bytes of C_ξB,0 (keyed by their SHA-256, as <see cref="Add(EncryptedBallot)"/>
    /// keys C_ξB,0's encoding), or an empty span when the item carries no C_ξB. For the record
    /// verifier, which builds the view from the parsed items whatever their verification findings:
    /// an item with a value out of range has no <see cref="EncryptedBallot"/> (design §4.8), yet its
    /// id_B, H_I and C_ξB,0 must still be refused, or a challenged copy of it with a repaired proof
    /// would be opened. So the values are held as stored, with no check that H_I is
    /// H(H_E; 0x20, id_B) (holding more only refuses more). Throws <see cref="ArgumentException"/>
    /// for any other status or width.
    /// </summary>
    public void Add(BallotStatus status, ReadOnlySpan<byte> selectionEncryptionIdentifier, ReadOnlySpan<byte> selectionEncryptionIdentifierHash, ReadOnlySpan<byte> encryptedBallotNonceC0)
    {
        if (status is not (BallotStatus.Cast or BallotStatus.Spoiled))
        {
            throw new ArgumentException($"A ballot recorded as {status} is not held; only cast and spoiled ballots are.", nameof(status));
        }

        if (selectionEncryptionIdentifier.Length != SelectionEncryptionIdentifier.ByteLength || selectionEncryptionIdentifierHash.Length != 32)
        {
            throw new ArgumentException("id_B and H_I must each be 32 bytes.", nameof(selectionEncryptionIdentifier));
        }

        if (encryptedBallotNonceC0.Length is not (0 or 512))
        {
            throw new ArgumentException("C_ξB,0 is 512 bytes, or empty when the item carries no C_ξB.", nameof(encryptedBallotNonceC0));
        }

        Key256? nonceKey = null;
        if (!encryptedBallotNonceC0.IsEmpty)
        {
            Span<byte> digest = stackalloc byte[32];
            SHA256.HashData(encryptedBallotNonceC0, digest);
            nonceKey = Key256.From(digest);
        }

        Hold(status, selectionEncryptionIdentifier, selectionEncryptionIdentifierHash, nonceKey);
    }

    private void Hold(BallotStatus status, ReadOnlySpan<byte> identifier, ReadOnlySpan<byte> identifierHash, Key256? nonceKey)
    {
        var identifierKey = Key256.From(identifier);
        var identifierHashKey = Key256.From(identifierHash);
        var sets = status == BallotStatus.Cast ? _cast : _spoiled;
        lock (_lock)
        {
            sets.Identifiers.Add(identifierKey);
            sets.IdentifierHashes.Add(identifierHashKey);
            if (nonceKey is { } key)
            {
                sets.Nonces.Add(key);
            }
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

    public PublishedBallotMatch Match(SelectionEncryptionIdentifier selectionEncryptionIdentifier, SelectionEncryptionIdentifierHash? selectionEncryptionIdentifierHash, IntegerModP? encryptedBallotNonceC0)
    {
        // A value of the wrong length matches nothing held here; the request's structure check
        // refuses it afterwards.
        byte[]? identifier = selectionEncryptionIdentifier;
        byte[]? identifierHash = selectionEncryptionIdentifierHash is null ? null : (byte[])selectionEncryptionIdentifierHash;
        Key256? identifierKey = identifier is { Length: 32 } ? Key256.From(identifier) : null;
        Key256? identifierHashKey = identifierHash is { Length: 32 } ? Key256.From(identifierHash) : null;
        Key256? nonceKey = encryptedBallotNonceC0 is { } c0 ? NonceKey(c0) : null;

        lock (_lock)
        {
            return new PublishedBallotMatch(
                _cast.Match(identifierKey, identifierHashKey, nonceKey),
                _spoiled.Match(identifierKey, identifierHashKey, nonceKey));
        }
    }

    private static Key256 NonceKey(IntegerModP c0)
    {
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(c0.ToByteArray(), digest);
        return Key256.From(digest);
    }

    private sealed class KeySets
    {
        public HashSet<Key256> Identifiers { get; } = [];
        public HashSet<Key256> IdentifierHashes { get; } = [];
        public HashSet<Key256> Nonces { get; } = [];

        public BallotValueMatch Match(Key256? identifier, Key256? identifierHash, Key256? nonce)
        {
            var match = BallotValueMatch.None;
            if (identifier is { } i && Identifiers.Contains(i))
            {
                match |= BallotValueMatch.SelectionEncryptionIdentifier;
            }

            if (identifierHash is { } h && IdentifierHashes.Contains(h))
            {
                match |= BallotValueMatch.SelectionEncryptionIdentifierHash;
            }

            if (nonce is { } n && Nonces.Contains(n))
            {
                match |= BallotValueMatch.EncryptedBallotNonce;
            }

            return match;
        }
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
