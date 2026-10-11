using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 5 (Uniqueness of selection encryption identifiers)
/// </summary>
public class SelectionEncryptionIdentifierVerification
{
    /// <summary>
    /// 5.A over <paramref name="identifiers"/>, which must be the identifiers of every submitted
    /// (cast, challenged and spoiled) ballot of the election: a list per ballot, or per batch, checks nothing
    /// across them. A caller that sees the ballots in batches should feed one
    /// <see cref="SelectionEncryptionIdentifierSet"/> instead.
    /// </summary>
    public void Verify(IReadOnlyCollection<SelectionEncryptionIdentifier> identifiers)
    {
        var set = new SelectionEncryptionIdentifierSet(identifiers.Count);
        foreach (var identifier in identifiers)
        {
            set.Add(identifier);
        }
    }

    public void Verify(SelectionEncryptionIdentifier identifier, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, ExtendedBaseHash extendedBaseHash)
    {
        var expected = EGHash.Hash(extendedBaseHash,
            [0x20],
            identifier);

        if (!expected.SequenceEqual((byte[])selectionEncryptionIdentifierHash))
        {
            throw new VerificationFailedException("5.B", "Selection encryption identifier hash was not calculated correctly.");
        }
    }
}

/// <summary>
/// Verification 5.A performed incrementally: the identifiers seen so far, compared by content, so
/// that a caller holding only a batch of ballots at a time -- a stream, chunks, several sources --
/// still checks uniqueness across the whole election. Holds one entry per identifier, not the
/// ballots. Not thread-safe.
/// </summary>
public class SelectionEncryptionIdentifierSet
{
    private readonly HashSet<SelectionEncryptionIdentifier> _seen;

    public SelectionEncryptionIdentifierSet(int capacity = 0)
    {
        _seen = new HashSet<SelectionEncryptionIdentifier>(capacity);
    }

    /// <summary>The number of distinct identifiers added so far.</summary>
    public int Count => _seen.Count;

    /// <summary>
    /// Adds <paramref name="identifier"/>, throwing <see cref="VerificationFailedException"/> with
    /// sub-section 5.A if an equal identifier was added before.
    /// </summary>
    public void Add(SelectionEncryptionIdentifier identifier)
    {
        if (!_seen.Add(identifier))
        {
            throw new VerificationFailedException("5.A", $"Duplicate selection encryption identifier detected. {identifier}");
        }
    }
}
