using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.RecordFormat.Mappers;

/// <summary>
/// Joins the record's ballot locators to the domain's ballots. The final-phase items (challenged
/// ballot decryptions, contest-data requests and decryptions, uncast nonce releases) name their
/// ballot by locator and H_I (design §4.5), while the domain objects name it by <c>BallotId</c>, the
/// unverified free text of <c>ballot_ref</c> (follow-up #12), which two ballots may share (devices
/// that number their paper independently). So nothing here is keyed by that text: reading resolves a
/// locator, which names one ballot, and writing locates a ballot by its H_I. An in-memory index,
/// built from the device sections in chain order.
/// </summary>
internal sealed class RecordBallotIndex
{
    private readonly Dictionary<BallotLocator, (string BallotId, SelectionEncryptionIdentifierHash IdentifierHash)> _byLocator = [];

    /// <summary>The locators of each H_I (as lowercase hex); more than one when two ballots share id_B, a 5.A failure.</summary>
    private readonly Dictionary<string, List<BallotLocator>> _byIdentifierHash = new(StringComparer.Ordinal);

    /// <summary>
    /// An index of one ballot, at <paramref name="locator"/>: the record verifier's streaming join
    /// (design §6.3) decodes each final-phase item next to the one ballot its locator names, so it
    /// never holds the O(N) index.
    /// </summary>
    public static RecordBallotIndex Single(BallotLocator locator, string ballotId, SelectionEncryptionIdentifierHash identifierHash)
    {
        var index = new RecordBallotIndex();
        index._byLocator[locator] = (ballotId, identifierHash);
        index._byIdentifierHash[Key(identifierHash)] = [locator];
        return index;
    }

    /// <summary>Adds a device section's ballots, in chain order: the i-th is at position i.</summary>
    public void AddDevice(DeviceKey device, IEnumerable<(string BallotId, SelectionEncryptionIdentifierHash IdentifierHash)> ballots)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        long position = 0;
        foreach (var (ballotId, identifierHash) in ballots)
        {
            var locator = new BallotLocator(device, ++position);
            _byLocator[locator] = (ballotId, identifierHash);
            string key = Key(identifierHash);
            if (!_byIdentifierHash.TryGetValue(key, out var locators))
            {
                _byIdentifierHash[key] = locators = [];
            }

            locators.Add(locator);
        }
    }

    /// <summary>
    /// The locator of the ballot whose H_I is <paramref name="identifierHash"/>. Throws
    /// <see cref="ArgumentException"/> if the record has no such ballot, or two (they share id_B,
    /// which 5.A refuses, so no item can name either one by H_I).
    /// </summary>
    public (BallotLocator Locator, SelectionEncryptionIdentifierHash IdentifierHash) Locate(SelectionEncryptionIdentifierHash identifierHash)
    {
        if (!_byIdentifierHash.TryGetValue(Key(identifierHash), out var locators))
        {
            throw new ArgumentException($"The record has no ballot with H_I {Key(identifierHash)}.", nameof(identifierHash));
        }

        if (locators.Count != 1)
        {
            throw new ArgumentException($"{locators.Count} ballots of the record have H_I {Key(identifierHash)}, so they share id_B (5.A).", nameof(identifierHash));
        }

        return (locators[0], identifierHash);
    }

    /// <summary>
    /// The string id of the ballot at <paramref name="locator"/>, or, for a locator the record does
    /// not hold, an id that is not text and so matches no ballot.
    /// </summary>
    public string BallotId(BallotLocator locator) =>
        _byLocator.TryGetValue(locator, out var found) ? found.BallotId : WireValues.UnknownLabel("ballot", locator.Position);

    /// <summary>
    /// <see cref="Resolve(BallotLocator, Google.Protobuf.ByteString, RecordDecodeContext, string)"/>
    /// on an item's <c>ballot</c> message, which may be absent: the canonicality check refuses an
    /// absent fixed-width bytes field (D1) or enum (D2), not an absent message. An item that names no
    /// ballot is a finding under <paramref name="subSection"/>, and its id matches no ballot.
    /// </summary>
    public string Resolve(ElectionGuard.Core.RecordFormat.Protobuf.BallotLocator? locator, Google.Protobuf.ByteString identifierHash, RecordDecodeContext context, string subSection)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (locator is null)
        {
            context.Add(subSection, "The item names no ballot (its locator is absent).");
            return WireValues.UnknownLabel("ballot", 0);
        }

        return Resolve(DeviceMapper.FromItem(locator), identifierHash, context, subSection);
    }

    /// <summary>
    /// The string id of the ballot an item names by <paramref name="locator"/> and
    /// <paramref name="identifierHash"/>; a finding under <paramref name="subSection"/> when the
    /// record holds no ballot there, or one with another H_I (the item's H_I is a binding).
    /// </summary>
    public string Resolve(BallotLocator locator, Google.Protobuf.ByteString identifierHash, RecordDecodeContext context, string subSection)
    {
        if (!_byLocator.TryGetValue(locator, out var found))
        {
            context.Add(subSection, $"The item names the ballot at position {locator.Position} of device {Convert.ToHexStringLower(locator.Device.ToBytes())}, which the record does not hold.");
            return WireValues.UnknownLabel("ballot", locator.Position);
        }

        if (!identifierHash.Span.SequenceEqual((byte[])found.IdentifierHash))
        {
            context.Add(subSection, $"The item names ballot {found.BallotId} with an H_I that is not the ballot's.");
        }

        return found.BallotId;
    }

    private static string Key(SelectionEncryptionIdentifierHash identifierHash) => Convert.ToHexStringLower((byte[])identifierHash);
}
