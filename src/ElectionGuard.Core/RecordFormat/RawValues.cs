using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using System.Numerics;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// A 512-byte big-endian value as the election record carries it: a claimed element of Z_p, not yet
/// one. The record format checks widths only (user decision #11: "Out of range values are a problem
/// for a verifier, not the election record format"), so a value ≥ p decodes, and the verifier
/// reports it under the spec's lettered check (design §4.8) instead of a reader rejecting it (which
/// made 6.B, 6.C and 2.B unreachable from a deserialized record). It never reduces mod p.
/// </summary>
public readonly record struct RawZp
{
    /// <summary>The fixed width, 512 bytes (b(x, 512), §5.1).</summary>
    public const int ByteLength = 512;

    private readonly byte[] _bytes;

    /// <summary>A copy of exactly 512 bytes; throws <see cref="NonCanonicalEncodingException"/> on any other width (a D1 failure, which the canonicality check reports first).</summary>
    public RawZp(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
        {
            throw new NonCanonicalEncodingException($"A Z_p value is {ByteLength} bytes in the record; got {bytes.Length}.");
        }

        _bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => _bytes;

    /// <summary>Whether the value is below p (<see cref="EGParameters.P"/>); if so, <paramref name="value"/> is it.</summary>
    public bool TryToModP(out IntegerModP value)
    {
        var integer = new BigInteger(_bytes, isUnsigned: true, isBigEndian: true);
        if (integer >= EGParameters.P)
        {
            value = default;
            return false;
        }

        value = new IntegerModP(integer);
        return true;
    }

    public bool Equals(RawZp other) => _bytes.AsSpan().SequenceEqual(other._bytes);

    public override int GetHashCode() => _bytes is null ? 0 : BitConverter.ToInt32(_bytes, ByteLength - 4);
}

/// <summary>
/// A 32-byte big-endian value as the election record carries it: a claimed element of Z_q, not yet
/// one (see <see cref="RawZp"/>). It never reduces mod q.
/// </summary>
public readonly record struct RawZq
{
    /// <summary>The fixed width, 32 bytes (b(x, 32), §5.1).</summary>
    public const int ByteLength = 32;

    private readonly byte[] _bytes;

    /// <summary>A copy of exactly 32 bytes; throws <see cref="NonCanonicalEncodingException"/> on any other width.</summary>
    public RawZq(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
        {
            throw new NonCanonicalEncodingException($"A Z_q value is {ByteLength} bytes in the record; got {bytes.Length}.");
        }

        _bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => _bytes;

    /// <summary>Whether the value is below q (<see cref="EGParameters.Q"/>); if so, <paramref name="value"/> is it.</summary>
    public bool TryToModQ(out IntegerModQ value)
    {
        var integer = new BigInteger(_bytes, isUnsigned: true, isBigEndian: true);
        if (integer >= EGParameters.Q)
        {
            value = default;
            return false;
        }

        value = new IntegerModQ(integer);
        return true;
    }

    public bool Equals(RawZq other) => _bytes.AsSpan().SequenceEqual(other._bytes);

    public override int GetHashCode() => _bytes is null ? 0 : BitConverter.ToInt32(_bytes, ByteLength - 4);
}

/// <summary>
/// A failure found while decoding a record item into the domain model (design §4.8, layer 2): a
/// fixed-width value outside Z_p or Z_q, reported under the spec's lettered check where one applies
/// (<see cref="SubSection"/>, e.g. "6.A") and as "N.structure" otherwise, N being the first
/// verification that consumes the value. See <see cref="RecordValueRanges"/> for the table.
/// <see cref="Item"/> names the record item the value came from (its <c>RecordItem</c> member, for
/// example "guardian_public_key") where one decoded object spans several items (the setup,
/// <see cref="Mappers.SetupMapper"/>), so that a verification is not evaluable only on the items it
/// reads (design §4.8); null for a decoded object of one item.
/// </summary>
internal sealed record RecordFinding(string SubSection, string Message, string? Item = null)
{
    /// <summary>The verification number the sub-section belongs to ("6.A" is 6).</summary>
    public int Verification => int.Parse(SubSection.AsSpan(0, SubSection.IndexOf('.')), System.Globalization.CultureInfo.InvariantCulture);
}

/// <summary>
/// A record item decoded into a domain object (<see cref="Value"/>), or, when any value of it is out
/// of range, only its findings: an item with a range failure is never handed to the domain
/// verifiers, which take <see cref="IntegerModP"/> and <see cref="IntegerModQ"/> values (design
/// §4.8). Findings are ordered by verification, then sub-section.
/// </summary>
internal sealed class RecordDecoded<T> : IRecordDecoded where T : class
{
    private readonly T _decoded;

    public RecordDecoded(T? value, IEnumerable<RecordFinding> findings)
    {
        Findings = findings
            .OrderBy(x => x.Verification)
            .ThenBy(x => x.SubSection, StringComparer.Ordinal)
            .ToList();
        _decoded = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>The domain object, or null when <see cref="Findings"/> is not empty.</summary>
    public T? Value => Findings.Count == 0 ? _decoded : null;

    public IReadOnlyList<RecordFinding> Findings { get; }

    /// <summary>Whether the domain verifiers can run on the item (no range finding).</summary>
    public bool IsEvaluable => Findings.Count == 0;

    /// <summary>
    /// For a decoded object spanning several record items: the findings of the items named
    /// <paramref name="items"/> (and any finding of no named item).
    /// </summary>
    public IReadOnlyList<RecordFinding> FindingsOn(IReadOnlyCollection<string> items) =>
        Findings.Where(x => x.Item is null || items.Contains(x.Item)).ToList();

    /// <summary>
    /// The decoded object when no item named <paramref name="items"/> has a finding: values of the
    /// other items may then be placeholders, so only a verification that reads nothing but those
    /// items may take it (<see cref="Verify.RecordItemGate"/>). Null otherwise.
    /// </summary>
    public T? ValueReading(IReadOnlyCollection<string> items) => FindingsOn(items).Count == 0 ? _decoded : null;

    /// <summary>
    /// The decoded object even when there are findings, with placeholders in place of the values out
    /// of range. Never for a verifier: only for reading a member that is decoded without a range check
    /// (a ballot's status, which decides whether Verification 9 needs the item at all).
    /// </summary>
    public T Placeholder => _decoded;
}

/// <summary>The findings of a decoded record item, whatever its type.</summary>
internal interface IRecordDecoded
{
    IReadOnlyList<RecordFinding> Findings { get; }

    bool IsEvaluable { get; }
}

/// <summary>
/// Collects range findings while a mapper decodes one item. A value out of range is recorded and
/// replaced by a placeholder so decoding goes on and every finding of the item is collected; the
/// decoded object is then discarded (<see cref="RecordDecoded{T}"/>).
/// </summary>
internal sealed class RecordDecodeContext
{
    private readonly List<RecordFinding> _findings = [];

    public IReadOnlyList<RecordFinding> Findings => _findings;

    /// <summary>The record item being decoded, where one object spans several (<see cref="RecordFinding.Item"/>).</summary>
    public string? Item { get; set; }

    public void Add(string subSection, string message) => _findings.Add(new RecordFinding(subSection, message, Item));

    public IntegerModP Zp(ReadOnlySpan<byte> bytes, string subSection, string what)
    {
        if (new RawZp(bytes).TryToModP(out var value))
        {
            return value;
        }

        Add(subSection, $"{what} is not below p (design §4.8).");
        return new IntegerModP(1);
    }

    public IntegerModQ Zq(ReadOnlySpan<byte> bytes, string subSection, string what)
    {
        if (new RawZq(bytes).TryToModQ(out var value))
        {
            return value;
        }

        Add(subSection, $"{what} is not below q (design §4.8).");
        return new IntegerModQ(0);
    }

    public RecordDecoded<T> Result<T>(T value) where T : class => new(value, _findings);
}

/// <summary>
/// Design §4.8's range table, fixed in S10b-4 against the Verify classes' lettering: the code under
/// which a value outside Z_p or Z_q is reported. Spec letters where a lettered check covers the
/// value's range (6.A-6.C, 7.B, 7.C, 2.A, 2.B, 10.A, 12.A) or where a stored value outside the group
/// can never equal the recomputed one (2.C, 3.A, 3.B, 9.A, 9.B, 10.B, 10.C, 12.B: the recomputed
/// side is always reduced); "N.structure" for the rest, N being the first verification that reads
/// the value.
/// </summary>
internal static class RecordValueRanges
{
    /// <summary>α, β of every selection encryption: ballots, combined and selected pre-encryption vectors, uncast vectors (V6 covers "all individual selection encryptions", §4.5).</summary>
    public const string SelectionCiphertext = "6.A";

    /// <summary>Range proof challenges c_j of a selection (6.B) and responses v_j (6.C).</summary>
    public const string SelectionChallenge = "6.B", SelectionResponse = "6.C";

    /// <summary>Limit, undervote-difference and null-vote proof challenges (7.B) and responses (7.C).</summary>
    public const string ContestChallenge = "7.B", ContestResponse = "7.C";

    /// <summary>Contest data C_0 and C_2 = (c, v): hashed into χ by eq. (70), so first read by Verification 8.</summary>
    public const string ContestData = "8.structure";

    /// <summary>The encrypted ballot nonce C_ξB,0 and C_ξB,2: first read by Verification 13 (it is no input to H_C).</summary>
    public const string BallotNonce = "13.structure";

    /// <summary>Guardian commitments K_i,j, K-hat_i,j and κ_i (2.A), responses (2.B), challenges (2.C).</summary>
    public const string GuardianKey = "2.A", GuardianResponse = "2.B", GuardianChallenge = "2.C";

    /// <summary>
    /// A guardian index of 0 or above 2^31 - 1: 2.A, as Verification 2 reports any index outside
    /// 1..n (<see cref="Verify.KeyGeneration.GuardianSet.RequireComplete"/>, G25). The set must be
    /// exactly G_1..G_n, and with an index outside 1..n some G_i is missing, for which 2.A ("the
    /// values K_i,j ... and κ_i are in Z_p^r", "for each guardian G_i, 1 ≤ i ≤ n") cannot be confirmed.
    /// </summary>
    public const string GuardianIndex = GuardianKey;

    /// <summary>
    /// The election keys K (3.A) and K-hat (3.B): Verification 3 checks K = (∏ K_i) mod p and
    /// K-hat = (∏ K-hat_i) mod p (p.82), so a stored value ≥ p can never equal the recomputed one.
    /// </summary>
    public const string ElectionKey = "3.A", ElectionKeyHat = "3.B";

    /// <summary>The encrypted tally's A (9.A) and B (9.B).</summary>
    public const string TallyA = "9.A", TallyB = "9.B";

    /// <summary>A decrypted tally's T (10.C: T = K^t mod p cannot hold), c (10.B) and v (10.A).</summary>
    public const string TallyT = "10.C", TallyChallenge = "10.B", TallyResponse = "10.A";

    /// <summary>A contest-data decryption's β (12.structure), c (12.B) and v (12.A).</summary>
    public const string ContestDataBeta = "12.structure", ContestDataChallenge = "12.B", ContestDataResponse = "12.A";

    /// <summary>A challenged ballot's released nonces ξ_i,j and contest-data ξ.</summary>
    public const string ChallengedNonce = "13.structure";

    /// <summary>An uncast ballot's released nonces ξ_i,j,k.</summary>
    public const string UncastNonce = "18.structure";

    /// <summary>
    /// An uncast pre-encrypted ballot's encrypted ballot nonce C_ξB,0 and (c_B, v_B): Verification 13
    /// never runs on an uncast ballot ("Verification 13 is replaced by Verification 18", §4.5 p.66),
    /// so they are 18's.
    /// </summary>
    public const string UncastBallotNonce = "18.structure";
}
