using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// Where a decoded election-record item enters a verification (design §4.8, user decision #11:
/// "Out of range values are a problem for a verifier, not the election record format"). The record
/// mappers decode fixed-width values raw and report a value outside Z_p or Z_q under the spec's
/// lettered check (<see cref="RecordValueRanges"/>), so the verifications' record-item entry points
/// first run this gate:
/// <list type="number">
/// <item>a range finding of this verification is its failure: <see cref="VerificationFailedException"/>
/// with the finding's sub-section (for example "6.B" for a range-proof challenge ≥ q, which a
/// range-strict reader made unreachable);</item>
/// <item>otherwise, a range finding of another verification leaves no domain object to verify, and
/// this verification is not evaluable on the item: <see cref="RecordItemNotEvaluableException"/>
/// (the item is still digested, chain-walked and entered into 5.A by the record verifier);</item>
/// <item>otherwise the existing domain verification runs.</item>
/// </list>
/// </summary>
internal static class RecordItemGate
{
    public static void Require(int verification, params IRecordDecoded[] items)
    {
        foreach (var item in items)
        {
            var own = item.Findings.FirstOrDefault(x => x.Verification == verification);
            if (own is not null)
            {
                throw new VerificationFailedException(own.SubSection, own.Message);
            }
        }

        var other = items.SelectMany(x => x.Findings).FirstOrDefault();
        if (other is not null)
        {
            throw new RecordItemNotEvaluableException(verification, other);
        }
    }

    public static T Require<T>(RecordDecoded<T> item, int verification) where T : class
    {
        Require(verification, [item]);
        return item.Value!;
    }

    /// <summary>
    /// The gate for a decoded object that spans several record items (the setup): only the findings
    /// of the items the verification reads, <paramref name="reads"/>, count (design §4.8: another
    /// verification's finding leaves it not evaluable "on the item"). The object is handed on with
    /// placeholders in the other items' out-of-range values, which the verification never reads.
    /// </summary>
    public static T Require<T>(RecordDecoded<T> item, int verification, IReadOnlyCollection<string> reads) where T : class
    {
        var findings = item.FindingsOn(reads);
        if (findings.FirstOrDefault(x => x.Verification == verification) is { } own)
        {
            throw new VerificationFailedException(own.SubSection, own.Message);
        }

        if (findings.FirstOrDefault() is { } other)
        {
            throw new RecordItemNotEvaluableException(verification, other);
        }

        return item.ValueReading(reads)!;
    }
}

/// <summary>
/// A verification cannot be evaluated on a record item, because a value of the item that another
/// verification checks is out of range (design §4.8: the item is not passed to the domain
/// verifiers). Not a failure of this verification; the record verifier reports it as
/// <c>NotEvaluable</c> and the finding under its own code.
/// </summary>
internal sealed class RecordItemNotEvaluableException(int verification, RecordFinding cause)
    : Exception($"Verification {verification} cannot be evaluated on this item: {cause.SubSection}: {cause.Message}")
{
    public int Verification { get; } = verification;

    public RecordFinding Cause { get; } = cause;
}
