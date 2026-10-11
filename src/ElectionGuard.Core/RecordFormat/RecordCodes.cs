using ElectionGuard.Core.Verify;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// The record-level failure codes (design §6.9), which no numbered verification owns. The carriers,
/// the readers and the writers report them as a <see cref="VerificationFailedException"/> whose
/// <see cref="VerificationFailedException.SubSection"/> is the code, as
/// <c>BallotAggregationVerifier.VerifySummary</c> reports <see cref="Summary"/>, so a caller (and
/// a test) reads every failure the same way.
/// </summary>
public static class RecordCodes
{
    /// <summary>The carrier: layout and naming (§5.3.1), framing and the 64 MiB ceiling (§5.2), zip consistency (§5.4), D6.</summary>
    public const string Container = "R.container";

    /// <summary>An item that is not canonical (wire rules W1-W8, decode rules D1-D5), or a JSON line that is not one item (§5.5).</summary>
    public const string Encoding = "R.encoding";

    /// <summary>A join section out of canonical ballot order (§4.5).</summary>
    public const string Order = "R.order";

    /// <summary>Section presence and phase (§4.5): a required section missing, or one of a later phase.</summary>
    public const string Structure = "R.structure";

    /// <summary>A format version, or content of a newer minor, that this reader cannot verify (§7).</summary>
    public const string Version = "R.version";

    /// <summary>A section or phase root that is not the claimed one (§4.9, §5.3.1).</summary>
    public const string Root = "R.root";

    /// <summary>The encrypted tally header against the recounted cast ballots (§6.1 step E).</summary>
    public const string Summary = "R.summary";

    /// <summary>A device attestation (§4.9).</summary>
    public const string Attestation = "R.attestation";

    /// <summary>A record signature (§4.9).</summary>
    public const string Signature = "R.signature";

    internal static VerificationFailedException Failure(string code, string message) => new(code, message);
}
