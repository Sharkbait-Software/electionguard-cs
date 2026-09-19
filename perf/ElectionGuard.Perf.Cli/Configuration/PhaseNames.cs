namespace ElectionGuard.Perf.Cli.Configuration;

/// <summary>
/// Phase identifiers. These strings are the keys in a scenario's budgets map and in a run record's
/// phases map, so they are part of the persisted result schema -- changing one is a schema change.
/// </summary>
public static class PhaseNames
{
    public const string EncryptBallots = "EncryptBallots";
    public const string VerifyBallots = "VerifyBallots";
    public const string Tally = "Tally";

    /// <summary>
    /// Verification 9 (<c>BallotAggregationVerification</c>). Runs once, after the streaming chunk
    /// loop, over every retained encrypted ballot -- the most expensive optional step after
    /// encryption. Present in a record only when it actually ran; every reader (RunComparer's
    /// Intersect-based phase comparison, ConsoleReport/HtmlReport's TryGetValue-guarded lookups)
    /// treats a missing "VerifyTally" key as "did not run" rather than as an error.
    /// </summary>
    public const string VerifyTally = "VerifyTally";

    public const string DecryptTally = "DecryptTally";

    public static readonly IReadOnlyList<string> All = [EncryptBallots, VerifyBallots, Tally, VerifyTally, DecryptTally];
}
