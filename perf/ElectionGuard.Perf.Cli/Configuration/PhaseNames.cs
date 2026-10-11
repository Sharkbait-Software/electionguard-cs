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
    /// Verification 9 (<c>BallotAggregationVerifier</c>). Streams like the other per-chunk phases:
    /// each chunk is folded into an independent recomputation of the aggregate right after it is
    /// aggregated, and the recomputation is compared with the tally once, after the chunk loop.
    /// Present in a record only once it started accumulating; every reader (RunComparer's
    /// Intersect-based phase comparison, ConsoleReport/HtmlReport's TryGetValue-guarded lookups)
    /// treats a missing "VerifyTally" key as "did not run" rather than as an error.
    /// </summary>
    public const string VerifyTally = "VerifyTally";

    public const string DecryptTally = "DecryptTally";

    /// <summary>
    /// Verifications 10 (the proof of correct decryption of every option) and 11 (the decrypted
    /// tally's labels against the manifest), run once after a successful decryption when tally
    /// verification is on. Absent from records made before stage S4 and from runs that did not reach
    /// it; readers treat a missing key as "did not run", as for <see cref="VerifyTally"/>.
    /// </summary>
    public const string VerifyDecryption = "VerifyDecryption";

    public static readonly IReadOnlyList<string> All = [EncryptBallots, VerifyBallots, Tally, VerifyTally, DecryptTally, VerifyDecryption];
}
