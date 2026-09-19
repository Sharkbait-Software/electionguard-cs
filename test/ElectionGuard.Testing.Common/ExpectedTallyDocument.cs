namespace ElectionGuard.Testing.Common;

/// <summary>
/// The canonical expected-tally.json schema:
///
/// <code>
/// {
///   "contests": {
///     "&lt;contestId&gt;": {
///       "overvotes": 0,
///       "nullvotes": 0,
///       "undervotes": 0,
///       "writeIns": 0,
///       "choices": { "&lt;choiceId&gt;": 0 }
///     }
///   }
/// }
/// </code>
///
/// Both ElectionGuard.Testing.Cli and ElectionGuard.Perf.Cli's `corpus` command serialize an
/// ExpectedTally through <see cref="ExpectedTallyDocument.From"/>, with their own
/// JsonSerializerOptions (camelCase, indented), so a non-.NET consumer sees exactly one shape
/// regardless of which tool produced the file.
/// </summary>
public sealed class ExpectedTallyDocument
{
    public required Dictionary<string, ExpectedContestDocument> Contests { get; init; }

    public static ExpectedTallyDocument From(ExpectedTally tally) =>
        new()
        {
            Contests = tally.ContestIds.ToDictionary(
                contestId => contestId,
                contestId => ExpectedContestDocument.From(tally, contestId)),
        };
}

public sealed class ExpectedContestDocument
{
    public required int Overvotes { get; init; }
    public required int Nullvotes { get; init; }
    public required int Undervotes { get; init; }
    public required int WriteIns { get; init; }
    public required Dictionary<string, int> Choices { get; init; }

    public static ExpectedContestDocument From(ExpectedTally tally, string contestId)
    {
        var counters = tally.GetCounters(contestId);
        return new ExpectedContestDocument
        {
            Overvotes = counters.Overvotes,
            Nullvotes = counters.Nullvotes,
            Undervotes = counters.Undervotes,
            WriteIns = counters.WriteIns,
            Choices = tally.ChoiceIds(contestId).ToDictionary(
                choiceId => choiceId,
                choiceId => tally.GetVotes(contestId, choiceId)),
        };
    }
}
