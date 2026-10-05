using ElectionGuard.Core.Tally;
using ElectionGuard.Perf.Cli.Results;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Perf.Cli.Running;

public static class TallyComparer
{
    /// <summary>
    /// Compares a decrypted tally against the expected per-choice vote counts, and against the
    /// expected total of every supplemental field (§3.3.9) the manifest declares, which is
    /// aggregated and decrypted under the field's label like an option. A field mismatch is
    /// recorded with the field's label as its ChoiceId.
    ///
    /// An expected contest or choice missing entirely from the decrypted tally is recorded as a
    /// mismatch with Actual = -1, which cannot collide with a real count.
    ///
    /// A failing 1,000,000-ballot run could otherwise produce hundreds of thousands of mismatch
    /// entries and a result file to match, so recording is capped; the count in the status message
    /// is not.
    /// </summary>
    public static CorrectnessResult Compare(
        ExpectedTally expected,
        DecryptedTally actual,
        int maxMismatchesRecorded = 25)
    {
        var mismatches = new List<TallyMismatch>();
        int total = 0;

        foreach (var contestId in expected.ContestIds)
        {
            actual.Contests.TryGetValue(contestId, out var actualContest);

            var expectedCounters = expected.GetCounters(contestId);
            var expectedCounts = expected.ChoiceIds(contestId)
                .Select(choiceId => (Id: choiceId, Count: expected.GetVotes(contestId, choiceId)))
                .Concat(expected.SupplementalFieldIds(contestId)
                    .Select(field => (Id: field.FieldId, Count: expectedCounters.Get(field.Kind))));

            foreach (var (choiceId, expectedVotes) in expectedCounts)
            {
                int actualVotes = -1;
                if (actualContest is not null
                    && actualContest.Choices.TryGetValue(choiceId, out var actualChoice))
                {
                    actualVotes = actualChoice.VoteCount;
                }

                if (actualVotes == expectedVotes)
                {
                    continue;
                }

                total++;
                if (mismatches.Count < maxMismatchesRecorded)
                {
                    mismatches.Add(new TallyMismatch
                    {
                        ContestId = contestId,
                        ChoiceId = choiceId,
                        Expected = expectedVotes,
                        Actual = actualVotes,
                    });
                }
            }
        }

        return new CorrectnessResult
        {
            Status = total == 0 ? CorrectnessStatus.Passed : CorrectnessStatus.Failed,
            Mismatches = mismatches,
        };
    }
}
