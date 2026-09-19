using ElectionGuard.Core.Tally;
using ElectionGuard.Perf.Cli.Results;
using ElectionGuard.Perf.Cli.Running;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Perf.UnitTests;

public class TallyComparerTests
{
    private static DecryptedTally Decrypted(params (string ContestId, string ChoiceId, int Votes)[] entries)
    {
        var contests = new Dictionary<string, DecryptedTally.DecryptedContest>();

        foreach (var group in entries.GroupBy(x => x.ContestId))
        {
            contests[group.Key] = new DecryptedTally.DecryptedContest
            {
                Choices = group.ToDictionary(
                    x => x.ChoiceId,
                    x => new DecryptedTally.DecryptedChoice { VoteCount = x.Votes }),
            };
        }

        return new DecryptedTally { Contests = contests };
    }

    private static ExpectedTally Expected(params (string ChoiceId, int Votes)[] votes)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var accumulator = new ExpectedTallyAccumulator(manifest);

        foreach (var (choiceId, count) in votes)
        {
            for (int i = 0; i < count; i++)
            {
                accumulator.Add(ElectionFixtureBuilder.CreateBallot(
                    manifest,
                    ballotId: $"{choiceId}-{i}",
                    selectionValuesByChoiceId: new Dictionary<string, int> { [choiceId] = 1 }));
            }
        }

        return accumulator.Build();
    }

    [Fact]
    public void Compare_PassesWhenEveryCountMatches()
    {
        var result = TallyComparer.Compare(
            Expected(("choice-1", 3), ("choice-2", 5)),
            Decrypted(("contest-1", "choice-1", 3), ("contest-1", "choice-2", 5)));

        Assert.Equal(CorrectnessStatus.Passed, result.Status);
        Assert.Empty(result.Mismatches);
    }

    [Fact]
    public void Compare_FailsAndNamesTheDivergentChoice()
    {
        var result = TallyComparer.Compare(
            Expected(("choice-1", 3), ("choice-2", 5)),
            Decrypted(("contest-1", "choice-1", 3), ("contest-1", "choice-2", 4)));

        Assert.Equal(CorrectnessStatus.Failed, result.Status);
        var mismatch = Assert.Single(result.Mismatches);
        Assert.Equal("contest-1", mismatch.ContestId);
        Assert.Equal("choice-2", mismatch.ChoiceId);
        Assert.Equal(5, mismatch.Expected);
        Assert.Equal(4, mismatch.Actual);
    }

    [Fact]
    public void Compare_PassesOnAnAllZeroTally()
    {
        var result = TallyComparer.Compare(
            Expected(),
            Decrypted(("contest-1", "choice-1", 0), ("contest-1", "choice-2", 0)));

        Assert.Equal(CorrectnessStatus.Passed, result.Status);
        Assert.Empty(result.Mismatches);
    }

    [Fact]
    public void Compare_ReportsAnAbsentContestAsAMismatch()
    {
        var result = TallyComparer.Compare(Expected(("choice-1", 2)), Decrypted());

        Assert.Equal(CorrectnessStatus.Failed, result.Status);
        Assert.Equal(2, result.Mismatches.Count);
        Assert.Contains(result.Mismatches, x => x.ChoiceId == "choice-1" && x.Actual == -1);
    }

    [Fact]
    public void Compare_ReportsAnAbsentChoiceAsAMismatch()
    {
        var result = TallyComparer.Compare(
            Expected(("choice-1", 2)),
            Decrypted(("contest-1", "choice-2", 0)));

        Assert.Equal(CorrectnessStatus.Failed, result.Status);
        Assert.Contains(result.Mismatches, x => x.ChoiceId == "choice-1" && x.Actual == -1);
    }

    [Fact]
    public void Compare_CapsTheNumberOfRecordedMismatches()
    {
        var expected = Expected(("choice-1", 3), ("choice-2", 5));

        var result = TallyComparer.Compare(
            expected,
            Decrypted(("contest-1", "choice-1", 99), ("contest-1", "choice-2", 99)),
            maxMismatchesRecorded: 1);

        Assert.Equal(CorrectnessStatus.Failed, result.Status);
        Assert.Single(result.Mismatches);
    }

    [Fact]
    public void Compare_FailsEvenWhenEveryMismatchIsTruncated()
    {
        var expected = Expected(("choice-1", 3), ("choice-2", 5));

        var result = TallyComparer.Compare(
            expected,
            Decrypted(("contest-1", "choice-1", 99), ("contest-1", "choice-2", 99)),
            maxMismatchesRecorded: 0);

        Assert.Equal(CorrectnessStatus.Failed, result.Status);
        Assert.Empty(result.Mismatches);
    }
}
