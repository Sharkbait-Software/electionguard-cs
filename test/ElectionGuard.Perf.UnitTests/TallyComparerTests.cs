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
            // TallyComparer reads only the counts. The indices and the proof fields are required
            // members of the published tally; placeholders do here.
            contests[group.Key] = new DecryptedTally.DecryptedContest
            {
                ContestIndex = 0,
                Choices = group.ToDictionary(
                    x => x.ChoiceId,
                    x => new DecryptedTally.DecryptedChoice { ChoiceIndex = 0, VoteCount = x.Votes, T = 1, Challenge = 0, Response = 0 }),
            };
        }

        return new DecryptedTally { Contests = contests };
    }

    /// <summary>
    /// The expected tally of a contest that declares no supplemental fields, so only the options
    /// are compared; <see cref="Compare_ChecksEveryDeclaredSupplementalField"/> covers the fields.
    /// </summary>
    private static ExpectedTally Expected(params (string ChoiceId, int Votes)[] votes)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(supplementalFields: []);
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

    /// <summary>
    /// G29: every supplemental field the manifest declares is decrypted under its label, so the
    /// comparer checks its total too. One overvoted ballot and one null vote, L = 1.
    /// </summary>
    [Fact]
    public void Compare_ChecksEveryDeclaredSupplementalField()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var accumulator = new ExpectedTallyAccumulator(manifest);
        accumulator.Add(ElectionFixtureBuilder.CreateBallot(manifest, ballotId: "over",
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 1 }));
        accumulator.Add(ElectionFixtureBuilder.CreateBallot(manifest, ballotId: "null"));
        var expected = accumulator.Build();

        (string, string, int)[] honest =
        [
            ("contest-1", "choice-1", 0),
            ("contest-1", "choice-2", 0),
            ("contest-1", "overvotes", 1),
            ("contest-1", "null-votes", 1),
            ("contest-1", "undervotes", 2),
            ("contest-1", "undervote-difference", 2),
            ("contest-1", "write-ins", 0),
        ];

        var passed = TallyComparer.Compare(expected, Decrypted(honest));
        Assert.Equal(CorrectnessStatus.Passed, passed.Status);

        var wrongField = honest.Select(x => x.Item2 == "null-votes" ? (x.Item1, x.Item2, 2) : x).ToArray();
        var failed = TallyComparer.Compare(expected, Decrypted(wrongField));
        Assert.Equal(CorrectnessStatus.Failed, failed.Status);
        var mismatch = Assert.Single(failed.Mismatches);
        Assert.Equal("null-votes", mismatch.ChoiceId);
        Assert.Equal(1, mismatch.Expected);
        Assert.Equal(2, mismatch.Actual);

        var missingField = honest.Where(x => x.Item2 != "write-ins").ToArray();
        var missing = Assert.Single(TallyComparer.Compare(expected, Decrypted(missingField)).Mismatches);
        Assert.Equal("write-ins", missing.ChoiceId);
        Assert.Equal(-1, missing.Actual);
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
