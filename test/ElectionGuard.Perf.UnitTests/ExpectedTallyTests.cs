using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Perf.UnitTests;

public class ExpectedTallyTests
{
    [Fact]
    public void Add_CountsASingleSelection()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 }));

        var tally = accumulator.Build();

        Assert.Equal(1, tally.GetVotes("contest-1", "choice-1"));
        Assert.Equal(0, tally.GetVotes("contest-1", "choice-2"));
    }

    [Fact]
    public void Add_AccumulatesAcrossBallots()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var accumulator = new ExpectedTallyAccumulator(manifest);

        for (int i = 0; i < 5; i++)
        {
            accumulator.Add(ElectionFixtureBuilder.CreateBallot(
                manifest,
                ballotId: i.ToString(),
                selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-2"] = 1 }));
        }

        Assert.Equal(5, accumulator.Build().GetVotes("contest-1", "choice-2"));
    }

    [Fact]
    public void Add_IgnoresOvervotedContestsEntirely()
    {
        // SelectionLimit 1, OptionSelectionLimit 1: selecting both choices totals 2 > 1, which is
        // what BallotEncryptor.EncryptContest treats as an overvote and zeroes.
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 1 }));

        var tally = accumulator.Build();

        Assert.Equal(0, tally.GetVotes("contest-1", "choice-1"));
        Assert.Equal(0, tally.GetVotes("contest-1", "choice-2"));
    }

    [Fact]
    public void Add_CountsUpToTheSelectionLimitWithoutOvervoting()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(selectionLimit: 2);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 1 }));

        var tally = accumulator.Build();

        Assert.Equal(1, tally.GetVotes("contest-1", "choice-1"));
        Assert.Equal(1, tally.GetVotes("contest-1", "choice-2"));
    }

    [Fact]
    public void Build_IncludesEveryManifestContestAndChoiceEvenWhenNeverVoted()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var tally = new ExpectedTallyAccumulator(manifest).Build();

        Assert.Equal(0, tally.GetVotes("contest-1", "choice-1"));
        Assert.Equal(0, tally.GetVotes("contest-1", "choice-2"));
    }

    [Fact]
    public void GetVotes_ThrowsForAnUnknownChoice()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var tally = new ExpectedTallyAccumulator(manifest).Build();

        Assert.Throws<KeyNotFoundException>(() => tally.GetVotes("contest-1", "no-such-choice"));
    }

    [Fact]
    public void GetCounters_CountsAnOvervote()
    {
        // SelectionLimit 1, OptionSelectionLimit 1: selecting both choices totals 2 > 1, which is
        // what BallotEncryptor.EncryptContest treats as an overvote.
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 1 }));

        var counters = accumulator.Build().GetCounters("contest-1");

        Assert.Equal(1, counters.Overvotes);
        Assert.Equal(0, counters.Nullvotes);
        Assert.Equal(0, counters.Undervotes);
        Assert.Equal(0, counters.WriteIns);
    }

    [Fact]
    public void GetCounters_CountsANullvoteAndItsFullUndervote()
    {
        // No selections at all: isNullVote is true, and numUndervotes is SelectionLimit (2) minus
        // the count of non-zero choices (0).
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(selectionLimit: 2);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(manifest));

        var counters = accumulator.Build().GetCounters("contest-1");

        Assert.Equal(0, counters.Overvotes);
        Assert.Equal(1, counters.Nullvotes);
        Assert.Equal(2, counters.Undervotes);
        Assert.Equal(0, counters.WriteIns);
    }

    [Fact]
    public void GetCounters_CountsAPartialUndervoteWithoutANullvote()
    {
        // SelectionLimit 2, one choice selected: not a nullvote (something is selected), but one
        // undervote short of the limit.
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(selectionLimit: 2);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 }));

        var counters = accumulator.Build().GetCounters("contest-1");

        Assert.Equal(0, counters.Overvotes);
        Assert.Equal(0, counters.Nullvotes);
        Assert.Equal(1, counters.Undervotes);
        Assert.Equal(0, counters.WriteIns);
    }

    [Fact]
    public void GetCounters_CountsWriteInsFromTheBallotContestRegardlessOfSelections()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 },
            numWriteinsSelected: 1));

        var counters = accumulator.Build().GetCounters("contest-1");

        Assert.Equal(1, counters.WriteIns);
    }

    [Fact]
    public void GetCounters_AccumulatesAcrossBallots()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var accumulator = new ExpectedTallyAccumulator(manifest);

        for (int i = 0; i < 3; i++)
        {
            accumulator.Add(ElectionFixtureBuilder.CreateBallot(
                manifest,
                ballotId: i.ToString(),
                selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 1 }));
        }

        Assert.Equal(3, accumulator.Build().GetCounters("contest-1").Overvotes);
    }

    [Fact]
    public void GetCounters_UsesTheOriginalSelectionValuesFromBeforeOvervoteZeroing()
    {
        // OptionSelectionLimit 2, SelectionLimit 1: the contest's limit is 1 * 2 = 2. choice-1 = 2
        // and choice-2 = 1 sum to 3, an overvote. Both choices are non-zero in the ORIGINAL ballot,
        // so (matching BallotEncryptor.EncryptContest, which computes isNullVote/numUndervotes
        // BEFORE zeroing an overvoted contest's selections) nullvotes and undervotes must both be
        // 0. An accumulator that zeroed the selections first would instead see zero choices
        // selected and wrongly report nullvotes=1 and undervotes=1.
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(optionSelectionLimit: 2, selectionLimit: 1);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 2, ["choice-2"] = 1 }));

        var counters = accumulator.Build().GetCounters("contest-1");

        Assert.Equal(1, counters.Overvotes);
        Assert.Equal(0, counters.Nullvotes);
        Assert.Equal(0, counters.Undervotes);
    }

    [Fact]
    public void GetCounters_ThrowsForAnUnknownContest()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var tally = new ExpectedTallyAccumulator(manifest).Build();

        Assert.Throws<KeyNotFoundException>(() => tally.GetCounters("no-such-contest"));
    }
}
