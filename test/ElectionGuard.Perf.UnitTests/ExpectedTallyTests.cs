using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
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
        // The undervote fields of an overvoted contest are computed on the zeroed selections
        // (sum 0 < L = 1), so the indicator is 1 and the difference L = 1. The difference is forced
        // (L - u = sum); the indicator follows p.38's disjunctive proof, where p.18/p.38's definition
        // by the voter's sum would give 0. DECISION-DEPENDENT PIN (open user question 4, option (a)):
        // re-pin Undervotes to 0 if the user picks (b).
        // Before S5 the single undervote counter was L minus the number of nonzero options before
        // zeroing, clamped at 0.
        Assert.Equal(1, counters.Undervotes);
        Assert.Equal(1, counters.UndervoteDifference);
        Assert.Equal(0, counters.WriteIns);
    }

    [Fact]
    public void GetCounters_CountsANullvoteAndItsFullUndervote()
    {
        // No selections at all: a null vote, an undervote, and an undervote difference of L = 2.
        // (Undervotes now counts ballots with an undervote, §3.3.9's indicator; the difference
        // count, which the single pre-S5 counter held, is UndervoteDifference.)
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(selectionLimit: 2);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(manifest));

        var counters = accumulator.Build().GetCounters("contest-1");

        Assert.Equal(0, counters.Overvotes);
        Assert.Equal(1, counters.Nullvotes);
        Assert.Equal(1, counters.Undervotes);
        Assert.Equal(2, counters.UndervoteDifference);
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
        Assert.Equal(1, counters.UndervoteDifference);
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
    public void GetCounters_OnAnOvervote_ComputesTheUndervoteFieldsOnTheZeroedSelections()
    {
        // OptionSelectionLimit 2, SelectionLimit 1: choice-1 = 2 and choice-2 = 1 sum to 3 > L, an
        // overvote (and choice-1 = 2 alone would be one too: 2 > L). The selections are zeroed, the
        // null-vote indicator is 0 on an overvote (§3.3.9 p.39, user decision Q3), and the undervote
        // fields see the zeroed sum: indicator 1, difference L. DECISION-DEPENDENT PIN (open user
        // question 4, option (a)): re-pin Undervotes to 0 if the user picks (b). (Before S5 this test pinned the
        // opposite, computing them from the original values; that matched the old encryptor, whose
        // overvote threshold L * R did not even treat 2 + 1 = 3 > 2 consistently with the spec.)
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(optionSelectionLimit: 2, selectionLimit: 1);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 2, ["choice-2"] = 1 }));

        var tally = accumulator.Build();
        var counters = tally.GetCounters("contest-1");

        Assert.Equal(1, counters.Overvotes);
        Assert.Equal(0, counters.Nullvotes);
        Assert.Equal(1, counters.Undervotes);
        Assert.Equal(1, counters.UndervoteDifference);
        Assert.Equal(0, tally.GetVotes("contest-1", "choice-1"));
        Assert.Equal(0, tally.GetVotes("contest-1", "choice-2"));
    }

    // --- G10: the overvote rule is "sum > L or any option > R", re-derived from the spec ---------

    [Theory]
    // L = 1, R = 2: a single 2 exceeds L, an overvote. The old L * R rule (threshold 2) counted it.
    [InlineData(1, 2, new[] { 2, 0 }, true)]
    [InlineData(1, 2, new[] { 1, 0 }, false)]
    // L = 3, R = 3: totals in (L, L * R] = (3, 9] are overvotes now; at most L is not.
    [InlineData(3, 3, new[] { 2, 2 }, true)]
    [InlineData(3, 3, new[] { 3, 1 }, true)]
    [InlineData(3, 3, new[] { 3, 0 }, false)]
    [InlineData(3, 3, new[] { 2, 1 }, false)]
    // L = 3, R = 1: one option above R overvotes even though the total (2) is within L.
    [InlineData(3, 1, new[] { 2, 0 }, true)]
    [InlineData(3, 1, new[] { 1, 1 }, false)]
    public void Add_OvervoteRule_IsSumAboveLOrAnOptionAboveR(int selectionLimit, int optionSelectionLimit, int[] values, bool overvoted)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(optionSelectionLimit: optionSelectionLimit, selectionLimit: selectionLimit);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = values[0], ["choice-2"] = values[1] }));

        var tally = accumulator.Build();
        var counters = tally.GetCounters("contest-1");

        Assert.Equal(overvoted ? 1 : 0, counters.Overvotes);
        Assert.Equal(overvoted ? 0 : values[0], tally.GetVotes("contest-1", "choice-1"));
        Assert.Equal(overvoted ? 0 : values[1], tally.GetVotes("contest-1", "choice-2"));
        int countedSum = overvoted ? 0 : values[0] + values[1];
        Assert.Equal(selectionLimit - countedSum, counters.UndervoteDifference);
        Assert.Equal(countedSum < selectionLimit ? 1 : 0, counters.Undervotes);
        Assert.Equal(!overvoted && countedSum == 0 ? 1 : 0, counters.Nullvotes);
    }

    [Theory]
    // L = 1, one option selected and one write-in used: counted write-ins make the sum 2 > L.
    [InlineData(true, 1, true)]
    [InlineData(false, 1, false)]
    // No option selected, one write-in: counted, the sum is 1 = L (no undervote, not a null vote).
    [InlineData(true, 0, false)]
    // DECISION-DEPENDENT PIN (open user question 2, option (a)): not counted, the sum is 0, so the
    // ballot is a null vote although it used a write-in. Re-pin if the user picks (b).
    [InlineData(false, 0, false)]
    public void Add_WriteInsCountTowardTheLimitOnlyWhereTheManifestSaysSo(bool writeInsCount, int optionSelected, bool overvoted)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true, writeInsCountTowardLimit: writeInsCount);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = optionSelected },
            numWriteinsSelected: 1));

        var tally = accumulator.Build();
        var counters = tally.GetCounters("contest-1");

        Assert.Equal(overvoted ? 1 : 0, counters.Overvotes);
        // An overvoted contest's write-ins are part of its invalid votes.
        Assert.Equal(overvoted ? 0 : 1, counters.WriteIns);
        int countedSum = overvoted ? 0 : optionSelected + (writeInsCount ? 1 : 0);
        Assert.Equal(1 - countedSum, counters.UndervoteDifference);
        Assert.Equal(!overvoted && countedSum == 0 ? 1 : 0, counters.Nullvotes);
    }

    [Fact]
    public void Add_OnAnOvervote_ZeroesWriteInsThatDoNotCountTowardTheLimit()
    {
        // DECISION-DEPENDENT PIN (open user question 1, option (a)): L = 1, both options selected
        // (an overvote) and one write-in that does not count toward the limit. The contest's votes
        // are invalid as a whole (§3.3.5 p.31), so its write-ins are not counted either. Re-pin
        // WriteIns to 1 if the user picks (b).
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true, writeInsCountTowardLimit: false);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 1 },
            numWriteinsSelected: 1));

        var tally = accumulator.Build();
        var counters = tally.GetCounters("contest-1");

        Assert.Equal(1, counters.Overvotes);
        Assert.Equal(0, counters.WriteIns);
        Assert.Equal(0, counters.Nullvotes);
        Assert.Equal(1, counters.Undervotes);
        Assert.Equal(1, counters.UndervoteDifference);
        Assert.Equal(0, tally.GetVotes("contest-1", "choice-1"));
    }

    [Fact]
    public void SupplementalFieldIds_ListsTheDeclaredFieldsInManifestOrder()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);

        var fields = new ExpectedTallyAccumulator(manifest).Build().SupplementalFieldIds("contest-1");

        Assert.Equal(
            manifest.Contests[0].SupplementalFields.Select(field => (field.Id, field.Kind)),
            fields);
    }

    [Fact]
    public void GetCounters_ThrowsForAnUnknownContest()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var tally = new ExpectedTallyAccumulator(manifest).Build();

        Assert.Throws<KeyNotFoundException>(() => tally.GetCounters("no-such-contest"));
    }
}
