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
        // User decisions Q11 and Q15: an overvote is not an undervote, and the undervote difference
        // count is 0, since s + w + L*overvote + u = L with s = w = 0. (S5 had 1 and L, computed on
        // the zeroed selections; before S5 the single undervote counter was L minus the number of
        // nonzero options before zeroing, clamped at 0.)
        Assert.Equal(0, counters.Undervotes);
        Assert.Equal(0, counters.UndervoteDifference);
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
        // L = 2: one selection and one write-in fill the limit (write-ins count toward it, Q13).
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true, selectionLimit: 2);
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
    public void GetCounters_OnAnOvervote_TheUndervoteFieldsAreZero()
    {
        // OptionSelectionLimit 2, SelectionLimit 1: choice-1 = 2 and choice-2 = 1 sum to 3 > L, an
        // overvote (and choice-1 = 2 alone would be one too: 2 > L). The selections are zeroed, and
        // the null-vote indicator, the undervote indicator and the undervote difference count are 0
        // (§3.3.9 p.39; user decisions Q3, Q11, Q15). (S5 pinned the undervote fields computed on the
        // zeroed sum, 1 and L; before S5 this test pinned them computed from the original values.)
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(optionSelectionLimit: 2, selectionLimit: 1);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 2, ["choice-2"] = 1 }));

        var tally = accumulator.Build();
        var counters = tally.GetCounters("contest-1");

        Assert.Equal(1, counters.Overvotes);
        Assert.Equal(0, counters.Nullvotes);
        Assert.Equal(0, counters.Undervotes);
        Assert.Equal(0, counters.UndervoteDifference);
        Assert.Equal(0, tally.GetVotes("contest-1", "choice-1"));
        Assert.Equal(0, tally.GetVotes("contest-1", "choice-2"));
    }

    [Fact]
    public void GetCounters_OnAnOvervoteWithoutAnOvervoteIndicator_TheUndervoteDifferenceIsL()
    {
        // Q15's relation s + w + L*overvote + u = L has the overvote term only when the contest
        // declares the indicator (Q14: an untracked field "isn't included"). Without it, an
        // overvoted contest's u is L, the difference to the zeroed selections.
        // DECISION-DEPENDENT PIN (open S5b question A, option (a)). If the user picks (b),
        // Manifest.Validate rejects this manifest, but neither CreateMinimalManifest nor the
        // accumulator validates, so this test would keep passing on a manifest no election can
        // use: delete it, or turn it into a Validate test.
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(
            selectionLimit: 2,
            supplementalFields: [SupplementalFieldKind.UndervoteIndicator, SupplementalFieldKind.UndervoteDifferenceCount]);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 2, ["choice-2"] = 1 }));

        var counters = accumulator.Build().GetCounters("contest-1");

        Assert.Equal(0, counters.Undervotes);
        Assert.Equal(2, counters.UndervoteDifference);
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
        // On an overvote every undervote field and the null-vote indicator are 0 (Q11, Q15, Q3).
        int sum = values[0] + values[1];
        Assert.Equal(overvoted ? 0 : selectionLimit - sum, counters.UndervoteDifference);
        Assert.Equal(!overvoted && sum < selectionLimit ? 1 : 0, counters.Undervotes);
        Assert.Equal(!overvoted && sum == 0 ? 1 : 0, counters.Nullvotes);
    }

    [Theory]
    // User decision Q13: write-ins always count toward the limit, exactly like selections, and the
    // null and undervote fields are judged on s + w. Columns: L, s, w, then the expected overvotes,
    // null votes, undervotes, undervote difference and write-ins.
    // L = 1: a selection and a write-in are 2 > L, an overvote whose write-ins are zeroed (Q12).
    [InlineData(1, 1, 1, 1, 0, 0, 0, 0)]
    // L = 1: a write-in alone fills the limit; it is not a null vote.
    [InlineData(1, 0, 1, 0, 0, 0, 0, 1)]
    // L = 3: a write-in alone is an undervote by 2, not a null vote.
    [InlineData(3, 0, 1, 0, 0, 1, 2, 1)]
    // L = 3: one selection and two write-ins fill the limit.
    [InlineData(3, 1, 2, 0, 0, 0, 0, 2)]
    // L = 2: one selection and two write-ins are 3 > L.
    [InlineData(2, 1, 2, 1, 0, 0, 0, 0)]
    public void Add_WriteInsAlwaysCountTowardTheLimit(int selectionLimit, int selected, int writeIns, int overvotes, int nullvotes, int undervotes, int difference, int writeInsCounted)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true, selectionLimit: selectionLimit, writeInFieldCount: 2);
        var accumulator = new ExpectedTallyAccumulator(manifest);

        accumulator.Add(ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = selected },
            numWriteinsSelected: writeIns));

        var tally = accumulator.Build();
        var counters = tally.GetCounters("contest-1");

        Assert.Equal(
            [overvotes, nullvotes, undervotes, difference, writeInsCounted],
            new[] { counters.Overvotes, counters.Nullvotes, counters.Undervotes, counters.UndervoteDifference, counters.WriteIns });
        Assert.Equal(overvotes == 1 ? 0 : selected, tally.GetVotes("contest-1", "choice-1"));
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
