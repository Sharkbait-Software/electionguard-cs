using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Testing.Common;

/// <summary>
/// The overvote/nullvote/undervote/write-in counters BallotEncryptor.EncryptContest embeds in a
/// single contest of a single ballot, accumulated across every ballot contributing to an
/// ExpectedTally.
/// </summary>
public sealed record ContestCounters(int Overvotes, int Nullvotes, int Undervotes, int WriteIns);

/// <summary>
/// The per-choice vote counts a correct decryption of the encrypted tally must produce, plus the
/// per-contest overvote/nullvote/undervote/write-in counters BallotEncryptor.EncryptContest embeds
/// in each ballot. The vote counts are shaped to match DecryptedTally, which carries per-choice
/// VoteCount and nothing else; the counters have no analogue to check against because
/// EncryptedTally never aggregates them, so they document the generated corpus rather than verify
/// it (see TallyComparer, which intentionally does not compare them).
/// </summary>
public sealed class ExpectedTally
{
    private readonly Dictionary<string, Dictionary<string, int>> _votes;
    private readonly Dictionary<string, ContestCounters> _counters;

    internal ExpectedTally(
        Dictionary<string, Dictionary<string, int>> votes,
        Dictionary<string, ContestCounters> counters)
    {
        _votes = votes;
        _counters = counters;
    }

    public IReadOnlyCollection<string> ContestIds => _votes.Keys;

    public IReadOnlyCollection<string> ChoiceIds(string contestId) => _votes[contestId].Keys;

    /// <summary>
    /// The expected vote count for a choice. Throws <see cref="KeyNotFoundException"/> for a
    /// contest or choice not in the manifest -- an unknown id is a bug in the caller, not a zero.
    /// </summary>
    public int GetVotes(string contestId, string choiceId) => _votes[contestId][choiceId];

    /// <summary>
    /// The expected overvote/nullvote/undervote/write-in counters for a contest. Throws
    /// <see cref="KeyNotFoundException"/> for a contest not in the manifest.
    /// </summary>
    public ContestCounters GetCounters(string contestId) => _counters[contestId];
}

/// <summary>
/// Accumulates the expected tally from plaintext ballots.
///
/// IMPORTANT: Add(ballot) must be called BEFORE the ballot is encrypted.
/// BallotEncryptor.EncryptContest mutates the ballot in place when it detects an overvote, zeroing
/// every SelectionValue, so a ballot accumulated after encryption contributes zeros for a contest
/// that should have contributed zeros anyway -- and contributes correctly for every other contest
/// purely by luck. Relying on that is how a real mismatch gets masked.
///
/// Not thread-safe. Accumulate a generated chunk serially before handing it to the encryptor.
/// </summary>
public sealed class ExpectedTallyAccumulator
{
    private readonly Dictionary<string, Contest> _contestsById;
    private readonly Dictionary<string, Dictionary<string, int>> _votes;
    private readonly Dictionary<string, ContestCounters> _counters;

    public ExpectedTallyAccumulator(Manifest manifest)
    {
        _contestsById = manifest.Contests.ToDictionary(x => x.Id);
        _votes = manifest.Contests.ToDictionary(
            contest => contest.Id,
            contest => contest.Choices.ToDictionary(choice => choice.Id, _ => 0));
        _counters = manifest.Contests.ToDictionary(
            contest => contest.Id,
            _ => new ContestCounters(0, 0, 0, 0));
    }

    public void Add(Ballot ballot)
    {
        foreach (var ballotContest in ballot.Contests)
        {
            var manifestContest = _contestsById[ballotContest.Id];

            var selectionTotal = ballotContest.Choices.Sum(choice => choice.SelectionValue);
            var countOfSelections = ballotContest.Choices.Count(choice => choice.SelectionValue > 0);

            // Mirrors BallotEncryptor.EncryptContest's four flags EXACTLY, and in the same order:
            // isOvervote, isNullVote, numUndervotes and numWriteIns are all computed from the
            // ballot's ORIGINAL selection values, before the encryptor (or this accumulator) does
            // anything about an overvote. The encryptor only zeroes SelectionValue -- and only
            // after computing all four -- so isNullVote/numUndervotes must never be derived from
            // post-zeroing values, or a contest that is both an overvote and would (pre-zeroing)
            // have been a null/undervote reports the wrong counters. This re-derives the rule
            // rather than calling into BallotEncryptor, deliberately: the expected tally is meant
            // to be an independent check, not a circular one.
            bool isOvervote = selectionTotal > manifestContest.SelectionLimit * manifestContest.OptionSelectionLimit;
            bool isNullVote = ballotContest.Choices.All(choice => choice.SelectionValue == 0);
            int numUndervotes = Math.Max(0, manifestContest.SelectionLimit - countOfSelections);
            int numWriteIns = ballotContest.NumWriteinsSelected;

            var currentCounters = _counters[ballotContest.Id];
            _counters[ballotContest.Id] = currentCounters with
            {
                Overvotes = currentCounters.Overvotes + (isOvervote ? 1 : 0),
                Nullvotes = currentCounters.Nullvotes + (isNullVote ? 1 : 0),
                Undervotes = currentCounters.Undervotes + numUndervotes,
                WriteIns = currentCounters.WriteIns + numWriteIns,
            };

            // Mirrors BallotEncryptor.EncryptContest: an overvote is a selection total exceeding
            // SelectionLimit * OptionSelectionLimit, and the encryptor responds by encrypting a
            // zero for every choice in the contest. So the contest contributes nothing to the
            // per-choice vote counts (the counters above were already recorded, matching the
            // encryptor, which computes them before zeroing anything).
            if (isOvervote)
            {
                continue;
            }

            var contestVotes = _votes[ballotContest.Id];
            foreach (var choice in ballotContest.Choices)
            {
                contestVotes[choice.Id] += choice.SelectionValue;
            }
        }
    }

    public ExpectedTally Build() =>
        new(
            _votes.ToDictionary(
                contest => contest.Key,
                contest => contest.Value.ToDictionary(choice => choice.Key, choice => choice.Value)),
            new Dictionary<string, ContestCounters>(_counters));
}
