using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Testing.Common;

/// <summary>
/// The totals of a contest's supplemental verifiable fields (§3.3.9) over every ballot contributing
/// to an <see cref="ExpectedTally"/>, whether or not the contest declares the field:
/// <list type="bullet">
/// <item><see cref="Overvotes"/>: ballots whose contest was overvoted.</item>
/// <item><see cref="Nullvotes"/>: ballots with no selection in the contest, overvotes excluded.</item>
/// <item><see cref="Undervotes"/>: ballots whose sum of selections was below the selection
/// limit.</item>
/// <item><see cref="UndervoteDifference"/>: the sum over ballots of the selection limit minus the
/// sum of selections.</item>
/// <item><see cref="WriteIns"/>: write-in fields used, overvoted contests excluded.</item>
/// </list>
/// </summary>
public sealed record ContestCounters(int Overvotes, int Nullvotes, int Undervotes, int UndervoteDifference, int WriteIns)
{
    /// <summary>The total a field of <paramref name="kind"/> should decrypt to.</summary>
    public int Get(SupplementalFieldKind kind) => kind switch
    {
        SupplementalFieldKind.OvervoteIndicator => Overvotes,
        SupplementalFieldKind.NullVoteIndicator => Nullvotes,
        SupplementalFieldKind.UndervoteIndicator => Undervotes,
        SupplementalFieldKind.UndervoteDifferenceCount => UndervoteDifference,
        SupplementalFieldKind.WriteInCount => WriteIns,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
    };
}

/// <summary>
/// The per-option vote counts a correct decryption of the encrypted tally must produce, and the
/// totals of each contest's supplemental fields (§3.3.9). Every supplemental field a contest
/// declares is aggregated and decrypted like an option, so TallyComparer checks those totals too,
/// under the field's label (<see cref="SupplementalFieldIds"/>).
/// </summary>
public sealed class ExpectedTally
{
    private readonly Dictionary<string, Dictionary<string, int>> _votes;
    private readonly Dictionary<string, ContestCounters> _counters;
    private readonly Dictionary<string, IReadOnlyList<(string FieldId, SupplementalFieldKind Kind)>> _fields;

    internal ExpectedTally(
        Dictionary<string, Dictionary<string, int>> votes,
        Dictionary<string, ContestCounters> counters,
        Dictionary<string, IReadOnlyList<(string FieldId, SupplementalFieldKind Kind)>> fields)
    {
        _votes = votes;
        _counters = counters;
        _fields = fields;
    }

    public IReadOnlyCollection<string> ContestIds => _votes.Keys;

    public IReadOnlyCollection<string> ChoiceIds(string contestId) => _votes[contestId].Keys;

    /// <summary>
    /// The expected vote count for a choice. Throws <see cref="KeyNotFoundException"/> for a
    /// contest or choice not in the manifest -- an unknown id is a bug in the caller, not a zero.
    /// </summary>
    public int GetVotes(string contestId, string choiceId) => _votes[contestId][choiceId];

    /// <summary>
    /// The expected supplemental-field totals for a contest. Throws
    /// <see cref="KeyNotFoundException"/> for a contest not in the manifest.
    /// </summary>
    public ContestCounters GetCounters(string contestId) => _counters[contestId];

    /// <summary>
    /// The supplemental fields the manifest declares for the contest, by label and kind, in manifest
    /// order. A decrypted tally holds a count for each.
    /// </summary>
    public IReadOnlyList<(string FieldId, SupplementalFieldKind Kind)> SupplementalFieldIds(string contestId) => _fields[contestId];
}

/// <summary>
/// Accumulates the expected tally from plaintext ballots.
///
/// The overvote rule and the supplemental-field values are derived here from the spec text, not
/// from BallotEncryptor's code, so that egperf's correctness gate is an independent check:
/// <list type="bullet">
/// <item>§3.1.3 p.17: a selection is a value in {0, ..., R}; L is "the maximal total value for the
/// sum of all selections made in that contest".</item>
/// <item>§3.1.3 p.19 and §3.3.9 p.39: write-ins count toward the selection limit when the manifest
/// says so ("Which of those fields are counted while ensuring adherence to the contest selection
/// limit must also be specified in the manifest").</item>
/// <item>§3.3.5 p.31: "When the number of selections made by the voter exceeds the contest selection
/// limit or when the selection assigned to a single option in a contest exceeds its option
/// selection limit, the votes in the contest become invalid as an overvote. To not affect the
/// election tallies, all selectable options in the contest are set to zero." The contest's
/// write-ins are part of its invalid votes, so they are not counted either.</item>
/// <item>§3.3.9 pp.38-39: overvote indicator 1 iff overvoted; null-vote indicator 1 iff no selection
/// was made, and 0 on an overvote ("should be set to zero"); undervote indicator 1 iff the sum of
/// the selections is strictly less than L; undervote difference L minus that sum. On an overvote the
/// sum is that of the zeroed selections, so the indicator is 1 and the difference L. For the
/// difference that is forced (L - u = sum); for the indicator it follows p.38's disjunctive proof,
/// where p.18/p.38's definition by the voter's sum would give 0 (open S5 user question 4).</item>
/// </list>
///
/// IMPORTANT: Add(ballot) must be called BEFORE the ballot is encrypted.
/// BallotEncryptor.EncryptContest mutates the ballot in place when it detects an overvote, zeroing
/// every SelectionValue, so a ballot accumulated afterwards would look like a null vote rather than
/// an overvote.
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
            _ => new ContestCounters(0, 0, 0, 0, 0));
    }

    public void Add(Ballot ballot)
    {
        foreach (var ballotContest in ballot.Contests)
        {
            var contest = _contestsById[ballotContest.Id];
            int contestLimit = contest.SelectionLimit;      // L
            int optionLimit = contest.OptionSelectionLimit; // R

            bool writeInsAreSelections = contest.SupplementalFields
                .Any(field => field.Kind == SupplementalFieldKind.WriteInCount && field.CountsTowardSelectionLimit);

            long selectionsTotal = ballotContest.Choices.Sum(choice => (long)choice.SelectionValue)
                + (writeInsAreSelections ? ballotContest.NumWriteinsSelected : 0);
            bool someOptionAboveItsLimit = ballotContest.Choices.Any(choice => choice.SelectionValue > optionLimit);
            bool overvoted = selectionsTotal > contestLimit || someOptionAboveItsLimit;

            // What the tally sees: nothing at all from an overvoted contest.
            // Two of these rules answer open user questions with the recommended option (a); both
            // change published totals only, and the tests that pin them are marked
            // DECISION-DEPENDENT PIN:
            // - question 1: an overvote zeroes the write-in count even where it does not count
            //   toward the limit (countedWriteIns below);
            // - question 2: uncounted write-ins are not selections, so a ballot whose only marks
            //   are uncounted write-ins is a null vote (Nullvotes uses countedTotal, which leaves
            //   them out).
            int countedTotal = overvoted ? 0 : (int)selectionsTotal;
            int countedWriteIns = overvoted ? 0 : ballotContest.NumWriteinsSelected;

            var current = _counters[ballotContest.Id];
            _counters[ballotContest.Id] = current with
            {
                Overvotes = current.Overvotes + (overvoted ? 1 : 0),
                Nullvotes = current.Nullvotes + (!overvoted && countedTotal == 0 ? 1 : 0),
                Undervotes = current.Undervotes + (countedTotal < contestLimit ? 1 : 0),
                UndervoteDifference = current.UndervoteDifference + (contestLimit - countedTotal),
                WriteIns = current.WriteIns + countedWriteIns,
            };

            if (overvoted)
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
            new Dictionary<string, ContestCounters>(_counters),
            _contestsById.ToDictionary(
                contest => contest.Key,
                contest => (IReadOnlyList<(string FieldId, SupplementalFieldKind Kind)>)contest.Value.SupplementalFields
                    .Select(field => (field.Id, field.Kind))
                    .ToList()));
}
