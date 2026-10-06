using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Testing.Common;

/// <summary>
/// The totals of a contest's supplemental verifiable fields (§3.3.9) over every ballot contributing
/// to an <see cref="ExpectedTally"/>, whether or not the contest declares the field (see
/// <see cref="ExpectedTallyAccumulator"/> for the rules):
/// <list type="bullet">
/// <item><see cref="Overvotes"/>: ballots whose contest was overvoted.</item>
/// <item><see cref="Nullvotes"/>: ballots with no selection and no write-in in the contest,
/// overvotes excluded.</item>
/// <item><see cref="Undervotes"/>: ballots whose selections and write-ins were below the selection
/// limit, overvotes excluded.</item>
/// <item><see cref="UndervoteDifference"/>: the sum over ballots of the undervote difference
/// count.</item>
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
/// The overvote rule and the supplemental-field values are derived here from the spec text and the
/// user's S5 follow-up decisions as recorded in docs/spec-compliance/2026-10-04-fix-progress.md
/// (Q11-Q16), not from BallotEncryptor's code, so that egperf's correctness gate is an independent
/// check. With s the sum of the voter's selections, w the number of write-ins used and L the
/// contest selection limit:
/// <list type="bullet">
/// <item>§3.1.3 p.17: a selection is a value in {0, ..., R}; L is "the maximal total value for the
/// sum of all selections made in that contest".</item>
/// <item>Q13: "Any write in should count towards the limit", "exactly like selections". The total
/// every rule is judged on is s + w.</item>
/// <item>§3.3.5 p.31: "When the number of selections made by the voter exceeds the contest selection
/// limit or when the selection assigned to a single option in a contest exceeds its option
/// selection limit, the votes in the contest become invalid as an overvote. To not affect the
/// election tallies, all selectable options in the contest are set to zero." So: overvoted when
/// s + w &gt; L or some option &gt; R.</item>
/// <item>"Resulting values on an overvote: options 0, write-in count 0, overvote 1, undervote
/// indicator 0, undervote difference 0, null 0" (Q11, Q12, Q3). The undervote difference count is
/// 0 because Q15 proves "s + w + L·overvote + u = L"; a contest that does not track the overvote
/// indicator has no such term (Q14: an untracked field "doesn't matter at all and presumably isn't
/// included"), and there the relation gives u = L (user decision Q18: with no tracked overvote
/// indicator nothing publishes an overvote, so the neutralized contest is a blank one).</item>
/// <item>"On a null vote (s + w = 0, no overvote): undervote indicator 1, difference L, null 1."
/// Otherwise (no overvote): undervote indicator 1 iff s + w &lt; L (§3.3.9 p.38 "strictly less
/// than the contest selection limit"), difference L - (s + w), null 0 (Q13: "A ballot that uses a
/// write-in is not a null vote").</item>
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

            long selections = ballotContest.Choices.Sum(choice => (long)choice.SelectionValue); // s
            int writeIns = ballotContest.NumWriteinsSelected;                                    // w
            bool someOptionAboveItsLimit = ballotContest.Choices.Any(choice => choice.SelectionValue > optionLimit);
            bool overvoted = selections + writeIns > contestLimit || someOptionAboveItsLimit;

            int overvotes, nullvotes, undervotes, undervoteDifference, writeInsCounted;
            if (overvoted)
            {
                bool overvoteTracked = contest.SupplementalFields.Any(field => field.Kind == SupplementalFieldKind.OvervoteIndicator);
                overvotes = 1;
                nullvotes = 0;
                undervotes = 0;
                undervoteDifference = overvoteTracked ? 0 : contestLimit;
                writeInsCounted = 0;
            }
            else
            {
                int total = (int)selections + writeIns;
                overvotes = 0;
                nullvotes = total == 0 ? 1 : 0;
                undervotes = total < contestLimit ? 1 : 0;
                undervoteDifference = contestLimit - total;
                writeInsCounted = writeIns;
            }

            var current = _counters[ballotContest.Id];
            _counters[ballotContest.Id] = current with
            {
                Overvotes = current.Overvotes + overvotes,
                Nullvotes = current.Nullvotes + nullvotes,
                Undervotes = current.Undervotes + undervotes,
                UndervoteDifference = current.UndervoteDifference + undervoteDifference,
                WriteIns = current.WriteIns + writeInsCounted,
            };

            // What the tally sees: nothing at all from an overvoted contest.
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
