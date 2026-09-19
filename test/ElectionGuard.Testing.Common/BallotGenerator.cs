using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Testing.Common;

/// <summary>
/// Produces plaintext ballots conforming to a manifest, deterministically from a seed and a ballot
/// index. Ballot i depends only on (seed, i), never on how many ballots were generated before it,
/// so generation parallelizes and any single ballot is reproducible in isolation.
///
/// The instance holds no mutable state and Generate is safe to call concurrently.
///
/// Note that BallotEncryptor.EncryptContest MUTATES the returned Ballot when the contest is an
/// overvote (it zeroes every SelectionValue). A generated ballot must therefore be encrypted at
/// most once, must not be shared across threads once handed to an encryptor, and must have its
/// expected-tally contribution recorded BEFORE it is encrypted.
/// </summary>
public sealed class BallotGenerator
{
    // Rolled once per contest against a 0-99 range. Cumulative: the first band that the roll falls
    // into wins.
    private const int OvervoteThreshold = 1;    // rolls 0
    private const int UndervoteThreshold = 5;   // rolls 1-4
    private const int WriteInThreshold = 10;    // rolls 5-9

    private readonly Manifest _manifest;
    private readonly int _seed;
    private readonly Dictionary<string, Contest> _contestsById;

    public BallotGenerator(Manifest manifest, int seed)
    {
        // GenerateContest's undervote loop marks distinct choice ids until it reaches `remaining`,
        // clamped to contest.Choices.Count (the list length, not the distinct-id count). A
        // duplicated choice id within one contest is a broken manifest that would otherwise make
        // that loop spin forever with no diagnostic -- fail fast here instead.
        if (manifest.Contests is null)
        {
            throw new ArgumentException("Manifest.Contests is null.", nameof(manifest));
        }

        foreach (var contest in manifest.Contests)
        {
            if (contest.Choices is null)
            {
                throw new ArgumentException(
                    $"Contest '{contest.Id}' has a null Choices collection.",
                    nameof(manifest));
            }

            var duplicateChoiceIds = contest.Choices
                .GroupBy(choice => choice.Id)
                .Where(group => group.Count() > 1)
                .Select(group => group.Key)
                .ToList();

            if (duplicateChoiceIds.Count > 0)
            {
                throw new ArgumentException(
                    $"Contest '{contest.Id}' has duplicated choice ids: {string.Join(", ", duplicateChoiceIds)}.",
                    nameof(manifest));
            }
        }

        _manifest = manifest;
        _seed = seed;
        _contestsById = manifest.Contests.ToDictionary(x => x.Id);
    }

    public Ballot Generate(int index)
    {
        // A cheap, well-mixed per-ballot seed. Multiplying the run seed by a large prime before
        // adding the index keeps neighbouring indexes from producing correlated streams.
        var random = new Random(unchecked(_seed * 486187739 + index));

        var ballotStyle = _manifest.BallotStyles[random.Next(_manifest.BallotStyles.Count)];

        var contests = new List<BallotContest>(ballotStyle.ContestIds.Count);
        foreach (var contestId in ballotStyle.ContestIds)
        {
            contests.Add(GenerateContest(_contestsById[contestId], random));
        }

        return new Ballot
        {
            Id = index.ToString(),
            BallotStyleId = ballotStyle.Id,
            Contests = contests,
        };
    }

    private BallotContest GenerateContest(Contest contest, Random random)
    {
        var roll = random.Next(100);

        bool isOvervote = _manifest.IncludeOvervotes && roll < OvervoteThreshold;
        int numUndervotes = 0;
        int numWriteIns = 0;

        if (!isOvervote && _manifest.IncludeUndervotes && roll < UndervoteThreshold)
        {
            numUndervotes = random.Next(1, contest.SelectionLimit + 1);
        }
        else if (!isOvervote && _manifest.IncludeWriteins && roll < WriteInThreshold)
        {
            numWriteIns = contest.SelectionLimit;
        }

        var selected = new HashSet<string>();

        if (isOvervote)
        {
            // Mark every choice. This is a genuine overvote only when SelectionLimit *
            // OptionSelectionLimit < Choices.Count; otherwise marking every choice does not exceed
            // the limit and this produces an ordinary max-selection ballot instead. Either way,
            // BallotEncryptor and ExpectedTallyAccumulator apply the identical formula to decide
            // whether it's an overvote, so there's nothing to special-case here.
            foreach (var choice in contest.Choices)
            {
                selected.Add(choice.Id);
            }
        }
        else
        {
            int remaining = Math.Max(0, contest.SelectionLimit - numUndervotes - numWriteIns);
            remaining = Math.Min(remaining, contest.Choices.Count);

            while (selected.Count < remaining)
            {
                selected.Add(contest.Choices[random.Next(contest.Choices.Count)].Id);
            }
        }

        var choices = contest.Choices
            .Select(choice => new BallotChoice
            {
                Id = choice.Id,
                SelectionValue = selected.Contains(choice.Id) ? 1 : 0,
            })
            .ToList();

        return new BallotContest
        {
            Id = contest.Id,
            Choices = choices,
            NumWriteinsSelected = numWriteIns,
            ContestData = null,
        };
    }
}
