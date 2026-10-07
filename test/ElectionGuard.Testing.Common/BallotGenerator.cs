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
            contests.Add(GenerateContest(_contestsById[contestId], random, index));
        }

        return new Ballot
        {
            Id = index.ToString(),
            BallotStyleId = ballotStyle.Id,
            Contests = contests,
        };
    }

    private BallotContest GenerateContest(Contest contest, Random random, int ballotIndex)
    {
        var roll = random.Next(100);

        // Overvotes and undervotes are things voters do whatever the manifest records about them, so
        // they are generated for every contest; write-ins only where the contest offers write-in
        // fields.
        bool isOvervote = roll < OvervoteThreshold;
        int numUndervotes = 0;
        int numWriteIns = 0;

        if (!isOvervote && roll < UndervoteThreshold)
        {
            numUndervotes = random.Next(1, contest.SelectionLimit + 1);
        }
        else if (!isOvervote && contest.WriteInFieldCount > 0 && roll < WriteInThreshold)
        {
            numWriteIns = random.Next(1, contest.WriteInFieldCount + 1);
        }

        var values = new Dictionary<string, int>();

        if (isOvervote)
        {
            // Half the overvoted contests that offer write-in fields use some too, so the gate sees
            // what an overvote does to the write-in count (zeroed, user decision Q12).
            if (contest.WriteInFieldCount > 0 && random.Next(2) == 0)
            {
                numWriteIns = random.Next(1, contest.WriteInFieldCount + 1);
            }

            if (contest.OptionSelectionLimit > 1 && random.Next(2) == 0)
            {
                // One option above its option selection limit R: an overvote of its own (§3.3.5),
                // whether or not the contest's total also exceeds L.
                values[contest.Choices[random.Next(contest.Choices.Count)].Id] = contest.OptionSelectionLimit + 1;
            }
            else
            {
                // Mark every choice. This is a genuine overvote only when the contest's choices
                // outnumber its selection limit; otherwise it is an ordinary maximal ballot.
                // BallotEncryptor and ExpectedTallyAccumulator each decide which, so there is nothing
                // to special-case here.
                foreach (var choice in contest.Choices)
                {
                    values[choice.Id] = 1;
                }
            }
        }
        else
        {
            // Spend `remaining` units of the selection limit on the options, at most R on any one.
            // With R = 1 this marks `remaining` distinct choices.
            int capacity = contest.Choices.Count * Math.Max(1, contest.OptionSelectionLimit);
            int remaining = Math.Max(0, contest.SelectionLimit - numUndervotes - numWriteIns);
            remaining = Math.Min(remaining, capacity);

            while (remaining > 0)
            {
                var choiceId = contest.Choices[random.Next(contest.Choices.Count)].Id;
                values.TryGetValue(choiceId, out int current);
                if (current >= contest.OptionSelectionLimit)
                {
                    continue;
                }

                int add = contest.OptionSelectionLimit == 1
                    ? 1
                    : random.Next(1, Math.Min(contest.OptionSelectionLimit - current, remaining) + 1);
                values[choiceId] = current + add;
                remaining -= add;
            }
        }

        var choices = contest.Choices
            .Select(choice => new BallotChoice
            {
                Id = choice.Id,
                SelectionValue = values.TryGetValue(choice.Id, out int value) ? value : 0,
            })
            .ToList();

        return new BallotContest
        {
            Id = contest.Id,
            Choices = choices,
            NumWriteinsSelected = numWriteIns,
            ContestData = WriteInText(contest, numWriteIns, ballotIndex),
        };
    }

    /// <summary>
    /// The contest data field (§3.3.10) of a contest whose voter used <paramref name="writeIns"/>
    /// write-in fields: the write-in text, encoded with <see cref="ContestDataEncoding"/> to the
    /// contest's b_Λ and cut to fit it. Null (the encryptor then encrypts an empty field) when the
    /// voter wrote nothing or the contest declares no contest data. Derived from the ballot index
    /// and the contest, never from the random stream, so adding it moved no other generated value.
    /// </summary>
    private static byte[]? WriteInText(Contest contest, int writeIns, int ballotIndex)
    {
        if (writeIns == 0 || contest.ContestDataBlocks == 0)
        {
            return null;
        }

        var names = string.Join(", ", Enumerable.Range(1, writeIns).Select(i => "Candidate " + i));
        var text = "Write-in " + ballotIndex + "/" + contest.Id + ": " + names;
        int capacity = ContestDataEncoding.Capacity(contest.ContestDataBlocks);
        if (System.Text.Encoding.UTF8.GetByteCount(text) > capacity)
        {
            // ASCII only, so a byte count is a character count.
            text = text[..capacity];
        }

        return ContestDataEncoding.Encode(text, contest.ContestDataBlocks);
    }
}
