namespace ElectionGuard.Core.Tally;

public class DecryptedTally
{
    public required Dictionary<string, DecryptedContest> Contests { get; init; }

    public class DecryptedContest
    {
        public required Dictionary<string, DecryptedChoice> Choices { get; init; }
    }

    public class DecryptedChoice
    {
        public int VoteCount { get; init; }
    }
}