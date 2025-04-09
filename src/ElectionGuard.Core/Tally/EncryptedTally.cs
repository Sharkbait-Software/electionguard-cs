using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Tally;

public class EncryptedTally
{
    public EncryptedTally(Manifest manifest)
    {
        _manifest = manifest;

        _contests = _manifest.Contests
            .ToDictionary(x => x.Id, x => new EncryptedAggregateContest
            {
                ContestId = x.Id,
                Choices = x.Choices.ToDictionary(ch => ch.Id, ch => new EncryptedAggregateChoice
                {
                    ChoiceId = ch.Id,
                    A = new IntegerModP(0),
                    B = new IntegerModP(0),
                })
            });
    }

    private readonly Manifest _manifest;
    private Dictionary<string, EncryptedAggregateContest> _contests;

    public void AddBallot(EncryptedBallot encryptedBallot)
    {
        foreach(var contest in encryptedBallot.Contests)
        {
            var aggregateContest = _contests[contest.Id];
            foreach(var choice in contest.Choices)
            {
                var aggregateChoice = aggregateContest.Choices[choice.ChoiceId];
                var alpha = choice.Value.Alpha;
                var beta = choice.Value.Beta;
                
                if(encryptedBallot.Weight > 1)
                {
                    alpha = IntegerModP.PowModP(alpha, encryptedBallot.Weight);
                    beta = IntegerModP.PowModP(beta, encryptedBallot.Weight);
                }

                aggregateChoice.A *= alpha;
                aggregateChoice.B *= beta;
            }
        }
    }

    private class EncryptedAggregateContest
    {
        public required string ContestId { get; init; }
        public required Dictionary<string, EncryptedAggregateChoice> Choices { get; init; }
    }

    private class EncryptedAggregateChoice
    {
        public required string ChoiceId { get; init; }
        public required IntegerModP A { get; set; }
        public required IntegerModP B { get; set; }
    }
}