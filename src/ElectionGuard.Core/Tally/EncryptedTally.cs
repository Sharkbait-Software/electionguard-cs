using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Tally;

public class EncryptedTally
{
    public EncryptedTally(Manifest manifest)
    {
        _manifest = manifest;

        Contests = _manifest.Contests
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
    public Dictionary<string, EncryptedAggregateContest> Contests;

    public void AddBallot(EncryptedBallot encryptedBallot)
    {
        foreach(var contest in encryptedBallot.Contests)
        {
            var aggregateContest = Contests[contest.Id];
            foreach(var choice in contest.Choices)
            {
                var aggregateChoice = aggregateContest.Choices[choice.ChoiceId];
                var alpha = choice.Alpha;
                var beta = choice.Beta;
                
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

    public class EncryptedAggregateContest
    {
        public required string ContestId { get; init; }
        public required Dictionary<string, EncryptedAggregateChoice> Choices { get; init; }
    }

    public class EncryptedAggregateChoice
    {
        public required string ChoiceId { get; init; }
        public required IntegerModP A { get; set; }
        public required IntegerModP B { get; set; }
    }
}


public class PartialTallyDecryption
{

}