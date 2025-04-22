using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;

namespace ElectionGuard.Core.Verify.Tally;

/// <summary>
/// Verification 9 (Correctness of ballot aggregation)
/// </summary>
public class BallotAggregationVerification
{
    public void Verify(List<EncryptedBallot> ballots, Manifest manifest, EncryptedTally encryptedTally)
    {
        var expectedEncryptedTally = new EncryptedTally(manifest);
        foreach(var ballot in ballots)
        {
            expectedEncryptedTally.AddBallot(ballot);
        }

        foreach (var contest in encryptedTally.Contests)
        {
            var expectedContest = expectedEncryptedTally.Contests[contest.Key];
            foreach (var choice in contest.Value.Choices)
            {
                var expectedChoice = expectedContest.Choices[choice.Key];
                if (expectedChoice.A != choice.Value.A)
                {
                    throw new Exception($"Ballot aggregation verification failed for contest {contest.Key}, choice {choice.Key}: expected A {expectedChoice.A}, got {choice.Value.A}");
                }
                if (expectedChoice.B != choice.Value.B)
                {
                    throw new Exception($"Ballot aggregation verification failed for contest {contest.Key}, choice {choice.Key}: expected B {expectedChoice.B}, got {choice.Value.B}");
                }
            }
        }
    }
}
