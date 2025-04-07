using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
///  Verification 8 (Validation of confirmation codes)
/// </summary>
public class ConfirmationCodeVerification
{
    public void Verify(EncryptedBallot ballot, EncryptionRecord encryptionRecord)
    {
        foreach(var contest in ballot.Contests)
        {
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
            var calculatedContestHash = new ContestHash(
                ballot.SelectionEncryptionIdentifierHash,
                manifestContest.Index,
                contest.Choices,
                contest.OvervoteCount,
                contest.NullvoteCount,
                contest.UndervoteCount,
                contest.WriteInVoteCount,
                contest.ContestData);

            // TODO: Finish
            //if(calculatedContestHash != contest.ContestHash)
            //{
            //    
            //}
        }
    }
}
