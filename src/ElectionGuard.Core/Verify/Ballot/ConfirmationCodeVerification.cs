using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
///  Verification 8 (Validation of confirmation codes)
/// </summary>
public class ConfirmationCodeVerification
{
    public void Verify(EncryptedBallot ballot, VotingDeviceInformationHash deviceInformationHash, EncryptionRecord encryptionRecord, ConfirmationCode? previousConfirmationCode)
    {
        List<ContestHash> contestHashes = new();
        foreach (var contest in ballot.Contests)
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

            if (calculatedContestHash != contest.ContestHash)
            {
                throw new VerificationFailedException("8.A", $"Contest hash for ballot {ballot.Id}, contest {contest.Id} does not match expected value.");
            }

            contestHashes.Add(calculatedContestHash);
        }

        var chainingField = new ChainingField(encryptionRecord.Manifest.ChainingMode, deviceInformationHash, encryptionRecord.ExtendedBaseHash, previousConfirmationCode);
        var expectedConfirmationCode = new ConfirmationCode(ballot.SelectionEncryptionIdentifierHash, contestHashes, chainingField);

        if (expectedConfirmationCode != ballot.ConfirmationCode)
        {
            throw new VerificationFailedException("8.B", $"Confirmation code for ballot {ballot.Id} does not match expected value of {ballot.ConfirmationCode}.");
        }

        // TODO: Move this out into a separate device verification.
        var expectedDeviceHash = new VotingDeviceInformationHash(encryptionRecord.ExtendedBaseHash, ballot.DeviceId);
        if (expectedDeviceHash != deviceInformationHash)
        {
            throw new VerificationFailedException("8.C", $"Device hash for ballot {ballot.Id} does not match expected value of {deviceInformationHash}.");
        }

        if(encryptionRecord.Manifest.ChainingMode == ChainingMode.None)
        {
            var expectedChainingField = new ChainingField(ChainingMode.None, deviceInformationHash, encryptionRecord.ExtendedBaseHash, null);
            if(expectedChainingField != chainingField)
            {
                throw new VerificationFailedException("8.D", $"Chaining field for ballot {ballot.Id} does not match expected value of {chainingField}.");
            }
        }
        else if (encryptionRecord.Manifest.ChainingMode == ChainingMode.Simple)
        {
            var expectedChainingField = new ChainingField(ChainingMode.Simple, deviceInformationHash, encryptionRecord.ExtendedBaseHash, previousConfirmationCode);
            if(expectedChainingField != chainingField)
            {
                throw new VerificationFailedException("8.E", $"Chaining field for ballot {ballot.Id} does not match expected value of {chainingField}.");
            }
        }
    }

    // TODO: Verify device information 8 C, F, and G.
    public void VerifyDevice()
    {

    }
}
