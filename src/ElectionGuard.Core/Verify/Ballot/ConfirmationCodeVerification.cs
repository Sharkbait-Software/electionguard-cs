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
        // The contest hashes recomputed below hash the manifest's contest indices. They are trusted
        // here because EncryptionRecord validated the manifest (§3.1.3) when it was built;
        // re-validating the whole manifest per ballot would cost O(manifest) each time.

        // Exactly the ballot style's contests and the manifest's options, each once, before anything
        // else (see BallotStructure). Without it, a contest listed twice would be hashed twice into
        // a confirmation code that then matches, and the ballot would be tallied twice.
        BallotStructure.Require(ballot, encryptionRecord.Manifest, 8);

        // The hashes are recomputed in the canonical order of eqs. (70) and (71) -- options in
        // option-index order within each contest, contests in contest-index order -- looked up by
        // label, whatever order the ballot happens to list them in. A ballot whose hashes were
        // computed over any other order therefore fails 8.A or 8.B. The encryptor writes the lists in
        // that order already, so sorting happens only for a ballot that lists them otherwise.
        var contestHashes = new List<ContestHash>(ballot.Contests.Count);
        bool contestsInOrder = true;
        int previousContestIndex = 0;
        foreach (var contest in ballot.Contests)
        {
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
            contestsInOrder &= manifestContest.Index > previousContestIndex;
            previousContestIndex = manifestContest.Index;

            var calculatedContestHash = new ContestHash(
                ballot.SelectionEncryptionIdentifierHash,
                manifestContest.Index,
                InManifestOrder(contest.Choices, manifestContest),
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

        if (!contestsInOrder)
        {
            var manifestContests = encryptionRecord.Manifest.Contests;
            contestHashes = ballot.Contests.Zip(contestHashes)
                .OrderBy(x => manifestContests.Single(c => c.Id == x.First.Id).Index)
                .Select(x => x.Second)
                .ToList();
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

    /// <summary>
    /// A contest's selections in manifest option-index order (eq. 70): the stored list itself when it
    /// is already in that order, otherwise a sorted copy. (BallotStructure has already required
    /// exactly the manifest's options, each once; an unknown label would sort last.)
    /// </summary>
    private static IEnumerable<EncryptedSelection> InManifestOrder(List<EncryptedSelection> choices, Contest manifestContest)
    {
        bool inOrder = choices.Count == manifestContest.Choices.Count;
        for (int i = 0; inOrder && i < choices.Count; i++)
        {
            inOrder = choices[i].ChoiceId == manifestContest.Choices[i].Id;
        }

        if (inOrder)
        {
            return choices;
        }

        return choices.OrderBy(choice => manifestContest.Choices.FirstOrDefault(x => x.Id == choice.ChoiceId)?.Index ?? int.MaxValue);
    }

    // TODO: Verify device information 8 C, F, and G.
    public void VerifyDevice()
    {

    }
}
