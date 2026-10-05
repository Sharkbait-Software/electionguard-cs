using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;

namespace ElectionGuard.Core.Verify.PreEncryption;

/// <summary>
/// Verification 16 (Validation of confirmation codes in pre-encrypted ballots), items 16.A-16.F,
/// for one pre-encrypted ballot. 16.G and 16.H are checked once per device and are not covered here.
///
/// 16.C recomputes the confirmation code from the chaining field published with the ballot; 16.E and
/// 16.F then check that published field against the one this device should have used, so a chaining
/// fault is reported under its own sub-section rather than as a confirmation code mismatch.
/// </summary>
public class PreEncryptedConfirmationCodeVerification
{
    /// <param name="deviceInformationHash">The pre-encrypted device information hash HDI of the device
    /// the ballot was generated on.</param>
    /// <param name="previousConfirmationCode">Under simple chaining, the confirmation code of the
    /// previous ballot generated on the device, or null for its first ballot.</param>
    public void Verify(PreEncryptedBallot ballot, VotingDeviceInformationHash deviceInformationHash, EncryptionRecord encryptionRecord, ConfirmationCode? previousConfirmationCode)
    {
        // The contest hashes recomputed below hash the manifest's contest indices. They are trusted
        // here because EncryptionRecord validated the manifest (§3.1.3) when it was built;
        // re-validating the whole manifest per ballot would cost O(manifest) each time.

        // 16.A-16.C recompute hashes over whatever the ballot publishes, so a ballot missing a null
        // vector, with a short vector, or repeating a contest would be internally consistent. Its
        // shape is checked first: the ballot style's contests, each once, and per contest m option
        // vectors and L null vectors of m encryptions each (eqs. 112-115; see BallotStructure).
        BallotStructure.Require(ballot, encryptionRecord.Manifest, 16);

        var selectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash;
        var contestHashes = new List<(int ContestIndex, ContestHash ContestHash)>();

        foreach (var contest in ballot.Contests)
        {
            foreach (var selection in contest.Selections)
            {
                // 16.A: psi_i = H(HI; 0x40, alpha_1, beta_1, ..., alpha_m, beta_m).
                var expectedSelectionHash = new SelectionHash(selectionEncryptionIdentifierHash, selection.Vector);
                if (expectedSelectionHash != selection.SelectionHash)
                {
                    throw new VerificationFailedException("16.A", $"Selection hash for ballot {ballot.Id}, contest {contest.ContestId}, selection index {selection.SelectionIndex} does not match its pre-encryption vector.");
                }
            }

            // 16.B: chi_l = H(HI; 0x41, ind_c(l), psi_pi(1), ..., psi_pi(m+L)), selection hashes sorted.
            var manifestContest = encryptionRecord.Manifest.Contests.SingleOrDefault(x => x.Id == contest.ContestId)
                ?? throw new VerificationFailedException("16.B", $"Contest {contest.ContestId} on ballot {ballot.Id} is not in the manifest, so its contest hash cannot be checked.");
            var expectedContestHash = ContestHash.ForPreEncryptedContest(
                selectionEncryptionIdentifierHash,
                manifestContest.Index,
                contest.Selections.Select(x => x.SelectionHash));
            if (expectedContestHash != contest.ContestHash)
            {
                throw new VerificationFailedException("16.B", $"Contest hash for ballot {ballot.Id}, contest {contest.ContestId} does not match its selection hashes.");
            }

            contestHashes.Add((manifestContest.Index, contest.ContestHash));
        }

        // 16.C: HC = H(HI; 0x42, chi_1, ..., chi_mB, BC), contest hashes in contest index order.
        var expectedConfirmationCode = ConfirmationCode.ForPreEncryptedBallot(
            selectionEncryptionIdentifierHash,
            contestHashes.OrderBy(x => x.ContestIndex).Select(x => x.ContestHash),
            ballot.ChainingField);
        if (expectedConfirmationCode != ballot.ConfirmationCode)
        {
            throw new VerificationFailedException("16.C", $"Confirmation code for ballot {ballot.Id} does not match its contest hashes and chaining field.");
        }

        // 16.D: HDI = H(HE; 0x43, S_device).
        var expectedDeviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(encryptionRecord.ExtendedBaseHash, ballot.DeviceId);
        if (expectedDeviceHash != deviceInformationHash)
        {
            throw new VerificationFailedException("16.D", $"Device information hash for ballot {ballot.Id} does not match device {ballot.DeviceId}.");
        }

        var chainingMode = encryptionRecord.Manifest.ChainingMode;
        var expectedChainingField = ChainingField.ForPreEncryptedBallots(chainingMode, deviceInformationHash, encryptionRecord.ExtendedBaseHash, previousConfirmationCode);
        if (chainingMode == ChainingMode.None && expectedChainingField != ballot.ChainingField)
        {
            // 16.E: BC = 0x00000000 || HDI.
            throw new VerificationFailedException("16.E", $"Chaining field for ballot {ballot.Id} is not the no-chaining field of device {ballot.DeviceId}.");
        }

        if (chainingMode == ChainingMode.Simple && expectedChainingField != ballot.ChainingField)
        {
            // 16.F: BC,j = 0x00000001 || Hj-1, with H0 from (117) for the device's first ballot.
            throw new VerificationFailedException("16.F", $"Chaining field for ballot {ballot.Id} does not chain from the previous confirmation code on device {ballot.DeviceId}.");
        }
    }
}
