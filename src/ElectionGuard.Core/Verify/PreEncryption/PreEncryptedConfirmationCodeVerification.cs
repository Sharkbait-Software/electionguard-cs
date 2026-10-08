using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;

namespace ElectionGuard.Core.Verify.PreEncryption;

/// <summary>
/// Verification 16 (Validation of confirmation codes in pre-encrypted ballots): items 16.A-16.F for
/// one pre-encrypted ballot (<see cref="Verify"/>), and the once-per-device items over a device's
/// published ordered list (§3.7; <see cref="VerifyDevice(DeviceChainRecord, IEnumerable{PreEncryptedBallot}, EncryptionRecord)"/>):
/// 16.D for the recorded H_DI, 16.E/16.F for every ballot in list order, 16.G (H_0, eq. 117) and
/// 16.H (the chain close, eqs. 118/120, body form per user decision Q4). See <see cref="DeviceChainWalk"/>.
///
/// A cast pre-encrypted ballot's record (§4.4; an <see cref="BallotEncryption.EncryptedBallot"/> with
/// <see cref="BallotEncryption.EncryptedBallot.PreEncryptedContests"/>) publishes every selection hash
/// but only the selected vectors; <see cref="Verify(BallotEncryption.EncryptedBallot, VotingDeviceInformationHash, EncryptionRecord, ConfirmationCode?)"/>
/// checks it, and the device walk accepts cast and uncast records together.
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

        VerifyConfirmationCodeAndChain(ballot.Id, ballot.DeviceId, selectionEncryptionIdentifierHash, contestHashes, ballot.ChainingField, ballot.ConfirmationCode, deviceInformationHash, encryptionRecord, previousConfirmationCode);
    }

    /// <summary>
    /// Verification 16 for a cast pre-encrypted ballot's record (§4.3.1, §4.4; see
    /// <see cref="BallotEncryption.EncryptedBallot.PreEncryptedContests"/>), which publishes every
    /// selection hash but only the vectors the voter selected: the structure
    /// (<see cref="BallotStructure.RequirePreEncryptedCast"/>, "16.structure"); 16.A for each
    /// published (selected) vector, whose ψ must be its recomputed hash and one of the contest's
    /// published selection hashes; 16.B over the published hashes; then 16.C-16.F as for
    /// <see cref="Verify(PreEncryptedBallot, VotingDeviceInformationHash, EncryptionRecord, ConfirmationCode?)"/>.
    /// </summary>
    public void Verify(BallotEncryption.EncryptedBallot ballot, VotingDeviceInformationHash deviceInformationHash, EncryptionRecord encryptionRecord, ConfirmationCode? previousConfirmationCode)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        BallotStructure.RequirePreEncryptedCast(ballot, encryptionRecord.Manifest, 16);

        var selectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash;
        var contestHashes = new List<(int ContestIndex, ContestHash ContestHash)>(ballot.Contests.Count);
        for (int i = 0; i < ballot.Contests.Count; i++)
        {
            var contest = ballot.Contests[i];
            var preEncrypted = ballot.PreEncryptedContests![i];
            foreach (var selected in preEncrypted.SelectedVectors)
            {
                // 16.A: psi = H(HI; 0x40, alpha_1, beta_1, ..., alpha_m, beta_m), and the record's
                // full list of selection hashes (which 16.B hashes) holds it.
                var expectedSelectionHash = new SelectionHash(selectionEncryptionIdentifierHash, selected.Vector);
                if (expectedSelectionHash != selected.SelectionHash)
                {
                    throw new VerificationFailedException("16.A", $"Selection hash {selected.SelectionHash} of a selected vector of contest {contest.Id} on ballot {ballot.Id} does not match the vector.");
                }

                if (preEncrypted.SelectionHashes.BinarySearch(selected.SelectionHash) < 0)
                {
                    throw new VerificationFailedException("16.A", $"Selected vector {selected.SelectionHash} of contest {contest.Id} on ballot {ballot.Id} is not one of the contest's published selection hashes.");
                }
            }

            // 16.B: chi_l = H(HI; 0x41, ind_c(l), psi_pi(1), ..., psi_pi(m+L)).
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
            var expectedContestHash = ContestHash.ForPreEncryptedContest(selectionEncryptionIdentifierHash, manifestContest.Index, preEncrypted.SelectionHashes);
            if (expectedContestHash != contest.ContestHash)
            {
                throw new VerificationFailedException("16.B", $"Contest hash for ballot {ballot.Id}, contest {contest.Id} does not match its selection hashes.");
            }

            contestHashes.Add((manifestContest.Index, contest.ContestHash));
        }

        VerifyConfirmationCodeAndChain(ballot.Id, ballot.DeviceId, selectionEncryptionIdentifierHash, contestHashes, ballot.ChainingField, ballot.ConfirmationCode, deviceInformationHash, encryptionRecord, previousConfirmationCode);
    }

    /// <summary>16.C over the contest hashes, then 16.D-16.F for one ballot.</summary>
    private static void VerifyConfirmationCodeAndChain(
        string ballotId,
        string deviceId,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        List<(int ContestIndex, ContestHash ContestHash)> contestHashes,
        ChainingField chainingField,
        ConfirmationCode confirmationCode,
        VotingDeviceInformationHash deviceInformationHash,
        EncryptionRecord encryptionRecord,
        ConfirmationCode? previousConfirmationCode)
    {
        // 16.C: HC = H(HI; 0x42, chi_1, ..., chi_mB, BC), contest hashes in contest index order.
        var expectedConfirmationCode = ConfirmationCode.ForPreEncryptedBallot(
            selectionEncryptionIdentifierHash,
            contestHashes.OrderBy(x => x.ContestIndex).Select(x => x.ContestHash),
            chainingField);
        if (expectedConfirmationCode != confirmationCode)
        {
            throw new VerificationFailedException("16.C", $"Confirmation code for ballot {ballotId} does not match its contest hashes and chaining field.");
        }

        // 16.D: HDI = H(HE; 0x43, S_device).
        var expectedDeviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(encryptionRecord.ExtendedBaseHash, deviceId);
        if (expectedDeviceHash != deviceInformationHash)
        {
            throw new VerificationFailedException("16.D", $"Device information hash for ballot {ballotId} does not match device {deviceId}.");
        }

        var chainingMode = encryptionRecord.Manifest.ChainingMode;
        var expectedChainingField = ChainingField.ForPreEncryptedBallots(chainingMode, deviceInformationHash, encryptionRecord.ExtendedBaseHash, previousConfirmationCode);
        if (chainingMode == ChainingMode.None && expectedChainingField != chainingField)
        {
            // 16.E: BC = 0x00000000 || HDI.
            throw new VerificationFailedException("16.E", $"Chaining field for ballot {ballotId} is not the no-chaining field of device {deviceId}.");
        }

        if (chainingMode == ChainingMode.Simple && expectedChainingField != chainingField)
        {
            // 16.F: BC,j = 0x00000001 || Hj-1, with H0 from (117) for the device's first ballot.
            throw new VerificationFailedException("16.F", $"Chaining field for ballot {ballotId} does not chain from the previous confirmation code on device {deviceId}.");
        }
    }

    /// <summary>
    /// The once-per-device part of Verification 16 for <paramref name="device"/>'s ordered list of
    /// pre-encrypted ballots, against <paramref name="ballots"/>, every pre-encrypted ballot of the
    /// record (or at least every one that names the device): "16.structure" unless the list accounts
    /// for exactly the ballots that name the device, each once; then 16.D, 16.G, 16.E/16.F for each
    /// ballot in list order, and 16.H. It does not recompute selection, contest or confirmation hashes:
    /// run <see cref="Verify"/> on every ballot as well.
    /// </summary>
    public void VerifyDevice(DeviceChainRecord device, IEnumerable<PreEncryptedBallot> ballots, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(ballots);
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        VerifyDevice(device, ballots.Select(DeviceChainLink.From), encryptionRecord);
    }

    /// <summary>
    /// <see cref="VerifyDevice(DeviceChainRecord, IEnumerable{PreEncryptedBallot}, EncryptionRecord)"/>
    /// over each ballot's id, device id, confirmation code and chaining field.
    /// </summary>
    public void VerifyDevice(DeviceChainRecord device, IEnumerable<DeviceChainLink> ballots, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(ballots);
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        var links = ballots.ToList();
        DeviceChainWalk.Verify(device, links, DeviceChainWalk.Index(links, DeviceChainWalk.PreEncrypted), encryptionRecord, DeviceChainWalk.PreEncrypted);
    }

    /// <summary>
    /// <see cref="VerifyDevice(DeviceChainRecord, IEnumerable{PreEncryptedBallot}, EncryptionRecord)"/> for every device, after checking ("16.structure") that no device has
    /// two lists and that every ballot names a device that has one.
    /// </summary>
    public void VerifyDevices(IEnumerable<DeviceChainRecord> devices, IEnumerable<PreEncryptedBallot> ballots, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        DeviceChainWalk.VerifyAll(devices, ballots.Select(DeviceChainLink.From), encryptionRecord, DeviceChainWalk.PreEncrypted);
    }

    /// <summary>
    /// <see cref="VerifyDevices(IEnumerable{DeviceChainRecord}, IEnumerable{PreEncryptedBallot}, EncryptionRecord)"/>
    /// over the record's pre-encrypted ballots as published (§4.4): the cast ones' records
    /// (<see cref="BallotEncryption.EncryptedBallot"/> with <see cref="BallotEncryption.EncryptedBallot.PreEncryptedContests"/>)
    /// and the uncast ones. A device's list names every ballot it printed, cast or not. A regular
    /// ballot among <paramref name="castBallots"/> is "16.structure".
    /// </summary>
    public void VerifyDevices(
        IEnumerable<DeviceChainRecord> devices,
        IEnumerable<BallotEncryption.EncryptedBallot> castBallots,
        IEnumerable<PreEncryptedUncastBallot> uncastBallots,
        EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(castBallots);
        ArgumentNullException.ThrowIfNull(uncastBallots);

        var links = castBallots.Select(ballot => ballot.IsPreEncrypted
                ? DeviceChainLink.From(ballot)
                : throw new VerificationFailedException("16.structure", $"Ballot {ballot.Id} is a regular ballot; it is not on any pre-encrypted ballot device's list."))
            .Concat(uncastBallots.Select(x => DeviceChainLink.From(x.Ballot)));
        DeviceChainWalk.VerifyAll(devices, links, encryptionRecord, DeviceChainWalk.PreEncrypted);
    }
}
