using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 8 (Validation of confirmation codes).
///
/// Per ballot (<see cref="Verify(EncryptedBallot, EncryptionRecord)"/>): 8.A (each contest hash),
/// 8.B (H_C recomputed from the contest hashes and the ballot's own chaining field B_C), and, under
/// no chaining, 8.D (B_C = 0x00000000 || H_DI of the device the ballot names). Under simple chaining
/// the per-ballot check only requires the mode identifier 0x00000001 (8.E); which H_{j-1} the field
/// must hold depends on the ballot's place in its device's chain.
///
/// Per device (<see cref="VerifyDevice(DeviceChainRecord, IEnumerable{EncryptedBallot}, EncryptionRecord)"/>
/// and <see cref="VerifyDevices(IEnumerable{DeviceChainRecord}, IEnumerable{EncryptedBallot}, EncryptionRecord)"/>):
/// the authoritative chain checks. 8.C (the recorded H_DI), 8.F (H_0), 8.D/8.E for every ballot in
/// the order of the device's published list (§3.7), so that reordered, dropped or spliced-in
/// ballots are detected, and 8.G (the chain close). See <see cref="DeviceChainWalk"/>.
///
/// <see cref="Verify(EncryptedBallot, VotingDeviceInformationHash, EncryptionRecord, ConfirmationCode?)"/>
/// checks one ballot against a caller-supplied device hash (8.C) and previous confirmation code
/// (8.E), for a caller that walks a chain itself.
///
/// Before S8 the ballot did not carry B_C, and 8.D/8.E compared two fields built from the same
/// inputs, so neither could fail (audit G37); a wrong chain position surfaced only as an 8.B
/// failure, and only when the caller supplied the right previous code.
/// </summary>
public class ConfirmationCodeVerification
{
    /// <summary>
    /// The per-ballot part of Verification 8: <see cref="BallotStructure"/> ("8.structure"), 8.A,
    /// 8.B over the ballot's own B_C, then 8.D under no chaining (H_DI computed from the ballot's
    /// device id) or, under simple chaining, the 0x00000001 mode identifier (8.E).
    /// </summary>
    public void Verify(EncryptedBallot ballot, EncryptionRecord encryptionRecord)
    {
        VerifyBallot(ballot, encryptionRecord, deviceInformationHash: null, checkPreviousConfirmationCode: false, previousConfirmationCode: null);
    }

    /// <summary>
    /// <see cref="Verify(EncryptedBallot, EncryptionRecord)"/>, plus 8.C (<paramref name="deviceInformationHash"/>
    /// is H(H_E; 0x2A, S_device) for the device the ballot names) and, under simple chaining, 8.E
    /// against <paramref name="previousConfirmationCode"/>: the confirmation code of the ballot
    /// processed before this one on the device, or null when this is the device's first ballot
    /// (B_C,1 = 0x00000001 || H_0). Under no chaining <paramref name="previousConfirmationCode"/> is
    /// ignored. A device's published chain is checked by
    /// <see cref="VerifyDevice(DeviceChainRecord, IEnumerable{EncryptedBallot}, EncryptionRecord)"/>.
    /// </summary>
    public void Verify(EncryptedBallot ballot, VotingDeviceInformationHash deviceInformationHash, EncryptionRecord encryptionRecord, ConfirmationCode? previousConfirmationCode)
    {
        VerifyBallot(ballot, encryptionRecord, deviceInformationHash, checkPreviousConfirmationCode: true, previousConfirmationCode);
    }

    private static void VerifyBallot(
        EncryptedBallot ballot,
        EncryptionRecord encryptionRecord,
        VotingDeviceInformationHash? deviceInformationHash,
        bool checkPreviousConfirmationCode,
        ConfirmationCode? previousConfirmationCode)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        // p.64: "Verification 8 is only used for regular ElectionGuard ballots. Confirmation codes
        // for pre-encrypted ballots must be validated with Verification 16." A cast pre-encrypted
        // ballot's contest hashes and confirmation code are eqs. (115)/(116), so 8.A/8.B would fail
        // it; it is refused here rather than reported as a wrong hash.
        if (ballot.IsPreEncrypted)
        {
            throw new VerificationFailedException("8.structure", $"Ballot {ballot.Id} is a cast pre-encrypted ballot; Verification 8 is only used for regular ballots, and its confirmation code is checked by Verification 16 (p.64).");
        }

        // The contest hashes recomputed below hash the manifest's contest indices. They are trusted
        // here because EncryptionRecord validated the manifest (§3.1.3) when it was built;
        // re-validating the whole manifest per ballot would cost O(manifest) each time.

        // Exactly the ballot style's contests and the manifest's options, each once, and a 36-byte
        // B_C, before anything else (see BallotStructure). Without it, a contest listed twice would
        // be hashed twice into a confirmation code that then matches, and the ballot would be
        // tallied twice.
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
                VerifiableFieldsInManifestOrder(contest, manifestContest),
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

        // 8.B: H_C = H(H_I; 0x29, chi_1, ..., chi_mB, B_C) over the chaining field the ballot
        // carries. Whether that is the right B_C for the ballot's device and chain position is
        // 8.D/8.E.
        var expectedConfirmationCode = new ConfirmationCode(ballot.SelectionEncryptionIdentifierHash, contestHashes, ballot.ChainingField);
        if (expectedConfirmationCode != ballot.ConfirmationCode)
        {
            throw new VerificationFailedException("8.B", $"Confirmation code for ballot {ballot.Id} does not match its contest hashes and chaining field.");
        }

        // 8.C: H_DI = H(H_E; 0x2A, S_device) for the device the ballot was processed on.
        var deviceHash = new VotingDeviceInformationHash(encryptionRecord.ExtendedBaseHash, ballot.DeviceId);
        if (deviceInformationHash is { } given && given != deviceHash)
        {
            throw new VerificationFailedException("8.C", $"The device information hash given for ballot {ballot.Id} is not H(H_E; 0x2A, S_device) for its device {ballot.DeviceId}.");
        }

        var chainingMode = encryptionRecord.Manifest.ChainingMode;
        if (chainingMode == ChainingMode.None)
        {
            // 8.D: B_C = 0x00000000 || H_DI.
            if (ballot.ChainingField != new ChainingField(ChainingMode.None, deviceHash, encryptionRecord.ExtendedBaseHash, null))
            {
                throw new VerificationFailedException("8.D", $"Ballot {ballot.Id} does not carry the no-chaining field B_C = 0x00000000 || H_DI of its device {ballot.DeviceId}.");
            }
        }
        else if (checkPreviousConfirmationCode)
        {
            // 8.E: B_C,j = 0x00000001 || H_{j-1}, with H_0 (eq. 74) for the device's first ballot.
            if (ballot.ChainingField != new ChainingField(chainingMode, deviceHash, encryptionRecord.ExtendedBaseHash, previousConfirmationCode))
            {
                throw new VerificationFailedException("8.E", $"Ballot {ballot.Id} does not carry B_C,j = 0x00000001 || H_(j-1) for the {(previousConfirmationCode is null ? "initial hash code H_0 of its device" : "previous confirmation code given")}.");
            }
        }
        else if (!((byte[])ballot.ChainingField).AsSpan(0, 4).SequenceEqual(((int)ChainingMode.Simple).ToByteArray()))
        {
            // 8.E's mode identifier 0x00000001 (the manifest's mode is None or Simple: Manifest.Validate
            // refuses any other). The hash it holds is checked in chain order by VerifyDevice.
            throw new VerificationFailedException("8.E", $"Ballot {ballot.Id} does not carry the simple chaining mode identifier 0x00000001 in its chaining field.");
        }
    }

    /// <summary>
    /// Every verifiable field of the contest in manifest option-index order (eq. 70): its selections,
    /// then its supplemental fields, each list as stored when it is already in manifest order and
    /// sorted otherwise. (BallotStructure has already required exactly the manifest's options and
    /// declared fields, each once; an unknown label would sort last.)
    /// </summary>
    private static List<EncryptedValueWithProofs> VerifiableFieldsInManifestOrder(EncryptedContest contest, Contest manifestContest)
    {
        var choices = contest.Choices;
        var fields = contest.SupplementalFields;
        var ordered = new List<EncryptedValueWithProofs>(choices.Count + fields.Count);

        bool choicesInOrder = choices.Count == manifestContest.Choices.Count;
        for (int i = 0; choicesInOrder && i < choices.Count; i++)
        {
            choicesInOrder = choices[i].ChoiceId == manifestContest.Choices[i].Id;
        }

        ordered.AddRange(choicesInOrder
            ? choices
            : choices.OrderBy(choice => manifestContest.Choices.FirstOrDefault(x => x.Id == choice.ChoiceId)?.Index ?? int.MaxValue));

        var declared = manifestContest.SupplementalFields;
        bool fieldsInOrder = fields.Count == declared.Count;
        for (int i = 0; fieldsInOrder && i < fields.Count; i++)
        {
            fieldsInOrder = fields[i].FieldId == declared[i].Id;
        }

        ordered.AddRange(fieldsInOrder
            ? fields
            : fields.OrderBy(field => declared.FirstOrDefault(x => x.Id == field.FieldId)?.Index ?? int.MaxValue));

        return ordered;
    }

    /// <summary>
    /// The once-per-device part of Verification 8 for <paramref name="device"/>'s published ordered
    /// list (§3.7), against <paramref name="ballots"/>, every ballot of the record (or at least every
    /// ballot that names the device): "8.structure" unless the list accounts for exactly the ballots
    /// that name the device, each once; then 8.C, 8.F, 8.D/8.E for each ballot in list order, and
    /// 8.G. It does not recompute contest hashes or confirmation codes: run
    /// <see cref="Verify(EncryptedBallot, EncryptionRecord)"/> on every ballot as well.
    /// </summary>
    public void VerifyDevice(DeviceChainRecord device, IEnumerable<EncryptedBallot> ballots, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        VerifyDevice(device, ballots.Select(DeviceChainLink.From), encryptionRecord);
    }

    /// <summary>
    /// <see cref="VerifyDevice(DeviceChainRecord, IEnumerable{EncryptedBallot}, EncryptionRecord)"/>
    /// over each ballot's id, device id, confirmation code and chaining field, so that a caller that
    /// streams the ballots need not keep them.
    /// </summary>
    public void VerifyDevice(DeviceChainRecord device, IEnumerable<DeviceChainLink> ballots, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(ballots);
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        var links = ballots.ToList();
        DeviceChainWalk.Verify(device, links, DeviceChainWalk.Index(links, DeviceChainWalk.Encrypted), encryptionRecord, DeviceChainWalk.Encrypted);
    }

    /// <summary>
    /// <see cref="VerifyDevice(DeviceChainRecord, IEnumerable{EncryptedBallot}, EncryptionRecord)"/> for
    /// every device, after checking ("8.structure") that no device has two lists and that every
    /// ballot names a device that has one, so that every ballot of the record is in exactly one list.
    /// </summary>
    public void VerifyDevices(IEnumerable<DeviceChainRecord> devices, IEnumerable<EncryptedBallot> ballots, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        VerifyDevices(devices, ballots.Select(DeviceChainLink.From), encryptionRecord);
    }

    /// <summary>
    /// <see cref="VerifyDevices(IEnumerable{DeviceChainRecord}, IEnumerable{EncryptedBallot}, EncryptionRecord)"/>
    /// over chain links.
    /// </summary>
    public void VerifyDevices(IEnumerable<DeviceChainRecord> devices, IEnumerable<DeviceChainLink> ballots, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        DeviceChainWalk.VerifyAll(devices, ballots, encryptionRecord, DeviceChainWalk.Encrypted);
    }
}
