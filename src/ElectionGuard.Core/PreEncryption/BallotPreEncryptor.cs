using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.PreEncryption;

/// <summary>
/// §4.2 The Ballot Encrypting Tool for pre-encrypted ballots, together with the short-code duties
/// §4.2.2 gives its caller: applying the manifest's hash-trimming function Ω to every selection hash
/// and discarding any ballot whose short codes repeat within a contest.
///
/// Every value on the ballot is derived deterministically from the selection encryption identifier
/// idB and the ballot nonce ξB (§4.2.1), so the recording tool can regenerate the encryptions once
/// the ballot nonce has been decrypted. The only randomness beyond those two seeds is in the
/// encryption of ξB itself (§3.3.4).
/// </summary>
public class BallotPreEncryptor
{
    public BallotPreEncryptor(EncryptionRecord encryptionRecord, string deviceId)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);
        ArgumentNullException.ThrowIfNull(deviceId);

        var manifest = encryptionRecord.Manifest;

        // §3.1.3: every nonce and selection hash below hashes the manifest's contest and option indices.
        manifest.Validate();

        _hashTrimmingFunction = manifest.HashTrimmingFunction
            ?? throw new ArgumentException("The manifest does not specify a hash-trimming function, so it does not support pre-encrypted ballots (§4.1.5).", nameof(encryptionRecord));

        // §4.1.5 requires the short codes within a contest to be unique. A contest with more vectors
        // than Ω has codes can never satisfy that, and retrying would never end.
        int codeSpaceSize = HashTrimming.CodeSpaceSize(_hashTrimmingFunction);
        foreach (var contest in manifest.Contests)
        {
            int vectors = contest.Choices.Count + contest.SelectionLimit;
            if (vectors > codeSpaceSize)
            {
                throw new ArgumentException(
                    $"Contest {contest.Id} needs {vectors} distinct short codes but hash-trimming function {_hashTrimmingFunction} has only {codeSpaceSize}.",
                    nameof(encryptionRecord));
            }
        }

        _encryptionRecord = encryptionRecord;
        _deviceId = deviceId;
        _deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(encryptionRecord.ExtendedBaseHash, deviceId);
    }

    private readonly EncryptionRecord _encryptionRecord;
    private readonly string _deviceId;
    private readonly VotingDeviceInformationHash _deviceHash;
    private readonly HashTrimmingFunction _hashTrimmingFunction;

    /// <summary>
    /// Generates a pre-encrypted ballot for the ballot style with fresh random idB and ξB, drawing
    /// again whenever two short codes within a contest collide (§4.2.2).
    /// </summary>
    /// <param name="previousConfirmationCode">The previous ballot's confirmation code on this device
    /// under simple chaining, or null for the device's first ballot or when chaining is not used.</param>
    /// <param name="maxAttempts">How many ballots to generate before giving up on unique short codes.</param>
    public PreEncryptedBallot PreEncrypt(string ballotId, string ballotStyleId, ConfirmationCode? previousConfirmationCode, int maxAttempts = 100)
    {
        return GenerateWithUniqueShortCodes(maxAttempts, () => PreEncrypt(
            ballotId,
            ballotStyleId,
            new SelectionEncryptionIdentifier(ElectionGuardRandom.GetBytes(32)),
            new BallotNonce(ElectionGuardRandom.GetBytes(32)),
            previousConfirmationCode));
    }

    /// <summary>
    /// §4.2.2: discard generated ballots until one has unique short codes within every contest.
    /// </summary>
    internal static PreEncryptedBallot GenerateWithUniqueShortCodes(int maxAttempts, Func<PreEncryptedBallot> generate)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxAttempts, 1);

        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            var ballot = generate();
            if (HasUniqueShortCodesPerContest(ballot))
            {
                return ballot;
            }
        }

        throw new InvalidOperationException(
            $"Could not generate a pre-encrypted ballot with unique short codes within each contest in {maxAttempts} attempts.");
    }

    /// <summary>
    /// The encrypting tool proper: the pre-encrypted ballot determined by idB and ξB, without any
    /// check of its short codes.
    /// </summary>
    internal PreEncryptedBallot PreEncrypt(
        string ballotId,
        string ballotStyleId,
        SelectionEncryptionIdentifier selectionEncryptionIdentifier,
        BallotNonce ballotNonce,
        ConfirmationCode? previousConfirmationCode)
    {
        var manifest = _encryptionRecord.Manifest;
        var ballotStyle = manifest.BallotStyles.SingleOrDefault(x => x.Id == ballotStyleId)
            ?? throw new ArgumentException($"Could not find ballot style with id {ballotStyleId} in manifest.", nameof(ballotStyleId));

        var selectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(_encryptionRecord.ExtendedBaseHash, selectionEncryptionIdentifier);
        var encryptedBallotNonce = BallotNonceEncryption.Encrypt(ballotNonce, selectionEncryptionIdentifierHash, _encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey);

        // §4.1.3: contest hashes enter the confirmation code in the order of their contest indices.
        var contests = ballotStyle.ContestIds
            .Select(contestId => manifest.Contests.SingleOrDefault(x => x.Id == contestId)
                ?? throw new ArgumentException($"Ballot style {ballotStyleId} lists contest {contestId}, which is not in the manifest.", nameof(ballotStyleId)))
            .OrderBy(x => x.Index)
            .Select(contest => PreEncryptContest(contest, selectionEncryptionIdentifierHash, ballotNonce))
            .ToList();

        var chainingField = ChainingField.ForPreEncryptedBallots(manifest.ChainingMode, _deviceHash, _encryptionRecord.ExtendedBaseHash, previousConfirmationCode);
        var confirmationCode = ConfirmationCode.ForPreEncryptedBallot(selectionEncryptionIdentifierHash, contests.Select(x => x.ContestHash), chainingField);

        return new PreEncryptedBallot
        {
            Id = ballotId,
            BallotStyleId = ballotStyleId,
            SelectionEncryptionIdentifier = selectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = selectionEncryptionIdentifierHash,
            EncryptedBallotNonce = encryptedBallotNonce,
            Contests = contests,
            ChainingField = chainingField,
            ConfirmationCode = confirmationCode,
            DeviceId = _deviceId,
        };
    }

    /// <summary>§4.1.5: the short codes within each contest must be unique.</summary>
    internal static bool HasUniqueShortCodesPerContest(PreEncryptedBallot ballot)
    {
        return ballot.Contests.All(contest =>
            contest.Selections.Select(x => x.ShortCode).Distinct().Count() == contest.Selections.Count);
    }

    private PreEncryptedContest PreEncryptContest(Contest contest, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce)
    {
        // §4.1: vector positions follow the option indices in increasing order. The index k of
        // eq. (121) is the option index at a position, the same index space as j, so that a vector
        // encrypts a one exactly where j = k.
        var options = contest.Choices.OrderBy(x => x.Index).ToList();
        var positions = options.Select(x => x.Index).ToList();

        var selections = options
            .Select(option => PreEncryptSelection(contest.Index, option.Index, option.Id, positions, selectionEncryptionIdentifierHash, ballotNonce))
            .ToList();

        // §4.1.1/§4.1.5: one null vector per unit of the selection limit. The manifest has no
        // labels for them, so their indices extend the option indices (§4.2.1) past the largest.
        int largestOptionIndex = positions.Max();
        for (int nullVector = 1; nullVector <= contest.SelectionLimit; nullVector++)
        {
            selections.Add(PreEncryptSelection(contest.Index, largestOptionIndex + nullVector, null, positions, selectionEncryptionIdentifierHash, ballotNonce));
        }

        return new PreEncryptedContest
        {
            ContestId = contest.Id,
            ContestIndex = contest.Index,
            Selections = selections,
            ContestHash = ContestHash.ForPreEncryptedContest(selectionEncryptionIdentifierHash, contest.Index, selections.Select(x => x.SelectionHash)),
        };
    }

    private PreEncryptedSelection PreEncryptSelection(
        int contestIndex,
        int selectionIndex,
        string? choiceId,
        List<int> positions,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        BallotNonce ballotNonce)
    {
        var vector = positions
            .Select(position => Encrypt(position == selectionIndex ? 1 : 0, selectionEncryptionIdentifierHash, ballotNonce, contestIndex, selectionIndex, position))
            .ToList();
        var selectionHash = new SelectionHash(selectionEncryptionIdentifierHash, vector);

        return new PreEncryptedSelection
        {
            SelectionIndex = selectionIndex,
            ChoiceId = choiceId,
            Vector = vector,
            SelectionHash = selectionHash,
            ShortCode = HashTrimming.Trim(_hashTrimmingFunction, selectionHash),
        };
    }

    private EncryptedValue Encrypt(int value, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce, int contestIndex, int selectionIndex, int positionIndex)
    {
        IntegerModQ nonce = new PreEncryptionNonce(selectionEncryptionIdentifierHash, ballotNonce, contestIndex, selectionIndex, positionIndex);
        return new EncryptedValue
        {
            Alpha = MontgomeryModP.PowModP(EGParameters.G, nonce),
            Beta = MontgomeryModP.PowModP(_encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, nonce + value),
            EncryptionNonce = nonce,
        };
    }
}
