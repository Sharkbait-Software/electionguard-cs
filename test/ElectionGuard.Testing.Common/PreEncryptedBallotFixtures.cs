using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;

namespace ElectionGuard.Testing.Common;

/// <summary>
/// Test-only stand-ins for the §4.2 encrypting tool and the §4.3 recording tool, which this library
/// does not implement (user decision Q35: it implements the primitives of pre-encryption and its
/// verifications only). They build the pre-encrypted ballots and the cast and uncast records that the
/// verification, known-answer and serializer tests need, from the public primitives in
/// <see cref="PreEncryptionPrimitives"/> and the public hash and chaining types. They are not a
/// reference tool: they obtain ξ_B from the caller (no guardian decrypts a pre-encrypted ballot's
/// nonce here), check nothing a real tool would have to (who asks, how often), and make the choices
/// the library's verifications expect (exactly L combined vectors per contest, an undervote padded
/// with the contest's first null vectors, decision Q27; values 0/1).
/// </summary>
public static class PreEncryptedBallotFixtures
{
    /// <summary>
    /// The prover of one combined contest: the signature of
    /// <see cref="PreEncryptionPrimitives.ProveCombinedContest"/>, which is the default. The
    /// known-answer tests pass one that reaches the library's internal proof-nonce seam.
    /// </summary>
    public delegate EncryptedContest CombinedContestProver(
        ElectionPublicKeys electionPublicKeys,
        Contest contest,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        IReadOnlyList<EncryptedValue> combined,
        IReadOnlyList<int> selections,
        ContestHash contestHash);

    /// <summary>
    /// The pre-encrypted ballot that <paramref name="selectionEncryptionIdentifier"/> and
    /// <paramref name="ballotNonce"/> determine (§4.2): every contest of the ballot style
    /// (<see cref="PreEncryptionPrimitives.GenerateContests"/>), ξ_B encrypted to K-hat (§3.3.4,
    /// with fresh randomness), and the confirmation code of eq. (116) over the device's pre-encrypted
    /// chaining field (eqs. 117-119) after <paramref name="previousConfirmationCode"/> (null for the
    /// device's first ballot or under no chaining). Short codes are not checked for uniqueness.
    /// </summary>
    public static PreEncryptedBallot PreEncrypt(
        EncryptionRecord encryptionRecord,
        string deviceId,
        string ballotId,
        string ballotStyleId,
        SelectionEncryptionIdentifier selectionEncryptionIdentifier,
        BallotNonce ballotNonce,
        ConfirmationCode? previousConfirmationCode)
    {
        var selectionHash = new SelectionEncryptionIdentifierHash(encryptionRecord.ExtendedBaseHash, selectionEncryptionIdentifier);
        var contests = PreEncryptionPrimitives.GenerateContests(encryptionRecord, ballotStyleId, selectionHash, ballotNonce);
        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(encryptionRecord.ExtendedBaseHash, deviceId);
        var chainingField = ChainingField.ForPreEncryptedBallots(encryptionRecord.Manifest.ChainingMode, deviceHash, encryptionRecord.ExtendedBaseHash, previousConfirmationCode);

        return new PreEncryptedBallot
        {
            Id = ballotId,
            BallotStyleId = ballotStyleId,
            SelectionEncryptionIdentifier = selectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = selectionHash,
            EncryptedBallotNonce = BallotNonceEncryption.Encrypt(ballotNonce, selectionHash, encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey),
            Contests = contests,
            ChainingField = chainingField,
            ConfirmationCode = ConfirmationCode.ForPreEncryptedBallot(selectionHash, contests.Select(x => x.ContestHash), chainingField),
            DeviceId = deviceId,
        };
    }

    /// <summary>
    /// A pre-encrypted ballot with fresh random id_B and ξ_B, drawn again until the short codes within
    /// every contest are unique (§4.1.5, <see cref="PreEncryptionPrimitives.HasUniqueShortCodes"/>),
    /// and the ξ_B it was made from.
    /// </summary>
    public static (PreEncryptedBallot Ballot, BallotNonce BallotNonce) PreEncrypt(
        EncryptionRecord encryptionRecord,
        string deviceId,
        string ballotId,
        string ballotStyleId,
        ConfirmationCode? previousConfirmationCode,
        int maxAttempts = 100)
    {
        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            var ballotNonce = new BallotNonce(ElectionGuardRandom.GetBytes(32));
            var ballot = PreEncrypt(encryptionRecord, deviceId, ballotId, ballotStyleId,
                new SelectionEncryptionIdentifier(ElectionGuardRandom.GetBytes(32)), ballotNonce, previousConfirmationCode);
            if (ballot.Contests.All(PreEncryptionPrimitives.HasUniqueShortCodes))
            {
                return (ballot, ballotNonce);
            }
        }

        throw new InvalidOperationException($"Could not generate a pre-encrypted ballot with unique short codes within each contest in {maxAttempts} attempts.");
    }

    /// <summary>
    /// <see cref="PreEncrypt(EncryptionRecord, string, string, string, ConfirmationCode?, int)"/> as the
    /// next ballot of the pre-encrypted device <paramref name="chain"/> (§4.1.4), appended to it.
    /// </summary>
    public static (PreEncryptedBallot Ballot, BallotNonce BallotNonce) PreEncryptNext(
        EncryptionRecord encryptionRecord,
        string ballotId,
        string ballotStyleId,
        DeviceChain chain)
    {
        var result = PreEncrypt(encryptionRecord, chain.DeviceId, ballotId, ballotStyleId, chain.PreviousConfirmationCode);
        chain.Append(result.Ballot);
        return result;
    }

    /// <summary>
    /// The record of <paramref name="ballot"/> cast with <paramref name="selections"/> (§4.3, §4.4):
    /// per contest, the vectors of the selected options (value 1; an option left out or 0 is not
    /// selected) padded with the contest's first null vectors to exactly L, combined
    /// (<see cref="PreEncryptionPrimitives.Combine"/>) and proved
    /// (<paramref name="prover"/>, by default <see cref="PreEncryptionPrimitives.ProveCombinedContest"/>);
    /// the eq. (115) contest hashes, the eq. (116) confirmation code, B_C and C_ξB of the ballot; status
    /// cast, weight 1; and per contest the sorted m + L selection hashes and the selected vectors
    /// ((α, β) only) sorted by hash, with their short codes. Throws
    /// <see cref="InvalidOperationException"/> if <paramref name="ballotNonce"/> does not regenerate the
    /// ballot.
    /// </summary>
    public static EncryptedBallot RecordCast(
        EncryptionRecord encryptionRecord,
        PreEncryptedBallot ballot,
        BallotNonce ballotNonce,
        Ballot selections,
        CombinedContestProver? prover = null)
    {
        prover ??= PreEncryptionPrimitives.ProveCombinedContest;
        var regenerated = Regenerate(encryptionRecord, ballot, ballotNonce);
        var manifest = encryptionRecord.Manifest;

        var contests = new List<EncryptedContest>(regenerated.Count);
        var preEncryptedContests = new List<PreEncryptedCastContest>(regenerated.Count);
        foreach (var contest in regenerated)
        {
            var manifestContest = manifest.Contests.Single(x => x.Id == contest.ContestId);
            var options = manifestContest.Choices.OrderBy(x => x.Index).ToList();
            var chosenOptions = selections.Contests.SingleOrDefault(x => x.Id == contest.ContestId)?.Choices
                .Where(x => x.SelectionValue == 1)
                .Select(x => x.Id)
                .ToHashSet(StringComparer.Ordinal) ?? [];

            // §4.3: the vectors of the selected options, then the first null vectors up to L.
            var chosen = contest.Selections.Where(x => x.ChoiceId is string id && chosenOptions.Contains(id)).ToList();
            chosen.AddRange(contest.Selections.Where(x => x.IsNullVote).Take(manifestContest.SelectionLimit - chosen.Count));

            var combined = PreEncryptionPrimitives.Combine(chosen);
            var values = options.Select(x => chosenOptions.Contains(x.Id) ? 1 : 0).ToList();
            contests.Add(prover(encryptionRecord.ElectionPublicKeys, manifestContest, ballot.SelectionEncryptionIdentifierHash, combined, values, contest.ContestHash));

            preEncryptedContests.Add(new PreEncryptedCastContest
            {
                ContestId = contest.ContestId,
                SelectionHashes = contest.Selections.Select(x => x.SelectionHash).Order().ToList(),
                SelectedVectors = chosen
                    .OrderBy(x => x.SelectionHash)
                    .Select(x => new PreEncryptedCastSelection
                    {
                        // The published vector: (α, β) only, never the nonces.
                        Vector = x.Vector.Select(e => new EncryptedValue { Alpha = e.Alpha, Beta = e.Beta }).ToList(),
                        SelectionHash = x.SelectionHash,
                        ShortCode = x.ShortCode,
                    })
                    .ToList(),
            });
        }

        return new EncryptedBallot
        {
            Id = ballot.Id,
            BallotStyleId = ballot.BallotStyleId,
            DeviceId = ballot.DeviceId,
            SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
            Contests = contests,
            ConfirmationCode = ballot.ConfirmationCode,
            ChainingField = ballot.ChainingField,
            EncryptedBallotNonce = ballot.EncryptedBallotNonce,
            Weight = 1,
            Status = BallotStatus.Cast,
            PreEncryptedContests = preEncryptedContests,
        };
    }

    /// <summary>
    /// The record of <paramref name="ballot"/> left uncast (§4.3, §4.4): the ballot, the eq. (121)
    /// nonces ξ_{i,j,k} of every encryption on it, and ξ_B only when
    /// <paramref name="releaseBallotNonce"/>. Throws <see cref="InvalidOperationException"/> if
    /// <paramref name="ballotNonce"/> does not regenerate the ballot.
    /// </summary>
    public static PreEncryptedUncastBallot RecordUncast(
        EncryptionRecord encryptionRecord,
        PreEncryptedBallot ballot,
        BallotNonce ballotNonce,
        bool releaseBallotNonce = false)
    {
        var regenerated = Regenerate(encryptionRecord, ballot, ballotNonce).ToDictionary(x => x.ContestId);

        return new PreEncryptedUncastBallot
        {
            Ballot = ballot,
            BallotNonce = releaseBallotNonce ? new BallotNonce(ballotNonce.ToByteArray().ToArray()) : null,
            Contests = ballot.Contests.Select(contest => new PreEncryptedReleasedContest
            {
                ContestId = contest.ContestId,
                Selections = contest.Selections.Select(selection => new PreEncryptedReleasedSelection
                {
                    SelectionIndex = selection.SelectionIndex,
                    Nonces = regenerated[contest.ContestId].Selections
                        .Single(x => x.SelectionIndex == selection.SelectionIndex)
                        .Vector.Select(x => x.EncryptionNonce!.Value).ToList(),
                }).ToList(),
            }).ToList(),
        };
    }

    /// <summary>
    /// The ballot's contests regenerated from ξ_B (eq. 121), with their nonces, after checking that
    /// they are the ballot's (every vector, hash, label and short code, every contest hash, and the
    /// confirmation code over the ballot's own B_C), so a test cannot record a ballot under a wrong ξ_B
    /// by mistake.
    /// </summary>
    private static List<PreEncryptedContest> Regenerate(EncryptionRecord encryptionRecord, PreEncryptedBallot ballot, BallotNonce ballotNonce)
    {
        var regenerated = PreEncryptionPrimitives.GenerateContests(encryptionRecord, ballot.BallotStyleId, ballot.SelectionEncryptionIdentifierHash, ballotNonce);
        bool matches = regenerated.Count == ballot.Contests.Count
            && regenerated.Zip(ballot.Contests).All(pair =>
                pair.First.ContestId == pair.Second.ContestId
                && pair.First.ContestHash == pair.Second.ContestHash
                && pair.First.Selections.Count == pair.Second.Selections.Count
                && pair.First.Selections.Zip(pair.Second.Selections).All(s =>
                    s.First.SelectionIndex == s.Second.SelectionIndex
                    && s.First.ChoiceId == s.Second.ChoiceId
                    && s.First.SelectionHash == s.Second.SelectionHash
                    && s.First.ShortCode == s.Second.ShortCode
                    && s.First.Vector.Select(x => (x.Alpha, x.Beta)).SequenceEqual(s.Second.Vector.Select(x => (x.Alpha, x.Beta)))))
            && ConfirmationCode.ForPreEncryptedBallot(ballot.SelectionEncryptionIdentifierHash, regenerated.Select(x => x.ContestHash), ballot.ChainingField) == ballot.ConfirmationCode;

        return matches
            ? regenerated
            : throw new InvalidOperationException($"The ballot nonce does not regenerate pre-encrypted ballot {ballot.Id} (eq. 121).");
    }
}
