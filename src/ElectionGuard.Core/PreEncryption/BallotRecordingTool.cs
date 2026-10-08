using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Verify;

namespace ElectionGuard.Core.PreEncryption;

/// <summary>
/// §4.3 The Ballot Recording Tool for pre-encrypted ballots, together with the duties §4.3.1 gives
/// its wrapper (short codes, and what is posted to the election record).
///
/// It receives the pre-encrypted ballot as the encrypting tool produced it (§4.2: its ballot style,
/// id_B, chaining field and confirmation code, which ξ_B alone does not determine), the decrypted
/// ballot nonce ξ_B (obtained from the guardians with
/// <see cref="Tally.TallyAdmin.DecryptPreEncryptedBallotNonce"/>, or from a local database, §4.3.1),
/// and, for a cast ballot, the voter's selections. It regenerates every encryption on the ballot
/// from ξ_B (eq. 121) and refuses to go on unless the regenerated ballot is exactly the given one:
/// otherwise a wrong ξ_B would yield proofs about other ciphertexts than the ones the voter's short
/// codes name.
///
/// <list type="bullet">
/// <item><see cref="RecordCast"/>: "isolates the pre-encryptions corresponding to the selections
/// made by the voter", combines them "by componentwise multiplication (modulo p)" with the derived
/// nonces "added (modulo q)", and proves the combined vector as standard ElectionGuard does
/// (§3.3.7): each component with the range proof of eq. (59) over 0..R, the contest with the
/// selection-limit proof of eq. (62) over 0..L, keyed with the ballot's H_I. The result is a
/// standard <see cref="EncryptedBallot"/> that tallies with regular ballots, carrying the §4.4
/// pre-encryption data in <see cref="EncryptedBallot.PreEncryptedContests"/>.</item>
/// <item><see cref="RecordUncast"/>: returns "the encryption nonces that enable the encryptions to
/// be opened and checked" (Verification 18).</item>
/// </list>
///
/// Choices the spec leaves open (S9; see the tracker):
/// <list type="bullet">
/// <item>The tool always combines exactly L vectors: the selected options' vectors, padded with the
/// contest's first null vectors, so that the published short codes never show an undervote
/// (§4.1.5, §4.4 "including null options"). The KAT oracle does the same.</item>
/// <item>A pre-encrypted ballot has one vector per option, so a selection is 0 or 1. More than L
/// selections in a contest (an overvote) is refused: the spec does not say how a recording tool
/// records one, and with no supplemental fields (refused by <see cref="Manifest.Validate"/>) an
/// overvote could not be published as such.</item>
/// </list>
///
/// Privacy: whoever holds ξ_B of a cast ballot can link its published selected vectors to options,
/// so the tool's caller learns the vote, as §4.3 intends (the tool is given the selections). The
/// combined nonces are never written by a serializer (<see cref="EncryptedValue.EncryptionNonce"/>
/// is not serialized), and a cast record names no option for any selected vector.
/// </summary>
public class BallotRecordingTool
{
    public BallotRecordingTool(EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        // §3.1.3: every nonce, hash and proof below hashes the manifest's contest and option indices.
        encryptionRecord.Manifest.Validate();

        _hashTrimmingFunction = encryptionRecord.Manifest.HashTrimmingFunction
            ?? throw new ArgumentException("The manifest does not specify a hash-trimming function, so it does not support pre-encrypted ballots (§4.1.5).", nameof(encryptionRecord));
        _encryptionRecord = encryptionRecord;
    }

    private readonly EncryptionRecord _encryptionRecord;
    private readonly HashTrimmingFunction _hashTrimmingFunction;

    /// <summary>
    /// Test seam: supplies, for the proof of contest index i, option index (null for the contest's
    /// selection-limit proof) and commitment j, the proof nonce u_j and the simulated challenge c_j
    /// in place of fresh random values (see <see cref="BallotEncryptor.GenerateProofs"/>). Lets the
    /// known-answer tests reproduce the oracle's proofs. Null outside tests.
    /// </summary>
    internal Func<int, int?, int, (IntegerModQ U, IntegerModQ C)>? ProofNoncesForTesting { get; set; }

    /// <summary>
    /// Records <paramref name="ballot"/> as cast with the voter's <paramref name="selections"/>
    /// (§4.3): a plaintext ballot of the same ballot style listing each of its contests once, each
    /// option at most once with a value of 0 or 1 (an option it leaves out is not selected), no
    /// write-ins and no contest data, and at most L selections per contest. Throws
    /// <see cref="ArgumentException"/> if the selections break any of that, if the ballot is
    /// malformed or keyed with an H_I that is not H(H_E; 0x20, id_B), or if
    /// <paramref name="ballotNonce"/> does not regenerate it exactly.
    ///
    /// Returns the cast ballot's record (§4.4), with <see cref="EncryptedBallot.Status"/> cast and
    /// weight 1: the combined vector of every contest with its proofs, the eq. (115) contest hashes
    /// and the eq. (116) confirmation code and chaining field of the pre-encrypted ballot, its
    /// encrypted ballot nonce, and per contest the sorted selection hashes and the selected vectors
    /// with their short codes. It does not modify <paramref name="selections"/>.
    /// </summary>
    public EncryptedBallot RecordCast(PreEncryptedBallot ballot, BallotNonce ballotNonce, Ballot selections)
    {
        ArgumentNullException.ThrowIfNull(selections);
        var regenerated = Regenerate(ballot, ballotNonce);
        var selected = ReadSelections(ballot, selections);
        var manifest = _encryptionRecord.Manifest;
        var keys = _encryptionRecord.ElectionPublicKeys;
        var selectionHash = ballot.SelectionEncryptionIdentifierHash;

        var contests = new List<EncryptedContest>(regenerated.Count);
        var preEncryptedContests = new List<PreEncryptedCastContest>(regenerated.Count);
        foreach (var contest in regenerated)
        {
            var manifestContest = manifest.Contests.Single(x => x.Id == contest.ContestId);
            var options = manifestContest.Choices;
            int m = options.Count;
            int limit = manifestContest.SelectionLimit;
            var chosenOptions = selected[contest.ContestId];

            // §4.3: the vectors of the selected options, then the first null vectors up to L.
            var chosen = contest.Selections.Where(x => x.ChoiceId is string id && chosenOptions.Contains(id)).ToList();
            chosen.AddRange(contest.Selections.Where(x => x.IsNullVote).Take(limit - chosen.Count));

            // Componentwise product of the chosen vectors, nonces summed mod q.
            var choices = new List<EncryptedSelection>(m);
            IntegerModP totalAlpha = 1;
            IntegerModP totalBeta = 1;
            IntegerModQ totalNonce = 0;
            for (int k = 0; k < m; k++)
            {
                IntegerModP alpha = 1;
                IntegerModP beta = 1;
                IntegerModQ nonce = 0;
                foreach (var vector in chosen)
                {
                    alpha *= vector.Vector[k].Alpha;
                    beta *= vector.Vector[k].Beta;
                    nonce += vector.Vector[k].EncryptionNonce!.Value;
                }

                var option = options[k];
                int value = chosenOptions.Contains(option.Id) ? 1 : 0;
                var combined = new EncryptedValue { Alpha = alpha, Beta = beta, EncryptionNonce = nonce };

                // §3.3.7 eq. (59): a range proof over 0..R for each component (Verification 6
                // "using the appropriate option selection limits", p.64). A component is 0 or 1.
                var proofs = BallotEncryptor.GenerateProofs(value, 0, manifestContest.OptionSelectionLimit, combined, keys, selectionHash, manifestContest.Index, option.Index,
                    proofNoncesForTesting: ProofNonces(manifestContest.Index, option.Index));
                choices.Add(new EncryptedSelection
                {
                    ChoiceId = option.Id,
                    Alpha = alpha,
                    Beta = beta,
                    EncryptionNonce = nonce,
                    Proofs = proofs,
                });

                totalAlpha *= alpha;
                totalBeta *= beta;
                totalNonce += nonce;
            }

            // §3.3.8 eq. (62): the selection-limit proof over 0..L of the product of the components.
            var total = new EncryptedValue { Alpha = totalAlpha, Beta = totalBeta, EncryptionNonce = totalNonce };
            var limitProofs = BallotEncryptor.GenerateProofs(chosenOptions.Count, 0, limit, total, keys, selectionHash, manifestContest.Index, optionIndex: null,
                proofNoncesForTesting: ProofNonces(manifestContest.Index, null));

            contests.Add(new EncryptedContest
            {
                Id = contest.ContestId,
                Choices = choices,
                SupplementalFields = [],
                Proofs = limitProofs,
                ContestData = null,
                ContestHash = contest.ContestHash,
            });

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
    /// Records <paramref name="ballot"/> as uncast (§4.3): the record publishes the whole ballot and
    /// the encryption nonces ξ_{i,j,k} (eq. 121) of every encryption on it, and, when
    /// <paramref name="releaseBallotNonce"/>, ξ_B itself (§4.4; see <see cref="PreEncryptedUncastBallot"/>).
    /// Throws <see cref="ArgumentException"/> as <see cref="RecordCast"/> does if the ballot is
    /// malformed or <paramref name="ballotNonce"/> does not regenerate it.
    /// </summary>
    public PreEncryptedUncastBallot RecordUncast(PreEncryptedBallot ballot, BallotNonce ballotNonce, bool releaseBallotNonce = false)
    {
        var regenerated = Regenerate(ballot, ballotNonce).ToDictionary(x => x.ContestId);

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

    private Func<int, (IntegerModQ U, IntegerModQ C)>? ProofNonces(int contestIndex, int? optionIndex)
    {
        var seam = ProofNoncesForTesting;
        return seam is null ? null : j => seam(contestIndex, optionIndex, j);
    }

    /// <summary>
    /// §4.3 "uses the ballot nonce ξB to regenerate all of the encryptions on the ballot": the ballot's
    /// contests as ξ_B determines them, after checking that the given ballot is well formed, keyed
    /// with H_I = H(H_E; 0x20, id_B), and exactly what ξ_B regenerates (every encryption, selection
    /// hash, label, short code and contest hash, and the confirmation code over the ballot's own
    /// chaining field).
    /// </summary>
    private List<PreEncryptedContest> Regenerate(PreEncryptedBallot ballot, BallotNonce ballotNonce)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        if (ballotNonce.ToByteArray() is not { Length: BallotNonceEncryption.NonceBytes })
        {
            throw new ArgumentException($"A ballot nonce ξ_B is {BallotNonceEncryption.NonceBytes} bytes.", nameof(ballotNonce));
        }

        if (BallotStructure.FindViolation(ballot, _encryptionRecord.Manifest) is string violation)
        {
            throw new ArgumentException($"Pre-encrypted ballot {ballot.Id} is malformed: {violation}", nameof(ballot));
        }

        var selectionHash = new SelectionEncryptionIdentifierHash(_encryptionRecord.ExtendedBaseHash, ballot.SelectionEncryptionIdentifier);
        if (!((byte[])selectionHash).AsSpan().SequenceEqual((byte[])ballot.SelectionEncryptionIdentifierHash))
        {
            throw new ArgumentException($"Pre-encrypted ballot {ballot.Id}'s H_I is not H(H_E; 0x20, id_B) (Verification 5.B).", nameof(ballot));
        }

        var regenerated = new BallotPreEncryptor(_encryptionRecord, ballot.DeviceId).PreEncryptContests(ballot.BallotStyleId, selectionHash, ballotNonce);
        foreach (var contest in regenerated)
        {
            var given = ballot.Contests.Single(x => x.ContestId == contest.ContestId);
            foreach (var selection in contest.Selections)
            {
                var givenSelection = given.Selections.SingleOrDefault(x => x.SelectionIndex == selection.SelectionIndex);
                if (givenSelection is null
                    || !string.Equals(givenSelection.ChoiceId, selection.ChoiceId, StringComparison.Ordinal)
                    || givenSelection.SelectionHash != selection.SelectionHash
                    || givenSelection.ShortCode != selection.ShortCode
                    || !givenSelection.Vector.Select(x => (x.Alpha, x.Beta)).SequenceEqual(selection.Vector.Select(x => (x.Alpha, x.Beta))))
                {
                    throw NotRegenerated(ballot, $"selection vector {selection.SelectionIndex} of contest {contest.ContestId}");
                }
            }

            if (given.ContestHash != contest.ContestHash)
            {
                throw NotRegenerated(ballot, $"the contest hash of contest {contest.ContestId}");
            }
        }

        var confirmationCode = ConfirmationCode.ForPreEncryptedBallot(selectionHash, regenerated.Select(x => x.ContestHash), ballot.ChainingField);
        if (confirmationCode != ballot.ConfirmationCode)
        {
            throw NotRegenerated(ballot, "its confirmation code");
        }

        return regenerated;
    }

    private static ArgumentException NotRegenerated(PreEncryptedBallot ballot, string what)
    {
        return new ArgumentException($"The ballot nonce does not regenerate pre-encrypted ballot {ballot.Id}: {what} differs (§4.3, eq. 121). Either ξ_B is wrong or the ballot was not produced from it.", "ballotNonce");
    }

    /// <summary>The selected option labels per contest, after checking <paramref name="selections"/> (see <see cref="RecordCast"/>).</summary>
    private Dictionary<string, HashSet<string>> ReadSelections(PreEncryptedBallot ballot, Ballot selections)
    {
        if (!string.Equals(selections.BallotStyleId, ballot.BallotStyleId, StringComparison.Ordinal))
        {
            throw new ArgumentException($"The selections are for ballot style {selections.BallotStyleId}; pre-encrypted ballot {ballot.Id} has ballot style {ballot.BallotStyleId}.", nameof(selections));
        }

        var manifest = _encryptionRecord.Manifest;
        var result = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var contest in selections.Contests)
        {
            var preEncrypted = ballot.Contests.FirstOrDefault(x => x.ContestId == contest.Id)
                ?? throw new ArgumentException($"The selections list contest {contest.Id}, which is not on pre-encrypted ballot {ballot.Id}.", nameof(selections));
            var manifestContest = manifest.Contests.Single(x => x.Id == preEncrypted.ContestId);

            if (contest.NumWriteinsSelected != 0 || contest.ContestData is not null)
            {
                throw new ArgumentException($"The selections for contest {contest.Id} use write-ins or contest data, which a pre-encrypted ballot has no place for (§4.1).", nameof(selections));
            }

            var chosen = new HashSet<string>(StringComparer.Ordinal);
            var listed = new HashSet<string>(StringComparer.Ordinal);
            foreach (var choice in contest.Choices)
            {
                if (!manifestContest.Choices.Any(x => x.Id == choice.Id))
                {
                    throw new ArgumentException($"The selections for contest {contest.Id} name option {choice.Id}, which is not an option of that contest.", nameof(selections));
                }

                if (!listed.Add(choice.Id))
                {
                    throw new ArgumentException($"The selections for contest {contest.Id} list option {choice.Id} more than once.", nameof(selections));
                }

                if (choice.SelectionValue is not (0 or 1))
                {
                    throw new ArgumentException($"The selection of option {choice.Id} in contest {contest.Id} is {choice.SelectionValue}; a pre-encrypted ballot has one vector per option, so a selection is 0 or 1 (§4.1).", nameof(selections));
                }

                if (choice.SelectionValue == 1)
                {
                    chosen.Add(choice.Id);
                }
            }

            if (chosen.Count > manifestContest.SelectionLimit)
            {
                throw new ArgumentException($"The selections for contest {contest.Id} select {chosen.Count} options; its selection limit is {manifestContest.SelectionLimit}. The recording tool does not record an overvote (the spec does not say how).", nameof(selections));
            }

            if (!result.TryAdd(contest.Id, chosen))
            {
                throw new ArgumentException($"The selections list contest {contest.Id} more than once.", nameof(selections));
            }
        }

        foreach (var contest in ballot.Contests)
        {
            if (!result.ContainsKey(contest.ContestId))
            {
                throw new ArgumentException($"The selections omit contest {contest.ContestId} of pre-encrypted ballot {ballot.Id}; list it with no option selected for no selection.", nameof(selections));
            }
        }

        return result;
    }
}
