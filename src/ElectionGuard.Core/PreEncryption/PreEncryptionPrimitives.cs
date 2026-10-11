using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.PreEncryption;

/// <summary>
/// The §4 formulas a pre-encrypted ballot is built from, as public primitives (user decision Q35:
/// this library implements the primitives of pre-encryption and its verifications, not the
/// encrypting tool of §4.2 or the recording tool of §4.3, which are out of scope).
/// <list type="bullet">
/// <item><see cref="GenerateSelection"/>, <see cref="GenerateContest"/>, <see cref="GenerateContests"/>:
/// the selection and null vectors that H_I and the ballot nonce ξ_B determine, with the encryption
/// nonces of eq. (121), the selection hashes of eqs. (113)/(114), the short codes Ω(ψ) (§4.6) and the
/// contest hash of eq. (115).</item>
/// <item><see cref="HasUniqueShortCodes"/>: the §4.1.5 requirement on one contest's short codes.</item>
/// <item><see cref="Combine"/> and <see cref="ProveCombinedContest"/>: §4.3's combination of the
/// selected vectors (componentwise product mod p, nonces summed mod q) and the standard proofs on the
/// combined vector (eq. 59 per component, eq. 62 for the contest), keyed with the ballot's H_I.</item>
/// </list>
/// The rest of the ballot is already public: H_I (<see cref="SelectionEncryptionIdentifierHash"/>),
/// the encrypted ballot nonce (<see cref="BallotNonceEncryption.Encrypt"/>), H_DI
/// (<see cref="VotingDeviceInformationHash.ForPreEncryptedBallots"/>), B_C
/// (<see cref="ChainingField.ForPreEncryptedBallots"/>), the confirmation code of eq. (116)
/// (<see cref="ConfirmationCode.ForPreEncryptedBallot"/>), the device chain
/// (<see cref="DeviceChain.ForPreEncryptedBallots"/>) and the published records
/// (<see cref="PreEncryptedBallot"/>, <see cref="EncryptedBallot.PreEncryptedContests"/>,
/// <see cref="PreEncryptedUncastBallot"/>). What a tool adds on top (drawing id_B and ξ_B, discarding a
/// ballot whose short codes repeat, choosing which vectors to combine, padding an undervote with null
/// vectors, checking a ballot against its regeneration, obtaining ξ_B, and what it publishes) is the
/// tool's.
///
/// Every function here works with secret values (ξ_B and the nonces it derives), so every
/// exponentiation is the constant-time <see cref="MontgomeryModP.PowModP"/>.
///
/// A <see cref="Contest"/> passed in must be the manifest's own: its <see cref="Contest.Index"/> is
/// its position in the manifest's contest list, which <see cref="Manifest.Validate"/> checks when the
/// <see cref="EncryptionRecord"/> is built and <see cref="GenerateContests"/> checks again. The
/// per-contest primitives (<see cref="GenerateSelection"/>, <see cref="GenerateContest"/>,
/// <see cref="ProveCombinedContest(ElectionPublicKeys, Contest, SelectionEncryptionIdentifierHash, IReadOnlyList{EncryptedValue}, IReadOnlyList{int}, ContestHash)"/>)
/// cannot see the manifest, so they check the part of §3.1.3 they rely on themselves: the contest
/// has at least one option (<see cref="ArgumentException"/>) and its option indices are 1..m in list
/// order (<see cref="InvalidManifestException"/>). Otherwise the vectors' indices (j and k of
/// eq. 121, the ℓ-th null vector's m + ℓ) and the proof challenges would be ones no verifier
/// reproduces.
/// </summary>
public static class PreEncryptionPrimitives
{
    /// <summary>
    /// The pre-encryption vector with index <paramref name="selectionIndex"/> of
    /// <paramref name="contest"/> (§4.1, §4.2.1): for k over the contest's option indices in
    /// increasing order, the encryption of δ (one where k = j, zero elsewhere, so a null vector
    /// encrypts all zeros) under ξ_{i,j,k} = H_q(H_I; 0x45, i, j, k, ξ_B) (eq. 121), i the contest
    /// index; its selection hash ψ (eq. 113, or eq. 114 for a null vector) and its short code
    /// Ω(ψ) (§4.6). j is an option index (1..m) for an option vector; for the ℓ-th null vector
    /// (1 ≤ ℓ ≤ L) it is m + ℓ (§4.2.1). Each encryption carries its nonce in
    /// <see cref="EncryptedValue.EncryptionNonce"/>, which no serializer writes. Throws
    /// <see cref="ArgumentOutOfRangeException"/> for an index outside 1..m + L, and checks the
    /// contest's option numbering first (see <see cref="PreEncryptionPrimitives"/>).
    /// </summary>
    public static PreEncryptedSelection GenerateSelection(
        ElectionPublicKeys electionPublicKeys,
        HashTrimmingFunction hashTrimmingFunction,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        BallotNonce ballotNonce,
        Contest contest,
        int selectionIndex)
    {
        ArgumentNullException.ThrowIfNull(electionPublicKeys);
        ArgumentNullException.ThrowIfNull(contest);

        var positions = Positions(contest);
        int m = positions.Count;
        if (selectionIndex < 1 || selectionIndex > m + contest.SelectionLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(selectionIndex), selectionIndex,
                $"Contest {contest.Id} has no pre-encryption vector with index {selectionIndex}: its option indices are 1..{m} and its null vectors {m + 1}..{m + contest.SelectionLimit}.");
        }

        var choice = selectionIndex <= m ? contest.Choices[selectionIndex - 1] : null;

        return GenerateSelection(electionPublicKeys.VoteEncryptionKey, hashTrimmingFunction, selectionEncryptionIdentifierHash, ballotNonce, contest.Index, selectionIndex, choice?.Id, positions);
    }

    /// <summary>
    /// Every pre-encryption vector of <paramref name="contest"/> (§4.1.2): one per option in
    /// increasing option index order, then the L null vectors (§4.1.1, §4.1.5), each as
    /// <see cref="GenerateSelection"/> gives it, and the contest hash
    /// χ = H(H_I; 0x41, ind_c, ψ sorted ascending) over all m + L selection hashes (eq. 115).
    /// Checks the contest's option numbering first (see <see cref="PreEncryptionPrimitives"/>).
    /// </summary>
    public static PreEncryptedContest GenerateContest(
        ElectionPublicKeys electionPublicKeys,
        HashTrimmingFunction hashTrimmingFunction,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        BallotNonce ballotNonce,
        Contest contest)
    {
        ArgumentNullException.ThrowIfNull(electionPublicKeys);
        ArgumentNullException.ThrowIfNull(contest);

        // §4.1: vector positions follow the option indices in increasing order, which Positions has
        // checked are 1..m in list order. The index k of eq. (121) is the option index at a
        // position, the same index space as j, so that a vector encrypts a one exactly where j = k.
        var positions = Positions(contest);
        var options = contest.Choices;
        var voteEncryptionKey = electionPublicKeys.VoteEncryptionKey;

        var selections = options
            .Select(option => GenerateSelection(voteEncryptionKey, hashTrimmingFunction, selectionEncryptionIdentifierHash, ballotNonce, contest.Index, option.Index, option.Id, positions))
            .ToList();

        // §4.1.1/§4.1.5: one null vector per unit of the selection limit. The manifest has no
        // labels for them, so their indices extend the option indices (§4.2.1): m + ℓ.
        int m = positions.Count;
        for (int nullVector = 1; nullVector <= contest.SelectionLimit; nullVector++)
        {
            selections.Add(GenerateSelection(voteEncryptionKey, hashTrimmingFunction, selectionEncryptionIdentifierHash, ballotNonce, contest.Index, m + nullVector, null, positions));
        }

        return new PreEncryptedContest
        {
            ContestId = contest.Id,
            ContestIndex = contest.Index,
            Selections = selections,
            ContestHash = ContestHash.ForPreEncryptedContest(selectionEncryptionIdentifierHash, contest.Index, selections.Select(x => x.SelectionHash)),
        };
    }

    /// <summary>
    /// Every contest of the ballot style <paramref name="ballotStyleId"/>, in increasing contest
    /// index order (§4.1.3: the order their contest hashes enter the confirmation code), as
    /// <see cref="GenerateContest"/> gives it under the manifest's hash-trimming function. Validates
    /// the manifest first (<see cref="InvalidManifestException"/>: every nonce and hash here hashes its
    /// indices, §3.1.3), and throws <see cref="ArgumentException"/> if it names no hash-trimming
    /// function (an election without pre-encrypted ballots, §4.1.5) or does not hold the ballot style
    /// or one of its contests.
    /// </summary>
    public static List<PreEncryptedContest> GenerateContests(
        EncryptionRecord encryptionRecord,
        string ballotStyleId,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        BallotNonce ballotNonce)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        var manifest = encryptionRecord.Manifest;
        manifest.Validate();
        var hashTrimmingFunction = manifest.HashTrimmingFunction
            ?? throw new ArgumentException("The manifest does not specify a hash-trimming function, so it does not support pre-encrypted ballots (§4.1.5).", nameof(encryptionRecord));
        var ballotStyle = manifest.BallotStyles.SingleOrDefault(x => x.Id == ballotStyleId)
            ?? throw new ArgumentException($"Could not find ballot style with id {ballotStyleId} in manifest.", nameof(ballotStyleId));

        return ballotStyle.ContestIds
            .Select(contestId => manifest.Contests.SingleOrDefault(x => x.Id == contestId)
                ?? throw new ArgumentException($"Ballot style {ballotStyleId} lists contest {contestId}, which is not in the manifest.", nameof(ballotStyleId)))
            .OrderBy(x => x.Index)
            .Select(contest => GenerateContest(encryptionRecord.ElectionPublicKeys, hashTrimmingFunction, selectionEncryptionIdentifierHash, ballotNonce, contest))
            .ToList();
    }

    /// <summary>
    /// §4.1.5: whether the short codes of <paramref name="contest"/>'s vectors are all distinct. A
    /// ballot that fails this for any contest must not be used; a contest with more vectors than Ω
    /// has codes (<see cref="HashTrimming.CodeSpaceSize"/>) can never pass.
    /// </summary>
    public static bool HasUniqueShortCodes(PreEncryptedContest contest)
    {
        ArgumentNullException.ThrowIfNull(contest);
        return contest.Selections.Select(x => x.ShortCode).Distinct().Count() == contest.Selections.Count;
    }

    /// <summary>
    /// §4.3: the componentwise product (mod p) of the pre-encryption <paramref name="vectors"/> of one
    /// contest, with the encryption nonces of each component "added (modulo q)", so that each
    /// component of the result is an encryption of the number of the vectors that select its option
    /// under the summed nonce. Every vector must have the same length and carry its nonces
    /// (<see cref="EncryptedValue.EncryptionNonce"/>, as <see cref="GenerateSelection"/> gives them);
    /// at least one vector is required. Which vectors to combine, including any null vectors that
    /// pad an undervote, is the caller's choice.
    /// </summary>
    public static List<EncryptedValue> Combine(IReadOnlyCollection<PreEncryptedSelection> vectors)
    {
        ArgumentNullException.ThrowIfNull(vectors);
        if (vectors.Count == 0)
        {
            throw new ArgumentException("At least one pre-encryption vector is required.", nameof(vectors));
        }

        int m = vectors.First().Vector.Count;
        if (vectors.Any(x => x.Vector.Count != m))
        {
            throw new ArgumentException("The pre-encryption vectors of one contest all have one entry per option.", nameof(vectors));
        }

        var combined = new List<EncryptedValue>(m);
        for (int k = 0; k < m; k++)
        {
            IntegerModP alpha = 1;
            IntegerModP beta = 1;
            IntegerModQ nonce = 0;
            foreach (var vector in vectors)
            {
                var encryption = vector.Vector[k];
                alpha *= encryption.Alpha;
                beta *= encryption.Beta;
                nonce += encryption.EncryptionNonce
                    ?? throw new ArgumentException($"Pre-encryption vector {vector.SelectionIndex} carries no encryption nonces; regenerate it from ξ_B (eq. 121).", nameof(vectors));
            }

            combined.Add(new EncryptedValue { Alpha = alpha, Beta = beta, EncryptionNonce = nonce });
        }

        return combined;
    }

    /// <summary>
    /// §4.3 "generates proofs of ballot-correctness as in standard ElectionGuard section 3.3.7" for
    /// one contest's combined vector <paramref name="combined"/> (one component per option, in
    /// increasing option index order, each with its summed nonce, as <see cref="Combine"/> returns
    /// it), which encrypts <paramref name="selections"/> (one value per option, same order): for each
    /// component the range proof of eq. (59) over 0..R (the contest's option selection limit;
    /// Verification 6 "using the appropriate option selection limits", p.64), and for the contest the
    /// selection-limit proof of eq. (62) over 0..L on the product of the components, all keyed with
    /// the ballot's H_I. Returns the contest as it is recorded on the cast ballot: those components
    /// with their proofs, no supplemental fields or contest data (§4.1, p.66), and
    /// <paramref name="contestHash"/>, the eq. (115) hash of the pre-encrypted contest. Checks the
    /// contest's option numbering first (see <see cref="PreEncryptionPrimitives"/>). Throws
    /// <see cref="ArgumentException"/> if the lengths do not match the contest's options or a
    /// component has no nonce, and <see cref="ArgumentOutOfRangeException"/> if a value is outside
    /// 0..R or their sum outside 0..L (no valid proof exists then).
    /// </summary>
    public static EncryptedContest ProveCombinedContest(
        ElectionPublicKeys electionPublicKeys,
        Contest contest,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        IReadOnlyList<EncryptedValue> combined,
        IReadOnlyList<int> selections,
        ContestHash contestHash)
    {
        return ProveCombinedContest(electionPublicKeys, contest, selectionEncryptionIdentifierHash, combined, selections, contestHash, proofNoncesForTesting: null);
    }

    /// <summary>
    /// <see cref="ProveCombinedContest(ElectionPublicKeys, Contest, SelectionEncryptionIdentifierHash, IReadOnlyList{EncryptedValue}, IReadOnlyList{int}, ContestHash)"/>
    /// with a test seam: <paramref name="proofNoncesForTesting"/>, when given, supplies for the proof
    /// of option index ind_o (null for the selection-limit proof) and commitment j the proof nonce u_j
    /// and the simulated challenge c_j in place of fresh random values (see
    /// <see cref="BallotEncryptor.GenerateProofs"/>). The known-answer tests use it to reproduce the
    /// oracle's proofs.
    /// </summary>
    internal static EncryptedContest ProveCombinedContest(
        ElectionPublicKeys electionPublicKeys,
        Contest contest,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        IReadOnlyList<EncryptedValue> combined,
        IReadOnlyList<int> selections,
        ContestHash contestHash,
        Func<int?, int, (IntegerModQ U, IntegerModQ C)>? proofNoncesForTesting)
    {
        ArgumentNullException.ThrowIfNull(electionPublicKeys);
        ArgumentNullException.ThrowIfNull(contest);
        ArgumentNullException.ThrowIfNull(combined);
        ArgumentNullException.ThrowIfNull(selections);

        // Positions checks that the option indices are 1..m in list order: option.Index enters each
        // range proof's challenge (eq. 59).
        int m = Positions(contest).Count;
        var options = contest.Choices;
        if (combined.Count != m || selections.Count != m)
        {
            throw new ArgumentException($"Contest {contest.Id} has {m} options; the combined vector has {combined.Count} components and the selections {selections.Count} values.", nameof(combined));
        }

        if (combined.Any(x => x.EncryptionNonce is null))
        {
            throw new ArgumentException("Every component of the combined vector must carry its summed nonce to be proved.", nameof(combined));
        }

        int total = 0;
        foreach (int value in selections)
        {
            if (value < 0 || value > contest.OptionSelectionLimit)
            {
                throw new ArgumentOutOfRangeException(nameof(selections), value, $"A component of contest {contest.Id} is proved over 0..{contest.OptionSelectionLimit} (R).");
            }

            total += value;
        }

        if (total > contest.SelectionLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(selections), total, $"The selections of contest {contest.Id} sum to {total}; its selection limit is {contest.SelectionLimit} (L).");
        }

        var choices = new List<EncryptedSelection>(m);
        IntegerModP totalAlpha = 1;
        IntegerModP totalBeta = 1;
        IntegerModQ totalNonce = 0;
        for (int k = 0; k < m; k++)
        {
            var component = combined[k];
            var option = options[k];

            // §3.3.7 eq. (59): a range proof over 0..R for each component.
            var proofs = BallotEncryptor.GenerateProofs(selections[k], 0, contest.OptionSelectionLimit, component, electionPublicKeys, selectionEncryptionIdentifierHash, contest.Index, option.Index,
                proofNoncesForTesting: ProofNonces(proofNoncesForTesting, option.Index));
            choices.Add(new EncryptedSelection
            {
                ChoiceId = option.Id,
                Alpha = component.Alpha,
                Beta = component.Beta,
                EncryptionNonce = component.EncryptionNonce,
                Proofs = proofs,
            });

            totalAlpha *= component.Alpha;
            totalBeta *= component.Beta;
            totalNonce += component.EncryptionNonce!.Value;
        }

        // §3.3.8 eq. (62): the selection-limit proof over 0..L of the product of the components.
        var totalCiphertext = new EncryptedValue { Alpha = totalAlpha, Beta = totalBeta, EncryptionNonce = totalNonce };
        var limitProofs = BallotEncryptor.GenerateProofs(total, 0, contest.SelectionLimit, totalCiphertext, electionPublicKeys, selectionEncryptionIdentifierHash, contest.Index, optionIndex: null,
            proofNoncesForTesting: ProofNonces(proofNoncesForTesting, null));

        return new EncryptedContest
        {
            Id = contest.Id,
            Choices = choices,
            SupplementalFields = [],
            Proofs = limitProofs,
            ContestData = null,
            ContestHash = contestHash,
        };
    }

    private static Func<int, (IntegerModQ U, IntegerModQ C)>? ProofNonces(Func<int?, int, (IntegerModQ U, IntegerModQ C)>? seam, int? optionIndex)
    {
        return seam is null ? null : j => seam(optionIndex, j);
    }

    /// <summary>
    /// The contest's option indices, the positions k of every vector: 1..m, after checking that the
    /// contest has an option (<see cref="ArgumentException"/>) and that each option's index is its
    /// 1-based position in the contest's option list (§3.1.3, <see cref="InvalidManifestException"/>),
    /// the per-contest part of <see cref="Manifest.Validate"/> these primitives rely on.
    /// </summary>
    private static List<int> Positions(Contest contest)
    {
        if (contest.Choices is null || contest.Choices.Count == 0)
        {
            throw new ArgumentException($"Contest {contest.Id} has no options.", nameof(contest));
        }

        for (int position = 0; position < contest.Choices.Count; position++)
        {
            var choice = contest.Choices[position];
            if (choice.Index != position + 1)
            {
                throw new InvalidManifestException(
                    $"Option {choice.Id} is at position {position + 1} of contest {contest.Id}'s option list but has index {choice.Index}; an option index must be its 1-based position (§3.1.3).");
            }
        }

        return Enumerable.Range(1, contest.Choices.Count).ToList();
    }

    private static PreEncryptedSelection GenerateSelection(
        IntegerModP voteEncryptionKey,
        HashTrimmingFunction hashTrimmingFunction,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        BallotNonce ballotNonce,
        int contestIndex,
        int selectionIndex,
        string? choiceId,
        List<int> positions)
    {
        var vector = positions
            .Select(position => Encrypt(position == selectionIndex ? 1 : 0, voteEncryptionKey, selectionEncryptionIdentifierHash, ballotNonce, contestIndex, selectionIndex, position))
            .ToList();
        var selectionHash = new SelectionHash(selectionEncryptionIdentifierHash, vector);

        return new PreEncryptedSelection
        {
            SelectionIndex = selectionIndex,
            ChoiceId = choiceId,
            Vector = vector,
            SelectionHash = selectionHash,
            ShortCode = HashTrimming.Trim(hashTrimmingFunction, selectionHash),
        };
    }

    private static EncryptedValue Encrypt(int value, IntegerModP voteEncryptionKey, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce, int contestIndex, int selectionIndex, int positionIndex)
    {
        // ξ_{i,j,k} is secret and a full-width element of Z_q: the constant-time path.
        IntegerModQ nonce = new PreEncryptionNonce(selectionEncryptionIdentifierHash, ballotNonce, contestIndex, selectionIndex, positionIndex);
        return new EncryptedValue
        {
            Alpha = MontgomeryModP.PowModP(EGParameters.G, nonce),
            Beta = MontgomeryModP.PowModP(voteEncryptionKey, nonce + value),
            EncryptionNonce = nonce,
        };
    }
}
