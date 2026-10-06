using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Text;

namespace ElectionGuard.Core.BallotEncryption;

public class BallotEncryptor
{
    public BallotEncryptor(EncryptionRecord encryptionRecord, string deviceId, VotingDeviceInformationHash deviceHash)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        // §3.1.3: every nonce and challenge below hashes the manifest's contest and option indices.
        encryptionRecord.Manifest.Validate();

        _encryptionRecord = encryptionRecord;
        _deviceId = deviceId;
        _deviceHash = deviceHash;
    }

    private readonly EncryptionRecord _encryptionRecord;
    private readonly string _deviceId;
    private readonly VotingDeviceInformationHash _deviceHash;

    /// <summary>
    /// Opt in to the precomputed power tables of Note 3.5.
    ///
    /// The note observes that every exponentiation performed while encrypting and proving ballot
    /// components has a base of either g or K, so tables of powers of those bases can be built once
    /// and reused, and holding them in Montgomery form makes them faster still. This builds exactly
    /// those tables: the generator g, the vote encryption key K, and the other-ballot-data
    /// encryption key K-hat.
    ///
    /// This is not done automatically, because it is not free: at the v2.1.0 parameter sizes the
    /// default 12-bit window costs 44 MiB per base (49.5 MiB in the AVX-512 representation) and
    /// tens of milliseconds to build. That is the right trade for a process that is about to
    /// encrypt ballots and the wrong one for a process that is not, so the choice belongs to the caller. Encryption is correct either way; without tables
    /// it simply runs the table-free Montgomery path instead.
    ///
    /// Calling this more than once for the same record and width is cheap: existing tables are kept.
    ///
    /// The tables live in <see cref="PowRadixRegistry"/> until something clears them, and they are
    /// keyed by base, so a process that encrypts for a second election adds a second set rather
    /// than replacing the first. A long-lived process that moves between elections should call
    /// <see cref="PowRadixRegistry.Clear"/> when it leaves one behind.
    /// </summary>
    public static void PrecomputePowerTables(EncryptionRecord encryptionRecord, int windowBits = PowRadix.DefaultWindowBits)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        PowRadixRegistry.Precompute(
            windowBits,
            EGParameters.G,
            encryptionRecord.ElectionPublicKeys.VoteEncryptionKey.ToBigInteger(),
            encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey.ToBigInteger());
    }

    public EncryptedBallot Encrypt(Ballot ballot, ConfirmationCode? previousConfirmationCode)
    {
        return Encrypt(
            ballot,
            previousConfirmationCode,
            new SelectionEncryptionIdentifier(ElectionGuardRandom.GetBytes(32)),
            new BallotNonce(ElectionGuardRandom.GetBytes(32)));
    }

    /// <summary>
    /// <see cref="Encrypt(Ballot, ConfirmationCode?)"/> with the selection encryption identifier
    /// id_B and ballot nonce xi_B given rather than drawn. They determine every ciphertext, contest
    /// hash and the confirmation code; only the proofs' commitments are still random.
    /// </summary>
    internal EncryptedBallot Encrypt(Ballot ballot, ConfirmationCode? previousConfirmationCode, SelectionEncryptionIdentifier selectionEncryptionIdentifier, BallotNonce ballotNonce)
    {
        Validate(ballot);

        var selectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(_encryptionRecord.ExtendedBaseHash, selectionEncryptionIdentifier);

        var encryptedBallotNonce = BallotNonceEncryption.Encrypt(ballotNonce, selectionEncryptionIdentifierHash, _encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey);

        // §3.4.2 eq. (71): the contest hashes enter the confirmation code in the order of the
        // contests in the manifest, whatever order the plaintext ballot lists them in. The encrypted
        // ballot lists its contests in that same order. Validate has already checked that the
        // ballot's contests are distinct and all in the manifest.
        var encryptedContests = new List<EncryptedContest>(ballot.Contests.Count);
        List<ContestHash> contestHashes = new List<ContestHash>(ballot.Contests.Count);
        foreach (var manifestContest in _encryptionRecord.Manifest.Contests)
        {
            var contest = ballot.Contests.SingleOrDefault(x => x.Id == manifestContest.Id);
            if (contest == null)
            {
                continue;
            }

            var encryptedContest = EncryptContest(contest, manifestContest, selectionEncryptionIdentifierHash, ballotNonce);
            encryptedContests.Add(encryptedContest);
            contestHashes.Add(encryptedContest.ContestHash);
        }

        var chainingField = new ChainingField(_encryptionRecord.Manifest.ChainingMode, _deviceHash, _encryptionRecord.ExtendedBaseHash, previousConfirmationCode);
        var confirmationCode = new ConfirmationCode(selectionEncryptionIdentifierHash, contestHashes, chainingField);

        return new EncryptedBallot
        {
            Id = ballot.Id,
            BallotStyleId = ballot.BallotStyleId,
            DeviceId = _deviceId,
            SelectionEncryptionIdentifier = selectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = selectionEncryptionIdentifierHash,
            Contests = encryptedContests,
            ConfirmationCode = confirmationCode,
            Weight = 1,
        };
    }

    private void Validate(Ballot ballot)
    {
        // Each contest appears once
        if (ballot.Contests.Select(x => x.Id).Distinct().Count() != ballot.Contests.Count)
        {
            throw new InvalidBallotException($"Ballot {ballot.Id} lists a contest more than once.");
        }

        // All contests exist in the manifest
        foreach(var contest in ballot.Contests)
        {
            var manifestContest = _encryptionRecord.Manifest.Contests.SingleOrDefault(x => x.Id == contest.Id);
            if(manifestContest == null)
            {
                throw new InvalidBallotException($"Contest with id {contest.Id} not found in manifest.");
            }

            // All choices exist in the manifest
            // All choices are specified for this contest
            var manifestChoices = manifestContest.Choices.Select(x => x.Id).ToList();
            var choices = contest.Choices.Select(x => x.Id).ToList();
            if(manifestChoices.Count != choices.Count
                || manifestChoices.Except(choices).Any()
                || choices.Except(manifestChoices).Any())
            {
                throw new InvalidBallotException($"Contest with id {contest.Id} did not provide all choice selections from the manifest.");
            }

            // §3.1.3: a selection is a value in {0, 1, ..., R}. A value above R is not refused: it
            // overvotes the contest (§3.3.5, §3.1.3 p.18 "treated analogously to a contest
            // overvote"), which EncryptContest neutralizes. A negative value is no selection at all.
            foreach(var choice in contest.Choices)
            {
                if(choice.SelectionValue < 0)
                {
                    throw new InvalidBallotException($"Choice for id {choice.Id} has negative selection value {choice.SelectionValue}.");
                }
            }

            // §3.3.9 p.39: the write-in count lies between zero and the number of write-in fields
            // the contest offers.
            if (contest.NumWriteinsSelected < 0 || contest.NumWriteinsSelected > manifestContest.WriteInFieldCount)
            {
                throw new InvalidBallotException($"Contest with id {contest.Id} uses {contest.NumWriteinsSelected} write-in fields; it offers {manifestContest.WriteInFieldCount}.");
            }
        }

        // All contests for the given ballot style are specified.
        var ballotStyle = _encryptionRecord.Manifest.BallotStyles.SingleOrDefault(x => x.Id == ballot.BallotStyleId);
        if(ballotStyle == null)
        {
            throw new InvalidBallotException($"Could not find ballot style with id {ballot.BallotStyleId} in manifest.");
        }
        var contestIds = ballot.Contests.Select(x => x.Id).ToList();
        if(contestIds.Count != ballotStyle.ContestIds.Count
            || contestIds.Except(ballotStyle.ContestIds).Any()
            || ballotStyle.ContestIds.Except(contestIds).Any())
        {
            throw new InvalidBallotException($"Ballot with id {ballot.BallotStyleId} did not specify all contestIds for the ballot style.");
        }
    }

    /// <summary>
    /// The value of a supplemental field of <paramref name="kind"/> (§3.3.9), from the contest's
    /// (neutralized) sum of selections s, its number of write-ins w (user decision Q13: write-ins
    /// always count toward the limit, exactly like selections) and whether it was overvoted:
    /// <list type="bullet">
    /// <item>Overvote indicator: 1 when the contest was overvoted (p.38).</item>
    /// <item>Null-vote indicator: 1 when s + w = 0 and the contest was not overvoted (p.39 "When all
    /// the selections are set to zero as a consequence of an overvote, the null vote indicator should
    /// be set to zero"; Q3, Q13: a write-in-only ballot is not a null vote).</item>
    /// <item>Undervote indicator: 1 when s + w is below L and the contest was not overvoted (p.38;
    /// Q11: "if a contest is an overvote, it is not an undervote").</item>
    /// <item>Undervote difference count u: L - (s + w + L * overvote), with the overvote term only
    /// when the contest declares the overvote indicator (Q15: s + w + L*overvote + u = L is proved
    /// exactly). So u = 0 on an overvote when the indicator is declared, and L, the difference to
    /// the zeroed selections, when it is not: p.38's relation without the term (open S5b user
    /// question).</item>
    /// <item>Write-in count: the number of write-in fields used, 0 on an overvote (p.39; Q12).</item>
    /// </list>
    /// On an overvote s and w are already 0 here.
    /// </summary>
    private static int SupplementalValue(SupplementalFieldKind kind, int limit, int sum, int writeIns, bool isOvervote, bool overvoteTracked)
    {
        int total = sum + writeIns;
        return kind switch
        {
            SupplementalFieldKind.OvervoteIndicator => isOvervote ? 1 : 0,
            SupplementalFieldKind.NullVoteIndicator => !isOvervote && total == 0 ? 1 : 0,
            SupplementalFieldKind.UndervoteIndicator => !isOvervote && total < limit ? 1 : 0,
            SupplementalFieldKind.UndervoteDifferenceCount => limit - total - (isOvervote && overvoteTracked ? limit : 0),
            SupplementalFieldKind.WriteInCount => writeIns,
            _ => throw new InvalidManifestException($"Supplemental field kind {kind} is not a kind of §3.3.9."),
        };
    }

    private EncryptedContest EncryptContest(BallotContest contest, Contest manifestContest, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce)
    {
        int limit = manifestContest.SelectionLimit;
        int optionLimit = manifestContest.OptionSelectionLimit;

        // §3.4.1 eq. (70): the selections enter the contest hash in the order of the options in the
        // manifest, whatever order the plaintext contest lists them in, and the encrypted contest
        // lists them in that same order. Validate has already checked that the two sets are equal.
        var choicesInManifestOrder = new BallotChoice[manifestContest.Choices.Count];
        for (int i = 0; i < choicesInManifestOrder.Length; i++)
        {
            choicesInManifestOrder[i] = contest.Choices.Single(x => x.Id == manifestContest.Choices[i].Id);
        }

        // The total every rule below is about: the selections s plus the write-ins used w, which
        // always count toward the selection limit (user decision Q13; §3.3.9 p.39 "The number of
        // write-ins should be incorporated into the proof of meeting the selection limit").
        // Manifest.Validate makes a contest that offers write-ins declare the write-in count, and
        // Validate(ballot) allows none where it offers none. Summed in long, so that no plaintext can
        // wrap it below L.
        int writeIns = contest.NumWriteinsSelected;
        long sum = 0;
        bool anyOptionOverLimit = false;
        foreach (var choice in choicesInManifestOrder)
        {
            sum += choice.SelectionValue;
            anyOptionOverLimit |= choice.SelectionValue > optionLimit;
        }

        // §3.3.5 p.31, §3.1.3 pp.17-18, §3.3.9 p.38: the contest is overvoted when the selections and
        // write-ins exceed the contest selection limit L, or when one option's value exceeds the
        // option selection limit R. Then every selectable option is encrypted as 0 "to not affect the
        // election tallies", and the write-in count is 0 too (user decision Q12).
        bool isOvervote = sum + writeIns > limit || anyOptionOverLimit;
        if (isOvervote)
        {
            foreach (var choice in choicesInManifestOrder)
            {
                choice.SelectionValue = 0;
            }

            writeIns = 0;
            sum = 0;
        }

        int neutralizedSum = (int)sum;
        bool overvoteTracked = manifestContest.SupplementalFieldOfKind(SupplementalFieldKind.OvervoteIndicator) is not null;

        // One encryption per selectable option, each with its own nonce xi_{i,j} (eq. 33) and range
        // proof over 0..R (eqs. 57-61).
        var encryptedSelections = new List<EncryptedSelection>(manifestContest.Choices.Count);
        var sumAlpha = new ModPProduct(1);
        var sumBeta = new ModPProduct(1);
        IntegerModQ sumNonce = 0;
        for (int i = 0; i < choicesInManifestOrder.Length; i++)
        {
            var manifestChoice = manifestContest.Choices[i];
            var encryptedSelection = EncryptSelection(manifestContest, manifestChoice, choicesInManifestOrder[i].SelectionValue, selectionEncryptionIdentifierHash, ballotNonce);
            encryptedSelections.Add(encryptedSelection);
            sumAlpha.Multiply(encryptedSelection.Alpha);
            sumBeta.Multiply(encryptedSelection.Beta);
            sumNonce += encryptedSelection.EncryptionNonce!.Value;
        }

        // One encryption per declared supplemental field, in manifest order, under its own option
        // index (§3.1.3 p.19: "treated like and listed with the option selection fields").
        var encryptedFields = new List<EncryptedSupplementalField>(manifestContest.SupplementalFields.Count);
        EncryptedSupplementalField? overvoteField = null;
        EncryptedSupplementalField? undervoteField = null;
        EncryptedSupplementalField? undervoteDifferenceField = null;
        EncryptedSupplementalField? nullVoteField = null;
        int undervoteValue = 0;
        int nullVoteValue = 0;
        int undervoteDifferenceIndex = 0;
        int nullVoteIndex = 0;
        foreach (var field in manifestContest.SupplementalFields)
        {
            int value = SupplementalValue(field.Kind, limit, neutralizedSum, writeIns, isOvervote, overvoteTracked);
            var encryptedField = EncryptSupplementalField(manifestContest, field, value, selectionEncryptionIdentifierHash, ballotNonce);
            encryptedFields.Add(encryptedField);

            switch (field.Kind)
            {
                case SupplementalFieldKind.OvervoteIndicator:
                    overvoteField = encryptedField;
                    break;
                case SupplementalFieldKind.UndervoteIndicator:
                    undervoteField = encryptedField;
                    undervoteValue = value;
                    break;
                case SupplementalFieldKind.UndervoteDifferenceCount:
                    undervoteDifferenceField = encryptedField;
                    undervoteDifferenceIndex = field.Index;
                    break;
                case SupplementalFieldKind.NullVoteIndicator:
                    nullVoteField = encryptedField;
                    nullVoteValue = value;
                    nullVoteIndex = field.Index;
                    break;
                case SupplementalFieldKind.WriteInCount:
                    // The write-ins are part of the total s + w.
                    sumAlpha.Multiply(encryptedField.Alpha);
                    sumBeta.Multiply(encryptedField.Beta);
                    sumNonce += encryptedField.EncryptionNonce!.Value;
                    break;
            }
        }

        // The encryption of s + w: the product of the options and the write-in count.
        int total = neutralizedSum + writeIns;
        var sumCiphertext = new EncryptedValue
        {
            Alpha = sumAlpha.Value,
            Beta = sumBeta.Value,
            EncryptionNonce = sumNonce,
        };

        // The relations of user decision Q15. Each is over the encryption of s + w times the terms
        // of the fields the contest declares, and only those. L times a field is its ciphertext
        // raised to L (footnote 42); L is a small public number, so it is raised with a window over
        // its own bits, never MontgomeryModP.PowModP.
        //
        // (1) §3.3.8 eq. (62) and §3.3.9 p.39: the selection-limit proof shows that
        //     s + w + L*overvote + undervote indicator lies in 0..L.
        var limitCiphertext = Combine(sumCiphertext, overvoteField, limit, undervoteField, 1);
        int limitValue = total
            + (overvoteField is not null && isOvervote ? limit : 0)
            + (undervoteField is not null ? undervoteValue : 0);
        var proofs = GenerateProofs(limitValue, 0, limit, limitCiphertext, _encryptionRecord.ElectionPublicKeys, selectionEncryptionIdentifierHash, manifestContest.Index, optionIndex: null);

        // (2) §3.3.9 p.38: s + w + L*overvote + u = L exactly, by the range proof of eqs. (57)-(61)
        //     over the singleton set {L} (Note 3.4): one commitment (a, b) = (g^r, K^r),
        //     c = H_q(H_I; 0x24, ind_c, ind_o(u), A, B, a, b) with ind_o(u) the undervote difference
        //     field's option index, c_L = c and v = r - c * (the nonce of (A, B)). NOT spec-defined:
        //     §3.3.9 says such proofs "are not described in detail", so this challenge is this
        //     implementation's own and is not interoperable.
        ChallengeResponsePair[]? undervoteDifferenceProof = null;
        if (undervoteDifferenceField is not null)
        {
            var relationCiphertext = Combine(sumCiphertext, overvoteField, limit, undervoteDifferenceField, 1);
            undervoteDifferenceProof = GenerateProofs(limit, limit, limit, relationCiphertext, _encryptionRecord.ElectionPublicKeys, selectionEncryptionIdentifierHash, manifestContest.Index, undervoteDifferenceIndex);
        }

        // (3) §3.3.9 p.39: "The validity of the encrypted null vote indicator can be enforced just as
        //     the validity of the encrypted overvote indicator": s + w + L*null lies in 0..L, by a
        //     range proof with c = H_q(H_I; 0x24, ind_c, ind_o(null), b(L, 4), A, B, a_0, b_0, ...,
        //     a_L, b_L). NOT spec-defined either; see
        //     AdherenceToVoteLimitsVerification.ComputeNullVoteChallenge.
        ChallengeResponsePair[]? nullVoteProof = null;
        if (nullVoteField is not null)
        {
            var nullCiphertext = Combine(sumCiphertext, nullVoteField, limit, null, 0);
            int nullValue = total + limit * nullVoteValue;
            nullVoteProof = GenerateProofs(nullValue, 0, limit, nullCiphertext, _encryptionRecord.ElectionPublicKeys, selectionEncryptionIdentifierHash, manifestContest.Index, nullVoteIndex, weight: limit);
        }

        EncryptedData? encryptedContestData = null;
        if(contest.ContestData != null)
        {
            encryptedContestData = EncryptContestData(contest.ContestData, manifestContest.Index, selectionEncryptionIdentifierHash, ballotNonce);
        }

        // Eq. (70): every verifiable field in manifest order, the options and then the declared
        // supplemental fields, and nothing else.
        var verifiableFields = new List<EncryptedValueWithProofs>(encryptedSelections.Count + encryptedFields.Count);
        verifiableFields.AddRange(encryptedSelections);
        verifiableFields.AddRange(encryptedFields);
        var contestHash = new ContestHash(selectionEncryptionIdentifierHash,
            manifestContest.Index,
            verifiableFields,
            encryptedContestData);

        var encryptedContest = new EncryptedContest
        {
            Id = contest.Id,
            Choices = encryptedSelections,
            SupplementalFields = encryptedFields,
            Proofs = proofs,
            UndervoteDifferenceProof = undervoteDifferenceProof,
            NullVoteProof = nullVoteProof,
            ContestData = encryptedContestData,
            ContestHash = contestHash,
        };

        return encryptedContest;
    }

    /// <summary>
    /// <paramref name="sum"/> times <paramref name="first"/> raised to <paramref name="firstWeight"/>
    /// and <paramref name="second"/> raised to <paramref name="secondWeight"/>, with the matching
    /// nonce. A term whose field the contest does not declare (null) is left out.
    /// </summary>
    private static EncryptedValue Combine(
        EncryptedValue sum,
        EncryptedSupplementalField? first,
        int firstWeight,
        EncryptedSupplementalField? second,
        int secondWeight)
    {
        if (first is null && second is null)
        {
            return sum;
        }

        var alpha = new ModPProduct(sum.Alpha);
        var beta = new ModPProduct(sum.Beta);
        IntegerModQ nonce = sum.EncryptionNonce!.Value;
        MultiplyTerm(first, firstWeight);
        MultiplyTerm(second, secondWeight);

        return new EncryptedValue
        {
            Alpha = alpha.Value,
            Beta = beta.Value,
            EncryptionNonce = nonce,
        };

        void MultiplyTerm(EncryptedSupplementalField? field, int weight)
        {
            if (field is null)
            {
                return;
            }

            if (weight == 1)
            {
                alpha.Multiply(field.Alpha);
                beta.Multiply(field.Beta);
            }
            else
            {
                alpha.MultiplyPower(field.Alpha, weight);
                beta.MultiplyPower(field.Beta, weight);
            }

            nonce += weight * field.EncryptionNonce!.Value;
        }
    }

    private EncryptedSelection EncryptSelection(Contest contest, Choice choice, int selectionValue, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce)
    {
        var encryptedValue = EncryptContestValue(selectionValue, selectionEncryptionIdentifierHash, ballotNonce, contest.Index, choice.Index);
        var proofs = GenerateProofs(selectionValue, 0, contest.OptionSelectionLimit, encryptedValue, _encryptionRecord.ElectionPublicKeys, selectionEncryptionIdentifierHash, contest.Index, choice.Index);

        var selection = new EncryptedSelection
        {
            ChoiceId = choice.Id,
            Alpha = encryptedValue.Alpha,
            Beta = encryptedValue.Beta,
            EncryptionNonce = encryptedValue.EncryptionNonce,
            Proofs = proofs,
        };

        // In theory we can decrypt this value with the encryption nonce if we have encrypted it properly.
        // See 3.3.1

        return selection;
    }

    /// <summary>
    /// A supplemental field is encrypted exactly as an option is: nonce xi_{i,j} with its own option
    /// index j (eq. 33), and a range proof over 0..its bound (eqs. 57-61) whose challenge hashes j
    /// (eq. 59). The bound is 1 for an indicator, L for the undervote difference count and the
    /// number of write-in fields for the write-in count (§3.3.9; user decision Q2).
    /// </summary>
    private EncryptedSupplementalField EncryptSupplementalField(Contest contest, SupplementalField field, int value, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce)
    {
        var encryptedValue = EncryptContestValue(value, selectionEncryptionIdentifierHash, ballotNonce, contest.Index, field.Index);
        var proofs = GenerateProofs(value, 0, contest.RangeBound(field), encryptedValue, _encryptionRecord.ElectionPublicKeys, selectionEncryptionIdentifierHash, contest.Index, field.Index);

        return new EncryptedSupplementalField
        {
            FieldId = field.Id,
            Alpha = encryptedValue.Alpha,
            Beta = encryptedValue.Beta,
            EncryptionNonce = encryptedValue.EncryptionNonce,
            Proofs = proofs,
        };
    }

    private EncryptedValue EncryptContestValue(int valueToEncrypt, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce, int contestIndex, int optionIndex)
    {
        IntegerModQ encryptionNonce = new EncryptionNonce(selectionEncryptionIdentifierHash, ballotNonce, contestIndex, optionIndex);
        var alpha = MontgomeryModP.PowModP(EGParameters.G, encryptionNonce);
        var beta = MontgomeryModP.PowModP(_encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, encryptionNonce + valueToEncrypt);
        return new EncryptedValue
        {
            Alpha = alpha,
            Beta = beta,
            EncryptionNonce = encryptionNonce,
        };
    }

    /// <summary>
    /// The disjunctive Chaum-Pedersen range proof of §3.3.7 (eqs. 57-61) that
    /// <paramref name="encryptedValue"/> encrypts <paramref name="valueToEncrypt"/>, one of the
    /// values <paramref name="firstValue"/>..<paramref name="lastValue"/>. The challenge is
    /// c = H_q(H_I; 0x24, ind_c, [ind_o,] alpha, beta, a_first, b_first, ..., a_last, b_last): eq. (59)
    /// with an option index, eq. (62) without one (the contest selection-limit proof).
    /// <paramref name="firstValue"/> is 0 except for the one-value proof of the undervote difference
    /// relation (Note 3.4). <paramref name="weight"/>, when given, is hashed as b(weight, 4) after the
    /// option index: the null-vote relation's format.
    /// </summary>
    private ChallengeResponsePair[] GenerateProofs(
        int valueToEncrypt,
        int firstValue,
        int lastValue,
        EncryptedValue encryptedValue,
        ElectionPublicKeys electionPublicKeys,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        int contestIndex,
        int? optionIndex,
        int? weight = null)
    {
        List<(IntegerModQ u, IntegerModP a, IntegerModP b, IntegerModQ? cj)> commitments = new();

        for (int i = firstValue; i <= lastValue; i++)
        {
            var keyPair = KeyPair.GenerateRandom();
            IntegerModQ u = keyPair.SecretKey;
            IntegerModP a = keyPair.PublicKey;

            IntegerModP b;
            IntegerModQ? cj = null;
            if (valueToEncrypt == i)
            {
                b = MontgomeryModP.PowModP(electionPublicKeys.VoteEncryptionKey, u);
            }
            else
            {
                cj = ElectionGuardRandom.GetIntegerModQ();
                var t = u + (valueToEncrypt - i) * cj.Value;
                b = MontgomeryModP.PowModP(electionPublicKeys.VoteEncryptionKey, t);
            }
            commitments.Add((u, a, b, cj));
        }

        List<byte[]> bytesToHash = [
            [0x24],
            contestIndex.ToByteArray()];

        if(optionIndex != null)
        {
            bytesToHash.Add(optionIndex.Value.ToByteArray());
        }

        if (weight != null)
        {
            bytesToHash.Add(weight.Value.ToByteArray());
        }

        bytesToHash.AddRange([
            encryptedValue.Alpha,
            encryptedValue.Beta]);

        foreach (var commitment in commitments)
        {
            bytesToHash.Add(commitment.a);
            bytesToHash.Add(commitment.b);
        }

        var c = EGHash.HashModQ(selectionEncryptionIdentifierHash, bytesToHash.ToArray());
        IntegerModQ cSum = new IntegerModQ();
        foreach (var commitment in commitments)
        {
            if (commitment.cj != null)
            {
                cSum += commitment.cj.Value;
            }
        }
        var cl = c - cSum;

        IEnumerable<(IntegerModQ challenge, IntegerModQ response)> challengeResponsePairs = commitments
            .Select(x => (x.cj ?? cl, x.u - (x.cj ?? cl) * encryptedValue.EncryptionNonce!.Value));

        return challengeResponsePairs.Select(x => new ChallengeResponsePair
        {
            Challenge = x.challenge,
            Response = x.response,
        }).ToArray();
    }

    private EncryptedData EncryptContestData(string valueToEncrypt, int contestIndex, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce)
    {
        // 3.3.10
        var bytes = Encoding.UTF8.GetBytes(valueToEncrypt);
        var encryptionNonce = EGHash.HashModQ(selectionEncryptionIdentifierHash,
            [0x25],
            contestIndex.ToByteArray(),
            ballotNonce);

        var alpha = MontgomeryModP.PowModP(EGParameters.G, encryptionNonce);
        var beta = MontgomeryModP.PowModP(_encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey, encryptionNonce);
        var secretKey = EGHash.Hash(selectionEncryptionIdentifierHash,
            [0x26],
            contestIndex.ToByteArray(),
            alpha,
            beta);

        List<byte[]> encryptedBlocks = new();

        for (int i = 0; i <= bytes.Length; i += 32)
        {
            int endOfSpan = i + 32;
            if(endOfSpan > bytes.Length)
            {
                endOfSpan = bytes.Length;
            }

            var di = bytes[i..endOfSpan];
            
            // Right pad any remaining bytes.
            if(di.Length < 32)
            {
                var ndi = new byte[32];
                di.CopyTo(ndi, 0);
                di = ndi;
            }

            var ki = EGHash.Hash(secretKey,
                i.ToByteArray(),
                Encoding.UTF8.GetBytes("data_enc_keys"),
                [0x00],
                Encoding.UTF8.GetBytes("contest_data"),
                contestIndex.ToByteArray(),
                (i * 256).ToByteArray());

            var encryptedBlock = di.XOR(ki);
            encryptedBlocks.Add(encryptedBlock);
        }

        var c0 = alpha;
        var c1 = ByteArrayExtensions.Concat(encryptedBlocks.ToArray());

        var proofKeyPair = KeyPair.GenerateRandom();
        var challenge = EGHash.HashModQ(selectionEncryptionIdentifierHash,
            [0x27],
            contestIndex.ToByteArray(),
            proofKeyPair.PublicKey,
            c0,
            c1);
        var response = proofKeyPair.SecretKey - challenge * encryptionNonce;

        return new EncryptedData
        {
            C0 = c0,
            C1 = c1,
            Challenge = challenge,
            Response = response,
        };
    }
}

public class EncryptedData
{
    public required byte[] C0 { get; init; }
    public required byte[] C1 { get; init; }
    public required IntegerModQ Challenge { get; init; }
    public required IntegerModQ Response { get; init; }
}