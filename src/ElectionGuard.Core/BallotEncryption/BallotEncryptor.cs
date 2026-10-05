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
    /// (neutralized) sum of selections and number of write-ins:
    /// <list type="bullet">
    /// <item>Overvote indicator: 1 when the contest was overvoted (p.38).</item>
    /// <item>Null-vote indicator: 1 when the sum is 0 and the contest was not overvoted (p.39 "When
    /// all the selections are set to zero as a consequence of an overvote, the null vote indicator
    /// should be set to zero"; user decision Q3).</item>
    /// <item>Undervote indicator: 1 when the sum is below L (p.38).</item>
    /// <item>Undervote difference count: L - sum (p.38: "the difference between the contest
    /// selection limit ... and the undervote difference count exactly matches the sum").</item>
    /// <item>Write-in count: the number of write-in fields used (p.39).</item>
    /// </list>
    /// On an overvote the sum is the neutralized sum, 0, so the undervote indicator is 1 and the
    /// difference L.
    /// <list type="bullet">
    /// <item>The difference count has no other choice: L - sum is negative for the voter's
    /// original sum, which no field can hold, and the implemented relation L - u = the sum the
    /// selection-limit proof sees needs L.</item>
    /// <item>The undervote indicator is where the spec contradicts itself. §3.1.3 p.18 and §3.3.9
    /// p.38 define it by the voter's sum ("strictly less than the contest selection limit"), which
    /// gives 0 on an overvote. p.38's disjunctive proof (indicator 0 and sum = L, or indicator 1 and
    /// sum in 0..L-1) can only be satisfied with 1 on the neutralized selections. We follow the
    /// proof, as p.39 shows happening to the null-vote indicator ("Providing such a proof forces
    /// setting the null vote indicator to one for every overvote ballot as well") before overriding
    /// it there ("should be set to zero"); p.38 gives no such override for the undervote indicator.
    /// That proof is not implemented (Q2), and the indicator has only its 0..1 range proof, so 0
    /// would verify too. The value moves published undervote totals, not bytes; it is open S5 user
    /// question 4, and the tests that pin it are marked DECISION-DEPENDENT PIN.</item>
    /// </list>
    /// </summary>
    private static int SupplementalValue(SupplementalFieldKind kind, int limit, int sum, int writeIns, bool isOvervote)
    {
        return kind switch
        {
            SupplementalFieldKind.OvervoteIndicator => isOvervote ? 1 : 0,
            SupplementalFieldKind.NullVoteIndicator => !isOvervote && sum == 0 ? 1 : 0,
            SupplementalFieldKind.UndervoteIndicator => sum < limit ? 1 : 0,
            SupplementalFieldKind.UndervoteDifferenceCount => limit - sum,
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

        // The "sum of the selections" every rule below is about: the selectable options, plus the
        // write-in count when the manifest says it counts toward the selection limit (§3.1.3 p.19,
        // §3.3.9 p.39). Summed in long, so that no plaintext can wrap it below L.
        var writeInField = manifestContest.SupplementalFieldOfKind(SupplementalFieldKind.WriteInCount);
        bool writeInsCount = writeInField is not null && manifestContest.SelectionLimitWeight(writeInField) == 1;
        int writeIns = contest.NumWriteinsSelected;
        long sum = writeInsCount ? writeIns : 0;
        bool anyOptionOverLimit = false;
        foreach (var choice in choicesInManifestOrder)
        {
            sum += choice.SelectionValue;
            anyOptionOverLimit |= choice.SelectionValue > optionLimit;
        }

        // §3.3.5 p.31, §3.1.3 pp.17-18, §3.3.9 p.38: the contest is overvoted when the sum exceeds the
        // contest selection limit L, or when one option's value exceeds the option selection limit R.
        // Then every selectable option is encrypted as 0 "to not affect the election tallies". The
        // write-ins used go too: the contest's votes are invalid as a whole (p.31), and a counted
        // write-in count left in place would make the selection-limit proof unprovable.
        bool isOvervote = sum > limit || anyOptionOverLimit;
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

        // One encryption per selectable option, each with its own nonce xi_{i,j} (eq. 33) and range
        // proof over 0..R (eqs. 57-61).
        var encryptedSelections = new List<EncryptedSelection>(manifestContest.Choices.Count);
        var limitAlpha = new ModPProduct(1);
        var limitBeta = new ModPProduct(1);
        IntegerModQ sumNonce = 0;
        for (int i = 0; i < choicesInManifestOrder.Length; i++)
        {
            var manifestChoice = manifestContest.Choices[i];
            var encryptedSelection = EncryptSelection(manifestContest, manifestChoice, choicesInManifestOrder[i].SelectionValue, selectionEncryptionIdentifierHash, ballotNonce);
            encryptedSelections.Add(encryptedSelection);
            limitAlpha.Multiply(encryptedSelection.Alpha);
            limitBeta.Multiply(encryptedSelection.Beta);
            sumNonce += encryptedSelection.EncryptionNonce!.Value;
        }

        // One encryption per declared supplemental field, in manifest order, under its own option
        // index (§3.1.3 p.19: "treated like and listed with the option selection fields").
        var encryptedFields = new List<EncryptedSupplementalField>(manifestContest.SupplementalFields.Count);
        EncryptedSupplementalField? overvoteField = null;
        EncryptedSupplementalField? undervoteDifferenceField = null;
        foreach (var field in manifestContest.SupplementalFields)
        {
            int value = SupplementalValue(field.Kind, limit, neutralizedSum, writeIns, isOvervote);
            var encryptedField = EncryptSupplementalField(manifestContest, field, value, selectionEncryptionIdentifierHash, ballotNonce);
            encryptedFields.Add(encryptedField);

            if (field.Kind == SupplementalFieldKind.OvervoteIndicator)
            {
                overvoteField = encryptedField;
            }
            else if (field.Kind == SupplementalFieldKind.UndervoteDifferenceCount)
            {
                undervoteDifferenceField = encryptedField;
            }
            else if (manifestContest.SelectionLimitWeight(field) == 1)
            {
                // A counted write-in count is part of the sum.
                limitAlpha.Multiply(encryptedField.Alpha);
                limitBeta.Multiply(encryptedField.Beta);
                sumNonce += encryptedField.EncryptionNonce!.Value;
            }
        }

        // The encryption of the sum, (prod alpha_i, prod beta_i) over the options and counted fields,
        // with nonce sum xi_i. It is the aggregate of eq. (62) when no field counts.
        var sumCiphertext = new EncryptedValue
        {
            Alpha = limitAlpha.Value,
            Beta = limitBeta.Value,
            EncryptionNonce = sumNonce,
        };

        // §3.3.8 eq. (62) and §3.3.9 p.39: the selection-limit proof shows that the sum plus L times
        // the overvote indicator lies in 0..L (footnote 42: the indicator's ciphertext raised to L).
        // The exponent L is a small public number, so it is raised with a window over its own bits.
        var limitCiphertext = sumCiphertext;
        int limitValue = neutralizedSum;
        if (overvoteField is not null)
        {
            limitAlpha.MultiplyPower(overvoteField.Alpha, limit);
            limitBeta.MultiplyPower(overvoteField.Beta, limit);
            limitCiphertext = new EncryptedValue
            {
                Alpha = limitAlpha.Value,
                Beta = limitBeta.Value,
                EncryptionNonce = sumNonce + limit * overvoteField.EncryptionNonce!.Value,
            };
            limitValue += limit * (isOvervote ? 1 : 0);
        }

        var proofs = GenerateProofs(limitValue, 0, limit, limitCiphertext, _encryptionRecord.ElectionPublicKeys, selectionEncryptionIdentifierHash, manifestContest.Index, optionIndex: null);

        // §3.3.9 p.38: L - u equals the sum, i.e. (sum ciphertext) * (u's ciphertext) encrypts exactly
        // L. Proved with the range proof of eqs. (57)-(61) over the singleton set {L} (Note 3.4): one
        // commitment (a, b) = (g^u, K^u), c = H_q(H_I; 0x24, ind_c, ind_o(u), alpha, beta, a, b) with
        // (alpha, beta) the product ciphertext and ind_o(u) the undervote difference field's option
        // index, c_L = c and v = u - c * xi. NOT spec-defined: §3.3.9 says such proofs "are not
        // described in detail", so this challenge is this implementation's own and is not
        // interoperable.
        ChallengeResponsePair[]? undervoteDifferenceProof = null;
        if (undervoteDifferenceField is not null)
        {
            var undervoteDifferenceIndex = manifestContest.SupplementalFieldOfKind(SupplementalFieldKind.UndervoteDifferenceCount)!.Index;
            var relationAlpha = new ModPProduct(sumCiphertext.Alpha);
            var relationBeta = new ModPProduct(sumCiphertext.Beta);
            relationAlpha.Multiply(undervoteDifferenceField.Alpha);
            relationBeta.Multiply(undervoteDifferenceField.Beta);
            var relationCiphertext = new EncryptedValue
            {
                Alpha = relationAlpha.Value,
                Beta = relationBeta.Value,
                EncryptionNonce = sumNonce + undervoteDifferenceField.EncryptionNonce!.Value,
            };
            undervoteDifferenceProof = GenerateProofs(limit, limit, limit, relationCiphertext, _encryptionRecord.ElectionPublicKeys, selectionEncryptionIdentifierHash, manifestContest.Index, undervoteDifferenceIndex);
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
            ContestData = encryptedContestData,
            ContestHash = contestHash,
        };

        return encryptedContest;
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
    /// relation (Note 3.4).
    /// </summary>
    private ChallengeResponsePair[] GenerateProofs(
        int valueToEncrypt,
        int firstValue,
        int lastValue,
        EncryptedValue encryptedValue,
        ElectionPublicKeys electionPublicKeys,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        int contestIndex,
        int? optionIndex)
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