using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.BallotEncryption;

public class BallotEncryptorTests
{
    public BallotEncryptorTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static (ElectionFixtureBuilder.GuardianSetResult GuardianSet, Manifest Manifest, ElectionFixtureBuilder.EncryptionRecordResult EncryptionRecordResult) BuildEncryptionRecord(
        bool includeWriteIns = false,
        ChainingMode chainingMode = ChainingMode.None,
        int optionSelectionLimit = 1,
        int selectionLimit = 1)
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns, chainingMode, optionSelectionLimit, selectionLimit);
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        return (guardianSet, manifest, encryptionRecordResult);
    }

    // Mirrors SelectionEncryptionsWellFormedVerification's disjunctive Chaum-Pedersen
    // recomputation (Verification 6), exercised here at the BallotEncryptor level as a self-check
    // that Encrypt() always produces spec-valid proofs: for selections and for the supplemental
    // fields alike, each under its own option index (eq. 59), and for the contest proof (eq. 62,
    // optionIndex null).
    private static void AssertProofIsWellFormed(
        EncryptedValueWithProofs value,
        int selectionOrOptionLimit,
        int contestIndex,
        int? choiceIndex,
        EncryptedBallot ballot,
        EncryptionRecord encryptionRecord)
    {
        Assert.Equal(selectionOrOptionLimit + 1, value.Proofs.Length);

        var calculatedValues = new List<(IntegerModP a, IntegerModP b)>();
        for (int i = 0; i < value.Proofs.Length; i++)
        {
            var pair = value.Proofs[i];
            var a = IntegerModP.PowModP(encryptionRecord.CryptographicParameters.G, pair.Response)
                * IntegerModP.PowModP(value.Alpha, pair.Challenge);
            var w = pair.Response - i * pair.Challenge;
            var b = IntegerModP.PowModP(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, w)
                * IntegerModP.PowModP(value.Beta, pair.Challenge);
            calculatedValues.Add((a, b));
        }

        var bytesToHash = new List<byte[]> { new byte[] { 0x24 }, contestIndex.ToByteArray() };
        if (choiceIndex != null)
        {
            bytesToHash.Add(choiceIndex.Value.ToByteArray());
        }
        bytesToHash.Add(value.Alpha);
        bytesToHash.Add(value.Beta);
        foreach (var (a, b) in calculatedValues)
        {
            bytesToHash.Add(a);
            bytesToHash.Add(b);
        }

        var c = EGHash.HashModQ(ballot.SelectionEncryptionIdentifierHash, bytesToHash.ToArray());
        var sumC = value.Proofs.Select(x => x.Challenge).Sum();

        Assert.Equal(c, sumC);
    }

    /// <summary>
    /// §3.1.3 p.19: a supplemental field's option index continues after the options, in declaration
    /// order. Derived from positions here rather than read back from the manifest's Index fields.
    /// </summary>
    private static int FieldIndex(Contest manifestContest, SupplementalFieldKind kind) =>
        manifestContest.Choices.Count + 1 + manifestContest.SupplementalFields.FindIndex(field => field.Kind == kind);

    /// <summary>The field's ciphertext is (g^xi, K^(value + xi)) for its nonce xi.</summary>
    private static void AssertEncrypts(EncryptedValueWithProofs field, int value, IntegerModP voteEncryptionKey)
    {
        var nonce = field.EncryptionNonce!.Value;
        Assert.Equal(IntegerModP.PowModP(voteEncryptionKey, nonce + value), field.Beta);
    }

    [Fact]
    public void Encrypt_SelectionCiphertexts_AreValidElGamalCiphertexts()
    {
        var (guardianSet, manifest, encryptionRecordResult) = BuildEncryptionRecord();
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");

        var selectionValues = new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 0 };
        var ballot = ElectionFixtureBuilder.CreateBallot(manifest, selectionValuesByChoiceId: selectionValues);

        var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot);

        var contest = encryptedBallot.Contests.Single();
        var q = encryptionRecordResult.EncryptionRecord.CryptographicParameters.Q;
        foreach (var selection in contest.Choices)
        {
            // Subgroup membership (mirrors 6.A's VerifyIsInZpr): value^Q == 1 mod P.
            Assert.Equal(new IntegerModP(1), IntegerModP.PowModP(selection.Alpha, q));
            Assert.Equal(new IntegerModP(1), IntegerModP.PowModP(selection.Beta, q));

            var nonce = selection.EncryptionNonce!.Value;
            var expectedValue = selectionValues[selection.ChoiceId];

            Assert.Equal(
                IntegerModP.PowModP(encryptionRecordResult.EncryptionRecord.CryptographicParameters.G, nonce),
                selection.Alpha);
            Assert.Equal(
                IntegerModP.PowModP(guardianSet.ElectionPublicKeys.VoteEncryptionKey, nonce + expectedValue),
                selection.Beta);
        }
    }

    [Fact]
    public void Encrypt_DisjunctiveChaumPedersenProof_SelectionIsWellFormed_ForEachSelection()
    {
        var (_, manifest, encryptionRecordResult) = BuildEncryptionRecord();
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");
        var ballot = ElectionFixtureBuilder.CreateBallot(manifest, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 });

        var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot);

        var contest = encryptedBallot.Contests.Single();
        var manifestContest = manifest.Contests.Single();
        foreach (var selection in contest.Choices)
        {
            // §3.1.3: the indices hashed are the 1-based list positions, derived here from the
            // position rather than read back from the manifest's own Index fields.
            var choiceIndex = manifestContest.Choices.FindIndex(c => c.Id == selection.ChoiceId) + 1;
            var contestIndex = manifest.Contests.IndexOf(manifestContest) + 1;
            AssertProofIsWellFormed(
                selection, manifestContest.OptionSelectionLimit, contestIndex, choiceIndex,
                encryptedBallot, encryptionRecordResult.EncryptionRecord);
        }
    }

    [Fact]
    public void Encrypt_OvervoteCounter_ProofIsWellFormed()
    {
        var (guardianSet, manifest, encryptionRecordResult) = BuildEncryptionRecord();
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-2");
        var k = guardianSet.ElectionPublicKeys.VoteEncryptionKey;

        // SelectionLimit=1/OptionSelectionLimit=1 (defaults) but both choices selected -> overvote.
        var ballot = ElectionFixtureBuilder.CreateBallot(
            manifest, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 1 });

        var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-2", deviceHash, ballot);

        var contest = encryptedBallot.Contests.Single();
        var manifestContest = manifest.Contests.Single();

        // G3: the overvote indicator's proof challenge hashes its own option index (here 3, after
        // the two options), as every option's does.
        var overvote = contest.Field(SupplementalFieldKind.OvervoteIndicator);
        AssertProofIsWellFormed(
            overvote, 1, manifestContest.Index, FieldIndex(manifestContest, SupplementalFieldKind.OvervoteIndicator), encryptedBallot, encryptionRecordResult.EncryptionRecord);

        // Secondary observable: the overvote counter's plaintext value must actually be 1 (true).
        AssertEncrypts(overvote, 1, k);

        // Per spec, selections themselves are re-encrypted as zero once an overvote is detected.
        Assert.All(contest.Choices, c => AssertEncrypts(c, 0, k));

        // §3.3.9 p.39 and user decisions Q3, Q11 and Q15: on an overvote the null-vote and undervote
        // indicators are 0 ("if a contest is an overvote, it is not an undervote"), and the
        // undervote difference count is 0, since s + w + L*overvote + u = L with s = w = 0 and the
        // overvote indicator 1. (S5 had the indicator 1 and the difference L, computed on the
        // neutralized sum; before S5 the counter was L minus the number of nonzero options before
        // neutralization, clamped at 0.)
        AssertEncrypts(contest.Field(SupplementalFieldKind.NullVoteIndicator), 0, k);
        AssertEncrypts(contest.Field(SupplementalFieldKind.UndervoteIndicator), 0, k);
        var difference = contest.Field(SupplementalFieldKind.UndervoteDifferenceCount);
        AssertProofIsWellFormed(
            difference, manifestContest.SelectionLimit, manifestContest.Index, FieldIndex(manifestContest, SupplementalFieldKind.UndervoteDifferenceCount),
            encryptedBallot, encryptionRecordResult.EncryptionRecord);
        AssertEncrypts(difference, 0, k);
    }

    [Fact]
    public void Encrypt_UndervoteCounter_ProofIsWellFormed()
    {
        var (guardianSet, manifest, encryptionRecordResult) = BuildEncryptionRecord(selectionLimit: 2);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-3");
        var k = guardianSet.ElectionPublicKeys.VoteEncryptionKey;

        // SelectionLimit=2 but only 1 of 2 choices selected -> an undervote by exactly 1, and (since
        // a choice was actually selected) not also a null vote.
        var ballot = ElectionFixtureBuilder.CreateBallot(
            manifest, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 });

        var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-3", deviceHash, ballot);

        var contest = encryptedBallot.Contests.Single();
        var manifestContest = manifest.Contests.Single();

        // The undervote difference count ranges over 0..L (user decision Q2).
        var difference = contest.Field(SupplementalFieldKind.UndervoteDifferenceCount);
        AssertProofIsWellFormed(
            difference, manifestContest.SelectionLimit, manifestContest.Index, FieldIndex(manifestContest, SupplementalFieldKind.UndervoteDifferenceCount),
            encryptedBallot, encryptionRecordResult.EncryptionRecord);
        AssertEncrypts(difference, 1, k);

        var indicator = contest.Field(SupplementalFieldKind.UndervoteIndicator);
        AssertProofIsWellFormed(
            indicator, 1, manifestContest.Index, FieldIndex(manifestContest, SupplementalFieldKind.UndervoteIndicator),
            encryptedBallot, encryptionRecordResult.EncryptionRecord);
        AssertEncrypts(indicator, 1, k);

        // Secondary observable: this scenario is exclusively an undervote, not also a null vote.
        AssertEncrypts(contest.Field(SupplementalFieldKind.NullVoteIndicator), 0, k);
    }

    [Fact]
    public void Encrypt_NullvoteCounter_ProofIsWellFormed()
    {
        var (guardianSet, manifest, encryptionRecordResult) = BuildEncryptionRecord();
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-4");

        // Entirely blank contest -> null vote.
        var ballot = ElectionFixtureBuilder.CreateBallot(manifest);

        var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-4", deviceHash, ballot);

        var contest = encryptedBallot.Contests.Single();
        var manifestContest = manifest.Contests.Single();

        var nullVote = contest.Field(SupplementalFieldKind.NullVoteIndicator);
        AssertProofIsWellFormed(
            nullVote, 1, manifestContest.Index, FieldIndex(manifestContest, SupplementalFieldKind.NullVoteIndicator), encryptedBallot, encryptionRecordResult.EncryptionRecord);

        AssertEncrypts(nullVote, 1, guardianSet.ElectionPublicKeys.VoteEncryptionKey);
    }

    [Fact]
    public void Encrypt_WriteInCounter_ProofIsWellFormed()
    {
        var (guardianSet, manifest, encryptionRecordResult) = BuildEncryptionRecord(includeWriteIns: true);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-5");

        var ballot = ElectionFixtureBuilder.CreateBallot(manifest, numWriteinsSelected: 1, contestData: "Write-In Candidate");

        var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-5", deviceHash, ballot);

        var contest = encryptedBallot.Contests.Single();
        var manifestContest = manifest.Contests.Single();

        // G22: the write-in count ranges over 0..the number of write-in fields (§3.3.9 p.39), not
        // 0..L; the fixture offers one write-in field.
        var writeIns = contest.Field(SupplementalFieldKind.WriteInCount);
        AssertProofIsWellFormed(
            writeIns, manifestContest.WriteInFieldCount, manifestContest.Index, FieldIndex(manifestContest, SupplementalFieldKind.WriteInCount),
            encryptedBallot, encryptionRecordResult.EncryptionRecord);

        AssertEncrypts(writeIns, 1, guardianSet.ElectionPublicKeys.VoteEncryptionKey);

        Assert.NotNull(contest.ContestData);
        Assert.NotEmpty(contest.ContestData!.C0);
        // "Write-In Candidate" is 18 UTF-8 bytes -- exactly one 32-byte block once right-padded, so
        // C1 (the XOR of that padded block with the derived keystream) must be exactly 32 bytes,
        // not merely non-empty.
        Assert.Equal(32, contest.ContestData!.C1.Length);

        // Assertion-quality strengthening: algebraically verify the contest-data ciphertext's
        // Schnorr proof of knowledge (BallotEncryptor.EncryptContestData) instead of only checking
        // C0/C1 are non-empty. Recompute the commitment from (response, c0, challenge) and confirm
        // hashing it alongside c0/c1 reproduces the stored challenge -- this would fail under a
        // sign flip in `response`, a swapped hash input, or a wrong base/exponent.
        var contestData = contest.ContestData!;
        var recomputedCommitment = IntegerModP.PowModP(encryptionRecordResult.EncryptionRecord.CryptographicParameters.G, contestData.Response)
            * IntegerModP.PowModP(new IntegerModP(contestData.C0), contestData.Challenge);
        var expectedChallenge = EGHash.HashModQ(
            encryptedBallot.SelectionEncryptionIdentifierHash,
            new byte[] { 0x27 },
            manifestContest.Index.ToByteArray(),
            recomputedCommitment,
            contestData.C0,
            contestData.C1);
        Assert.Equal(expectedChallenge, contestData.Challenge);
    }

    [Fact]
    public void Encrypt_FirstBallotOnDevice_PreviousConfirmationCodeNull_FoldsInRealChainingField()
    {
        // ConfirmationCode's constructor now folds its ChainingField parameter into the hash (§3.4.2
        // formula (71): HC = H(HI; 0x29, chi_1,...,chi_mB, BC)), so the ConfirmationCode
        // BallotEncryptor produces must be computed with the REAL ChainingField for this ballot
        // (ChainingMode.None -> BC = 0x00000000 || HDI, see Models/ChainingField.cs), not with a
        // bare null chaining field.
        var (_, manifest, encryptionRecordResult) = BuildEncryptionRecord(chainingMode: ChainingMode.None);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-6");
        var ballot = ElectionFixtureBuilder.CreateBallot(manifest, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 });

        var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-6", deviceHash, ballot, previousConfirmationCode: null);

        var realChainingField = new ChainingField(ChainingMode.None, deviceHash, encryptionRecordResult.ExtendedBaseHash, null);
        var expectedConfirmationCode = new ConfirmationCode(
            encryptedBallot.SelectionEncryptionIdentifierHash,
            encryptedBallot.Contests.Select(c => c.ContestHash),
            realChainingField);

        Assert.Equal(expectedConfirmationCode, encryptedBallot.ConfirmationCode);
    }

    [Fact]
    public void Encrypt_SecondBallotOnDevice_ChainingAffectsConfirmationCode()
    {
        // Was GENUINE BUG #7 (now fixed): because ConfirmationCode's constructor used to ignore its
        // ChainingField? parameter, the previousConfirmationCode argument to
        // BallotEncryptor.Encrypt had zero observable effect on the resulting
        // EncryptedBallot.ConfirmationCode. Now that ConfirmationCode folds the chaining field into
        // the hash (and ChainingField itself correctly threads the previous confirmation code
        // through per §3.4.4 formula (76)), the second ballot's confirmation code genuinely depends
        // on the first ballot's confirmation code: recomputing it with the real prior code matches
        // what BallotEncryptor produced, while recomputing it as if this were the FIRST ballon on
        // the device (no previous code, so ChainingField takes the H0-initialization branch instead)
        // produces a different value.
        var (_, manifest, encryptionRecordResult) = BuildEncryptionRecord(chainingMode: ChainingMode.Simple);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-7");
        var ballot1 = ElectionFixtureBuilder.CreateBallot(manifest, ballotId: "ballot-1", selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 });
        var ballot2 = ElectionFixtureBuilder.CreateBallot(manifest, ballotId: "ballot-2", selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-2"] = 1 });

        var encryptedBallot1 = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-7", deviceHash, ballot1, previousConfirmationCode: null);

        var encryptedBallot2 = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-7", deviceHash, ballot2, previousConfirmationCode: encryptedBallot1.ConfirmationCode);

        var contestHashes = encryptedBallot2.Contests.Select(c => c.ContestHash).ToList();

        var chainingFieldWithRealPrevious = new ChainingField(
            ChainingMode.Simple, deviceHash, encryptionRecordResult.ExtendedBaseHash, encryptedBallot1.ConfirmationCode);
        var chainingFieldAsIfFirstBallot = new ChainingField(
            ChainingMode.Simple, deviceHash, encryptionRecordResult.ExtendedBaseHash, previousConfirmationCode: null);

        var codeWithRealChaining = new ConfirmationCode(encryptedBallot2.SelectionEncryptionIdentifierHash, contestHashes, chainingFieldWithRealPrevious);
        var codeAsIfFirstBallot = new ConfirmationCode(encryptedBallot2.SelectionEncryptionIdentifierHash, contestHashes, chainingFieldAsIfFirstBallot);

        Assert.NotEqual(codeWithRealChaining, codeAsIfFirstBallot);
        Assert.Equal(codeWithRealChaining, encryptedBallot2.ConfirmationCode);
    }

    [Fact]
    public void Encrypt_InvalidManifestReference_ThrowsException()
    {
        var (_, manifest, encryptionRecordResult) = BuildEncryptionRecord();
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-8");

        var ballot = new Ballot
        {
            Id = "ballot-bad",
            BallotStyleId = manifest.BallotStyles.Single().Id,
            Contests = new List<BallotContest>
            {
                new BallotContest
                {
                    Id = "not-a-real-contest",
                    Choices = new List<BallotChoice>
                    {
                        new BallotChoice { Id = "choice-1", SelectionValue = 0 },
                        new BallotChoice { Id = "choice-2", SelectionValue = 0 },
                    },
                    NumWriteinsSelected = 0,
                },
            },
        };

        var encryptor = new BallotEncryptor(encryptionRecordResult.EncryptionRecord, "device-8", deviceHash);

        Assert.Throws<InvalidBallotException>(() => encryptor.Encrypt(ballot, null));
    }

    [Fact]
    public void Encrypt_BallotStyleMismatch_ThrowsException()
    {
        var (_, manifest, encryptionRecordResult) = BuildEncryptionRecord();
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-9");

        var ballot = ElectionFixtureBuilder.CreateBallot(manifest) with { BallotStyleId = "not-a-real-ballot-style" };

        var encryptor = new BallotEncryptor(encryptionRecordResult.EncryptionRecord, "device-9", deviceHash);

        Assert.Throws<InvalidBallotException>(() => encryptor.Encrypt(ballot, null));
    }

    [Fact]
    public void Encrypt_ChoiceCountMismatch_ThrowsException()
    {
        var (_, manifest, encryptionRecordResult) = BuildEncryptionRecord();
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-10");

        var ballot = ElectionFixtureBuilder.CreateBallot(manifest);
        var originalContest = ballot.Contests.Single();
        var tamperedContest = originalContest with { Choices = originalContest.Choices.Take(1).ToList() };
        var tamperedBallot = ballot with { Contests = new List<BallotContest> { tamperedContest } };

        var encryptor = new BallotEncryptor(encryptionRecordResult.EncryptionRecord, "device-10", deviceHash);

        Assert.Throws<InvalidBallotException>(() => encryptor.Encrypt(tamperedBallot, null));
    }

    [Fact]
    public void Encrypt_ChoiceIdMismatch_SameChoiceCount_ThrowsException()
    {
        // MUTATION-GAP REGRESSION: Validate's choice-set check is
        // `manifestChoices.Count != choices.Count || manifestChoices.Except(choices).Any() ||
        // choices.Except(manifestChoices).Any()`. Encrypt_ChoiceCountMismatch_ThrowsException above
        // only exercises the leading Count check (2 vs 1) -- short-circuiting before either Except()
        // clause runs. Empirically verified: removing both Except() clauses (leaving only the Count
        // check) left every existing BallotEncryptor test green. Here the choice COUNT matches (2)
        // but one ID doesn't exist in the manifest, so only the Except() clauses can catch it.
        var (_, manifest, encryptionRecordResult) = BuildEncryptionRecord();
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-11");

        var ballot = ElectionFixtureBuilder.CreateBallot(manifest);
        var originalContest = ballot.Contests.Single();
        var tamperedChoices = new List<BallotChoice>
        {
            originalContest.Choices[0],
            new BallotChoice { Id = "choice-not-in-manifest", SelectionValue = 0 },
        };
        var tamperedContest = originalContest with { Choices = tamperedChoices };
        var tamperedBallot = ballot with { Contests = new List<BallotContest> { tamperedContest } };

        var encryptor = new BallotEncryptor(encryptionRecordResult.EncryptionRecord, "device-11", deviceHash);

        Assert.Throws<InvalidBallotException>(() => encryptor.Encrypt(tamperedBallot, null));
    }

    [Fact]
    public void Encrypt_SelectionValueExceedsOptionSelectionLimit_IsNeutralizedAsAnOvervote()
    {
        // G10 (§3.3.5 p.31, §3.1.3 p.18): a value above the option selection limit R overvotes the
        // contest; it is neutralized, not refused. (Before S5 the encryptor threw
        // InvalidBallotException here.) OptionSelectionLimit defaults to 1, so a raw SelectionValue
        // of 2 overvotes even though nothing else is selected.
        var (guardianSet, manifest, encryptionRecordResult) = BuildEncryptionRecord();
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-12");
        var k = guardianSet.ElectionPublicKeys.VoteEncryptionKey;

        var ballot = ElectionFixtureBuilder.CreateBallot(manifest, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 2 });

        var encryptor = new BallotEncryptor(encryptionRecordResult.EncryptionRecord, "device-12", deviceHash);
        var contest = encryptor.Encrypt(ballot, null).Contests.Single();

        Assert.All(contest.Choices, choice => AssertEncrypts(choice, 0, k));
        AssertEncrypts(contest.Field(SupplementalFieldKind.OvervoteIndicator), 1, k);
        AssertEncrypts(contest.Field(SupplementalFieldKind.NullVoteIndicator), 0, k);
    }

    [Fact]
    public void Encrypt_NegativeSelectionValue_ThrowsException()
    {
        // NO-COVERAGE GAP: same guard as above, negative side of the range
        // (`choice.SelectionValue < 0`).
        var (_, manifest, encryptionRecordResult) = BuildEncryptionRecord();
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-13");

        var ballot = ElectionFixtureBuilder.CreateBallot(manifest, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = -1 });

        var encryptor = new BallotEncryptor(encryptionRecordResult.EncryptionRecord, "device-13", deviceHash);

        Assert.Throws<InvalidBallotException>(() => encryptor.Encrypt(ballot, null));
    }
}
