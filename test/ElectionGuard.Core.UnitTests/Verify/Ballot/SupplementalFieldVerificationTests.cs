using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Testing.Common;
using System.Security.Cryptography;
using System.Text;

namespace ElectionGuard.Core.UnitTests.Verify.Ballot;

/// <summary>
/// Stage S5: supplemental verifiable fields declared per contest (user decisions Q1-Q3; G3, G8, G10,
/// G22). Each field is encrypted under its own nonce xi_{i,j} and option index j, carries a range
/// proof that Verification 6 checks, and enters the contest's selection-limit proof (the overvote
/// indicator L times, a counted write-in count once) and the undervote difference relation, which
/// Verification 7 checks. The encryptor derives every value from the selections and the number of
/// write-ins used, with the spec's overvote rule (sum &gt; L or an option &gt; R).
/// </summary>
public class SupplementalFieldVerificationTests
{
    private const string DeviceId = "device-1";

    public SupplementalFieldVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private sealed record Election(Manifest Manifest, EncryptionRecord Record, VotingDeviceInformationHash DeviceHash)
    {
        public Contest Contest => Manifest.Contests[0];

        public IntegerModP K => Record.ElectionPublicKeys.VoteEncryptionKey;
    }

    /// <summary>
    /// The minimal two-option contest with selection limit L and option selection limit R,
    /// declaring <paramref name="kinds"/> (every kind by default) and offering
    /// <paramref name="writeInFields"/> write-in fields.
    /// </summary>
    private static Election Build(
        int selectionLimit = 1,
        int optionSelectionLimit = 1,
        bool writeInsCount = true,
        int writeInFields = 2,
        IReadOnlyList<SupplementalFieldKind>? kinds = null)
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(
            optionSelectionLimit: optionSelectionLimit,
            selectionLimit: selectionLimit,
            supplementalFields: kinds ?? ElectionFixtureBuilder.AllSupplementalFields,
            writeInFieldCount: writeInFields,
            writeInsCountTowardLimit: writeInsCount);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        return new Election(manifest, records.EncryptionRecord, new VotingDeviceInformationHash(records.ExtendedBaseHash, DeviceId));
    }

    private static readonly SelectionEncryptionIdentifier Identifier = new(SHA256.HashData(Encoding.UTF8.GetBytes("s5-id")));
    private static readonly BallotNonce Nonce = new(SHA256.HashData(Encoding.UTF8.GetBytes("s5-nonce")));

    private static EncryptedBallot Encrypt(Election election, int choice1, int choice2, int writeIns = 0)
    {
        var ballot = ElectionFixtureBuilder.CreateBallot(
            election.Manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = choice1, ["choice-2"] = choice2 },
            numWriteinsSelected: writeIns);
        var encrypted = new BallotEncryptor(election.Record, DeviceId, election.DeviceHash).Encrypt(ballot, null, Identifier, Nonce);
        encrypted.RecordStatus(BallotStatus.Cast);
        return encrypted;
    }

    private static void Verify6(Election election, EncryptedBallot ballot) => new SelectionEncryptionsWellFormedVerification().Verify(ballot, election.Record);

    private static void Verify7(Election election, EncryptedBallot ballot) => new AdherenceToVoteLimitsVerification().Verify(ballot, election.Record);

    private static void Verify8(Election election, EncryptedBallot ballot) => new ConfirmationCodeVerification().Verify(ballot, election.DeviceHash, election.Record, null);

    private static void VerifyAll(Election election, EncryptedBallot ballot)
    {
        Verify6(election, ballot);
        Verify7(election, ballot);
        Verify8(election, ballot);
    }

    /// <summary>The plaintext of a freshly encrypted value, read with its nonce: beta = K^(xi + value).</summary>
    private static int Plaintext(EncryptedValueWithProofs value, IntegerModP k)
    {
        var xi = value.EncryptionNonce!.Value;
        for (int candidate = 0; candidate <= 16; candidate++)
        {
            if (IntegerModP.PowModP(k, xi + candidate) == value.Beta)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException("The value does not encrypt a small count.");
    }

    private static int FieldIndex(Contest contest, SupplementalFieldKind kind) => contest.SupplementalFieldOfKind(kind)!.Index;

    private static EncryptedBallot WithContest(EncryptedBallot ballot, Func<EncryptedContest, EncryptedContest> change) => new()
    {
        Id = ballot.Id,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        BallotStyleId = ballot.BallotStyleId,
        Contests = [change(ballot.Contests[0]), .. ballot.Contests.Skip(1)],
        ConfirmationCode = ballot.ConfirmationCode,
        Weight = ballot.Weight,
        Status = ballot.Status,
        DeviceId = ballot.DeviceId,
    };

    /// <summary>
    /// The field of <paramref name="kind"/> re-encrypted to <paramref name="value"/> under its own
    /// nonce, with a valid range proof over 0..<paramref name="bound"/>: what a dishonest device can
    /// produce for a value inside the field's range.
    /// </summary>
    private static EncryptedSupplementalField Reencrypt(Election election, EncryptedBallot ballot, SupplementalFieldKind kind, int value, int bound)
    {
        var field = ballot.Contests[0].Field(kind);
        var xi = field.EncryptionNonce!.Value;
        var beta = IntegerModP.PowModP(election.K, xi + value);
        return field with
        {
            Beta = beta,
            Proofs = ZeroChallengeRangeProof.Prove(field.Alpha, beta, xi, value, bound, election.K, ballot.SelectionEncryptionIdentifierHash, election.Contest.Index, FieldIndex(election.Contest, kind)),
        };
    }

    // --- Honest ballots: values, the overvote rule (G10), and Verifications 6-8 ----------------

    public static TheoryData<int, int, bool, int, int, int, int[]> HonestCases() => new()
    {
        // L, R, write-ins count, choice-1, choice-2, write-ins, expected
        // [choice-1, choice-2, overvote, null, undervote, difference, write-ins]
        // DECISION-DEPENDENT PIN (open user question 4, option (a)): every overvoted row (overvote
        // entry 1) has undervote indicator 1, following p.38's disjunctive proof on the zeroed
        // selections. Re-pin those undervote entries to 0 if the user picks (b); the difference
        // stays L.
        { 1, 1, true, 0, 0, 0, [0, 0, 0, 1, 1, 1, 0] },
        { 1, 1, true, 1, 0, 0, [1, 0, 0, 0, 0, 0, 0] },
        { 1, 1, true, 1, 1, 0, [0, 0, 1, 0, 1, 1, 0] },
        // G10: L = 1, R = 2: a single 2 is an overvote (sum 2 > L), which the old L * R rule let through.
        { 1, 2, true, 2, 0, 0, [0, 0, 1, 0, 1, 1, 0] },
        { 1, 2, true, 1, 0, 0, [1, 0, 0, 0, 0, 0, 0] },
        // G10: L = 3, R = 3: a total in (L, L * R] is neutralized.
        { 3, 3, true, 2, 2, 0, [0, 0, 1, 0, 1, 3, 0] },
        { 3, 3, true, 3, 0, 0, [3, 0, 0, 0, 0, 0, 0] },
        { 3, 3, true, 1, 1, 0, [1, 1, 0, 0, 1, 1, 0] },
        // G10: one option above R overvotes although the total is within L.
        { 3, 1, true, 2, 0, 0, [0, 0, 1, 0, 1, 3, 0] },
        // Write-ins counted toward the limit: a write-in is a selection.
        { 1, 1, true, 0, 0, 1, [0, 0, 0, 0, 0, 0, 1] },
        { 1, 1, true, 1, 0, 1, [0, 0, 1, 0, 1, 1, 0] },
        { 2, 1, true, 1, 0, 2, [0, 0, 1, 0, 1, 2, 0] },
        { 3, 1, true, 1, 0, 2, [1, 0, 0, 0, 0, 0, 2] },
        // Write-ins not counted: they never overvote, and do not fill the limit.
        { 1, 1, false, 1, 0, 2, [1, 0, 0, 0, 0, 0, 2] },
        // DECISION-DEPENDENT PIN (open user question 2, option (a)): uncounted write-ins are not a
        // selection, so a ballot whose only marks are uncounted write-ins is a null vote. Re-pin the
        // null indicator to 0 if the user picks (b).
        { 1, 1, false, 0, 0, 1, [0, 0, 0, 1, 1, 1, 1] },
        // DECISION-DEPENDENT PIN (open user question 1, option (a)): an overvoted contest's
        // write-in count is zeroed even when it does not count toward the limit (p.31: the
        // contest's votes become invalid). Re-pin the last entry to 2 if the user picks (b).
        { 1, 1, false, 1, 1, 2, [0, 0, 1, 0, 1, 1, 0] },
    };

    [Theory]
    [MemberData(nameof(HonestCases))]
    public void Encrypt_DerivesEveryFieldFromTheSelections_AndTheBallotVerifies(int selectionLimit, int optionSelectionLimit, bool writeInsCount, int choice1, int choice2, int writeIns, int[] expected)
    {
        var election = Build(selectionLimit, optionSelectionLimit, writeInsCount);
        var contest = Encrypt(election, choice1, choice2, writeIns).Contests[0];

        int[] actual =
        [
            Plaintext(contest.Choices[0], election.K),
            Plaintext(contest.Choices[1], election.K),
            Plaintext(contest.Field(SupplementalFieldKind.OvervoteIndicator), election.K),
            Plaintext(contest.Field(SupplementalFieldKind.NullVoteIndicator), election.K),
            Plaintext(contest.Field(SupplementalFieldKind.UndervoteIndicator), election.K),
            Plaintext(contest.Field(SupplementalFieldKind.UndervoteDifferenceCount), election.K),
            Plaintext(contest.Field(SupplementalFieldKind.WriteInCount), election.K),
        ];

        Assert.Equal(expected, actual);
        VerifyAll(election, Encrypt(election, choice1, choice2, writeIns));
    }

    [Fact]
    public void Encrypt_OptionAboveR_IsNotRefused_ButANegativeSelectionIs()
    {
        var election = Build(selectionLimit: 1, optionSelectionLimit: 2);

        var exception = Record.Exception(() => Encrypt(election, 7, 0));
        Assert.Null(exception);
        Assert.Throws<InvalidBallotException>(() => Encrypt(election, -1, 0));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(3)]
    public void Encrypt_WriteInsOutsideTheWriteInFieldCount_AreRefused(int writeIns)
    {
        // G22: the write-in count is validated against the manifest's write-in field count (2 here).
        var election = Build(writeInFields: 2);

        Assert.Throws<InvalidBallotException>(() => Encrypt(election, 0, 0, writeIns));
    }

    [Fact]
    public void Encrypt_WriteInsInAContestThatOffersNone_AreRefused()
    {
        var election = Build(writeInFields: 0, kinds: ElectionFixtureBuilder.DefaultSupplementalFields);

        Assert.Throws<InvalidBallotException>(() => Encrypt(election, 0, 0, 1));
    }

    [Fact]
    public void Encrypt_OnlyTheDeclaredFields_InManifestOrder()
    {
        // G8: a contest declaring only the write-in count and the null-vote indicator, in that
        // order, carries exactly those, in that order, under indices 3 and 4.
        var election = Build(kinds: [SupplementalFieldKind.WriteInCount, SupplementalFieldKind.NullVoteIndicator]);

        var contest = Encrypt(election, 0, 0, 1).Contests[0];

        Assert.Equal(["write-ins", "null-votes"], contest.SupplementalFields.Select(x => x.FieldId));
        Assert.Equal([3, 4], election.Contest.SupplementalFields.Select(x => x.Index));
        Assert.Null(contest.UndervoteDifferenceProof);
        VerifyAll(election, Encrypt(election, 0, 0, 1));
    }

    [Fact]
    public void Encrypt_EachFieldHasItsOwnNonce_UnderItsOwnOptionIndex()
    {
        // G3: eq. (33) with j = the field's option index; before S5 all four counters shared the
        // j-less nonce H_q(H_I; 0x21, i, xi_B), so beta ratios revealed the counters' plaintexts.
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var contest = ballot.Contests[0];
        IntegerModP g = new(EGParameters.G);

        foreach (var field in contest.SupplementalFields)
        {
            int index = election.Contest.SupplementalFields.Single(x => x.Id == field.FieldId).Index;
            IntegerModQ xi = new EncryptionNonce(ballot.SelectionEncryptionIdentifierHash, Nonce, election.Contest.Index, index);
            Assert.Equal(IntegerModP.PowModP(g, xi), field.Alpha);
        }

        var alphas = contest.Choices.Select(x => x.Alpha).Concat(contest.SupplementalFields.Select(x => x.Alpha)).ToList();
        Assert.Equal(alphas.Count, alphas.Distinct().Count());
    }

    [Fact]
    public void LimitProof_IsEq62OverTheSelectionsTheCountedWriteInsAndTheOvervoteIndicatorToTheL()
    {
        // §3.3.9 p.39, footnote 42 and user decision Q2: the selection-limit proof's ciphertext is
        // prod alpha_i * alpha_wc * alpha_ov^L (and likewise beta), challenged as in eq. (62).
        var election = Build(selectionLimit: 3, optionSelectionLimit: 3);
        var ballot = Encrypt(election, 2, 2, 1);
        var contest = ballot.Contests[0];
        int limit = election.Contest.SelectionLimit;
        var overvote = contest.Field(SupplementalFieldKind.OvervoteIndicator);
        var writeIns = contest.Field(SupplementalFieldKind.WriteInCount);

        var alpha = contest.Choices[0].Alpha * contest.Choices[1].Alpha * writeIns.Alpha * IntegerModP.PowModP(overvote.Alpha, limit);
        var beta = contest.Choices[0].Beta * contest.Choices[1].Beta * writeIns.Beta * IntegerModP.PowModP(overvote.Beta, limit);

        AssertChallenge(election, ballot, contest.Proofs, alpha, beta, firstValue: 0, election.Contest.Index);
    }

    [Fact]
    public void UndervoteDifferenceProof_IsTheDocumentedOneValueProof()
    {
        // Not spec-defined (§3.3.9: "These proofs are not described in detail"); this pins the
        // implementation's documented format: c = H_q(H_I; 0x24, ind_c, ind_o(u), A, B, a_L, b_L)
        // with (A, B) = prod over the selections and the counted write-in count, times u's
        // ciphertext, a_L = g^v A^c and b_L = K^(v - L c) B^c.
        var election = Build(selectionLimit: 3, optionSelectionLimit: 3);
        var ballot = Encrypt(election, 1, 0, 1);
        var contest = ballot.Contests[0];
        var difference = contest.Field(SupplementalFieldKind.UndervoteDifferenceCount);
        var writeIns = contest.Field(SupplementalFieldKind.WriteInCount);
        Assert.Equal(1, Plaintext(difference, election.K));

        var alpha = contest.Choices[0].Alpha * contest.Choices[1].Alpha * writeIns.Alpha * difference.Alpha;
        var beta = contest.Choices[0].Beta * contest.Choices[1].Beta * writeIns.Beta * difference.Beta;

        var proof = Assert.Single(contest.UndervoteDifferenceProof!);
        AssertChallenge(election, ballot, [proof], alpha, beta, firstValue: election.Contest.SelectionLimit,
            election.Contest.Index, FieldIndex(election.Contest, SupplementalFieldKind.UndervoteDifferenceCount));
    }

    private static void AssertChallenge(Election election, EncryptedBallot ballot, ChallengeResponsePair[] proofs, IntegerModP alpha, IntegerModP beta, int firstValue, params int[] indices)
    {
        IntegerModP g = new(EGParameters.G);
        var bytes = new List<byte[]> { new byte[] { 0x24 } };
        bytes.AddRange(indices.Select(index => index.ToByteArray()));
        bytes.Add(alpha);
        bytes.Add(beta);
        for (int j = 0; j < proofs.Length; j++)
        {
            bytes.Add(IntegerModP.PowModP(g, proofs[j].Response) * IntegerModP.PowModP(alpha, proofs[j].Challenge));
            bytes.Add(IntegerModP.PowModP(election.K, proofs[j].Response - (firstValue + j) * proofs[j].Challenge) * IntegerModP.PowModP(beta, proofs[j].Challenge));
        }

        var c = EGHash.HashModQ(ballot.SelectionEncryptionIdentifierHash, bytes.ToArray());
        Assert.Equal(c, proofs.Select(x => x.Challenge).Sum());
    }

    // --- Verification 6 over the supplemental fields (G22) -------------------------------------

    [Fact]
    public void Verification6_TamperedFieldProof_Fails6D()
    {
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var field = ballot.Contests[0].Field(SupplementalFieldKind.UndervoteIndicator);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.UndervoteIndicator,
            field with { Proofs = [field.Proofs[0] with { Challenge = field.Proofs[0].Challenge + 1 }, .. field.Proofs.Skip(1)] }));

        var exception = Assert.Throws<VerificationFailedException>(() => Verify6(election, tampered));

        Assert.Equal("6.D", exception.SubSection);
    }

    [Fact]
    public void Verification6_FieldTamperedOutsideTheSubgroupWithoutReproving_Fails6A()
    {
        // The alpha is replaced without re-proving, so the field's proof fails too: 6.A is reported
        // either by the fused check or, were that skipped, by the batch membership test the fused
        // path runs before reporting a 6.D. This shows the precedence of 6.A over 6.D, not that the
        // fused check covers fields; Verification6_FieldNonMemberWithAValidProof_Fails6A does that.
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var field = ballot.Contests[0].Field(SupplementalFieldKind.WriteInCount);
        // p - 1 = -1 is a quadratic non-residue (p = 3 mod 4), so not in Z_p^r.
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.WriteInCount,
            field with { Alpha = new IntegerModP(EGParameters.P - 1) }));

        var exception = Assert.Throws<VerificationFailedException>(() => Verify6(election, tampered));

        Assert.Equal("6.A", exception.SubSection);
    }

    [Fact]
    public void Verification6_FieldNonMemberWithAValidProof_Fails6A()
    {
        // The only 6.A failure no proof check can also catch (see NonMemberRangeProof): the null-vote
        // indicator's alpha negated, with a range proof over 0..1 that passes 6.D. The ballot passes
        // every structural check, so Verification 6 takes the fused path, and only its membership
        // check on the field can reject the ballot.
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var kind = SupplementalFieldKind.NullVoteIndicator;
        var field = ballot.Contests[0].Field(kind);
        Assert.Equal(0, Plaintext(field, election.K));
        var (negatedAlpha, proofs) = NonMemberRangeProof.Forge(
            field.Alpha, field.Beta, field.EncryptionNonce!.Value, value: 0, limit: election.Contest.RangeBound(kind),
            election.K, ballot.SelectionEncryptionIdentifierHash, election.Contest.Index, FieldIndex(election.Contest, kind));
        var tampered = WithContest(ballot, c => c.WithField(kind, field with { Alpha = negatedAlpha, Proofs = proofs }));

        // The forged proof really does pass the challenge-sum check (6.D), so only 6.A can reject it.
        AssertChallenge(election, ballot, proofs, negatedAlpha, field.Beta, firstValue: 0, election.Contest.Index, FieldIndex(election.Contest, kind));

        var exception = Assert.Throws<VerificationFailedException>(() => Verify6(election, tampered));

        Assert.Equal("6.A", exception.SubSection);
    }

    /// <summary>
    /// The null-vote indicator forged as a non-member with a range proof that passes 6.D (as in
    /// <see cref="Verification6_FieldNonMemberWithAValidProof_Fails6A"/>): only a membership test
    /// that covers the field can reject it.
    /// </summary>
    private static EncryptedContest WithNonMemberNullVoteIndicator(Election election, EncryptedBallot ballot, EncryptedContest contest)
    {
        var kind = SupplementalFieldKind.NullVoteIndicator;
        var field = ballot.Contests[0].Field(kind);
        var (negatedAlpha, proofs) = NonMemberRangeProof.Forge(
            field.Alpha, field.Beta, field.EncryptionNonce!.Value, value: 0, limit: election.Contest.RangeBound(kind),
            election.K, ballot.SelectionEncryptionIdentifierHash, election.Contest.Index, FieldIndex(election.Contest, kind));
        return contest.WithField(kind, field with { Alpha = negatedAlpha, Proofs = proofs });
    }

    [Fact]
    public void Verification6_FieldNonMemberOnABallotThatFailsAStructuralCheck_Fails6A()
    {
        // In-order path: choice 1 has one proof too few, so Verification 6 skips the fused path, and
        // its batch membership test runs first. That test must cover the supplemental fields, or the
        // forged field goes unseen and choice 1's "6" is reported instead of 6.A.
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        static EncryptedContest Truncated(EncryptedContest c) =>
            c with { Choices = [c.Choices[0] with { Proofs = c.Choices[0].Proofs[..^1] }, .. c.Choices.Skip(1)] };

        // Each fault on its own.
        Assert.Equal("6", Assert.Throws<VerificationFailedException>(() => Verify6(election, WithContest(ballot, Truncated))).SubSection);
        Assert.Equal("6.A", Assert.Throws<VerificationFailedException>(() => Verify6(election, WithContest(ballot, c => WithNonMemberNullVoteIndicator(election, ballot, c)))).SubSection);

        var both = WithContest(ballot, c => WithNonMemberNullVoteIndicator(election, ballot, Truncated(c)));
        var exception = Assert.Throws<VerificationFailedException>(() => Verify6(election, both));

        Assert.Equal("6.A", exception.SubSection);
    }

    [Fact]
    public void Verification6_FieldNonMemberAfterAnEarlierSumFailure_Fails6A()
    {
        // Fused path: choice 1 fails 6.D, which ends the fused walk before the contest's fields are
        // reached. The batch membership test run before reporting 6.D must cover the fields, or the
        // forged field goes unseen and 6.D is reported instead of 6.A.
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        static EncryptedContest SumFailure(EncryptedContest c)
        {
            var first = c.Choices[0];
            ChallengeResponsePair[] proofs = [first.Proofs[0] with { Challenge = first.Proofs[0].Challenge + 1 }, .. first.Proofs.Skip(1)];
            return c with { Choices = [first with { Proofs = proofs }, .. c.Choices.Skip(1)] };
        }

        // Each fault on its own.
        Assert.Equal("6.D", Assert.Throws<VerificationFailedException>(() => Verify6(election, WithContest(ballot, SumFailure))).SubSection);

        var both = WithContest(ballot, c => WithNonMemberNullVoteIndicator(election, ballot, SumFailure(c)));
        var exception = Assert.Throws<VerificationFailedException>(() => Verify6(election, both));

        Assert.Equal("6.A", exception.SubSection);
    }

    [Fact]
    public void Verification6_FieldWithTheWrongNumberOfProofs_Fails()
    {
        // The undervote difference count ranges over 0..L, so it has L + 1 proofs.
        var election = Build(selectionLimit: 2);
        var ballot = Encrypt(election, 1, 0);
        var field = ballot.Contests[0].Field(SupplementalFieldKind.UndervoteDifferenceCount);
        Assert.Equal(3, field.Proofs.Length);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.UndervoteDifferenceCount, field with { Proofs = field.Proofs[..2] }));

        var exception = Assert.Throws<VerificationFailedException>(() => Verify6(election, tampered));

        Assert.Equal("6", exception.SubSection);
    }

    [Fact]
    public void Verification6_IndicatorEncryptingTwo_Fails6D()
    {
        // An indicator's range is 0..1 (user decision Q2): no range proof over 0..1 exists for 2.
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var forged = Reencrypt(election, ballot, SupplementalFieldKind.NullVoteIndicator, value: 2, bound: 1);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.NullVoteIndicator, forged));

        var exception = Assert.Throws<VerificationFailedException>(() => Verify6(election, tampered));

        Assert.Equal("6.D", exception.SubSection);
    }

    [Fact]
    public void Verification6_WriteInCountAboveTheWriteInFieldCount_Fails6D()
    {
        // G22: the write-in count ranges over 0..the number of write-in fields (2), not 0..L.
        var election = Build(selectionLimit: 3, writeInsCount: false, writeInFields: 2);
        var ballot = Encrypt(election, 0, 0, 2);
        var forged = Reencrypt(election, ballot, SupplementalFieldKind.WriteInCount, value: 3, bound: 2);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.WriteInCount, forged));

        var exception = Assert.Throws<VerificationFailedException>(() => Verify6(election, tampered));

        Assert.Equal("6.D", exception.SubSection);
    }

    // --- Verification 7: the combined limit proof and the relation (Q2) -------------------------

    [Fact]
    public void Verification7_OvervoteIndicatorSetOnAnHonestSelection_Fails7D()
    {
        // The indicator alone passes Verification 6 (1 is in 0..1), but the selection plus L times
        // the indicator is 2 > L: the selection-limit proof cannot hold (§3.3.9 p.39).
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var forged = Reencrypt(election, ballot, SupplementalFieldKind.OvervoteIndicator, value: 1, bound: 1);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.OvervoteIndicator, forged));

        Verify6(election, tampered);
        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7.D", exception.SubSection);
    }

    [Fact]
    public void Verification7_CountedWriteInOnAFullContest_Fails7D()
    {
        // Write-ins count toward the limit (user decision Q2 (c)): a selection plus a write-in is
        // 2 > L = 1, so a device that reports both cannot prove the limit.
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var forged = Reencrypt(election, ballot, SupplementalFieldKind.WriteInCount, value: 1, bound: 2);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.WriteInCount, forged));

        Verify6(election, tampered);
        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7.D", exception.SubSection);
    }

    /// <summary>
    /// The undervote difference proof a device computes, in the documented format, for
    /// <paramref name="difference"/> as u's encryption: the one-value proof (Note 3.4) that the
    /// product of the selections, the counted write-in count and u encrypts L, using the nonce sum.
    /// </summary>
    private static ChallengeResponsePair[] RelationProof(Election election, EncryptedBallot ballot, EncryptedSupplementalField difference)
    {
        var contest = ballot.Contests[0];
        var writeIns = contest.Field(SupplementalFieldKind.WriteInCount);
        var alpha = contest.Choices[0].Alpha * contest.Choices[1].Alpha * writeIns.Alpha * difference.Alpha;
        var beta = contest.Choices[0].Beta * contest.Choices[1].Beta * writeIns.Beta * difference.Beta;
        var nonce = contest.Choices[0].EncryptionNonce!.Value + contest.Choices[1].EncryptionNonce!.Value
            + writeIns.EncryptionNonce!.Value + difference.EncryptionNonce!.Value;

        IntegerModP g = new(EGParameters.G);
        IntegerModQ u = ElectionGuardRandom.GetIntegerModQ();
        var c = EGHash.HashModQ(ballot.SelectionEncryptionIdentifierHash,
            [0x24],
            election.Contest.Index.ToByteArray(),
            FieldIndex(election.Contest, SupplementalFieldKind.UndervoteDifferenceCount).ToByteArray(),
            alpha,
            beta,
            IntegerModP.PowModP(g, u),
            IntegerModP.PowModP(election.K, u));
        return [new ChallengeResponsePair { Challenge = c, Response = u - c * nonce }];
    }

    [Fact]
    public void Verification7_UndervoteDifferenceProofRecomputedByTheDevice_Passes()
    {
        // The control for the forgery below: the same prover, on the honest u, is accepted.
        var election = Build(selectionLimit: 3, optionSelectionLimit: 3);
        var ballot = Encrypt(election, 2, 0);
        var difference = ballot.Contests[0].Field(SupplementalFieldKind.UndervoteDifferenceCount);
        var reproved = WithContest(ballot, c => c with { UndervoteDifferenceProof = RelationProof(election, ballot, difference) });

        Verify7(election, reproved);
    }

    [Fact]
    public void Verification7_UndervoteDifferenceThatDoesNotMatchTheSelections_Fails7D()
    {
        // u = 2 is in 0..L = 3, so Verification 6 passes, but L - u = 1 is not the sum 2. A device
        // that re-proves the relation for its forged ciphertext still cannot make it hold.
        var election = Build(selectionLimit: 3, optionSelectionLimit: 3);
        var ballot = Encrypt(election, 2, 0);
        var forged = Reencrypt(election, ballot, SupplementalFieldKind.UndervoteDifferenceCount, value: 2, bound: 3);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.UndervoteDifferenceCount, forged) with
        {
            UndervoteDifferenceProof = RelationProof(election, ballot, forged),
        });

        Verify6(election, tampered);
        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7.D", exception.SubSection);
        Assert.Contains("Undervote difference", exception.Message);
    }

    [Fact]
    public void Verification7_TamperedUndervoteDifferenceProof_Fails7D()
    {
        var election = Build(selectionLimit: 2);
        var ballot = Encrypt(election, 1, 0);
        var proof = ballot.Contests[0].UndervoteDifferenceProof![0];
        var tampered = WithContest(ballot, c => c with { UndervoteDifferenceProof = [proof with { Response = proof.Response + 1 }] });

        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7.D", exception.SubSection);
        Assert.Contains("Undervote difference", exception.Message);
    }

    [Fact]
    public void Verification7_MissingUndervoteDifferenceProof_Fails()
    {
        var election = Build();
        var tampered = WithContest(Encrypt(election, 1, 0), c => c with { UndervoteDifferenceProof = null });

        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7", exception.SubSection);
    }

    [Fact]
    public void Verification7_UndervoteDifferenceProofWithoutTheField_Fails()
    {
        var election = Build(kinds: [SupplementalFieldKind.OvervoteIndicator]);
        var ballot = Encrypt(election, 1, 0);
        Assert.Null(ballot.Contests[0].UndervoteDifferenceProof);
        var tampered = WithContest(ballot, c => c with { UndervoteDifferenceProof = [c.Proofs[0]] });

        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7", exception.SubSection);
    }

    /// <summary>
    /// Each JSON edit, and the decoded proof list it must produce: the JSON decoder keeps a null
    /// list or a null entry as is (protobuf cannot encode either).
    /// </summary>
    private static readonly Dictionary<string, (Action<System.Text.Json.Nodes.JsonNode> Edit, Func<EncryptedContest, ChallengeResponsePair[]?> Decoded)> NullProofEdits = new()
    {
        ["undervote difference proof entry"] = (c => c["undervoteDifferenceProof"]![0] = null, c => c.UndervoteDifferenceProof),
        ["contest proof entry"] = (c => c["proofs"]![0] = null, c => c.Proofs),
        ["contest proof list"] = (c => c["proofs"] = null, c => c.Proofs),
        ["selection proof entry"] = (c => c["choices"]![0]!["proof"]![0] = null, c => c.Choices[0].Proofs),
        ["selection proof list"] = (c => c["choices"]![0]!["proof"] = null, c => c.Choices[0].Proofs),
        ["field proof entry"] = (c => c["supplementalFields"]![0]!["proof"]![0] = null, c => c.SupplementalFields[0].Proofs),
        ["field proof list"] = (c => c["supplementalFields"]![0]!["proof"] = null, c => c.SupplementalFields[0].Proofs),
    };

    public static TheoryData<string, int> NullProofCases() => new()
    {
        { "undervote difference proof entry", 7 },
        { "contest proof entry", 7 },
        { "contest proof list", 7 },
        { "selection proof entry", 6 },
        { "selection proof list", 6 },
        { "field proof entry", 6 },
        { "field proof list", 6 },
    };

    [Theory]
    [MemberData(nameof(NullProofCases))]
    public void JsonBallotWithANullProofListOrEntry_FailsLikeAProofListOfTheWrongLength(string fault, int verification)
    {
        // S5 review round 2: these once threw NullReferenceException from Verification 6 or 7. A
        // malformed proof list is reported as "6"/"7", like one of the wrong length: after 6.A/7.A
        // (proofs are read by Verifications 6 and 7 only, so this is not a ballot-structure failure).
        var election = Build(selectionLimit: 2);
        var ballot = Encrypt(election, 1, 0);
        var serializer = new Core.Serialization.JsonEncryptedBallotSerializer();
        using var encoded = new MemoryStream();
        serializer.Serialize(encoded, ballot);
        var document = System.Text.Json.Nodes.JsonNode.Parse(encoded.ToArray())!;
        var (edit, decodedList) = NullProofEdits[fault];
        edit(document["contests"]![0]!);

        var decoded = serializer.Deserialize(new MemoryStream(Encoding.UTF8.GetBytes(document.ToJsonString())))!;
        var list = decodedList(decoded.Contests[0]);
        Assert.True(list is null || list.Any(x => x is null),$"The decoder did not keep the null ({fault}).");

        var exception = Assert.Throws<VerificationFailedException>(() =>
        {
            if (verification == 6)
            {
                Verify6(election, decoded);
            }
            else
            {
                Verify7(election, decoded);
            }
        });

        Assert.Equal(verification.ToString(), exception.SubSection);
    }

    [Fact]
    public void Verification7_FieldOutsideTheSubgroup_Fails7A()
    {
        // 7.A covers every verifiable field's alpha and beta (§3.1.3 p.19), supplemental ones too.
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var field = ballot.Contests[0].Field(SupplementalFieldKind.NullVoteIndicator);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.NullVoteIndicator, field with { Beta = new IntegerModP(EGParameters.P - 1) }));

        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7.A", exception.SubSection);
    }

    // --- Verification 8 and the ballot structure (G8, BallotStructure) --------------------------

    [Fact]
    public void Verification8_TamperedFieldCiphertext_Fails8A()
    {
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var field = ballot.Contests[0].Field(SupplementalFieldKind.UndervoteDifferenceCount);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.UndervoteDifferenceCount, field with { Beta = field.Beta * new IntegerModP(EGParameters.G) }));

        var exception = Assert.Throws<VerificationFailedException>(() => Verify8(election, tampered));

        Assert.Equal("8.A", exception.SubSection);
    }

    [Fact]
    public void FieldsListedOutOfManifestOrder_StillVerify()
    {
        // Eq. (70) hashes the fields in manifest order whatever order the ballot lists them in.
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var reordered = WithContest(ballot, c => c with { SupplementalFields = Enumerable.Reverse(c.SupplementalFields).ToList() });

        VerifyAll(election, reordered);
    }

    public static TheoryData<string, int> StructureCases()
    {
        var data = new TheoryData<string, int>();
        foreach (var verification in new[] { 6, 7, 8, 9 })
        {
            data.Add("missing", verification);
            data.Add("duplicated", verification);
            data.Add("undeclared", verification);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(StructureCases))]
    public void BallotWithoutExactlyTheDeclaredFields_IsRejectedAsStructure(string fault, int verification)
    {
        var election = Build(kinds: [SupplementalFieldKind.OvervoteIndicator, SupplementalFieldKind.NullVoteIndicator]);
        var ballot = Encrypt(election, 1, 0);
        var fields = ballot.Contests[0].SupplementalFields;
        List<EncryptedSupplementalField> changed = fault switch
        {
            "missing" => [fields[0]],
            "duplicated" => [fields[0], fields[0], fields[1]],
            _ => [.. fields, fields[1] with { FieldId = "write-ins" }],
        };
        var tampered = WithContest(ballot, c => c with { SupplementalFields = changed });

        Action verify = verification switch
        {
            6 => () => Verify6(election, tampered),
            7 => () => Verify7(election, tampered),
            8 => () => Verify8(election, tampered),
            _ => () => new Core.Tally.EncryptedTally(election.Manifest).AddBallot(tampered),
        };
        var exception = Assert.Throws<VerificationFailedException>(verify);

        Assert.Equal($"{verification}.structure", exception.SubSection);
    }
}
