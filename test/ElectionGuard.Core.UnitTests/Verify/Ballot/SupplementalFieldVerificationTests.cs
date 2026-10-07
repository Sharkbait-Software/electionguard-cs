using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.Crypto;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Testing.Common;
using System.Security.Cryptography;
using System.Text;

namespace ElectionGuard.Core.UnitTests.Verify.Ballot;

/// <summary>
/// Stages S5 and S5b: supplemental verifiable fields declared per contest (user decisions Q1-Q3 and
/// Q11-Q17; G3, G8, G10, G22). Each field is encrypted under its own nonce xi_{i,j} and option index
/// j and carries a range proof that Verification 6 checks. With s the sum of the selections, w the
/// write-in count and L the selection limit, Verification 7 checks the relations of Q15 (and Q17)
/// over the fields the contest declares: (1) the selection-limit proof of s + w + L*overvote +
/// undervote indicator in 0..L, (2) s + w + L*overvote + u = L, and (3) s + w + L*overvote + L*null
/// in 0..L, each L*overvote term only where the overvote indicator is declared. The encryptor
/// derives every value from the selections and the write-ins used, with the overvote rule
/// s + w &gt; L or an option &gt; R.
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

        public int L => Contest.SelectionLimit;

        public IntegerModP K => Record.ElectionPublicKeys.VoteEncryptionKey;

        public bool Declares(SupplementalFieldKind kind) => Contest.SupplementalFieldOfKind(kind) is not null;
    }

    /// <summary>
    /// The minimal two-option contest with selection limit L and option selection limit R,
    /// declaring <paramref name="kinds"/> (every kind by default) and offering
    /// <paramref name="writeInFields"/> write-in fields (by default 2 when the write-in count is
    /// declared and none otherwise: Manifest.Validate requires the count wherever write-ins are
    /// offered, user decision Q19 "Reject manifest").
    /// </summary>
    private static Election Build(
        int selectionLimit = 1,
        int optionSelectionLimit = 1,
        int? writeInFields = null,
        IReadOnlyList<SupplementalFieldKind>? kinds = null)
    {
        kinds ??= ElectionFixtureBuilder.AllSupplementalFields;
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(
            optionSelectionLimit: optionSelectionLimit,
            selectionLimit: selectionLimit,
            supplementalFields: kinds,
            writeInFieldCount: writeInFields ?? (kinds.Contains(SupplementalFieldKind.WriteInCount) ? 2 : 0));
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
        EncryptedBallotNonce = ballot.EncryptedBallotNonce,
        Weight = ballot.Weight,
        Status = ballot.Status,
        DeviceId = ballot.DeviceId,
    };

    /// <summary>
    /// The field of <paramref name="kind"/> re-encrypted to <paramref name="value"/> under its own
    /// nonce, with a valid range proof over 0..its bound: what a dishonest device can produce for a
    /// value inside the field's range. Verification 6 accepts it.
    /// </summary>
    private static EncryptedSupplementalField Reencrypt(Election election, EncryptedBallot ballot, SupplementalFieldKind kind, int value, int? bound = null)
    {
        var field = ballot.Contests[0].Field(kind);
        var xi = field.EncryptionNonce!.Value;
        var beta = IntegerModP.PowModP(election.K, xi + value);
        return field with
        {
            Beta = beta,
            Proofs = ZeroChallengeRangeProof.Prove(field.Alpha, beta, xi, value, bound ?? election.Contest.RangeBound(kind), election.K, ballot.SelectionEncryptionIdentifierHash, election.Contest.Index, FieldIndex(election.Contest, kind)),
        };
    }

    // --- The relation ciphertexts, recomputed here from their documented definitions -------------

    /// <summary>An ElGamal ciphertext with its nonce, for recomputing the relation ciphertexts.</summary>
    private readonly record struct Ciphertext(IntegerModP Alpha, IntegerModP Beta, IntegerModQ Nonce)
    {
        public static Ciphertext Of(EncryptedValueWithProofs value) => new(value.Alpha, value.Beta, value.EncryptionNonce!.Value);

        public Ciphertext Times(EncryptedValueWithProofs? value, int weight = 1)
        {
            if (value is null)
            {
                return this;
            }

            return new Ciphertext(
                Alpha * IntegerModP.PowModP(value.Alpha, weight),
                Beta * IntegerModP.PowModP(value.Beta, weight),
                Nonce + weight * value.EncryptionNonce!.Value);
        }
    }

    /// <summary>
    /// The field of <paramref name="kind"/> when the contest declares it, else null. A forgery
    /// may <paramref name="omit"/> one field's term from the relations it proves.
    /// </summary>
    private static EncryptedSupplementalField? Declared(Election election, EncryptedContest contest, SupplementalFieldKind kind, SupplementalFieldKind? omit = null) =>
        election.Declares(kind) && kind != omit ? contest.Field(kind) : null;

    /// <summary>The encryption of s + w: the selections times the write-in count, when declared.</summary>
    private static Ciphertext SumOfSelectionsAndWriteIns(Election election, EncryptedContest contest, SupplementalFieldKind? omit = null) =>
        Ciphertext.Of(contest.Choices[0]).Times(contest.Choices[1]).Times(Declared(election, contest, SupplementalFieldKind.WriteInCount, omit));

    /// <summary>(1) s + w + L*overvote + undervote indicator.</summary>
    private static Ciphertext LimitCiphertext(Election election, EncryptedContest contest, SupplementalFieldKind? omit = null) =>
        SumOfSelectionsAndWriteIns(election, contest, omit)
            .Times(Declared(election, contest, SupplementalFieldKind.OvervoteIndicator, omit), election.L)
            .Times(Declared(election, contest, SupplementalFieldKind.UndervoteIndicator, omit));

    /// <summary>(2) s + w + L*overvote + u.</summary>
    private static Ciphertext DifferenceCiphertext(Election election, EncryptedContest contest, SupplementalFieldKind? omit = null) =>
        SumOfSelectionsAndWriteIns(election, contest, omit)
            .Times(Declared(election, contest, SupplementalFieldKind.OvervoteIndicator, omit), election.L)
            .Times(contest.Field(SupplementalFieldKind.UndervoteDifferenceCount));

    /// <summary>(3) s + w + L*overvote + L*null (Q17).</summary>
    private static Ciphertext NullVoteCiphertext(Election election, EncryptedContest contest, SupplementalFieldKind? omit = null) =>
        SumOfSelectionsAndWriteIns(election, contest, omit)
            .Times(Declared(election, contest, SupplementalFieldKind.OvervoteIndicator, omit), election.L)
            .Times(Declared(election, contest, SupplementalFieldKind.NullVoteIndicator, omit), election.L);

    private static int[] LimitPrefix(Election election) => [election.Contest.Index];

    private static int[] DifferencePrefix(Election election) => [election.Contest.Index, FieldIndex(election.Contest, SupplementalFieldKind.UndervoteDifferenceCount)];

    private static int[] NullVotePrefix(Election election) => [election.Contest.Index, FieldIndex(election.Contest, SupplementalFieldKind.NullVoteIndicator), election.L];

    /// <summary>
    /// A range proof over <paramref name="first"/>..<paramref name="last"/>, by the prover's
    /// algorithm of eqs. (57)-(61), with challenge H_q(H_I; 0x24, b(prefix_k, 4)..., alpha, beta,
    /// a_first, b_first, ...): what a device computes for <paramref name="value"/>. For a value in
    /// range it is the honest proof. For one outside, the device still commits in the last branch as
    /// if that were the value, and gives the challenges summing to c; the verifier's recomputed
    /// commitment then differs, which is all a device can do without breaking the proof.
    /// </summary>
    private static ChallengeResponsePair[] DeviceProof(Election election, EncryptedBallot ballot, Ciphertext ciphertext, int value, int first, int last, int[] prefix)
    {
        IntegerModP g = new(EGParameters.G);
        int real = value >= first && value <= last ? value : last;
        int count = last - first + 1;
        var u = new IntegerModQ[count];
        var challenges = new IntegerModQ[count];
        var bytes = new List<byte[]> { new byte[] { 0x24 } };
        bytes.AddRange(prefix.Select(x => x.ToByteArray()));
        bytes.Add(ciphertext.Alpha);
        bytes.Add(ciphertext.Beta);
        for (int j = first; j <= last; j++)
        {
            int k = j - first;
            u[k] = ElectionGuardRandom.GetIntegerModQ();
            if (j == real)
            {
                bytes.Add(IntegerModP.PowModP(g, u[k]));
                bytes.Add(IntegerModP.PowModP(election.K, u[k]));
            }
            else
            {
                challenges[k] = ElectionGuardRandom.GetIntegerModQ();
                bytes.Add(IntegerModP.PowModP(g, u[k]));
                bytes.Add(IntegerModP.PowModP(election.K, u[k] + (value - j) * challenges[k]));
            }
        }

        IntegerModQ c = EGHash.HashModQ(ballot.SelectionEncryptionIdentifierHash, bytes.ToArray());
        IntegerModQ simulated = 0;
        for (int k = 0; k < count; k++)
        {
            if (k != real - first)
            {
                simulated += challenges[k];
            }
        }

        challenges[real - first] = c - simulated;
        return Enumerable.Range(0, count)
            .Select(k => new ChallengeResponsePair { Challenge = challenges[k], Response = u[k] - challenges[k] * ciphertext.Nonce })
            .ToArray();
    }

    /// <summary>
    /// Recomputes a proof's challenge from its documented format (verifier side, with plain
    /// BigInteger arithmetic) and asserts that the proof's challenges sum to it.
    /// </summary>
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

    // --- Honest ballots: values, the overvote rule (G10), and Verifications 6-8 ----------------

    public static TheoryData<int, int, int, int, int, int[]> HonestCases() => new()
    {
        // L, R, choice-1, choice-2, write-ins, expected
        // [choice-1, choice-2, overvote, null, undervote, difference, write-ins]
        // Every field is declared. On an overvote: options 0, write-ins 0, overvote 1, undervote 0,
        // difference 0, null 0 (Q11, Q12, Q3, Q15). On a null vote: undervote 1, difference L, null 1.
        { 1, 1, 0, 0, 0, [0, 0, 0, 1, 1, 1, 0] },
        { 1, 1, 1, 0, 0, [1, 0, 0, 0, 0, 0, 0] },
        { 1, 1, 1, 1, 0, [0, 0, 1, 0, 0, 0, 0] },
        // G10: L = 1, R = 2: a single 2 is an overvote (s = 2 > L), which the old L * R rule let through.
        { 1, 2, 2, 0, 0, [0, 0, 1, 0, 0, 0, 0] },
        { 1, 2, 1, 0, 0, [1, 0, 0, 0, 0, 0, 0] },
        // G10: L = 3, R = 3: a total in (L, L * R] is neutralized.
        { 3, 3, 2, 2, 0, [0, 0, 1, 0, 0, 0, 0] },
        { 3, 3, 3, 0, 0, [3, 0, 0, 0, 0, 0, 0] },
        // Partial undervote.
        { 3, 3, 1, 1, 0, [1, 1, 0, 0, 1, 1, 0] },
        // G10: one option above R overvotes although the total is within L.
        { 3, 1, 2, 0, 0, [0, 0, 1, 0, 0, 0, 0] },
        // Q13: write-ins count toward the limit exactly like selections.
        // A write-in-only ballot is not a null vote.
        { 1, 1, 0, 0, 1, [0, 0, 0, 0, 0, 0, 1] },
        { 3, 1, 0, 0, 1, [0, 0, 0, 0, 1, 2, 1] },
        // Write-ins pushing the contest over L overvote it, and are zeroed (Q12).
        { 1, 1, 1, 0, 1, [0, 0, 1, 0, 0, 0, 0] },
        { 2, 1, 1, 0, 2, [0, 0, 1, 0, 0, 0, 0] },
        // Write-ins filling the limit exactly.
        { 3, 1, 1, 0, 2, [1, 0, 0, 0, 0, 0, 2] },
    };

    [Theory]
    [MemberData(nameof(HonestCases))]
    public void Encrypt_DerivesEveryFieldFromTheSelections_AndTheBallotVerifies(int selectionLimit, int optionSelectionLimit, int choice1, int choice2, int writeIns, int[] expected)
    {
        var election = Build(selectionLimit, optionSelectionLimit);
        var ballot = Encrypt(election, choice1, choice2, writeIns);
        var contest = ballot.Contests[0];

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
        VerifyAll(election, ballot);
    }

    /// <summary>
    /// The ballots of <see cref="EveryCombinationOfTrackedFields_HonestBallotsOfEveryKind_Verify"/>,
    /// in a contest with L = 3, R = 2 and 2 write-in fields, with the expected field values when
    /// every field is declared: [overvote, null, undervote, difference, write-ins].
    /// </summary>
    private static readonly (string Name, int Choice1, int Choice2, int WriteIns, int[] Fields)[] BallotKinds =
    [
        ("normal (s = L)", 2, 1, 0, [0, 0, 0, 0, 0]),
        ("partial undervote", 1, 0, 0, [0, 0, 1, 2, 0]),
        ("null vote", 0, 0, 0, [0, 1, 1, 3, 0]),
        ("write-in only", 0, 0, 1, [0, 0, 1, 2, 1]),
        ("write-ins fill the limit", 2, 0, 1, [0, 0, 0, 0, 1]),
        ("overvote by sum", 2, 2, 0, [1, 0, 0, 0, 0]),
        ("overvote by an option above R", 3, 0, 0, [1, 0, 0, 0, 0]),
        ("write-ins push over L", 2, 1, 1, [1, 0, 0, 0, 0]),
    ];

    public static TheoryData<int> TrackedFieldSubsets()
    {
        var data = new TheoryData<int>();
        for (int mask = 0; mask < 1 << ElectionFixtureBuilder.AllSupplementalFields.Count; mask++)
        {
            data.Add(mask);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(TrackedFieldSubsets))]
    public void EveryCombinationOfTrackedFields_HonestBallotsOfEveryKind_Verify(int mask)
    {
        // Q14: a field is tracked (declared) or not, and every tracked field takes part in its
        // relations; Q15's three relations must hold for every subset, in particular with the
        // null-vote indicator, the undervote indicator and the difference count all declared
        // (masks with bits 1, 2 and 3 set). The bits follow AllSupplementalFields: overvote, null,
        // undervote, difference, write-ins.
        var all = ElectionFixtureBuilder.AllSupplementalFields;
        var kinds = all.Where((_, bit) => (mask & (1 << bit)) != 0).ToList();
        var election = Build(selectionLimit: 3, optionSelectionLimit: 2, kinds: kinds);
        bool writeInsOffered = election.Declares(SupplementalFieldKind.WriteInCount);

        foreach (var (name, choice1, choice2, writeIns, fields) in BallotKinds)
        {
            if (writeIns > 0 && !writeInsOffered)
            {
                continue;
            }

            var ballot = Encrypt(election, choice1, choice2, writeIns);
            var contest = ballot.Contests[0];
            bool overvoted = fields[0] == 1;

            Assert.Equal(overvoted ? new[] { 0, 0 } : new[] { choice1, choice2 }, contest.Choices.Select(x => Plaintext(x, election.K)).ToArray());
            Assert.Equal(kinds.Select(kind => ElectionFixtureBuilder.SupplementalFieldId(kind)), contest.SupplementalFields.Select(x => x.FieldId));
            for (int bit = 0; bit < all.Count; bit++)
            {
                if (election.Declares(all[bit]))
                {
                    int expected = fields[bit];

                    // Q15 relation (2) has the overvote term only when the overvote indicator is
                    // tracked; without it, an overvoted contest's u is L. User decision Q18: with no
                    // tracked overvote field there is no published overvote, the neutralized
                    // contest is a blank one, and Manifest.Validate accepts u without the
                    // indicator.
                    if (all[bit] == SupplementalFieldKind.UndervoteDifferenceCount && overvoted && !election.Declares(SupplementalFieldKind.OvervoteIndicator))
                    {
                        expected = election.L;
                    }

                    Assert.True(expected == Plaintext(contest.Field(all[bit]), election.K), $"{name}: {all[bit]}");
                }
            }

            Assert.Equal(election.Declares(SupplementalFieldKind.UndervoteDifferenceCount), contest.UndervoteDifferenceProof is not null);
            Assert.Equal(election.Declares(SupplementalFieldKind.NullVoteIndicator), contest.NullVoteProof is not null);
            var exception = Record.Exception(() => VerifyAll(election, ballot));
            Assert.True(exception is null, $"{name} with fields [{string.Join(", ", kinds)}]: {exception}");
        }
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
        Assert.Equal(election.L + 1, contest.NullVoteProof!.Length);
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

    // --- The documented proof formats, pinned by recomputation ----------------------------------

    [Fact]
    public void LimitProof_IsEq62OverTheSelectionsWriteInsOvervoteToTheLAndUndervoteIndicator()
    {
        // §3.3.9 p.39, footnote 42 and user decision Q15 (1): the selection-limit proof's ciphertext
        // is prod alpha_i * alpha_w * alpha_ov^L * alpha_und (and likewise beta), challenged as in
        // eq. (62). A partial undervote, so the undervote indicator is 1 and the value is s + w + 1.
        var election = Build(selectionLimit: 3, optionSelectionLimit: 3);
        var ballot = Encrypt(election, 1, 0, 1);
        var contest = ballot.Contests[0];
        var overvote = contest.Field(SupplementalFieldKind.OvervoteIndicator);
        var undervote = contest.Field(SupplementalFieldKind.UndervoteIndicator);
        var writeIns = contest.Field(SupplementalFieldKind.WriteInCount);
        Assert.Equal(1, Plaintext(undervote, election.K));

        var alpha = contest.Choices[0].Alpha * contest.Choices[1].Alpha * writeIns.Alpha * IntegerModP.PowModP(overvote.Alpha, election.L) * undervote.Alpha;
        var beta = contest.Choices[0].Beta * contest.Choices[1].Beta * writeIns.Beta * IntegerModP.PowModP(overvote.Beta, election.L) * undervote.Beta;

        AssertChallenge(election, ballot, contest.Proofs, alpha, beta, firstValue: 0, election.Contest.Index);
    }

    [Fact]
    public void UndervoteDifferenceProof_IsTheDocumentedOneValueProof()
    {
        // Not spec-defined (§3.3.9: "These proofs are not described in detail"); this pins the
        // implementation's documented format (Q15 (2)): c = H_q(H_I; 0x24, ind_c, ind_o(u), A, B,
        // a_L, b_L) with (A, B) = prod over the selections, the write-in count, the overvote
        // indicator raised to L and u, a_L = g^v A^c and b_L = K^(v - L c) B^c.
        var election = Build(selectionLimit: 3, optionSelectionLimit: 3);
        var ballot = Encrypt(election, 1, 0, 1);
        var contest = ballot.Contests[0];
        var difference = contest.Field(SupplementalFieldKind.UndervoteDifferenceCount);
        var overvote = contest.Field(SupplementalFieldKind.OvervoteIndicator);
        var writeIns = contest.Field(SupplementalFieldKind.WriteInCount);
        Assert.Equal(1, Plaintext(difference, election.K));

        var alpha = contest.Choices[0].Alpha * contest.Choices[1].Alpha * writeIns.Alpha * IntegerModP.PowModP(overvote.Alpha, election.L) * difference.Alpha;
        var beta = contest.Choices[0].Beta * contest.Choices[1].Beta * writeIns.Beta * IntegerModP.PowModP(overvote.Beta, election.L) * difference.Beta;

        var proof = Assert.Single(contest.UndervoteDifferenceProof!);
        AssertChallenge(election, ballot, [proof], alpha, beta, firstValue: election.L,
            election.Contest.Index, FieldIndex(election.Contest, SupplementalFieldKind.UndervoteDifferenceCount));
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(2, 1)]
    public void NullVoteProof_IsTheDocumentedRangeProof(int choice1, int choice2)
    {
        // Not spec-defined either (§3.3.9 p.39 names the check, not its format); this pins the
        // documented format (Q15 (3), with Q17's overvote term): c = H_q(H_I; 0x24, ind_c,
        // ind_o(null), b(L, 4), A, B, a_0, b_0, ..., a_L, b_L) with (A, B) = prod over the
        // selections, the write-in count, the overvote indicator raised to L and the null-vote
        // indicator raised to L. A null vote (null 1) and an overvote (overvote 1): the value is L.
        var election = Build(selectionLimit: 2, optionSelectionLimit: 1);
        var ballot = Encrypt(election, choice1, choice2);
        var contest = ballot.Contests[0];
        var nullVote = contest.Field(SupplementalFieldKind.NullVoteIndicator);
        var overvote = contest.Field(SupplementalFieldKind.OvervoteIndicator);
        var writeIns = contest.Field(SupplementalFieldKind.WriteInCount);
        Assert.Equal(1, Plaintext(nullVote, election.K) + Plaintext(overvote, election.K));

        var alpha = contest.Choices[0].Alpha * contest.Choices[1].Alpha * writeIns.Alpha * IntegerModP.PowModP(overvote.Alpha, election.L) * IntegerModP.PowModP(nullVote.Alpha, election.L);
        var beta = contest.Choices[0].Beta * contest.Choices[1].Beta * writeIns.Beta * IntegerModP.PowModP(overvote.Beta, election.L) * IntegerModP.PowModP(nullVote.Beta, election.L);

        Assert.Equal(election.L + 1, contest.NullVoteProof!.Length);
        AssertChallenge(election, ballot, contest.NullVoteProof, alpha, beta, firstValue: 0,
            election.Contest.Index, FieldIndex(election.Contest, SupplementalFieldKind.NullVoteIndicator), election.L);
    }

    [Fact]
    public void NullVoteProof_WithoutAnOvervoteIndicator_HasNoOvervoteTerm()
    {
        // Q17 adds the overvote term only "when the overvote indicator is tracked"; otherwise (3)
        // stays s + w + L*null. A null vote in a contest declaring every field but the overvote
        // indicator.
        var election = Build(selectionLimit: 2, optionSelectionLimit: 1, kinds: ElectionFixtureBuilder.AllSupplementalFields.Where(x => x != SupplementalFieldKind.OvervoteIndicator).ToList());
        var ballot = Encrypt(election, 0, 0);
        var contest = ballot.Contests[0];
        var nullVote = contest.Field(SupplementalFieldKind.NullVoteIndicator);
        var writeIns = contest.Field(SupplementalFieldKind.WriteInCount);
        Assert.Equal(1, Plaintext(nullVote, election.K));

        var alpha = contest.Choices[0].Alpha * contest.Choices[1].Alpha * writeIns.Alpha * IntegerModP.PowModP(nullVote.Alpha, election.L);
        var beta = contest.Choices[0].Beta * contest.Choices[1].Beta * writeIns.Beta * IntegerModP.PowModP(nullVote.Beta, election.L);

        AssertChallenge(election, ballot, contest.NullVoteProof!, alpha, beta, firstValue: 0,
            election.Contest.Index, FieldIndex(election.Contest, SupplementalFieldKind.NullVoteIndicator), election.L);
        VerifyAll(election, ballot);
    }

    /// <summary>
    /// RangeProofChallenge.RelationCiphertexts computes the three relation ciphertexts in one
    /// Montgomery representation; on each engine it must equal the plain products.
    /// </summary>
    private static void AssertRelationCiphertextsMatchTheirDefinitions(int selectionLimit, bool avx512)
    {
        var election = Build(selectionLimit: selectionLimit);
        var contest = Encrypt(election, 1, 0, 1).Contests[0];
        var limit = LimitCiphertext(election, contest);
        var difference = DifferenceCiphertext(election, contest);
        var nullVote = NullVoteCiphertext(election, contest);

        var challenge = new RangeProofChallenge(election.K, allowAvx512: avx512);
        Assert.Equal(avx512, challenge.UsesAvx512);
        var result = challenge.RelationCiphertexts(
            [contest.Choices[0], contest.Choices[1], contest.Field(SupplementalFieldKind.WriteInCount)],
            contest.Field(SupplementalFieldKind.OvervoteIndicator),
            contest.Field(SupplementalFieldKind.UndervoteIndicator),
            contest.Field(SupplementalFieldKind.UndervoteDifferenceCount),
            contest.Field(SupplementalFieldKind.NullVoteIndicator),
            election.L);

        Assert.Equal((limit.Alpha, limit.Beta), result.Limit);
        Assert.Equal((difference.Alpha, difference.Beta), result.Difference!.Value);
        Assert.Equal((nullVote.Alpha, nullVote.Beta), result.NullVote!.Value);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void RelationCiphertexts_MatchTheirDefinitions_OnTheScalarEngine(int selectionLimit) =>
        AssertRelationCiphertextsMatchTheirDefinitions(selectionLimit, avx512: false);

    /// <summary>Skipped where AVX-512 is unavailable (it would run the scalar engine again).</summary>
    [Avx512Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void RelationCiphertexts_MatchTheirDefinitions_OnTheAvx512Engine(int selectionLimit) =>
        AssertRelationCiphertextsMatchTheirDefinitions(selectionLimit, avx512: true);

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
        var election = Build(selectionLimit: 3, writeInFields: 2);
        var ballot = Encrypt(election, 0, 0, 2);
        var forged = Reencrypt(election, ballot, SupplementalFieldKind.WriteInCount, value: 3, bound: 2);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.WriteInCount, forged));

        var exception = Assert.Throws<VerificationFailedException>(() => Verify6(election, tampered));

        Assert.Equal("6.D", exception.SubSection);
    }

    // --- Verification 7: the relations of Q15 ---------------------------------------------------

    [Fact]
    public void Verification7_EveryRelationReprovedByTheDeviceOnHonestValues_Passes()
    {
        // The control for the forgeries below: DeviceProof, on the honest values and the documented
        // formats, produces proofs that Verification 7 accepts, for a ballot of each shape.
        foreach (var (choice1, choice2, writeIns) in new[] { (1, 0, 0), (0, 0, 0), (2, 1, 0), (0, 0, 1), (2, 2, 0) })
        {
            var election = Build(selectionLimit: 3, optionSelectionLimit: 2);
            var ballot = Encrypt(election, choice1, choice2, writeIns);
            var contest = ballot.Contests[0];
            int Value(SupplementalFieldKind kind) => Plaintext(contest.Field(kind), election.K);
            int total = Plaintext(contest.Choices[0], election.K) + Plaintext(contest.Choices[1], election.K) + Value(SupplementalFieldKind.WriteInCount);
            int limitValue = total + election.L * Value(SupplementalFieldKind.OvervoteIndicator) + Value(SupplementalFieldKind.UndervoteIndicator);
            int nullValue = total + election.L * Value(SupplementalFieldKind.OvervoteIndicator) + election.L * Value(SupplementalFieldKind.NullVoteIndicator);

            var reproved = WithContest(ballot, c => c with
            {
                Proofs = DeviceProof(election, ballot, LimitCiphertext(election, c), limitValue, 0, election.L, LimitPrefix(election)),
                UndervoteDifferenceProof = DeviceProof(election, ballot, DifferenceCiphertext(election, c), election.L, election.L, election.L, DifferencePrefix(election)),
                NullVoteProof = DeviceProof(election, ballot, NullVoteCiphertext(election, c), nullValue, 0, election.L, NullVotePrefix(election)),
            });

            Verify7(election, reproved);
        }
    }

    /// <summary>
    /// A device's forgery: the fields of <paramref name="forged"/> re-encrypted to the given values
    /// with valid range proofs (so Verification 6 passes), and every relation proof recomputed by
    /// <see cref="DeviceProof"/> for the values the forged ballot really encrypts. With
    /// <paramref name="omit"/>, the device leaves that field's term out of every relation it proves,
    /// so each proof is valid for the statement it proves; only a verifier that includes the term
    /// rejects it.
    /// </summary>
    private static EncryptedBallot Forge(Election election, EncryptedBallot ballot, SupplementalFieldKind? omit, params (SupplementalFieldKind Kind, int Value)[] forged)
    {
        var contest = ballot.Contests[0];
        foreach (var (kind, value) in forged)
        {
            contest = contest.WithField(kind, Reencrypt(election, ballot, kind, value));
        }

        var values = forged.ToDictionary(x => x.Kind, x => x.Value);
        int Value(SupplementalFieldKind kind) => kind == omit ? 0 : values.TryGetValue(kind, out int v) ? v : election.Declares(kind) ? Plaintext(contest.Field(kind), election.K) : 0;
        int total = Plaintext(contest.Choices[0], election.K) + Plaintext(contest.Choices[1], election.K) + Value(SupplementalFieldKind.WriteInCount);
        int limitValue = total + election.L * Value(SupplementalFieldKind.OvervoteIndicator) + Value(SupplementalFieldKind.UndervoteIndicator);
        int differenceValue = total + election.L * Value(SupplementalFieldKind.OvervoteIndicator) + Value(SupplementalFieldKind.UndervoteDifferenceCount);
        int nullValue = total + election.L * Value(SupplementalFieldKind.OvervoteIndicator) + election.L * Value(SupplementalFieldKind.NullVoteIndicator);

        var tamperedContest = contest with
        {
            Proofs = DeviceProof(election, ballot, LimitCiphertext(election, contest, omit), limitValue, 0, election.L, LimitPrefix(election)),
            UndervoteDifferenceProof = election.Declares(SupplementalFieldKind.UndervoteDifferenceCount)
                ? DeviceProof(election, ballot, DifferenceCiphertext(election, contest, omit), differenceValue, election.L, election.L, DifferencePrefix(election))
                : null,
            NullVoteProof = election.Declares(SupplementalFieldKind.NullVoteIndicator)
                ? DeviceProof(election, ballot, NullVoteCiphertext(election, contest, omit), nullValue, 0, election.L, NullVotePrefix(election))
                : null,
        };

        var tampered = WithContest(ballot, _ => tamperedContest);
        Verify6(election, tampered);
        return tampered;
    }

    /// <summary>
    /// <paramref name="forged"/> with only its null-vote proof re-proved over S5b's relation
    /// s + w + L*null, without the L*overvote term that user decision Q17 added: a valid proof of
    /// a true statement, which only a verifier that includes the term rejects.
    /// </summary>
    private static EncryptedBallot WithoutOvervoteTermInNullVoteProof(Election election, EncryptedBallot forged) =>
        WithContest(forged, c => c with
        {
            NullVoteProof = DeviceProof(
                election,
                forged,
                NullVoteCiphertext(election, c, omit: SupplementalFieldKind.OvervoteIndicator),
                Plaintext(c.Choices[0], election.K) + Plaintext(c.Choices[1], election.K)
                    + Plaintext(c.Field(SupplementalFieldKind.WriteInCount), election.K)
                    + election.L * Plaintext(c.Field(SupplementalFieldKind.NullVoteIndicator), election.K),
                0,
                election.L,
                NullVotePrefix(election)),
        });

    public static TheoryData<string> ForgeryCases() => new()
    {
        "overvote indicator set beside real selections",
        "null-vote indicator set beside a selection",
        "null-vote indicator set beside a write-in",
        "null-vote indicator set on an overvote",
        "undervote difference ignores a selection",
        "undervote difference ignores the write-ins",
        "undervote difference L on an overvote",
        "undervote indicator set on a full contest",
        "undervote indicator set when write-ins fill the contest",
        "write-in count beside a full contest",
        "overvote indicator set beside real selections, proved without its term",
        "null-vote indicator set beside a selection, proved without its term",
        "null-vote indicator set on an overvote, null-vote proof without the overvote term",
        "undervote indicator set on a full contest, proved without its term",
        "write-in count beside a full contest, proved without its term",
    };

    [Theory]
    [MemberData(nameof(ForgeryCases))]
    public void Verification7_DeviceThatForgesAFieldAndReprovesEveryRelation_Fails7D(string forgery)
    {
        // Each forged value is inside its field's range, so Verification 6 passes (Forge checks
        // that), and the device recomputes every relation proof. The relation the forgery breaks
        // has a value outside its range, so no proof can hold. The "without its term" cases prove
        // valid statements that leave the forged field out, so they fail only because Verification
        // 7 includes that field in the relation (a verifier that dropped the term would accept).
        var election = Build(selectionLimit: 2, optionSelectionLimit: 2);
        var (expectedMessage, tampered) = forgery switch
        {
            // (1) s + w + L*overvote + und = 2 + 2 > L.
            "overvote indicator set beside real selections" => ("Sum of challenge values", Forge(election, Encrypt(election, 1, 1), null, (SupplementalFieldKind.OvervoteIndicator, 1))),
            // (3) s + w + L*overvote + L*null = 1 + 0 + 2 > L.
            "null-vote indicator set beside a selection" => ("Null-vote proof", Forge(election, Encrypt(election, 1, 0), null, (SupplementalFieldKind.NullVoteIndicator, 1))),
            "null-vote indicator set beside a write-in" => ("Null-vote proof", Forge(election, Encrypt(election, 0, 0, 1), null, (SupplementalFieldKind.NullVoteIndicator, 1))),
            // (3) on an overvote: 0 + L + L > L (Q17; p.39 and Q3: null is 0 on an overvote). Before
            // Q17, (3) had no overvote term and this forgery verified. (1) and (2) give L.
            "null-vote indicator set on an overvote" => ("Null-vote proof", Forge(election, Encrypt(election, 2, 1), null, (SupplementalFieldKind.NullVoteIndicator, 1))),
            // (2) s + w + L*overvote + u = 1 + 2 != L.
            "undervote difference ignores a selection" => ("Undervote difference", Forge(election, Encrypt(election, 1, 0), null, (SupplementalFieldKind.UndervoteDifferenceCount, 2))),
            "undervote difference ignores the write-ins" => ("Undervote difference", Forge(election, Encrypt(election, 1, 0, 1), null, (SupplementalFieldKind.UndervoteDifferenceCount, 1))),
            // (2) on an overvote: 0 + L + L != L (Q15: u = 0 on an overvote).
            "undervote difference L on an overvote" => ("Undervote difference", Forge(election, Encrypt(election, 2, 1), null, (SupplementalFieldKind.UndervoteDifferenceCount, 2))),
            // (1) s + w + und = L + 1.
            "undervote indicator set on a full contest" => ("Sum of challenge values", Forge(election, Encrypt(election, 1, 1), null, (SupplementalFieldKind.UndervoteIndicator, 1), (SupplementalFieldKind.UndervoteDifferenceCount, 0))),
            "undervote indicator set when write-ins fill the contest" => ("Sum of challenge values", Forge(election, Encrypt(election, 1, 0, 1), null, (SupplementalFieldKind.UndervoteIndicator, 1))),
            // (1) s + w = 2 + 1 > L: write-ins always count (Q13).
            "write-in count beside a full contest" => ("Sum of challenge values", Forge(election, Encrypt(election, 2, 0), null, (SupplementalFieldKind.WriteInCount, 1))),
            // The same forgeries, each relation proved without the forged field's term.
            "overvote indicator set beside real selections, proved without its term" => ("Sum of challenge values", Forge(election, Encrypt(election, 1, 1), SupplementalFieldKind.OvervoteIndicator, (SupplementalFieldKind.OvervoteIndicator, 1))),
            "null-vote indicator set beside a selection, proved without its term" => ("Null-vote proof", Forge(election, Encrypt(election, 1, 0), SupplementalFieldKind.NullVoteIndicator, (SupplementalFieldKind.NullVoteIndicator, 1))),
            // Only the null-vote proof leaves the overvote term out (Forge's omit would drop it
            // from (1) too, which then fails first): 0 + L*null = L is a true statement, so only
            // a verifier whose (3) includes L*overvote (Q17) rejects it.
            "null-vote indicator set on an overvote, null-vote proof without the overvote term" => ("Null-vote proof", WithoutOvervoteTermInNullVoteProof(election, Forge(election, Encrypt(election, 2, 1), null, (SupplementalFieldKind.NullVoteIndicator, 1)))),
            "undervote indicator set on a full contest, proved without its term" => ("Sum of challenge values", Forge(election, Encrypt(election, 1, 1), SupplementalFieldKind.UndervoteIndicator, (SupplementalFieldKind.UndervoteIndicator, 1))),
            "write-in count beside a full contest, proved without its term" => ("Sum of challenge values", Forge(election, Encrypt(election, 2, 0), SupplementalFieldKind.WriteInCount, (SupplementalFieldKind.WriteInCount, 1))),
            _ => throw new ArgumentOutOfRangeException(nameof(forgery)),
        };

        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7.D", exception.SubSection);
        Assert.Contains(expectedMessage, exception.Message);
    }

    public static TheoryData<string> UncheckedCases() => new()
    {
        "undervote indicator 0 below the limit",
        "null-vote indicator 0 on a null vote",
        "null vote reported as an overvote",
    };

    [Theory]
    [MemberData(nameof(UncheckedCases))]
    public void Verification7_InconsistentIndicatorsNoRelationCovers_Verify(string forgery)
    {
        // The known gaps documented on AdherenceToVoteLimitsVerification, pinned so that the
        // documentation cannot drift from the code: a device that forges these values and re-proves
        // every relation passes Verifications 6 and 7. A case that starts failing here has been
        // closed and moves to ForgeryCases, as "null-vote indicator 1 on an overvote" did with
        // user decision Q17 ("null-vote indicator set on an overvote").
        var election = Build(selectionLimit: 2, optionSelectionLimit: 2);
        var tampered = forgery switch
        {
            // Q2 (no disjunctive proofs): (1) s + w + und = 1 + 0 is in 0..L.
            "undervote indicator 0 below the limit" => Forge(election, Encrypt(election, 1, 0), null, (SupplementalFieldKind.UndervoteIndicator, 0)),
            // Q2: (3) s + w + L*overvote + L*null = 0 is in 0..L.
            "null-vote indicator 0 on a null vote" => Forge(election, Encrypt(election, 0, 0), null, (SupplementalFieldKind.NullVoteIndicator, 0)),
            // Inherent, as in the spec: the overvote indicator is only checked against s + w = 0, so
            // a null vote re-encoded as an encrypted overvote (overvote 1, everything else 0) gives
            // (1) L, (2) L and (3) L, all honest values for an overvote.
            "null vote reported as an overvote" => Forge(
                election,
                Encrypt(election, 0, 0),
                null,
                (SupplementalFieldKind.OvervoteIndicator, 1),
                (SupplementalFieldKind.NullVoteIndicator, 0),
                (SupplementalFieldKind.UndervoteIndicator, 0),
                (SupplementalFieldKind.UndervoteDifferenceCount, 0)),
            _ => throw new ArgumentOutOfRangeException(nameof(forgery)),
        };

        // Not vacuous: the forged ballot really carries an inconsistent value.
        var (kind, value) = forgery switch
        {
            "undervote indicator 0 below the limit" => (SupplementalFieldKind.UndervoteIndicator, 0),
            "null-vote indicator 0 on a null vote" => (SupplementalFieldKind.NullVoteIndicator, 0),
            _ => (SupplementalFieldKind.OvervoteIndicator, 1),
        };
        Assert.Equal(value, Plaintext(tampered.Contests[0].Field(kind), election.K));
        Assert.Null(Record.Exception(() => Verify7(election, tampered)));
    }

    [Fact]
    public void Verification7_OvervoteIndicatorSetOnAnHonestSelectionWithoutReproving_Fails7D()
    {
        // The indicator alone passes Verification 6 (1 is in 0..1), but the selection plus L times
        // the indicator is 2 > L: the selection-limit proof cannot hold (§3.3.9 p.39).
        var election = Build();
        var ballot = Encrypt(election, 1, 0);
        var forged = Reencrypt(election, ballot, SupplementalFieldKind.OvervoteIndicator, value: 1);
        var tampered = WithContest(ballot, c => c.WithField(SupplementalFieldKind.OvervoteIndicator, forged));

        Verify6(election, tampered);
        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7.D", exception.SubSection);
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
    public void Verification7_TamperedNullVoteProof_Fails7D()
    {
        var election = Build(selectionLimit: 2);
        var ballot = Encrypt(election, 1, 0);
        var proofs = ballot.Contests[0].NullVoteProof!;
        var tampered = WithContest(ballot, c => c with { NullVoteProof = [proofs[0] with { Response = proofs[0].Response + 1 }, .. proofs.Skip(1)] });

        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7.D", exception.SubSection);
        Assert.Contains("Null-vote proof", exception.Message);
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

    [Theory]
    [InlineData("missing")]
    [InlineData("one too few")]
    [InlineData("one too many")]
    public void Verification7_NullVoteProofOfTheWrongLength_Fails(string fault)
    {
        // The null-vote proof ranges over 0..L, so it has L + 1 entries when the indicator is declared.
        var election = Build(selectionLimit: 2);
        var ballot = Encrypt(election, 1, 0);
        var proofs = ballot.Contests[0].NullVoteProof!;
        Assert.Equal(3, proofs.Length);
        ChallengeResponsePair[]? changed = fault switch
        {
            "missing" => null,
            "one too few" => proofs[..2],
            _ => [.. proofs, proofs[0]],
        };
        var tampered = WithContest(ballot, c => c with { NullVoteProof = changed });

        var exception = Assert.Throws<VerificationFailedException>(() => Verify7(election, tampered));

        Assert.Equal("7", exception.SubSection);
    }

    [Fact]
    public void Verification7_NullVoteProofWithoutTheField_Fails()
    {
        var election = Build(kinds: [SupplementalFieldKind.OvervoteIndicator]);
        var ballot = Encrypt(election, 1, 0);
        Assert.Null(ballot.Contests[0].NullVoteProof);
        var tampered = WithContest(ballot, c => c with { NullVoteProof = c.Proofs });

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
        ["null-vote proof entry"] = (c => c["nullVoteProof"]![0] = null, c => c.NullVoteProof),
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
        { "null-vote proof entry", 7 },
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
