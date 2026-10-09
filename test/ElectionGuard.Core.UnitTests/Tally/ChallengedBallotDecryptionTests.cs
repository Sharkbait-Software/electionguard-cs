using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Serialization.Converters;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;
using System.Numerics;
using System.Text.Json;

namespace ElectionGuard.Core.UnitTests.Tally;

/// <summary>
/// §3.6.7 decryption of challenged ballots (G18) and Verifications 13 and 14, on a real 2-of-3
/// guardian set. The minimal manifest with write-ins has two options, L = R = 1, every supplemental
/// field and b_Λ = 2. The known-answer tests pin the bytes; these pin the behavior, the refusals and
/// the sub-sections.
/// </summary>
public class ChallengedBallotDecryptionTests
{
    public ChallengedBallotDecryptionTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private const string WriteIn = "Write-in: Ada Lovelace";

    private sealed class Election
    {
        public required ElectionFixtureBuilder.GuardianSetResult GuardianSet { get; init; }
        public required Manifest Manifest { get; init; }
        public required EncryptionRecord Record { get; init; }
        public required VotingDeviceInformationHash DeviceHash { get; init; }

        public Contest Contest => Manifest.Contests.Single();

        public EncryptedBallot Encrypt(
            int choice1 = 1,
            int choice2 = 0,
            int writeIns = 0,
            string? text = WriteIn,
            string ballotId = "ballot-1",
            BallotStatus status = BallotStatus.Challenged,
            BallotNonce? ballotNonce = null)
        {
            var plaintext = ElectionFixtureBuilder.CreateBallot(Manifest, ballotId,
                new Dictionary<string, int> { ["choice-1"] = choice1, ["choice-2"] = choice2 }, writeIns, text);
            var encrypted = new BallotEncryptor(Record, "device-1", DeviceHash).Encrypt(
                plaintext,
                null,
                new SelectionEncryptionIdentifier(ElectionGuardRandom.GetBytes(32)),
                ballotNonce ?? new BallotNonce(ElectionGuardRandom.GetBytes(32)));
            if (status != BallotStatus.Unrecorded)
            {
                encrypted.RecordStatus(status);
            }

            return encrypted;
        }

        /// <summary>A view of the published record with no cast ballot: nothing to refuse on (user decision Q31).</summary>
        public PublishedCastBallots NoCastBallots => new(Record.ExtendedBaseHash);

        public List<TallyGuardian> Guardians(params int[] positions) =>
            positions.Select(i => new TallyGuardian(GuardianSet.Guardians[i].Index, GuardianSet.SecretShares[GuardianSet.Guardians[i].Index])).ToList();

        public void Verify13(EncryptedBallot ballot, DecryptedChallengedBallot decrypted) =>
            new ChallengedBallotDecryptionVerification().Verify(Record, ballot, decrypted, DeviceHash, null);

        public void Verify14(EncryptedBallot ballot, DecryptedChallengedBallot decrypted) =>
            new ChallengedBallotWellFormednessVerification().Verify(Manifest, ballot, decrypted);
    }

    private static Election Build()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        return new Election
        {
            GuardianSet = guardianSet,
            Manifest = manifest,
            Record = record.EncryptionRecord,
            DeviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1"),
        };
    }

    private static readonly Lazy<Election> Shared = new(Build);

    /// <summary>One ballot and its honest decryption, shared by the tamper theories (read only).</summary>
    private static readonly Lazy<(EncryptedBallot Ballot, DecryptedChallengedBallot Decrypted)> Opened = new(() =>
    {
        var election = Shared.Value;
        var ballot = election.Encrypt();
        return (ballot, new TallyAdmin().DecryptChallengedBallot(election.Guardians(0, 1), ballot, election.Record, election.NoCastBallots));
    });

    private static EncryptedBallot Copy(EncryptedBallot ballot, BallotStatus? status = null, EncryptedBallotNonce? nonce = null, SelectionEncryptionIdentifierHash? selectionHash = null, List<EncryptedContest>? contests = null, string? ballotStyleId = null, string? id = null, SelectionEncryptionIdentifier? identifier = null) => new()
    {
        Id = id ?? ballot.Id,
        SelectionEncryptionIdentifier = identifier ?? ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = selectionHash ?? ballot.SelectionEncryptionIdentifierHash,
        BallotStyleId = ballotStyleId ?? ballot.BallotStyleId,
        Contests = contests ?? ballot.Contests,
        ConfirmationCode = ballot.ConfirmationCode,
        EncryptedBallotNonce = nonce ?? ballot.EncryptedBallotNonce,
        ChainingField = ballot.ChainingField,
        Weight = ballot.Weight,
        Status = status ?? ballot.Status,
        DeviceId = ballot.DeviceId,
    };

    private static EncryptedBallotNonce With(EncryptedBallotNonce nonce, IntegerModP? c0 = null, byte[]? c1 = null, IntegerModQ? challenge = null, IntegerModQ? response = null) => new()
    {
        C0 = c0 ?? nonce.C0,
        C1 = c1 ?? nonce.C1,
        Challenge = challenge ?? nonce.Challenge,
        Response = response ?? nonce.Response,
    };

    private static DecryptedChallengedBallot With(DecryptedChallengedBallot decrypted, Func<DecryptedChallengedContest, DecryptedChallengedContest>? contest = null, string? ballotId = null, List<DecryptedChallengedContest>? contests = null) => new()
    {
        BallotId = ballotId ?? decrypted.BallotId,
        Contests = contests ?? decrypted.Contests.Select(x => contest is null ? x : contest(x)).ToList(),
    };

    private static DecryptedChallengedContest With(DecryptedChallengedContest contest, string? contestId = null, List<DecryptedChallengedField>? choices = null, List<DecryptedChallengedField>? fields = null, DecryptedChallengedContestData? data = null, bool dropData = false) => new()
    {
        ContestId = contestId ?? contest.ContestId,
        Choices = choices ?? contest.Choices,
        SupplementalFields = fields ?? contest.SupplementalFields,
        ContestData = dropData ? null : data ?? contest.ContestData,
    };

    private static DecryptedChallengedField With(DecryptedChallengedField field, string? id = null, int? value = null, IntegerModQ? nonce = null) => new()
    {
        Id = id ?? field.Id,
        Value = value ?? field.Value,
        EncryptionNonce = nonce ?? field.EncryptionNonce,
    };

    private static List<DecryptedChallengedField> Replace(List<DecryptedChallengedField> fields, string id, Func<DecryptedChallengedField, DecryptedChallengedField> change) =>
        fields.Select(x => x.Id == id ? change(x) : x).ToList();

    private static string FieldId(SupplementalFieldKind kind) => ElectionFixtureBuilder.SupplementalFieldId(kind);

    // --- Decryption ---------------------------------------------------------------------------

    [Theory]
    [InlineData(new[] { 0, 1 })]
    [InlineData(new[] { 0, 2 })]
    [InlineData(new[] { 1, 2 })]
    [InlineData(new[] { 0, 1, 2 })]
    public void DecryptChallengedBallot_AnyQuorum_ReleasesTheSelectionsAndContestData_AndVerifications13And14Accept(int[] positions)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(choice1: 0, choice2: 1);

        var decrypted = new TallyAdmin().DecryptChallengedBallot(election.Guardians(positions), ballot, election.Record, election.NoCastBallots);

        Assert.Equal(ballot.Id, decrypted.BallotId);
        var contest = Assert.Single(decrypted.Contests);
        Assert.Equal("contest-1", contest.ContestId);
        Assert.Equal(new[] { "choice-1", "choice-2" }, contest.Choices.Select(x => x.Id));
        Assert.Equal(new[] { 0, 1 }, contest.Choices.Select(x => x.Value));
        Assert.Equal(election.Contest.SupplementalFields.Select(x => x.Id), contest.SupplementalFields.Select(x => x.Id));
        Assert.All(contest.SupplementalFields, x => Assert.Equal(0, x.Value));
        Assert.Equal(WriteIn, contest.ContestData!.DecodeText());

        // Each released nonce reproduces its field's α (eq. 31) and the contest data's C_0 (eq. 67).
        var encrypted = ballot.Contests.Single();
        Assert.All(contest.Choices, x => Assert.Equal(encrypted.Choices.Single(c => c.ChoiceId == x.Id).Alpha, MontgomeryModP.PowModP(EGParameters.G, x.EncryptionNonce)));
        Assert.All(contest.SupplementalFields, x => Assert.Equal(encrypted.SupplementalFields.Single(c => c.FieldId == x.Id).Alpha, MontgomeryModP.PowModP(EGParameters.G, x.EncryptionNonce)));
        Assert.Equal(encrypted.ContestData!.C0, MontgomeryModP.PowModP(EGParameters.G, contest.ContestData.EncryptionNonce));

        election.Verify13(ballot, decrypted);
        election.Verify14(ballot, decrypted);
    }

    /// <summary>
    /// §3.6.7: "The ballot nonce ξ_B should not be published." What is released is exactly the
    /// eq. (33) nonces and the eq. (64) contest data nonce derived from it.
    /// </summary>
    [Fact]
    public void DecryptChallengedBallot_ReleasesTheDerivedNonces_NeverTheBallotNonce()
    {
        var election = Shared.Value;
        var ballotNonceBytes = ElectionGuardRandom.GetBytes(32);
        var ballot = election.Encrypt(ballotNonce: new BallotNonce((byte[])ballotNonceBytes.Clone()));
        var selectionHash = ballot.SelectionEncryptionIdentifierHash;

        var decrypted = new TallyAdmin().DecryptChallengedBallot(election.Guardians(1, 2), ballot, election.Record, election.NoCastBallots);

        var contest = decrypted.Contests.Single();
        var manifestContest = election.Contest;
        foreach (var field in contest.Choices.Concat(contest.SupplementalFields))
        {
            int index = manifestContest.VerifiableFields().Single(x => x.Id == field.Id).Index;
            Assert.Equal((IntegerModQ)new EncryptionNonce(selectionHash, new BallotNonce(ballotNonceBytes), 1, index), field.EncryptionNonce);
        }

        Assert.Equal(ContestDataEncryption.Nonce(selectionHash, 1, new BallotNonce(ballotNonceBytes)), contest.ContestData!.EncryptionNonce);

        var options = new JsonSerializerOptions { Converters = { new IntegerModQJsonConverter(), new IntegerModPJsonConverter() } };
        var published = JsonSerializer.Serialize(decrypted, options);
        Assert.DoesNotContain(Convert.ToBase64String(ballotNonceBytes), published);
        Assert.DoesNotContain(Convert.ToHexString(ballotNonceBytes), published, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(new IntegerModQ(ballotNonceBytes).ToByteArray()), published);
    }

    /// <summary>
    /// An overvoted contest (§3.3.5) was encrypted with every option zeroed, the write-in count zeroed
    /// and the overvote indicator set (user decisions Q11, Q12): that is what the decryption shows,
    /// and Verifications 13 and 14 accept it.
    /// </summary>
    [Fact]
    public void DecryptChallengedBallot_Overvote_ShowsTheNeutralizedContest()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(choice1: 1, choice2: 1, writeIns: 1);

        var decrypted = new TallyAdmin().DecryptChallengedBallot(election.Guardians(0, 2), ballot, election.Record, election.NoCastBallots);

        var contest = decrypted.Contests.Single();
        Assert.Equal(new[] { 0, 0 }, contest.Choices.Select(x => x.Value));
        Assert.Equal(1, contest.SupplementalFields.Single(x => x.Id == FieldId(SupplementalFieldKind.OvervoteIndicator)).Value);
        Assert.Equal(0, contest.SupplementalFields.Single(x => x.Id == FieldId(SupplementalFieldKind.WriteInCount)).Value);
        election.Verify13(ballot, decrypted);
        election.Verify14(ballot, decrypted);
    }

    /// <summary>
    /// The encrypted nonce is not an input to the confirmation code (eqs. 70, 71): the same ballot
    /// under the same id_B and ξ_B has the same H_C with a different C_ξB (ξ-hat_B is fresh each time).
    /// </summary>
    [Fact]
    public void Encrypt_TheEncryptedBallotNonceIsNotAnInputToTheConfirmationCode()
    {
        var election = Shared.Value;
        var identifier = new SelectionEncryptionIdentifier(ElectionGuardRandom.GetBytes(32));
        var nonce = ElectionGuardRandom.GetBytes(32);

        // The contest data proof's u (eq. 69) is fixed too: C_2 is hashed into the contest hash.
        IntegerModQ contestDataProofNonce = ElectionGuardRandom.GetIntegerModQ();
        EncryptedBallot Encrypt() => new BallotEncryptor(election.Record, "device-1", election.DeviceHash) { ContestDataProofNonceForTesting = _ => contestDataProofNonce }.Encrypt(
            ElectionFixtureBuilder.CreateBallot(election.Manifest, "ballot-1", new Dictionary<string, int> { ["choice-1"] = 1 }), null, identifier, new BallotNonce((byte[])nonce.Clone()));

        var first = Encrypt();
        var second = Encrypt();

        Assert.Equal(first.ConfirmationCode, second.ConfirmationCode);
        Assert.NotEqual(first.EncryptedBallotNonce.C0, second.EncryptedBallotNonce.C0);
        Assert.Equal(BallotNonceEncryption.NonceBytes, first.EncryptedBallotNonce.C1.Length);
        Assert.True(BallotNonceEncryption.ProofHolds(first.SelectionEncryptionIdentifierHash, first.EncryptedBallotNonce));
    }

    // --- The guardians' and the administrator's refusals ----------------------------------------

    /// <summary>Decrypting a cast ballot's nonce would reveal its votes: guardians and administrator refuse.</summary>
    [Theory]
    [InlineData(BallotStatus.Cast)]
    [InlineData(BallotStatus.Unrecorded)]
    [InlineData(BallotStatus.Spoiled)]
    public void DecryptBallotNonce_BallotNotRecordedAsChallenged_IsRefused(BallotStatus status)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(status: status);
        var guardians = election.Guardians(0, 1);

        Assert.Contains("challenged", Assert.Throws<ArgumentException>(() => guardians[0].DecryptBallotNonce(ballot, election.Record, election.NoCastBallots)).Message);

        // The administrator too, given partial decryptions made for the same ballot once challenged.
        var challenged = Copy(ballot, status: BallotStatus.Challenged);
        var partials = guardians.Select(x => x.DecryptBallotNonce(challenged, election.Record, election.NoCastBallots)).ToList();
        Assert.Throws<ArgumentException>(() => new TallyAdmin().CombineChallengedBallot(ballot, election.Record, partials));
    }

    [Fact]
    public void DecryptBallotNonce_MalformedBallotOrForeignH_I_IsRefused()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt();
        var guardian = election.Guardians(0)[0];

        Assert.Throws<ArgumentException>(() => guardian.DecryptBallotNonce(Copy(ballot, nonce: With(ballot.EncryptedBallotNonce, c1: ballot.EncryptedBallotNonce.C1[1..])), election.Record, election.NoCastBallots));
        Assert.Throws<ArgumentException>(() => guardian.DecryptBallotNonce(Copy(ballot, selectionHash: new SelectionEncryptionIdentifierHash(ElectionGuardRandom.GetBytes(32))), election.Record, election.NoCastBallots));
    }

    // --- Who may have a ballot's nonce decrypted (user decision Q31) -----------------------------

    /// <summary>
    /// The security review finding on S7: a cast ballot, relabelled challenged, under its own string
    /// id or a new one, passes the status, structure, H_I and eq. (38) checks, since all of them read
    /// the ballot object the requester supplies. The guardians refuse it by the record check, whose
    /// view of the cast ballots is their own, before any exponentiation with ẑ_i; so does the
    /// administrator's wrapper, through them.
    /// </summary>
    [Theory]
    [InlineData("same id")]
    [InlineData("new id")]
    public void DecryptBallotNonce_CastBallotRelabelledChallenged_IsRefusedByTheRecordCheck(string copy)
    {
        var election = Shared.Value;
        var cast = election.Encrypt(ballotId: "cast-1", status: BallotStatus.Cast);
        var published = PublishedCastBallots.FromRecord(election.Record.ExtendedBaseHash, [cast, election.Encrypt(ballotId: "challenged-1")]);
        Assert.Equal(1, published.Count);
        var relabelled = Copy(cast, status: BallotStatus.Challenged, id: copy == "new id" ? "challenged-copy" : null);
        var guardians = election.Guardians(0, 1);
        bool exponentiated = false;
        guardians.ForEach(x => x.PartialDecryptionTamperForTesting = (_, _, m) => { exponentiated = true; return m; });

        // Without the record check nothing about the copy would be refused.
        Assert.Null(BallotStructure.FindViolation(relabelled, election.Record.Manifest));
        Assert.True(BallotNonceEncryption.ProofHolds(relabelled.SelectionEncryptionIdentifierHash, relabelled.EncryptedBallotNonce));

        var refused = Assert.Throws<BallotNonceDecryptionRefusedException>(() => guardians[0].DecryptBallotNonce(relabelled, election.Record, published));
        Assert.Equal(BallotNonceDecryptionRefusal.CastBallot, refused.Reason);
        Assert.Equal(guardians[0].Index, refused.GuardianIndex);
        Assert.Equal(relabelled.Id, refused.BallotId);
        Assert.Contains("id_B, H_I, C_ξB,0", refused.Message);
        Assert.Equal(BallotNonceDecryptionRefusal.CastBallot, Assert.Throws<BallotNonceDecryptionRefusedException>(
            () => new TallyAdmin().DecryptChallengedBallot(guardians, relabelled, election.Record, published)).Reason);
        Assert.False(exponentiated);
    }

    /// <summary>
    /// The record check matches each of id_B, H_I and C_ξB,0 on its own: a challenged ballot that
    /// shares any one of them with a cast ballot is refused, naming what matched. (A ballot whose
    /// C_ξB is another ballot's fails the eq. (38) proof anyway, since c_B binds H_I; the refusal
    /// comes first.)
    /// </summary>
    [Theory]
    [InlineData("id_B and H_I", CastBallotMatch.SelectionEncryptionIdentifier | CastBallotMatch.SelectionEncryptionIdentifierHash)]
    [InlineData("H_I", CastBallotMatch.SelectionEncryptionIdentifierHash)]
    [InlineData("C_ξB,0", CastBallotMatch.EncryptedBallotNonce)]
    public void DecryptBallotNonce_ChallengedBallotSharingAValueWithACastBallot_IsRefused(string shared, CastBallotMatch expected)
    {
        var election = Shared.Value;
        var cast = election.Encrypt(ballotId: "cast-1", status: BallotStatus.Cast);
        var published = PublishedCastBallots.FromRecord(election.Record.ExtendedBaseHash, [cast]);
        var challenged = election.Encrypt(ballotId: "challenged-1");
        var request = shared switch
        {
            "id_B and H_I" => Copy(challenged, identifier: cast.SelectionEncryptionIdentifier, selectionHash: cast.SelectionEncryptionIdentifierHash),
            "H_I" => Copy(challenged, selectionHash: cast.SelectionEncryptionIdentifierHash),
            _ => Copy(challenged, nonce: cast.EncryptedBallotNonce),
        };

        Assert.Equal(expected, published.Match(request.SelectionEncryptionIdentifier, request.SelectionEncryptionIdentifierHash, request.EncryptedBallotNonce.C0));
        var refused = Assert.Throws<BallotNonceDecryptionRefusedException>(() => election.Guardians(0)[0].DecryptBallotNonce(request, election.Record, published));
        Assert.Equal(BallotNonceDecryptionRefusal.CastBallot, refused.Reason);
        Assert.Contains($"its {shared.Replace(" and ", ", ")} matches", refused.Message);
    }

    /// <summary>
    /// The honest path is unchanged: a challenged ballot that shares nothing with the record's cast
    /// ballots decrypts and verifies, the record holding cast ballots of the same election.
    /// </summary>
    [Fact]
    public void DecryptChallengedBallot_HonestChallengedBallot_WithCastBallotsInTheRecord_Decrypts()
    {
        var election = Shared.Value;
        var castBallots = Enumerable.Range(1, 3).Select(i => election.Encrypt(ballotId: $"cast-{i}", status: BallotStatus.Cast)).ToList();
        var challenged = election.Encrypt(choice1: 0, choice2: 1, ballotId: "challenged-1");
        var published = PublishedCastBallots.FromRecord(election.Record.ExtendedBaseHash, [.. castBallots, challenged]);
        Assert.Equal(3, published.Count);

        var decrypted = new TallyAdmin().DecryptChallengedBallot(election.Guardians(0, 2), challenged, election.Record, published);

        election.Verify13(challenged, decrypted);
        election.Verify14(challenged, decrypted);
        Assert.Equal([0, 1], decrypted.Contests.Single().Choices.Select(x => x.Value));
    }

    /// <summary>A cast-ballot view built for another election cannot vouch for a request here.</summary>
    [Fact]
    public void DecryptBallotNonce_CastBallotViewOfAnotherElection_IsRefused()
    {
        var election = Shared.Value;
        var other = Build();
        var refused = Assert.Throws<BallotNonceDecryptionRefusedException>(
            () => election.Guardians(0)[0].DecryptBallotNonce(election.Encrypt(), election.Record, other.NoCastBallots));
        Assert.Equal(BallotNonceDecryptionRefusal.ForeignElection, refused.Reason);
    }

    /// <summary>
    /// §3.6.7 p.52: "Only if the proof is verified as correct" does a guardian decrypt. Every tamper
    /// of C_ξB breaks the eq. (38) proof (C_ξB,1 is hashed into c_B), and the guardian refuses naming
    /// no guardian: the fault is the ballot's.
    /// </summary>
    [Theory]
    [InlineData("response")]
    [InlineData("challenge")]
    [InlineData("C1")]
    [InlineData("C0")]
    public void DecryptBallotNonce_InvalidSchnorrProof_IsRefused(string tamper)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt();
        var nonce = ballot.EncryptedBallotNonce;
        var tampered = tamper switch
        {
            "response" => With(nonce, response: nonce.Response + 1),
            "challenge" => With(nonce, challenge: nonce.Challenge + 1),
            "C1" => With(nonce, c1: [(byte)(nonce.C1[0] ^ 1), .. nonce.C1[1..]]),
            _ => With(nonce, c0: nonce.C0 * new IntegerModP(EGParameters.G)),
        };
        var bad = Copy(ballot, nonce: tampered);
        Assert.False(BallotNonceEncryption.ProofHolds(ballot.SelectionEncryptionIdentifierHash, tampered));

        var exception = Assert.Throws<TallyDecryptionException>(() => election.Guardians(0)[0].DecryptBallotNonce(bad, election.Record, election.NoCastBallots));
        Assert.Null(exception.OffendingGuardian);
        Assert.Contains("eq. 38", exception.Message);

        // The administrator checks it again before combining anything.
        var partials = election.Guardians(0, 1).Select(x => x.DecryptBallotNonce(ballot, election.Record, election.NoCastBallots)).ToList();
        var adminException = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().CombineChallengedBallot(bad, election.Record, partials));
        Assert.Null(adminException.OffendingGuardian);
    }

    /// <summary>
    /// The S6 lesson, for C_ξB,0 (a library hardening the spec does not state): the eq. (38) proof
    /// accepts C_ξB,0 = 0 (with a_B = 0) and C_ξB,0 = -g^ξ-hat whenever c_B is even, so a guardian
    /// requires C_ξB,0 in Z_p^r before it raises it to its share ẑ_i (or it would hand out ẑ_i's
    /// parity). Each case first shows the forged proof holds, so the refusal comes from the
    /// membership check.
    /// </summary>
    [Theory]
    [InlineData("zero")]
    [InlineData("negated")]
    public void DecryptBallotNonce_C0NotInTheSubgroupWithAValidProof_IsRefusedNamingNoGuardian(string forgery)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt();
        var selectionHash = ballot.SelectionEncryptionIdentifierHash;
        var c1 = ballot.EncryptedBallotNonce.C1;
        EncryptedBallotNonce forged;
        if (forgery == "zero")
        {
            // a_B = g^v·0^c = 0 for c != 0.
            var challenge = BallotNonceEncryption.ProofChallenge(selectionHash, 0, 0, c1);
            forged = new EncryptedBallotNonce { C0 = 0, C1 = c1, Challenge = challenge, Response = 12345 };
        }
        else
        {
            // C_ξB,0 = -g^ξ-hat with an even c_B: (-g^ξ-hat)^c_B = g^(ξ-hat·c_B), so the proof holds.
            IntegerModQ xiHat = ElectionGuardRandom.GetIntegerModQ();
            var negated = new IntegerModP(EGParameters.P - MontgomeryModP.PowModP(EGParameters.G, xiHat).ToBigInteger());
            while (true)
            {
                var u = ElectionGuardRandom.GetIntegerModQ();
                var challenge = BallotNonceEncryption.ProofChallenge(selectionHash, MontgomeryModP.PowModP(EGParameters.G, u), negated, c1);
                if (challenge.ToBigInteger().IsEven)
                {
                    forged = new EncryptedBallotNonce { C0 = negated, C1 = c1, Challenge = challenge, Response = u - challenge * xiHat };
                    break;
                }
            }
        }

        Assert.True(BallotNonceEncryption.ProofHolds(selectionHash, forged));
        Assert.False(SubgroupMembership.IsMember(forged.C0));

        var exception = Assert.Throws<TallyDecryptionException>(() => election.Guardians(0)[0].DecryptBallotNonce(Copy(ballot, nonce: forged), election.Record, election.NoCastBallots));
        Assert.Null(exception.OffendingGuardian);
        Assert.Contains("Z_p^r", exception.Message);
    }

    /// <summary>
    /// §3.6.7 defines no proof of correct decryption for m_i, so a guardian that sends a wrong m_i
    /// cannot be named. The administrator still publishes nothing: the ξ_B it recovers does not
    /// reproduce the ballot's ciphertexts.
    /// </summary>
    [Fact]
    public void CombineChallengedBallot_WrongPartialDecryption_PublishesNothing()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt();
        var guardians = election.Guardians(0, 2);
        guardians[1].PartialDecryptionTamperForTesting = (c, o, m) =>
        {
            Assert.Equal((0, 0), (c, o));
            return m * new IntegerModP(EGParameters.G);
        };

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().DecryptChallengedBallot(guardians, ballot, election.Record, election.NoCastBallots));

        Assert.Null(exception.OffendingGuardian);
        Assert.Contains("did not decrypt consistently", exception.Message);
    }

    /// <summary>
    /// p.53: inconsistent nonces "may only reflect that the ballot nonce encryption was incorrect".
    /// A device that encrypted another nonce than the one its selections used (with a valid proof)
    /// yields a ξ_B that reproduces nothing, and the administrator refuses to publish.
    /// </summary>
    [Fact]
    public void CombineChallengedBallot_BallotNonceEncryptionOfAnotherNonce_PublishesNothing()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt();
        var otherNonce = BallotNonceEncryption.Encrypt(new BallotNonce(ElectionGuardRandom.GetBytes(32)), ballot.SelectionEncryptionIdentifierHash, election.Record.ElectionPublicKeys.OtherBallotDataEncryptionKey);
        var bad = Copy(ballot, nonce: otherNonce);

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().DecryptChallengedBallot(election.Guardians(0, 1), bad, election.Record, election.NoCastBallots));

        Assert.Null(exception.OffendingGuardian);
        Assert.Contains("does not reproduce", exception.Message);
    }

    /// <summary>
    /// The administrator's contest data branch: every selection was encrypted with its eq. (33)
    /// nonce, but the contest data was encrypted under another ballot nonce, so the eq. (64) ξ the
    /// administrator derives does not reproduce C_0. The fields open honestly first; the refusal
    /// comes from the contest data check, and nothing is published.
    /// </summary>
    [Fact]
    public void CombineChallengedBallot_ContestDataEncryptedUnderAnotherNonce_PublishesNothing()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt();
        var contest = ballot.Contests.Single();
        var otherData = ContestDataEncryption.Encrypt(
            ContestDataEncoding.Encode(WriteIn, election.Contest.ContestDataBlocks),
            election.Contest.Index,
            election.Contest.ContestDataBlocks,
            ballot.SelectionEncryptionIdentifierHash,
            new BallotNonce(ElectionGuardRandom.GetBytes(32)),
            election.Record.ElectionPublicKeys.OtherBallotDataEncryptionKey);
        var bad = Copy(ballot, contests: [contest with { ContestData = otherData }]);

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().DecryptChallengedBallot(election.Guardians(0, 1), bad, election.Record, election.NoCastBallots));

        Assert.Null(exception.OffendingGuardian);
        Assert.Contains("contest data nonce ξ (eq. 64) does not reproduce C_0", exception.Message);
    }

    [Fact]
    public void CombineChallengedBallot_ZeroPartialDecryption_NamesTheGuardian()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt();
        var guardians = election.Guardians(0, 2);
        guardians[1].PartialDecryptionTamperForTesting = (_, _, _) => 0;

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().DecryptChallengedBallot(guardians, ballot, election.Record, election.NoCastBallots));

        Assert.Equal(guardians[1].Index, exception.OffendingGuardian);
        Assert.Contains("is 0", exception.Message);
    }

    [Fact]
    public void CombineChallengedBallot_MessageForAnotherBallot_NamesTheSender()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt();
        var other = election.Encrypt(ballotId: "ballot-2");
        var guardians = election.Guardians(0, 1);
        var partials = new List<BallotNoncePartialDecryption>
        {
            guardians[0].DecryptBallotNonce(ballot, election.Record, election.NoCastBallots),
            guardians[1].DecryptBallotNonce(other, election.Record, election.NoCastBallots),
        };

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().CombineChallengedBallot(ballot, election.Record, partials));

        Assert.Equal(guardians[1].Index, exception.OffendingGuardian);
        Assert.Contains("ballot-2", exception.Message);
    }

    [Fact]
    public void CombineChallengedBallot_RepeatedMessageOrNoQuorum_IsRefused()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt();
        var guardians = election.Guardians(0, 1);
        var first = guardians[0].DecryptBallotNonce(ballot, election.Record, election.NoCastBallots);
        var second = guardians[1].DecryptBallotNonce(ballot, election.Record, election.NoCastBallots);

        var repeated = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().CombineChallengedBallot(ballot, election.Record, [first, second, first]));
        Assert.Equal(guardians[0].Index, repeated.OffendingGuardian);

        Assert.Throws<ArgumentException>(() => new TallyAdmin().CombineChallengedBallot(ballot, election.Record, [first]));
    }

    // --- Verification 13 ----------------------------------------------------------------------

    /// <summary>Each tamper of the published decryption, with the sub-section that must catch it.</summary>
    public static TheoryData<string, string> Verification13Tampers() => new()
    {
        { "wrong σ of an option", "13.B" },
        { "wrong σ of a supplemental field", "13.B" },
        { "wrong released ξ_{i,j}", "13.B" },
        { "released ξ of another field", "13.B" },
        { "wrong contest data ξ", "13.A" },
        { "tampered D", "13.A" },
        { "D one block short", "13.A" },
        { "tampered D and wrong σ", "13.A" },
        { "decryption for another ballot", "13.structure" },
        { "contest not on the ballot", "13.structure" },
        { "contest listed twice", "13.structure" },
        { "option missing", "13.structure" },
        { "option listed twice", "13.structure" },
        { "supplemental field missing", "13.structure" },
        { "contest data missing", "13.structure" },
        { "no contest list", "13.structure" },
        { "null contest entry", "13.structure" },
        { "no option list", "13.structure" },
        { "no supplemental field list", "13.structure" },
        { "null option entry", "13.structure" },
        { "unknown option label", "13.structure" },
        { "contest data D null", "13.A" },
    };

    private static DecryptedChallengedBallot Tamper13(DecryptedChallengedBallot d, string tamper)
    {
        var overvote = FieldId(SupplementalFieldKind.OvervoteIndicator);
        return tamper switch
        {
            "wrong σ of an option" => With(d, c => With(c, choices: Replace(c.Choices, "choice-1", f => With(f, value: 1 - f.Value)))),
            "wrong σ of a supplemental field" => With(d, c => With(c, fields: Replace(c.SupplementalFields, overvote, f => With(f, value: 1)))),
            "wrong released ξ_{i,j}" => With(d, c => With(c, choices: Replace(c.Choices, "choice-2", f => With(f, nonce: f.EncryptionNonce + 1)))),
            "released ξ of another field" => With(d, c => With(c, choices: Replace(c.Choices, "choice-1", f => With(f, nonce: c.Choices[1].EncryptionNonce)))),
            "wrong contest data ξ" => With(d, c => With(c, data: new DecryptedChallengedContestData { EncryptionNonce = c.ContestData!.EncryptionNonce + 1, Data = c.ContestData.Data })),
            "tampered D" => With(d, c => With(c, data: new DecryptedChallengedContestData { EncryptionNonce = c.ContestData!.EncryptionNonce, Data = [.. c.ContestData.Data[..^1], (byte)(c.ContestData.Data[^1] ^ 1)] })),
            "D one block short" => With(d, c => With(c, data: new DecryptedChallengedContestData { EncryptionNonce = c.ContestData!.EncryptionNonce, Data = c.ContestData.Data[32..] })),
            "tampered D and wrong σ" => Tamper13(Tamper13(d, "tampered D"), "wrong σ of an option"),
            "decryption for another ballot" => With(d, ballotId: "ballot-2"),
            "contest not on the ballot" => With(d, c => With(c, contestId: "contest-2")),
            "contest listed twice" => With(d, contests: [d.Contests[0], d.Contests[0]]),
            "option missing" => With(d, c => With(c, choices: [c.Choices[0]])),
            "option listed twice" => With(d, c => With(c, choices: [c.Choices[0], c.Choices[0]])),
            "supplemental field missing" => With(d, c => With(c, fields: c.SupplementalFields.Skip(1).ToList())),
            "contest data missing" => With(d, c => With(c, dropData: true)),
            "no contest list" => new DecryptedChallengedBallot { BallotId = d.BallotId, Contests = null! },
            "null contest entry" => With(d, contests: [null!]),
            "no option list" => With(d, c => new DecryptedChallengedContest { ContestId = c.ContestId, Choices = null!, SupplementalFields = c.SupplementalFields, ContestData = c.ContestData }),
            "no supplemental field list" => With(d, c => new DecryptedChallengedContest { ContestId = c.ContestId, Choices = c.Choices, SupplementalFields = null!, ContestData = c.ContestData }),
            "null option entry" => With(d, c => With(c, choices: [c.Choices[0], null!])),
            "unknown option label" => With(d, c => With(c, choices: [c.Choices[0], With(c.Choices[1], id: "choice-x")])),
            "contest data D null" => With(d, c => With(c, data: new DecryptedChallengedContestData { EncryptionNonce = c.ContestData!.EncryptionNonce, Data = null! })),
            _ => throw new ArgumentOutOfRangeException(nameof(tamper)),
        };
    }

    [Theory]
    [MemberData(nameof(Verification13Tampers))]
    public void Verification13_TamperedDecryption_FailsItsSubSection(string tamper, string subSection)
    {
        var election = Shared.Value;
        var (ballot, decrypted) = Opened.Value;
        election.Verify13(ballot, decrypted);

        var exception = Assert.Throws<VerificationFailedException>(() => election.Verify13(ballot, Tamper13(decrypted, tamper)));

        Assert.Equal(subSection, exception.SubSection);

        // The two 13.A causes are told apart: a ξ that does not reproduce C_0, or a D that is not C_1 ⊕ k.
        if (tamper == "wrong contest data ξ")
        {
            Assert.Contains("is not the ballot's C_0", exception.Message);
        }
        else if (tamper is "tampered D" or "D one block short" or "contest data D null")
        {
            Assert.Contains("C_1 is not D XOR", exception.Message);
        }
    }

    /// <summary>
    /// The adaptive forgery of the contest data (library hardening; the spec's 13.4-13.A has no
    /// α = C_0 step): release another nonce ξ' together with D' = C_1 ⊕ k(ξ'), the keys derived from
    /// h = H(H_I; 0x26, ind_c, g^ξ', K-hat^ξ'). D' decrypts C_1 under ξ' by construction, which the
    /// test asserts first, and χ_i hashes the ballot's own C_0, C_1, C_2, so 13.B cannot see it
    /// either. Only the comparison of α = g^ξ' with the ballot's C_0 catches it.
    /// </summary>
    [Fact]
    public void Verification13_ContestDataForgedUnderAnotherNonce_Fails13A()
    {
        var election = Shared.Value;
        var (ballot, decrypted) = Opened.Value;
        var encryptedData = ballot.Contests.Single().ContestData!;
        var selectionHash = ballot.SelectionEncryptionIdentifierHash;
        int index = election.Contest.Index;
        int blocks = election.Contest.ContestDataBlocks;

        var forgedNonce = decrypted.Contests[0].ContestData!.EncryptionNonce + 1;
        var forgedKey = ContestDataEncryption.SecretKey(
            selectionHash,
            index,
            MontgomeryModP.PowModP(EGParameters.G, forgedNonce),
            MontgomeryModP.PowModP(election.Record.ElectionPublicKeys.OtherBallotDataEncryptionKey, forgedNonce));
        var forgedData = ContestDataEncryption.Apply(forgedKey, index, blocks, encryptedData.C1);
        Assert.Equal(encryptedData.C1, ContestDataEncryption.Apply(forgedKey, index, blocks, forgedData));
        Assert.NotEqual(decrypted.Contests[0].ContestData!.Data, forgedData);

        var forged = With(decrypted, c => With(c, data: new DecryptedChallengedContestData { EncryptionNonce = forgedNonce, Data = forgedData }));
        var exception = Assert.Throws<VerificationFailedException>(() => election.Verify13(ballot, forged));

        Assert.Equal("13.A", exception.SubSection);
        Assert.Contains("is not the ballot's C_0", exception.Message);
    }

    /// <summary>
    /// A cast ballot presented with a decryption as if it were challenged fails 13.structure (and
    /// 14.structure); so does a spoiled one (S10b-1: a spoiled ballot is never decrypted).
    /// </summary>
    [Theory]
    [InlineData(BallotStatus.Cast)]
    [InlineData(BallotStatus.Spoiled)]
    public void Verification13And14_BallotNotChallengedPresentedWithADecryption_Fail(BallotStatus status)
    {
        var election = Shared.Value;
        var (ballot, decrypted) = Opened.Value;
        var cast = Copy(ballot, status: status);

        Assert.Equal("13.structure", Assert.Throws<VerificationFailedException>(() => election.Verify13(cast, decrypted)).SubSection);
        Assert.Equal("14.structure", Assert.Throws<VerificationFailedException>(() => election.Verify14(cast, decrypted)).SubSection);
    }

    [Fact]
    public void Verification13_MalformedBallotOrForeignH_I_Fails13Structure()
    {
        var election = Shared.Value;
        var (ballot, decrypted) = Opened.Value;

        var malformed = Copy(ballot, nonce: With(ballot.EncryptedBallotNonce, c1: [.. ballot.EncryptedBallotNonce.C1, 0]));
        Assert.Equal("13.structure", Assert.Throws<VerificationFailedException>(() => election.Verify13(malformed, decrypted)).SubSection);

        var foreign = Copy(ballot, selectionHash: new SelectionEncryptionIdentifierHash(ElectionGuardRandom.GetBytes(32)));
        Assert.Equal("13.structure", Assert.Throws<VerificationFailedException>(() => election.Verify13(foreign, decrypted)).SubSection);
    }

    /// <summary>13.B's chaining field B_C is formed from the device as for Verification 8: another device's B_C fails.</summary>
    [Fact]
    public void Verification13_AnotherDevice_Fails13B()
    {
        var election = Shared.Value;
        var (ballot, decrypted) = Opened.Value;
        var otherDevice = new VotingDeviceInformationHash(election.Record.ExtendedBaseHash, "device-2");

        var exception = Assert.Throws<VerificationFailedException>(() => new ChallengedBallotDecryptionVerification().Verify(election.Record, ballot, decrypted, otherDevice, null));

        Assert.Equal("13.B", exception.SubSection);
    }

    /// <summary>
    /// S8: the overload without a device hash or previous code computes 13.B over the chaining field
    /// the ballot carries ("B_C is the chaining field for ballot B"); whether that field is right for
    /// the ballot's device and chain position is Verification 8.D/8.E. A ballot whose stored field
    /// is not the one it was hashed with fails 13.B.
    /// </summary>
    [Fact]
    public void Verification13_OverTheBallotsOwnChainingField()
    {
        var election = Shared.Value;
        var (ballot, decrypted) = Opened.Value;
        var verification = new ChallengedBallotDecryptionVerification();

        Assert.Null(Record.Exception(() => verification.Verify(election.Record, ballot, decrypted)));

        byte[] field = ((byte[])ballot.ChainingField).ToArray();
        field[^1] ^= 0x01;
        var tampered = new EncryptedBallot
        {
            Id = ballot.Id,
            SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
            BallotStyleId = ballot.BallotStyleId,
            Contests = ballot.Contests,
            ConfirmationCode = ballot.ConfirmationCode,
            EncryptedBallotNonce = ballot.EncryptedBallotNonce,
            ChainingField = ChainingField.FromCanonicalBytes(field),
            Weight = ballot.Weight,
            Status = ballot.Status,
            DeviceId = ballot.DeviceId,
        };

        Assert.Equal("13.B", Assert.Throws<VerificationFailedException>(() => verification.Verify(election.Record, tampered, decrypted)).SubSection);
    }

    /// <summary>
    /// "If only selected contests have been decrypted -- as might be the case in an RLA setting --
    /// Verification step (13.B) uses contest hashes ... recomputed from the encrypted ballot for the
    /// contests that have not been decrypted." Verification 14.B, as written, still requires every
    /// contest of the ballot style on the decrypted ballot.
    /// </summary>
    [Fact]
    public void Verification13_ContestNotDecrypted_UsesTheEncryptedBallotsContestHash_And14BFails()
    {
        var election = Shared.Value;
        var (ballot, decrypted) = Opened.Value;
        var partial = With(decrypted, contests: []);

        election.Verify13(ballot, partial);

        Assert.Equal("14.B", Assert.Throws<VerificationFailedException>(() => election.Verify14(ballot, partial)).SubSection);
    }

    /// <summary>
    /// A three-contest manifest whose ballot style lists contests 1 and 3 only, so the ballot's second
    /// contest has ind_c = 3. Contest 1 offers write-ins and carries contest data (b_Λ = 2); contest 3
    /// carries none. A ballot of that style, challenged and opened by guardians 1 and 2.
    /// </summary>
    private static readonly Lazy<(Election Election, EncryptedBallot Ballot, DecryptedChallengedBallot Decrypted)> TwoOfThreeContests = new(() =>
    {
        var withData = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true).Manifest.Contests.Single();
        var plain = ElectionFixtureBuilder.CreateMinimalManifest().Manifest.Contests.Single();
        var manifest = new Manifest
        {
            ElectionId = "test-election-3",
            Contests =
            [
                withData with { Id = "contest-1", Name = "Contest 1", Index = 1 },
                plain with { Id = "contest-2", Name = "Contest 2", Index = 2 },
                plain with { Id = "contest-3", Name = "Contest 3", Index = 3 },
            ],
            BallotStyles = [new BallotStyle { Id = "style-1-3", Name = "Contests 1 and 3", ContestIds = ["contest-1", "contest-3"] }],
            ChainingMode = ChainingMode.None,
        };
        var manifestFile = ManifestSerializer.ToManifestFile(manifest);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var election = new Election
        {
            GuardianSet = guardianSet,
            Manifest = manifest,
            Record = record.EncryptionRecord,
            DeviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1"),
        };

        var plaintext = new Ballot
        {
            Id = "ballot-1-3",
            BallotStyleId = "style-1-3",
            Contests =
            [
                new BallotContest
                {
                    Id = "contest-1",
                    Choices = [new BallotChoice { Id = "choice-1", SelectionValue = 1 }, new BallotChoice { Id = "choice-2", SelectionValue = 0 }],
                    ContestData = ContestDataEncoding.Encode(WriteIn, withData.ContestDataBlocks),
                },
                new BallotContest
                {
                    Id = "contest-3",
                    Choices = [new BallotChoice { Id = "choice-1", SelectionValue = 0 }, new BallotChoice { Id = "choice-2", SelectionValue = 1 }],
                },
            ],
        };
        var ballot = new BallotEncryptor(election.Record, "device-1", election.DeviceHash).Encrypt(
            plaintext, null, new SelectionEncryptionIdentifier(ElectionGuardRandom.GetBytes(32)), new BallotNonce(ElectionGuardRandom.GetBytes(32)));
        ballot.RecordStatus(BallotStatus.Challenged);
        return (election, ballot, new TallyAdmin().DecryptChallengedBallot(election.Guardians(1, 2), ballot, election.Record, election.NoCastBallots));
    });

    [Fact]
    public void Verification13And14_BallotStyleSkippingAContest_AcceptTheFullDecryption()
    {
        var (election, ballot, decrypted) = TwoOfThreeContests.Value;

        Assert.Equal(new[] { "contest-1", "contest-3" }, decrypted.Contests.Select(x => x.ContestId));
        Assert.Equal(new[] { 0, 1 }, decrypted.Contests[1].Choices.Select(x => x.Value));
        Assert.Null(decrypted.Contests[1].ContestData);
        Assert.Equal(WriteIn, decrypted.Contests[0].ContestData!.DecodeText());

        election.Verify13(ballot, decrypted);
        election.Verify14(ballot, decrypted);
    }

    /// <summary>
    /// 13.B's RLA case with contests of both kinds: one contest's hash is recomputed from the released
    /// values, the other's taken from the encrypted ballot, and both are keyed by ind_c (3 for the
    /// ballot's second contest, never its position 2). Either contest alone verifies, and a wrong σ in
    /// the one decrypted fails 13.B.
    /// </summary>
    [Theory]
    [InlineData("contest-1")]
    [InlineData("contest-3")]
    public void Verification13_OnlyOneOfTwoContestsDecrypted_VerifiesAndCatchesAWrongValue(string contestId)
    {
        var (election, ballot, decrypted) = TwoOfThreeContests.Value;
        var partial = With(decrypted, contests: decrypted.Contests.Where(x => x.ContestId == contestId).ToList());

        election.Verify13(ballot, partial);

        var tampered = With(partial, c => With(c, choices: Replace(c.Choices, "choice-2", f => With(f, value: 1 - f.Value))));
        Assert.Equal("13.B", Assert.Throws<VerificationFailedException>(() => election.Verify13(ballot, tampered)).SubSection);
    }

    /// <summary>A decryption that releases contest data for a contest that carries none fails 13.structure.</summary>
    [Fact]
    public void Verification13_ContestDataReleasedForAContestWithout_Fails13Structure()
    {
        var (election, ballot, decrypted) = TwoOfThreeContests.Value;
        var extra = With(decrypted, c => c.ContestId == "contest-3" ? With(c, data: decrypted.Contests[0].ContestData) : c);

        var exception = Assert.Throws<VerificationFailedException>(() => election.Verify13(ballot, extra));

        Assert.Equal("13.structure", exception.SubSection);
        Assert.Contains("releases contest data, but the contest carries none", exception.Message);
    }

    // --- Verification 14 ----------------------------------------------------------------------

    public static TheoryData<string, string> Verification14Tampers() => new()
    {
        { "contest not on the ballot style", "14.A" },
        { "no contest", "14.B" },
        { "unknown option label", "14.C" },
        { "unknown supplemental field label", "14.C" },
        { "manifest option missing", "14.D" },
        { "declared supplemental field missing", "14.D" },
        { "option value 2 (R = 1)", "14.E" },
        { "option value -1", "14.E" },
        { "indicator value 2", "14.E" },
        { "write-in count above the write-in fields", "14.E" },
        { "undervote difference L + 1", "14.E" },
        { "two options selected (L = 1)", "14.F" },
        { "one option and one write-in (L = 1, Q13)", "14.F" },
        { "option listed twice", "14.structure" },
        { "contest listed twice", "14.structure" },
        { "decryption for another ballot", "14.structure" },
        { "no contest list", "14.structure" },
        { "null contest entry", "14.structure" },
        { "no option list", "14.structure" },
        { "no supplemental field list", "14.structure" },
        { "null option entry", "14.structure" },
        { "null supplemental field entry", "14.structure" },
    };

    private static DecryptedChallengedBallot Tamper14(DecryptedChallengedBallot d, string tamper)
    {
        var overvote = FieldId(SupplementalFieldKind.OvervoteIndicator);
        var writeIns = FieldId(SupplementalFieldKind.WriteInCount);
        return tamper switch
        {
            "contest not on the ballot style" => With(d, c => With(c, contestId: "contest-x")),
            "no contest" => With(d, contests: []),
            "unknown option label" => With(d, c => With(c, choices: [c.Choices[0], With(c.Choices[1], id: "choice-x")])),
            "unknown supplemental field label" => With(d, c => With(c, fields: Replace(c.SupplementalFields, overvote, f => With(f, id: "field-x")))),
            "manifest option missing" => With(d, c => With(c, choices: [c.Choices[0]])),
            "declared supplemental field missing" => With(d, c => With(c, fields: c.SupplementalFields.Where(f => f.Id != overvote).ToList())),
            "option value 2 (R = 1)" => With(d, c => With(c, choices: Replace(c.Choices, "choice-1", f => With(f, value: 2)))),
            "option value -1" => With(d, c => With(c, choices: Replace(c.Choices, "choice-2", f => With(f, value: -1)))),
            "indicator value 2" => With(d, c => With(c, fields: Replace(c.SupplementalFields, overvote, f => With(f, value: 2)))),
            "write-in count above the write-in fields" => With(d, c => With(c, fields: Replace(c.SupplementalFields, writeIns, f => With(f, value: 2)))),
            "two options selected (L = 1)" => With(d, c => With(c, choices: c.Choices.Select(f => With(f, value: 1)).ToList())),
            "one option and one write-in (L = 1, Q13)" => With(d, c => With(c, fields: Replace(c.SupplementalFields, writeIns, f => With(f, value: 1)))),
            "option listed twice" => With(d, c => With(c, choices: [.. c.Choices, c.Choices[0]])),
            "contest listed twice" => With(d, contests: [d.Contests[0], d.Contests[0]]),
            "decryption for another ballot" => With(d, ballotId: "ballot-2"),
            "undervote difference L + 1" => With(d, c => With(c, fields: Replace(c.SupplementalFields, FieldId(SupplementalFieldKind.UndervoteDifferenceCount), f => With(f, value: 2)))),
            "no contest list" => new DecryptedChallengedBallot { BallotId = d.BallotId, Contests = null! },
            "null contest entry" => With(d, contests: [null!]),
            "no option list" => With(d, c => new DecryptedChallengedContest { ContestId = c.ContestId, Choices = null!, SupplementalFields = c.SupplementalFields, ContestData = c.ContestData }),
            "no supplemental field list" => With(d, c => new DecryptedChallengedContest { ContestId = c.ContestId, Choices = c.Choices, SupplementalFields = null!, ContestData = c.ContestData }),
            "null option entry" => With(d, c => With(c, choices: [c.Choices[0], null!])),
            "null supplemental field entry" => With(d, c => With(c, fields: [.. c.SupplementalFields.Skip(1), null!])),
            _ => throw new ArgumentOutOfRangeException(nameof(tamper)),
        };
    }

    [Theory]
    [MemberData(nameof(Verification14Tampers))]
    public void Verification14_MalformedDecryption_FailsItsSubSection(string tamper, string subSection)
    {
        var election = Shared.Value;
        var (ballot, decrypted) = Opened.Value;

        // The honest decryption selects choice-1 (σ = 1, L = 1) and no write-in.
        Assert.Equal(1, decrypted.Contests[0].Choices.Single(x => x.Id == "choice-1").Value);
        election.Verify14(ballot, decrypted);

        var exception = Assert.Throws<VerificationFailedException>(() => election.Verify14(ballot, Tamper14(decrypted, tamper)));

        Assert.Equal(subSection, exception.SubSection);
    }

    /// <summary>
    /// A ballot naming a ballot style the manifest does not have fails 14.structure before any label
    /// check: Verification 14 does not run <see cref="BallotStructure"/>, so the lookup is its own.
    /// </summary>
    [Fact]
    public void Verification14_BallotStyleNotInTheManifest_Fails14Structure()
    {
        var election = Shared.Value;
        var (ballot, decrypted) = Opened.Value;

        var exception = Assert.Throws<VerificationFailedException>(() => election.Verify14(Copy(ballot, ballotStyleId: "style-x"), decrypted));

        Assert.Equal("14.structure", exception.SubSection);
        Assert.Contains("names ballot style style-x, which is not in the manifest", exception.Message);
    }

    /// <summary>
    /// 14.F sums the selections: the options and, by user decision Q13, the write-in count. The
    /// indicators and the undervote difference are not selections, so an undervote difference of
    /// L = 1 next to no selection at all does not exceed the limit.
    /// </summary>
    [Fact]
    public void Verification14_IndicatorsAndTheUndervoteDifference_AreNotSelections()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(choice1: 0, choice2: 0);
        var decrypted = new TallyAdmin().DecryptChallengedBallot(election.Guardians(0, 1), ballot, election.Record, election.NoCastBallots);
        var fields = decrypted.Contests[0].SupplementalFields;
        Assert.Equal(1, fields.Single(x => x.Id == FieldId(SupplementalFieldKind.UndervoteDifferenceCount)).Value);
        Assert.Equal(1, fields.Single(x => x.Id == FieldId(SupplementalFieldKind.UndervoteIndicator)).Value);
        Assert.Equal(1, fields.Single(x => x.Id == FieldId(SupplementalFieldKind.NullVoteIndicator)).Value);

        election.Verify13(ballot, decrypted);
        election.Verify14(ballot, decrypted);
    }
}
