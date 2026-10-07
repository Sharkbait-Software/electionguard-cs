using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ElectionGuard.Core.UnitTests.Tally;

/// <summary>
/// §3.6.6 verifiable decryption of contest data (G32) and Verification 12, on a real 2-of-3
/// guardian set: the minimal manifest with write-ins declares b_Λ = 2. The known-answer tests pin
/// the bytes; these pin the behavior, the refusals and the sub-sections.
/// </summary>
public class ContestDataDecryptionTests
{
    public ContestDataDecryptionTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private const string ContestId = "contest-1";
    private const string WriteIn = "Write-in: Ada Lovelace";

    private sealed class Election
    {
        public required ElectionFixtureBuilder.GuardianSetResult GuardianSet { get; init; }
        public required Manifest Manifest { get; init; }
        public required EncryptionRecord Record { get; init; }
        public required VotingDeviceInformationHash DeviceHash { get; init; }

        public EncryptedBallot Encrypt(string? text, string ballotId = "ballot-1") =>
            ElectionFixtureBuilder.CreateEncryptedBallot(Record, "device-1", DeviceHash,
                ElectionFixtureBuilder.CreateBallot(Manifest, ballotId, new Dictionary<string, int> { ["choice-1"] = 1 }, contestData: text));

        public List<TallyGuardian> Guardians(params int[] positions) =>
            positions.Select(i => new TallyGuardian(GuardianSet.Guardians[i].Index, GuardianSet.SecretShares[GuardianSet.Guardians[i].Index])).ToList();
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

    private static VerificationFailedException Verify12Fails(Election election, EncryptedBallot ballot, DecryptedContestData decrypted) =>
        Assert.Throws<VerificationFailedException>(() => new ContestDataDecryptionVerification().Verify(election.Record, ballot, decrypted));

    private static DecryptedContestData With(DecryptedContestData d, IntegerModP? beta = null, IntegerModQ? challenge = null, IntegerModQ? response = null, byte[]? data = null, int? contestIndex = null, string? ballotId = null, string? contestId = null) => new()
    {
        BallotId = ballotId ?? d.BallotId,
        ContestId = contestId ?? d.ContestId,
        ContestIndex = contestIndex ?? d.ContestIndex,
        Beta = beta ?? d.Beta,
        Challenge = challenge ?? d.Challenge,
        Response = response ?? d.Response,
        Data = data ?? d.Data,
    };

    [Theory]
    [InlineData(0, 1)]
    [InlineData(0, 2)]
    [InlineData(1, 2)]
    public void DecryptContestData_AnyQuorum_RecoversTheTextAndVerification12Accepts(int first, int second)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);

        var decrypted = new TallyAdmin().DecryptContestData(election.Guardians(first, second), ballot, ContestId, election.Record);

        Assert.Equal(WriteIn, decrypted.DecodeText());
        Assert.Equal(ContestDataEncoding.Encode(WriteIn, ElectionFixtureBuilder.DefaultContestDataBlocks), decrypted.Data);
        Assert.Equal(ballot.Id, decrypted.BallotId);
        Assert.Equal(1, decrypted.ContestIndex);
        new ContestDataDecryptionVerification().Verify(election.Record, ballot, decrypted);
    }

    /// <summary>
    /// A ballot with no text still carries the field (the design of S6: its presence never shows
    /// whether a write-in was entered), and it decrypts to the empty string.
    /// </summary>
    [Fact]
    public void DecryptContestData_BallotWithoutText_CarriesAFieldThatDecryptsToTheEmptyString()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(text: null);
        var withText = election.Encrypt(WriteIn, "ballot-2");

        Assert.Equal(withText.Contests[0].ContestData!.C1.Length, ballot.Contests[0].ContestData!.C1.Length);

        var decrypted = new TallyAdmin().DecryptContestData(election.Guardians(0, 1, 2), ballot, ContestId, election.Record);

        Assert.Equal(string.Empty, decrypted.DecodeText());
        Assert.All(decrypted.Data, b => Assert.Equal(0, b));
        new ContestDataDecryptionVerification().Verify(election.Record, ballot, decrypted);
    }

    /// <summary>
    /// A guardian consistent about a wrong m_i (it hashes the wrong value into d_i) passes the
    /// commitment check, but the combined proof fails, and Note 3.7's checks against the guardians'
    /// K-hat commitments name it.
    /// </summary>
    [Fact]
    public void CombineContestData_WrongPartialDecryption_NamesTheGuardian()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var guardians = election.Guardians(0, 2);
        guardians[1].PartialDecryptionTamperForTesting = (_, _, m) => m * new IntegerModP(EGParameters.G);

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().DecryptContestData(guardians, ballot, ContestId, election.Record));

        Assert.Equal(guardians[1].Index, exception.OffendingGuardian);
        Assert.Contains("Note 3.7", exception.Message);
    }

    /// <summary>
    /// A guardian that sends m_i = 0 is named by the administrator's own zero-share check, before
    /// any proof is combined. The C_0 membership check (RequireDecryptable) is what makes this
    /// attribution sound: an honest guardian's m_i = C_0^{ẑ_i} is never 0 for a C_0 in Z_p^r.
    /// Without the zero-share check, β = 0 would fall through to Note 3.7's attribution instead.
    /// </summary>
    [Fact]
    public void CombineContestData_ZeroPartialDecryption_NamesTheGuardian()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var guardians = election.Guardians(0, 2);
        guardians[1].PartialDecryptionTamperForTesting = (_, _, _) => new IntegerModP(0);

        var exception = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().DecryptContestData(guardians, ballot, ContestId, election.Record));

        Assert.Equal(guardians[1].Index, exception.OffendingGuardian);
        Assert.StartsWith("Contest data did not decrypt successfully", exception.Message, StringComparison.Ordinal);
        Assert.Contains("is 0", exception.Message);
        Assert.DoesNotContain("Note 3.7", exception.Message);
    }

    public static TheoryData<int, string> MisaddressedRounds() => new()
    {
        { 1, "ballot" }, { 2, "ballot" }, { 3, "ballot" },
        { 1, "contest" }, { 2, "contest" }, { 3, "contest" },
    };

    /// <summary>
    /// The administrator reads every round's messages through the statement, as the guardians do:
    /// a message addressed to another ballot or contest names its sender, whichever round it is in.
    /// </summary>
    [Theory]
    [MemberData(nameof(MisaddressedRounds))]
    public void CombineContestData_MessageForAnotherBallotOrContest_NamesTheSender(int round, string target)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.CommitContestData(ballot, ContestId, election.Record, participants)).ToList();
        var reveals = guardians.Select(x => x.RevealContestData(commitments)).ToList();
        var responses = guardians.Select(x => x.RespondContestData(reveals)).ToList();
        var admin = new TallyAdmin();

        // The messages are valid as sent.
        Assert.Equal(WriteIn, admin.CombineContestData(ballot, ContestId, election.Record, commitments, reveals, responses).DecodeText());

        var ballotId = target == "ballot" ? "ballot-2" : ballot.Id;
        var contestId = target == "contest" ? "contest-2" : ContestId;
        switch (round)
        {
            case 1:
                commitments[1] = new ContestDataPartialDecryption { GuardianIndex = commitments[1].GuardianIndex, BallotId = ballotId, ContestId = contestId, Mi = commitments[1].Mi, CommitmentHash = commitments[1].CommitmentHash };
                break;
            case 2:
                reveals[1] = new ContestDataCommitmentReveal { GuardianIndex = reveals[1].GuardianIndex, BallotId = ballotId, ContestId = contestId, CommitmentA = reveals[1].CommitmentA, CommitmentB = reveals[1].CommitmentB };
                break;
            default:
                responses[1] = new ContestDataDecryptionResponse { GuardianIndex = responses[1].GuardianIndex, BallotId = ballotId, ContestId = contestId, Response = responses[1].Response };
                break;
        }

        var exception = Assert.Throws<TallyDecryptionException>(() => admin.CombineContestData(ballot, ContestId, election.Record, commitments, reveals, responses));

        Assert.Equal(guardians[1].Index, exception.OffendingGuardian);
        Assert.Contains($"is for ballot {ballotId}, contest {contestId}", exception.Message);
    }

    /// <summary>
    /// The same wrong m_i published by a careless administrator: Verification 12 rejects it at 12.B
    /// (β is wrong, so b and the challenge are).
    /// </summary>
    [Fact]
    public void Verification12_WrongPartialDecryptionPublishedUnchecked_Fails12B()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var guardians = election.Guardians(0, 1);
        guardians[0].PartialDecryptionTamperForTesting = (_, _, m) => m * new IntegerModP(EGParameters.G);

        var decrypted = new TallyAdmin { VerifyBeforePublishing = false }.DecryptContestData(guardians, ballot, ContestId, election.Record);

        Assert.Equal("12.B", Verify12Fails(election, ballot, decrypted).SubSection);
    }

    public static TheoryData<string> Tamperings() => new() { "challenge", "response", "beta" };

    [Theory]
    [MemberData(nameof(Tamperings))]
    public void Verification12_TamperedProofOrBeta_Fails12B(string tampering)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var decrypted = new TallyAdmin().DecryptContestData(election.Guardians(0, 1), ballot, ContestId, election.Record);

        var tampered = tampering switch
        {
            "challenge" => With(decrypted, challenge: decrypted.Challenge + 1),
            "response" => With(decrypted, response: decrypted.Response + 1),
            "beta" => With(decrypted, beta: decrypted.Beta * new IntegerModP(EGParameters.G)),
            _ => throw new ArgumentOutOfRangeException(nameof(tampering)),
        };

        Assert.Equal("12.B", Verify12Fails(election, ballot, tampered).SubSection);
    }

    [Fact]
    public void Verification12_TamperedData_Fails12C()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var decrypted = new TallyAdmin().DecryptContestData(election.Guardians(1, 2), ballot, ContestId, election.Record);

        var data = (byte[])decrypted.Data.Clone();
        data[^1] ^= 0x01;

        Assert.Equal("12.C", Verify12Fails(election, ballot, With(decrypted, data: data)).SubSection);
        Assert.Equal("12.C", Verify12Fails(election, ballot, With(decrypted, data: data[..32])).SubSection);
    }

    /// <summary>
    /// D derived with the pre-S6 KDF, or with Verification 13.7's 0-based counter (user decision Q6:
    /// an erratum), is not what eq. (104) gives: 12.C rejects it. Each key is HMAC(h, b(i, 4) ‖
    /// "data_enc_keys" ‖ 0x00 ‖ "contest_data" ‖ b(ind_c, 4) ‖ b(L, 4)).
    /// </summary>
    [Theory]
    [InlineData("0-based counter")]
    [InlineData("per-block length field")]
    public void Verification12_DataFromAWrongKeyDerivation_Fails12C(string derivation)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var decrypted = new TallyAdmin().DecryptContestData(election.Guardians(0, 2), ballot, ContestId, election.Record);
        var data = ballot.Contests[0].ContestData!;
        int blocks = ElectionFixtureBuilder.DefaultContestDataBlocks;
        var h = ContestDataEncryption.SecretKey(ballot.SelectionEncryptionIdentifierHash, 1, data.C0, decrypted.Beta);

        var wrong = new byte[data.C1.Length];
        for (int block = 0; block < blocks; block++)
        {
            var (counter, bits) = derivation == "0-based counter" ? (block, blocks * 256) : (block * 32, block * 32 * 256);
            var message = new byte[38];
            BinaryPrimitives.WriteInt32BigEndian(message, counter);
            Encoding.UTF8.GetBytes("data_enc_keys").CopyTo(message, 4);
            Encoding.UTF8.GetBytes("contest_data").CopyTo(message, 18);
            BinaryPrimitives.WriteInt32BigEndian(message.AsSpan(30), 1);
            BinaryPrimitives.WriteInt32BigEndian(message.AsSpan(34), bits);
            var key = HMACSHA256.HashData(h, message);
            for (int b = 0; b < 32; b++)
            {
                wrong[block * 32 + b] = (byte)(data.C1[block * 32 + b] ^ key[b]);
            }
        }

        Assert.NotEqual(decrypted.Data, wrong);
        Assert.Equal("12.C", Verify12Fails(election, ballot, With(decrypted, data: wrong)).SubSection);
    }

    [Fact]
    public void Verification12_DecryptionOfAnotherBallotOrIndex_Fails12Structure()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var decrypted = new TallyAdmin().DecryptContestData(election.Guardians(0, 1), ballot, ContestId, election.Record);

        Assert.Equal("12.structure", Verify12Fails(election, ballot, With(decrypted, ballotId: "another-ballot")).SubSection);
        Assert.Equal("12.structure", Verify12Fails(election, ballot, With(decrypted, contestIndex: 2)).SubSection);

        // The same published values against another ballot's field: its C_0 and C_1 differ.
        var other = election.Encrypt(WriteIn, decrypted.BallotId);
        Assert.Equal("12.B", Verify12Fails(election, other, decrypted).SubSection);
    }

    /// <summary>
    /// §3.6.6 p.49-50: a guardian verifies the field's Schnorr proof C_2 (eq. 69) before computing
    /// m_i, and refuses otherwise. The proof covers C_1, so tampered data is refused too.
    /// </summary>
    [Theory]
    [InlineData("response")]
    [InlineData("C1")]
    [InlineData("C0")]
    public void CommitContestData_InvalidSchnorrProof_Refuses(string tampering)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var data = ballot.Contests[0].ContestData!;
        var c1 = (byte[])data.C1.Clone();
        c1[0] ^= 0x80;
        var tamperedData = new EncryptedContestData
        {
            C0 = tampering == "C0" ? data.C0 * new IntegerModP(EGParameters.G) : data.C0,
            C1 = tampering == "C1" ? c1 : data.C1,
            Challenge = data.Challenge,
            Response = tampering == "response" ? data.Response + 1 : data.Response,
        };
        var tampered = WithContestData(ballot, tamperedData);
        var guardian = election.Guardians(0)[0];

        var exception = Assert.Throws<TallyDecryptionException>(() =>
            guardian.CommitContestData(tampered, ContestId, election.Record, [new GuardianIndex(1), new GuardianIndex(2)]));

        Assert.Null(exception.OffendingGuardian);
        Assert.Contains("eq. 69", exception.Message);
    }

    /// <summary>
    /// A field whose C_0 is not in Z_p^r but whose eq. (69) proof is valid, which a device can forge
    /// (S6 review): C_0 = 0 with a = 0, and C_0 = p - g^ξ with an even challenge, so that
    /// C_0^c = g^{cξ} and v = u - c·ξ answers g^u.
    /// </summary>
    private static EncryptedContestData ForgedNonMemberField(EncryptedBallot ballot, string kind)
    {
        var data = ballot.Contests[0].ContestData!;
        var selectionHash = ballot.SelectionEncryptionIdentifierHash;
        if (kind == "zero")
        {
            // a = g^v·0^c = 0 for every v and every c != 0.
            IntegerModP zero = 0;
            return new EncryptedContestData
            {
                C0 = zero,
                C1 = data.C1,
                Challenge = ContestDataEncryption.ProofChallenge(selectionHash, 1, zero, zero, data.C1),
                Response = ElectionGuardRandom.GetIntegerModQ(),
            };
        }

        var xi = ElectionGuardRandom.GetIntegerModQ();
        var c0 = new IntegerModP(0) - MontgomeryModP.PowModP(EGParameters.G, xi);
        while (true)
        {
            var u = ElectionGuardRandom.GetIntegerModQ();
            var challenge = ContestDataEncryption.ProofChallenge(selectionHash, 1, MontgomeryModP.PowModP(EGParameters.G, u), c0, data.C1);
            if (challenge.ToBigInteger().IsEven)
            {
                return new EncryptedContestData { C0 = c0, C1 = data.C1, Challenge = challenge, Response = u - challenge * xi };
            }
        }
    }

    /// <summary>
    /// The eq. (69) proof alone accepts these fields; the guardian refuses them because C_0 is not in
    /// Z_p^r, before computing m_i = C_0^{ẑ_i} (which would be 0, so that an honest guardian is
    /// blamed, or would leak the parity of ẑ_i), and names no guardian: the ballot is at fault.
    /// </summary>
    [Theory]
    [InlineData("zero")]
    [InlineData("negated")]
    public void CommitContestData_C0NotInTheSubgroupWithAValidProof_RefusesNamingNoGuardian(string kind)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var forged = ForgedNonMemberField(ballot, kind);
        Assert.True(ContestDataEncryption.ProofHolds(ballot.SelectionEncryptionIdentifierHash, 1, forged));
        Assert.False(SubgroupMembership.IsMember(forged.C0));
        var guardian = election.Guardians(0)[0];

        var exception = Assert.Throws<TallyDecryptionException>(() =>
            guardian.CommitContestData(WithContestData(ballot, forged), ContestId, election.Record, [new GuardianIndex(1), new GuardianIndex(2)]));

        Assert.Null(exception.OffendingGuardian);
        Assert.Contains("Z_p^r", exception.Message);
    }

    /// <summary>
    /// The administrator makes the guardians' checks again before publishing: given valid messages
    /// for a good field, it refuses a ballot whose field fails eq. (69) or whose C_0 is not in Z_p^r,
    /// and names no guardian.
    /// </summary>
    [Theory]
    [InlineData("response", "eq. 69")]
    [InlineData("zero", "Z_p^r")]
    [InlineData("negated", "Z_p^r")]
    public void CombineContestData_FieldTheGuardiansWouldRefuse_RefusesNamingNoGuardian(string tampering, string expected)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.CommitContestData(ballot, ContestId, election.Record, participants)).ToList();
        var reveals = guardians.Select(x => x.RevealContestData(commitments)).ToList();
        var responses = guardians.Select(x => x.RespondContestData(reveals)).ToList();
        var admin = new TallyAdmin();

        // The messages are valid for the ballot as encrypted.
        Assert.Equal(WriteIn, admin.CombineContestData(ballot, ContestId, election.Record, commitments, reveals, responses).DecodeText());

        var data = ballot.Contests[0].ContestData!;
        var field = tampering == "response"
            ? new EncryptedContestData { C0 = data.C0, C1 = data.C1, Challenge = data.Challenge, Response = data.Response + 1 }
            : ForgedNonMemberField(ballot, tampering);

        var exception = Assert.Throws<TallyDecryptionException>(() =>
            admin.CombineContestData(WithContestData(ballot, field), ContestId, election.Record, commitments, reveals, responses));

        Assert.Null(exception.OffendingGuardian);
        Assert.Contains(expected, exception.Message);
        Assert.Contains("the administrator", exception.Message);
    }

    public static TheoryData<string> StructureFaults() => new() { "unknown contest", "no contest data", "C1 one block short", "H_I not H(H_E; 0x20, id_B)" };

    /// <summary>
    /// The 12.structure branches not covered above. The H_I check keeps every keyed hash of the
    /// decryption bound to H_E.
    /// </summary>
    [Theory]
    [MemberData(nameof(StructureFaults))]
    public void Verification12_StructureFault_Fails12Structure(string fault)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var decrypted = new TallyAdmin().DecryptContestData(election.Guardians(0, 1), ballot, ContestId, election.Record);

        var exception = fault switch
        {
            "unknown contest" => Verify12Fails(election, ballot, With(decrypted, contestId: "no-such-contest")),
            "no contest data" => Assert.Throws<VerificationFailedException>(() =>
                new ContestDataDecryptionVerification().Verify(RecordWithoutContestData(election.Record), ballot, decrypted)),
            "C1 one block short" => Verify12Fails(election, ShortField(ballot), decrypted),
            "H_I not H(H_E; 0x20, id_B)" => Verify12Fails(election, WithBallot(ballot, selectionHash: OtherSelectionHash()), decrypted),
            _ => throw new ArgumentOutOfRangeException(nameof(fault)),
        };

        Assert.Equal("12.structure", exception.SubSection);
    }

    /// <summary>The same faults on the guardian's side, before anything is computed.</summary>
    [Theory]
    [InlineData("unknown contest")]
    [InlineData("C1 one block short")]
    [InlineData("H_I not H(H_E; 0x20, id_B)")]
    public void CommitContestData_StructureFault_Throws(string fault)
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var guardian = election.Guardians(0)[0];
        GuardianIndex[] participants = [new GuardianIndex(1), new GuardianIndex(2)];

        var (target, contestId) = fault switch
        {
            "unknown contest" => (ballot, "no-such-contest"),
            "C1 one block short" => (ShortField(ballot), ContestId),
            "H_I not H(H_E; 0x20, id_B)" => (WithBallot(ballot, selectionHash: OtherSelectionHash()), ContestId),
            _ => throw new ArgumentOutOfRangeException(nameof(fault)),
        };

        Assert.Throws<ArgumentException>(() => guardian.CommitContestData(target, contestId, election.Record, participants));
    }

    private static EncryptedBallot ShortField(EncryptedBallot ballot)
    {
        var data = ballot.Contests[0].ContestData!;
        return WithContestData(ballot, new EncryptedContestData
        {
            C0 = data.C0,
            C1 = data.C1[..^ContestDataEncryption.BlockBytes],
            Challenge = data.Challenge,
            Response = data.Response,
        });
    }

    private static SelectionEncryptionIdentifierHash OtherSelectionHash() =>
        new(Enumerable.Range(0, 32).Select(i => (byte)(0xA0 + i)).ToArray());

    /// <summary>The election's record with a manifest whose contest declares b_Λ = 0.</summary>
    private static EncryptionRecord RecordWithoutContestData(EncryptionRecord record) => new()
    {
        CryptographicParameters = record.CryptographicParameters,
        GuardianParameters = record.GuardianParameters,
        ParameterBaseHash = record.ParameterBaseHash,
        ManifestFile = record.ManifestFile,
        ElectionBaseHash = record.ElectionBaseHash,
        Guardians = record.Guardians,
        ElectionPublicKeys = record.ElectionPublicKeys,
        ExtendedBaseHash = record.ExtendedBaseHash,
        Manifest = record.Manifest with { Contests = record.Manifest.Contests.Select(c => c with { ContestDataBlocks = 0 }).ToList() },
    };

    [Fact]
    public void CommitContestData_ContestWithoutContestData_Throws()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        Assert.Equal(0, manifest.Contests[0].ContestDataBlocks);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var ballot = ElectionFixtureBuilder.CreateEncryptedBallot(record.EncryptionRecord, "device-1",
            new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1"), ElectionFixtureBuilder.CreateBallot(manifest));
        Assert.Null(ballot.Contests[0].ContestData);

        var guardian = new TallyGuardian(guardianSet.Guardians[0].Index, guardianSet.SecretShares[guardianSet.Guardians[0].Index]);

        Assert.Throws<ArgumentException>(() => guardian.CommitContestData(ballot, ContestId, record.EncryptionRecord, [new GuardianIndex(1), new GuardianIndex(2)]));
    }

    /// <summary>A guardian that reveals (a_j, b_j) other than what its d_j committed to is named (eq. 99).</summary>
    [Fact]
    public void RespondContestData_RevealNotMatchingTheCommitment_NamesTheGuardian()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.CommitContestData(ballot, ContestId, election.Record, participants)).ToList();
        var reveals = guardians.Select(x => x.RevealContestData(commitments)).ToList();
        reveals[1] = new ContestDataCommitmentReveal
        {
            GuardianIndex = reveals[1].GuardianIndex,
            BallotId = reveals[1].BallotId,
            ContestId = reveals[1].ContestId,
            CommitmentA = reveals[1].CommitmentA * new IntegerModP(EGParameters.G),
            CommitmentB = reveals[1].CommitmentB,
        };

        var exception = Assert.Throws<TallyDecryptionException>(() => guardians[0].RespondContestData(reveals));

        Assert.Equal(guardians[1].Index, exception.OffendingGuardian);
        Assert.Contains("eq. 99", exception.Message);
    }

    [Fact]
    public void RevealContestData_MessageForAnotherBallot_NamesTheSender()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var other = election.Encrypt(WriteIn, "ballot-2");
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = new List<ContestDataPartialDecryption>
        {
            guardians[0].CommitContestData(ballot, ContestId, election.Record, participants),
            guardians[1].CommitContestData(other, ContestId, election.Record, participants),
        };

        var exception = Assert.Throws<TallyDecryptionException>(() => guardians[0].RevealContestData(commitments));

        Assert.Equal(guardians[1].Index, exception.OffendingGuardian);
    }

    /// <summary>
    /// One session at a time, of one kind: a tally decryption in progress cannot be continued with
    /// contest data messages, nor the other way round, and a new commit discards the old session.
    /// </summary>
    [Fact]
    public void Sessions_OfTheOtherKind_AreRefused()
    {
        var election = Shared.Value;
        var ballot = election.Encrypt(WriteIn);
        var tally = ElectionFixtureBuilder.CreateEncryptedTally(election.Manifest, [ballot]);
        var guardians = election.Guardians(0, 1);
        var participants = guardians.Select(x => x.Index).ToList();

        var tallyCommitments = guardians.Select(x => x.Commit(tally, election.Record, participants)).ToList();
        Assert.Throws<InvalidOperationException>(() => guardians[0].RevealContestData([]));

        var contestCommitments = guardians.Select(x => x.CommitContestData(ballot, ContestId, election.Record, participants)).ToList();
        Assert.Throws<InvalidOperationException>(() => guardians[0].Reveal(tallyCommitments));

        var reveals = guardians.Select(x => x.RevealContestData(contestCommitments)).ToList();
        Assert.Throws<InvalidOperationException>(() => guardians[0].Respond([]));
        guardians[0].RespondContestData(reveals);

        // Respond ends the session: u_i is never used twice.
        Assert.Throws<InvalidOperationException>(() => guardians[0].RespondContestData(reveals));
    }

    private static EncryptedBallot WithContestData(EncryptedBallot ballot, EncryptedContestData data) => WithBallot(ballot, data);

    private static EncryptedBallot WithBallot(EncryptedBallot ballot, EncryptedContestData? data = null, SelectionEncryptionIdentifierHash? selectionHash = null) => new()
    {
        Id = ballot.Id,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = selectionHash ?? ballot.SelectionEncryptionIdentifierHash,
        BallotStyleId = ballot.BallotStyleId,
        Contests = ballot.Contests.Select(c => c with { ContestData = data ?? c.ContestData }).ToList(),
        ConfirmationCode = ballot.ConfirmationCode,
        Weight = ballot.Weight,
        Status = ballot.Status,
        DeviceId = ballot.DeviceId,
    };
}
