using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Tally;
using System.Numerics;
using System.Text.Json;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.Kat;

/// <summary>
/// The contest data families (§3.3.10 eqs. 64-69, §3.4.1 eq. 70 with contest data, §3.6.6 eqs.
/// 96-106 and Verification 12), each through the library's own API: the shared derivations of
/// <see cref="ContestDataEncryption"/>, the encryptor, and the three-round decryption protocol.
/// </summary>
public partial class KnownAnswerTests
{
    /// <summary>The main-chain election's ballot data encryption key, K-hat = g^7.</summary>
    private static IntegerModP MainChainBallotDataKey => IntegerModP.PowModP(EGParameters.G, new BigInteger(7));

    private static BallotNonce MainChainBallotNonce => new(Hex(Root.GetProperty("main_chain"), "xi_B_hex"));

    private static SelectionEncryptionIdentifierHash ContestDataSelectionHash(JsonElement vector)
    {
        var hash = SelectionEncryptionIdentifierHashFor(Inputs(vector).GetProperty("H_I_hex").GetString()!);
        Assert.Equal(vector.GetProperty("b0_hex").GetString(), ToHex(hash));
        return hash;
    }

    private static EncryptedContestData ContestData(JsonElement element, string c0 = "C0_hex", string c1 = "C1_hex", string c2 = "C2_hex")
    {
        var proof = Hex(element, c2);
        Assert.Equal(64, proof.Length);
        return new EncryptedContestData
        {
            C0 = P(element, c0),
            C1 = Hex(element, c1),
            Challenge = new IntegerModQ(proof[..32]),
            Response = new IntegerModQ(proof[32..]),
        };
    }

    [Theory]
    [MemberData(nameof(VectorNames), "contest_data_nonce")]
    public void ContestDataNonce_Eq64(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var xi = ContestDataEncryption.Nonce(ContestDataSelectionHash(vector), Int(inputs, "ind_c"), new BallotNonce(Hex(inputs, "xi_B_hex")));

        AssertExpected(vector, xi);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "contest_data_secret_key")]
    public void ContestDataSecretKey_Eq65(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = ContestDataSelectionHash(vector);
        int contestIndex = Int(inputs, "ind_c");

        // ξ (eq. 64), α = g^ξ and β = K-hat^ξ, through the library.
        var xi = ContestDataEncryption.Nonce(selectionHash, contestIndex, MainChainBallotNonce);
        Assert.Equal(inputs.GetProperty("xi_hex").GetString(), ToHex(xi));
        var alpha = MontgomeryModP.PowModP(EGParameters.G, xi);
        var beta = MontgomeryModP.PowModP(MainChainBallotDataKey, xi);
        Assert.Equal(inputs.GetProperty("alpha_hex").GetString(), ToHex(alpha));
        Assert.Equal(inputs.GetProperty("beta_hex").GetString(), ToHex(beta));

        AssertExpected(vector, ContestDataEncryption.SecretKey(selectionHash, contestIndex, alpha, beta));
    }

    /// <summary>
    /// Eq. (66): k_i with the block counter i from 1 (user decision Q6) and the constant length field
    /// b(b_Λ·256, 4). The oracle expands the same h with b_Λ = 1 and b_Λ = 3, so a library that let
    /// the length field vary per block, or counted from 0, fails here.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "contest_data_kdf_key")]
    public void ContestDataKdfKey_Eq66(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        Assert.Equal(38, vector.GetProperty("b1_len").GetInt32());
        Span<byte> key = stackalloc byte[ContestDataEncryption.BlockBytes];
        ContestDataEncryption.BlockKey(Hex(inputs, "h_hex"), Int(inputs, "ind_c"), Int(inputs, "b_Lambda"), Int(inputs, "i"), key);

        AssertExpected(vector, key.ToArray());
    }

    /// <summary>
    /// Eqs. (64)-(69) end to end through the encryption the ballot encryptor uses, given the oracle's
    /// proof nonce u: C_0, C_1 and C_2 = (c, v) must be the oracle's. D is the Q7 string helper's
    /// encoding, which must also be the oracle's D. The proof must then verify as a guardian checks
    /// it (§3.6.6), and C_1 must decrypt to D under β = K-hat^ξ.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "contest_data_encryption_challenge")]
    public void ContestDataEncryption_Eq64To69(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = ContestDataSelectionHash(vector);
        int contestIndex = Int(inputs, "ind_c");
        int blocks = Int(inputs, "b_Lambda");

        var data = ContestDataEncoding.Encode(inputs.GetProperty("contest_data_string").GetString()!, blocks);
        Assert.Equal(inputs.GetProperty("D_hex").GetString(), ToHex(data));
        Assert.Equal(inputs.GetProperty("contest_data_string").GetString(), ContestDataEncoding.Decode(data));

        var encrypted = ContestDataEncryption.Encrypt(data, contestIndex, blocks, selectionHash, MainChainBallotNonce, MainChainBallotDataKey, Q(inputs, "u_hex"));

        var expected = ContestData(vector.GetProperty("ciphertext"));
        Assert.Equal(ToHex(expected.C0), ToHex(encrypted.C0));
        Assert.Equal(ToHex(expected.C1), ToHex(encrypted.C1));
        Assert.Equal(ToHex(expected.Challenge), ToHex(encrypted.Challenge));
        Assert.Equal(ToHex(expected.Response), ToHex(encrypted.Response));
        AssertExpected(vector, encrypted.Challenge);
        Assert.Equal(blocks * ContestDataEncryption.BlockBytes, encrypted.C1.Length);

        // The eq. (69) challenge from the vector's own a.
        AssertExpected(vector, ContestDataEncryption.ProofChallenge(selectionHash, contestIndex, P(inputs, "a_hex"), encrypted.C0, encrypted.C1));
        Assert.True(ContestDataEncryption.ProofHolds(selectionHash, contestIndex, encrypted));

        // Each k_i of the vector, and C_1 back to D under β (eqs. 104-106).
        var secretKey = Hex(inputs, "h_hex");
        var keys = inputs.GetProperty("k_hex").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Equal(blocks, keys.Count);
        var key = new byte[ContestDataEncryption.BlockBytes];
        for (int i = 1; i <= blocks; i++)
        {
            ContestDataEncryption.BlockKey(secretKey, contestIndex, blocks, i, key);
            Assert.Equal(keys[i - 1], ToHex(key));
        }

        Assert.Equal(ToHex(data), ToHex(ContestDataEncryption.Decrypt(selectionHash, contestIndex, blocks, encrypted, P(inputs, "beta_hex"))));
    }

    /// <summary>The Q7 helper refuses, rather than truncates, a string one UTF-8 byte too long.</summary>
    [Fact]
    public void ContestDataEncoding_RejectsTheOraclesTooLongStrings()
    {
        var rejections = Root.GetProperty("contest_data").GetProperty("string_helper_rejections").EnumerateArray().ToList();
        Assert.NotEmpty(rejections);
        foreach (var rejection in rejections)
        {
            int blocks = Int(rejection, "b_Lambda");
            Assert.Equal(Int(rejection, "capacity_utf8_bytes"), ContestDataEncoding.Capacity(blocks));
            Assert.Equal(Int(rejection, "utf8_len"), System.Text.Encoding.UTF8.GetByteCount(rejection.GetProperty("string").GetString()!));
            Assert.Throws<ArgumentException>(() => ContestDataEncoding.Encode(rejection.GetProperty("string").GetString()!, blocks));
        }
    }

    [Theory]
    [MemberData(nameof(VectorNames), "contest_hash_with_contest_data")]
    public void ContestHashWithContestData_Eq70(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = ContestDataSelectionHash(vector);
        var ciphertexts = inputs.GetProperty("ciphertexts").EnumerateArray()
            .Select((x, i) => new EncryptedSelection
            {
                ChoiceId = $"option-{i + 1}",
                Alpha = P(x, "alpha_hex"),
                Beta = P(x, "beta_hex"),
                Proofs = [],
            })
            .ToList();
        var contestData = ContestData(inputs);
        Assert.Equal(Int(inputs, "b_Lambda") * ContestDataEncryption.BlockBytes, contestData.C1.Length);

        var contestHash = new ContestHash(selectionHash, Int(inputs, "l"), ciphertexts, contestData);

        AssertExpected(vector, contestHash);
    }

    /// <summary>
    /// The oracle's main-chain ballot with contest data on three contests, encrypted by the library:
    /// contest 1 (two options voted (1, 0), b_Λ = 1, empty field), contest 2 (three options voted
    /// (0, 0, 1), b_Λ = 1, "Write-in: Ada Lovelace") and contest 3 (one option voted 1, b_Λ = 3,
    /// non-ASCII), with the oracle's proof nonces. Every contest hash must be the
    /// contest_hash_with_contest_data vector, and the confirmation code the confirmation_code vector
    /// over them; Verification 8 must accept the ballot.
    /// </summary>
    [Fact]
    public void Encryption_WithContestData_ReproducesTheContestHashAndConfirmationCodeVectors()
    {
        var chain = Root.GetProperty("main_chain");
        var g = EGParameters.G;
        var parameterBaseHash = new ParameterBaseHash(new CryptographicParameters(), new GuardianParameters(Int(chain, "n"), Int(chain, "k")));
        var manifestFile = new ManifestFile { Bytes = Hex(chain, "manifest_hex") };
        var electionBaseHash = new ElectionBaseHash(parameterBaseHash, manifestFile);
        var keys = new ElectionPublicKeys([IntegerModP.PowModP(g, new BigInteger(5))], [MainChainBallotDataKey]);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, keys);

        var encryptionVectors = AllVectors.Where(x => x.GetProperty("family").GetString() == "contest_data_encryption_challenge")
            .ToDictionary(x => Int(Inputs(x), "ind_c"));
        var hashVectors = AllVectors.Where(x => x.GetProperty("family").GetString() == "contest_hash_with_contest_data")
            .OrderBy(x => Int(Inputs(x), "l"))
            .ToList();
        Assert.Equal([1, 2, 3], hashVectors.Select(x => Int(Inputs(x), "l")));

        int[][] votes = [[1, 0], [0, 0, 1], [1]];
        var contests = hashVectors.Select(x =>
        {
            int index = Int(Inputs(x), "l");
            return new Contest
            {
                Id = $"contest-{index}",
                Name = $"Contest {index}",
                Index = index,
                SelectionLimit = 1,
                OptionSelectionLimit = 1,
                Choices = Enumerable.Range(1, votes[index - 1].Length).Select(j => new Choice { Id = $"option-{index}-{j}", Name = $"Option {j}", Index = j }).ToList(),
                ContestDataBlocks = Int(Inputs(x), "b_Lambda"),
            };
        }).ToList();
        var manifest = new Manifest
        {
            ElectionId = "kat",
            Contests = contests,
            BallotStyles = [new BallotStyle { Id = "style", Name = "Style", ContestIds = contests.Select(x => x.Id).ToList() }],
            ChainingMode = ChainingMode.None,
        };
        var record = new EncryptionRecord
        {
            CryptographicParameters = new CryptographicParameters(),
            GuardianParameters = new GuardianParameters(Int(chain, "n"), Int(chain, "k")),
            ParameterBaseHash = parameterBaseHash,
            ManifestFile = manifestFile,
            ElectionBaseHash = electionBaseHash,
            Guardians = [],
            ElectionPublicKeys = keys,
            ExtendedBaseHash = extendedBaseHash,
            Manifest = manifest,
        };

        var ballot = new Core.BallotEncryption.Ballot
        {
            Id = "kat-ballot",
            BallotStyleId = "style",
            Contests = contests.Select((contest, c) =>
            {
                var text = Inputs(encryptionVectors[contest.Index]).GetProperty("contest_data_string").GetString()!;
                return new BallotContest
                {
                    Id = contest.Id,
                    Choices = contest.Choices.Select((choice, j) => new BallotChoice { Id = choice.Id, SelectionValue = votes[c][j] }).ToList(),
                    // Contest 1's field is empty: left null, the encryptor encrypts 32 zero bytes,
                    // which is the empty string's encoding.
                    ContestData = text.Length == 0 ? null : ContestDataEncoding.Encode(text, contest.ContestDataBlocks),
                };
            }).ToList(),
        };
        var device = chain.GetProperty("S_device").GetString()!;
        var deviceHash = new VotingDeviceInformationHash(extendedBaseHash, device);
        var encryptor = new BallotEncryptor(record, device, deviceHash)
        {
            ContestDataProofNonceForTesting = contestIndex => Q(Inputs(encryptionVectors[contestIndex]), "u_hex"),
        };
        var encrypted = encryptor.Encrypt(ballot, previousConfirmationCode: null, new SelectionEncryptionIdentifier(Hex(chain, "id_B_hex")), MainChainBallotNonce);

        for (int c = 0; c < hashVectors.Count; c++)
        {
            Assert.Equal(hashVectors[c].GetProperty("expected_hex").GetString(), ToHex(encrypted.Contests[c].ContestHash));
            var expectedData = ContestData(Inputs(hashVectors[c]));
            Assert.Equal(ToHex(expectedData.C1), ToHex(encrypted.Contests[c].ContestData!.C1));
        }

        var confirmationCode = AllVectors.Single(x =>
            x.GetProperty("family").GetString() == "confirmation_code"
            && Inputs(x).GetProperty("contest_hashes_hex").EnumerateArray().Select(h => h.GetString())
                .SequenceEqual(hashVectors.Select(v => v.GetProperty("expected_hex").GetString())));
        AssertExpected(confirmationCode, encrypted.ConfirmationCode);

        new ElectionGuard.Core.Verify.Ballot.ConfirmationCodeVerification().Verify(encrypted, deviceHash, record, null);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "contest_data_decryption_commitment_hash")]
    public void ContestDataDecryptionCommitmentHash_Eq99(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = ContestDataSelectionHash(vector);
        var data = ContestData(inputs);
        Assert.Equal(Int(inputs, "b_Lambda") * ContestDataEncryption.BlockBytes, data.C1.Length);

        // The commitment pair and the partial decryption, through the library's exponentiation.
        var u = Q(inputs, "u_i_hex");
        var commitmentA = MontgomeryModP.PowModP(EGParameters.G, u);
        var commitmentB = MontgomeryModP.PowModP(data.C0, u);
        var partialDecryption = MontgomeryModP.PowModP(data.C0, Q(inputs, "z_hat_i_hex"));
        Assert.Equal(inputs.GetProperty("a_i_hex").GetString(), ToHex(commitmentA));
        Assert.Equal(inputs.GetProperty("b_i_hex").GetString(), ToHex(commitmentB));
        Assert.Equal(inputs.GetProperty("m_i_hex").GetString(), ToHex(partialDecryption));

        var participants = Participants(inputs);
        byte[] Hash(IReadOnlyCollection<GuardianIndex> u) => ContestDataDecryptionHashes.CommitmentHash(
            selectionHash, Int(inputs, "ind_c"), new GuardianIndex(Int(inputs, "i")), data, commitmentA, commitmentB, partialDecryption, u);

        AssertExpected(vector, Hash(participants));

        // U in ascending order whatever order it is given in (user decision Q10).
        AssertExpected(vector, Hash(Enumerable.Reverse(participants).ToList()));
    }

    /// <summary>
    /// The whole §3.6.6 protocol, end to end, against the oracle's complete proof: the guardians of
    /// U hold the oracle's ẑ_i (from the n = 3, k = 2 guardian_record_hash K-hat polynomials) and are
    /// handed its u_i, the ballot carries the oracle's (C_0, C_1, C_2), and every value along the way
    /// (m_i, a_i, b_i, d_i, w_i, v_i, β, c, v, h, D) must match. Verification 12 must then accept
    /// the result.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "contest_data_decryption_challenge")]
    public void ContestDataDecryptionProof_Eq96To106_AndVerification12(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var proof = inputs.GetProperty("proof");
        var decryption = inputs.GetProperty("decryption");
        var selectionHash = ContestDataSelectionHash(vector);
        int contestIndex = Int(inputs, "ind_c");
        int blocks = Int(inputs, "b_Lambda");
        var contestData = ContestData(inputs);
        var (record, ballot, contestId) = ContestDataBallot(contestIndex, blocks, contestData);
        Assert.Equal(ToHex(selectionHash), ToHex(ballot.SelectionEncryptionIdentifierHash));

        var guardianVectors = proof.GetProperty("guardians").EnumerateArray().ToList();
        var guardians = guardianVectors.Select(x =>
        {
            var guardian = new TallyGuardian(new GuardianIndex(Int(x, "i")), new GuardianSecretShares
            {
                VoteEncryptionKeyShare = 0,
                OtherBallotDataEncryptionKeyShare = Q(x, "z_hat_i_hex"),
            });
            var u = Q(x, "u_i_hex");
            guardian.NonceSourceForTesting = (c, o) => c == contestIndex && o == 0 ? u : throw new InvalidOperationException("Only the contest data nonce is drawn.");
            return guardian;
        }).ToList();
        var participants = Participants(proof);
        Assert.Equal(participants, guardians.Select(x => x.Index).ToList());

        var commitments = guardians.Select(x => x.CommitContestData(ballot, contestId, record, participants)).ToList();
        var reveals = guardians.Select(x => x.RevealContestData(commitments)).ToList();
        var responses = guardians.Select(x => x.RespondContestData(reveals)).ToList();

        for (int j = 0; j < guardians.Count; j++)
        {
            var expected = guardianVectors[j];
            Assert.Equal(expected.GetProperty("w_i_hex").GetString(), ToHex(TallyDecryptionHashes.LagrangeCoefficient(guardians[j].Index, participants)));
            Assert.Equal(expected.GetProperty("m_i_hex").GetString(), ToHex(commitments[j].Mi));
            Assert.Equal(expected.GetProperty("d_i_hex").GetString(), ToHex(commitments[j].CommitmentHash));
            Assert.Equal(expected.GetProperty("a_i_hex").GetString(), ToHex(reveals[j].CommitmentA));
            Assert.Equal(expected.GetProperty("b_i_hex").GetString(), ToHex(reveals[j].CommitmentB));
            Assert.Equal(expected.GetProperty("v_i_hex").GetString(), ToHex(responses[j].Response));
        }

        var decrypted = new TallyAdmin().CombineContestData(ballot, contestId, record, commitments, reveals, responses);

        AssertExpected(vector, decrypted.Challenge);
        Assert.Equal(proof.GetProperty("c_hex").GetString(), ToHex(decrypted.Challenge));
        Assert.Equal(proof.GetProperty("v_hex").GetString(), ToHex(decrypted.Response));
        Assert.Equal(inputs.GetProperty("beta_hex").GetString(), ToHex(decrypted.Beta));
        Assert.Equal(contestIndex, decrypted.ContestIndex);
        Assert.Equal(decryption.GetProperty("D_hex").GetString(), ToHex(decrypted.Data));
        Assert.Equal(decryption.GetProperty("contest_data_string").GetString(), decrypted.DecodeText());

        // (12.3): h over C_0 and β is the oracle's h, which is also the encryption side's eq. (65) h.
        Assert.Equal(decryption.GetProperty("h_hex").GetString(), ToHex(ContestDataEncryption.SecretKey(selectionHash, contestIndex, contestData.C0, decrypted.Beta)));

        // The eq. (101) challenge from the vector's own a, b and β.
        AssertExpected(vector, ContestDataDecryptionHashes.Challenge(selectionHash, contestIndex, contestData, P(inputs, "a_hex"), P(inputs, "b_hex"), P(inputs, "beta_hex")));

        new ContestDataDecryptionVerification().Verify(record, ballot, decrypted);
    }

    /// <summary>
    /// The main-chain election (K = g^5, K-hat = g^7, H_E rebuilt through the constructors) with a
    /// manifest of <paramref name="contestIndex"/> one-option contests, the last declaring
    /// <paramref name="blocks"/> blocks of contest data, and the main-chain ballot (its id_B, so its
    /// H_I) voting in that contest alone and carrying <paramref name="contestData"/>. Only the index,
    /// b_Λ, H_I and the field enter the decryption; the selection's ciphertext is a placeholder.
    /// </summary>
    private static (EncryptionRecord Record, EncryptedBallot Ballot, string ContestId) ContestDataBallot(int contestIndex, int blocks, EncryptedContestData contestData)
    {
        var chain = Root.GetProperty("main_chain");
        var g = EGParameters.G;
        var keys = new ElectionPublicKeys([IntegerModP.PowModP(g, new BigInteger(5))], [MainChainBallotDataKey]);
        var parameterBaseHash = new ParameterBaseHash(new CryptographicParameters(), new GuardianParameters(3, 2));
        var manifestFile = new ManifestFile { Bytes = Hex(chain, "manifest_hex") };
        var electionBaseHash = new ElectionBaseHash(parameterBaseHash, manifestFile);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, keys);
        Assert.Equal(chain.GetProperty("H_E_hex").GetString(), ToHex(extendedBaseHash));

        string contestId = $"contest-{contestIndex}";
        var manifest = new Manifest
        {
            ElectionId = "kat",
            Contests = Enumerable.Range(1, contestIndex).Select(c => new Contest
            {
                Id = $"contest-{c}",
                Name = $"Contest {c}",
                SelectionLimit = 1,
                OptionSelectionLimit = 1,
                Index = c,
                Choices = [new Choice { Id = $"contest-{c}-option-1", Name = "Option 1", Index = 1 }],
                ContestDataBlocks = c == contestIndex ? blocks : 0,
            }).ToList(),
            BallotStyles = [new BallotStyle { Id = "style", Name = "Style", ContestIds = [contestId] }],
        };
        var record = new EncryptionRecord
        {
            CryptographicParameters = new CryptographicParameters(),
            GuardianParameters = new GuardianParameters(3, 2),
            ParameterBaseHash = parameterBaseHash,
            ManifestFile = manifestFile,
            ElectionBaseHash = electionBaseHash,
            Guardians = [],
            ElectionPublicKeys = keys,
            ExtendedBaseHash = extendedBaseHash,
            Manifest = manifest,
        };

        var identifier = new SelectionEncryptionIdentifier(Hex(chain, "id_B_hex"));
        var ballot = new EncryptedBallot
        {
            Id = "kat-ballot",
            SelectionEncryptionIdentifier = identifier,
            SelectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(extendedBaseHash, identifier),
            BallotStyleId = "style",
            DeviceId = "kat-device",
            Weight = 1,
            ConfirmationCode = new ConfirmationCode(new byte[32]),
            EncryptedBallotNonce = ElectionFixtureBuilder.PlaceholderBallotNonce,
            Contests =
            [
                new EncryptedContest
                {
                    Id = contestId,
                    Choices = [new EncryptedSelection { ChoiceId = $"{contestId}-option-1", Alpha = 1, Beta = 1, Proofs = [] }],
                    SupplementalFields = [],
                    Proofs = [],
                    ContestData = contestData,
                    ContestHash = new ContestHash(new byte[32]),
                },
            ],
        };

        return (record, ballot, contestId);
    }
}
