using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;
using System.Numerics;
using System.Text.Json;

namespace ElectionGuard.Core.UnitTests.Kat;

/// <summary>
/// The ballot nonce families (§3.3.4 eqs. 34-38) and the challenged ballot families (§3.6.7
/// eqs. 107-111, Verification 13), each through the library's own API: the shared derivations of
/// <see cref="BallotNonceEncryption"/>, the encryptor, the guardians' partial decryption, the
/// administrator's opening of a challenged ballot, and Verifications 13 and 14. The spec defines no
/// proof of correct decryption for the ballot nonce, so the oracle has none and neither has the
/// library.
/// </summary>
public partial class KnownAnswerTests
{
    /// <summary>
    /// The library's H_I for <paramref name="hex"/>: H(H_E; 0x20, id_B) under the main-chain H_E, for
    /// the id_B of the main-chain ballot, the sparse ballot or one of the ballot nonce vectors.
    /// </summary>
    private static SelectionEncryptionIdentifierHash ChallengedSelectionHash(string hex)
    {
        var chain = Root.GetProperty("main_chain");
        var extendedBaseHash = ExtendedBaseHashFor(chain.GetProperty("H_E_hex").GetString()!);
        var identifiers = new List<string>
        {
            chain.GetProperty("id_B_hex").GetString()!,
            Root.GetProperty("challenged_ballots").GetProperty("sparse_ballot").GetProperty("id_B_hex").GetString()!,
        };
        identifiers.AddRange(AllVectors
            .Where(x => x.GetProperty("family").GetString()!.StartsWith("ballot_nonce_", StringComparison.Ordinal))
            .Select(x => Inputs(x))
            .Where(x => x.TryGetProperty("id_B_hex", out _))
            .Select(x => x.GetProperty("id_B_hex").GetString()!));

        foreach (var identifier in identifiers.Distinct())
        {
            var hash = new SelectionEncryptionIdentifierHash(extendedBaseHash, new SelectionEncryptionIdentifier(Convert.FromHexString(identifier)));
            if (ToHex(hash) == hex)
            {
                return hash;
            }
        }

        throw new Xunit.Sdk.XunitException($"No id_B of the challenged ballot vectors gives the library an H_I of {hex}.");
    }

    private static SelectionEncryptionIdentifierHash ChallengedSelectionHash(JsonElement vector)
    {
        var hash = ChallengedSelectionHash(Inputs(vector).GetProperty("H_I_hex").GetString()!);
        Assert.Equal(vector.GetProperty("b0_hex").GetString(), ToHex(hash));
        return hash;
    }

    private static EncryptedBallotNonce BallotNonceCiphertext(JsonElement element, string c0, string c1, string challenge, string response) => new()
    {
        C0 = P(element, c0),
        C1 = Hex(element, c1),
        Challenge = Q(element, challenge),
        Response = Q(element, response),
    };

    private static EncryptedBallotNonce BallotNonceCiphertext(JsonElement element)
    {
        var proof = Hex(element, "C2_hex");
        Assert.Equal(64, proof.Length);
        return new EncryptedBallotNonce
        {
            C0 = P(element, "C0_hex"),
            C1 = Hex(element, "C1_hex"),
            Challenge = new IntegerModQ(proof[..32]),
            Response = new IntegerModQ(proof[32..]),
        };
    }

    [Theory]
    [MemberData(nameof(VectorNames), "ballot_nonce_secret_key")]
    public void BallotNonceSecretKey_Eq35(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = ChallengedSelectionHash(vector);
        Assert.Equal(inputs.GetProperty("K_hat_hex").GetString(), ToHex(MainChainBallotDataKey));
        Assert.Equal(1025, vector.GetProperty("b1_len").GetInt32());

        // Eq. (34) through the library's exponentiation.
        var xiHat = Q(inputs, "xi_hat_B_hex");
        var alpha = MontgomeryModP.PowModP(EGParameters.G, xiHat);
        var beta = MontgomeryModP.PowModP(MainChainBallotDataKey, xiHat);
        Assert.Equal(inputs.GetProperty("alpha_B_hex").GetString(), ToHex(alpha));
        Assert.Equal(inputs.GetProperty("beta_B_hex").GetString(), ToHex(beta));

        AssertExpected(vector, BallotNonceEncryption.SecretKey(selectionHash, alpha, beta));
    }

    /// <summary>
    /// Eq. (36): a one-byte counter and a two-byte length, the shape of eqs. (17)/(18), not the
    /// four-byte fields of eq. (66). The message is the same 36 bytes for every h.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "ballot_nonce_kdf_key")]
    public void BallotNonceKdfKey_Eq36(string name)
    {
        var vector = Vector(name);
        Assert.Equal(36, vector.GetProperty("b1_len").GetInt32());
        Assert.Equal(Root.GetProperty("challenged_ballots").GetProperty("ballot_nonce_kdf").GetProperty("message_hex").GetString(), vector.GetProperty("b1_hex").GetString());

        AssertExpected(vector, BallotNonceEncryption.EncryptionKey(Hex(Inputs(vector), "h_hex")));
    }

    /// <summary>
    /// Eqs. (34)-(38) through the encryption the ballot encryptor uses, with the oracle's ξ-hat_B and
    /// u_B: C_ξB,0, C_ξB,1 and C_ξB,2 = (c_B, v_B) must be the oracle's. The proof must then verify as a
    /// guardian checks it (§3.6.7 p.52), and C_ξB,1 must decrypt to ξ_B under β_B = K-hat^ξ-hat_B. One
    /// vector has ξ_B = 2^256 - 1, at least q: it is encrypted as its 32 bytes, never reduced.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "ballot_nonce_encryption_challenge")]
    public void BallotNonceEncryption_Eq34To38(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = ChallengedSelectionHash(vector);
        Assert.Equal(1057, vector.GetProperty("b1_len").GetInt32());
        var ballotNonce = new BallotNonce(Hex(inputs, "xi_B_hex"));

        var encrypted = BallotNonceEncryption.Encrypt(ballotNonce, selectionHash, MainChainBallotDataKey, Q(inputs, "xi_hat_B_hex"), Q(inputs, "u_B_hex"));

        var ciphertext = vector.GetProperty("ciphertext");
        Assert.Equal(ciphertext.GetProperty("C0_hex").GetString(), ToHex(encrypted.C0));
        Assert.Equal(ciphertext.GetProperty("C1_hex").GetString(), ToHex(encrypted.C1));
        Assert.Equal(ciphertext.GetProperty("c_hex").GetString(), ToHex(encrypted.Challenge));
        Assert.Equal(ciphertext.GetProperty("v_hex").GetString(), ToHex(encrypted.Response));
        Assert.Equal(ciphertext.GetProperty("C2_hex").GetString(), ToHex(encrypted.Challenge) + ToHex(encrypted.Response));
        AssertExpected(vector, encrypted.Challenge);

        // The eq. (38) challenge from the vector's own a_B, and the guardians' check.
        AssertExpected(vector, BallotNonceEncryption.ProofChallenge(selectionHash, P(inputs, "a_B_hex"), encrypted.C0, encrypted.C1));
        Assert.True(BallotNonceEncryption.ProofHolds(selectionHash, encrypted));

        // h (eq. 35), k_1 (eq. 36), and C_ξB,1 back to ξ_B.
        Assert.Equal(inputs.GetProperty("h_hex").GetString(), ToHex(BallotNonceEncryption.SecretKey(selectionHash, encrypted.C0, P(inputs, "beta_B_hex"))));
        Assert.Equal(inputs.GetProperty("k_1_hex").GetString(), ToHex(BallotNonceEncryption.EncryptionKey(Hex(inputs, "h_hex"))));
        Assert.Equal(inputs.GetProperty("xi_B_hex").GetString(), ToHex(BallotNonceEncryption.Decrypt(selectionHash, encrypted, P(inputs, "beta_B_hex"))));
    }

    /// <summary>
    /// Eqs. (107), (108) and the decryption of p.52: each guardian of U holds the oracle's ẑ_i (the
    /// n = 3, k = 2 K-hat polynomials) and computes m_i through <see cref="TallyGuardian.DecryptBallotNonce"/>
    /// for a challenged ballot carrying the oracle's C_ξB; β_B = ∏ m_i^{w_i} and the h, k_1 and ξ_B
    /// derived from it must be the oracle's.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "ballot_nonce_decryption_secret_key")]
    public void BallotNonceDecryption_Eq107And108(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = ChallengedSelectionHash(vector);
        var nonce = BallotNonceCiphertext(inputs);
        var (record, ballot) = ChallengedShell(selectionHash, nonce);

        var participants = Participants(inputs);
        IntegerModP betaB = 1;
        foreach (var guardianVector in inputs.GetProperty("guardians").EnumerateArray())
        {
            var index = new GuardianIndex(Int(guardianVector, "i"));
            var guardian = new TallyGuardian(index, new GuardianSecretShares
            {
                VoteEncryptionKeyShare = 0,
                OtherBallotDataEncryptionKeyShare = Q(guardianVector, "z_hat_i_hex"),
            });

            var partial = guardian.DecryptBallotNonce(ballot, record);
            Assert.Equal(guardianVector.GetProperty("m_i_hex").GetString(), ToHex(partial.Mi));

            var w = TallyDecryptionHashes.LagrangeCoefficient(index, participants);
            Assert.Equal(guardianVector.GetProperty("w_i_hex").GetString(), ToHex(w));
            betaB *= MontgomeryModP.PowModP(partial.Mi, w);
        }

        Assert.Equal(inputs.GetProperty("beta_B_hex").GetString(), ToHex(betaB));
        var h = BallotNonceEncryption.SecretKey(selectionHash, nonce.C0, betaB);
        AssertExpected(vector, h);
        var decryption = inputs.GetProperty("decryption");
        Assert.Equal(decryption.GetProperty("k_1_hex").GetString(), ToHex(BallotNonceEncryption.EncryptionKey(h)));
        Assert.Equal(decryption.GetProperty("xi_B_hex").GetString(), ToHex(BallotNonceEncryption.Decrypt(selectionHash, nonce, betaB)));
    }

    /// <summary>Verification 13.4-13.6: h = H(H_I; 0x26, ind_c, g^ξ, K-hat^ξ) from the released contest data nonce ξ.</summary>
    [Theory]
    [MemberData(nameof(VectorNames), "challenged_ballot_contest_data_secret_key")]
    public void ChallengedBallotContestDataSecretKey_Verification13_4To13_6(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = ChallengedSelectionHash(vector);
        var xi = Q(inputs, "released_xi_hex");
        var alpha = MontgomeryModP.PowModP(EGParameters.G, xi);
        var beta = MontgomeryModP.PowModP(MainChainBallotDataKey, xi);
        Assert.Equal(inputs.GetProperty("alpha_hex").GetString(), ToHex(alpha));
        Assert.Equal(inputs.GetProperty("beta_hex").GetString(), ToHex(beta));

        AssertExpected(vector, ContestDataEncryption.SecretKey(selectionHash, Int(inputs, "ind_c"), alpha, beta));
    }

    /// <summary>Verification 13.7 with the counter from 1 (user decision Q6).</summary>
    [Theory]
    [MemberData(nameof(VectorNames), "challenged_ballot_contest_data_kdf_key")]
    public void ChallengedBallotContestDataKdfKey_Verification13_7(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        Assert.Equal(38, vector.GetProperty("b1_len").GetInt32());
        Span<byte> key = stackalloc byte[ContestDataEncryption.BlockBytes];
        ContestDataEncryption.BlockKey(Hex(inputs, "h_hex"), Int(inputs, "ind_c"), Int(inputs, "b_Lambda"), Int(inputs, "l"), key);

        AssertExpected(vector, key.ToArray());
    }

    /// <summary>
    /// Verification 13.1-13.3: (α, β) recomputed from each released ξ_{i,j} and σ, then χ by eq. (70)
    /// with the contest's (C_0, C_1, C_2) where it carries contest data, keyed by ind_c (not the
    /// contest's position on the ballot: the sparse ballot makes the two differ).
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "challenged_ballot_contest_hash")]
    public void ChallengedBallotContestHash_Verification13_1To13_3(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var released = inputs.GetProperty("released");
        var selectionHash = ChallengedSelectionHash(vector);
        var voteEncryptionKey = IntegerModP.PowModP(EGParameters.G, new BigInteger(5));

        var fields = released.GetProperty("selections").EnumerateArray().Select(x =>
        {
            var xi = Q(x, "xi_hex");
            var field = new EncryptedValueWithProofs
            {
                Alpha = MontgomeryModP.PowModP(EGParameters.G, xi),
                Beta = MontgomeryModP.PowModP(voteEncryptionKey, xi + Int(x, "sigma")),
                Proofs = [],
            };
            Assert.Equal(x.GetProperty("alpha_hex").GetString(), ToHex(field.Alpha));
            Assert.Equal(x.GetProperty("beta_hex").GetString(), ToHex(field.Beta));
            return field;
        }).ToList();

        EncryptedContestData? contestData = released.TryGetProperty("contest_data", out var data) ? ContestData(data) : null;

        AssertExpected(vector, new ContestHash(selectionHash, Int(inputs, "ind_c"), fields, contestData));
    }

    /// <summary>Verification 13.B: H_C over the recomputed contest hashes and the ballot's B_C.</summary>
    [Theory]
    [MemberData(nameof(VectorNames), "challenged_ballot_confirmation_code")]
    public void ChallengedBallotConfirmationCode_Verification13B(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = ChallengedSelectionHash(vector);
        var chainingField = ChallengedChainingField(inputs.GetProperty("B_C_hex").GetString()!);
        var hashes = inputs.GetProperty("contest_hashes_hex").EnumerateArray().Select(x => new ContestHash(Convert.FromHexString(x.GetString()!))).ToList();

        AssertExpected(vector, new ConfirmationCode(selectionHash, hashes, chainingField));
    }

    /// <summary>
    /// Every challenged ballot of the oracle, end to end: the ballot carries the oracle's ciphertexts,
    /// contest hashes, confirmation code and encrypted nonce, the guardians of U decrypt the nonce with
    /// the oracle's ẑ_i, and the administrator's published decryption must release exactly the oracle's
    /// ξ_{i,j}, σ, contest data ξ and D, and never ξ_B. Verifications 13 and 14 must accept it.
    /// </summary>
    [Theory]
    [InlineData("main_chain ballot")]
    [InlineData("sparse ballot (ind_c 2 and 5)")]
    public void ChallengedBallot_Decryption_ReleasesTheOraclesNoncesAndValues_AndVerifications13And14Accept(string ballotName)
    {
        var (record, ballot, deviceHash, guardians, contestVectors) = OracleChallengedBallot(ballotName);

        var decrypted = new TallyAdmin().DecryptChallengedBallot(guardians, ballot, record);

        Assert.Equal(contestVectors.Count, decrypted.Contests.Count);
        for (int c = 0; c < contestVectors.Count; c++)
        {
            var released = Inputs(contestVectors[c]).GetProperty("released");
            var contest = decrypted.Contests[c];
            Assert.Equal($"contest-{Int(released, "ind_c")}", contest.ContestId);

            var selections = released.GetProperty("selections").EnumerateArray().ToList();
            Assert.Equal(selections.Count, contest.Choices.Count);
            for (int j = 0; j < selections.Count; j++)
            {
                Assert.Equal($"contest-{Int(released, "ind_c")}-option-{Int(selections[j], "ind_o")}", contest.Choices[j].Id);
                Assert.Equal(selections[j].GetProperty("xi_hex").GetString(), ToHex(contest.Choices[j].EncryptionNonce));
                Assert.Equal(Int(selections[j], "sigma"), contest.Choices[j].Value);
            }

            if (released.TryGetProperty("contest_data", out var data))
            {
                Assert.Equal(released.GetProperty("contest_data_xi_hex").GetString(), ToHex(contest.ContestData!.EncryptionNonce));
                Assert.Equal(data.GetProperty("D_hex").GetString(), ToHex(contest.ContestData.Data));
                Assert.Equal(data.GetProperty("contest_data_string").GetString(), contest.ContestData.DecodeText());
            }
            else
            {
                Assert.Null(contest.ContestData);
            }
        }

        // ξ_B "should not be published": no released value is it.
        var ballotNonce = Root.GetProperty("challenged_ballots").GetProperty("ballot_nonce_encryptions").EnumerateArray()
            .First(x => x.GetProperty("ballot").GetString() == ballotName).GetProperty("xi_B_hex").GetString();
        Assert.DoesNotContain(decrypted.Contests.SelectMany(x => x.Choices.Select(f => ToHex(f.EncryptionNonce)).Append(x.ContestData is null ? "" : ToHex(x.ContestData.EncryptionNonce))), x => x == ballotNonce);

        new ChallengedBallotDecryptionVerification().Verify(record, ballot, decrypted, deviceHash, null);
        new ChallengedBallotWellFormednessVerification().Verify(record.Manifest, ballot, decrypted);
    }

    /// <summary>
    /// The oracle's main-chain ballot with contest data, encrypted by <see cref="BallotEncryptor"/>
    /// with the oracle's proof nonces and ξ-hat_B = 9001, u_B = 9101: the encrypted nonce must be the
    /// oracle's C_ξB, the confirmation code must be the Verification 13.B vector's, and once the
    /// ballot is challenged the guardians and the administrator must open it so that Verifications 8,
    /// 13 and 14 accept.
    /// </summary>
    [Fact]
    public void Encryption_CarriesTheOraclesEncryptedBallotNonce_AndTheChallengedBallotOpens()
    {
        var nonceVector = AllVectors.Single(x => x.GetProperty("name").GetString() == "ballot nonce C main_chain ballot xi_hat_B=9001");
        var (record, oracleBallot, deviceHash, guardians, _) = OracleChallengedBallot("main_chain ballot");
        var chain = Root.GetProperty("main_chain");

        var encryptionVectors = AllVectors.Where(x => x.GetProperty("family").GetString() == "contest_data_encryption_challenge")
            .ToDictionary(x => Int(Inputs(x), "ind_c"));
        int[][] votes = [[1, 0], [0, 0, 1], [1]];
        var plaintext = new Core.BallotEncryption.Ballot
        {
            Id = oracleBallot.Id,
            BallotStyleId = oracleBallot.BallotStyleId,
            Contests = record.Manifest.Contests.Select((contest, c) =>
            {
                var text = Inputs(encryptionVectors[contest.Index]).GetProperty("contest_data_string").GetString()!;
                return new BallotContest
                {
                    Id = contest.Id,
                    Choices = contest.Choices.Select((choice, j) => new BallotChoice { Id = choice.Id, SelectionValue = votes[c][j] }).ToList(),
                    ContestData = text.Length == 0 ? null : ContestDataEncoding.Encode(text, contest.ContestDataBlocks),
                };
            }).ToList(),
        };
        var nonceInputs = Inputs(nonceVector);
        var encryptor = new BallotEncryptor(record, chain.GetProperty("S_device").GetString()!, deviceHash)
        {
            ContestDataProofNonceForTesting = contestIndex => Q(Inputs(encryptionVectors[contestIndex]), "u_hex"),
            BallotNonceEncryptionNoncesForTesting = () => (Q(nonceInputs, "xi_hat_B_hex"), Q(nonceInputs, "u_B_hex")),
        };

        var encrypted = encryptor.Encrypt(plaintext, previousConfirmationCode: null, new SelectionEncryptionIdentifier(Hex(chain, "id_B_hex")), MainChainBallotNonce);

        var ciphertext = nonceVector.GetProperty("ciphertext");
        Assert.Equal(ciphertext.GetProperty("C0_hex").GetString(), ToHex(encrypted.EncryptedBallotNonce.C0));
        Assert.Equal(ciphertext.GetProperty("C1_hex").GetString(), ToHex(encrypted.EncryptedBallotNonce.C1));
        Assert.Equal(ciphertext.GetProperty("c_hex").GetString(), ToHex(encrypted.EncryptedBallotNonce.Challenge));
        Assert.Equal(ciphertext.GetProperty("v_hex").GetString(), ToHex(encrypted.EncryptedBallotNonce.Response));

        // C_ξB is not an input to the confirmation code: the ballot's H_C is the 13.B vector's.
        Assert.Equal(ToHex(oracleBallot.ConfirmationCode), ToHex(encrypted.ConfirmationCode));
        new ConfirmationCodeVerification().Verify(encrypted, deviceHash, record, null);

        encrypted.RecordStatus(BallotStatus.Challenged);
        var decrypted = new TallyAdmin().DecryptChallengedBallot(guardians, encrypted, record);
        new ChallengedBallotDecryptionVerification().Verify(record, encrypted, decrypted, deviceHash, null);
        new ChallengedBallotWellFormednessVerification().Verify(record.Manifest, encrypted, decrypted);
        for (int c = 0; c < votes.Length; c++)
        {
            Assert.Equal(votes[c], decrypted.Contests[c].Choices.Select(f => f.Value).ToArray());
        }
    }

    /// <summary>B_C from its bytes: 0x00000000 ‖ H_DI (no chaining) or 0x00000001 ‖ H_0 (simple chaining, first ballot).</summary>
    private static ChainingField ChallengedChainingField(string hex)
    {
        var chain = Root.GetProperty("main_chain");
        var extendedBaseHash = ExtendedBaseHashFor(chain.GetProperty("H_E_hex").GetString()!);
        var deviceHash = new VotingDeviceInformationHash(Hex(chain, "H_DI_hex"));
        var mode = hex.StartsWith("00000000", StringComparison.Ordinal) ? ChainingMode.None : ChainingMode.Simple;
        var chainingField = new ChainingField(mode, deviceHash, extendedBaseHash, previousConfirmationCode: null);
        Assert.Equal(hex, ToHex(chainingField));
        return chainingField;
    }

    /// <summary>
    /// The main-chain election (K = g^5, K-hat = g^7, H_E rebuilt through the constructors) with one
    /// one-option contest and no contest data, and a challenged ballot keyed with
    /// <paramref name="selectionHash"/>'s id_B carrying <paramref name="nonce"/>. Only H_I and C_ξB
    /// enter a guardian's partial decryption; the selection's ciphertext is a placeholder.
    /// </summary>
    private static (EncryptionRecord Record, EncryptedBallot Ballot) ChallengedShell(SelectionEncryptionIdentifierHash selectionHash, EncryptedBallotNonce nonce)
    {
        var record = MainChainRecord([new Contest
        {
            Id = "contest-1",
            Name = "Contest 1",
            SelectionLimit = 1,
            OptionSelectionLimit = 1,
            Index = 1,
            Choices = [new Choice { Id = "contest-1-option-1", Name = "Option 1", Index = 1 }],
        }], ChainingMode.None);
        var identifier = IdentifierFor(record, selectionHash);
        var ballot = new EncryptedBallot
        {
            Id = "kat-challenged",
            SelectionEncryptionIdentifier = identifier,
            SelectionEncryptionIdentifierHash = selectionHash,
            BallotStyleId = "style",
            DeviceId = "kat-device",
            Weight = 1,
            ConfirmationCode = new ConfirmationCode(new byte[32]),
            ChainingField = ElectionFixtureBuilder.PlaceholderChainingField,
            EncryptedBallotNonce = nonce,
            Status = BallotStatus.Challenged,
            Contests =
            [
                new EncryptedContest
                {
                    Id = "contest-1",
                    Choices = [new EncryptedSelection { ChoiceId = "contest-1-option-1", Alpha = 1, Beta = 1, Proofs = [] }],
                    SupplementalFields = [],
                    Proofs = [],
                    ContestData = null,
                    ContestHash = new ContestHash(new byte[32]),
                },
            ],
        };

        return (record, ballot);
    }

    /// <summary>
    /// The oracle's challenged ballot <paramref name="ballotName"/>, rebuilt from its vectors: a
    /// manifest of contests 1..max(ind_c), the ballot's own on its ballot style (one option per
    /// released selection, b_Λ as released, L = R = 1); the ballot with the oracle's (α, β), contest
    /// data fields, contest hashes, confirmation code (13.B) and the first C_ξB the oracle encrypted
    /// for it, recorded as challenged; and the guardians of that C_ξB's decryption vector with their ẑ_i.
    /// </summary>
    private static (EncryptionRecord Record, EncryptedBallot Ballot, VotingDeviceInformationHash DeviceHash, List<TallyGuardian> Guardians, List<JsonElement> ContestVectors) OracleChallengedBallot(string ballotName)
    {
        var contestVectors = AllVectors
            .Where(x => x.GetProperty("family").GetString() == "challenged_ballot_contest_hash" && x.GetProperty("name").GetString()!.StartsWith($"V13 chi {ballotName} ind_c=", StringComparison.Ordinal))
            .OrderBy(x => Int(Inputs(x), "ind_c"))
            .ToList();
        Assert.NotEmpty(contestVectors);
        var codeVector = AllVectors.Single(x => x.GetProperty("name").GetString() == $"V13 H_C {ballotName}");
        var nonceEntry = Root.GetProperty("challenged_ballots").GetProperty("ballot_nonce_encryptions").EnumerateArray()
            .First(x => x.GetProperty("ballot").GetString() == ballotName);
        var decryptionVector = AllVectors.First(x => x.GetProperty("family").GetString() == "ballot_nonce_decryption_secret_key"
            && x.GetProperty("name").GetString()!.StartsWith($"ballot nonce decryption h {ballotName} xi_hat_B=", StringComparison.Ordinal)
            && Inputs(x).GetProperty("C1_hex").GetString() == nonceEntry.GetProperty("C1_hex").GetString());

        var released = contestVectors.Select(x => Inputs(x).GetProperty("released")).ToList();
        int lastIndex = released.Max(x => Int(x, "ind_c"));
        var contests = Enumerable.Range(1, lastIndex).Select(index =>
        {
            var own = released.FirstOrDefault(x => Int(x, "ind_c") == index);
            int options = own.ValueKind == JsonValueKind.Undefined ? 1 : own.GetProperty("selections").GetArrayLength();
            return new Contest
            {
                Id = $"contest-{index}",
                Name = $"Contest {index}",
                SelectionLimit = 1,
                OptionSelectionLimit = 1,
                Index = index,
                Choices = Enumerable.Range(1, options).Select(j => new Choice { Id = $"contest-{index}-option-{j}", Name = $"Option {j}", Index = j }).ToList(),
                ContestDataBlocks = own.ValueKind != JsonValueKind.Undefined && own.TryGetProperty("contest_data", out var data) ? Int(data, "b_Lambda") : 0,
            };
        }).ToList();

        var codeInputs = Inputs(codeVector);
        var chainingField = ChallengedChainingField(codeInputs.GetProperty("B_C_hex").GetString()!);
        var mode = ((byte[])chainingField)[3] == 0 ? ChainingMode.None : ChainingMode.Simple;
        var record = MainChainRecord(contests, mode, released.Select(x => $"contest-{Int(x, "ind_c")}").ToList());

        var selectionHash = ChallengedSelectionHash(codeVector);
        var ballot = new EncryptedBallot
        {
            Id = "kat-challenged",
            SelectionEncryptionIdentifier = IdentifierFor(record, selectionHash),
            SelectionEncryptionIdentifierHash = selectionHash,
            BallotStyleId = "style",
            DeviceId = Root.GetProperty("main_chain").GetProperty("S_device").GetString()!,
            Weight = 1,
            ConfirmationCode = new ConfirmationCode(Convert.FromHexString(codeVector.GetProperty("expected_hex").GetString()!)),
            ChainingField = chainingField,
            EncryptedBallotNonce = BallotNonceCiphertext(nonceEntry, "C0_hex", "C1_hex", "c_B_hex", "v_B_hex"),
            Status = BallotStatus.Challenged,
            Contests = contestVectors.Select(vector =>
            {
                var own = Inputs(vector).GetProperty("released");
                int index = Int(own, "ind_c");
                return new EncryptedContest
                {
                    Id = $"contest-{index}",
                    Choices = own.GetProperty("selections").EnumerateArray().Select(x => new EncryptedSelection
                    {
                        ChoiceId = $"contest-{index}-option-{Int(x, "ind_o")}",
                        Alpha = P(x, "alpha_hex"),
                        Beta = P(x, "beta_hex"),
                        Proofs = [],
                    }).ToList(),
                    SupplementalFields = [],
                    Proofs = [],
                    ContestData = own.TryGetProperty("contest_data", out var data) ? ContestData(data) : null,
                    ContestHash = new ContestHash(Convert.FromHexString(vector.GetProperty("expected_hex").GetString()!)),
                };
            }).ToList(),
        };

        var guardians = Inputs(decryptionVector).GetProperty("guardians").EnumerateArray()
            .Select(x => new TallyGuardian(new GuardianIndex(Int(x, "i")), new GuardianSecretShares
            {
                VoteEncryptionKeyShare = 0,
                OtherBallotDataEncryptionKeyShare = Q(x, "z_hat_i_hex"),
            }))
            .ToList();

        return (record, ballot, new VotingDeviceInformationHash(Hex(Root.GetProperty("main_chain"), "H_DI_hex")), guardians, contestVectors);
    }

    /// <summary>The main-chain election record over <paramref name="contests"/>, one ballot style "style".</summary>
    private static EncryptionRecord MainChainRecord(List<Contest> contests, ChainingMode chainingMode, List<string>? styleContests = null)
    {
        var chain = Root.GetProperty("main_chain");
        var keys = new ElectionPublicKeys([IntegerModP.PowModP(EGParameters.G, new BigInteger(5))], [MainChainBallotDataKey]);
        var parameterBaseHash = new ParameterBaseHash(new CryptographicParameters(), new GuardianParameters(3, 2));
        var manifestFile = new ManifestFile { Bytes = Hex(chain, "manifest_hex") };
        var electionBaseHash = new ElectionBaseHash(parameterBaseHash, manifestFile);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, keys);
        Assert.Equal(chain.GetProperty("H_E_hex").GetString(), ToHex(extendedBaseHash));

        return new EncryptionRecord
        {
            CryptographicParameters = new CryptographicParameters(),
            GuardianParameters = new GuardianParameters(3, 2),
            ParameterBaseHash = parameterBaseHash,
            ManifestFile = manifestFile,
            ElectionBaseHash = electionBaseHash,
            Guardians = [],
            ElectionPublicKeys = keys,
            ExtendedBaseHash = extendedBaseHash,
            Manifest = new Manifest
            {
                ElectionId = "kat",
                Contests = contests,
                BallotStyles = [new BallotStyle { Id = "style", Name = "Style", ContestIds = styleContests ?? contests.Select(x => x.Id).ToList() }],
                ChainingMode = chainingMode,
            },
        };
    }

    /// <summary>The id_B whose H(H_E; 0x20, id_B) under <paramref name="record"/>'s H_E is <paramref name="selectionHash"/>.</summary>
    private static SelectionEncryptionIdentifier IdentifierFor(EncryptionRecord record, SelectionEncryptionIdentifierHash selectionHash)
    {
        var candidates = new List<string>
        {
            Root.GetProperty("main_chain").GetProperty("id_B_hex").GetString()!,
            Root.GetProperty("challenged_ballots").GetProperty("sparse_ballot").GetProperty("id_B_hex").GetString()!,
        };
        candidates.AddRange(AllVectors
            .Where(x => x.GetProperty("family").GetString()!.StartsWith("ballot_nonce_", StringComparison.Ordinal))
            .Select(x => Inputs(x))
            .Where(x => x.TryGetProperty("id_B_hex", out _))
            .Select(x => x.GetProperty("id_B_hex").GetString()!));

        foreach (var candidate in candidates.Distinct())
        {
            var identifier = new SelectionEncryptionIdentifier(Convert.FromHexString(candidate));
            if (ToHex(new SelectionEncryptionIdentifierHash(record.ExtendedBaseHash, identifier)) == ToHex(selectionHash))
            {
                return identifier;
            }
        }

        throw new Xunit.Sdk.XunitException($"No id_B of the vectors gives H_I {ToHex(selectionHash)}.");
    }
}
