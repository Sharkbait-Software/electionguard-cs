using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using System.Numerics;
using System.Text;
using System.Text.Json;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Testing.Common;
using Version = ElectionGuard.Core.Models.Version;

namespace ElectionGuard.Core.UnitTests.Kat;

/// <summary>
/// Known-answer tests against test/kat/vectors.json, which test/kat/eg_kat.py generates from the
/// v2.1.0 specification text alone, without reading this library. Every other hash test in this
/// project compares the library against a re-statement of its own formula, so a hash computed
/// consistently wrong passes them and the end-to-end pipeline alike; these do not.
///
/// Each vector is pushed through the library's own constructors, never through EGHash directly, so
/// what is pinned is the encoding the library actually uses. Where a vector's key is an earlier
/// value in the hash chain, that value is itself recomputed through the constructors and checked
/// against the vector's input first, so the chain is checked link by link.
/// </summary>
public partial class KnownAnswerTests
{
    public KnownAnswerTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    /// <summary>
    /// Vector families the library cannot yet express, with the reason. A family that is neither
    /// checked here nor listed below fails <see cref="EveryVectorFamilyIsCheckedOrExplicitlyUnsupported"/>,
    /// so a family added to the oracle is never skipped silently.
    /// </summary>
    private static readonly Dictionary<string, string> UnsupportedFamilies = new()
    {
        // Chain closing (eqs. 77/78, 0x2B) has no API yet; stage S8 (G19).
        ["chain_close_inner"] = "G19: no chain-closing API",
        ["chain_close"] = "G19: no chain-closing API",
    };

    private static readonly Lazy<JsonDocument> Document = new(() =>
        JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "kat", "vectors.json"))));

    private static JsonElement Root => Document.Value.RootElement;

    private static IEnumerable<JsonElement> AllVectors => Root.GetProperty("vectors").EnumerateArray();

    public static IEnumerable<object[]> VectorNames(string family) =>
        AllVectors.Where(x => x.GetProperty("family").GetString() == family)
            .Select(x => new object[] { x.GetProperty("name").GetString()! });

    private static JsonElement Vector(string name) =>
        AllVectors.Single(x => x.GetProperty("name").GetString() == name);

    private static JsonElement Inputs(JsonElement vector) => vector.GetProperty("inputs");

    private static byte[] Hex(JsonElement element, string property) =>
        Convert.FromHexString(element.GetProperty(property).GetString()!);

    private static int Int(JsonElement element, string property)
    {
        var value = element.GetProperty(property);
        return value.ValueKind == JsonValueKind.Number ? value.GetInt32() : int.Parse(value.GetString()!);
    }

    private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes);

    private static void AssertExpected(JsonElement vector, byte[] actual)
    {
        Assert.Equal(vector.GetProperty("expected_hex").GetString(), ToHex(actual));
    }

    // --- The chain of keys, rebuilt through the library's constructors -------------------------

    private static readonly (int N, int K)[] GuardianShapes = [(3, 2), (5, 3), (1, 1)];

    /// <summary>The library's H_P for the (n, k) whose value is <paramref name="hex"/>.</summary>
    private static ParameterBaseHash ParameterBaseHashFor(string hex)
    {
        foreach (var (n, k) in GuardianShapes)
        {
            var hash = new ParameterBaseHash(new CryptographicParameters(), new GuardianParameters(n, k));
            if (ToHex(hash) == hex)
            {
                return hash;
            }
        }

        throw new Xunit.Sdk.XunitException($"No (n, k) in {string.Join(", ", GuardianShapes)} gives the library an H_P of {hex}.");
    }

    /// <summary>
    /// The library's H_B equal to <paramref name="hex"/>, found among the election_base_hash vectors'
    /// inputs. Each candidate is computed by the library, so finding one also confirms that link.
    /// </summary>
    private static ElectionBaseHash ElectionBaseHashFor(string hex)
    {
        foreach (var vector in AllVectors.Where(x => x.GetProperty("family").GetString() == "election_base_hash"))
        {
            var inputs = Inputs(vector);
            var hash = new ElectionBaseHash(
                ParameterBaseHashFor(inputs.GetProperty("H_P_hex").GetString()!),
                new ManifestFile { Bytes = Hex(inputs, "manifest_hex") });
            if (ToHex(hash) == hex)
            {
                return hash;
            }
        }

        throw new Xunit.Sdk.XunitException($"No election_base_hash vector input gives the library an H_B of {hex}.");
    }

    /// <summary>The library's H_E equal to <paramref name="hex"/>, found among the extended_base_hash vectors' inputs.</summary>
    private static ExtendedBaseHash ExtendedBaseHashFor(string hex)
    {
        foreach (var vector in AllVectors.Where(x => x.GetProperty("family").GetString() == "extended_base_hash"))
        {
            var hash = ComputeExtendedBaseHash(Inputs(vector));
            if (ToHex(hash) == hex)
            {
                return hash;
            }
        }

        throw new Xunit.Sdk.XunitException($"No extended_base_hash vector input gives the library an H_E of {hex}.");
    }

    private static ExtendedBaseHash ComputeExtendedBaseHash(JsonElement inputs)
    {
        var keys = new ElectionPublicKeys(
            [new IntegerModP(Hex(inputs, "K_hex"))],
            [new IntegerModP(Hex(inputs, "K_hat_hex"))]);
        return new ExtendedBaseHash(ElectionBaseHashFor(inputs.GetProperty("H_B_hex").GetString()!), keys);
    }

    /// <summary>The library's H_I equal to <paramref name="hex"/>, found among the selection_encryption_identifier_hash vectors' inputs.</summary>
    private static SelectionEncryptionIdentifierHash SelectionEncryptionIdentifierHashFor(string hex)
    {
        foreach (var vector in AllVectors.Where(x => x.GetProperty("family").GetString() == "selection_encryption_identifier_hash"))
        {
            var inputs = Inputs(vector);
            var hash = new SelectionEncryptionIdentifierHash(
                ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!),
                new SelectionEncryptionIdentifier(Hex(inputs, "id_B_hex")));
            if (ToHex(hash) == hex)
            {
                return hash;
            }
        }

        throw new Xunit.Sdk.XunitException($"No selection_encryption_identifier_hash vector input gives the library an H_I of {hex}.");
    }

    // --- Tests -------------------------------------------------------------------------------

    [Fact]
    public void EveryVectorFamilyIsCheckedOrExplicitlyUnsupported()
    {
        var checkedFamilies = new HashSet<string>
        {
            "parameter_base_hash",
            "election_base_hash",
            "guardian_share_kdf_key",
            "guardian_record_hash",
            "extended_base_hash",
            "selection_encryption_identifier_hash",
            "encryption_nonce",
            "device_info_hash",
            "preencrypted_device_info_hash",
            "contest_hash",
            "confirmation_code",
            "chain_init",
            "tally_decryption_commitment_hash",
            "tally_decryption_challenge",
            "contest_data_nonce",
            "contest_data_secret_key",
            "contest_data_kdf_key",
            "contest_data_encryption_challenge",
            "contest_hash_with_contest_data",
            "contest_data_decryption_commitment_hash",
            "contest_data_decryption_challenge",
        };

        var families = AllVectors.Select(x => x.GetProperty("family").GetString()!).ToHashSet();

        Assert.Empty(families.Except(checkedFamilies).Except(UnsupportedFamilies.Keys));
        Assert.Equal("v2.1.0", Root.GetProperty("spec_version").GetString());
    }

    [Fact]
    public void Parameters_MatchTheLibraryDefaults()
    {
        var parameters = Root.GetProperty("parameters");
        var library = new CryptographicParameters();

        Assert.Equal(Convert.FromHexString(parameters.GetProperty("p_hex").GetString()!), library.P.ToByteArray(isUnsigned: true, isBigEndian: true));
        Assert.Equal(Convert.FromHexString(parameters.GetProperty("q_hex").GetString()!), library.Q.ToByteArray(isUnsigned: true, isBigEndian: true));
        Assert.Equal(Convert.FromHexString(parameters.GetProperty("g_hex").GetString()!), library.G.ToByteArray(isUnsigned: true, isBigEndian: true));
    }

    [Fact]
    public void MainChain_RebuiltThroughTheConstructors_MatchesEveryLink()
    {
        var chain = Root.GetProperty("main_chain");
        var g = EGParameters.G;

        var parameterBaseHash = new ParameterBaseHash(new CryptographicParameters(), new GuardianParameters(Int(chain, "n"), Int(chain, "k")));
        Assert.Equal(chain.GetProperty("H_P_hex").GetString(), ToHex(parameterBaseHash));

        var electionBaseHash = new ElectionBaseHash(parameterBaseHash, new ManifestFile { Bytes = Hex(chain, "manifest_hex") });
        Assert.Equal(chain.GetProperty("H_B_hex").GetString(), ToHex(electionBaseHash));

        Assert.Equal("g^5", chain.GetProperty("K").GetString());
        Assert.Equal("g^7", chain.GetProperty("K_hat").GetString());
        var keys = new ElectionPublicKeys(
            [IntegerModP.PowModP(g, new BigInteger(5))],
            [IntegerModP.PowModP(g, new BigInteger(7))]);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, keys);
        Assert.Equal(chain.GetProperty("H_E_hex").GetString(), ToHex(extendedBaseHash));

        var selectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(extendedBaseHash, new SelectionEncryptionIdentifier(Hex(chain, "id_B_hex")));
        Assert.Equal(chain.GetProperty("H_I_hex").GetString(), ToHex(selectionEncryptionIdentifierHash));

        var device = chain.GetProperty("S_device").GetString()!;
        Assert.Equal(chain.GetProperty("H_DI_hex").GetString(), ToHex(new VotingDeviceInformationHash(extendedBaseHash, device)));
        Assert.Equal(chain.GetProperty("H_DI_preencrypted_hex").GetString(), ToHex(VotingDeviceInformationHash.ForPreEncryptedBallots(extendedBaseHash, device)));
    }

    [Theory]
    [MemberData(nameof(VectorNames), "parameter_base_hash")]
    public void ParameterBaseHash_Eq4(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var cryptographicParameters = new CryptographicParameters();
        Assert.Equal("standard", inputs.GetProperty("p").GetString());

        // The key: ver = "v2.1.0" || b(0, 26), right-padded.
        Assert.Equal(inputs.GetProperty("ver_hex").GetString(), ToHex(cryptographicParameters.Version));
        Assert.Equal(new Version(CryptographicParameters.VERSION_DEFAULT), cryptographicParameters.Version);

        var hash = new ParameterBaseHash(cryptographicParameters, new GuardianParameters(Int(inputs, "n"), Int(inputs, "k")));

        AssertExpected(vector, hash);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "election_base_hash")]
    public void ElectionBaseHash_Eq5(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var manifest = Hex(inputs, "manifest_hex");
        Assert.Equal(Int(inputs, "manifest_len"), manifest.Length);

        var hash = new ElectionBaseHash(ParameterBaseHashFor(inputs.GetProperty("H_P_hex").GetString()!), new ManifestFile { Bytes = manifest });

        AssertExpected(vector, hash);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "guardian_share_kdf_key")]
    public void GuardianShareSecretKey_Eq16(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var parameterBaseHash = ParameterBaseHashFor(inputs.GetProperty("H_P_hex").GetString()!);

        var key = Guardian.ComputeShareSecretKey(
            parameterBaseHash,
            Int(inputs, "i"),
            Int(inputs, "l"),
            new IntegerModP(Hex(inputs, "kappa_l_hex")),
            new IntegerModP(Hex(inputs, "alpha_hex")),
            new IntegerModP(Hex(inputs, "beta_hex")));

        AssertExpected(vector, key);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "guardian_record_hash")]
    public void GuardianRecordHash_Eq27(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        int n = Int(inputs, "n");
        int k = Int(inputs, "k");
        var g = EGParameters.G;

        // The key, H_B, rebuilt through the library from H_P(n, k) and the named manifest's bytes
        // (taken from an election_base_hash vector over the same manifest; (1, 1) has no H_B vector
        // of its own).
        var manifestName = inputs.GetProperty("manifest").GetString()!;
        var manifest = Hex(Inputs(AllVectors.First(x =>
            x.GetProperty("family").GetString() == "election_base_hash"
            && x.GetProperty("name").GetString()!.EndsWith(" " + manifestName))), "manifest_hex");
        var electionBaseHash = new ElectionBaseHash(new ParameterBaseHash(new CryptographicParameters(), new GuardianParameters(n, k)), new ManifestFile { Bytes = manifest });
        Assert.Equal(inputs.GetProperty("H_B_hex").GetString(), ToHex(electionBaseHash));
        Assert.Equal(vector.GetProperty("b0_hex").GetString(), ToHex(electionBaseHash));

        // Every element is g^exponent; check each one against its published value as it is built.
        IntegerModP Element(JsonElement entry)
        {
            var element = IntegerModP.PowModP(g, new BigInteger(Convert.FromHexString(entry.GetProperty("exponent_hex").GetString()!), isUnsigned: true, isBigEndian: true));
            Assert.Equal(entry.GetProperty("hex").GetString(), ToHex(element));
            return element;
        }

        var commitments = inputs.GetProperty("K_i_j").EnumerateArray().Select(row => row.EnumerateArray().Select(Element).ToList()).ToList();
        var commitmentsHat = inputs.GetProperty("K_hat_i_j").EnumerateArray().Select(row => row.EnumerateArray().Select(Element).ToList()).ToList();
        var kappas = inputs.GetProperty("kappa_i").EnumerateArray().Select(Element).ToList();
        Assert.Equal(n, commitments.Count);
        Assert.All(commitments, row => Assert.Equal(k, row.Count));

        // H_G hashes no proof, so the views carry a placeholder.
        var placeholderProof = new SchnorrProof { Challenge = new IntegerModQ(0), Responses = [] };
        var views = Enumerable.Range(0, n).Select(i => new GuardianPublicView
        {
            Index = new GuardianIndex(i + 1),
            VoteEncryptionCommitments = commitments[i],
            OtherBallotDataEncryptionCommitments = commitmentsHat[i],
            CommunicationPublicKey = kappas[i],
            VoteEncryptionProof = placeholderProof,
            OtherDataEncryptionProof = placeholderProof,
        }).ToList();

        // K and K-hat through the library's own product (eqs. 25, 26, with K_i = K_{i,0}).
        var keys = new ElectionPublicKeys(views.Select(v => v.VoteEncryptionCommitments[0]), views.Select(v => v.OtherBallotDataEncryptionCommitments[0]));
        Assert.Equal(inputs.GetProperty("K_hex").GetString(), ToHex(keys.VoteEncryptionKey));
        Assert.Equal(inputs.GetProperty("K_hat_hex").GetString(), ToHex(keys.OtherBallotDataEncryptionKey));

        AssertExpected(vector, Guardian.ComputeGuardianRecordHash(electionBaseHash, keys, views));

        // The guardians are taken in index order whatever order the record lists them in.
        views.Reverse();
        AssertExpected(vector, Guardian.ComputeGuardianRecordHash(electionBaseHash, keys, views));
    }

    [Theory]
    [MemberData(nameof(VectorNames), "extended_base_hash")]
    public void ExtendedBaseHash_Eq30(string name)
    {
        var vector = Vector(name);

        var hash = ComputeExtendedBaseHash(Inputs(vector));

        AssertExpected(vector, hash);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "selection_encryption_identifier_hash")]
    public void SelectionEncryptionIdentifierHash_Eq32(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var identifier = Hex(inputs, "id_B_hex");
        Assert.Equal(32, identifier.Length);

        var hash = new SelectionEncryptionIdentifierHash(
            ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!),
            new SelectionEncryptionIdentifier(identifier));

        AssertExpected(vector, hash);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "encryption_nonce")]
    public void EncryptionNonce_Eq33(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var ballotNonce = Hex(inputs, "xi_B_hex");
        Assert.Equal(32, ballotNonce.Length);

        var nonce = new EncryptionNonce(
            SelectionEncryptionIdentifierHashFor(inputs.GetProperty("H_I_hex").GetString()!),
            new BallotNonce(ballotNonce),
            Int(inputs, "i"),
            Int(inputs, "j"));

        // H_q: the HMAC output reduced mod q, as 32 bytes.
        AssertExpected(vector, nonce);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "device_info_hash")]
    public void VotingDeviceInformationHash_Eq72(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var device = inputs.GetProperty("S_device").GetString()!;
        Assert.Equal(inputs.GetProperty("S_device_utf8_hex").GetString(), ToHex(Encoding.UTF8.GetBytes(device)));

        var hash = new VotingDeviceInformationHash(ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!), device);

        AssertExpected(vector, hash);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "preencrypted_device_info_hash")]
    public void PreEncryptedVotingDeviceInformationHash_Eq119(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var device = inputs.GetProperty("S_device").GetString()!;
        Assert.Equal(inputs.GetProperty("S_device_utf8_hex").GetString(), ToHex(Encoding.UTF8.GetBytes(device)));

        var hash = VotingDeviceInformationHash.ForPreEncryptedBallots(ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!), device);

        AssertExpected(vector, hash);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "chain_init")]
    public void ChainInitialization_Eq74And75(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var extendedBaseHash = ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!);
        var deviceHash = new VotingDeviceInformationHash(Hex(inputs, "H_DI_hex"));

        // The first ballot's chaining field under simple chaining is 0x00000001 || H_0, with
        // H_0 = H(H_E; 0x29, B_C,0) and B_C,0 = 0x00000001 || H_DI.
        byte[] chainingField = new ChainingField(ChainingMode.Simple, deviceHash, extendedBaseHash, previousConfirmationCode: null);

        Assert.Equal(36, chainingField.Length);
        Assert.Equal("00000001", ToHex(chainingField[..4]));
        Assert.Equal(vector.GetProperty("expected_hex").GetString(), ToHex(chainingField[4..]));
        Assert.Equal(inputs.GetProperty("B_C0_hex").GetString(), "00000001" + inputs.GetProperty("H_DI_hex").GetString());
    }

    /// <summary>
    /// Eq. (70) with no contest data: chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ..., alpha_m, beta_m)
    /// over exactly the verifiable fields given, here the options alone (G8: before S5 the library
    /// always appended four supplemental counters), through the constructor the encryptor and
    /// Verification 8 use. <see cref="Encryption_ReproducesTheContestHashAndConfirmationCodeVectors"/>
    /// checks it through an encryption.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "contest_hash")]
    public void ContestHash_Eq70(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionEncryptionIdentifierHash = SelectionEncryptionIdentifierHashFor(inputs.GetProperty("H_I_hex").GetString()!);
        var ciphertexts = inputs.GetProperty("ciphertexts").EnumerateArray()
            .Select((x, i) => new EncryptedSelection
            {
                ChoiceId = $"option-{i + 1}",
                Alpha = P(x, "alpha_hex"),
                Beta = P(x, "beta_hex"),
                Proofs = [],
            })
            .ToList();

        var contestHash = new ContestHash(selectionEncryptionIdentifierHash, inputs.GetProperty("l").GetInt32(), ciphertexts, encryptedContestData: null);

        AssertExpected(vector, contestHash);
    }

    /// <summary>
    /// The oracle's main-chain ballot, encrypted by the library: K = g^5, K-hat = g^7, H_E and H_I
    /// from the main chain, xi_B = A0A1..BF, contest 1 with two options voted (1, 0) and contest 2
    /// with three voted (0, 0, 1), neither declaring a supplemental field. Every ciphertext comes from
    /// eq. (33)'s nonces, so the contest hashes must be the contest_hash vectors chi_1 and chi_2, and
    /// with no chaining the confirmation code must be the confirmation_code vector over them. A
    /// declared supplemental field must then change chi (eq. 70 hashes every declared field), while
    /// leaving the options' ciphertexts alone (each field has its own nonce xi_{i,j}).
    /// </summary>
    [Fact]
    public void Encryption_ReproducesTheContestHashAndConfirmationCodeVectors()
    {
        var chain = Root.GetProperty("main_chain");
        var g = EGParameters.G;
        var parameterBaseHash = new ParameterBaseHash(new CryptographicParameters(), new GuardianParameters(Int(chain, "n"), Int(chain, "k")));
        var manifestFile = new ManifestFile { Bytes = Hex(chain, "manifest_hex") };
        var electionBaseHash = new ElectionBaseHash(parameterBaseHash, manifestFile);
        var keys = new ElectionPublicKeys(
            [IntegerModP.PowModP(g, new BigInteger(5))],
            [IntegerModP.PowModP(g, new BigInteger(7))]);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, keys);
        Assert.Equal(chain.GetProperty("H_E_hex").GetString(), ToHex(extendedBaseHash));

        static Contest Contest(int index, int options, List<SupplementalField>? fields = null) => new()
        {
            Id = $"contest-{index}",
            Name = $"Contest {index}",
            Index = index,
            SelectionLimit = 1,
            OptionSelectionLimit = 1,
            Choices = Enumerable.Range(1, options).Select(j => new Choice { Id = $"option-{index}-{j}", Name = $"Option {j}", Index = j }).ToList(),
            SupplementalFields = fields ?? [],
        };

        EncryptedBallot Encrypt(List<Contest> contests)
        {
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
            int[][] votes = [[1, 0], [0, 0, 1]];
            var ballot = new Core.BallotEncryption.Ballot
            {
                Id = "kat-ballot",
                BallotStyleId = "style",
                Contests = contests.Select((contest, c) => new BallotContest
                {
                    Id = contest.Id,
                    Choices = contest.Choices.Select((choice, j) => new BallotChoice { Id = choice.Id, SelectionValue = votes[c][j] }).ToList(),
                }).ToList(),
            };
            var deviceHash = new VotingDeviceInformationHash(extendedBaseHash, chain.GetProperty("S_device").GetString()!);
            return new BallotEncryptor(record, "kat-device", deviceHash).Encrypt(
                ballot,
                previousConfirmationCode: null,
                new SelectionEncryptionIdentifier(Hex(chain, "id_B_hex")),
                new BallotNonce(Hex(chain, "xi_B_hex")));
        }

        var encrypted = Encrypt([Contest(1, 2), Contest(2, 3)]);
        Assert.Equal(chain.GetProperty("H_I_hex").GetString(), ToHex(encrypted.SelectionEncryptionIdentifierHash));

        var chi = AllVectors.Where(x => x.GetProperty("family").GetString() == "contest_hash")
            .ToDictionary(x => Inputs(x).GetProperty("l").GetInt32(), x => x.GetProperty("expected_hex").GetString());
        Assert.Equal(chi[1], ToHex(encrypted.Contests[0].ContestHash));
        Assert.Equal(chi[2], ToHex(encrypted.Contests[1].ContestHash));

        var confirmationCode = AllVectors.Single(x =>
            x.GetProperty("family").GetString() == "confirmation_code"
            && Inputs(x).TryGetProperty("H_DI_hex", out var deviceHex) && deviceHex.GetString() == chain.GetProperty("H_DI_hex").GetString()
            && Inputs(x).GetProperty("contest_hashes_hex").EnumerateArray().Select(h => h.GetString()).SequenceEqual([chi[1], chi[2]]));
        AssertExpected(confirmationCode, encrypted.ConfirmationCode);

        // Contest 2 declaring an overvote indicator (option index 4): its ciphertext enters chi_2,
        // under its own nonce, and the options' ciphertexts do not move.
        var withField = Encrypt([Contest(1, 2), Contest(2, 3, ElectionFixtureBuilder.SupplementalFields(3, [SupplementalFieldKind.OvervoteIndicator]))]);
        Assert.Equal(chi[1], ToHex(withField.Contests[0].ContestHash));
        Assert.NotEqual(chi[2], ToHex(withField.Contests[1].ContestHash));
        Assert.Equal(encrypted.Contests[1].Choices.Select(x => x.Beta), withField.Contests[1].Choices.Select(x => x.Beta));
        var overvote = Assert.Single(withField.Contests[1].SupplementalFields);
        IntegerModQ xi = new EncryptionNonce(encrypted.SelectionEncryptionIdentifierHash, new BallotNonce(Hex(chain, "xi_B_hex")), 2, 4);
        Assert.Equal(IntegerModP.PowModP(g, xi), overvote.Alpha);
        var expectedChi2 = new ContestHash(encrypted.SelectionEncryptionIdentifierHash, 2,
            withField.Contests[1].Choices.Concat<EncryptedValueWithProofs>([overvote]), encryptedContestData: null);
        Assert.Equal(expectedChi2, withField.Contests[1].ContestHash);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "confirmation_code")]
    public void ConfirmationCode_Eq71(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var mainChain = Root.GetProperty("main_chain");
        var extendedBaseHash = ExtendedBaseHashFor(mainChain.GetProperty("H_E_hex").GetString()!);
        var selectionEncryptionIdentifierHash = SelectionEncryptionIdentifierHashFor(inputs.GetProperty("H_I_hex").GetString()!);
        var contestHashes = inputs.GetProperty("contest_hashes_hex").EnumerateArray()
            .Select(x => new ContestHash(Convert.FromHexString(x.GetString()!)))
            .ToList();
        var expectedChainingField = inputs.GetProperty("B_C_hex").GetString()!;

        ChainingField chainingField;
        if (inputs.TryGetProperty("H_DI_hex", out var deviceHashHex))
        {
            // Eq. (73): no chaining, B_C = 0x00000000 || H_DI.
            chainingField = new ChainingField(ChainingMode.None, new VotingDeviceInformationHash(Convert.FromHexString(deviceHashHex.GetString()!)), extendedBaseHash, previousConfirmationCode: null);
        }
        else
        {
            // Eq. (76): simple chaining, B_C,j = 0x00000001 || H_{j-1}. For the first ballot H_{j-1}
            // is H_0, which the library derives itself from the device hash rather than taking it.
            var previous = inputs.GetProperty("H_prev_hex").GetString()!;
            var chainInit = AllVectors.Single(x => x.GetProperty("family").GetString() == "chain_init");
            chainingField = previous == chainInit.GetProperty("expected_hex").GetString()
                ? new ChainingField(ChainingMode.Simple, new VotingDeviceInformationHash(Hex(Inputs(chainInit), "H_DI_hex")), extendedBaseHash, previousConfirmationCode: null)
                : new ChainingField(ChainingMode.Simple, new VotingDeviceInformationHash(Hex(mainChain, "H_DI_hex")), extendedBaseHash, new ConfirmationCode(Convert.FromHexString(previous)));
        }

        Assert.Equal(expectedChainingField, ToHex(chainingField));

        var confirmationCode = new ConfirmationCode(selectionEncryptionIdentifierHash, contestHashes, chainingField);

        AssertExpected(vector, confirmationCode);
    }

    private static IntegerModP P(JsonElement element, string property) => new(Hex(element, property));

    private static IntegerModQ Q(JsonElement element, string property) => new(Hex(element, property));

    private static List<GuardianIndex> Participants(JsonElement element) =>
        element.GetProperty("U").EnumerateArray().Select(x => new GuardianIndex(x.GetInt32())).ToList();

    [Theory]
    [MemberData(nameof(VectorNames), "tally_decryption_commitment_hash")]
    public void TallyDecryptionCommitmentHash_Eq88(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var extendedBaseHash = ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!);
        Assert.Equal(vector.GetProperty("b0_hex").GetString(), ToHex(extendedBaseHash));
        var a = P(inputs, "A_hex");

        // The commitment pair and the partial decryption, through the library's exponentiation.
        var u = Q(inputs, "u_i_hex");
        var commitmentA = MontgomeryModP.PowModP(EGParameters.G, u);
        var commitmentB = MontgomeryModP.PowModP(a, u);
        var partialDecryption = MontgomeryModP.PowModP(a, Q(inputs, "z_i_hex"));
        Assert.Equal(inputs.GetProperty("a_i_hex").GetString(), ToHex(commitmentA));
        Assert.Equal(inputs.GetProperty("b_i_hex").GetString(), ToHex(commitmentB));
        Assert.Equal(inputs.GetProperty("M_i_hex").GetString(), ToHex(partialDecryption));

        var participants = Participants(inputs);
        byte[] Hash(IReadOnlyCollection<GuardianIndex> u) => TallyDecryptionHashes.CommitmentHash(
            extendedBaseHash, Int(inputs, "ind_c"), Int(inputs, "ind_o"), new GuardianIndex(Int(inputs, "i")),
            a, P(inputs, "B_hex"), commitmentA, commitmentB, partialDecryption, u);

        AssertExpected(vector, Hash(participants));

        // U is encoded in ascending order whatever order it is given in (the spec does not say;
        // the oracle and the library both use ascending order).
        AssertExpected(vector, Hash(Enumerable.Reverse(participants).ToList()));
    }

    /// <summary>
    /// The whole §3.6.5 protocol, end to end, against the oracle's complete proof: the guardians
    /// hold the oracle's z_i and are handed its u_i, the aggregate is the oracle's (A, B), and every
    /// value along the way (M_i, a_i, b_i, d_i, w_i, c, v_i, v, T, t) must match. Verification 10
    /// must then accept the result.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "tally_decryption_challenge")]
    public void TallyDecryptionProof_Eq86To93_AndVerification10(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var proof = inputs.GetProperty("proof");
        var mainChain = Root.GetProperty("main_chain");
        Assert.Equal(mainChain.GetProperty("H_E_hex").GetString(), inputs.GetProperty("H_E_hex").GetString());
        Assert.Equal(3, Int(mainChain, "n"));
        Assert.Equal(2, Int(mainChain, "k"));
        int contestIndex = Int(inputs, "ind_c");
        int optionIndex = Int(inputs, "ind_o");

        // The election of main_chain: K = g^5, K-hat = g^7, H_E rebuilt through the constructors.
        var g = EGParameters.G;
        var keys = new ElectionPublicKeys([IntegerModP.PowModP(g, new BigInteger(5))], [IntegerModP.PowModP(g, new BigInteger(7))]);
        var parameterBaseHash = new ParameterBaseHash(new CryptographicParameters(), new GuardianParameters(3, 2));
        var manifestFile = new ManifestFile { Bytes = Hex(mainChain, "manifest_hex") };
        var electionBaseHash = new ElectionBaseHash(parameterBaseHash, manifestFile);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, keys);
        Assert.Equal(inputs.GetProperty("H_E_hex").GetString(), ToHex(extendedBaseHash));

        // A manifest in which (ind_c, ind_o) exists: two contests of three options each. Only the
        // indices enter the proof; the labels are the library's own.
        var manifest = new Manifest
        {
            ElectionId = "kat",
            Contests = Enumerable.Range(1, 2).Select(c => new Contest
            {
                Id = $"contest-{c}",
                Name = $"Contest {c}",
                SelectionLimit = 1,
                OptionSelectionLimit = 1,
                Index = c,
                Choices = Enumerable.Range(1, 3).Select(o => new Choice { Id = $"contest-{c}-option-{o}", Name = $"Option {o}", Index = o }).ToList(),
            }).ToList(),
            BallotStyles = [new BallotStyle { Id = "style", Name = "Style", ContestIds = ["contest-1", "contest-2"] }],
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

        string contestId = $"contest-{contestIndex}";
        string optionId = $"contest-{contestIndex}-option-{optionIndex}";
        int count = Int(proof, "t");
        var tally = new EncryptedTally(manifest);
        var aggregate = tally.Contests[contestId].Choices[optionId];
        aggregate.A = P(inputs, "A_hex");
        aggregate.B = P(inputs, "B_hex");

        // The search bound: the oracle's three ballots, of which t select this option.
        Assert.Equal(3, inputs.GetProperty("ballots").GetArrayLength());
        aggregate.MaximumCount = 3;

        // The guardians of U hold the oracle's z_i and use its u_i for this option.
        var guardianVectors = proof.GetProperty("guardians").EnumerateArray().ToList();
        var guardians = guardianVectors.Select(x =>
        {
            var guardian = new TallyGuardian(new GuardianIndex(Int(x, "i")), new GuardianSecretShares
            {
                VoteEncryptionKeyShare = Q(x, "z_i_hex"),
                OtherBallotDataEncryptionKeyShare = 0,
            });
            var u = Q(x, "u_i_hex");
            guardian.NonceSourceForTesting = (c, o) => c == contestIndex && o == optionIndex ? u : ElectionGuardRandom.GetIntegerModQ();
            return guardian;
        }).ToList();
        var participants = Participants(proof);
        Assert.Equal(participants, guardians.Select(x => x.Index).ToList());

        var commitments = guardians.Select(x => x.Commit(tally, record, participants)).ToList();
        var reveals = guardians.Select(x => x.Reveal(commitments)).ToList();
        var responses = guardians.Select(x => x.Respond(reveals)).ToList();

        for (int j = 0; j < guardians.Count; j++)
        {
            var expected = guardianVectors[j];
            Assert.Equal(expected.GetProperty("w_i_hex").GetString(), ToHex(TallyDecryptionHashes.LagrangeCoefficient(guardians[j].Index, participants)));
            Assert.Equal(expected.GetProperty("M_i_hex").GetString(), ToHex(commitments[j].Contests[contestId].Choices[optionId].Mi));
            Assert.Equal(expected.GetProperty("d_i_hex").GetString(), ToHex(commitments[j].Contests[contestId].Choices[optionId].CommitmentHash));
            Assert.Equal(expected.GetProperty("a_i_hex").GetString(), ToHex(reveals[j].Contests[contestId].Choices[optionId].CommitmentA));
            Assert.Equal(expected.GetProperty("b_i_hex").GetString(), ToHex(reveals[j].Contests[contestId].Choices[optionId].CommitmentB));
            Assert.Equal(expected.GetProperty("v_i_hex").GetString(), ToHex(responses[j].Contests[contestId].Choices[optionId].Response));
        }

        var decrypted = new TallyAdmin().Combine(tally, record, commitments, reveals, responses);
        var choice = decrypted.Contests[contestId].Choices[optionId];

        // c is H_q (reduced mod q) and 32 bytes; the vector's expected_hex is the same.
        AssertExpected(vector, choice.Challenge);
        Assert.Equal(proof.GetProperty("c_hex").GetString(), ToHex(choice.Challenge));
        Assert.Equal(proof.GetProperty("v_hex").GetString(), ToHex(choice.Response));
        Assert.Equal(proof.GetProperty("T_hex").GetString(), ToHex(choice.T));
        Assert.Equal(count, choice.VoteCount);
        Assert.Equal(contestIndex, decrypted.Contests[contestId].ContestIndex);
        Assert.Equal(optionIndex, choice.ChoiceIndex);

        // The eq. (90) challenge from the vector's own a, b and M.
        AssertExpected(vector, TallyDecryptionHashes.Challenge(extendedBaseHash, contestIndex, optionIndex,
            P(inputs, "A_hex"), P(inputs, "B_hex"), P(inputs, "a_hex"), P(inputs, "b_hex"), P(inputs, "M_hex")));

        new ElectionGuard.Core.Verify.Tally.TallyDecryptionVerification().Verify(record, tally, decrypted);
    }
}
