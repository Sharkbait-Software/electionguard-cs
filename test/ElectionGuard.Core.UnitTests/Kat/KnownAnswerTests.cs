using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Numerics;
using System.Text;
using System.Text.Json;
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
public class KnownAnswerTests
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
        // ContestHash always appends the four supplemental counters (overvote, null vote,
        // undervote, write-in); the vectors hash the options alone. Supplemental fields are
        // redesigned in stage S5 (G3/G8).
        ["contest_hash"] = "G8: ContestHash cannot omit the supplemental counters",
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
            "extended_base_hash",
            "selection_encryption_identifier_hash",
            "encryption_nonce",
            "device_info_hash",
            "preencrypted_device_info_hash",
            "confirmation_code",
            "chain_init",
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
}
