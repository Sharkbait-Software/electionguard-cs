using ElectionGuard.Core.Models;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.PreEncryption;
using System.Text.Json;

namespace ElectionGuard.Core.UnitTests.Kat;

/// <summary>
/// Ballot chaining (§3.4.4 eqs. 74-78, Verification 8.F/8.G; §4.1.4 eqs. 116-120, Verification
/// 16.C/16.G/16.H), through the library's own API: the chain close of regular ballots (0x2B, then
/// 0x29), the pre-encrypted initialization (0x42), confirmation codes (0x42) and close (0x44 body form
/// per user decision Q4, then 0x42), and the oracle's two-ballot chains walked by
/// <see cref="ConfirmationCodeVerification.VerifyDevice(DeviceChainRecord, IEnumerable{DeviceChainLink}, EncryptionRecord)"/>
/// and its Verification 16 counterpart.
/// </summary>
public partial class KnownAnswerTests
{
    [Theory]
    [MemberData(nameof(VectorNames), "chain_close_inner")]
    public void ChainCloseInner_Eq78(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var extendedBaseHash = ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!);
        var (deviceHash, last) = CloseInputs(inputs);

        // B-bar_C = 0x00000001 || H(H_E; 0x2B, H_l, B_C,0).
        byte[] closing = ChainingField.Closing(deviceHash, extendedBaseHash, last);

        Assert.Equal(ChainingField.ByteLength, closing.Length);
        Assert.Equal("00000001", ToHex(closing[..4]));
        Assert.Equal(vector.GetProperty("expected_hex").GetString(), ToHex(closing[4..]));
        Assert.Equal(inputs.GetProperty("B_C_bar_hex").GetString(), ToHex(closing));
    }

    [Theory]
    [MemberData(nameof(VectorNames), "chain_close")]
    public void ChainClose_Eq77(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var extendedBaseHash = ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!);

        // H-bar = H(H_E; 0x29, B-bar_C).
        var closingHash = ChainingField.ClosingHash(ChainingField.FromCanonicalBytes(Hex(inputs, "B_C_bar_hex")), extendedBaseHash);

        AssertExpected(vector, closingHash);
    }

    [Theory]
    [MemberData(nameof(VectorNames), "preencrypted_chain_init")]
    public void PreEncryptedChainInitialization_Eq117(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var extendedBaseHash = ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!);
        var deviceHash = new VotingDeviceInformationHash(Hex(inputs, "H_DI_hex"));
        Assert.Equal(inputs.GetProperty("B_C0_hex").GetString(), "00000001" + inputs.GetProperty("H_DI_hex").GetString());

        // H_0 = H(H_E; 0x42, B_C,0), and the first ballot's field is 0x00000001 || H_0.
        AssertExpected(vector, ChainingField.InitialHashForPreEncryptedBallots(deviceHash, extendedBaseHash));
        byte[] chainingField = ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, deviceHash, extendedBaseHash, previousConfirmationCode: null);
        Assert.Equal("00000001" + vector.GetProperty("expected_hex").GetString(), ToHex(chainingField));

        // The regular-ballot H_0 (0x29) of the same device hash is a different value.
        Assert.NotEqual(vector.GetProperty("expected_hex").GetString(), ToHex(ChainingField.InitialHash(deviceHash, extendedBaseHash)));
    }

    [Theory]
    [MemberData(nameof(VectorNames), "preencrypted_confirmation_code")]
    public void PreEncryptedConfirmationCode_Eq116(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var mainChain = Root.GetProperty("main_chain");
        var extendedBaseHash = ExtendedBaseHashFor(mainChain.GetProperty("H_E_hex").GetString()!);
        var selectionEncryptionIdentifierHash = SelectionEncryptionIdentifierHashFor(inputs.GetProperty("H_I_hex").GetString()!);
        var contestHashes = inputs.GetProperty("contest_hashes_hex").EnumerateArray()
            .Select(x => new ContestHash(Convert.FromHexString(x.GetString()!)))
            .ToList();
        var preEncryptedDeviceHash = new VotingDeviceInformationHash(Hex(mainChain, "H_DI_preencrypted_hex"));

        ChainingField chainingField;
        if (inputs.TryGetProperty("H_DI_hex", out var deviceHashHex))
        {
            // 16.E: no chaining, B_C = 0x00000000 || H_DI with the 0x43 H_DI of eq. (119).
            Assert.Equal(ToHex(preEncryptedDeviceHash), deviceHashHex.GetString());
            chainingField = ChainingField.ForPreEncryptedBallots(ChainingMode.None, preEncryptedDeviceHash, extendedBaseHash, previousConfirmationCode: null);
        }
        else
        {
            // 16.F: B_C,j = 0x00000001 || H_{j-1}; for j = 1 the library derives H_0 (eq. 117) itself.
            var previous = inputs.GetProperty("H_prev_hex").GetString()!;
            var chainInit = AllVectors.Single(x => x.GetProperty("family").GetString() == "preencrypted_chain_init");
            chainingField = previous == chainInit.GetProperty("expected_hex").GetString()
                ? ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, preEncryptedDeviceHash, extendedBaseHash, previousConfirmationCode: null)
                : ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, preEncryptedDeviceHash, extendedBaseHash, new ConfirmationCode(Convert.FromHexString(previous)));
        }

        Assert.Equal(inputs.GetProperty("B_C_hex").GetString(), ToHex(chainingField));

        var confirmationCode = ConfirmationCode.ForPreEncryptedBallot(selectionEncryptionIdentifierHash, contestHashes, chainingField);

        AssertExpected(vector, confirmationCode);

        // The regular-ballot form (0x29) over the same inputs is a different value.
        Assert.NotEqual(vector.GetProperty("expected_hex").GetString(), ToHex(new ConfirmationCode(selectionEncryptionIdentifierHash, contestHashes, chainingField)));
    }

    [Theory]
    [MemberData(nameof(VectorNames), "preencrypted_chain_close_inner")]
    public void PreEncryptedChainCloseInner_Eq120_BodyForm(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var extendedBaseHash = ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!);
        var (deviceHash, last) = CloseInputs(inputs);

        // B-bar_C = 0x00000001 || H(H_E; 0x44, H_l, B_C,0), 69-byte body form (user decision Q4).
        byte[] closing = ChainingField.ClosingForPreEncryptedBallots(deviceHash, extendedBaseHash, last);

        Assert.Equal("00000001", ToHex(closing[..4]));
        Assert.Equal(vector.GetProperty("expected_hex").GetString(), ToHex(closing[4..]));
        Assert.Equal(inputs.GetProperty("B_C_bar_hex").GetString(), ToHex(closing));
        Assert.Equal(69, vector.GetProperty("b1_len").GetInt32());

        // Not the §5.5.5 table's 73-byte "LOCK" layout, which the oracle records as the erratum.
        var erratum = vector.GetProperty("lock_form_erratum");
        Assert.False(erratum.GetProperty("expected").GetBoolean());
        Assert.NotEqual(erratum.GetProperty("hash_hex").GetString(), ToHex(closing[4..]));

        // Nor the regular-ballot close (0x2B).
        Assert.NotEqual(ToHex(closing), ToHex(ChainingField.Closing(deviceHash, extendedBaseHash, last)));
    }

    [Theory]
    [MemberData(nameof(VectorNames), "preencrypted_chain_close")]
    public void PreEncryptedChainClose_Eq118(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var extendedBaseHash = ExtendedBaseHashFor(inputs.GetProperty("H_E_hex").GetString()!);

        // H-bar = H(H_E; 0x42, B-bar_C), from the oracle's B-bar_C and from H_l and B_C,0.
        AssertExpected(vector, ChainingField.ClosingHashForPreEncryptedBallots(ChainingField.FromCanonicalBytes(Hex(inputs, "B_C_bar_hex")), extendedBaseHash));

        var (deviceHash, last) = CloseInputs(inputs);
        var closing = ChainingField.ClosingForPreEncryptedBallots(deviceHash, extendedBaseHash, last);
        Assert.Equal(inputs.GetProperty("B_C_bar_hex").GetString(), ToHex(closing));
        AssertExpected(vector, ChainingField.ClosingHashForPreEncryptedBallots(closing, extendedBaseHash));
    }

    /// <summary>
    /// The oracle's chain H_0, H_1, H_2 and its close, as a device record, walked by Verification 8
    /// (regular ballots) or 16 (pre-encrypted): 8.C/16.D, 8.F/16.G, 8.E/16.F for both ballots and
    /// 8.G/16.H all accept the oracle's values; the record loses its last ballot, or swaps the
    /// two, or carries the 73-byte "LOCK" close, and the walk fails where the spec says.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OracleChain_AsADeviceRecord_VerifiesAndDetectsTampering(bool preEncrypted)
    {
        string prefix = preEncrypted ? "preencrypted_" : "";
        var mainChain = Root.GetProperty("main_chain");
        var record = MainChainRecord([], ChainingMode.Simple);
        string device = mainChain.GetProperty("S_device").GetString()!;
        var deviceHash = new VotingDeviceInformationHash(Hex(mainChain, preEncrypted ? "H_DI_preencrypted_hex" : "H_DI_hex"));
        Assert.Equal(deviceHash, preEncrypted
            ? VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, device)
            : new VotingDeviceInformationHash(record.ExtendedBaseHash, device));

        var links = AllVectors
            .Where(x => x.GetProperty("family").GetString() == $"{prefix}confirmation_code" && Inputs(x).TryGetProperty("H_prev_hex", out _))
            .Select((x, i) => new DeviceChainLink($"ballot-{i + 1}", device, new ConfirmationCode(Hex(x, "expected_hex")), ChainingField.FromCanonicalBytes(Hex(Inputs(x), "B_C_hex"))))
            .ToList();
        Assert.Equal(2, links.Count);

        var initial = AllVectors.Single(x => x.GetProperty("family").GetString() == $"{prefix}chain_init");
        var closeInner = AllVectors.Single(x => x.GetProperty("family").GetString() == $"{prefix}chain_close_inner");
        var close = AllVectors.Single(x => x.GetProperty("family").GetString() == $"{prefix}chain_close");
        Assert.Equal(ToHex(links[^1].ConfirmationCode), Inputs(closeInner).GetProperty("H_l_hex").GetString());

        var deviceRecord = new DeviceChainRecord
        {
            DeviceId = device,
            DeviceInformationHash = deviceHash,
            BallotKind = preEncrypted ? DeviceChainBallotKind.PreEncrypted : DeviceChainBallotKind.Encrypted,
            ChainingMode = ChainingMode.Simple,
            ConfirmationCodes = links.Select(x => x.ConfirmationCode).ToList(),
            InitialHash = new ConfirmationCode(Hex(initial, "expected_hex")),
            ClosingChainingField = ChainingField.FromCanonicalBytes(Hex(Inputs(closeInner), "B_C_bar_hex")),
            ClosingHash = new ConfirmationCode(Hex(close, "expected_hex")),
        };

        void Walk(DeviceChainRecord candidate, IEnumerable<DeviceChainLink> ballots)
        {
            if (preEncrypted)
            {
                new PreEncryptedConfirmationCodeVerification().VerifyDevice(candidate, ballots, record);
            }
            else
            {
                new ConfirmationCodeVerification().VerifyDevice(candidate, ballots, record);
            }
        }

        Walk(deviceRecord, links);

        string close8 = preEncrypted ? "16.H" : "8.G";
        string chain8 = preEncrypted ? "16.F" : "8.E";

        // The last ballot dropped from the record: the close no longer covers the list.
        var truncated = deviceRecord with { ConfirmationCodes = [links[0].ConfirmationCode] };
        Assert.Equal(close8, Assert.Throws<VerificationFailedException>(() => Walk(truncated, links.Take(1))).SubSection);

        // The two ballots swapped: the first listed does not chain from H_0.
        var swapped = deviceRecord with { ConfirmationCodes = [links[1].ConfirmationCode, links[0].ConfirmationCode] };
        Assert.Equal(chain8, Assert.Throws<VerificationFailedException>(() => Walk(swapped, links)).SubSection);

        if (preEncrypted)
        {
            // A close computed with the table's 73-byte "LOCK" layout is not the spec's (Q4).
            var lockHash = Convert.FromHexString(Inputs(closeInner).GetProperty("B_C_bar_hex").GetString()![..8]
                + Vector(closeInner.GetProperty("name").GetString()!).GetProperty("lock_form_erratum").GetProperty("hash_hex").GetString());
            var lockForm = deviceRecord with { ClosingChainingField = ChainingField.FromCanonicalBytes(lockHash) };
            Assert.Equal(close8, Assert.Throws<VerificationFailedException>(() => Walk(lockForm, links)).SubSection);
        }
    }

    /// <summary>H_DI (from B_C,0 = 0x00000001 || H_DI) and H_l of a chain close vector.</summary>
    private static (VotingDeviceInformationHash DeviceHash, ConfirmationCode Last) CloseInputs(JsonElement inputs)
    {
        byte[] initialField = Hex(inputs, "B_C0_hex");
        Assert.Equal("00000001", ToHex(initialField[..4]));
        return (new VotingDeviceInformationHash(initialField[4..]), new ConfirmationCode(Hex(inputs, "H_l_hex")));
    }
}
