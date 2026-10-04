using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Text;

namespace ElectionGuard.Core.UnitTests.Models;

/// <summary>
/// The §4.1 / §5.5.5 hash computations for pre-encrypted ballots, each checked against a direct
/// EGHash call over the byte layout listed in §5.5.5.
/// </summary>
public class PreEncryptionHashTests
{
    public PreEncryptionHashTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static SelectionEncryptionIdentifierHash CreateSelIdHash(byte marker = 0x00)
    {
        var bytes = new byte[32];
        bytes[0] = marker;
        return new SelectionEncryptionIdentifierHash(bytes);
    }

    private static ExtendedBaseHash CreateExtendedBaseHash()
    {
        var manifestFile = new ManifestFile { Bytes = new byte[] { 0x01, 0x02 } };
        var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var electionPublicKeys = new ElectionPublicKeys(
            new[] { new IntegerModP(3) },
            new[] { new IntegerModP(5) });
        return new ExtendedBaseHash(electionBaseHash, electionPublicKeys);
    }

    private static SelectionHash HashWithLeadingBytes(params byte[] leading)
    {
        var bytes = new byte[32];
        leading.CopyTo(bytes, 0);
        return new SelectionHash(bytes);
    }

    private static EncryptedValue Ciphertext(int alpha, int beta)
    {
        return new EncryptedValue { Alpha = new IntegerModP(alpha), Beta = new IntegerModP(beta) };
    }

    // eq. 121
    [Fact]
    public void PreEncryptionNonce_MatchesDirectHashModQCall()
    {
        var hi = CreateSelIdHash();
        var ballotNonce = new BallotNonce(Enumerable.Range(1, 32).Select(b => (byte)b).ToArray());

        var nonce = new PreEncryptionNonce(hi, ballotNonce, contestIndex: 4, selectionIndex: 2, positionIndex: 3);

        var expected = EGHash.HashModQ(hi, [0x45], 4.ToByteArray(), 2.ToByteArray(), 3.ToByteArray(), ballotNonce);
        Assert.Equal(expected, (IntegerModQ)nonce);
    }

    [Fact]
    public void PreEncryptionNonce_EachIndexChangesTheNonce()
    {
        var hi = CreateSelIdHash();
        var ballotNonce = new BallotNonce(new byte[32]);

        var baseline = (IntegerModQ)new PreEncryptionNonce(hi, ballotNonce, 1, 1, 1);

        Assert.NotEqual(baseline, (IntegerModQ)new PreEncryptionNonce(hi, ballotNonce, 2, 1, 1));
        Assert.NotEqual(baseline, (IntegerModQ)new PreEncryptionNonce(hi, ballotNonce, 1, 2, 1));
        Assert.NotEqual(baseline, (IntegerModQ)new PreEncryptionNonce(hi, ballotNonce, 1, 1, 2));
    }

    // eq. 113 / 114
    [Fact]
    public void SelectionHash_FromVector_MatchesDirectHashCall()
    {
        var hi = CreateSelIdHash();
        var vector = new[] { Ciphertext(2, 3), Ciphertext(5, 7), Ciphertext(11, 13) };

        var psi = new SelectionHash(hi, vector);

        var expected = EGHash.Hash(hi, [0x40],
            new IntegerModP(2), new IntegerModP(3),
            new IntegerModP(5), new IntegerModP(7),
            new IntegerModP(11), new IntegerModP(13));
        Assert.Equal(expected, (byte[])psi);
    }

    [Fact]
    public void SelectionHash_FromVector_DependsOnSelectionEncryptionIdentifierHash()
    {
        var vector = new[] { Ciphertext(2, 3) };

        Assert.NotEqual(new SelectionHash(CreateSelIdHash(0x01), vector), new SelectionHash(CreateSelIdHash(0x02), vector));
    }

    [Fact]
    public void SelectionHash_CompareTo_OrdersAsBigEndianUnsignedIntegers()
    {
        var small = HashWithLeadingBytes(0x00, 0xFF);
        var large = HashWithLeadingBytes(0x01, 0x00);

        Assert.True(small.CompareTo(large) < 0);
        Assert.True(large.CompareTo(small) > 0);
        Assert.Equal(0, small.CompareTo(HashWithLeadingBytes(0x00, 0xFF)));
    }

    [Fact]
    public void SelectionHash_CompareTo_TreatsBytesAsUnsigned()
    {
        // 0x80 would sort below 0x7F if bytes were compared as signed values.
        Assert.True(HashWithLeadingBytes(0x7F).CompareTo(HashWithLeadingBytes(0x80)) < 0);
    }

    // eq. 115
    [Fact]
    public void ContestHash_ForPreEncryptedContest_HashesSelectionHashesInSortedOrder()
    {
        var hi = CreateSelIdHash();
        var low = HashWithLeadingBytes(0x01);
        var mid = HashWithLeadingBytes(0x02);
        var high = HashWithLeadingBytes(0x03);

        var chi = ContestHash.ForPreEncryptedContest(hi, 7, [high, low, mid]);

        var expected = EGHash.Hash(hi, [0x41], 7.ToByteArray(), low, mid, high);
        Assert.Equal(expected, (byte[])chi);
    }

    [Fact]
    public void ContestHash_ForPreEncryptedContest_IsIndependentOfInputOrder()
    {
        var hi = CreateSelIdHash();
        var a = HashWithLeadingBytes(0x10);
        var b = HashWithLeadingBytes(0x20);
        var c = HashWithLeadingBytes(0x30);

        Assert.Equal(
            ContestHash.ForPreEncryptedContest(hi, 1, [a, b, c]),
            ContestHash.ForPreEncryptedContest(hi, 1, [c, a, b]));
    }

    // eq. 116
    [Fact]
    public void ConfirmationCode_ForPreEncryptedBallot_MatchesDirectHashCall()
    {
        var hi = CreateSelIdHash();
        var extendedBaseHash = CreateExtendedBaseHash();
        var chi1 = new ContestHash(Enumerable.Repeat((byte)0x11, 32).ToArray());
        var chi2 = new ContestHash(Enumerable.Repeat((byte)0x22, 32).ToArray());
        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(extendedBaseHash, "Device 1");
        var chainingField = ChainingField.ForPreEncryptedBallots(ChainingMode.None, deviceHash, extendedBaseHash, null);

        var code = ConfirmationCode.ForPreEncryptedBallot(hi, [chi1, chi2], chainingField);

        var expected = EGHash.Hash(hi, [0x42], chi1, chi2, chainingField);
        Assert.Equal(expected, (byte[])code);
    }

    [Fact]
    public void ConfirmationCode_ForPreEncryptedBallot_DiffersFromRegularConfirmationCode()
    {
        var hi = CreateSelIdHash();
        var extendedBaseHash = CreateExtendedBaseHash();
        var chi = new ContestHash(Enumerable.Repeat((byte)0x11, 32).ToArray());
        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(extendedBaseHash, "Device 1");
        var chainingField = ChainingField.ForPreEncryptedBallots(ChainingMode.None, deviceHash, extendedBaseHash, null);

        Assert.NotEqual(
            new ConfirmationCode(hi, [chi], chainingField),
            ConfirmationCode.ForPreEncryptedBallot(hi, [chi], chainingField));
    }

    // eq. 119
    [Fact]
    public void VotingDeviceInformationHash_ForPreEncryptedBallots_MatchesDirectHashCall()
    {
        var extendedBaseHash = CreateExtendedBaseHash();
        var deviceBytes = Encoding.UTF8.GetBytes("Device 1");

        var hdi = VotingDeviceInformationHash.ForPreEncryptedBallots(extendedBaseHash, "Device 1");

        var expected = EGHash.Hash(extendedBaseHash, [0x43], deviceBytes.Length.ToByteArray(), deviceBytes);
        Assert.Equal(expected, (byte[])hdi);
    }

    // §4.1.4, 16.E
    [Fact]
    public void ChainingField_ForPreEncryptedBallots_NoChaining_IsZeroModeAndDeviceHash()
    {
        var extendedBaseHash = CreateExtendedBaseHash();
        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(extendedBaseHash, "Device 1");

        var field = ChainingField.ForPreEncryptedBallots(ChainingMode.None, deviceHash, extendedBaseHash, null);

        Assert.Equal(ByteArrayExtensions.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }, deviceHash), (byte[])field);
    }

    // eq. 117, 16.G
    [Fact]
    public void ChainingField_ForPreEncryptedBallots_SimpleChainingFirstBallot_UsesH0WithSeparator0x42()
    {
        var extendedBaseHash = CreateExtendedBaseHash();
        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(extendedBaseHash, "Device 1");

        var field = ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, deviceHash, extendedBaseHash, null);

        byte[] mode = { 0x00, 0x00, 0x00, 0x01 };
        var h0 = EGHash.Hash(extendedBaseHash, [0x42], ByteArrayExtensions.Concat(mode, deviceHash));
        Assert.Equal(ByteArrayExtensions.Concat(mode, h0), (byte[])field);
    }

    // 16.F
    [Fact]
    public void ChainingField_ForPreEncryptedBallots_SimpleChainingLaterBallot_UsesPreviousConfirmationCode()
    {
        var extendedBaseHash = CreateExtendedBaseHash();
        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(extendedBaseHash, "Device 1");
        var previous = new ConfirmationCode(Enumerable.Repeat((byte)0x33, 32).ToArray());

        var field = ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, deviceHash, extendedBaseHash, previous);

        Assert.Equal(ByteArrayExtensions.Concat(new byte[] { 0x00, 0x00, 0x00, 0x01 }, previous), (byte[])field);
    }
}
