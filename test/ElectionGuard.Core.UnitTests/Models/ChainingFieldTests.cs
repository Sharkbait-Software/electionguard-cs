using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.Models;

public class ChainingFieldTests
{
    public ChainingFieldTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static ExtendedBaseHash CreateExtendedBaseHash(int voteKeySeed = 3, int otherKeySeed = 5)
    {
        var manifestFile = new ManifestFile { Bytes = new byte[] { 0x01, 0x02 } };
        var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var electionPublicKeys = new ElectionPublicKeys(
            new[] { new IntegerModP(voteKeySeed) },
            new[] { new IntegerModP(otherKeySeed) });
        return new ExtendedBaseHash(electionBaseHash, electionPublicKeys);
    }

    [Fact]
    public void Constructor_NullPreviousConfirmationCode_ConcatenatesModeAndDeviceHash()
    {
        var extendedBaseHash = CreateExtendedBaseHash();
        var deviceHash = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");

        var field = new ChainingField(ChainingMode.None, deviceHash, extendedBaseHash, null);

        var expected = ByteArrayExtensions.Concat(((int)ChainingMode.None).ToByteArray(), deviceHash);

        Assert.Equal(expected, (byte[])field);
    }

    [Fact]
    public void Constructor_NonNullPreviousConfirmationCode_ConcatenatesModeAndPreviousCode()
    {
        var extendedBaseHash = CreateExtendedBaseHash();
        var deviceHash = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");
        var previousConfirmationCode = new ConfirmationCode(new byte[] { 0xAA, 0xBB, 0xCC });

        var field = new ChainingField(ChainingMode.Simple, deviceHash, extendedBaseHash, previousConfirmationCode);

        var expected = ByteArrayExtensions.Concat(((int)ChainingMode.Simple).ToByteArray(), previousConfirmationCode);

        Assert.Equal(expected, (byte[])field);
    }

    // ExtendedBaseHash is genuinely irrelevant to this SPECIFIC scenario -- simple chaining with a
    // real (non-null) previous confirmation code -- per §3.4.4 formula (76): BC,j = 0x00000001 ||
    // Hj-1 only depends on the mode identifier and the previous code, not HE. (ExtendedBaseHash
    // DOES matter for the different "first ballot on device" scenario -- see
    // Constructor_NullPreviousConfirmationCode_SimpleChaining_ExtendedBaseHashAffectsFieldViaH0Initialization
    // below -- this was the actual bug fixed in Models/ChainingField.cs.)
    [Fact]
    public void Constructor_NonNullPreviousConfirmationCode_ExtendedBaseHashDoesNotAffectField()
    {
        var extendedBaseHash1 = CreateExtendedBaseHash(3, 5);
        var extendedBaseHash2 = CreateExtendedBaseHash(7, 11);
        Assert.NotEqual((byte[])extendedBaseHash1, (byte[])extendedBaseHash2);

        var deviceHash = new VotingDeviceInformationHash(extendedBaseHash1, "Device 1");
        var previousConfirmationCode = new ConfirmationCode(new byte[] { 0xAA, 0xBB });

        var field1 = new ChainingField(ChainingMode.Simple, deviceHash, extendedBaseHash1, previousConfirmationCode);
        var field2 = new ChainingField(ChainingMode.Simple, deviceHash, extendedBaseHash2, previousConfirmationCode);

        Assert.Equal(field1, field2);
    }

    // Was GENUINE BUG #7 (now fixed): ChainingField's ExtendedBaseHash parameter used to be
    // accepted but never used at all. For the "first ballot on a device" case (simple chaining,
    // previousConfirmationCode == null), §3.4.4 formulas (74)/(75) require computing an
    // initialization code H0 = H(HE; 0x29, BC,0) where BC,0 = 0x00000001 || HDI -- so
    // ExtendedBaseHash (HE) is the HMAC key for that computation and genuinely affects the
    // resulting chaining field.
    [Fact]
    public void Constructor_NullPreviousConfirmationCode_SimpleChaining_ExtendedBaseHashAffectsFieldViaH0Initialization()
    {
        var extendedBaseHash1 = CreateExtendedBaseHash(3, 5);
        var extendedBaseHash2 = CreateExtendedBaseHash(7, 11);
        Assert.NotEqual((byte[])extendedBaseHash1, (byte[])extendedBaseHash2);

        var deviceHash = new VotingDeviceInformationHash(extendedBaseHash1, "Device 1");

        var field1 = new ChainingField(ChainingMode.Simple, deviceHash, extendedBaseHash1, previousConfirmationCode: null);
        var field2 = new ChainingField(ChainingMode.Simple, deviceHash, extendedBaseHash2, previousConfirmationCode: null);

        Assert.NotEqual(field1, field2);
    }

    [Fact]
    public void Constructor_NullPreviousConfirmationCode_SimpleChaining_MatchesHandComputedH0Formula()
    {
        // Hand-verifies §3.4.4 formulas (74)/(75) exactly: BC,0 = 0x00000001 || HDI,
        // H0 = H(HE; 0x29, BC,0), and the resulting chaining field is 0x00000001 || H0.
        var extendedBaseHash = CreateExtendedBaseHash();
        var deviceHash = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");

        var field = new ChainingField(ChainingMode.Simple, deviceHash, extendedBaseHash, previousConfirmationCode: null);

        byte[] modeBytes = ((int)ChainingMode.Simple).ToByteArray();
        byte[] bc0 = ByteArrayExtensions.Concat(modeBytes, deviceHash);
        byte[] h0 = EGHash.Hash(extendedBaseHash, new byte[] { 0x29 }, bc0);
        byte[] expected = ByteArrayExtensions.Concat(modeBytes, h0);

        Assert.Equal(expected, (byte[])field);
    }
}
