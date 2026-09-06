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

    // Quirk-pinning test: research.md documents that ChainingField's ExtendedBaseHash parameter is
    // accepted but unused by the current implementation (Models/ChainingField.cs lines 9-18 only
    // combine chainingMode + deviceHash/previousConfirmationCode). Per CLAUDE.md, spec-section
    // comments are the source of truth, not code shape -- this test pins current behavior rather
    // than "fixing" it to expect ExtendedBaseHash to matter.
    [Fact]
    public void Constructor_ExtendedBaseHashParameterIsUnused_FieldUnaffectedByItsValue()
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
}
