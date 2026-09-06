using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.Models;

public class ConfirmationCodeTests
{
    public ConfirmationCodeTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static SelectionEncryptionIdentifierHash CreateSelIdHash()
    {
        return new SelectionEncryptionIdentifierHash(new byte[32]);
    }

    private static ContestHash CreateContestHash(byte marker)
    {
        return new ContestHash(new byte[] { marker, 0x02, 0x03 });
    }

    private static ExtendedBaseHash CreateExtendedBaseHash(int voteKeySeed, int otherKeySeed)
    {
        var manifestFile = new ManifestFile { Bytes = new byte[] { 0x01, 0x02 } };
        var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var electionPublicKeys = new ElectionPublicKeys(
            new[] { new IntegerModP(voteKeySeed) },
            new[] { new IntegerModP(otherKeySeed) });
        return new ExtendedBaseHash(electionBaseHash, electionPublicKeys);
    }

    [Fact]
    public void Constructor_SameContestHashes_ProducesSameCode()
    {
        var selIdHash = CreateSelIdHash();
        var contestHashes = new[] { CreateContestHash(0x01), CreateContestHash(0x02) };

        var code1 = new ConfirmationCode(selIdHash, contestHashes, null);
        var code2 = new ConfirmationCode(selIdHash, contestHashes, null);

        Assert.Equal(code1, code2);
    }

    [Fact]
    public void Constructor_DifferentContestHashes_ProducesDifferentCode()
    {
        var selIdHash = CreateSelIdHash();
        var contestHashes1 = new[] { CreateContestHash(0x01) };
        var contestHashes2 = new[] { CreateContestHash(0x99) };

        var code1 = new ConfirmationCode(selIdHash, contestHashes1, null);
        var code2 = new ConfirmationCode(selIdHash, contestHashes2, null);

        Assert.NotEqual(code1, code2);
    }

    [Fact]
    public void Constructor_HandComputed_MatchesDirectEGHashCall()
    {
        var selIdHash = CreateSelIdHash();
        var contestHash1 = CreateContestHash(0x01);
        var contestHash2 = CreateContestHash(0x02);

        var code = new ConfirmationCode(selIdHash, new[] { contestHash1, contestHash2 }, null);
        var expected = EGHash.Hash(selIdHash, new byte[] { 0x29 }, contestHash1, contestHash2);

        Assert.Equal(expected, (byte[])code);
    }

    // Was a quirk-pinning test for a GENUINE BUG (now fixed): ConfirmationCode's constructor used
    // to accept a ChainingField? parameter but never fold it into the hash computation. Per §3.4.2
    // formula (71), HC = H(HI; 0x29, chi_1,...,chi_mB, BC) -- the chaining field BC is a required
    // hash input. ConfirmationCode's constructor now appends chainingField's bytes (when non-null)
    // to the hash input, so two different chaining fields now produce different confirmation codes.
    [Fact]
    public void Constructor_DifferentChainingFields_ProduceDifferentCodes()
    {
        var selIdHash = CreateSelIdHash();
        var contestHashes = new[] { CreateContestHash(0x01) };

        var extendedBaseHash = CreateExtendedBaseHash(3, 5);
        var deviceHash1 = new VotingDeviceInformationHash(extendedBaseHash, "Device A");
        var deviceHash2 = new VotingDeviceInformationHash(extendedBaseHash, "Device B");

        var chainingField1 = new ChainingField(ChainingMode.None, deviceHash1, extendedBaseHash, null);
        var chainingField2 = new ChainingField(ChainingMode.None, deviceHash2, extendedBaseHash, null);

        // Sanity check: the two ChainingFields really are different values.
        Assert.NotEqual(chainingField1, chainingField2);

        var code1 = new ConfirmationCode(selIdHash, contestHashes, chainingField1);
        var code2 = new ConfirmationCode(selIdHash, contestHashes, chainingField2);

        Assert.NotEqual(code1, code2);
    }
}
