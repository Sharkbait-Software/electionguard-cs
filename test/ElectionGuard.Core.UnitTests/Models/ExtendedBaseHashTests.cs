using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.Models;

public class ExtendedBaseHashTests
{
    public ExtendedBaseHashTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static ElectionBaseHash CreateElectionBaseHash()
    {
        var manifestFile = new ManifestFile { Bytes = new byte[] { 0x0A, 0x0B } };
        return new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
    }

    private static ElectionPublicKeys CreateElectionPublicKeys(int voteKeySeed = 7, int otherKeySeed = 11)
    {
        return new ElectionPublicKeys(
            new[] { new IntegerModP(voteKeySeed) },
            new[] { new IntegerModP(otherKeySeed) });
    }

    [Fact]
    public void Constructor_SameInputs_ProducesSameHash()
    {
        var electionBaseHash = CreateElectionBaseHash();
        var electionPublicKeys = CreateElectionPublicKeys();

        var hash1 = new ExtendedBaseHash(electionBaseHash, electionPublicKeys);
        var hash2 = new ExtendedBaseHash(electionBaseHash, electionPublicKeys);

        Assert.Equal((byte[])hash1, (byte[])hash2);
    }

    [Fact]
    public void Constructor_DifferentElectionPublicKeys_ProducesDifferentHash()
    {
        var electionBaseHash = CreateElectionBaseHash();
        var keys1 = CreateElectionPublicKeys(7, 11);
        var keys2 = CreateElectionPublicKeys(8, 11);

        var hash1 = new ExtendedBaseHash(electionBaseHash, keys1);
        var hash2 = new ExtendedBaseHash(electionBaseHash, keys2);

        Assert.NotEqual((byte[])hash1, (byte[])hash2);
    }

    [Fact]
    public void Constructor_HandComputed_MatchesDirectEGHashCall()
    {
        var electionBaseHash = CreateElectionBaseHash();
        var electionPublicKeys = CreateElectionPublicKeys();

        var hash = new ExtendedBaseHash(electionBaseHash, electionPublicKeys);
        var expected = EGHash.Hash(
            electionBaseHash,
            new byte[] { 0x14 },
            electionPublicKeys.VoteEncryptionKey,
            electionPublicKeys.OtherBallotDataEncryptionKey);

        Assert.Equal(expected, (byte[])hash);
    }
}
