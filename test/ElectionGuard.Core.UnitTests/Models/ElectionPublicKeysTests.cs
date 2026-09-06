using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.Models;

public class ElectionPublicKeysTests
{
    public ElectionPublicKeysTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    [Fact]
    public void Constructor_VoteEncryptionKey_IsProductOfInputKeys()
    {
        var key1 = new IntegerModP(3);
        var key2 = new IntegerModP(5);
        var key3 = new IntegerModP(7);

        var electionPublicKeys = new ElectionPublicKeys(new[] { key1, key2, key3 }, new[] { new IntegerModP(2) });

        var expected = key1 * key2 * key3;
        Assert.Equal(expected, electionPublicKeys.VoteEncryptionKey);
    }

    [Fact]
    public void Constructor_OtherBallotDataEncryptionKey_IsProductOfInputKeys()
    {
        var key1 = new IntegerModP(11);
        var key2 = new IntegerModP(13);

        var electionPublicKeys = new ElectionPublicKeys(new[] { new IntegerModP(2) }, new[] { key1, key2 });

        var expected = key1 * key2;
        Assert.Equal(expected, electionPublicKeys.OtherBallotDataEncryptionKey);
    }

    [Fact]
    public void Constructor_SingleKeyInput_EqualsThatKey()
    {
        var key = new IntegerModP(17);

        var electionPublicKeys = new ElectionPublicKeys(new[] { key }, new[] { key });

        Assert.Equal(key, electionPublicKeys.VoteEncryptionKey);
        Assert.Equal(key, electionPublicKeys.OtherBallotDataEncryptionKey);
    }
}
