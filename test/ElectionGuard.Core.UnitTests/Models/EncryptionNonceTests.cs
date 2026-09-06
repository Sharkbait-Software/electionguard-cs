using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.Models;

public class EncryptionNonceTests
{
    public EncryptionNonceTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static SelectionEncryptionIdentifierHash CreateSelIdHash()
    {
        return new SelectionEncryptionIdentifierHash(new byte[32]);
    }

    [Fact]
    public void Constructor_WithoutChoiceIndex_HandComputed_MatchesDirectHashModQCall()
    {
        var selIdHash = CreateSelIdHash();
        var ballotNonce = new BallotNonce(new byte[] { 0x01, 0x02, 0x03 });
        int contestIndex = 4;

        var nonce = new EncryptionNonce(selIdHash, ballotNonce, contestIndex);
        var expected = EGHash.HashModQ(selIdHash, new byte[] { 0x21 }, contestIndex.ToByteArray(), ballotNonce);

        Assert.Equal(expected, (IntegerModQ)nonce);
    }

    [Fact]
    public void Constructor_WithChoiceIndex_HandComputed_MatchesDirectHashModQCall()
    {
        var selIdHash = CreateSelIdHash();
        var ballotNonce = new BallotNonce(new byte[] { 0x01, 0x02, 0x03 });
        int contestIndex = 4;
        int choiceIndex = 2;

        var nonce = new EncryptionNonce(selIdHash, ballotNonce, contestIndex, choiceIndex);
        var expected = EGHash.HashModQ(
            selIdHash,
            new byte[] { 0x21 },
            contestIndex.ToByteArray(),
            choiceIndex.ToByteArray(),
            ballotNonce);

        Assert.Equal(expected, (IntegerModQ)nonce);
    }

    [Fact]
    public void Constructor_DifferentContestIndex_ProducesDifferentNonce()
    {
        var selIdHash = CreateSelIdHash();
        var ballotNonce = new BallotNonce(new byte[] { 0x01, 0x02, 0x03 });

        var nonce1 = new EncryptionNonce(selIdHash, ballotNonce, 1);
        var nonce2 = new EncryptionNonce(selIdHash, ballotNonce, 2);

        Assert.NotEqual((IntegerModQ)nonce1, (IntegerModQ)nonce2);
    }

    [Fact]
    public void Constructor_DifferentChoiceIndex_ProducesDifferentNonce()
    {
        var selIdHash = CreateSelIdHash();
        var ballotNonce = new BallotNonce(new byte[] { 0x01, 0x02, 0x03 });

        var nonce1 = new EncryptionNonce(selIdHash, ballotNonce, 1, 1);
        var nonce2 = new EncryptionNonce(selIdHash, ballotNonce, 1, 2);

        Assert.NotEqual((IntegerModQ)nonce1, (IntegerModQ)nonce2);
    }
}
