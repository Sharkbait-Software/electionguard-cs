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

    // G3: the j-less form H_q(H_I; 0x21, i, xi_B), which the four supplemental counters shared, is
    // gone; eq. (33) always hashes an option index. Its hand-computed test went with it, replaced by
    // this check that no constructor without j remains.
    [Fact]
    public void Constructor_AlwaysTakesAnOptionIndex()
    {
        var constructors = typeof(EncryptionNonce).GetConstructors();

        Assert.All(constructors, constructor =>
        {
            var parameters = constructor.GetParameters();
            Assert.Equal(4, parameters.Length);
            Assert.Equal(typeof(int), parameters[3].ParameterType);
            Assert.False(parameters[3].IsOptional);
        });
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

        var nonce1 = new EncryptionNonce(selIdHash, ballotNonce, 1, 1);
        var nonce2 = new EncryptionNonce(selIdHash, ballotNonce, 2, 1);

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
