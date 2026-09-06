using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.TestFixtures;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.KeyGeneration;

namespace ElectionGuard.Core.UnitTests.Verify.KeyGeneration;

public class ElectionPublicKeyVerificationTests
{
    public ElectionPublicKeyVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    [Fact]
    public void Verify_ValidElectionPublicKeys_DoesNotThrow()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var verification = new ElectionPublicKeyVerification();

        var exception = Record.Exception(
            () => verification.Verify(guardianSet.GuardianPublicViews, guardianSet.ElectionPublicKeys));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify_VoteEncryptionKeyMismatch_Throws_SubSection3A()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var voteKeys = guardianSet.GuardianPublicViews.Select(x => x.VoteEncryptionCommitments[0]);
        var otherKeys = guardianSet.GuardianPublicViews.Select(x => x.OtherBallotDataEncryptionCommitments[0]);

        // Fold in an extra factor so the stored VoteEncryptionKey no longer equals the product
        // of the guardians' first vote-encryption commitments.
        var tamperedElectionPublicKeys = new ElectionPublicKeys(
            voteKeys.Append(new IntegerModP(2)),
            otherKeys);

        var verification = new ElectionPublicKeyVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(guardianSet.GuardianPublicViews, tamperedElectionPublicKeys));
        Assert.Equal("3.A", exception.SubSection);
    }

    [Fact]
    public void Verify_OtherBallotDataKeyMismatch_Throws_SubSection3B()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var voteKeys = guardianSet.GuardianPublicViews.Select(x => x.VoteEncryptionCommitments[0]);
        var otherKeys = guardianSet.GuardianPublicViews.Select(x => x.OtherBallotDataEncryptionCommitments[0]);

        // Vote key stays correct so only the 3.B (other-ballot-data) check is exercised.
        var tamperedElectionPublicKeys = new ElectionPublicKeys(
            voteKeys,
            otherKeys.Append(new IntegerModP(2)));

        var verification = new ElectionPublicKeyVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(guardianSet.GuardianPublicViews, tamperedElectionPublicKeys));
        Assert.Equal("3.B", exception.SubSection);
    }
}
