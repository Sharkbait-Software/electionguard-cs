using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.TestFixtures;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.KeyGeneration;

namespace ElectionGuard.Core.UnitTests.Verify.KeyGeneration;

public class ExtendedBaseHashVerificationTests
{
    public ExtendedBaseHashVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static (ElectionBaseHash ElectionBaseHash, ExtendedBaseHash ExtendedBaseHash, ElectionFixtureBuilder.GuardianSetResult GuardianSet) BuildValidHashes()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (_, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();

        var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, guardianSet.ElectionPublicKeys);

        return (electionBaseHash, extendedBaseHash, guardianSet);
    }

    [Fact]
    public void Verify_ValidExtendedBaseHash_DoesNotThrow()
    {
        var (electionBaseHash, extendedBaseHash, guardianSet) = BuildValidHashes();
        var verification = new ExtendedBaseHashVerification();

        var exception = Record.Exception(
            () => verification.Verify(extendedBaseHash, electionBaseHash, guardianSet.ElectionPublicKeys));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify_TamperedHashBytes_Throws_SubSection4A()
    {
        var (electionBaseHash, extendedBaseHash, guardianSet) = BuildValidHashes();

        // Pass a different ElectionPublicKeys than the one actually used to derive
        // extendedBaseHash -- the recomputed hash will disagree with the real (actual) bytes.
        var voteKeys = new List<IntegerModP> { guardianSet.ElectionPublicKeys.VoteEncryptionKey, new IntegerModP(2) };
        var otherKeys = new List<IntegerModP> { guardianSet.ElectionPublicKeys.OtherBallotDataEncryptionKey };
        var mismatchedElectionPublicKeys = new ElectionPublicKeys(voteKeys, otherKeys);

        var verification = new ExtendedBaseHashVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(extendedBaseHash, electionBaseHash, mismatchedElectionPublicKeys));
        Assert.Equal("4.A", exception.SubSection);
    }
}
