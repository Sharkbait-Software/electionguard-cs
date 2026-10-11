using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;
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
    public void Verify_GuardianSetMissingAGuardian_WithMatchingKeys_Throws_SubSection3A()
    {
        // G25: K and K-hat recomputed consistently over only two of the three guardians. The
        // products agree, but they are not the products over i = 1..n of eqs. (25) and (26).
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var twoGuardians = guardianSet.GuardianPublicViews.Take(2).ToList();
        var keysOverTwo = new ElectionPublicKeys(
            twoGuardians.Select(x => x.VoteEncryptionCommitments[0]),
            twoGuardians.Select(x => x.OtherBallotDataEncryptionCommitments[0]));

        var exception = Assert.Throws<VerificationFailedException>(
            () => new ElectionPublicKeyVerification().Verify(twoGuardians, keysOverTwo));
        Assert.Equal("3.A", exception.SubSection);
    }

    [Fact]
    public void Verify_GuardianSetWithADuplicatedGuardian_Throws_SubSection3A()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var views = guardianSet.GuardianPublicViews;
        var duplicated = new List<GuardianPublicView> { views[0], views[1], views[1] };
        var keys = new ElectionPublicKeys(
            duplicated.Select(x => x.VoteEncryptionCommitments[0]),
            duplicated.Select(x => x.OtherBallotDataEncryptionCommitments[0]));

        var exception = Assert.Throws<VerificationFailedException>(
            () => new ElectionPublicKeyVerification().Verify(duplicated, keys));
        Assert.Equal("3.A", exception.SubSection);
    }

    [Fact]
    public void Verify_EmptyGuardianSet_Throws_SubSection3A_NotArgumentOutOfRange()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();

        var exception = Assert.Throws<VerificationFailedException>(
            () => new ElectionPublicKeyVerification().Verify(new List<GuardianPublicView>(), guardianSet.ElectionPublicKeys));
        Assert.Equal("3.A", exception.SubSection);
    }

    [Fact]
    public void Verify_GuardianSetWithAnIndexAboveN_Throws_SubSection3A()
    {
        // n guardians with matching keys, but numbered 1, 2, n+1: not G_1..G_n.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var views = guardianSet.GuardianPublicViews.OrderBy(x => x.Index.Index).ToList();
        int n = EGParameters.GuardianParameters.N;
        views[n - 1] = WithCommitments(views[n - 1], index: n + 1);

        var exception = Assert.Throws<VerificationFailedException>(
            () => new ElectionPublicKeyVerification().Verify(views, guardianSet.ElectionPublicKeys));
        Assert.Equal("3.A", exception.SubSection);
        Assert.Contains($"{n + 1}", exception.Message);
    }

    [Fact]
    public void Verify_GuardianWithNoVoteEncryptionCommitments_Throws_SubSection3A_NotArgumentOutOfRange()
    {
        // K_i = K_{i,0} is the first vote-encryption commitment; with none there is no K_i to multiply.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var views = guardianSet.GuardianPublicViews.ToList();
        views[1] = WithCommitments(views[1], vote: new List<IntegerModP>());

        var exception = Assert.Throws<VerificationFailedException>(
            () => new ElectionPublicKeyVerification().Verify(views, guardianSet.ElectionPublicKeys));
        Assert.Equal("3.A", exception.SubSection);
        Assert.Contains("vote encryption public key", exception.Message);
    }

    [Fact]
    public void Verify_GuardianWithNoBallotDataCommitments_Throws_SubSection3B_NotArgumentOutOfRange()
    {
        // K-hat_i = K-hat_{i,0}; vote commitments stay intact so the failure is 3.B's.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var views = guardianSet.GuardianPublicViews.ToList();
        views[1] = WithCommitments(views[1], ballotData: new List<IntegerModP>());

        var exception = Assert.Throws<VerificationFailedException>(
            () => new ElectionPublicKeyVerification().Verify(views, guardianSet.ElectionPublicKeys));
        Assert.Equal("3.B", exception.SubSection);
        Assert.Contains("ballot data encryption public key", exception.Message);
    }

    private static GuardianPublicView WithCommitments(
        GuardianPublicView view,
        int? index = null,
        List<IntegerModP>? vote = null,
        List<IntegerModP>? ballotData = null) => new()
    {
        Index = index is null ? view.Index : new GuardianIndex(index.Value),
        VoteEncryptionCommitments = vote ?? view.VoteEncryptionCommitments,
        OtherBallotDataEncryptionCommitments = ballotData ?? view.OtherBallotDataEncryptionCommitments,
        CommunicationPublicKey = view.CommunicationPublicKey,
        VoteEncryptionProof = view.VoteEncryptionProof,
        OtherDataEncryptionProof = view.OtherDataEncryptionProof,
    };

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
