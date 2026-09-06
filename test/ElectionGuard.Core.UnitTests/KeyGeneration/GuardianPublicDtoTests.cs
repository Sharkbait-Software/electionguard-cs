using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.KeyGeneration;

public class GuardianPublicDtoTests
{
    public GuardianPublicDtoTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    [Fact]
    public void GuardianPublicView_PropertiesRoundTrip()
    {
        var index = new GuardianIndex(1);
        var voteCommitments = new List<IntegerModP> { new IntegerModP(3), new IntegerModP(5) };
        var otherCommitments = new List<IntegerModP> { new IntegerModP(7), new IntegerModP(11) };
        var communicationKey = new IntegerModP(13);
        var voteProof = new SchnorrProof { Challenge = new IntegerModQ(1), Responses = new[] { new IntegerModQ(2) } };
        var otherProof = new SchnorrProof { Challenge = new IntegerModQ(3), Responses = new[] { new IntegerModQ(4) } };

        var view = new GuardianPublicView
        {
            Index = index,
            VoteEncryptionCommitments = voteCommitments,
            OtherBallotDataEncryptionCommitments = otherCommitments,
            CommunicationPublicKey = communicationKey,
            VoteEncryptionProof = voteProof,
            OtherDataEncryptionProof = otherProof,
        };

        Assert.Equal(index, view.Index);
        Assert.Same(voteCommitments, view.VoteEncryptionCommitments);
        Assert.Same(otherCommitments, view.OtherBallotDataEncryptionCommitments);
        Assert.Equal(communicationKey, view.CommunicationPublicKey);
        Assert.Equal(voteProof, view.VoteEncryptionProof);
        Assert.Equal(otherProof, view.OtherDataEncryptionProof);
    }

    [Fact]
    public void GuardianEncryptedShare_PropertiesRoundTrip()
    {
        var source = new GuardianIndex(1);
        var destination = new GuardianIndex(2);
        var c0 = new byte[] { 1, 2, 3 };
        var c1 = new byte[] { 4, 5, 6 };
        var challenge = new IntegerModQ(7);
        var response = new IntegerModQ(8);

        var share = new GuardianEncryptedShare
        {
            SourceIndex = source,
            DestinationIndex = destination,
            C0 = c0,
            C1 = c1,
            Challenge = challenge,
            Response = response,
        };

        Assert.Equal(source, share.SourceIndex);
        Assert.Equal(destination, share.DestinationIndex);
        Assert.Same(c0, share.C0);
        Assert.Same(c1, share.C1);
        Assert.Equal(challenge, share.Challenge);
        Assert.Equal(response, share.Response);
    }

    [Fact]
    public void GuardianSecretShares_PropertiesRoundTrip()
    {
        var voteShare = new IntegerModQ(9);
        var otherShare = new IntegerModQ(10);

        var secretShares = new GuardianSecretShares
        {
            VoteEncryptionKeyShare = voteShare,
            OtherBallotDataEncryptionKeyShare = otherShare,
        };

        Assert.Equal(voteShare, secretShares.VoteEncryptionKeyShare);
        Assert.Equal(otherShare, secretShares.OtherBallotDataEncryptionKeyShare);
    }
}
