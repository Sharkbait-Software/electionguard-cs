using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.KeyGeneration;

public class GuardianKeysTests
{
    public GuardianKeysTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static GuardianKeys BuildGuardianKeys()
    {
        var voteKeyPairs = new List<KeyPair> { KeyPair.GenerateRandom(), KeyPair.GenerateRandom() };
        var otherKeyPairs = new List<KeyPair> { KeyPair.GenerateRandom(), KeyPair.GenerateRandom() };
        var communicationKeyPair = KeyPair.GenerateRandom();

        return new GuardianKeys
        {
            Index = new GuardianIndex(1),
            VoteEncryptionKeyPairs = voteKeyPairs,
            OtherBallotDataEncryptionKeyPairs = otherKeyPairs,
            CommunicationKeyPair = communicationKeyPair,
            VoteEncryptionKeyProof = new SchnorrProof { Challenge = new IntegerModQ(1), Responses = new[] { new IntegerModQ(2), new IntegerModQ(3), new IntegerModQ(4) } },
            OtherBallotDataEncryptionKeyProof = new SchnorrProof { Challenge = new IntegerModQ(5), Responses = new[] { new IntegerModQ(6), new IntegerModQ(7), new IntegerModQ(8) } },
        };
    }

    [Fact]
    public void ToPublicView_MapsVoteEncryptionCommitments()
    {
        var keys = BuildGuardianKeys();

        var publicView = keys.ToPublicView();

        Assert.Equal(keys.VoteEncryptionKeyPairs.Select(k => k.PublicKey), publicView.VoteEncryptionCommitments);
    }

    [Fact]
    public void ToPublicView_MapsOtherBallotDataEncryptionCommitments()
    {
        var keys = BuildGuardianKeys();

        var publicView = keys.ToPublicView();

        Assert.Equal(keys.OtherBallotDataEncryptionKeyPairs.Select(k => k.PublicKey), publicView.OtherBallotDataEncryptionCommitments);
    }

    [Fact]
    public void ToPublicView_PreservesGuardianIndexAndProofs()
    {
        var keys = BuildGuardianKeys();

        var publicView = keys.ToPublicView();

        Assert.Equal(keys.Index, publicView.Index);
        Assert.Equal(keys.CommunicationKeyPair.PublicKey, publicView.CommunicationPublicKey);
        // ToPublicView assigns the proof references directly rather than defensively copying them.
        Assert.Same(keys.VoteEncryptionKeyProof, publicView.VoteEncryptionProof);
        Assert.Same(keys.OtherBallotDataEncryptionKeyProof, publicView.OtherDataEncryptionProof);
    }
}
