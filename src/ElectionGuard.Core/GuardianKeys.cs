namespace ElectionGuard.Core;

public class GuardianKeys
{
    public required GuardianIndex Index { get; init; }
    public required List<KeyPair> VoteEncryptionKeyPairs { get; init; }
    public required List<KeyPair> OtherBallotDataEncryptionKeyPairs { get; init; }
    public required KeyPair CommunicationKeyPair { get; init; }
    public required Proof VoteEncryptionKeyProof { get; init; }
    public required Proof OtherBallotDataEncryptionKeyProof { get; init; }

    public GuardianPublicView ToPublicView()
    {
        return new GuardianPublicView
        {
            Index = Index,
            VoteEncryptionPublicKey = VoteEncryptionKeyPairs[0].PublicKey,
            OtherDataEncryptionPublicKey = OtherBallotDataEncryptionKeyPairs[0].PublicKey,
            CommunicationPublicKey = CommunicationKeyPair.PublicKey,
            VoteEncryptionProof = VoteEncryptionKeyProof,
            OtherDataEncryptionProof = OtherBallotDataEncryptionKeyProof,
        };
    }
}
