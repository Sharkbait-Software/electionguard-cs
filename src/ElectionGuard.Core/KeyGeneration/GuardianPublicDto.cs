using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.KeyGeneration;

public class GuardianPublicView
{
    public required GuardianIndex Index { get; init; }
    public required List<IntegerModP> VoteEncryptionCommitments { get; init; }
    public required List<IntegerModP> OtherBallotDataEncryptionCommitments { get; init; }
    public required IntegerModP CommunicationPublicKey { get; init; }
    public required SchnorrProof VoteEncryptionProof { get; init; }
    public required SchnorrProof OtherDataEncryptionProof { get; init; }
}

public class GuardianEncryptedShare
{
    public required GuardianIndex SourceIndex { get; init; }
    public required GuardianIndex DestinationIndex { get; init; }
    public required byte[] C0 { get; init; }
    public required byte[] C1 { get; init; }

    // CBar
    public required IntegerModQ Challenge { get; init; }

    // VBar
    public required IntegerModQ Response { get; init; }
}

public class GuardianSecretShares
{
    public required IntegerModQ VoteEncryptionKeyShare { get; init; }
    public required IntegerModQ OtherBallotDataEncryptionKeyShare { get; init; }
}