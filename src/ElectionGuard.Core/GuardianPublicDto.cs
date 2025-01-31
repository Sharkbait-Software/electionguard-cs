namespace ElectionGuard.Core;

public class GuardianPublicView
{
    public required GuardianIndex Index { get; init; }
    public required IntegerModP VoteEncryptionPublicKey { get; init; }
    public required IntegerModP OtherDataEncryptionPublicKey { get; init; }
    public required IntegerModP CommunicationPublicKey { get; init; }
    public required Proof VoteEncryptionProof { get; init; }
    public required Proof OtherDataEncryptionProof { get; init; }
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