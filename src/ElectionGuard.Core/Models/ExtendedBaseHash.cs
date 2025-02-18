using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.Models;

public class ExtendedBaseHash : HashValue
{
    public ExtendedBaseHash(ElectionBaseHash electionBaseHash, ElectionPublicKeys electionPublicKeys)
    {
        Bytes = EGHash.Hash(electionBaseHash,
            [0x14],
            electionPublicKeys.VoteEncryptionKey,
            electionPublicKeys.OtherBallotDataEncryptionKey);
    }

    protected override byte[] Bytes { get; }
}

public class SelectionEncryptionIdentifierHash : HashValue
{
    public SelectionEncryptionIdentifierHash(ExtendedBaseHash extendedBaseHash, SelectionEncryptionIdentifier identifier)
    {
        Bytes = EGHash.Hash(extendedBaseHash,
            [0x20],
            identifier);
    }

    protected override byte[] Bytes { get; }
}