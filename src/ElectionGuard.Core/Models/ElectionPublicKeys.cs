using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using System.Diagnostics.CodeAnalysis;

namespace ElectionGuard.Core.Models;

public class ElectionPublicKeys
{
    [SetsRequiredMembers]
    public ElectionPublicKeys(IEnumerable<IntegerModP> voteEncryptionPublicKeys, IEnumerable<IntegerModP> otherBallotDataPublicKeys)
    {
        VoteEncryptionKey = voteEncryptionPublicKeys.Product();
        OtherBallotDataEncryptionKey = otherBallotDataPublicKeys.Product();
    }

    public required IntegerModP VoteEncryptionKey { get; init; }
    public required IntegerModP OtherBallotDataEncryptionKey { get; init; }
}