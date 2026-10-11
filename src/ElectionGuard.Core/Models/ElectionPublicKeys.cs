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

    private ElectionPublicKeys()
    {
    }

    /// <summary>
    /// The keys K and K-hat as a record states them, kept as read rather than recomputed from the
    /// guardians' commitments: Verification 3 checks them against those (eqs. 23, 24).
    /// </summary>
    public static ElectionPublicKeys FromKeys(IntegerModP voteEncryptionKey, IntegerModP otherBallotDataEncryptionKey)
    {
        return new ElectionPublicKeys
        {
            VoteEncryptionKey = voteEncryptionKey,
            OtherBallotDataEncryptionKey = otherBallotDataEncryptionKey,
        };
    }

    public required IntegerModP VoteEncryptionKey { get; init; }
    public required IntegerModP OtherBallotDataEncryptionKey { get; init; }
}