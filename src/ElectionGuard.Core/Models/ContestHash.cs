using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

public struct ContestHash
{
    public ContestHash(
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, 
        int contestIndex,
        IEnumerable<EncryptedSelection> encryptedChoices,
        EncryptedValueWithProofs overVoteCount,
        EncryptedValueWithProofs nullVoteCount,
        EncryptedValueWithProofs underVoteCount,
        EncryptedValueWithProofs writeInVoteCount,
        EncryptedData? encryptedContestData)
    {
        List<byte[]> contestBytesToHash = [
            [0x28],
            contestIndex.ToByteArray()];
        foreach (var encryptedSelection in encryptedChoices)
        {
            contestBytesToHash.Add(encryptedSelection.Value.Alpha);
            contestBytesToHash.Add(encryptedSelection.Value.Beta);
        }
        contestBytesToHash.Add(overVoteCount.Value.Alpha);
        contestBytesToHash.Add(overVoteCount.Value.Beta);
        contestBytesToHash.Add(nullVoteCount.Value.Alpha);
        contestBytesToHash.Add(nullVoteCount.Value.Beta);
        contestBytesToHash.Add(underVoteCount.Value.Alpha);
        contestBytesToHash.Add(underVoteCount.Value.Beta);
        contestBytesToHash.Add(writeInVoteCount.Value.Alpha);
        contestBytesToHash.Add(writeInVoteCount.Value.Beta);
        if (encryptedContestData != null)
        {
            contestBytesToHash.Add(encryptedContestData.C0);
            contestBytesToHash.Add(encryptedContestData.C1);
            
            // These 2 values are called for in the spec but really don't seem like they belong.
            contestBytesToHash.Add(encryptedContestData.Challenge);
            contestBytesToHash.Add(encryptedContestData.Response);
        }

        _value = EGHash.Hash(selectionEncryptionIdentifierHash, contestBytesToHash.ToArray());
    }

    private readonly byte[] _value;

    public static implicit operator byte[](ContestHash i)
    {
        return i._value;
    }
}
