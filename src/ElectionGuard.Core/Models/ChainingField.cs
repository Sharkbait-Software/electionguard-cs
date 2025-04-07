using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

public struct ChainingField
{
    public ChainingField(ChainingMode chainingMode, VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash, ConfirmationCode? previousConfirmationCode)
    {
        int chainingModeIdentifier = (int)chainingMode;

        if (previousConfirmationCode == null)
        {
            _value = ByteArrayExtensions.Concat(chainingModeIdentifier.ToByteArray(), deviceHash);
        }
        else
        {
            _value = ByteArrayExtensions.Concat(chainingModeIdentifier.ToByteArray(), previousConfirmationCode);
        }
    }

    private readonly byte[] _value;

    public static implicit operator byte[](ChainingField i)
    {
        return i._value;
    }
}