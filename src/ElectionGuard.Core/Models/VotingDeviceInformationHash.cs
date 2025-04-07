using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using System.Text;

namespace ElectionGuard.Core.Models;

public struct VotingDeviceInformationHash
{
    public VotingDeviceInformationHash(ExtendedBaseHash extendedBaseHash, string deviceIdentifier)
    {
        var deviceIdentifierBytes = Encoding.UTF8.GetBytes(deviceIdentifier);
        _value = EGHash.Hash(extendedBaseHash,
            deviceIdentifierBytes.Length.ToByteArray(),
            deviceIdentifierBytes);
    }

    private readonly byte[] _value;

    public static implicit operator byte[](VotingDeviceInformationHash i)
    {
        return i._value;
    }
}