using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using System.Text;

namespace ElectionGuard.Core.Models;

public struct VotingDeviceInformationHash : IEquatable<VotingDeviceInformationHash>
{
    public VotingDeviceInformationHash(byte[] bytes)
    {
        _value = bytes;
    }

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

    public static bool operator ==(VotingDeviceInformationHash left, VotingDeviceInformationHash right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(VotingDeviceInformationHash left, VotingDeviceInformationHash right)
    {
        return !(left == right);
    }

    public override bool Equals(object? obj)
    {
        return obj is VotingDeviceInformationHash hash && Equals(hash);
    }

    public bool Equals(VotingDeviceInformationHash other)
    {
        return _value.SequenceEqual(other._value);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(_value);
    }
}