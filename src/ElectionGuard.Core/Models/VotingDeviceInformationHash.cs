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
        // §3.4.3 eq. (72): HDI = H(HE; 0x2A, S_device), with S_device length-prefixed per §5.1.4,
        // 5 + len(S_device) bytes (§5.5.3).
        var deviceIdentifierBytes = Encoding.UTF8.GetBytes(deviceIdentifier);
        _value = EGHash.Hash(extendedBaseHash,
            [0x2A],
            deviceIdentifierBytes.Length.ToByteArray(),
            deviceIdentifierBytes);
    }

    /// <summary>
    /// §4.1.4 device information hash for a device generating pre-encrypted ballots.
    /// </summary>
    public static VotingDeviceInformationHash ForPreEncryptedBallots(ExtendedBaseHash extendedBaseHash, string deviceIdentifier)
    {
        // Formula (119): HDI = H(HE; 0x43, S_device), with S_device length-prefixed per §5.5.5.
        var deviceIdentifierBytes = Encoding.UTF8.GetBytes(deviceIdentifier);
        return new VotingDeviceInformationHash(EGHash.Hash(extendedBaseHash,
            [0x43],
            deviceIdentifierBytes.Length.ToByteArray(),
            deviceIdentifierBytes));
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
        var hash = new HashCode();
        foreach (var b in _value)
        {
            hash.Add(b);
        }
        return hash.ToHashCode();
    }
}