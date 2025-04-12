using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

public struct ChainingField : IEquatable<ChainingField>
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

    public static bool operator ==(ChainingField left, ChainingField right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(ChainingField left, ChainingField right)
    {
        return !(left == right);
    }

    public override bool Equals(object? obj)
    {
        return obj is ChainingField field && Equals(field);
    }

    public bool Equals(ChainingField other)
    {
        return EqualityComparer<byte[]>.Default.Equals(_value, other._value);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(_value);
    }
}