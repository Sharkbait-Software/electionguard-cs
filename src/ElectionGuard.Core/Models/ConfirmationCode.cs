using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.Models;

public struct ConfirmationCode : IEquatable<ConfirmationCode>
{
    public ConfirmationCode(byte[] bytes)
    {
        _value = bytes;
    }

    public ConfirmationCode(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, IEnumerable<ContestHash> contestHashes, ChainingField? chainingField)
    {
        List<byte[]> bytesToHash = [[0x29]];
        foreach(var contestHash in contestHashes)
        {
            bytesToHash.Add(contestHash);
        }

        _value = EGHash.Hash(selectionEncryptionIdentifierHash, bytesToHash.ToArray());
    }

    private readonly byte[] _value;

    public static implicit operator byte[](ConfirmationCode i)
    {
        return i._value;
    }

    public static bool operator ==(ConfirmationCode left, ConfirmationCode right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(ConfirmationCode left, ConfirmationCode right)
    {
        return !(left == right);
    }

    public override bool Equals(object? obj)
    {
        return obj is ConfirmationCode code && Equals(code);
    }

    public bool Equals(ConfirmationCode other)
    {
        return EqualityComparer<byte[]>.Default.Equals(_value, other._value);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(_value);
    }
}
