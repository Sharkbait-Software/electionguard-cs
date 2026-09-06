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
        // §3.4.2 formula (71): HC = H(HI; 0x29, chi_1, ..., chi_mB, BC).
        List<byte[]> bytesToHash = [[0x29]];
        foreach(var contestHash in contestHashes)
        {
            bytesToHash.Add(contestHash);
        }
        if (chainingField != null)
        {
            bytesToHash.Add(chainingField.Value);
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
        return _value.SequenceEqual(other._value);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(_value);
    }
}
