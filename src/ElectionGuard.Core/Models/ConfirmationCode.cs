using ElectionGuard.Core.Crypto;
using System.Buffers;

namespace ElectionGuard.Core.Models;

public struct ConfirmationCode : IEquatable<ConfirmationCode>
{
    public ConfirmationCode(byte[] bytes)
    {
        _value = bytes;
    }

    public ConfirmationCode(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, IEnumerable<ContestHash> contestHashes, ChainingField? chainingField)
        // §3.4.2 formula (71): HC = H(HI; 0x29, chi_1, ..., chi_mB, BC).
        : this(0x29, selectionEncryptionIdentifierHash, contestHashes, chainingField)
    {
    }

    /// <summary>
    /// §4.1.3 Confirmation Code of a pre-encrypted ballot, computed from its pre-encrypted contest
    /// hashes before any selection is made.
    /// </summary>
    public static ConfirmationCode ForPreEncryptedBallot(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, IEnumerable<ContestHash> contestHashes, ChainingField chainingField)
    {
        // Formula (116): HC = H(HI; 0x42, chi_1, ..., chi_mB, BC).
        return new ConfirmationCode(0x42, selectionEncryptionIdentifierHash, contestHashes, chainingField);
    }

    private ConfirmationCode(byte domainSeparator, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, IEnumerable<ContestHash> contestHashes, ChainingField? chainingField)
    {
        // Built in one pooled buffer rather than as a list of arrays; the bytes hashed are the same.
        IReadOnlyCollection<ContestHash> hashes = contestHashes as IReadOnlyCollection<ContestHash>
            ?? contestHashes.ToList();
        byte[]? chaining = chainingField.HasValue ? (byte[])chainingField.Value : null;

        int length = 1 + (chaining?.Length ?? 0);
        foreach (var contestHash in hashes)
        {
            length += ((byte[])contestHash).Length;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = domainSeparator;
            int offset = 1;
            foreach (var contestHash in hashes)
            {
                byte[] bytes = contestHash;
                bytes.CopyTo(message[offset..]);
                offset += bytes.Length;
            }

            chaining?.CopyTo(message[offset..]);

            _value = new byte[EGHash.HashBytes];
            EGHash.HashConcatenated(selectionEncryptionIdentifierHash, message, _value);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
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
