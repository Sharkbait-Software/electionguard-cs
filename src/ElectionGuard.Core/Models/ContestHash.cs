using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using System.Buffers;
using System.Buffers.Binary;

namespace ElectionGuard.Core.Models;

public struct ContestHash : IEquatable<ContestHash>
{
    public ContestHash(byte[] bytes)
    {
        _value = bytes;
    }

    /// <summary>
    /// §3.4.1 eq. (70): chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ..., alpha_ml, beta_ml, C_0, C_1, C_2)
    /// over the encryptions E_1..E_ml of every verifiable field of the contest "in order specified by
    /// the election manifest": the selectable options, then the supplemental fields the manifest
    /// declares (§3.3.9), and no others. <paramref name="verifiableFields"/> is that ordered list; the
    /// caller puts it in manifest order. C_0, C_1, C_2 = (c, v) are omitted when there is no contest
    /// data.
    /// </summary>
    public ContestHash(
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        int contestIndex,
        IEnumerable<EncryptedValueWithProofs> verifiableFields,
        EncryptedData? encryptedContestData)
    {
        // Built in one pooled buffer rather than as a list of freshly allocated 512-byte arrays; the
        // bytes hashed are the same. Both the encryptor and Verification 8 come through here.
        IReadOnlyCollection<EncryptedValueWithProofs> choices = verifiableFields as IReadOnlyCollection<EncryptedValueWithProofs>
            ?? verifiableFields.ToList();

        int length = 1 + sizeof(int) + ModPBytes * 2 * choices.Count;
        if (encryptedContestData != null)
        {
            length += encryptedContestData.C0.Length + encryptedContestData.C1.Length + 2 * ModQBytes;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = 0x28;
            BinaryPrimitives.WriteInt32BigEndian(message.Slice(1, sizeof(int)), contestIndex);
            int offset = 1 + sizeof(int);

            foreach (var encryptedField in choices)
            {
                WriteCiphertext(message, ref offset, encryptedField);
            }

            if (encryptedContestData != null)
            {
                encryptedContestData.C0.CopyTo(message[offset..]);
                offset += encryptedContestData.C0.Length;
                encryptedContestData.C1.CopyTo(message[offset..]);
                offset += encryptedContestData.C1.Length;

                // These 2 values are called for in the spec but really don't seem like they belong.
                encryptedContestData.Challenge.WriteBigEndian(message.Slice(offset, ModQBytes));
                offset += ModQBytes;
                encryptedContestData.Response.WriteBigEndian(message.Slice(offset, ModQBytes));
                offset += ModQBytes;
            }

            _value = new byte[EGHash.HashBytes];
            EGHash.HashConcatenated(selectionEncryptionIdentifierHash, message, _value);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private const int ModPBytes = IntegerModP.ByteLength;
    private const int ModQBytes = IntegerModQ.ByteLength;

    private static void WriteCiphertext(Span<byte> message, ref int offset, EncryptedValueWithProofs value)
    {
        value.Alpha.WriteBigEndian(message.Slice(offset, ModPBytes));
        offset += ModPBytes;
        value.Beta.WriteBigEndian(message.Slice(offset, ModPBytes));
        offset += ModPBytes;
    }

    /// <summary>
    /// §4.1.2 Contest Hash for a pre-encrypted ballot, computed from the contest's selection hashes
    /// (including its null-vector hashes) rather than from a single selection vector.
    /// </summary>
    public static ContestHash ForPreEncryptedContest(
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        int contestIndex,
        IEnumerable<SelectionHash> selectionHashes)
    {
        // Formula (115): chi_l = H(HI; 0x41, ind_c(l), psi_pi(1), ..., psi_pi(m+L)), the selection
        // hashes in increasing numerical order so their order reveals nothing about the selections.
        var sorted = selectionHashes.Order().ToList();

        int length = 5 + sorted.Count * EGHash.HashBytes;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = 0x41;
            BinaryPrimitives.WriteInt32BigEndian(message.Slice(1, 4), contestIndex);
            int offset = 5;
            foreach (var selectionHash in sorted)
            {
                byte[] bytes = selectionHash;
                bytes.CopyTo(message[offset..]);
                offset += bytes.Length;
            }

            var value = new byte[EGHash.HashBytes];
            EGHash.HashConcatenated(selectionEncryptionIdentifierHash, message, value);
            return new ContestHash(value);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private readonly byte[] _value;

    public static implicit operator byte[](ContestHash i)
    {
        return i._value;
    }

    public static bool operator ==(ContestHash left, ContestHash right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(ContestHash left, ContestHash right)
    {
        return !(left == right);
    }

    public override bool Equals(object? obj)
    {
        return obj is ContestHash hash && Equals(hash);
    }

    public bool Equals(ContestHash other)
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
