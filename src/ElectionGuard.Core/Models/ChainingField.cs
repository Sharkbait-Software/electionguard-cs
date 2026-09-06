using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

/// <summary>
/// §3.4.4 Ballot Chaining. The chaining field BC is 36 bytes: a 4-byte chaining mode identifier
/// followed by a 32-byte hash value.
/// </summary>
public struct ChainingField : IEquatable<ChainingField>
{
    public ChainingField(ChainingMode chainingMode, VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash, ConfirmationCode? previousConfirmationCode)
    {
        byte[] chainingModeIdentifier = ((int)chainingMode).ToByteArray();

        if (chainingMode == ChainingMode.None)
        {
            // Formula (73): BC = 0x00000000 || HDI. No dependency on any previous confirmation
            // code -- the same 32 bytes are used for every confirmation code computation.
            _value = ByteArrayExtensions.Concat(chainingModeIdentifier, deviceHash);
        }
        else if (previousConfirmationCode == null)
        {
            // Formulas (74)/(75): first ballot on the device -- initialize the chain.
            // BC,0 = 0x00000001 || HDI ; H0 = H(HE; 0x29, BC,0) ; the first ballot's chaining
            // field then contains this initialization code H0 in place of a "previous" code.
            byte[] bc0 = ByteArrayExtensions.Concat(chainingModeIdentifier, deviceHash);
            byte[] h0 = EGHash.Hash(extendedBaseHash, [0x29], bc0);
            _value = ByteArrayExtensions.Concat(chainingModeIdentifier, h0);
        }
        else
        {
            // Formula (76): BC,j = 0x00000001 || Hj-1, the previous ballot's confirmation code.
            _value = ByteArrayExtensions.Concat(chainingModeIdentifier, previousConfirmationCode);
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
        return _value.SequenceEqual(other._value);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(_value);
    }
}