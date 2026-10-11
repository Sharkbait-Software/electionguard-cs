using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Serialization;

namespace ElectionGuard.Core.Models;

/// <summary>
/// §3.4.4 Ballot Chaining. The chaining field BC is 36 bytes: a 4-byte chaining mode identifier
/// followed by a 32-byte hash value.
///
/// Every ballot carries the field it was hashed with (Verification 13.B: "B_C is the chaining field
/// for ballot B"), so that Verification 8.B (16.C) recomputes H_C from it and 8.D/8.E (16.E/16.F)
/// compare it with the field the ballot's place in its device's chain implies. The static members
/// build the per-device values of §3.4.4 and §4.1.4: the initialization code H_0 (eqs. 74, 117)
/// and the chain close (eqs. 77/78, 118/120).
/// </summary>
public struct ChainingField : IEquatable<ChainingField>
{
    /// <summary>The length of B_C in bytes: a 4-byte mode identifier and a 32-byte hash.</summary>
    public const int ByteLength = 36;

    /// <summary>Domain separator of H_0 and H-bar for regular ballots (eqs. 74, 77).</summary>
    private const byte ChainHashSeparator = 0x29;

    /// <summary>Domain separator of the chain close's inner hash for regular ballots (eq. 78).</summary>
    private const byte ClosingSeparator = 0x2B;

    /// <summary>Domain separator of H_0 and H-bar for pre-encrypted ballots (eqs. 117, 118).</summary>
    private const byte PreEncryptedChainHashSeparator = 0x42;

    /// <summary>Domain separator of the chain close's inner hash for pre-encrypted ballots (eq. 120).</summary>
    private const byte PreEncryptedClosingSeparator = 0x44;

    public ChainingField(ChainingMode chainingMode, VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash, ConfirmationCode? previousConfirmationCode)
    {
        _value = For(chainingMode, deviceHash, extendedBaseHash, previousConfirmationCode, ChainHashSeparator)._value;
    }

    /// <summary>
    /// §4.1.4 Ballot Chaining on a device generating pre-encrypted ballots. The same as §3.4.4
    /// except that the chain is initialized with the pre-encrypted domain separator 0x42.
    /// </summary>
    public static ChainingField ForPreEncryptedBallots(ChainingMode chainingMode, VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash, ConfirmationCode? previousConfirmationCode)
    {
        return For(chainingMode, deviceHash, extendedBaseHash, previousConfirmationCode, PreEncryptedChainHashSeparator);
    }

    private static ChainingField For(ChainingMode chainingMode, VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash, ConfirmationCode? previousConfirmationCode, byte chainHashSeparator)
    {
        // Only the two modes §3.4.4 specifies (Manifest.Validate refuses any other), so the
        // identifier written here always agrees with the 0x00000001 that B_C,0 and the chain close
        // hard-code under simple chaining.
        if (chainingMode is not (ChainingMode.None or ChainingMode.Simple))
        {
            throw new ArgumentOutOfRangeException(nameof(chainingMode), chainingMode, "Only the no chaining and simple chaining modes of §3.4.4 are specified.");
        }

        byte[] chainingModeIdentifier = ((int)chainingMode).ToByteArray();

        if (chainingMode == ChainingMode.None)
        {
            // Formula (73) (8.D, 16.E): BC = 0x00000000 || HDI. No dependency on any previous
            // confirmation code -- the same 32 bytes are used for every confirmation code computation.
            return new ChainingField(ByteArrayExtensions.Concat(chainingModeIdentifier, deviceHash));
        }

        // Formula (76) (8.E, 16.F): BC,j = 0x00000001 || Hj-1, the previous ballot's confirmation
        // code, or the initialization code H0 (eqs. 74/75, 117) for the device's first ballot.
        ConfirmationCode previous = previousConfirmationCode ?? InitialHash(deviceHash, extendedBaseHash, chainHashSeparator);
        return new ChainingField(ByteArrayExtensions.Concat(chainingModeIdentifier, previous));
    }

    /// <summary>
    /// Formulas (74)/(75), Verification 8.F: the simple chaining mode's initialization code
    /// H0 = H(HE; 0x29, BC,0) with BC,0 = 0x00000001 || HDI. The first ballot on the device chains
    /// from it (eq. 76 with j = 1). It is a 32-byte hash, typed as a confirmation code because it
    /// plays the part of H_0 in the sequence H_0, H_1, ..., H_ℓ.
    /// </summary>
    public static ConfirmationCode InitialHash(VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash)
    {
        return InitialHash(deviceHash, extendedBaseHash, ChainHashSeparator);
    }

    /// <summary>
    /// Formula (117), Verification 16.G: H0 = H(HE; 0x42, BC,0) on a device generating
    /// pre-encrypted ballots, with HDI the device information hash of eq. (119).
    /// </summary>
    public static ConfirmationCode InitialHashForPreEncryptedBallots(VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash)
    {
        return InitialHash(deviceHash, extendedBaseHash, PreEncryptedChainHashSeparator);
    }

    private static ConfirmationCode InitialHash(VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash, byte separator)
    {
        return new ConfirmationCode(EGHash.Hash(extendedBaseHash, [separator], InitialChainingField(deviceHash)));
    }

    /// <summary>BC,0 = 0x00000001 || HDI (eq. 75).</summary>
    private static byte[] InitialChainingField(VotingDeviceInformationHash deviceHash)
    {
        return ByteArrayExtensions.Concat(((int)ChainingMode.Simple).ToByteArray(), deviceHash);
    }

    /// <summary>
    /// Formula (78), Verification 8.G: the final input byte array of a simple chain,
    /// BC = 0x00000001 || H(HE; 0x2B, Hℓ, BC,0), where Hℓ is the confirmation code of the last
    /// ballot on the device and BC,0 = 0x00000001 || HDI. <see cref="ClosingHash"/> hashes it.
    /// </summary>
    public static ChainingField Closing(VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash, ConfirmationCode lastConfirmationCode)
    {
        return Closing(deviceHash, extendedBaseHash, lastConfirmationCode, ClosingSeparator);
    }

    /// <summary>
    /// Formula (120), Verification 16.H: BC = 0x00000001 || H(HE; 0x44, Hℓ, BC,0) on a device
    /// generating pre-encrypted ballots. The hash input is the body form 0x44 || Hℓ || BC,0, 69
    /// bytes (user decision Q4); the §5.5.5 table's extra 0x4C4F434B ("LOCK") is an erratum.
    /// </summary>
    public static ChainingField ClosingForPreEncryptedBallots(VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash, ConfirmationCode lastConfirmationCode)
    {
        return Closing(deviceHash, extendedBaseHash, lastConfirmationCode, PreEncryptedClosingSeparator);
    }

    private static ChainingField Closing(VotingDeviceInformationHash deviceHash, ExtendedBaseHash extendedBaseHash, ConfirmationCode lastConfirmationCode, byte separator)
    {
        byte[] inner = EGHash.Hash(extendedBaseHash, [separator], lastConfirmationCode, InitialChainingField(deviceHash));
        return new ChainingField(ByteArrayExtensions.Concat(((int)ChainingMode.Simple).ToByteArray(), inner));
    }

    /// <summary>
    /// Formula (77), Verification 8.G: the closing hash H-bar = H(HE; 0x29, BC) of a simple chain,
    /// over the final input byte array of <see cref="Closing"/>. It is published with the device's
    /// ordered list of ballots (§3.7).
    /// </summary>
    public static ConfirmationCode ClosingHash(ChainingField closingField, ExtendedBaseHash extendedBaseHash)
    {
        return new ConfirmationCode(EGHash.Hash(extendedBaseHash, [ChainHashSeparator], closingField));
    }

    /// <summary>Formula (118), Verification 16.H: H-bar = H(HE; 0x42, BC) on a pre-encrypting device.</summary>
    public static ConfirmationCode ClosingHashForPreEncryptedBallots(ChainingField closingField, ExtendedBaseHash extendedBaseHash)
    {
        return new ConfirmationCode(EGHash.Hash(extendedBaseHash, [PreEncryptedChainHashSeparator], closingField));
    }

    /// <summary>
    /// Decodes a published chaining field: exactly <see cref="ByteLength"/> bytes, copied. Its
    /// content (mode identifier and hash) is left to Verification 8.D/8.E (16.E/16.F); a field missing
    /// from a protobuf document arrives as an empty span and fails the length check.
    /// </summary>
    public static ChainingField FromCanonicalBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
        {
            throw new NonCanonicalEncodingException($"A chaining field B_C must be exactly {ByteLength} bytes; got {bytes.Length}.");
        }

        return new ChainingField(bytes.ToArray());
    }

    private ChainingField(byte[] value)
    {
        _value = value;
    }

    private readonly byte[] _value;

    /// <summary>
    /// True when this holds a 36-byte field. A default instance (as a malformed document can produce)
    /// does not; <see cref="Verify.BallotStructure"/> rejects a ballot that carries one.
    /// </summary>
    public readonly bool IsWellFormed => _value is { Length: ByteLength };

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
        return (_value ?? []).AsSpan().SequenceEqual(other._value ?? []);
    }

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_value ?? []);
        return hash.ToHashCode();
    }

    public override string ToString()
    {
        return Convert.ToHexString(_value ?? []);
    }
}
