using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Buffers;
using System.Security.Cryptography;

namespace ElectionGuard.Core.BallotEncryption;

/// <summary>
/// The encrypted ballot nonce C_ξB = (C_ξB,0, C_ξB,1, C_ξB,2) of §3.3.4 (eqs. 34-38), which "every
/// ElectionGuard ballot contains": C_ξB,0 = α_B = g^ξ-hat_B, C_ξB,1 = b(ξ_B, 32) ⊕ k_1 (32 bytes) and
/// C_ξB,2 = (c_B, v_B), a Schnorr proof of knowledge of ξ-hat_B. It is not an input to the contest
/// hashes or the confirmation code (eqs. 70, 71). The guardians decrypt it only for a challenged
/// ballot (§3.6.7).
/// </summary>
public class EncryptedBallotNonce
{
    /// <summary>C_ξB,0 = α_B = g^ξ-hat_B mod p (eqs. 34, 37).</summary>
    public required IntegerModP C0 { get; init; }

    /// <summary>C_ξB,1 = b(ξ_B, 32) ⊕ k_1 (eq. 37): exactly 32 bytes.</summary>
    public required byte[] C1 { get; init; }

    /// <summary>c_B of C_ξB,2 (eq. 38).</summary>
    public required IntegerModQ Challenge { get; init; }

    /// <summary>v_B = (u_B - c_B·ξ-hat_B) mod q of C_ξB,2.</summary>
    public required IntegerModQ Response { get; init; }
}

/// <summary>
/// §3.3.4 encryption of the ballot nonce ξ_B to the ballot data encryption key K-hat, and the
/// derivations its decryption (§3.6.7 p.52, eqs. 107-108) repeats. Shared by
/// <see cref="BallotEncryptor"/>, the pre-encrypted ballot encrypting tool (§4.2), the guardians
/// and the administrator, so that no two of them can encode an input differently:
/// <list type="bullet">
/// <item>eq. (35): h = H(H_I; 0x22, α_B, β_B), B1 = 0x22 ‖ b(α_B, 512) ‖ b(β_B, 512), 1025 bytes
/// (§5.5.3 table, p.75);</item>
/// <item>eq. (36): k_1 = HMAC(h, 0x01 ‖ Label ‖ 0x00 ‖ Context ‖ 0x0100), Label = b("ballot_nonce", 12),
/// Context = b("ballot_nonce_encrypt", 20): a one-byte counter and a two-byte length (256 bits), as
/// the p.30 page image shows and as in eqs. (17)/(18), not the four-byte fields of eq. (66). The
/// message is always the same 36 bytes;</item>
/// <item>eq. (38): c_B = H_q(H_I; 0x23, a_B, C_ξB,0, C_ξB,1), B1 = 0x23 ‖ b(a_B, 512) ‖
/// b(C_ξB,0, 512) ‖ C_ξB,1, 1057 bytes (§5.5.3 table, p.75).</item>
/// </list>
/// ξ_B is a 256-bit value, written as its 32 bytes and never reduced mod q. The known-answer tests
/// (test/kat, families ballot_nonce_*) pin every one of these.
/// </summary>
public static class BallotNonceEncryption
{
    /// <summary>The KDF label of eq. (36): b("ballot_nonce", 12), the UTF-8 bytes with no length prefix.</summary>
    private static ReadOnlySpan<byte> Label => "ballot_nonce"u8;

    /// <summary>The KDF context of eq. (36): b("ballot_nonce_encrypt", 20).</summary>
    private static ReadOnlySpan<byte> Context => "ballot_nonce_encrypt"u8;

    /// <summary>Bytes of ξ_B, of C_ξB,1 and of k_1.</summary>
    public const int NonceBytes = 32;

    /// <summary>
    /// §3.3.4: encrypts <paramref name="ballotNonce"/> (ξ_B, 32 bytes) to <paramref name="otherBallotDataEncryptionKey"/>
    /// (K-hat) under H_I, with fresh random ξ-hat_B and u_B (<paramref name="encryptionNonce"/> and
    /// <paramref name="proofNonce"/> only in tests).
    /// </summary>
    public static EncryptedBallotNonce Encrypt(
        BallotNonce ballotNonce,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        IntegerModP otherBallotDataEncryptionKey,
        IntegerModQ? encryptionNonce = null,
        IntegerModQ? proofNonce = null)
    {
        byte[] nonce = ballotNonce;
        if (nonce is null || nonce.Length != NonceBytes)
        {
            throw new ArgumentException("The ballot nonce ξ_B is 32 bytes (§3.3.3).", nameof(ballotNonce));
        }

        // ξ-hat_B, u_B and their powers are secret: full-width exponents of Z_q on the constant-time path.
        var xiHat = encryptionNonce ?? ElectionGuardRandom.GetIntegerModQ();
        var alpha = MontgomeryModP.PowModP(EGParameters.G, xiHat);
        var beta = MontgomeryModP.PowModP(otherBallotDataEncryptionKey, xiHat);
        var c1 = Apply(SecretKey(selectionEncryptionIdentifierHash, alpha, beta), nonce);

        var u = proofNonce ?? ElectionGuardRandom.GetIntegerModQ();
        var commitment = MontgomeryModP.PowModP(EGParameters.G, u);
        var challenge = ProofChallenge(selectionEncryptionIdentifierHash, commitment, alpha, c1);

        return new EncryptedBallotNonce
        {
            C0 = alpha,
            C1 = c1,
            Challenge = challenge,
            Response = u - challenge * xiHat,
        };
    }

    /// <summary>
    /// Eq. (35), and its use in decryption (§3.6.7 p.52): h = H(H_I; 0x22, α_B, β_B), with
    /// α_B = C_ξB,0 and β_B = K-hat^ξ-hat_B (encryption) or the combined decryption
    /// ∏ m_i^{w_i} (eq. 108).
    /// </summary>
    public static byte[] SecretKey(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, IntegerModP alpha, IntegerModP beta)
    {
        const int length = 1 + 2 * IntegerModP.ByteLength;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = 0x22;
            alpha.WriteBigEndian(message.Slice(1, IntegerModP.ByteLength));
            beta.WriteBigEndian(message.Slice(1 + IntegerModP.ByteLength, IntegerModP.ByteLength));
            var h = new byte[EGHash.HashBytes];
            EGHash.HashConcatenated(selectionEncryptionIdentifierHash, message, h);
            return h;
        }
        finally
        {
            // β_B decrypts ξ_B: leave no copy of it in the pool.
            buffer.AsSpan(0, length).Clear();
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Eq. (36): k_1 = HMAC(h, 0x01 ‖ "ballot_nonce" ‖ 0x00 ‖ "ballot_nonce_encrypt" ‖ 0x0100), 32 bytes.
    /// </summary>
    public static byte[] EncryptionKey(byte[] secretKey)
    {
        if (secretKey is null || secretKey.Length != EGHash.HashBytes)
        {
            throw new ArgumentException("The secret key h is a 32-byte hash (eq. 35).", nameof(secretKey));
        }

        // 0x01 ‖ Label ‖ 0x00 ‖ Context ‖ 0x0100: 1 + 12 + 1 + 20 + 2 = 36 bytes.
        Span<byte> message = stackalloc byte[1 + 12 + 1 + 20 + 2];
        int offset = 0;
        message[offset++] = 0x01;
        Label.CopyTo(message[offset..]);
        offset += Label.Length;
        message[offset++] = 0x00;
        Context.CopyTo(message[offset..]);
        offset += Context.Length;
        message[offset++] = 0x01;
        message[offset] = 0x00;

        return HMACSHA256.HashData(secretKey, message);
    }

    /// <summary>Eq. (38): c_B = H_q(H_I; 0x23, a_B, C_ξB,0, C_ξB,1).</summary>
    public static IntegerModQ ProofChallenge(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, IntegerModP commitment, IntegerModP c0, byte[] c1)
    {
        if (c1 is null || c1.Length != NonceBytes)
        {
            throw new ArgumentException($"C_ξB,1 is {NonceBytes} bytes (eq. 37).", nameof(c1));
        }

        const int length = 1 + 2 * IntegerModP.ByteLength + NonceBytes;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = 0x23;
            commitment.WriteBigEndian(message.Slice(1, IntegerModP.ByteLength));
            c0.WriteBigEndian(message.Slice(1 + IntegerModP.ByteLength, IntegerModP.ByteLength));
            c1.CopyTo(message[(1 + 2 * IntegerModP.ByteLength)..]);
            return EGHash.HashModQConcatenated(selectionEncryptionIdentifierHash, message);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// §3.6.7 p.52, the check each guardian makes before it computes a partial decryption: a_B =
    /// g^{v_B}·C_ξB,0^{c_B} and c_B = H_q(H_I; 0x23, a_B, C_ξB,0, C_ξB,1) (eq. 38). The values are all
    /// public. False for a field that is null or whose C_ξB,1 is not 32 bytes.
    /// </summary>
    public static bool ProofHolds(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, EncryptedBallotNonce? encrypted)
    {
        if (encrypted?.C1 is not { Length: NonceBytes })
        {
            return false;
        }

        var commitment = MontgomeryModP.PowModP(EGParameters.G, encrypted.Response) * MontgomeryModP.PowModP(encrypted.C0, encrypted.Challenge);
        return ProofChallenge(selectionEncryptionIdentifierHash, commitment, encrypted.C0, encrypted.C1) == encrypted.Challenge;
    }

    /// <summary>
    /// §3.6.7 p.52: ξ_B = C_ξB,1 ⊕ k_1, with h = H(H_I; 0x22, C_ξB,0, β_B) (eq. 35) and k_1 (eq. 36),
    /// β_B being the guardians' combined decryption ∏ m_i^{w_i} (eq. 108). ξ_B is secret: the spec
    /// says it "should not be published".
    /// </summary>
    public static BallotNonce Decrypt(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, EncryptedBallotNonce encrypted, IntegerModP beta)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        if (encrypted.C1 is not { Length: NonceBytes })
        {
            throw new ArgumentException($"C_ξB,1 is {NonceBytes} bytes (eq. 37).", nameof(encrypted));
        }

        return new BallotNonce(Apply(SecretKey(selectionEncryptionIdentifierHash, encrypted.C0, beta), encrypted.C1));
    }

    /// <summary><paramref name="input"/> (32 bytes) XOR k_1 derived from <paramref name="secretKey"/>.</summary>
    private static byte[] Apply(byte[] secretKey, byte[] input)
    {
        var key = EncryptionKey(secretKey);
        var output = new byte[NonceBytes];
        for (int i = 0; i < NonceBytes; i++)
        {
            output[i] = (byte)(input[i] ^ key[i]);
        }

        Array.Clear(key);
        Array.Clear(secretKey);
        return output;
    }
}
